import { readFileSync, readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  DiadocAuthError,
  DiadocConflictError,
  DiadocError,
  DiadocOperationPendingError,
  SHELF_UPLOAD_MAX_BYTES,
  type DocflowStatus,
  type Document,
  type DocumentRef,
  type Message,
  type MessagePrototype,
  type MessageToPost,
  type MessageValidationResult,
  type PostMessageOptions,
  type ShelfUploadOptions,
} from '../diadoc/index.js';
import {
  SignerTimeoutError,
  type SignResult,
  type Signer,
  type VerifyResult,
} from '../signer/index.js';
import { UtdError } from '../utd/index.js';
import { PipelineError } from './errors.js';
import { operationIdFor } from './operation-id.js';
import { sendUtd, type PipelineDiadoc, type SendUtdInput, type SendUtdOptions } from './send.js';

const FIXTURES = new URL('../utd/fixtures/', import.meta.url);
const FILE_NAME = readdirSync(FIXTURES).find((f) => f.endsWith('.xml')) ?? '';
const CONTENT = readFileSync(new URL(FILE_NAME, FIXTURES));

// ContentInfo { pkcs7-signedData, [0] {} }: a minimal DER CMS envelope.
const SIGNED_DATA_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const DER_SIGNATURE = Buffer.from([0x30, 0x0d, ...SIGNED_DATA_OID, 0xa0, 0x00]);
const BER_SIGNATURE = Buffer.from([0x30, 0x80, ...SIGNED_DATA_OID, 0xa0, 0x00, 0x00, 0x00]);

const FROM = 'from-box';
const TO = 'to-box';

/** Pads the УПД with whitespace before the closing root tag: still the same valid document. */
function padded(size: number): Buffer {
  const at = CONTENT.lastIndexOf(Buffer.from('</', 'latin1'));
  return Buffer.concat([
    CONTENT.subarray(0, at),
    Buffer.alloc(size - CONTENT.length, 0x20),
    CONTENT.subarray(at),
  ]);
}

class FakeSigner implements Signer {
  signed: Buffer[] = [];
  verified: { data: Buffer; signature: Buffer }[] = [];
  signResult: SignResult | Error = { signature: DER_SIGNATURE };
  verifyResult: VerifyResult | Error = { valid: true, signers: [{ valid: true }] };

  sign(data: Buffer): Promise<SignResult> {
    this.signed.push(data);
    return this.signResult instanceof Error
      ? Promise.reject(this.signResult)
      : Promise.resolve(this.signResult);
  }

  verify(data: Buffer, signature: Buffer): Promise<VerifyResult> {
    this.verified.push({ data, signature });
    return this.verifyResult instanceof Error
      ? Promise.reject(this.verifyResult)
      : Promise.resolve(this.verifyResult);
  }
}

const POSTED: Message = {
  MessageId: 'msg-1',
  Entities: [
    { EntityType: 'Attachment', EntityId: 'sig-1', ParentEntityId: 'doc-1' },
    { EntityType: 'Attachment', EntityId: 'doc-1', ParentEntityId: '' },
  ],
};

const status = (severity: string, text = severity): DocflowStatus => ({
  PrimaryStatus: { Severity: severity, StatusText: text },
});

class FakeDiadoc implements PipelineDiadoc {
  calls: string[] = [];
  prototypes: MessagePrototype[] = [];
  uploads: { content: Buffer; options: ShelfUploadOptions | undefined }[] = [];
  posts: { message: MessageToPost; options: PostMessageOptions }[] = [];
  refs: DocumentRef[] = [];

  canPostResult: MessageValidationResult | Error = { Errors: [] };
  shelfResult: string | Error = 'dd-api-shelf';
  postResult: Message | Error = POSTED;
  /** One entry per GetDocument call; the last one repeats. */
  documents: (Document | Error)[] = [{ DocflowStatus: status('Success', 'Подписан') }];

  canPostMessage(p: MessagePrototype): Promise<MessageValidationResult> {
    this.calls.push('canPostMessage');
    this.prototypes.push(p);
    return settle(this.canPostResult);
  }

  shelfUpload(content: Buffer, options?: ShelfUploadOptions): Promise<string> {
    this.calls.push('shelfUpload');
    this.uploads.push({ content, options });
    return settle(this.shelfResult);
  }

  postMessage(message: MessageToPost, options: PostMessageOptions): Promise<Message> {
    this.calls.push('postMessage');
    this.posts.push({ message, options });
    return settle(this.postResult);
  }

  getDocument(ref: DocumentRef): Promise<Document> {
    this.calls.push('getDocument');
    this.refs.push(ref);
    const next = this.documents.length > 1 ? this.documents.shift() : this.documents[0];
    return settle(next ?? new Error('no document'));
  }
}

function settle<T>(value: T | Error): Promise<T> {
  return value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
}

function setup(options: Partial<SendUtdOptions> = {}) {
  const signer = new FakeSigner();
  const diadoc = new FakeDiadoc();
  let clock = 1_000_000;
  const slept: number[] = [];
  const logs: string[] = [];
  const run = (input: SendUtdInput = { fileName: FILE_NAME, content: CONTENT }) =>
    sendUtd(
      input,
      {
        signer,
        diadoc,
        now: () => clock,
        sleep: (ms) => {
          slept.push(ms);
          clock += ms;
          return Promise.resolve();
        },
        log: (m) => logs.push(m),
      },
      {
        fromBoxId: FROM,
        toBoxId: TO,
        poll: { initialDelayMs: 1000, maxDelayMs: 4000, timeoutMs: 10_000 },
        ...options,
      },
    );
  return { signer, diadoc, slept, logs, run };
}

async function failure(promise: Promise<unknown>): Promise<PipelineError> {
  const error: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(PipelineError);
  return error as PipelineError;
}

describe('sendUtd happy path', () => {
  it('signs, verifies, pre-checks, posts the exact bytes and returns the final status', async () => {
    const { signer, diadoc, run } = setup();

    const result = await run();

    expect(signer.signed).toHaveLength(1);
    expect(signer.signed[0]?.equals(CONTENT)).toBe(true);
    expect(signer.verified[0]?.data.equals(CONTENT)).toBe(true);
    expect(signer.verified[0]?.signature).toBe(DER_SIGNATURE);
    expect(diadoc.calls).toEqual(['canPostMessage', 'postMessage', 'getDocument']);
    expect(diadoc.prototypes[0]).toEqual({
      FromBoxId: FROM,
      ToBoxId: TO,
      DocumentPrototypes: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФДОП',
          Version: 'utd970_05_03_01',
        },
      ],
    });

    const post = diadoc.posts[0];
    expect(post?.options.operationId).toBe(operationIdFor(FROM, TO, FILE_NAME, CONTENT));
    expect(post?.message).toEqual({
      FromBoxId: FROM,
      ToBoxId: TO,
      DocumentAttachments: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФДОП',
          Version: 'utd970_05_03_01',
          SignedContent: { Content: CONTENT, Signature: DER_SIGNATURE },
        },
      ],
    });
    expect(post?.message.DocumentAttachments[0]?.SignedContent.Content?.equals(CONTENT)).toBe(true);
    expect(diadoc.refs[0]).toEqual({ boxId: FROM, messageId: 'msg-1', entityId: 'doc-1' });

    expect(result).toEqual({
      operationId: post?.options.operationId,
      fileName: FILE_NAME,
      fromBoxId: FROM,
      toBoxId: TO,
      messageId: 'msg-1',
      entityId: 'doc-1',
      contentPlacement: 'inline',
      outcome: 'success',
      final: true,
      status: status('Success', 'Подписан'),
      polls: 1,
      warnings: [],
    });
  });

  it('skips CanPostMessage when precheck is off and passes customDocumentId through', async () => {
    const { diadoc, run } = setup({ precheck: false, customDocumentId: 'inv-42' });
    await run();
    expect(diadoc.calls).not.toContain('canPostMessage');
    expect(diadoc.posts[0]?.message.DocumentAttachments[0]?.CustomDocumentId).toBe('inv-42');
  });

  it('returns CanPostMessage warnings without failing', async () => {
    const { diadoc, run } = setup();
    const warning = { Severity: 'Warning', UserMessage: 'hint' };
    diadoc.canPostResult = { Errors: [warning] };
    expect((await run()).warnings).toEqual([warning]);
  });

  it('uploads 500 KB+ content to the shelf and sends NameOnShelf', async () => {
    const { diadoc, run } = setup();
    const big = padded(600_000);

    const result = await run({ fileName: FILE_NAME, content: big });

    expect(diadoc.calls).toEqual(['canPostMessage', 'shelfUpload', 'postMessage', 'getDocument']);
    expect(diadoc.uploads[0]?.content.equals(big)).toBe(true);
    expect(diadoc.uploads[0]?.options).toEqual({ fileExtension: '.xml' });
    expect(diadoc.posts[0]?.message.DocumentAttachments[0]?.SignedContent).toEqual({
      NameOnShelf: 'dd-api-shelf',
      Signature: DER_SIGNATURE,
    });
    expect(result).toMatchObject({ contentPlacement: 'shelf', nameOnShelf: 'dd-api-shelf' });
  });
});

describe('sendUtd operationId', () => {
  it('is deterministic and depends on boxes, file name and content', () => {
    const id = operationIdFor(FROM, TO, FILE_NAME, CONTENT);
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    expect(operationIdFor(FROM, TO, FILE_NAME, Buffer.from(CONTENT))).toBe(id);
    expect(operationIdFor(TO, FROM, FILE_NAME, CONTENT)).not.toBe(id);
    expect(operationIdFor(FROM, TO, `x${FILE_NAME}`, CONTENT)).not.toBe(id);
    expect(operationIdFor(FROM, TO, FILE_NAME, padded(CONTENT.length + 1))).not.toBe(id);
    // Field boundaries are unambiguous.
    expect(operationIdFor('ab', 'c', 'f', CONTENT)).not.toBe(
      operationIdFor('a', 'bc', 'f', CONTENT),
    );
  });

  it('is the same on a retry of the same document, although the signature changes', async () => {
    const first = setup();
    const second = setup();
    second.signer.signResult = { signature: Buffer.from([0x30, 0x02, 0x05, 0x00]) };
    await first.run();
    await second.run();
    expect(second.diadoc.posts[0]?.options.operationId).toBe(
      first.diadoc.posts[0]?.options.operationId,
    );
    expect(second.diadoc.posts[0]?.message).not.toEqual(first.diadoc.posts[0]?.message);
  });
});

describe('sendUtd failures before sending', () => {
  it('rejects an invalid УПД before signing', async () => {
    const { signer, diadoc, run } = setup();
    const error = await failure(run({ fileName: 'wrong.xml', content: CONTENT }));
    expect(error).toMatchObject({ code: 'INVALID_UTD', step: 'parse' });
    expect(error.cause).toBeInstanceOf(UtdError);
    expect(signer.signed).toHaveLength(0);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects content above the shelf upload limit before signing', async () => {
    const { signer, run } = setup();
    const error = await failure(
      run({ fileName: FILE_NAME, content: padded(SHELF_UPLOAD_MAX_BYTES + 1) }),
    );
    expect(error).toMatchObject({ code: 'CONTENT_TOO_LARGE', step: 'parse' });
    expect(error.message).toMatch(/not supported yet/);
    expect(signer.signed).toHaveLength(0);
  });

  it('wraps a signer failure', async () => {
    const { signer, diadoc, run } = setup();
    const cause = new SignerTimeoutError('sign', 10);
    signer.signResult = cause;
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGN_FAILED', step: 'sign', cause });
    expect(diadoc.calls).toHaveLength(0);
  });

  it('fails fast when the signature does not verify', async () => {
    const { signer, diadoc, run } = setup();
    signer.verifyResult = { valid: false, signers: [], reason: 'chain' };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGNATURE_INVALID', step: 'verify' });
    expect(error.message).toMatch(/chain/);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('wraps a verify call failure', async () => {
    const { signer, diadoc, run } = setup();
    signer.verifyResult = new Error('boom');
    expect(await failure(run())).toMatchObject({ code: 'VERIFY_FAILED', step: 'verify' });
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects a non-DER signature from the signer', async () => {
    const { signer, diadoc, run } = setup();
    signer.signResult = { signature: BER_SIGNATURE };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'INVALID_SIGNATURE', step: 'attach' });
    expect(diadoc.calls).toHaveLength(0);
  });

  it('stops when CanPostMessage reports errors', async () => {
    const { diadoc, run } = setup();
    diadoc.canPostResult = {
      Errors: [
        { Severity: 'Error', UserMessage: 'Контрагент не найден' },
        { UserMessage: 'no severity counts as an error' },
      ],
    };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'PRECHECK_REJECTED', step: 'precheck' });
    expect(error.message).toMatch(/Контрагент не найден/);
    expect(error.details).toHaveLength(2);
    expect(diadoc.calls).toEqual(['canPostMessage']);
  });

  it('includes a network cause in the message', async () => {
    const { diadoc, run } = setup();
    diadoc.canPostResult = new TypeError('fetch failed', {
      cause: new Error('connect ECONNREFUSED 127.0.0.1:9'),
    });
    expect((await failure(run())).message).toBe(
      'precheck: fetch failed: connect ECONNREFUSED 127.0.0.1:9',
    );
  });

  it('wraps a CanPostMessage call failure', async () => {
    const { diadoc, run } = setup();
    diadoc.canPostResult = new DiadocError('POST', '/CanPostMessage', 403, 'no');
    expect(await failure(run())).toMatchObject({ code: 'PRECHECK_FAILED', step: 'precheck' });
    expect(diadoc.calls).toEqual(['canPostMessage']);
  });

  it('wraps a shelf upload failure', async () => {
    const { diadoc, run } = setup();
    diadoc.shelfResult = new DiadocError('POST', '/V2/ShelfUpload', 500, 'oops');
    const error = await failure(run({ fileName: FILE_NAME, content: padded(600_000) }));
    expect(error).toMatchObject({ code: 'SHELF_UPLOAD_FAILED', step: 'upload' });
    expect(diadoc.calls).not.toContain('postMessage');
  });
});

describe('sendUtd PostMessage failures', () => {
  it.each([
    ['duplicate', 'Message with the same content has already been sent', 'ALREADY_SENT'],
    [
      'forbidden',
      'Получатель запретил получение документов от вашей организации',
      'RECIPIENT_FORBIDS',
    ],
    ['unknown', 'Conflict', 'POST_CONFLICT'],
  ])('409 %s → %s', async (_kind, body, code) => {
    const { diadoc, run } = setup();
    diadoc.postResult = new DiadocConflictError('POST', '/V3/PostMessage', body);
    const error = await failure(run());
    expect(error).toMatchObject({ code, step: 'post' });
    expect(error.operationId).toBe(operationIdFor(FROM, TO, FILE_NAME, CONTENT));
    expect(error.message).toContain(body);
    expect(diadoc.calls).not.toContain('getDocument');
  });

  it('wraps any other PostMessage failure', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = new DiadocError('POST', '/V3/PostMessage', 400, 'bad signature');
    expect(await failure(run())).toMatchObject({ code: 'POST_FAILED', step: 'post' });
  });

  it('reports a PostMessage still in progress as POST_PENDING (retry is safe)', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = new DiadocOperationPendingError('op', 10);
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'POST_PENDING', step: 'post' });
    expect(error.message).toMatch(/run send again/);
  });

  it('fails with the messageId when the message has no document entity', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = { MessageId: 'msg-2', Entities: [] };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'NO_DOCUMENT_ENTITY', step: 'post', messageId: 'msg-2' });
  });
});

describe('sendUtd status polling', () => {
  it('backs off exponentially up to maxDelayMs until a final status', async () => {
    const { diadoc, slept, run } = setup();
    diadoc.documents = [
      {},
      { DocflowStatus: status('Info', 'Отправляется') },
      new DiadocError('GET', '/V3/GetDocument', 503, 'busy'),
      { DocflowStatus: status('Info', 'Отправляется') },
      { DocflowStatus: status('Error', 'Ошибка проверки подписи') },
    ];

    const result = await run();

    expect(slept).toEqual([1000, 2000, 4000, 3000]);
    expect(result).toMatchObject({
      outcome: 'error',
      final: true,
      polls: 5,
      status: status('Error', 'Ошибка проверки подписи'),
    });
    expect(result.statusError).toBeUndefined();
  });

  it('treats an Error severity in SecondaryStatus as final', async () => {
    const { diadoc, run } = setup();
    diadoc.documents = [
      {
        DocflowStatus: {
          PrimaryStatus: { Severity: 'Info' },
          SecondaryStatus: { Severity: 'error', StatusText: 'bad' },
        },
      },
    ];
    expect(await run()).toMatchObject({ outcome: 'error', final: true, polls: 1 });
  });

  it('stops at the deadline with the last status (never sleeping past it)', async () => {
    const { diadoc, slept, run } = setup();
    diadoc.documents = [{ DocflowStatus: status('Info', 'Доставлен') }];

    const result = await run();

    expect(slept).toEqual([1000, 2000, 4000, 3000]);
    expect(result).toMatchObject({
      outcome: 'pending',
      final: false,
      polls: 5,
      status: status('Info', 'Доставлен'),
    });
  });

  it('returns the sent message even if every status request fails', async () => {
    const { diadoc, run } = setup();
    const cause = new DiadocError('GET', '/V3/GetDocument', 502, 'bad gateway');
    diadoc.documents = [cause];
    const result = await run();
    expect(result).toMatchObject({ messageId: 'msg-1', outcome: 'pending', final: false });
    expect(result.status).toBeUndefined();
    expect(result.statusError).toBe(cause);
  });

  it('stops polling on a non-retryable status error', async () => {
    const { diadoc, slept, run } = setup();
    const cause = new DiadocError('GET', '/V3/GetDocument', 403, 'forbidden');
    diadoc.documents = [cause];
    const result = await run();
    expect(result).toMatchObject({ polls: 1, outcome: 'pending', statusError: cause });
    expect(slept).toEqual([]);
  });

  it('stops polling on a token error', async () => {
    const { diadoc, slept, run } = setup();
    diadoc.documents = [new DiadocAuthError('refresh failed', 400, 'invalid_grant')];
    expect(await run()).toMatchObject({ polls: 1, outcome: 'pending' });
    expect(slept).toEqual([]);
  });

  it('records a failing sleep as statusError instead of throwing', async () => {
    const signer = new FakeSigner();
    const diadoc = new FakeDiadoc();
    diadoc.documents = [{ DocflowStatus: status('Info') }];
    const cause = new Error('timer broke');
    const result = await sendUtd(
      { fileName: FILE_NAME, content: CONTENT },
      { signer, diadoc, sleep: () => Promise.reject(cause) },
      { fromBoxId: FROM, toBoxId: TO },
    );
    expect(result).toMatchObject({ messageId: 'msg-1', polls: 1, statusError: cause });
  });

  it('stops polling (keeping the ids) when aborted during polling', async () => {
    const controller = new AbortController();
    const signer = new FakeSigner();
    const diadoc = new FakeDiadoc();
    diadoc.documents = [{ DocflowStatus: status('Info') }];
    const result = await sendUtd(
      { fileName: FILE_NAME, content: CONTENT },
      {
        signer,
        diadoc,
        sleep: () => {
          controller.abort(new Error('stop'));
          return Promise.reject(new Error('aborted'));
        },
      },
      { fromBoxId: FROM, toBoxId: TO, signal: controller.signal },
    );
    expect(result).toMatchObject({ messageId: 'msg-1', polls: 1, outcome: 'pending' });
  });

  it('with timeoutMs 0 reads the status exactly once', async () => {
    const { diadoc, slept, run } = setup({ poll: { timeoutMs: 0 } });
    diadoc.documents = [{ DocflowStatus: status('Info') }];
    expect(await run()).toMatchObject({ polls: 1, final: false });
    expect(slept).toEqual([]);
  });
});

describe('sendUtd cancellation and options', () => {
  it('rethrows the abort reason without calling anything', async () => {
    const { signer, diadoc, run } = setup({ signal: AbortSignal.abort(new Error('shutdown')) });
    await expect(run()).rejects.toThrow('shutdown');
    expect(signer.signed).toHaveLength(0);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rethrows the abort reason when aborted during signing', async () => {
    const controller = new AbortController();
    const reason = new Error('shutdown');
    const { signer, diadoc, run } = setup({ signal: controller.signal });
    signer.sign = () => {
      controller.abort(reason);
      return Promise.reject(reason);
    };
    await expect(run()).rejects.toBe(reason);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects equal or empty box ids', async () => {
    await expect(setup({ toBoxId: FROM }).run()).rejects.toThrow(/differ/);
    await expect(setup({ fromBoxId: '' }).run()).rejects.toThrow(/fromBoxId/);
  });

  it('logs each step', async () => {
    const { logs, run } = setup();
    await run();
    expect(logs.join('\n')).toMatch(/parsed[\s\S]*signed[\s\S]*verified[\s\S]*posted[\s\S]*status/);
  });
});

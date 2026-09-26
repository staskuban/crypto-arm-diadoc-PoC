import { readFileSync, readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  DiadocAuthError,
  DiadocConflictError,
  DiadocError,
  DiadocOperationPendingError,
  DiadocPostOutcomeUnknownError,
  DiadocTokenDeadlineError,
  SHELF_MAX_BYTES,
  SHELF_UPLOAD_MAX_BYTES,
  type DocflowStatus,
  type Document,
  type DocumentRef,
  type Message,
  type MessagePrototype,
  type MessageToPost,
  type MessageValidationResult,
  type Organization,
  type PostMessageOptions,
  type RequestOptions,
  type ShelfUploadOptions,
  type SignatureInfo,
} from '../diadoc/index.js';
import {
  SignerNetworkError,
  SignerTimeoutError,
  type SignResult,
  type Signer,
  type VerifyResult,
} from '../signer/index.js';
import { derChildren, parseCmsSignedData, readDer } from '../asn1/index.js';
import { DIADOC_TEST_SIGNATURE, UtdError } from '../utd/index.js';
import { PipelineError } from './errors.js';
import { customDocumentIdFor } from './custom-document-id.js';
import { operationIdFor, type OperationKey } from './operation-id.js';
import { sendUtd, type PipelineDiadoc, type SendUtdInput, type SendUtdOptions } from './send.js';

const FIXTURES = new URL('../utd/fixtures/', import.meta.url);
const FILE_NAME = readdirSync(FIXTURES).find((f) => f.endsWith('.xml')) ?? '';
const CONTENT = readFileSync(new URL(FILE_NAME, FIXTURES));
const ID_FILE = FILE_NAME.slice(0, -'.xml'.length);

// A real detached CMS (КриптоАРМ Server, CN=cryptoarm.server.test) and its signer certificate. The
// fake verifier decides validity; the pipeline checks the structure and the signer.
const DER_SIGNATURE = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
const BER_SIGNATURE = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url),
);
const SIGNER_CERT = parseCmsSignedData(DER_SIGNATURE).certificates[0] ?? Buffer.alloc(0);
const THUMBPRINT = '0e84b59e46e4648fc3dc808eb94d58f4de673f1f';
const OTHER_CERT = readFileSync(
  new URL('../signer/fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
);
/** Inside the signer certificate's validity (2026-09-10 .. 2026-10-28). */
const NOW = Date.parse('2026-10-01T00:00:00Z');

const GUID = '6f9619ff-8b86-d011-b42d-00cf4fc964ff';
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`./fixtures/diadoc-s1/${name}.json`, import.meta.url), 'utf8'));

const FROM = 'from-box';
const TO = 'to-box';

const opId = (key: Partial<OperationKey> = {}): string =>
  operationIdFor({ fromBoxId: FROM, toBoxId: TO, idFile: ID_FILE, content: CONTENT, ...key });

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
  certificate = SIGNER_CERT;
  signed: Buffer[] = [];
  verified: { data: Buffer; signature: Buffer }[] = [];
  signResult: SignResult | Error = { signature: DER_SIGNATURE };
  verifyResult: VerifyResult | Error = {
    valid: true,
    signers: [{ valid: true, mathValid: true, thumbprint: THUMBPRINT, detached: true }],
  };

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
  getOptions: (RequestOptions | undefined)[] = [];
  canPostOptions: (RequestOptions | undefined)[] = [];
  onCanPostMessage: (() => Promise<MessageValidationResult>) | undefined;
  onGetDocument: (() => Promise<Document>) | undefined;
  onShelfUpload: (() => Promise<string>) | undefined;
  lookups: unknown[][] = [];
  message: Message | Error = new Error('GetMessage not expected');
  signatureInfo: SignatureInfo | Error = new Error('GetSignatureInfo not expected');

  canPostResult: MessageValidationResult | Error = { Errors: [] };
  shelfResult: string | Error = 'dd-api-shelf';
  postResult: Message | Error = POSTED;
  /** One entry per GetDocument call; the last one repeats. */
  documents: (Document | Error)[] = [{ DocflowStatus: status('Success', 'Подписан') }];

  canPostMessage(p: MessagePrototype, options?: RequestOptions): Promise<MessageValidationResult> {
    this.calls.push('canPostMessage');
    this.prototypes.push(p);
    this.canPostOptions.push(options);
    if (this.onCanPostMessage) return this.onCanPostMessage();
    return settle(this.canPostResult);
  }

  shelfUpload(content: Buffer, options?: ShelfUploadOptions): Promise<string> {
    this.calls.push('shelfUpload');
    this.uploads.push({ content, options });
    if (this.onShelfUpload) return this.onShelfUpload();
    return settle(this.shelfResult);
  }

  postMessage(message: MessageToPost, options: PostMessageOptions): Promise<Message> {
    this.calls.push('postMessage');
    this.posts.push({ message, options });
    return settle(this.postResult);
  }

  getDocument(ref: DocumentRef, options?: RequestOptions): Promise<Document> {
    this.calls.push('getDocument');
    this.refs.push(ref);
    this.getOptions.push(options);
    if (this.onGetDocument) return this.onGetDocument();
    const next = this.documents.length > 1 ? this.documents.shift() : this.documents[0];
    return settle(next ?? new Error('no document'));
  }

  getMessage(boxId: string, messageId: string, options?: RequestOptions): Promise<Message> {
    this.calls.push('getMessage');
    this.lookups.push([boxId, messageId, options]);
    return settle(this.message);
  }

  organizations: Record<string, Organization | Error> = {
    [FROM]: { IsTest: true, ShortName: 'Тестовая организация №1' },
    [TO]: { IsTest: true, ShortName: 'Тестовая организация №2' },
  };
  organizationOptions: (RequestOptions | undefined)[] = [];

  getOrganization(boxId: string, options?: RequestOptions): Promise<Organization> {
    this.calls.push(`getOrganization ${boxId}`);
    this.organizationOptions.push(options);
    return settle(this.organizations[boxId] ?? new Error(`unknown box ${boxId}`));
  }

  getSignatureInfo(ref: DocumentRef, options?: RequestOptions): Promise<SignatureInfo> {
    this.calls.push('getSignatureInfo');
    this.lookups.push([ref, options]);
    return settle(this.signatureInfo);
  }
}

function settle<T>(value: T | Error): Promise<T> {
  return value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
}

function setup(options: Partial<SendUtdOptions> = {}, testSignature = false) {
  const signer = new FakeSigner();
  const diadoc = new FakeDiadoc();
  let clock = NOW;
  const slept: number[] = [];
  const logs: string[] = [];
  const run = (input: SendUtdInput = { fileName: FILE_NAME, content: CONTENT }) =>
    sendUtd(
      input,
      {
        signer: testSignature ? DIADOC_TEST_SIGNATURE : signer,
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
          // D200: CanPostMessage requires a GUID CustomDocumentId.
          CustomDocumentId: customDocumentIdFor(opId()),
        },
      ],
    });

    const post = diadoc.posts[0];
    expect(post?.options.operationId).toBe(opId());
    expect(post?.message).toEqual({
      FromBoxId: FROM,
      ToBoxId: TO,
      DocumentAttachments: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФДОП',
          Version: 'utd970_05_03_01',
          SignedContent: { Content: CONTENT, Signature: DER_SIGNATURE },
          CustomDocumentId: customDocumentIdFor(opId()),
        },
      ],
    });
    expect(post?.message.DocumentAttachments[0]?.SignedContent.Content?.equals(CONTENT)).toBe(true);
    expect(diadoc.refs[0]).toEqual({ boxId: FROM, messageId: 'msg-1', entityId: 'doc-1' });

    expect(result).toEqual({
      operationId: post?.options.operationId,
      customDocumentId: customDocumentIdFor(opId()),
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
    const { diadoc, run } = setup({ precheck: false, customDocumentId: GUID });
    const result = await run();
    expect(diadoc.calls).not.toContain('canPostMessage');
    expect(diadoc.posts[0]?.message.DocumentAttachments[0]?.CustomDocumentId).toBe(GUID);
    expect(result.customDocumentId).toBe(GUID);
  });

  it('sends a given customDocumentId in the CanPostMessage prototype too', async () => {
    const { diadoc, run } = setup({ customDocumentId: GUID });
    await run();
    expect(diadoc.prototypes[0]?.DocumentPrototypes[0]?.CustomDocumentId).toBe(GUID);
  });

  it('derives the same CustomDocumentId on a retry and a new one on a resend (D200)', async () => {
    const first = setup();
    const again = setup();
    const resent = setup({ resend: 'r1' });
    await first.run();
    await again.run();
    await resent.run();
    const idOf = (d: typeof first.diadoc) =>
      d.posts[0]?.message.DocumentAttachments[0]?.CustomDocumentId;
    expect(idOf(first.diadoc)).toBe(idOf(again.diadoc));
    expect(idOf(resent.diadoc)).toBe(customDocumentIdFor(opId({ resend: 'r1' })));
    expect(idOf(resent.diadoc)).not.toBe(idOf(first.diadoc));
  });

  it.each([
    ['a free-form id', 'inv-42'],
    ['an empty string', ''],
    ['a GUID in braces', `{${GUID}}`],
  ])('refuses %s as customDocumentId before signing (D192)', async (_name, customDocumentId) => {
    const { signer, diadoc, run } = setup({ customDocumentId });
    await expect(run()).rejects.toThrow(/customDocumentId .* must be a GUID/);
    expect(signer.signed).toEqual([]);
    expect(diadoc.calls).toEqual([]);
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

describe('sendUtd shelf upload', () => {
  it('sends content above the single-request limit through the shelf as well', async () => {
    const { diadoc, run } = setup();
    const big = padded(SHELF_UPLOAD_MAX_BYTES + 1);
    const result = await run({ fileName: FILE_NAME, content: big });
    expect(diadoc.calls).toEqual(['canPostMessage', 'shelfUpload', 'postMessage', 'getDocument']);
    expect(diadoc.uploads[0]?.content.equals(big)).toBe(true);
    expect(result).toMatchObject({ contentPlacement: 'shelf', nameOnShelf: 'dd-api-shelf' });
  });

  it('passes the abort signal to the upload and rethrows its reason', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted');
    const { diadoc, run } = setup({ signal: controller.signal });
    diadoc.onShelfUpload = () => {
      controller.abort(reason);
      return Promise.reject(new DOMException('This operation was aborted', 'AbortError'));
    };
    await expect(run({ fileName: FILE_NAME, content: padded(600_000) })).rejects.toBe(reason);
    expect(diadoc.uploads[0]?.options?.signal).toBe(controller.signal);
    expect(diadoc.calls).not.toContain('postMessage');
  });
});

describe('sendUtd precheck abort', () => {
  it('passes the abort signal to CanPostMessage and rethrows its reason', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGTERM)');
    const { diadoc, run } = setup({ signal: controller.signal });
    diadoc.onCanPostMessage = () => {
      controller.abort(reason);
      // An aborted retry pause rejects with its own AbortError, not the reason.
      return Promise.reject(new DOMException('This operation was aborted', 'AbortError'));
    };
    await expect(run()).rejects.toBe(reason);
    expect(diadoc.canPostOptions).toEqual([{ signal: controller.signal }]);
    expect(diadoc.calls).toEqual(['canPostMessage']);
  });
});

describe('sendUtd operationId', () => {
  it('hashes ИдФайл, not the file name: the extension case does not make a second send', async () => {
    const lower = setup();
    const upper = setup();
    await lower.run();
    await upper.run({ fileName: `${ID_FILE}.XML`, content: CONTENT });
    expect(upper.diadoc.posts[0]?.options.operationId).toBe(opId());
    expect(lower.diadoc.posts[0]?.options.operationId).toBe(opId());
  });

  it('includes customDocumentId', async () => {
    const { diadoc, run } = setup({ customDocumentId: GUID });
    const result = await run();
    expect(diadoc.posts[0]?.options.operationId).toBe(opId({ customDocumentId: GUID }));
    expect(result.operationId).not.toBe(opId());
  });

  it('resend adds the salt: a new operationId, repeated for the same salt, reported back', async () => {
    const first = setup({ resend: 'retry-1' });
    const again = setup({ resend: 'retry-1' });
    const result = await first.run();
    await again.run();
    expect(first.diadoc.posts[0]?.options.operationId).toBe(opId({ resend: 'retry-1' }));
    expect(again.diadoc.posts[0]?.options.operationId).toBe(opId({ resend: 'retry-1' }));
    expect(result.operationId).not.toBe(opId());
    expect(result.resend).toBe('retry-1');
  });

  it('without resend the result has no resend field', async () => {
    const { run } = setup();
    expect(await run()).not.toHaveProperty('resend');
  });

  it('rejects an invalid resend salt before anything else', async () => {
    const { signer, run } = setup({ resend: 'a b' });
    await expect(run()).rejects.toThrow(/resend/);
    expect(signer.signed).toHaveLength(0);
  });

  it('is the same on a retry of the same document, although the signature changes', async () => {
    const first = setup();
    const second = setup();
    const resigned = Buffer.from(DER_SIGNATURE);
    resigned[resigned.length - 1] = (resigned.at(-1) ?? 0) ^ 0xff; // another signature value
    second.signer.signResult = { signature: resigned };
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

  it('rejects content above the documented shelf maximum before parsing', async () => {
    const { signer, run } = setup();
    const error = await failure(
      run({ fileName: FILE_NAME, content: Buffer.alloc(SHELF_MAX_BYTES + 1) }),
    );
    expect(error).toMatchObject({ code: 'CONTENT_TOO_LARGE', step: 'parse' });
    expect(error.message).toMatch(/400000000/);
    expect(signer.signed).toHaveLength(0);
  });

  // Relies on parseUtd refusing a blank buffer at once (55 ms today); it must not decode it all first.
  it('accepts content of exactly the shelf maximum past the size check', async () => {
    const { run } = setup();
    const error = await failure(
      run({ fileName: FILE_NAME, content: Buffer.alloc(SHELF_MAX_BYTES, 0x20) }),
    );
    expect(error).toMatchObject({ code: 'INVALID_UTD', step: 'parse' });
  });

  it('wraps a signer failure', async () => {
    const { signer, diadoc, run } = setup();
    const cause = new SignerTimeoutError('sign', 10);
    signer.signResult = cause;
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGN_FAILED', step: 'sign', cause });
    expect(diadoc.calls).toHaveLength(0);
  });

  it('does not repeat a root cause the signer error already names', async () => {
    const { signer, run } = setup();
    signer.signResult = new SignerNetworkError('sign', {
      cause: new TypeError('fetch failed', {
        cause: new Error('connect ECONNREFUSED 127.0.0.1:3037'),
      }),
    });
    // The pipeline's own "<step>: " prefix, then the signer message as is.
    expect((await failure(run())).message).toBe(
      'sign: sign: request failed: fetch failed: connect ECONNREFUSED 127.0.0.1:3037',
    );
  });

  it('fails fast when the signature does not verify', async () => {
    const { signer, diadoc, run } = setup();
    signer.verifyResult = { valid: false, signers: [], reason: 'no signatures in CMS' };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGNATURE_INVALID', step: 'verify' });
    expect(error.message).toMatch(/no signatures in CMS/);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('tells broken signature math from a certificate or chain problem', async () => {
    const math = setup();
    math.signer.verifyResult = {
      valid: false,
      signers: [{ valid: false, mathValid: false, chainValid: true }],
      reason: 'bad',
    };
    const mathError = await failure(math.run());
    expect(mathError).toMatchObject({ code: 'SIGNATURE_INVALID', step: 'verify' });
    expect(mathError.message).toMatch(/math is invalid/);
    expect(mathError.details).toEqual([{ valid: false, mathValid: false, chainValid: true }]);

    const chain = setup();
    chain.signer.verifyResult = {
      valid: false,
      signers: [{ valid: false, mathValid: true, chainValid: false, thumbprint: THUMBPRINT }],
      reason: 'untrusted root',
    };
    const chainError = await failure(chain.run());
    expect(chainError).toMatchObject({ code: 'CERTIFICATE_INVALID', step: 'verify' });
    expect(chainError.message).toMatch(/math is valid.*chain.*untrusted root.*2026-10-28/);
    expect(chain.diadoc.calls).toHaveLength(0);
  });

  it('refuses to sign with an expired signer certificate, naming the expiry date', async () => {
    const signer = new FakeSigner();
    const diadoc = new FakeDiadoc();
    const error = await failure(
      sendUtd(
        { fileName: FILE_NAME, content: CONTENT },
        { signer, diadoc, now: () => Date.parse('2026-10-28T12:32:12Z') },
        { fromBoxId: FROM, toBoxId: TO },
      ),
    );
    expect(error).toMatchObject({ code: 'CERTIFICATE_INVALID', step: 'sign' });
    expect(error.message).toContain(`${THUMBPRINT} expired on 2026-10-28T12:32:11.000Z`);
    expect(signer.signed).toHaveLength(0);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects an unreadable signer certificate before signing', async () => {
    const { signer, run } = setup();
    signer.certificate = Buffer.from([0x30, 0x00]);
    expect(await failure(run())).toMatchObject({ code: 'CERTIFICATE_INVALID', step: 'sign' });
    expect(signer.signed).toHaveLength(0);
  });

  it('rejects a signature made by another certificate before verifying it', async () => {
    const { signer, diadoc, run } = setup();
    signer.certificate = OTHER_CERT; // the КриптоПро test CA: valid now, but not the CMS signer
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGNATURE_POLICY_VIOLATION', step: 'policy' });
    expect(error.message).toMatch(/not by the configured certificate/);
    expect(signer.verified).toHaveLength(0);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects a verified signature when the verifier reports another signer', async () => {
    const { signer, diadoc, run } = setup();
    signer.verifyResult = {
      valid: true,
      signers: [{ valid: true, mathValid: true, thumbprint: 'ffff' }],
    };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'SIGNATURE_POLICY_VIOLATION', step: 'verify' });
    expect(error.message).toMatch(/thumbprint ffff, expected 0e84/);
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
    expect(error).toMatchObject({ code: 'INVALID_SIGNATURE', step: 'policy' });
    expect(signer.verified).toHaveLength(0);
    expect(diadoc.calls).toHaveLength(0);
  });

  it('rejects a malformed SignerInfo (version 3 with issuerAndSerialNumber) as INVALID_SIGNATURE', async () => {
    const signedData = derChildren(
      derChildren(readDer(DER_SIGNATURE))[1] ?? readDer(DER_SIGNATURE),
    )[0];
    const signerInfo = derChildren(
      derChildren(signedData ?? readDer(DER_SIGNATURE)).at(-1) ?? readDer(DER_SIGNATURE),
    )[0];
    if (signerInfo === undefined) throw new Error('fixture');
    const versionAt = signerInfo.offset + signerInfo.raw.length - signerInfo.content.length + 2;
    const v3 = Buffer.from(DER_SIGNATURE);
    expect(v3[versionAt]).toBe(1);
    v3[versionAt] = 3;
    const { signer, diadoc, run } = setup();
    signer.signResult = { signature: v3 };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'INVALID_SIGNATURE', step: 'policy' });
    expect(error.message).toMatch(/SignerInfo version must be 1/);
    expect(signer.verified).toHaveLength(0);
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
    expect(error.operationId).toBe(opId());
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

describe('sendUtd token failures (R2 minor 11)', () => {
  const authError = () =>
    new DiadocAuthError(
      'Token endpoint https://idp/token -> 400: invalid_grant',
      400,
      'invalid_grant',
    );

  it('reports a token failure in CanPostMessage as DIADOC_AUTH, not PRECHECK_FAILED', async () => {
    const { diadoc, run } = setup();
    const cause = authError();
    diadoc.canPostResult = cause;
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'DIADOC_AUTH', step: 'precheck', cause });
    expect(error.operationId).toBe(opId());
    expect(error.message).toMatch(/invalid_grant/);
  });

  it('reports a token failure in the shelf upload as DIADOC_AUTH', async () => {
    const { diadoc, run } = setup({ precheck: false });
    diadoc.shelfResult = authError();
    const error = await failure(run({ fileName: FILE_NAME, content: padded(600_000) }));
    expect(error).toMatchObject({ code: 'DIADOC_AUTH', step: 'upload' });
    expect(diadoc.calls).not.toContain('postMessage');
  });

  it('reports a token failure before PostMessage was sent as DIADOC_AUTH', async () => {
    const { diadoc, run } = setup({ precheck: false });
    diadoc.postResult = authError();
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'DIADOC_AUTH', step: 'post' });
    expect(error.operationId).toBe(opId());
    expect(error.message).not.toMatch(/may have been posted/);
  });

  it('keeps "may have been posted" when the token failed after a PostMessage request', async () => {
    const { diadoc, run } = setup({ precheck: false });
    diadoc.postResult = new DiadocPostOutcomeUnknownError(opId(), authError());
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'POST_FAILED', step: 'post' });
    expect(error.message).toMatch(/may have been posted/);
    expect(error.message).toMatch(/invalid_grant/);
  });

  it('keeps the step code when the token was not asked for lack of time', async () => {
    const { diadoc, run } = setup({ precheck: false });
    diadoc.postResult = new DiadocTokenDeadlineError('Token endpoint not asked: deadline');
    expect(await failure(run())).toMatchObject({ code: 'POST_FAILED', step: 'post' });
  });

  it('finds a token failure wrapped as a cause', async () => {
    const { diadoc, run } = setup();
    diadoc.canPostResult = new Error('outer', { cause: authError() });
    expect(await failure(run())).toMatchObject({ code: 'DIADOC_AUTH', step: 'precheck' });
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
    expect(error.operationId).toBe(opId());
    expect(error.message).toContain(body);
    expect(diadoc.calls).not.toContain('getDocument');
  });

  it('wraps any other PostMessage failure', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = new DiadocError('POST', '/V3/PostMessage', 400, 'bad signature');
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'POST_FAILED', step: 'post' });
    expect(error.message).not.toMatch(/may have been posted/);
  });

  it('says an ambiguous PostMessage failure may have been posted', async () => {
    const { diadoc, run } = setup();
    const operationId = opId();
    diadoc.postResult = new DiadocPostOutcomeUnknownError(
      operationId,
      new DiadocError('POST', '/V3/PostMessage', 502, 'bad gateway'),
    );
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'POST_FAILED', step: 'post', operationId });
    expect(error.message).toMatch(/may have been posted/);
    expect(error.message).toMatch(/502/);
    expect(error.message).toMatch(/before sending again/);
  });

  it('truncates a long 409 body in the message', async () => {
    const { diadoc, run } = setup();
    const body = `duplicate ${'x'.repeat(10_000)}`;
    diadoc.postResult = new DiadocConflictError('POST', '/V3/PostMessage', body);
    const error = await failure(run());
    expect(error.code).toBe('ALREADY_SENT');
    expect(error.message.length).toBeLessThan(1100);
  });

  it('reports a PostMessage still in progress as POST_PENDING (retry is safe)', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = new DiadocOperationPendingError('op', 10);
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'POST_PENDING', step: 'post' });
    expect(error.message).toMatch(/run send again/);
  });

  it('tells a pending or ambiguous resend to repeat with the same salt', async () => {
    const pending = setup({ resend: 'r-7' });
    pending.diadoc.postResult = new DiadocOperationPendingError('op', 10);
    expect((await failure(pending.run())).message).toMatch(/same resend salt r-7/);

    const unknown = setup({ resend: 'r-7' });
    unknown.diadoc.postResult = new DiadocPostOutcomeUnknownError(
      'op',
      new DiadocError('POST', '/V3/PostMessage', 502, 'bad gateway'),
    );
    expect((await failure(unknown.run())).message).toMatch(/same resend salt r-7/);
  });

  it('fails with the messageId when the message has no document entity', async () => {
    const { diadoc, run } = setup();
    diadoc.postResult = { MessageId: 'msg-2', Entities: [] };
    const error = await failure(run());
    expect(error).toMatchObject({ code: 'NO_DOCUMENT_ENTITY', step: 'post', messageId: 'msg-2' });
  });
});

describe('sendUtd sender signature check (D203)', () => {
  // The live S1 doc2 answers: math valid, certificate not trusted, DeliveryFailureNotification.
  const liveMessage = fixture('doc2-message') as Message;
  const liveDocument = fixture('doc2-document') as Document;
  const posted: Message = {
    MessageId: liveMessage.MessageId,
    Entities: (liveMessage.Entities ?? []).filter(
      (e) =>
        e.AttachmentType !== 'DeliveryFailureNotification' &&
        e.AttachmentType !== 'SignatureVerificationReport',
    ),
  };

  function rejected(options: Partial<SendUtdOptions> = {}) {
    const s = setup(options);
    s.diadoc.postResult = posted;
    s.diadoc.documents = [liveDocument];
    s.diadoc.message = liveMessage;
    s.diadoc.signatureInfo = fixture('doc2-signatureinfo') as SignatureInfo;
    return s;
  }

  it('on «Ошибка в подписи» reads the message and the signature and reports why', async () => {
    const { diadoc, logs, run } = rejected();
    const result = await run();

    expect(diadoc.calls).toEqual([
      'canPostMessage',
      'postMessage',
      'getDocument',
      'getMessage',
      'getSignatureInfo',
    ]);
    expect(diadoc.lookups[1]?.[0]).toEqual({
      boxId: FROM,
      messageId: liveMessage.MessageId,
      entityId: '763850b8-f00d-4938-b46b-ba2e8a9e5f89',
    });
    expect(result).toMatchObject({
      outcome: 'error',
      signatureCheck: {
        senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
        reason: 'certificate',
        mathValid: true,
        certificateValid: false,
        delivered: false,
      },
    });
    expect(logs.join('\n')).toMatch(/\[SENDER_CERTIFICATE_REJECTED\]/);
  });

  it('checks an invalid sender signature even while the status is not an error yet', async () => {
    const { diadoc, run } = rejected();
    diadoc.documents = [
      {
        ...liveDocument,
        DocflowStatus: status('Warning', 'Ожидается подпись контрагента'),
      },
    ];
    const result = await run();
    expect(result.outcome).toBe('pending');
    expect(result.signatureCheck?.reason).toBe('certificate');
  });

  it('a failed lookup does not fail the posted send', async () => {
    const { diadoc, run } = rejected();
    diadoc.message = new DiadocError('GET', '/V5/GetMessage', 503, 'busy');
    const result = await run();
    expect(result).toMatchObject({ outcome: 'error', messageId: liveMessage.MessageId });
    expect(result.signatureCheck).toMatchObject({ reason: 'unknown' });
    expect(result.signatureCheck?.lookupErrors[0]).toMatch(/^GetMessage: /);
    expect(diadoc.calls).not.toContain('getSignatureInfo');
  });

  it('gives the lookups their own deadline and the abort signal', async () => {
    const controller = new AbortController();
    const { diadoc, run } = rejected({ signal: controller.signal });
    await run();
    // Past the poll deadline (NOW + 10 s), and room for a token refresh (IdP timeout 30 s).
    expect(diadoc.lookups[0]?.[2]).toEqual({ deadline: NOW + 90_000, signal: controller.signal });
    expect(diadoc.lookups[1]?.[1]).toEqual({ deadline: NOW + 90_000, signal: controller.signal });
  });

  it('does not look anything up for a success or a valid signature', async () => {
    const { diadoc, run } = setup();
    const result = await run();
    expect(diadoc.calls).not.toContain('getMessage');
    expect(result.signatureCheck).toBeUndefined();
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

  it('keeps polling after a 404 (the new document may not be visible yet)', async () => {
    const { diadoc, run } = setup();
    diadoc.documents = [
      new DiadocError('GET', '/V3/GetDocument', 404, 'not found'),
      { DocflowStatus: status('Success', 'Подписан') },
    ];
    const result = await run();
    expect(result).toMatchObject({ outcome: 'success', final: true, polls: 2 });
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
      { signer, diadoc, now: () => NOW, sleep: () => Promise.reject(cause) },
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
        now: () => NOW,
        sleep: () => {
          controller.abort(new Error('stop'));
          return Promise.reject(new Error('aborted'));
        },
      },
      { fromBoxId: FROM, toBoxId: TO, signal: controller.signal },
    );
    expect(result).toMatchObject({ messageId: 'msg-1', polls: 1, outcome: 'pending' });
  });

  it('gives GetDocument the polling deadline and the abort signal', async () => {
    const controller = new AbortController();
    const { diadoc, run } = setup({ signal: controller.signal });
    diadoc.documents = [{ DocflowStatus: status('Success') }];
    await run();
    expect(diadoc.getOptions).toEqual([{ deadline: NOW + 10_000, signal: controller.signal }]);
  });

  it('an abort during GetDocument ends polling without a statusError', async () => {
    const controller = new AbortController();
    const { diadoc, run } = setup({ signal: controller.signal });
    const reason = new Error('stop');
    diadoc.onGetDocument = () => {
      controller.abort(reason);
      return Promise.reject(reason);
    };
    const result = await run();
    expect(result).toMatchObject({ messageId: 'msg-1', polls: 1, outcome: 'pending' });
    expect(result.statusError).toBeUndefined();
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

describe('sendUtd with the Diadoc test signature (SIGNER_KIND=diadoc-test, D202)', () => {
  const testOpId = (key: Partial<OperationKey> = {}): string =>
    opId({ testSignature: true, ...key });

  it('checks both boxes are test organisations, skips our signer and posts SignWithTestSignature', async () => {
    const { signer, diadoc, logs, run } = setup({}, true);

    const result = await run();

    expect(signer.signed).toEqual([]);
    expect(signer.verified).toEqual([]);
    expect(diadoc.calls).toEqual([
      `getOrganization ${FROM}`,
      `getOrganization ${TO}`,
      'canPostMessage',
      'postMessage',
      'getDocument',
    ]);
    const post = diadoc.posts[0];
    expect(post?.options.operationId).toBe(testOpId());
    expect(post?.message.DocumentAttachments[0]).toEqual({
      TypeNamedId: 'UniversalTransferDocument',
      Function: 'СЧФДОП',
      Version: 'utd970_05_03_01',
      SignedContent: { Content: CONTENT, SignWithTestSignature: true },
      CustomDocumentId: customDocumentIdFor(testOpId()),
    });
    expect(result).toMatchObject({
      operationId: testOpId(),
      customDocumentId: customDocumentIdFor(testOpId()),
      testSignature: true,
      outcome: 'success',
    });
    expect(testOpId()).not.toBe(opId());
    expect(logs.join('\n')).toMatch(/Diadoc test signature/);
  });

  it('uses the shelf for large content like a real send', async () => {
    const { diadoc, run } = setup({}, true);
    const content = padded(SHELF_UPLOAD_MAX_BYTES + 1);

    const result = await run({ fileName: FILE_NAME, content });

    expect(diadoc.uploads[0]?.content.equals(content)).toBe(true);
    expect(diadoc.posts[0]?.message.DocumentAttachments[0]?.SignedContent).toEqual({
      NameOnShelf: 'dd-api-shelf',
      SignWithTestSignature: true,
    });
    expect(result.contentPlacement).toBe('shelf');
  });

  it('runs the box check even without the precheck', async () => {
    const { diadoc, run } = setup({ precheck: false }, true);
    await run();
    expect(diadoc.calls.slice(0, 3)).toEqual([
      `getOrganization ${FROM}`,
      `getOrganization ${TO}`,
      'postMessage',
    ]);
  });

  it.each<[string, Organization]>([
    ['IsTest false', { IsTest: false, ShortName: 'ООО Реальная' }],
    ['no IsTest', { ShortName: 'ООО Без флага' }],
  ])(
    'refuses a recipient that is not a test organisation (%s) before any side effect',
    async (_n, org) => {
      const { diadoc, run } = setup({}, true);
      diadoc.organizations[TO] = org;

      const error = await failure(run());

      expect(error.code).toBe('TEST_SIGNATURE_REFUSED');
      expect(error.step).toBe('precheck');
      expect(error.operationId).toBe(testOpId());
      expect(error.message).toContain(TO);
      expect(error.message).toContain(org.ShortName);
      expect(diadoc.calls).toEqual([`getOrganization ${FROM}`, `getOrganization ${TO}`]);
    },
  );

  it('refuses a sender that is not a test organisation', async () => {
    const { diadoc, run } = setup({ precheck: false }, true);
    diadoc.organizations[FROM] = { IsTest: false };

    const error = await failure(run());

    expect(error.code).toBe('TEST_SIGNATURE_REFUSED');
    expect(error.message).toContain(FROM);
    expect(diadoc.calls).not.toContain('postMessage');
  });

  it('fails as PRECHECK_FAILED when GetOrganization fails, DIADOC_AUTH on a token error', async () => {
    const first = setup({}, true);
    first.diadoc.organizations[TO] = new DiadocError('GET', '/GetOrganization', 403, 'Forbidden');
    const error = await failure(first.run());
    expect(error.code).toBe('PRECHECK_FAILED');
    expect(first.diadoc.calls).not.toContain('postMessage');

    const second = setup({}, true);
    second.diadoc.organizations[FROM] = new DiadocAuthError(
      'token endpoint said 400',
      400,
      'invalid_client',
    );
    expect((await failure(second.run())).code).toBe('DIADOC_AUTH');
  });

  it('passes the abort signal to GetOrganization', async () => {
    const controller = new AbortController();
    const { diadoc, run } = setup({ signal: controller.signal }, true);
    await run();
    expect(diadoc.organizationOptions[0]?.signal).toBe(controller.signal);
  });

  it('a real send does not call GetOrganization', async () => {
    const { diadoc, run } = setup();
    await run();
    expect(diadoc.calls.some((c) => c.startsWith('getOrganization'))).toBe(false);
  });
});

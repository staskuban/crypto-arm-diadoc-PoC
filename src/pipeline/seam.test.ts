// Seam tests (R1 minor 15-16): the real RefreshTokenAuth, DiadocClient and ServerCmsSigner under
// sendUtd, with one mocked fetch standing in for the IdP, КриптоАРМ Server and Diadoc. Checks what
// actually goes over the wire: the exact УПД bytes, the DER signature, auth, shelf/inline and retries.
import { readFileSync, readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { parseCmsSignedData } from '../asn1/index.js';
import {
  DiadocClient,
  RefreshTokenAuth,
  SHELF_UPLOAD_MAX_BYTES,
  type Message,
} from '../diadoc/index.js';
import { ServerCmsSigner } from '../signer/index.js';
import { INLINE_CONTENT_LIMIT } from '../utd/index.js';
import { PipelineError } from './errors.js';
import { operationIdFor } from './operation-id.js';
import { sendUtd, type SendUtdResult } from './send.js';

const FIXTURES = new URL('../utd/fixtures/', import.meta.url);
const XML_FIXTURES = readdirSync(FIXTURES).filter((f) => f.endsWith('.xml'));
const FILE_NAME = XML_FIXTURES[0] ?? '';
const CONTENT = readFileSync(new URL(FILE_NAME, FIXTURES));
const ID_FILE = FILE_NAME.slice(0, -'.xml'.length);

// Real /cms/sign output (BER, indefinite lengths) and OpenSSL's DER re-encoding of it.
const BER_SIGNATURE = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url),
);
const DER_SIGNATURE = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
const SIGNER_CERT = parseCmsSignedData(DER_SIGNATURE).certificates[0] ?? Buffer.alloc(0);
const THUMBPRINT = '0e84b59e46e4648fc3dc808eb94d58f4de673f1f';
/** Inside the signer certificate's validity (2026-09-10 .. 2026-10-28). */
const NOW = Date.parse('2026-10-01T00:00:00Z');

/** operationIdFor(from-box, to-box, the fixture) as of T8 (key domain v2). */
const GOLDEN_OPERATION_ID = '828cad14369f9311fc67f8e7c03498e88f5c808cee300c0a1529fd162bb1aca0';
const FROM = 'from-box';
const TO = 'to-box';
const IDP = 'https://idp.test/connect/token';
const SIGNER_URL = 'http://signer.test:3037';
const DIADOC_URL = 'https://diadoc.test';

const POSTED: Message = {
  MessageId: 'msg-1',
  Entities: [
    { EntityType: 'Attachment', EntityId: 'sig-1', ParentEntityId: 'doc-1' },
    { EntityType: 'Attachment', EntityId: 'doc-1', ParentEntityId: '' },
  ],
};

/** Pads the УПД with whitespace before the closing root tag: still the same valid document. */
function padded(size: number): Buffer {
  const at = CONTENT.lastIndexOf(Buffer.from('</', 'latin1'));
  return Buffer.concat([
    CONTENT.subarray(0, at),
    Buffer.alloc(size - CONTENT.length, 0x20),
    CONTENT.subarray(at),
  ]);
}

interface Recorded {
  method: string;
  url: URL;
  headers: Headers;
  body: Buffer;
  redirect: RequestInit['redirect'];
}

type Handler = (req: Recorded) => Response;

const json = (value: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

/**
 * One fetch for all three services, routed by `host + path`. Each route has a queue of one-shot
 * handlers (`once`) in front of its default handler.
 */
class FakeNet {
  requests: Recorded[] = [];
  private readonly once = new Map<string, Handler[]>();
  private readonly defaults = new Map<string, Handler>();
  tokens = 0;
  shelf = new Map<string, Buffer[]>();

  constructor() {
    this.on(IDP, () => {
      this.tokens++;
      return json({
        access_token: `at-${String(this.tokens)}`,
        refresh_token: `rt-${String(this.tokens + 1)}`,
        expires_in: 3600,
      });
    });
    this.on(`${SIGNER_URL}/cms/sign`, () => json({ cms: BER_SIGNATURE.toString('base64') }, 201));
    this.on(`${SIGNER_URL}/cms/verify`, (req) => {
      const body = JSON.parse(req.body.toString('utf8')) as { cms: string };
      // Answers like the real server only for the DER form of the fixture signature.
      const ok = Buffer.from(body.cms, 'base64').equals(DER_SIGNATURE);
      return json(
        {
          isValidSign: ok,
          signs: [
            {
              isValidSign: ok,
              isDetached: true,
              certificate: { thumbprint: THUMBPRINT, subjectName: 'CN=cryptoarm.server.test' },
              extVerifyInfo: { mathValidity: ok },
            },
          ],
        },
        201,
      );
    });
    this.on(`${DIADOC_URL}/CanPostMessage`, () => json({ Errors: [] }));
    this.on(`${DIADOC_URL}/V2/ShelfUpload`, (req) => {
      this.shelf.set('shelf-v2', [req.body]);
      return new Response('shelf-v2', { headers: { 'content-type': 'text/plain' } });
    });
    this.on(`${DIADOC_URL}/ShelfUploadPartInit`, (req) => {
      this.shelf.set('shelf-parts', [req.body]);
      return json('shelf-parts');
    });
    this.on(`${DIADOC_URL}/ShelfUploadPart`, (req) => {
      const q = req.url.searchParams;
      const parts = this.shelf.get(q.get('fileName') ?? '') ?? [];
      parts[Number(q.get('partIndex'))] = req.body;
      return json([]);
    });
    this.on(`${DIADOC_URL}/V3/PostMessage`, () => json(POSTED));
    this.on(`${DIADOC_URL}/V3/GetDocument`, () =>
      json({ DocflowStatus: { PrimaryStatus: { Severity: 'Success', StatusText: 'Подписан' } } }),
    );
  }

  on(route: string, handler: Handler): void {
    this.defaults.set(route, handler);
  }

  next(route: string, ...handlers: Handler[]): void {
    this.once.set(route, [...(this.once.get(route) ?? []), ...handlers]);
  }

  to(path: string): Recorded[] {
    return this.requests.filter((r) => `${r.url.origin}${r.url.pathname}`.endsWith(path));
  }

  fetch: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const raw = init?.body;
    const body =
      raw === undefined || raw === null
        ? Buffer.alloc(0)
        : typeof raw === 'string'
          ? Buffer.from(raw, 'utf8')
          : raw instanceof Uint8Array
            ? Buffer.from(raw)
            : undefined;
    if (body === undefined) throw new Error('FakeNet: unsupported request body type');
    const req: Recorded = {
      method: init?.method ?? 'GET',
      url,
      headers: new Headers(init?.headers),
      body,
      redirect: init?.redirect,
    };
    this.requests.push(req);
    const route = `${url.origin}${url.pathname}`;
    const handler = this.once.get(route)?.shift() ?? this.defaults.get(route);
    if (!handler) return Promise.resolve(new Response(`no route ${route}`, { status: 404 }));
    // A throwing handler is a network failure (a rejected fetch).
    return Promise.resolve().then(() => handler(req));
  };
}

interface Setup {
  net: FakeNet;
  sleeps: number[];
  rotated: string[];
  send: (content: Buffer) => Promise<SendUtdResult>;
}

function setup(): Setup {
  const net = new FakeNet();
  const sleeps: number[] = [];
  const rotated: string[] = [];
  const sleep = (ms: number): Promise<void> => {
    sleeps.push(ms);
    return Promise.resolve();
  };
  const now = (): number => NOW;
  const auth = new RefreshTokenAuth({
    clientId: 'client',
    clientSecret: 'secret',
    refreshToken: 'rt-1',
    tokenUrl: IDP,
    onRefreshTokenRotated: (t) => {
      rotated.push(t);
    },
    fetch: net.fetch,
    sleep,
    now,
  });
  const diadoc = new DiadocClient({ auth, baseUrl: DIADOC_URL, fetch: net.fetch, sleep, now });
  const signer = new ServerCmsSigner({
    baseUrl: SIGNER_URL,
    certificate: SIGNER_CERT,
    apiKey: 'signer-key',
    fetch: net.fetch,
  });
  return {
    net,
    sleeps,
    rotated,
    send: (content) =>
      sendUtd(
        { fileName: FILE_NAME, content },
        { signer, diadoc, sleep, now },
        { fromBoxId: FROM, toBoxId: TO },
      ),
  };
}

interface WireAttachment {
  TypeNamedId: string;
  Function: string;
  Version: string;
  SignedContent: { Content?: string; Signature?: string; NameOnShelf?: string };
}

function postedAttachment(req: Recorded | undefined): WireAttachment {
  const body = JSON.parse(req?.body.toString('utf8') ?? '{}') as {
    FromBoxId: string;
    ToBoxId: string;
    DocumentAttachments: WireAttachment[];
  };
  expect(body.FromBoxId).toBe(FROM);
  expect(body.ToBoxId).toBe(TO);
  expect(body.DocumentAttachments).toHaveLength(1);
  const [attachment] = body.DocumentAttachments;
  if (attachment === undefined) throw new Error('no attachment');
  return attachment;
}

const b64 = (s: string | undefined): Buffer => Buffer.from(s ?? '', 'base64');

/** Pinned here, not read from the code under test: 500 KB inline (D3), 3 MB per shelf request. */
const INLINE_LIMIT = 500_000;
const PART = 3_000_000;

const signedData = (req: Recorded | undefined): Buffer =>
  b64((JSON.parse(req?.body.toString('utf8') ?? '{}') as { data?: string }).data);

describe('seam thresholds', () => {
  it('match the documented limits', () => {
    expect(XML_FIXTURES).toHaveLength(1);
    expect(INLINE_CONTENT_LIMIT).toBe(INLINE_LIMIT);
    expect(SHELF_UPLOAD_MAX_BYTES).toBe(PART);
  });
});

describe('sendUtd over the real clients (seam)', () => {
  it('sends the exact УПД bytes inline with the DER-normalised КриптоАРМ Server signature', async () => {
    const { net, rotated, send } = setup();

    const result = await send(CONTENT);

    // Golden value: a silent change of the key formula breaks idempotency across versions (D7).
    expect(result.operationId).toBe(GOLDEN_OPERATION_ID);
    expect(result).toMatchObject({
      operationId: operationIdFor({
        fromBoxId: FROM,
        toBoxId: TO,
        idFile: ID_FILE,
        content: CONTENT,
      }),
      messageId: 'msg-1',
      entityId: 'doc-1',
      contentPlacement: 'inline',
      outcome: 'success',
      final: true,
    });

    // Order across the three services.
    expect(net.requests.map((r) => r.url.pathname)).toEqual([
      '/cms/sign',
      '/cms/verify',
      '/connect/token',
      '/CanPostMessage',
      '/V3/PostMessage',
      '/V3/GetDocument',
    ]);

    // No client follows redirects (R1 M1): IdP, signer and Diadoc alike.
    expect(net.requests.map((r) => r.redirect)).toEqual(net.requests.map(() => 'error'));

    // Signer: the windows-1251 bytes unchanged, detached CAdES-BES, API key header.
    const [signReq] = net.to('/cms/sign');
    expect(signReq?.headers.get('x-api-key')).toBe('signer-key');
    const signBody = JSON.parse(signReq?.body.toString('utf8') ?? '{}') as Record<string, unknown>;
    expect(b64(signBody.data as string).equals(CONTENT)).toBe(true);
    expect(b64(signBody.cert as string).equals(SIGNER_CERT)).toBe(true);
    expect(signBody).toMatchObject({ detached: true, cadesStandard: 'CAdES-BES' });

    // Verify sees the DER form, not the raw BER.
    const [verifyReq] = net.to('/cms/verify');
    const verifyBody = JSON.parse(verifyReq?.body.toString('utf8') ?? '{}') as Record<
      string,
      string
    >;
    expect(b64(verifyBody.cms).equals(DER_SIGNATURE)).toBe(true);
    expect(b64(verifyBody.data).equals(CONTENT)).toBe(true);

    // IdP: refresh token flow, the rotated refresh token handed to the caller.
    const [tokenReq] = net.to('/connect/token');
    expect(Object.fromEntries(new URLSearchParams(tokenReq?.body.toString('utf8')))).toEqual({
      grant_type: 'refresh_token',
      client_id: 'client',
      client_secret: 'secret',
      refresh_token: 'rt-1',
    });
    expect(tokenReq?.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(rotated).toEqual(['rt-2']);

    // Precheck: the prototype only, no content or signature.
    const [precheck] = net.to('/CanPostMessage');
    expect(JSON.parse(precheck?.body.toString('utf8') ?? '{}')).toEqual({
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

    // Diadoc: one token for every call, the operationId on PostMessage.
    for (const r of net.requests.filter((q) => q.url.origin === DIADOC_URL)) {
      expect(r.headers.get('authorization')).toBe('Bearer at-1');
    }
    const [postReq] = net.to('/V3/PostMessage');
    expect(postReq?.url.searchParams.get('operationId')).toBe(result.operationId);
    expect(postReq?.headers.get('content-type')).toBe('application/json; charset=utf-8');
    const attachment = postedAttachment(postReq);
    expect(attachment).toMatchObject({
      TypeNamedId: 'UniversalTransferDocument',
      Function: 'СЧФДОП',
      Version: 'utd970_05_03_01',
    });
    expect(attachment.SignedContent.NameOnShelf).toBeUndefined();
    expect(b64(attachment.SignedContent.Content).equals(CONTENT)).toBe(true);
    const signature = b64(attachment.SignedContent.Signature);
    expect(signature.equals(DER_SIGNATURE)).toBe(true);
    expect(signature.equals(BER_SIGNATURE)).toBe(false);

    const [getReq] = net.to('/V3/GetDocument');
    expect(Object.fromEntries(getReq?.url.searchParams ?? [])).toMatchObject({
      boxId: FROM,
      messageId: 'msg-1',
      entityId: 'doc-1',
    });
  });

  it('refreshes the access token once when Diadoc answers 401 and repeats the request', async () => {
    const { net, rotated, send } = setup();
    net.next(`${DIADOC_URL}/CanPostMessage`, () => new Response('expired', { status: 401 }));

    await expect(send(CONTENT)).resolves.toMatchObject({ outcome: 'success' });

    expect(net.tokens).toBe(2);
    const auths = net.to('/CanPostMessage').map((r) => r.headers.get('authorization'));
    expect(auths).toEqual(['Bearer at-1', 'Bearer at-2']);
    // The second refresh used the rotated refresh token.
    const second = net.to('/connect/token')[1];
    expect(new URLSearchParams(second?.body.toString('utf8')).get('refresh_token')).toBe('rt-2');
    expect(net.to('/V3/PostMessage')[0]?.headers.get('authorization')).toBe('Bearer at-2');
    expect(rotated).toEqual(['rt-2', 'rt-3']);
  });

  it(`keeps ${String(INLINE_LIMIT - 1)} B inline`, async () => {
    const { net, send } = setup();
    const content = padded(INLINE_LIMIT - 1);

    await expect(send(content)).resolves.toMatchObject({ contentPlacement: 'inline' });

    expect(net.requests.filter((r) => r.url.pathname.includes('Shelf'))).toHaveLength(0);
    expect(signedData(net.to('/cms/sign')[0]).equals(content)).toBe(true);
    expect(signedData(net.to('/cms/verify')[0]).equals(content)).toBe(true);
    const attachment = postedAttachment(net.to('/V3/PostMessage')[0]);
    expect(b64(attachment.SignedContent.Content).equals(content)).toBe(true);
  });

  it(`puts ${String(INLINE_LIMIT)} B on the shelf with one V2/ShelfUpload`, async () => {
    const { net, send } = setup();
    const content = padded(INLINE_LIMIT);

    const result = await send(content);

    expect(result).toMatchObject({ contentPlacement: 'shelf', nameOnShelf: 'shelf-v2' });
    const [upload] = net.to('/V2/ShelfUpload');
    expect(upload?.headers.get('content-type')).toBe('application/octet-stream');
    expect(upload?.headers.get('authorization')).toBe('Bearer at-1');
    expect(upload?.url.searchParams.get('fileExtension')).toBe('.xml');
    expect(upload?.body.equals(content)).toBe(true);
    expect(net.to('/ShelfUploadPartInit')).toHaveLength(0);
    // The signer signed and verified the whole large file too.
    expect(signedData(net.to('/cms/sign')[0]).equals(content)).toBe(true);
    expect(signedData(net.to('/cms/verify')[0]).equals(content)).toBe(true);

    const attachment = postedAttachment(net.to('/V3/PostMessage')[0]);
    expect(attachment.SignedContent).toEqual({
      NameOnShelf: 'shelf-v2',
      Signature: DER_SIGNATURE.toString('base64'),
    });
  });

  it(`uploads exactly ${String(PART)} B in one V2/ShelfUpload`, async () => {
    const { net, send } = setup();
    const content = padded(PART);

    await expect(send(content)).resolves.toMatchObject({ nameOnShelf: 'shelf-v2' });

    expect(net.to('/V2/ShelfUpload')[0]?.body.equals(content)).toBe(true);
    expect(net.to('/ShelfUploadPartInit')).toHaveLength(0);
    expect(signedData(net.to('/cms/verify')[0]).equals(content)).toBe(true);
  });

  it('uploads more than 3 MB in parts, re-sends a missing part, and a 503 repeats the same bytes', async () => {
    const { net, sleeps, send } = setup();
    const content = padded(2 * PART + 1);
    // Part 1 hits a transient 503 first; the last part's answer says part 1 is missing anyway.
    net.next(`${DIADOC_URL}/ShelfUploadPart`, () => new Response('busy', { status: 503 }));
    net.next(
      `${DIADOC_URL}/ShelfUploadPart`,
      () => json([]),
      (req) => {
        const parts = net.shelf.get('shelf-parts') ?? [];
        parts[2] = req.body;
        return json([1]);
      },
    );

    const result = await send(content);

    expect(result).toMatchObject({ contentPlacement: 'shelf', nameOnShelf: 'shelf-parts' });
    const [init] = net.to('/ShelfUploadPartInit');
    expect(Object.fromEntries(init?.url.searchParams ?? [])).toEqual({
      fileExtension: '.xml',
      isLastPart: 'false',
    });
    expect(init?.body.equals(content.subarray(0, PART))).toBe(true);
    const parts = net.to('/ShelfUploadPart');
    expect(parts.map((r) => Object.fromEntries(r.url.searchParams))).toEqual([
      { fileName: 'shelf-parts', partIndex: '1', isLastPart: 'false' }, // 503
      { fileName: 'shelf-parts', partIndex: '1', isLastPart: 'false' },
      { fileName: 'shelf-parts', partIndex: '2', isLastPart: 'true' }, // → [1]
      { fileName: 'shelf-parts', partIndex: '1', isLastPart: 'true' }, // re-send → []
    ]);
    expect(parts[0]?.body.equals(parts[1]?.body ?? Buffer.alloc(0))).toBe(true);
    expect(parts.map((r) => r.body.length)).toEqual([PART, PART, 1, PART]);
    // Every request carried the right slice, not only the one that ended up on the shelf.
    const part1 = content.subarray(PART, 2 * PART);
    expect(
      parts
        .filter((r) => r.url.searchParams.get('partIndex') === '1')
        .every((r) => r.body.equals(part1)),
    ).toBe(true);
    expect(parts[2]?.body.equals(content.subarray(2 * PART))).toBe(true);
    // What the shelf holds is the file, byte for byte.
    expect(Buffer.concat(net.shelf.get('shelf-parts') ?? []).equals(content)).toBe(true);
    expect(sleeps).toEqual([1000]);
    expect(net.to('/V2/ShelfUpload')).toHaveLength(0);
    expect(signedData(net.to('/cms/sign')[0]).equals(content)).toBe(true);
    expect(signedData(net.to('/cms/verify')[0]).equals(content)).toBe(true);

    const attachment = postedAttachment(net.to('/V3/PostMessage')[0]);
    expect(attachment.SignedContent).toEqual({
      NameOnShelf: 'shelf-parts',
      Signature: DER_SIGNATURE.toString('base64'),
    });
  });

  it('repeats PostMessage after 204 + Retry-After with the identical body and operationId', async () => {
    const { net, sleeps, send } = setup();
    net.next(
      `${DIADOC_URL}/V3/PostMessage`,
      () => new Response(null, { status: 204, headers: { 'retry-after': '7' } }),
    );

    const result = await send(CONTENT);

    expect(result).toMatchObject({ messageId: 'msg-1', outcome: 'success' });
    const posts = net.to('/V3/PostMessage');
    expect(posts).toHaveLength(2);
    expect(posts[1]?.body.equals(posts[0]?.body ?? Buffer.alloc(0))).toBe(true);
    expect(posts.map((r) => r.url.searchParams.get('operationId'))).toEqual([
      result.operationId,
      result.operationId,
    ]);
    expect(sleeps).toEqual([7000]);
  });

  it.each([
    ['Document with this operationId already exists', 'ALREADY_SENT'],
    ['Recipient forbids receiving documents (Sociability)', 'RECIPIENT_FORBIDS'],
    ['Conflict', 'POST_CONFLICT'],
  ])('maps a PostMessage 409 "%s" to %s without repeating it', async (text, code) => {
    const { net, send } = setup();
    net.next(`${DIADOC_URL}/V3/PostMessage`, () => new Response(text, { status: 409 }));

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipelineError);
    expect(error).toMatchObject({ code, step: 'post' });
    expect((error as PipelineError).message).toContain(text);
    expect(net.to('/V3/PostMessage')).toHaveLength(1);
    expect(net.to('/V3/GetDocument')).toHaveLength(0);
  });

  it('reports "may have been posted" when PostMessage ends in 5xx and network errors (F3)', async () => {
    const { net, sleeps, send } = setup();
    const lost = (): Response => {
      throw new TypeError('fetch failed', { cause: new Error('ECONNRESET') });
    };
    net.next(
      `${DIADOC_URL}/V3/PostMessage`,
      () => new Response('bad gateway', { status: 502 }),
      lost,
      () => new Response('unavailable', { status: 503 }),
      lost,
    );

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toMatchObject({ code: 'POST_FAILED', step: 'post' });
    expect((error as PipelineError).message).toContain('may have been posted');
    const posts = net.to('/V3/PostMessage');
    expect(posts).toHaveLength(4);
    expect(posts.every((r) => r.body.equals(posts[0]?.body ?? Buffer.alloc(0)))).toBe(true);
    expect(sleeps).toHaveLength(3);
  });

  it('treats 503 on every PostMessage attempt as a possible post too (conservative, F3)', async () => {
    const { net, send } = setup();
    const busy = (): Response => new Response('unavailable', { status: 503 });
    net.next(`${DIADOC_URL}/V3/PostMessage`, busy, busy, busy, busy);

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toMatchObject({ code: 'POST_FAILED' });
    expect((error as PipelineError).message).toContain('may have been posted');
  });

  it('reports a plain POST_FAILED when Diadoc rejects PostMessage outright', async () => {
    const { net, send } = setup();
    net.next(`${DIADOC_URL}/V3/PostMessage`, () => new Response('bad signature', { status: 400 }));

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toMatchObject({ code: 'POST_FAILED' });
    expect((error as PipelineError).message).not.toContain('may have been posted');
    expect(net.to('/V3/PostMessage')).toHaveLength(1);
  });

  it('reports a burnt refresh token as DIADOC_AUTH with a hint, without secrets (R2 minor 11)', async () => {
    const { net, send } = setup();
    net.next(IDP, () => json({ error: 'invalid_grant' }, 400));

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toMatchObject({ code: 'DIADOC_AUTH', step: 'precheck' });
    const { message, operationId } = error as PipelineError;
    expect(operationId).toBe(GOLDEN_OPERATION_ID);
    expect(message).toMatch(/invalid_grant.*issue a new one in the integrator cabinet/);
    expect(message).not.toMatch(/rt-1|secret\b/);
    expect(net.to('/CanPostMessage')).toHaveLength(0);
    expect(net.to('/V3/PostMessage')).toHaveLength(0);
  });
});

describe('sendUtd over the real signer, failures (seam)', () => {
  const verifyAnswer = (sign: Record<string, unknown>): Response =>
    json(
      {
        isValidSign: false,
        signs: [
          {
            isValidSign: false,
            isDetached: true,
            certificate: { thumbprint: THUMBPRINT },
            ...sign,
          },
        ],
      },
      201,
    );

  it.each([
    [
      'the key is not on the server',
      '/cms/sign',
      (): Response =>
        json(
          { statusCode: 400, message: 'Закрытый ключ для переданного сертификата не найден' },
          400,
        ),
      'SIGN_FAILED',
    ],
    [
      'the math is broken',
      '/cms/verify',
      (): Response => verifyAnswer({ extVerifyInfo: { mathValidity: false } }),
      'SIGNATURE_INVALID',
    ],
    [
      'the math is valid but the certificate is not',
      '/cms/verify',
      (): Response => verifyAnswer({ extVerifyInfo: { mathValidity: true }, isCertValid: false }),
      'CERTIFICATE_INVALID',
    ],
  ])('stops before Diadoc when %s', async (_, path, answer, code) => {
    const { net, send } = setup();
    net.next(`${SIGNER_URL}${path}`, answer);

    const error = await send(CONTENT).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(PipelineError);
    expect(error).toMatchObject({ code });
    // Nothing reached the IdP or Diadoc.
    expect(net.requests.every((r) => r.url.origin === SIGNER_URL)).toBe(true);
  });
});

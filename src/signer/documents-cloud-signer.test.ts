import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import {
  DocumentsCloudSigner,
  type DocumentsCloudSignerOptions,
} from './documents-cloud-signer.js';
import {
  SignerConfigError,
  SignerHttpError,
  SignerKeyNotFoundError,
  SignerNetworkError,
  SignerResponseError,
  SignerTimeoutError,
} from './errors.js';
import type { Signer, VerifyResult } from './signer.js';

const certDer = Buffer.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x05, 0x01, 0x00]);
const pfxDer = Buffer.from([0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]);
// Real КриптоАРМ Server CMS (BER, indefinite lengths) — what Документы stores and exports (D11) —
// and its DER re-encoding by OpenSSL, see src/asn1/fixtures.
const serverBer = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url),
);
const serverDer = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
// windows-1251 bytes that are not valid UTF-8: must be uploaded unchanged.
const data = Buffer.from([0x3c, 0xc4, 0xee, 0xea, 0x3e, 0x00, 0xff]);

const BASE = 'http://documents.test:3040';
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2VjcmV0LWp3dC1zaWduYXR1cmU';
const LOGIN_JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.bG9naW4tand0LXNpZ25hdHVyZQ';
const PASSWORD = 'pa55-w0rd-never-shown';
const NOW = '2026-09-24T12:00:00.000Z';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const json = (
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response =>
  new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...init.headers },
  });

const apiError = (status: number, code: string, message: string, requestId = 'req-1'): Response =>
  json(
    { error: { code, message, hint: 'Проверьте формат и обязательные поля запроса.' } },
    { status, headers: { 'X-Request-Id': requestId } },
  );

interface Call {
  method: string;
  path: string;
  url: URL;
  init: RequestInit;
  headers: Headers;
}

type Handler = (call: Call) => Response | Promise<Response>;

/** Routes `METHOD /path` (without the query) to a handler or a queue of handlers (one per call). */
function router(routes: Record<string, Handler | Handler[]>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn<typeof fetch>((input, init = {}) => {
    if (!(input instanceof URL)) throw new Error('expected fetch(URL, init)');
    const url = input;
    const call: Call = {
      method: init.method ?? 'GET',
      path: url.pathname,
      url,
      init,
      headers: new Headers(init.headers),
    };
    calls.push(call);
    const route = routes[`${call.method} ${call.path}`];
    const handler = Array.isArray(route) ? route.shift() : route;
    if (!handler) return Promise.reject(new Error(`unexpected ${call.method} ${call.path}`));
    return Promise.resolve(handler(call));
  });
  return { fetchMock, calls };
}

/** The happy path of one signing: upload -> cloud-sign -> export. */
function signingRoutes(docId = 42, sigId = 7): Record<string, Handler | Handler[]> {
  return {
    'POST /api/v1/documents/upload': () =>
      json({ message: 'Файл успешно загружен', document: { id: docId } }, { status: 201 }),
    [`POST /api/v1/signatures/cloud-sign/${String(docId)}`]: () =>
      json({
        success: true,
        signatureId: sigId,
        signature: serverBer.toString('base64'),
        documentId: docId,
      }),
    [`POST /api/v1/documents/${String(docId)}/signature`]: () =>
      new Response(new Uint8Array(serverBer), {
        status: 201,
        headers: { 'Content-Type': 'documents/signatures' },
      }),
  };
}

const verifier = { verify: vi.fn<Signer['verify']>() };

function setup(
  routes: Record<string, Handler | Handler[]>,
  options: Partial<DocumentsCloudSignerOptions> = {},
) {
  const { fetchMock, calls } = router(routes);
  const sleep = vi.fn<(ms: number, signal?: AbortSignal) => Promise<void>>(() => Promise.resolve());
  const signer = new DocumentsCloudSigner({
    baseUrl: BASE,
    certificate: certDer,
    auth: { jwt: JWT },
    verifier,
    fetch: fetchMock,
    sleep,
    now: () => Date.parse(NOW),
    ...options,
  });
  return { signer, fetchMock, calls, sleep };
}

function loginRoutes(): Record<string, Handler | Handler[]> {
  return {
    'POST /api/v1/login': () => {
      const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
      headers.append('Set-Cookie', 'session=c2Vzc2lvbg; path=/; expires=Invalid Date; httponly');
      headers.append('Set-Cookie', 'session.sig=c2ln; path=/; expires=Invalid Date; httponly');
      return new Response(JSON.stringify({ userId: 1 }), { status: 200, headers });
    },
    'GET /api/v1/auth/jwt': () =>
      json({ token: LOGIN_JWT, expiresInSeconds: 900, expiresAt: '2026-09-24T12:15:00.000Z' }),
  };
}

function jsonBody(call: Call): unknown {
  if (typeof call.init.body !== 'string') throw new Error('body is not a string');
  return JSON.parse(call.init.body);
}

function uploadedFile(call: Call): File {
  const body = call.init.body;
  if (!(body instanceof FormData)) throw new Error('upload body is not FormData');
  const file = body.get('file');
  if (!(file instanceof File)) throw new Error('no "file" part');
  return file;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected a rejection');
    },
    (error: unknown) => error,
  );
}

describe('DocumentsCloudSigner construction', () => {
  it('exposes the configured certificate as DER (PEM accepted)', () => {
    const pem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64')}\n-----END CERTIFICATE-----\n`;
    expect(setup({}).signer.certificate).toEqual(certDer);
    expect(setup({}, { certificate: Buffer.from(pem) }).signer.certificate).toEqual(certDer);
  });

  it('rejects a PKCS#12 container as the certificate', () => {
    expect(() => setup({}, { certificate: pfxDer })).toThrow(SignerConfigError);
  });

  it.each(['', 'not a url', 'ftp://documents.test'])('rejects base URL %j', (baseUrl) => {
    expect(() => setup({}, { baseUrl })).toThrow(SignerConfigError);
  });

  it.each(['http://user:secret@d.test', 'http://d.test/?token=secret', 'http://d.test/#secret'])(
    'rejects base URL with credentials, query or fragment without echoing it: %s',
    (baseUrl) => {
      const create = () => setup({}, { baseUrl });
      expect(create).toThrow(SignerConfigError);
      expect(create).not.toThrow(/secret/);
    },
  );

  it.each(['', 'a b', 'jwt\nnext', 'токен'])(
    'rejects a JWT that is not a header token without echoing it: %j',
    (jwt) => {
      const create = () => setup({}, { auth: { jwt } });
      expect(create).toThrow(SignerConfigError);
      expect(create).not.toThrow(jwt || 'never');
    },
  );

  it('rejects an empty login or password', () => {
    expect(() => setup({}, { auth: { login: '', password: PASSWORD } })).toThrow(SignerConfigError);
    expect(() => setup({}, { auth: { login: 'admin', password: '' } })).toThrow(SignerConfigError);
  });

  it.each([0, -1, 1.5, 2 ** 31])('rejects timeout %d', (timeoutMs) => {
    expect(() => setup({}, { timeoutMs })).toThrow(SignerConfigError);
  });

  it('rejects an upload content type that is not a MIME type', () => {
    expect(() => setup({}, { uploadContentType: 'xml' })).toThrow(SignerConfigError);
  });
});

describe('DocumentsCloudSigner.sign', () => {
  it('uploads the exact bytes, cloud-signs them and exports the detached signature as DER', async () => {
    const { signer, calls } = setup(signingRoutes());
    const result = await signer.sign(data);

    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /api/v1/documents/upload',
      'POST /api/v1/signatures/cloud-sign/42',
      'POST /api/v1/documents/42/signature',
    ]);
    const [upload, cloudSign, exported] = calls as [Call, Call, Call];
    const file = uploadedFile(upload);
    expect(Buffer.from(await file.arrayBuffer())).toEqual(data);
    expect(file.type).toBe('application/octet-stream');
    expect(jsonBody(cloudSign)).toEqual({});
    expect(jsonBody(exported)).toEqual({ signatureId: 7, attached: false });

    // D11: the service returns BER; Signer.sign returns DER and keeps the raw bytes.
    expect(result.signature).toEqual(serverDer);
    expect(result.rawSignature).toEqual(serverBer);
  });

  it('authenticates every call with the configured Bearer JWT and never uses X-API-KEY', async () => {
    const { signer, calls } = setup(signingRoutes());
    await signer.sign(data);
    for (const call of calls) {
      expect(call.headers.get('authorization')).toBe(`Bearer ${JWT}`);
      expect(call.headers.has('x-api-key')).toBe(false);
      expect(call.headers.has('cookie')).toBe(false);
    }
  });

  it('sends Idempotency-Key on the mutating calls and a fresh X-Request-Id on every call', async () => {
    const { signer, calls } = setup(signingRoutes());
    await signer.sign(data);
    const [upload, cloudSign, exported] = calls as [Call, Call, Call];
    expect(upload.headers.get('idempotency-key')).toMatch(UUID);
    expect(cloudSign.headers.get('idempotency-key')).toMatch(UUID);
    expect(upload.headers.get('idempotency-key')).not.toBe(
      cloudSign.headers.get('idempotency-key'),
    );
    expect(exported.headers.has('idempotency-key')).toBe(false);
    const ids = calls.map((c) => c.headers.get('x-request-id'));
    for (const id of ids) expect(id).toMatch(UUID);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('does not follow redirects on any call (the JWT must not reach another host)', async () => {
    const { signer, calls } = setup(signingRoutes());
    await signer.sign(data);
    for (const call of calls) expect(call.init.redirect).toBe('error');
  });

  it('keeps a path prefix of the base URL', async () => {
    const { signer, calls } = setup(
      Object.fromEntries(
        Object.entries(signingRoutes()).map(([k, v]) => [k.replace(' /', ' /gw/'), v]),
      ),
      { baseUrl: `${BASE}/gw` },
    );
    await signer.sign(data);
    expect(calls.map((c) => c.url.href)).toEqual([
      `${BASE}/gw/api/v1/documents/upload`,
      `${BASE}/gw/api/v1/signatures/cloud-sign/42`,
      `${BASE}/gw/api/v1/documents/42/signature`,
    ]);
  });

  it('uploads with the configured content type', async () => {
    const { signer, calls } = setup(signingRoutes(), { uploadContentType: 'application/xml' });
    await signer.sign(data);
    const [upload] = calls as [Call];
    expect(uploadedFile(upload).type).toBe('application/xml');
  });

  it('uploads a new document for every signing (one signature per user and document)', async () => {
    const routes = signingRoutes(42, 7);
    const second = signingRoutes(43, 8);
    const { signer, calls } = setup({
      ...routes,
      ...second,
      'POST /api/v1/documents/upload': [
        routes['POST /api/v1/documents/upload'] as Handler,
        second['POST /api/v1/documents/upload'] as Handler,
      ],
    });
    await signer.sign(data);
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/documents/upload')).toHaveLength(2);
    expect(calls.map((c) => c.path)).toContain('/api/v1/signatures/cloud-sign/43');
  });

  it('refuses to sign empty data without calling the service', async () => {
    const { signer, fetchMock } = setup(signingRoutes());
    await expect(signer.sign(Buffer.alloc(0))).rejects.toThrow(/must not be empty/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maps the error envelope to SignerHttpError with step, code, message and request id', async () => {
    const { signer } = setup({
      ...signingRoutes(),
      'POST /api/v1/signatures/cloud-sign/42': () =>
        apiError(400, 'bad_request', 'Повторная подпись документа этим пользователем запрещена'),
    });
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerHttpError);
    expect(error).not.toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toMatchObject({ operation: 'sign', status: 400, requestId: 'req-1' });
    expect((error as SignerHttpError).upstreamMessage).toBe(
      'cloud-sign: Повторная подпись документа этим пользователем запрещена [bad_request]',
    );
  });

  it('maps "no corporate certificate for the user" to SignerKeyNotFoundError', async () => {
    const { signer } = setup({
      ...signingRoutes(),
      'POST /api/v1/signatures/cloud-sign/42': () =>
        apiError(400, 'bad_request', 'Не удалось получить корпоративный сертификат пользователя'),
    });
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toMatchObject({ status: 400 });
  });

  it('maps a relayed КриптоАРМ Server "private key not found" to SignerKeyNotFoundError', async () => {
    const { signer } = setup({
      ...signingRoutes(),
      'POST /api/v1/signatures/cloud-sign/42': () =>
        apiError(
          400,
          'bad_request',
          'Закрытый ключ для переданного сертификата не найден в хранилище КриптоПро.',
        ),
    });
    await expect(signer.sign(data)).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('maps a 401 on the export step (configured JWT) to SignerHttpError naming the step', async () => {
    const { signer } = setup({
      ...signingRoutes(),
      'POST /api/v1/documents/42/signature': () => apiError(401, 'unauthorized', 'Unauthorized'),
    });
    const error = (await rejection(signer.sign(data))) as SignerHttpError;
    expect(error.upstreamMessage).toBe('export: Unauthorized [unauthorized]');
  });

  it('falls back to the request id it sent when the response has none', async () => {
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': () => new Response('bad gateway text', { status: 400 }),
    });
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerHttpError);
    expect((error as SignerHttpError).upstreamMessage).toBe('upload: bad gateway text');
    expect((error as SignerHttpError).requestId).toBe(calls[0]?.headers.get('x-request-id'));
  });

  it('truncates a long upstream message', async () => {
    const { signer } = setup({
      'POST /api/v1/documents/upload': () => apiError(400, 'bad_request', 'x'.repeat(5000)),
    });
    const error = (await rejection(signer.sign(data))) as SignerHttpError;
    expect(error.upstreamMessage.length).toBeLessThanOrEqual(520);
  });

  it('repeats a 429 after Retry-After with the same Idempotency-Key', async () => {
    const routes = signingRoutes();
    const ok = routes['POST /api/v1/signatures/cloud-sign/42'] as Handler;
    const { signer, calls, sleep } = setup({
      ...routes,
      'POST /api/v1/signatures/cloud-sign/42': [
        () => apiError(429, 'rate_limited', 'Too Many Requests'),
        () =>
          json(
            { error: { code: 'rate_limited', message: 'slow down' } },
            {
              status: 429,
              headers: { 'Retry-After': '3' },
            },
          ),
        ok,
      ],
    });
    const result = await signer.sign(data);
    expect(result.signature).toEqual(serverDer);
    const signs = calls.filter((c) => c.path === '/api/v1/signatures/cloud-sign/42');
    expect(signs).toHaveLength(3);
    const keys = new Set(signs.map((c) => c.headers.get('idempotency-key')));
    expect(keys.size).toBe(1);
    expect(sleep.mock.calls.map(([ms]) => ms)).toEqual([1000, 3000]);
  });

  it('repeats transient 5xx and network failures, then gives up with the last error', async () => {
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': [
        () => new Response('', { status: 503 }),
        () => {
          throw new TypeError('fetch failed');
        },
        () => new Response('', { status: 502 }),
        () => apiError(500, 'internal', 'boom'),
      ],
    });
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerHttpError);
    expect(error).toMatchObject({ status: 500 });
    expect(calls).toHaveLength(4);
  });

  it('does not repeat a 4xx other than 408/429', async () => {
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': () => apiError(403, 'forbidden', 'Forbidden'),
    });
    await expect(signer.sign(data)).rejects.toBeInstanceOf(SignerHttpError);
    expect(calls).toHaveLength(1);
  });

  it('maps a persistent network failure to SignerNetworkError keeping the cause', async () => {
    const cause = new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') });
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': () => {
        throw cause;
      },
    });
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerNetworkError);
    expect((error as Error).cause).toBe(cause);
    expect(calls).toHaveLength(4);
  });

  it('maps a persistent timeout to SignerTimeoutError', async () => {
    const { signer } = setup(
      {
        'POST /api/v1/documents/upload': () => {
          throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
        },
      },
      { timeoutMs: 1234 },
    );
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerTimeoutError);
    expect(error).toMatchObject({ timeoutMs: 1234 });
  });

  it('does not repeat a refused redirect', async () => {
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': () => {
        throw new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
      },
    });
    await expect(signer.sign(data)).rejects.toBeInstanceOf(SignerNetworkError);
    expect(calls).toHaveLength(1);
  });

  it('aborts when the caller signal aborts and rethrows its reason', async () => {
    const controller = new AbortController();
    const reason = new Error('stop');
    const { signer, calls } = setup({
      ...signingRoutes(),
      'POST /api/v1/documents/upload': (call) => {
        controller.abort(reason);
        expect(call.init.signal?.aborted).toBe(true);
        throw new DOMException('aborted', 'AbortError');
      },
    });
    await expect(signer.sign(data, { signal: controller.signal })).rejects.toBe(reason);
    expect(calls).toHaveLength(1);
  });

  it('rejects at once with an already aborted signal', async () => {
    const { signer, fetchMock } = setup(signingRoutes());
    const reason = new Error('already');
    await expect(signer.sign(data, { signal: AbortSignal.abort(reason) })).rejects.toBe(reason);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['upload without document.id', 'POST /api/v1/documents/upload', () => json({ document: {} })],
    [
      'cloud-sign without signatureId',
      'POST /api/v1/signatures/cloud-sign/42',
      () => json({ success: true }),
    ],
    [
      'cloud-sign with success false',
      'POST /api/v1/signatures/cloud-sign/42',
      () => json({ success: false, signatureId: 7 }),
    ],
    ['upload with a non-JSON body', 'POST /api/v1/documents/upload', () => new Response('<html>')],
    [
      'an empty export',
      'POST /api/v1/documents/42/signature',
      () => new Response(new Uint8Array(0), { status: 201 }),
    ],
    [
      'an export that is not BER',
      'POST /api/v1/documents/42/signature',
      () => new Response(new Uint8Array([0x30, 0x85, 0x01]), { status: 201 }),
    ],
    [
      'an export that is not a CMS SignedData',
      'POST /api/v1/documents/42/signature',
      () => new Response(new Uint8Array(certDer), { status: 201 }),
    ],
    [
      'an export that differs from the cloud-sign signature',
      'POST /api/v1/documents/42/signature',
      () => new Response(new Uint8Array(serverDer), { status: 201 }),
    ],
  ])('rejects %s with SignerResponseError', async (_name, route, handler) => {
    const { signer } = setup({ ...signingRoutes(), [route]: handler });
    await expect(signer.sign(data)).rejects.toBeInstanceOf(SignerResponseError);
  });

  it('accepts a cloud-sign answer without the signature copy (export is authoritative)', async () => {
    const { signer } = setup({
      ...signingRoutes(),
      'POST /api/v1/signatures/cloud-sign/42': () => json({ success: true, signatureId: 7 }),
    });
    expect((await signer.sign(data)).signature).toEqual(serverDer);
  });
});

describe('DocumentsCloudSigner login', () => {
  const auth = { login: 'admin', password: PASSWORD };

  it('logs in, exchanges the session for a short JWT and signs with it as Bearer', async () => {
    const { signer, calls } = setup({ ...loginRoutes(), ...signingRoutes() }, { auth });
    await signer.sign(data);

    const [login, jwt, ...rest] = calls as [Call, Call, ...Call[]];
    expect(`${login.method} ${login.path}`).toBe('POST /api/v1/login');
    expect(jsonBody(login)).toEqual({ username: 'admin', password: PASSWORD });
    expect(login.headers.has('idempotency-key')).toBe(false);
    expect(login.init.redirect).toBe('error');
    expect(`${jwt.method} ${jwt.path}`).toBe('GET /api/v1/auth/jwt');
    expect(jwt.url.searchParams.get('expiresIn')).toBe('15m');
    expect(jwt.headers.get('cookie')).toBe('session=c2Vzc2lvbg; session.sig=c2ln');
    expect(jwt.headers.has('authorization')).toBe(false);
    expect(rest.map((c) => c.headers.get('authorization'))).toEqual([
      `Bearer ${LOGIN_JWT}`,
      `Bearer ${LOGIN_JWT}`,
      `Bearer ${LOGIN_JWT}`,
    ]);
    for (const call of rest) expect(call.headers.has('cookie')).toBe(false);
  });

  it('reuses the JWT until shortly before it expires, then logs in again', async () => {
    let now = Date.parse('2026-09-24T12:00:00.000Z');
    const routes = {
      ...loginRoutes(),
      ...signingRoutes(),
      'GET /api/v1/auth/jwt': () =>
        json({ token: LOGIN_JWT, expiresAt: new Date(now + 900_000).toISOString() }),
    };
    const { signer, calls } = setup(routes, { auth, now: () => now });
    await signer.sign(data);
    now = Date.parse('2026-09-24T12:13:00.000Z');
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(1);
    now = Date.parse('2026-09-24T12:14:30.000Z'); // inside the 60 s margin before expiresAt
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(2);
  });

  it('shares one login between concurrent signings', async () => {
    const { signer, calls } = setup({ ...loginRoutes(), ...signingRoutes() }, { auth });
    await Promise.all([signer.sign(data), signer.sign(data)]);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(1);
  });

  it('logs in again once when a login JWT is rejected with 401', async () => {
    const routes = { ...loginRoutes(), ...signingRoutes() };
    const ok = routes['POST /api/v1/documents/upload'] as Handler;
    const { signer, calls } = setup(
      {
        ...routes,
        'POST /api/v1/documents/upload': [() => apiError(401, 'unauthorized', 'Unauthorized'), ok],
      },
      { auth },
    );
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(2);
    expect(calls.filter((c) => c.path === '/api/v1/documents/upload')).toHaveLength(2);
  });

  it('re-logs in once when two concurrent signings get 401 on the same JWT', async () => {
    const routes = { ...loginRoutes(), ...signingRoutes() };
    const ok = routes['POST /api/v1/documents/upload'] as Handler;
    const unauthorized: Handler = () => apiError(401, 'unauthorized', 'Unauthorized');
    const { signer, calls } = setup(
      { ...routes, 'POST /api/v1/documents/upload': [unauthorized, unauthorized, ok, ok] },
      { auth },
    );
    await Promise.all([signer.sign(data), signer.sign(data)]);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(2);
  });

  it('repeats a request rejected with 401 under a new Idempotency-Key and cancels the 401 body', async () => {
    const routes = { ...loginRoutes(), ...signingRoutes() };
    const ok = routes['POST /api/v1/documents/upload'] as Handler;
    const rejected = apiError(401, 'unauthorized', 'Unauthorized');
    const { signer, calls } = setup(
      { ...routes, 'POST /api/v1/documents/upload': [() => rejected, ok] },
      { auth },
    );
    await signer.sign(data);
    const keys = calls
      .filter((c) => c.path === '/api/v1/documents/upload')
      .map((c) => c.headers.get('idempotency-key'));
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toBe(keys[1]);
    expect(rejected.bodyUsed || rejected.body?.locked).toBe(true);
  });

  it.each([
    ['expiresInSeconds', { token: LOGIN_JWT, expiresInSeconds: 120 }, 59_000, 61_000],
    ['no lifetime (15 min assumed)', { token: LOGIN_JWT }, 839_000, 841_000],
  ])('derives the JWT lifetime from %s', async (_name, body, reuseAt, renewAt) => {
    const start = Date.parse(NOW);
    let now = start;
    const { signer, calls } = setup(
      { ...loginRoutes(), ...signingRoutes(), 'GET /api/v1/auth/jwt': () => json(body) },
      { auth, now: () => now },
    );
    await signer.sign(data);
    now = start + reuseAt;
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(1);
    now = start + renewAt;
    await signer.sign(data);
    expect(calls.filter((c) => c.path === '/api/v1/login')).toHaveLength(2);
  });

  it('gives up after the second 401', async () => {
    const { signer, calls } = setup(
      {
        ...loginRoutes(),
        'POST /api/v1/documents/upload': () => apiError(401, 'unauthorized', 'Unauthorized'),
      },
      { auth },
    );
    await expect(signer.sign(data)).rejects.toMatchObject({ status: 401 });
    expect(calls.filter((c) => c.path === '/api/v1/documents/upload')).toHaveLength(2);
  });

  it('does not repeat a 401 with a configured JWT (it cannot be renewed)', async () => {
    const { signer, calls } = setup({
      'POST /api/v1/documents/upload': () => apiError(401, 'unauthorized', 'Unauthorized'),
    });
    const error = await rejection(signer.sign(data));
    expect(error).toMatchObject({ status: 401 });
    expect(calls).toHaveLength(1);
    expect(String(error)).not.toContain(JWT);
  });

  it('reports a failed login without the password', async () => {
    const { signer } = setup(
      { 'POST /api/v1/login': () => apiError(401, 'unauthorized', 'Unauthorized') },
      { auth },
    );
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerHttpError);
    expect((error as SignerHttpError).upstreamMessage).toBe('login: Unauthorized [unauthorized]');
    expect(JSON.stringify(error) + String(error)).not.toContain(PASSWORD);
  });

  it('rejects a login answer without a session cookie', async () => {
    const { signer } = setup({ 'POST /api/v1/login': () => json({ userId: 1 }) }, { auth });
    await expect(signer.sign(data)).rejects.toThrow(/login: no session cookie/);
  });

  it.each([
    ['without token', { expiresAt: '2026-09-24T12:15:00.000Z' }],
    ['with a token that is not a header value', { token: 'a b', expiresInSeconds: 900 }],
  ])('rejects a JWT answer %s without echoing it', async (_name, body) => {
    const { signer } = setup(
      { ...loginRoutes(), 'GET /api/v1/auth/jwt': () => json(body) },
      { auth },
    );
    const error = await rejection(signer.sign(data));
    expect(error).toBeInstanceOf(SignerResponseError);
    expect(String(error)).not.toContain('a b');
  });
});

describe('DocumentsCloudSigner.verify', () => {
  it('delegates to the configured verifier with the exact bytes and options', async () => {
    const result: VerifyResult = { valid: true, signers: [{ valid: true, thumbprint: 'ab' }] };
    verifier.verify.mockResolvedValueOnce(result);
    const { signer, fetchMock } = setup({});
    const signal = new AbortController().signal;
    await expect(signer.verify(data, serverDer, { signal })).resolves.toBe(result);
    expect(verifier.verify).toHaveBeenLastCalledWith(data, serverDer, { signal });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

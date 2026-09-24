import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import { isDerFramed } from '../asn1/index.js';
import {
  SignerConfigError,
  SignerError,
  SignerHttpError,
  SignerKeyNotFoundError,
  SignerNetworkError,
  SignerPayloadTooLargeError,
  SignerResponseError,
  SignerTimeoutError,
} from './errors.js';
import {
  DEFAULT_MAX_REQUEST_BYTES,
  ServerCmsSigner,
  type ServerCmsSignerOptions,
} from './server-cms-signer.js';

const certDer = Buffer.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x05, 0x01, 0x00]);
const pfxDer = Buffer.from([0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]);
// ContentInfo { contentType pkcs7-signedData, [0] ... }: only the envelope matters for the client.
const SIGNED_DATA_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const cmsDer = Buffer.from([0x30, 0x0d, ...SIGNED_DATA_OID, 0xa0, 0x00]);
// КриптоАРМ Server returns BER with indefinite lengths (seen live): 30 80 ... 00 00.
const cmsBer = Buffer.from([0x30, 0x80, ...SIGNED_DATA_OID, 0xa0, 0x80, 0x00, 0x00, 0x00, 0x00]);
// Real /cms/sign output (BER) and its DER re-encoding by OpenSSL, see src/asn1/fixtures.
const serverBer = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url),
);
const serverDer = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
// windows-1251 bytes that are not valid UTF-8: must reach the server unchanged.
const data = Buffer.from([0x3c, 0xc4, 0xee, 0xea, 0x3e, 0x00, 0xff]);

const json = (
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response =>
  new Response(JSON.stringify(body), {
    status: init.status ?? 201,
    headers: { 'Content-Type': 'application/json', ...init.headers },
  });

type FetchMock = ReturnType<typeof vi.fn<typeof fetch>>;

function setup(
  response: Response | (() => Promise<Response>),
  options: Partial<ServerCmsSignerOptions> = {},
): { signer: ServerCmsSigner; fetchMock: FetchMock } {
  const fetchMock = vi.fn<typeof fetch>(() =>
    typeof response === 'function' ? response() : Promise.resolve(response),
  );
  const signer = new ServerCmsSigner({
    baseUrl: 'http://server.test:3037',
    certificate: certDer,
    fetch: fetchMock,
    ...options,
  });
  return { signer, fetchMock };
}

function lastRequest(fetchMock: FetchMock): { url: string; init: RequestInit; body: unknown } {
  const call = fetchMock.mock.lastCall;
  if (!call) throw new Error('fetch was not called');
  const [url, init = {}] = call;
  if (!(url instanceof URL) || typeof init.body !== 'string') {
    throw new Error('expected fetch(URL, { body: string })');
  }
  return { url: url.href, init, body: JSON.parse(init.body) };
}

describe('ServerCmsSigner construction', () => {
  it('rejects a PKCS#12 container as the certificate', () => {
    expect(
      () => new ServerCmsSigner({ baseUrl: 'http://server.test', certificate: pfxDer }),
    ).toThrow(SignerConfigError);
  });

  it.each(['', 'not a url', 'ftp://server.test'])('rejects base URL %j', (baseUrl) => {
    expect(() => new ServerCmsSigner({ baseUrl, certificate: certDer })).toThrow(SignerConfigError);
  });

  it.each([0, -1, 1.5, 2 ** 31])('rejects timeout %d', (timeoutMs) => {
    expect(
      () => new ServerCmsSigner({ baseUrl: 'http://s.test', certificate: certDer, timeoutMs }),
    ).toThrow(SignerConfigError);
  });

  it.each(['http://user:pass@s.test', 'http://s.test/?apiKey=secret', 'http://s.test/#x'])(
    'rejects base URL with credentials, query or fragment without echoing it: %s',
    (baseUrl) => {
      const error = (() => {
        try {
          return new ServerCmsSigner({ baseUrl, certificate: certDer });
        } catch (e) {
          return e;
        }
      })();
      expect(error).toBeInstanceOf(SignerConfigError);
      expect(String(error)).not.toMatch(/pass|secret/);
    },
  );

  it.each(['ключ', 'a b', 'line\nbreak', ''])(
    'rejects an API key that is not a header token without echoing it: %j',
    (apiKey) => {
      const create = () =>
        new ServerCmsSigner({ baseUrl: 'http://s.test', certificate: certDer, apiKey });
      expect(create).toThrow(SignerConfigError);
      expect(create).not.toThrow(apiKey || 'never');
    },
  );
});

describe('ServerCmsSigner.certificate', () => {
  it('exposes the configured public certificate as DER', () => {
    const pem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64')}\n-----END CERTIFICATE-----\n`;
    expect(setup(json({})).signer.certificate).toEqual(certDer);
    expect(setup(json({}), { certificate: Buffer.from(pem) }).signer.certificate).toEqual(certDer);
  });
});

describe('ServerCmsSigner.sign', () => {
  it('posts a detached CAdES-BES request with only the public certificate', async () => {
    const { signer, fetchMock } = setup(json({ cms: cmsDer.toString('base64') }));

    await signer.sign(data);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const { url, init, body } = lastRequest(fetchMock);
    expect(url).toBe('http://server.test:3037/cms/sign');
    expect(init.method).toBe('POST');
    expect(body).toEqual({
      cert: certDer.toString('base64'),
      data: data.toString('base64'),
      detached: true,
      cadesStandard: 'CAdES-BES',
    });
    const headers = new Headers(init.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('accept')).toBe('application/json');
    expect(headers.has('x-api-key')).toBe(false);
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.redirect).toBe('error');
  });

  it('returns the CMS as DER bytes', async () => {
    const { signer } = setup(json({ cms: cmsDer.toString('base64') }));
    const result = await signer.sign(data);
    expect(Buffer.isBuffer(result.signature)).toBe(true);
    expect(result.signature).toEqual(cmsDer);
    expect(result.rawSignature).toBeUndefined();
  });

  it('normalizes a BER CMS with indefinite lengths to DER and keeps the raw bytes', async () => {
    const { signer } = setup(json({ cms: cmsBer.toString('base64') }));
    await expect(signer.sign(data)).resolves.toEqual({ signature: cmsDer, rawSignature: cmsBer });
  });

  it('normalizes a real КриптоАРМ Server CMS to the same DER as OpenSSL', async () => {
    const { signer } = setup(json({ cms: serverBer.toString('base64') }));
    const result = await signer.sign(data);
    expect(result.signature).toEqual(serverDer);
    expect(isDerFramed(result.signature)).toBe(true);
    expect(result.rawSignature).toEqual(serverBer);
  });

  it('sends X-API-Key when configured', async () => {
    const { signer, fetchMock } = setup(json({ cms: cmsDer.toString('base64') }), {
      apiKey: 'secret-key',
    });
    await signer.sign(data);
    expect(new Headers(lastRequest(fetchMock).init.headers).get('x-api-key')).toBe('secret-key');
  });

  it('keeps a path prefix of the base URL and tolerates a trailing slash', async () => {
    const { signer, fetchMock } = setup(json({ cms: cmsDer.toString('base64') }), {
      baseUrl: 'https://gw.test/cryptoarm/',
    });
    await signer.sign(data);
    expect(lastRequest(fetchMock).url).toBe('https://gw.test/cryptoarm/cms/sign');
  });

  it('refuses to sign empty data without calling the server', async () => {
    const { signer, fetchMock } = setup(json({ cms: cmsDer.toString('base64') }));
    await expect(signer.sign(Buffer.alloc(0))).rejects.toThrow(SignerError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maps an upstream NestJS error to SignerHttpError with status and message', async () => {
    const { signer } = setup(
      json(
        { message: 'Сертификат не предоставлен', error: 'Bad Request', statusCode: 400 },
        { status: 400, headers: { 'X-Request-Id': 'req-42' } },
      ),
    );
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerHttpError);
    expect(error).toMatchObject({
      status: 400,
      upstreamMessage: 'Сертификат не предоставлен',
      requestId: 'req-42',
      operation: 'sign',
    });
    expect((error as Error).message).toContain('400');
    expect((error as Error).message).toContain('Сертификат не предоставлен');
  });

  it('maps a missing private key to SignerKeyNotFoundError (still a SignerHttpError)', async () => {
    // Verbatim КриптоАРМ Server answer for a real .cer whose key is not in uMy (2026-09-24).
    const message =
      'Закрытый ключ для переданного сертификата не найден в хранилище КриптоПро. Установите контейнер заранее или передайте файл PFX/P12.';
    const { signer } = setup(
      json({ message, error: 'Bad Request', statusCode: 400 }, { status: 400 }),
    );
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toBeInstanceOf(SignerHttpError);
    expect(error).toMatchObject({ status: 400, upstreamMessage: message, operation: 'sign' });
    expect((error as Error).name).toBe('SignerKeyNotFoundError');
  });

  it('recognizes a missing key whatever the certificate name contains (dots, line breaks)', async () => {
    const message =
      'Закрытый ключ для сертификата CN=signer.example.ru, O=ООО "А.Б."\nне найден в хранилище.';
    const { signer } = setup(json({ message }, { status: 400 }));
    await expect(signer.sign(data)).rejects.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('keeps other 400 errors as plain SignerHttpError', async () => {
    const { signer } = setup(json({ message: 'Сертификат не предоставлен' }, { status: 400 }));
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerHttpError);
    expect(error).not.toBeInstanceOf(SignerKeyNotFoundError);
  });

  it('joins array validation messages', async () => {
    const { signer } = setup(
      json({ message: ['data must be base64', 'cert is required'] }, { status: 400 }),
    );
    await expect(signer.sign(data)).rejects.toMatchObject({
      upstreamMessage: 'data must be base64; cert is required',
    });
  });

  it('truncates a long upstream message', async () => {
    const { signer } = setup(json({ message: 'x'.repeat(5000) }, { status: 500 }));
    const error = (await signer.sign(data).catch((e: unknown) => e)) as SignerHttpError;
    expect(error.upstreamMessage.length).toBeLessThanOrEqual(500);
  });

  it('does not follow redirects (the API key must not reach another host)', async () => {
    const cause = new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
    const { signer } = setup(() => Promise.reject(cause), { apiKey: 'secret-key' });
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerNetworkError);
    expect(String(error)).not.toContain('secret-key');
  });

  it('aborts when the caller signal aborts and rethrows its reason', async () => {
    const fetchMock = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(init.signal?.reason as Error);
          });
        }),
    );
    const signer = new ServerCmsSigner({
      baseUrl: 'http://server.test',
      certificate: certDer,
      fetch: fetchMock,
    });
    const controller = new AbortController();
    const reason = new Error('shutdown');
    const pending = signer.sign(data, { signal: controller.signal });
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it('times out while reading a hanging response body', async () => {
    const fetchMock = vi.fn<typeof fetch>((_url, init) => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          init?.signal?.addEventListener('abort', () => {
            controller.error(init.signal?.reason);
          });
        },
      });
      return Promise.resolve(new Response(body, { status: 201 }));
    });
    const signer = new ServerCmsSigner({
      baseUrl: 'http://server.test',
      certificate: certDer,
      fetch: fetchMock,
      timeoutMs: 20,
    });
    await expect(signer.sign(data)).rejects.toThrow(SignerTimeoutError);
  });

  it('maps a non-JSON error body to SignerHttpError with the raw text', async () => {
    const { signer } = setup(new Response('Bad Gateway', { status: 502 }));
    await expect(signer.sign(data)).rejects.toMatchObject({
      name: 'SignerHttpError',
      status: 502,
      upstreamMessage: 'Bad Gateway',
    });
  });

  it('maps 401 without leaking the API key', async () => {
    const { signer } = setup(
      json({ message: 'API key is required', statusCode: 401 }, { status: 401 }),
      { apiKey: 'secret-key' },
    );
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 401, upstreamMessage: 'API key is required' });
    expect(JSON.stringify(error) + String(error)).not.toContain('secret-key');
  });

  it.each([
    ['no cms field', { status: 201 }],
    ['empty cms', { cms: '' }],
    ['cms not a string', { cms: 42 }],
    ['cms not base64', { cms: 'not base64!!' }],
    ['cms not DER', { cms: Buffer.from('plain').toString('base64') }],
    ['cms truncated DER', { cms: cmsDer.subarray(0, 8).toString('base64') }],
    ['cms BER without end-of-contents', { cms: cmsBer.subarray(0, -4).toString('base64') }],
    ['cms not SignedData', { cms: Buffer.from([0x30, 0x03, 0x06, 0x01, 0x2a]).toString('base64') }],
    [
      'cms with trailing bytes',
      { cms: Buffer.concat([cmsDer, Buffer.from([0])]).toString('base64') },
    ],
  ])('rejects a malformed success response: %s', async (_name, body) => {
    const { signer } = setup(json(body));
    await expect(signer.sign(data)).rejects.toThrow(SignerResponseError);
  });

  it('rejects a success response that is not JSON', async () => {
    const { signer } = setup(new Response('<html>', { status: 200 }));
    await expect(signer.sign(data)).rejects.toThrow(SignerResponseError);
  });

  it('maps a timeout to SignerTimeoutError', async () => {
    const { signer } = setup(
      () => Promise.reject(new DOMException('The operation timed out.', 'TimeoutError')),
      { timeoutMs: 5 },
    );
    await expect(signer.sign(data)).rejects.toThrow(SignerTimeoutError);
  });

  it('aborts a hanging request after timeoutMs', async () => {
    const fetchMock = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(init.signal?.reason as Error);
          });
        }),
    );
    const signer = new ServerCmsSigner({
      baseUrl: 'http://server.test',
      certificate: certDer,
      fetch: fetchMock,
      timeoutMs: 20,
    });
    await expect(signer.sign(data)).rejects.toThrow(SignerTimeoutError);
  });

  it('maps a network failure to SignerNetworkError keeping the cause', async () => {
    const cause = new TypeError('fetch failed');
    const { signer } = setup(() => Promise.reject(cause));
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerNetworkError);
    expect((error as Error).cause).toBe(cause);
  });
});

describe('ServerCmsSigner.verify', () => {
  const signature = cmsDer;
  const validResponse = {
    isValidSign: true,
    isValid: true,
    signs: [
      {
        cadesTypeName: 'CAdES-BES',
        certificate: { subjectName: 'CN=cryptoarm.server.test', thumbprint: '0e84b5' },
        signingTime: '2026-09-24T10:52:48.000Z',
        isCertChainValid: true,
        isValidSign: true,
        isDetached: true,
        extVerifyInfo: { cadesVfyStatus: 0, mathValidity: true },
      },
    ],
  };

  it('posts the detached CMS together with the signed data', async () => {
    const { signer, fetchMock } = setup(json(validResponse), { apiKey: 'k' });
    await signer.verify(data, signature);
    const { url, init, body } = lastRequest(fetchMock);
    expect(url).toBe('http://server.test:3037/cms/verify');
    expect(init.method).toBe('POST');
    expect(body).toEqual({ cms: signature.toString('base64'), data: data.toString('base64') });
    expect(new Headers(init.headers).get('x-api-key')).toBe('k');
  });

  it('reports a valid signature with signer details', async () => {
    const { signer } = setup(json(validResponse));
    await expect(signer.verify(data, signature)).resolves.toEqual({
      valid: true,
      signers: [
        {
          subject: 'CN=cryptoarm.server.test',
          thumbprint: '0e84b5',
          signingTime: '2026-09-24T10:52:48.000Z',
          valid: true,
          mathValid: true,
          chainValid: true,
          detached: true,
        },
      ],
    });
  });

  it('reports certificate validity, expiry and the detached flag when the server gives them', async () => {
    const sign = {
      ...validResponse.signs[0],
      certificate: {
        ...validResponse.signs[0]?.certificate,
        notAfter: '2026-10-28T12:32:11.000Z',
      },
      isCertValid: false,
      isCertChainValid: false,
      isValidSign: false,
    };
    const { signer } = setup(json({ isValidSign: false, signs: [sign] }));
    const result = await signer.verify(data, signature);
    expect(result.signers[0]).toEqual({
      subject: 'CN=cryptoarm.server.test',
      thumbprint: '0e84b5',
      signingTime: '2026-09-24T10:52:48.000Z',
      notAfter: '2026-10-28T12:32:11.000Z',
      valid: false,
      mathValid: true,
      chainValid: false,
      certValid: false,
      detached: true,
    });
  });

  it('reports an invalid signature with the upstream reason', async () => {
    const { signer } = setup(
      json({
        isValidSign: false,
        isValid: false,
        message: 'Подпись не верна',
        signs: [
          {
            certificate: { subjectName: 'CN=x' },
            isValidSign: false,
            cadesVfyStatusDescription: 'hash mismatch',
            extVerifyInfo: { mathValidity: false },
          },
        ],
      }),
    );
    const result = await signer.verify(data, signature);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Подпись не верна; hash mismatch');
    expect(result.signers[0]).toMatchObject({ subject: 'CN=x', valid: false, mathValid: false });
  });

  it('treats a response with no signatures as invalid', async () => {
    const { signer } = setup(json({ isValidSign: true, signs: [] }));
    await expect(signer.verify(data, signature)).resolves.toMatchObject({ valid: false });
  });

  it('rejects a response without isValidSign', async () => {
    const { signer } = setup(json({ signs: [] }));
    await expect(signer.verify(data, signature)).rejects.toThrow(SignerResponseError);
  });

  it('maps upstream errors to SignerHttpError', async () => {
    const { signer } = setup(json({ message: 'bad cms', statusCode: 400 }, { status: 400 }));
    await expect(signer.verify(data, signature)).rejects.toMatchObject({
      name: 'SignerHttpError',
      status: 400,
      operation: 'verify',
    });
  });

  it('refuses empty data or signature without calling the server', async () => {
    const { signer, fetchMock } = setup(json(validResponse));
    await expect(signer.verify(Buffer.alloc(0), signature)).rejects.toThrow(SignerError);
    await expect(signer.verify(data, Buffer.alloc(0))).rejects.toThrow(SignerError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('ServerCmsSigner request size limit', () => {
  const ok = () => Promise.resolve(json({ cms: cmsDer.toString('base64') }));
  // Exact JSON body of sign(data) with certDer, as sent on the wire.
  const signBodyBytes = (bytes: Buffer) =>
    Buffer.byteLength(
      JSON.stringify({
        cert: certDer.toString('base64'),
        data: bytes.toString('base64'),
        detached: true,
        cadesStandard: 'CAdES-BES',
      }),
    );

  it('defaults to the КриптоАРМ Server JSON_LIMIT of 50mb (52 428 800 B, measured on the stand)', () => {
    expect(DEFAULT_MAX_REQUEST_BYTES).toBe(52_428_800);
  });

  it('sends a body of exactly maxRequestBytes and refuses one byte more without calling the server', async () => {
    const limit = signBodyBytes(data);
    const { signer: atLimit, fetchMock } = setup(ok, { maxRequestBytes: limit });
    await atLimit.sign(data);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const { init } = lastRequest(fetchMock);
    expect(Buffer.byteLength(init.body as string)).toBe(limit);

    const { signer: below, fetchMock: notCalled } = setup(ok, { maxRequestBytes: limit - 1 });
    const error = await below.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerPayloadTooLargeError);
    expect(error).toBeInstanceOf(SignerError);
    expect(error).toMatchObject({
      operation: 'sign',
      requestBytes: limit,
      limitBytes: limit - 1,
      status: undefined,
    });
    expect((error as Error).message).toMatch(/sign: .*request body.*too large/i);
    expect((error as Error).message).toContain(String(limit - 1));
    expect(notCalled).not.toHaveBeenCalled();
  });

  it('refuses data above the default limit before encoding or sending it', async () => {
    const { signer, fetchMock } = setup(ok);
    // base64 alone: 4 * 13 107 201 = 52 428 804 B > 52 428 800 B.
    const big = Buffer.alloc(3 * 13_107_201);
    await expect(signer.sign(big)).rejects.toMatchObject({
      name: 'SignerPayloadTooLargeError',
      limitBytes: DEFAULT_MAX_REQUEST_BYTES,
    });
    await expect(signer.verify(big, cmsDer)).rejects.toMatchObject({
      name: 'SignerPayloadTooLargeError',
      operation: 'verify',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('counts the signature in the verify body', async () => {
    const body = Buffer.byteLength(
      JSON.stringify({ cms: cmsDer.toString('base64'), data: data.toString('base64') }),
    );
    const { signer, fetchMock } = setup(json({ isValidSign: false }), {
      maxRequestBytes: body - 1,
    });
    await expect(signer.verify(data, cmsDer)).rejects.toMatchObject({
      name: 'SignerPayloadTooLargeError',
      requestBytes: body,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['400 «request entity too large» (what the stand answers)', 400],
    ['413', 413],
  ])('maps an upstream %s to SignerPayloadTooLargeError', async (_label, status) => {
    const { signer } = setup(
      json(
        { statusCode: status, message: 'request entity too large' },
        { status, headers: { 'X-Request-Id': 'req-7' } },
      ),
    );
    const error = await signer.sign(data).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerPayloadTooLargeError);
    expect(error).toMatchObject({
      operation: 'sign',
      status,
      requestBytes: signBodyBytes(data),
      limitBytes: DEFAULT_MAX_REQUEST_BYTES,
    });
    expect(error).toMatchObject({
      upstreamMessage: 'request entity too large',
      requestId: 'req-7',
    });
    expect((error as Error).message).toContain('JSON_LIMIT');
    expect((error as Error).message).toContain('request id req-7');
    expect((error as Error).message).toMatch(/proxy/);
  });

  it('maps a bare 413 without a JSON body too', async () => {
    const { signer } = setup(new Response('Payload Too Large', { status: 413 }));
    await expect(signer.verify(data, cmsDer)).rejects.toMatchObject({
      name: 'SignerPayloadTooLargeError',
      operation: 'verify',
      status: 413,
    });
  });

  it.each([0, -1, 1.5, Number.NaN])('rejects maxRequestBytes %s', (maxRequestBytes) => {
    expect(() => setup(ok, { maxRequestBytes })).toThrow(SignerConfigError);
  });
});

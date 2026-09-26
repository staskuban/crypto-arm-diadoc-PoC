import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import {
  createSignerFromEnv,
  signerKind,
  loadDocumentsCloudSignerEnv,
  loadServerCmsSignerOptions,
} from './config.js';
import { DocumentsCloudSigner } from './documents-cloud-signer.js';
import { SignerConfigError } from './errors.js';
import { ServerCmsSigner } from './server-cms-signer.js';

const certDer = readFileSync(new URL('./fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url));
/** An unsigned JWT with the given payload (the config reads only `exp`). */
function jwt(payload: Record<string, unknown>): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'HS256', typ: 'JWT' })}.${part(payload)}.c2ln`;
}
/** 2100-01-01T00:00:00Z */
const FUTURE_EXP = 4_102_444_800;
const JWT = jwt({ sub: 'svc', exp: FUTURE_EXP });

describe('loadServerCmsSignerOptions', () => {
  const readFile = vi.fn((path: string) =>
    path === '/certs/signer.cer' ? Promise.resolve(certDer) : Promise.reject(new Error('ENOENT')),
  );

  it('reads URL, API key, certificate and timeout from env', async () => {
    const options = await loadServerCmsSignerOptions(
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037',
        CRYPTOARM_SERVER_API_KEY: 'key',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_TIMEOUT_MS: '5000',
        CRYPTOARM_SERVER_MAX_REQUEST_BYTES: '104857600',
      },
      readFile,
    );
    expect(options).toEqual({
      baseUrl: 'http://127.0.0.1:3037',
      apiKey: 'key',
      certificate: certDer,
      timeoutMs: 5000,
      maxRequestBytes: 104_857_600,
    });
  });

  it('omits optional values that are unset or empty', async () => {
    const options = await loadServerCmsSignerOptions(
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037',
        CRYPTOARM_SERVER_API_KEY: '',
        SIGNER_CERT_PATH: '/certs/signer.cer',
      },
      readFile,
    );
    expect(options).toEqual({ baseUrl: 'http://127.0.0.1:3037', certificate: certDer });
  });

  it.each([
    [{ SIGNER_CERT_PATH: '/certs/signer.cer' }, /CRYPTOARM_SERVER_URL/],
    [{ CRYPTOARM_SERVER_URL: 'http://127.0.0.1' }, /SIGNER_CERT_PATH/],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_TIMEOUT_MS: 'x',
      },
      /CRYPTOARM_SERVER_TIMEOUT_MS/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_TIMEOUT_MS: '9999999999',
      },
      /CRYPTOARM_SERVER_TIMEOUT_MS/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_MAX_REQUEST_BYTES: '50mb',
      },
      /CRYPTOARM_SERVER_MAX_REQUEST_BYTES/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://127.0.0.1',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_MAX_REQUEST_BYTES: '0',
      },
      /CRYPTOARM_SERVER_MAX_REQUEST_BYTES/,
    ],
  ])('rejects incomplete env %#', async (env, message) => {
    await expect(loadServerCmsSignerOptions(env, readFile)).rejects.toThrow(message);
  });

  it.each(['/certs/signer.pfx', '/certs/SIGNER.P12'])(
    'rejects a PKCS#12 path %s without reading it',
    async (path) => {
      const read = vi.fn(readFile);
      await expect(
        loadServerCmsSignerOptions(
          { CRYPTOARM_SERVER_URL: 'http://127.0.0.1', SIGNER_CERT_PATH: path },
          read,
        ),
      ).rejects.toThrow(/PKCS#12/);
      expect(read).not.toHaveBeenCalled();
    },
  );

  it('wraps an unreadable certificate file in SignerConfigError', async () => {
    const error = await loadServerCmsSignerOptions(
      { CRYPTOARM_SERVER_URL: 'http://127.0.0.1', SIGNER_CERT_PATH: '/missing.cer' },
      readFile,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect((error as Error).message).toContain('/missing.cer');
  });
});

describe('loadDocumentsCloudSignerEnv', () => {
  const files: Record<string, string> = {
    '/certs/signer.cer': certDer.toString('latin1'),
    '/run/secrets/jwt': `${JWT}\n`,
    '/run/secrets/password': ' pass word \n',
  };
  const readFile = vi.fn((path: string) =>
    path in files
      ? Promise.resolve(Buffer.from(files[path] ?? '', 'latin1'))
      : Promise.reject(new Error('ENOENT')),
  );
  const base = { DOCUMENTS_URL: 'http://127.0.0.1:3040', SIGNER_CERT_PATH: '/certs/signer.cer' };

  it('reads URL, certificate, JWT file, content type and timeout', async () => {
    const options = await loadDocumentsCloudSignerEnv(
      {
        ...base,
        DOCUMENTS_JWT_FILE: '/run/secrets/jwt',
        DOCUMENTS_UPLOAD_CONTENT_TYPE: 'application/xml',
        DOCUMENTS_TIMEOUT_MS: '5000',
      },
      readFile,
    );
    expect(options).toEqual({
      baseUrl: 'http://127.0.0.1:3040',
      certificate: certDer,
      auth: { jwt: JWT },
      uploadContentType: 'application/xml',
      timeoutMs: 5000,
    });
  });

  it('accepts the JWT inline', async () => {
    const options = await loadDocumentsCloudSignerEnv({ ...base, DOCUMENTS_JWT: JWT }, readFile);
    expect(options.auth).toEqual({ jwt: JWT });
  });

  it('reads login + password file, keeping inner and leading spaces of the password', async () => {
    const options = await loadDocumentsCloudSignerEnv(
      { ...base, DOCUMENTS_LOGIN: 'svc', DOCUMENTS_PASSWORD_FILE: '/run/secrets/password' },
      readFile,
    );
    expect(options.auth).toEqual({ login: 'svc', password: ' pass word ' });
    const inline = await loadDocumentsCloudSignerEnv(
      { ...base, DOCUMENTS_LOGIN: 'svc', DOCUMENTS_PASSWORD: 'p' },
      readFile,
    );
    expect(inline.auth).toEqual({ login: 'svc', password: 'p' });
  });

  it.each([
    [{ SIGNER_CERT_PATH: '/certs/signer.cer', DOCUMENTS_JWT: JWT }, /DOCUMENTS_URL is not set/],
    [{ DOCUMENTS_URL: 'http://127.0.0.1:3040', DOCUMENTS_JWT: JWT }, /SIGNER_CERT_PATH is not set/],
    [base, /set DOCUMENTS_JWT_FILE .* or DOCUMENTS_LOGIN/],
    [{ ...base, DOCUMENTS_JWT: JWT, DOCUMENTS_LOGIN: 'svc' }, /either .*JWT.* or .*LOGIN/],
    [{ ...base, DOCUMENTS_JWT: JWT, DOCUMENTS_JWT_FILE: '/run/secrets/jwt' }, /not both/],
    [{ ...base, DOCUMENTS_LOGIN: 'svc' }, /DOCUMENTS_PASSWORD_FILE or DOCUMENTS_PASSWORD/],
    [{ ...base, DOCUMENTS_PASSWORD: 'p' }, /DOCUMENTS_LOGIN/],
    [{ ...base, DOCUMENTS_JWT: JWT, DOCUMENTS_TIMEOUT_MS: '0' }, /DOCUMENTS_TIMEOUT_MS/],
    [{ ...base, DOCUMENTS_JWT_FILE: '/missing' }, /cannot read DOCUMENTS_JWT_FILE \/missing/],
  ])('rejects env %#', async (env, message) => {
    const error = await loadDocumentsCloudSignerEnv(env, readFile).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(message);
  });

  it('never echoes a secret value in an error', async () => {
    const error = await loadDocumentsCloudSignerEnv(
      {
        ...base,
        DOCUMENTS_JWT: 'top-secret-jwt',
        DOCUMENTS_LOGIN: 'svc',
        DOCUMENTS_PASSWORD: 'pw-9',
      },
      readFile,
    ).catch((e: unknown) => e);
    expect(String(error)).not.toMatch(/top-secret-jwt|pw-9/);
  });
});

describe('createSignerFromEnv', () => {
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const server = {
    CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037',
    SIGNER_CERT_PATH: '/certs/signer.cer',
  };

  it('builds a ServerCmsSigner by default and for SIGNER_KIND=server', async () => {
    expect(await createSignerFromEnv(server, readFile)).toBeInstanceOf(ServerCmsSigner);
    expect(
      await createSignerFromEnv({ ...server, SIGNER_KIND: 'server' }, readFile),
    ).toBeInstanceOf(ServerCmsSigner);
  });

  it('builds a DocumentsCloudSigner for SIGNER_KIND=documents', async () => {
    const signer = await createSignerFromEnv(
      {
        ...server,
        SIGNER_KIND: 'documents',
        DOCUMENTS_URL: 'http://127.0.0.1:3040',
        DOCUMENTS_JWT: JWT,
      },
      readFile,
    );
    expect(signer).toBeInstanceOf(DocumentsCloudSigner);
    expect(signer.certificate).toEqual(certDer);
  });

  it('requires КриптоАРМ Server for verification with SIGNER_KIND=documents', async () => {
    const error = await createSignerFromEnv(
      {
        SIGNER_KIND: 'documents',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        DOCUMENTS_URL: 'http://127.0.0.1:3040',
        DOCUMENTS_JWT: JWT,
      },
      readFile,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(/CRYPTOARM_SERVER_URL is not set .*verif/);
  });

  it('rejects an unknown SIGNER_KIND', async () => {
    await expect(createSignerFromEnv({ ...server, SIGNER_KIND: 'dss' }, readFile)).rejects.toThrow(
      /SIGNER_KIND must be "server", "documents" or "diadoc-test", got "dss"/,
    );
  });

  it('builds no signer for SIGNER_KIND=diadoc-test (the pipeline posts the Diadoc test signature)', async () => {
    await expect(
      createSignerFromEnv({ ...server, SIGNER_KIND: 'diadoc-test' }, readFile),
    ).rejects.toThrow(/SIGNER_KIND=diadoc-test has no signer/);
  });

  it.each<[string | undefined, string]>([
    [undefined, 'server'],
    ['', 'server'],
    ['documents', 'documents'],
    ['diadoc-test', 'diadoc-test'],
  ])('signerKind(%j) = %s', (kind, expected) => {
    expect(signerKind({ SIGNER_KIND: kind })).toBe(expected);
  });

  it('signerKind rejects an unknown kind', () => {
    expect(() => signerKind({ SIGNER_KIND: 'Server' })).toThrow(SignerConfigError);
  });
});

describe('transport policy (D20)', () => {
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const server = { SIGNER_CERT_PATH: '/certs/signer.cer' };
  const documents = { ...server, DOCUMENTS_JWT: JWT };

  it.each([
    'https://cryptoarm.example.com',
    'https://cryptoarm-server.example.com',
    'http://localhost:3037',
    'http://LOCALHOST:3037',
    'http://127.0.0.1:3037',
    'http://127.1:3037',
    'http://[::1]:3037',
    'http://[0:0:0:0:0:0:0:1]:3037',
  ])('accepts %s for both services', async (url) => {
    await expect(
      loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_URL: url }, readFile),
    ).resolves.toMatchObject({ baseUrl: url });
    await expect(
      loadDocumentsCloudSignerEnv({ ...documents, DOCUMENTS_URL: url }, readFile),
    ).resolves.toMatchObject({ baseUrl: url });
  });

  it.each(['http://cryptoarm-server:3037', 'http://Cryptoarm-Server:3037'])(
    'accepts the compose service name %s only for КриптоАРМ Server',
    async (url) => {
      await expect(
        loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_URL: url }, readFile),
      ).resolves.toMatchObject({ baseUrl: url });
      await expect(
        loadDocumentsCloudSignerEnv({ ...documents, DOCUMENTS_URL: url }, readFile),
      ).rejects.toThrow(/DOCUMENTS_URL must use https/);
    },
  );

  it.each([
    'http://cryptoarm.example.com',
    'http://10.0.0.5:3037',
    'http://cryptoarm-server.evil.example:3037',
    'http://localhost.:3037',
    'http://127.0.0.2:3037',
    'http://0.0.0.0:3037',
    'http://[::ffff:127.0.0.1]:3037',
    'http://documents-api:3000',
    'http://kryptoarm-diadoc-cryptoarm-server:3037',
  ])('refuses plain http to %s', async (url) => {
    const serverError = await loadServerCmsSignerOptions(
      { ...server, CRYPTOARM_SERVER_URL: url },
      readFile,
    ).catch((e: unknown) => e);
    expect(serverError).toBeInstanceOf(SignerConfigError);
    expect(String(serverError)).toMatch(/CRYPTOARM_SERVER_URL must use https/);
    const documentsError = await loadDocumentsCloudSignerEnv(
      { ...documents, DOCUMENTS_URL: url },
      readFile,
    ).catch((e: unknown) => e);
    expect(documentsError).toBeInstanceOf(SignerConfigError);
    expect(String(documentsError)).toMatch(/DOCUMENTS_URL must use https/);
  });

  it('refuses a URL that does not parse, without echoing it', async () => {
    const error = await loadServerCmsSignerOptions(
      { ...server, CRYPTOARM_SERVER_URL: 'not a url secret-9' },
      readFile,
    ).catch((e: unknown) => e);
    expect(String(error)).toMatch(/CRYPTOARM_SERVER_URL is not a valid URL/);
    expect(String(error)).not.toContain('secret-9');
  });
});

describe('placeholders (D20)', () => {
  const readFile = vi.fn((path: string) =>
    Promise.resolve(path === '/run/secrets/password' ? Buffer.from('changeme\n') : certDer),
  );
  const server = { CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037', SIGNER_CERT_PATH: '/c.cer' };
  const documents = { DOCUMENTS_URL: 'http://127.0.0.1:3040', SIGNER_CERT_PATH: '/c.cer' };

  it.each(['changeme', 'change-me-api-key'])(
    'refuses the CRYPTOARM_SERVER_API_KEY placeholder %s',
    async (key) => {
      await expect(
        loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_API_KEY: key }, readFile),
      ).rejects.toThrow(/CRYPTOARM_SERVER_API_KEY is still the placeholder/);
    },
  );

  it.each([
    [{ DOCUMENTS_JWT: 'changeme' }, /DOCUMENTS_JWT is still the placeholder/],
    [{ DOCUMENTS_LOGIN: 'changeme', DOCUMENTS_PASSWORD: 'p' }, /DOCUMENTS_LOGIN is still/],
    [{ DOCUMENTS_LOGIN: 'svc', DOCUMENTS_PASSWORD: 'changeme' }, /DOCUMENTS_PASSWORD is still/],
    [
      { DOCUMENTS_LOGIN: 'svc', DOCUMENTS_PASSWORD_FILE: '/run/secrets/password' },
      /DOCUMENTS_PASSWORD is still/,
    ],
  ])('refuses Документы placeholder %#', async (env, message) => {
    const error = await loadDocumentsCloudSignerEnv({ ...documents, ...env }, readFile).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(message);
  });
});

describe('DOCUMENTS_JWT expiry (R2 minor 3)', () => {
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const base = { DOCUMENTS_URL: 'http://127.0.0.1:3040', SIGNER_CERT_PATH: '/c.cer' };
  const now = () => Date.UTC(2026, 8, 24, 12, 0, 0);
  const at = (iso: string) => Date.parse(iso) / 1000;

  it('accepts a JWT without exp or with exp at least 5 minutes ahead', async () => {
    for (const token of [jwt({ sub: 'svc' }), jwt({ exp: at('2026-09-24T12:05:00Z') })]) {
      await expect(
        loadDocumentsCloudSignerEnv({ ...base, DOCUMENTS_JWT: token }, readFile, now),
      ).resolves.toMatchObject({ auth: { jwt: token } });
    }
  });

  it.each([
    [
      jwt({ exp: at('2026-09-24T11:00:00Z') }),
      /DOCUMENTS_JWT expired at 2026-09-24T11:00:00\.000Z/,
    ],
    [
      jwt({ exp: at('2026-09-24T12:04:59Z') }),
      /DOCUMENTS_JWT expires at 2026-09-24T12:04:59\.000Z/,
    ],
    [jwt({ exp: 'soon' }), /DOCUMENTS_JWT has a non-numeric exp/],
    ['not-a-jwt', /DOCUMENTS_JWT is not a JWT/],
    ['a.%%%.c', /DOCUMENTS_JWT is not a JWT/],
    [
      `${Buffer.from('{}').toString('base64url')}.${Buffer.from('[1]').toString('base64url')}.c`,
      /DOCUMENTS_JWT is not a JWT/,
    ],
  ])('refuses %s', async (token, message) => {
    const error = await loadDocumentsCloudSignerEnv(
      { ...base, DOCUMENTS_JWT: token },
      readFile,
      now,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(message);
    expect(String(error)).not.toContain(token);
  });

  it('checks the JWT from DOCUMENTS_JWT_FILE too', async () => {
    const expired = jwt({ exp: 1 });
    const error = await loadDocumentsCloudSignerEnv(
      { ...base, DOCUMENTS_JWT_FILE: '/run/secrets/jwt' },
      (path) =>
        Promise.resolve(path === '/run/secrets/jwt' ? Buffer.from(`${expired}\n`) : certDer),
      now,
    ).catch((e: unknown) => e);
    expect(String(error)).toMatch(/DOCUMENTS_JWT expired at 1970/);
  });
});

describe('SIGNER_CERT_PATH is parsed at start (R2 minor 17)', () => {
  const server = { CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037', SIGNER_CERT_PATH: '/c.cer' };
  const pem = (der: Buffer, eol: string) =>
    `-----BEGIN CERTIFICATE-----${eol}${(der.toString('base64').match(/.{1,64}/g) ?? []).join(eol)}${eol}-----END CERTIFICATE-----${eol}`;

  it.each(['\n', '\r\n'])('converts a PEM certificate to DER (eol %j)', async (eol) => {
    const options = await loadServerCmsSignerOptions(server, () =>
      Promise.resolve(Buffer.from(pem(certDer, eol))),
    );
    expect(options.certificate).toEqual(certDer);
  });

  it.each([
    ['garbage', Buffer.from('hello'), /not a DER or PEM encoded X\.509 certificate/],
    ['a SEQUENCE that is no certificate', Buffer.from('3003020102', 'hex'), /PKCS#12/],
    [
      'a SEQUENCE of SEQUENCEs that is no certificate',
      Buffer.from('300830030201020501' + '00', 'hex'),
      /not an X\.509 certificate/,
    ],
    [
      'non-minimal DER lengths',
      Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), certDer.subarray(2, 4), certDer.subarray(4)]),
      /must be DER/,
    ],
    ['a truncated certificate', certDer.subarray(0, certDer.length - 1), /X\.509/],
  ])('refuses %s with SignerConfigError naming the path', async (_name, bytes, message) => {
    const error = await loadServerCmsSignerOptions(server, () => Promise.resolve(bytes)).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(message);
    expect(String(error)).toContain('SIGNER_CERT_PATH /c.cer');
  });
});

describe('DOCUMENTS_JWT expiry edge cases', () => {
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const base = { DOCUMENTS_URL: 'http://127.0.0.1:3040', SIGNER_CERT_PATH: '/c.cer' };

  it('accepts an exp beyond the Date range instead of crashing', async () => {
    const token = jwt({ exp: 1e300 });
    await expect(
      loadDocumentsCloudSignerEnv({ ...base, DOCUMENTS_JWT: token }, readFile),
    ).resolves.toMatchObject({ auth: { jwt: token } });
  });

  it('refuses an exp far in the past below the Date range', async () => {
    await expect(
      loadDocumentsCloudSignerEnv({ ...base, DOCUMENTS_JWT: jwt({ exp: -1e300 }) }, readFile),
    ).rejects.toThrow(SignerConfigError);
  });
});

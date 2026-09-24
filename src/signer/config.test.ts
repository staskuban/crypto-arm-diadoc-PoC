import { describe, expect, it, vi } from 'vitest';

import {
  createSignerFromEnv,
  loadDocumentsCloudSignerEnv,
  loadServerCmsSignerOptions,
} from './config.js';
import { DocumentsCloudSigner } from './documents-cloud-signer.js';
import { SignerConfigError } from './errors.js';
import { ServerCmsSigner } from './server-cms-signer.js';

const certDer = Buffer.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x05, 0x01, 0x00]);

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
    [{ CRYPTOARM_SERVER_URL: 'http://s' }, /SIGNER_CERT_PATH/],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://s',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_TIMEOUT_MS: 'x',
      },
      /CRYPTOARM_SERVER_TIMEOUT_MS/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://s',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_TIMEOUT_MS: '9999999999',
      },
      /CRYPTOARM_SERVER_TIMEOUT_MS/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://s',
        SIGNER_CERT_PATH: '/certs/signer.cer',
        CRYPTOARM_SERVER_MAX_REQUEST_BYTES: '50mb',
      },
      /CRYPTOARM_SERVER_MAX_REQUEST_BYTES/,
    ],
    [
      {
        CRYPTOARM_SERVER_URL: 'http://s',
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
          { CRYPTOARM_SERVER_URL: 'http://s', SIGNER_CERT_PATH: path },
          read,
        ),
      ).rejects.toThrow(/PKCS#12/);
      expect(read).not.toHaveBeenCalled();
    },
  );

  it('wraps an unreadable certificate file in SignerConfigError', async () => {
    const error = await loadServerCmsSignerOptions(
      { CRYPTOARM_SERVER_URL: 'http://s', SIGNER_CERT_PATH: '/missing.cer' },
      readFile,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect((error as Error).message).toContain('/missing.cer');
  });
});

describe('loadDocumentsCloudSignerEnv', () => {
  const files: Record<string, string> = {
    '/certs/signer.cer': certDer.toString('latin1'),
    '/run/secrets/jwt': 'jwt.from.file\n',
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
      auth: { jwt: 'jwt.from.file' },
      uploadContentType: 'application/xml',
      timeoutMs: 5000,
    });
  });

  it('accepts the JWT inline', async () => {
    const options = await loadDocumentsCloudSignerEnv(
      { ...base, DOCUMENTS_JWT: 'inline' },
      readFile,
    );
    expect(options.auth).toEqual({ jwt: 'inline' });
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
    [{ SIGNER_CERT_PATH: '/certs/signer.cer', DOCUMENTS_JWT: 'j' }, /DOCUMENTS_URL is not set/],
    [{ DOCUMENTS_URL: 'http://d', DOCUMENTS_JWT: 'j' }, /SIGNER_CERT_PATH is not set/],
    [base, /set DOCUMENTS_JWT_FILE .* or DOCUMENTS_LOGIN/],
    [{ ...base, DOCUMENTS_JWT: 'j', DOCUMENTS_LOGIN: 'svc' }, /either .*JWT.* or .*LOGIN/],
    [{ ...base, DOCUMENTS_JWT: 'j', DOCUMENTS_JWT_FILE: '/run/secrets/jwt' }, /not both/],
    [{ ...base, DOCUMENTS_LOGIN: 'svc' }, /DOCUMENTS_PASSWORD_FILE or DOCUMENTS_PASSWORD/],
    [{ ...base, DOCUMENTS_PASSWORD: 'p' }, /DOCUMENTS_LOGIN/],
    [{ ...base, DOCUMENTS_JWT: 'j', DOCUMENTS_TIMEOUT_MS: '0' }, /DOCUMENTS_TIMEOUT_MS/],
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
      { ...server, SIGNER_KIND: 'documents', DOCUMENTS_URL: 'http://d', DOCUMENTS_JWT: 'j' },
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
        DOCUMENTS_URL: 'http://d',
        DOCUMENTS_JWT: 'j',
      },
      readFile,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerConfigError);
    expect(String(error)).toMatch(/CRYPTOARM_SERVER_URL is not set .*verif/);
  });

  it('rejects an unknown SIGNER_KIND', async () => {
    await expect(createSignerFromEnv({ ...server, SIGNER_KIND: 'dss' }, readFile)).rejects.toThrow(
      /SIGNER_KIND must be "server" or "documents", got "dss"/,
    );
  });
});

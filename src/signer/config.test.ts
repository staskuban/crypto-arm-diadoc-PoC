import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import { createSignerFromEnv, signerKind, loadServerCmsSignerOptions } from './config.js';
import { SignerConfigError } from './errors.js';
import { ServerCmsSigner } from './server-cms-signer.js';

const certDer = readFileSync(new URL('./fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url));

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

  it('rejects an unknown SIGNER_KIND', async () => {
    await expect(createSignerFromEnv({ ...server, SIGNER_KIND: 'dss' }, readFile)).rejects.toThrow(
      /SIGNER_KIND must be "server" or "diadoc-test", got "dss"/,
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
    ['diadoc-test', 'diadoc-test'],
  ])('signerKind(%j) = %s', (kind, expected) => {
    expect(signerKind({ SIGNER_KIND: kind })).toBe(expected);
  });

  it.each(['Server', 'documents'])('signerKind rejects %j (documents: removed in F21)', (kind) => {
    expect(() => signerKind({ SIGNER_KIND: kind })).toThrow(SignerConfigError);
  });
});

describe('transport policy (D20)', () => {
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const server = { SIGNER_CERT_PATH: '/certs/signer.cer' };

  it.each([
    'https://cryptoarm.example.com',
    'https://cryptoarm-server.example.com',
    'http://localhost:3037',
    'http://LOCALHOST:3037',
    'http://127.0.0.1:3037',
    'http://127.1:3037',
    'http://[::1]:3037',
    'http://[0:0:0:0:0:0:0:1]:3037',
  ])('accepts %s', async (url) => {
    await expect(
      loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_URL: url }, readFile),
    ).resolves.toMatchObject({ baseUrl: url });
  });

  it.each(['http://cryptoarm-server:3037', 'http://Cryptoarm-Server:3037'])(
    'accepts the compose service name %s',
    async (url) => {
      await expect(
        loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_URL: url }, readFile),
      ).resolves.toMatchObject({ baseUrl: url });
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
    'http://kryptoarm-diadoc-cryptoarm-server:3037',
  ])('refuses plain http to %s', async (url) => {
    const serverError = await loadServerCmsSignerOptions(
      { ...server, CRYPTOARM_SERVER_URL: url },
      readFile,
    ).catch((e: unknown) => e);
    expect(serverError).toBeInstanceOf(SignerConfigError);
    expect(String(serverError)).toMatch(/CRYPTOARM_SERVER_URL must use https/);
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
  const readFile = vi.fn(() => Promise.resolve(certDer));
  const server = { CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037', SIGNER_CERT_PATH: '/c.cer' };

  it.each(['changeme', 'change-me-api-key'])(
    'refuses the CRYPTOARM_SERVER_API_KEY placeholder %s',
    async (key) => {
      await expect(
        loadServerCmsSignerOptions({ ...server, CRYPTOARM_SERVER_API_KEY: key }, readFile),
      ).rejects.toThrow(/CRYPTOARM_SERVER_API_KEY is still the placeholder/);
    },
  );
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

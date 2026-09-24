import { describe, expect, it, vi } from 'vitest';

import { loadServerCmsSignerOptions } from './config.js';
import { SignerConfigError } from './errors.js';

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

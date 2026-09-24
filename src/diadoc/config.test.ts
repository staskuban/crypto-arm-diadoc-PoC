import { describe, expect, it } from 'vitest';

import { loadDiadocEnv } from './config.js';
import { DiadocConfigError } from './errors.js';

const base = {
  DIADOC_API_URL: 'https://diadoc-api-staging.kontur.ru',
  DIADOC_CLIENT_ID: 'cid',
  DIADOC_CLIENT_SECRET: 'secret',
  DIADOC_REFRESH_TOKEN: 'rt',
};

const noFile = (): Promise<string> => Promise.reject(new Error('no file expected'));

describe('loadDiadocEnv', () => {
  it('reads the API URL and refresh-token credentials', async () => {
    expect(await loadDiadocEnv(base, noFile)).toEqual({
      baseUrl: 'https://diadoc-api-staging.kontur.ru',
      clientId: 'cid',
      clientSecret: 'secret',
      refreshToken: 'rt',
    });
  });

  it('passes optional token URL and timeout', async () => {
    const config = await loadDiadocEnv(
      { ...base, DIADOC_TOKEN_URL: 'https://idp.test/token', DIADOC_TIMEOUT_MS: '5000' },
      noFile,
    );
    expect(config).toMatchObject({ tokenUrl: 'https://idp.test/token', timeoutMs: 5000 });
  });

  it.each(['DIADOC_API_URL', 'DIADOC_CLIENT_ID', 'DIADOC_CLIENT_SECRET'])(
    'requires %s',
    async (name) => {
      await expect(loadDiadocEnv({ ...base, [name]: '' }, noFile)).rejects.toThrow(
        new DiadocConfigError(`${name} is not set`),
      );
    },
  );

  it('requires a refresh token from env or file', async () => {
    await expect(
      loadDiadocEnv({ ...base, DIADOC_REFRESH_TOKEN: undefined }, noFile),
    ).rejects.toThrow(/DIADOC_REFRESH_TOKEN or DIADOC_REFRESH_TOKEN_FILE/);
  });

  it('prefers DIADOC_REFRESH_TOKEN_FILE (trimmed) and returns its path for rotation', async () => {
    const config = await loadDiadocEnv({ ...base, DIADOC_REFRESH_TOKEN_FILE: '/run/rt' }, (path) =>
      Promise.resolve(path === '/run/rt' ? ' from-file\n' : ''),
    );
    expect(config).toMatchObject({ refreshToken: 'from-file', refreshTokenFile: '/run/rt' });
  });

  it('rejects an empty or unreadable token file without echoing its content', async () => {
    const env = { ...base, DIADOC_REFRESH_TOKEN_FILE: '/run/rt' };
    await expect(loadDiadocEnv(env, () => Promise.resolve('\n'))).rejects.toThrow(/is empty/);
    await expect(loadDiadocEnv(env, () => Promise.reject(new Error('ENOENT')))).rejects.toThrow(
      /cannot read DIADOC_REFRESH_TOKEN_FILE/,
    );
  });

  it('rejects a non-https URL except for localhost', async () => {
    await expect(
      loadDiadocEnv({ ...base, DIADOC_API_URL: 'http://diadoc.example' }, noFile),
    ).rejects.toThrow(/https/);
    await expect(loadDiadocEnv({ ...base, DIADOC_API_URL: 'nope' }, noFile)).rejects.toThrow(
      DiadocConfigError,
    );
    expect(
      await loadDiadocEnv({ ...base, DIADOC_API_URL: 'http://127.0.0.1:8080' }, noFile),
    ).toMatchObject({ baseUrl: 'http://127.0.0.1:8080' });
  });

  it.each([
    'https://diadoc.example/?x=1',
    'https://diadoc.example/#top',
    'https://diadoc.example/?',
  ])('rejects a DIADOC_API_URL with a query or fragment: %s', async (url) => {
    await expect(loadDiadocEnv({ ...base, DIADOC_API_URL: url }, noFile)).rejects.toThrow(
      new DiadocConfigError('DIADOC_API_URL must not contain a query or fragment'),
    );
  });

  it('rejects the .env.example placeholder and blank values', async () => {
    await expect(
      loadDiadocEnv({ ...base, DIADOC_CLIENT_SECRET: 'changeme' }, noFile),
    ).rejects.toThrow(/DIADOC_CLIENT_SECRET is still the placeholder/);
    await expect(loadDiadocEnv({ ...base, DIADOC_CLIENT_ID: '  ' }, noFile)).rejects.toThrow(
      /DIADOC_CLIENT_ID is not set/,
    );
  });

  it('never echoes URL credentials in errors', async () => {
    const error: unknown = await loadDiadocEnv(
      { ...base, DIADOC_API_URL: 'http://user:pw@diadoc.example/x' },
      noFile,
    ).catch((e: unknown) => e);
    expect(String(error)).not.toMatch(/pw/);
  });

  it('rejects a bad timeout', async () => {
    await expect(loadDiadocEnv({ ...base, DIADOC_TIMEOUT_MS: '0' }, noFile)).rejects.toThrow(
      /DIADOC_TIMEOUT_MS/,
    );
  });
});

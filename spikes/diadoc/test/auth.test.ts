import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refreshAccessToken } from '../src/auth.ts';

test('posts a form-encoded refresh_token grant and returns the tokens', async () => {
  let seen: { url: string; init: RequestInit } | undefined;
  const fetchFn = async (url: string | URL | Request, init?: RequestInit) => {
    seen = { url: String(url), init: init! };
    return new Response(JSON.stringify({ access_token: 'AT', token_type: 'Bearer', expires_in: 86400, refresh_token: 'RT2' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const r = await refreshAccessToken({
    tokenUrl: 'https://identity.kontur.ru/connect/token',
    clientId: 'cid',
    clientSecret: 's&cret',
    refreshToken: 'RT1',
    fetchFn,
  });
  assert.deepEqual(r, { accessToken: 'AT', expiresIn: 86400, refreshToken: 'RT2' });
  assert.equal(seen!.url, 'https://identity.kontur.ru/connect/token');
  assert.equal(seen!.init.method, 'POST');
  assert.equal(new Headers(seen!.init.headers).get('content-type'), 'application/x-www-form-urlencoded');
  const body = new URLSearchParams(String(seen!.init.body));
  assert.deepEqual(Object.fromEntries(body), {
    grant_type: 'refresh_token',
    client_id: 'cid',
    client_secret: 's&cret',
    refresh_token: 'RT1',
  });
});

test('keeps the old refresh token when the response does not rotate it', async () => {
  const fetchFn = async () => new Response(JSON.stringify({ access_token: 'AT', expires_in: 60 }), { status: 200 });
  const r = await refreshAccessToken({ tokenUrl: 'u', clientId: 'c', clientSecret: 's', refreshToken: 'RT1', fetchFn });
  assert.equal(r.refreshToken, 'RT1');
});

test('surfaces OIDC errors without leaking the secret', async () => {
  const fetchFn = async () =>
    new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400, headers: { 'content-type': 'application/json' } });
  await assert.rejects(
    refreshAccessToken({ tokenUrl: 'u', clientId: 'c', clientSecret: 'SUPERSECRET', refreshToken: 'RT1', fetchFn }),
    (e: Error) => /400/.test(e.message) && /invalid_grant/.test(e.message) && !e.message.includes('SUPERSECRET'),
  );
});

test('chooseRefreshToken prefers the rotated token unless .env was changed since', async () => {
  const { chooseRefreshToken } = await import('../src/auth.ts');
  assert.equal(chooseRefreshToken('ENV1', undefined), 'ENV1');
  assert.equal(chooseRefreshToken('ENV1', { refreshToken: 'ROT', sourceRefreshToken: 'ENV1' }), 'ROT');
  assert.equal(chooseRefreshToken('ENV2', { refreshToken: 'ROT', sourceRefreshToken: 'ENV1' }), 'ENV2');
});

test('refresh token file: read trims, write replaces atomically with mode 0600', async () => {
  const { readRefreshTokenFile, writeRefreshTokenFile } = await import('../src/auth.ts');
  const { mkdtempSync, writeFileSync, statSync, readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'rt-'));
  const file = join(dir, 'token');
  writeFileSync(file, 'RT1\n', { mode: 0o600 });
  assert.equal(readRefreshTokenFile(file), 'RT1');
  writeRefreshTokenFile(file, 'RT2');
  assert.equal(readFileSync(file, 'utf8'), 'RT2\n');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(existsSync(`${file}.tmp`), false);
  writeFileSync(file, '\n');
  assert.throws(() => readRefreshTokenFile(file), /empty/);
});

test('assertTokenFileUsable refuses a left-over .tmp and a lock held by the main CLI', async () => {
  const { assertTokenFileUsable } = await import('../src/auth.ts');
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'rt-'));
  const file = join(dir, 'token');
  writeFileSync(file, 'RT1\n', { mode: 0o600 });
  assert.doesNotThrow(() => assertTokenFileUsable(file));
  writeFileSync(`${file}.tmp`, 'RT0\n');
  assert.throws(() => assertTokenFileUsable(file), /\.tmp/);
  rmSync(`${file}.tmp`);
  writeFileSync(`${file}.lock`, 'pid');
  assert.throws(() => assertTokenFileUsable(file), /\.lock/);
  rmSync(dir, { recursive: true });
});

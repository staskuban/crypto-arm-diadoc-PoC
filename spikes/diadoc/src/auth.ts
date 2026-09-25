import { accessSync, closeSync, constants, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
// OIDC Refresh Token Flow against identity.kontur.ru (developer.kontur.ru/doc/diadoc-api/authentication.html).
// The staging/prod choice is not a token parameter: the scope (Diadoc.PublicAPI.Staging) is fixed when
// the refresh token is issued in the integrator cabinet.

export type TokenSet = { accessToken: string; expiresIn: number; refreshToken: string };

export async function refreshAccessToken(o: {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  fetchFn?: typeof fetch;
}): Promise<TokenSet> {
  const res = await (o.fetchFn ?? fetch)(o.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: o.clientId,
      client_secret: o.clientSecret,
      refresh_token: o.refreshToken,
    }).toString(),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Token endpoint ${o.tokenUrl} -> ${res.status}: ${text.slice(0, 500)}`);
  let body: { access_token?: string; expires_in?: number; refresh_token?: string };
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`Token endpoint returned non-JSON (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!body.access_token) throw new Error(`Token endpoint returned no access_token: ${text.slice(0, 200)}`);
  return {
    accessToken: body.access_token,
    expiresIn: body.expires_in ?? 0,
    // the docs say the refresh token is rotated on each exchange; fall back to the old one if it is not
    refreshToken: body.refresh_token ?? o.refreshToken,
  };
}

/**
 * The token endpoint may rotate the refresh token, so the latest one is cached in .state. A token re-issued
 * in the integrator cabinet and put into .env must win over that cache, hence the remembered .env source.
 */
export function chooseRefreshToken(envToken: string, cached?: { refreshToken: string; sourceRefreshToken: string }): string {
  return cached && cached.sourceRefreshToken === envToken ? cached.refreshToken : envToken;
}

/** DIADOC_REFRESH_TOKEN_FILE: the single copy of the refresh token shared with the main CLI. */
export function readRefreshTokenFile(file: string): string {
  const token = readFileSync(file, 'utf8').trim();
  if (!token) throw new Error(`Refresh token file ${file} is empty`);
  return token;
}

/**
 * Checked before a refresh, so a rotated token never ends up only in memory: a <file>.lock means the main CLI
 * is using the token (one process per refresh token), a <file>.tmp may hold a newer token, and the directory
 * must be writable for the <file>.tmp + rename below.
 */
export function assertTokenFileUsable(file: string): void {
  if (existsSync(`${file}.lock`)) throw new Error(`${file}.lock exists: another process (the main CLI?) is using this refresh token`);
  if (existsSync(`${file}.tmp`)) throw new Error(`${file}.tmp exists and may hold a newer refresh token: check it and remove it by hand`);
  accessSync(dirname(file), constants.W_OK);
}

/** Replaces the token file via <file>.tmp (0600, fsync) + rename + dir fsync, as the main CLI does. */
export function writeRefreshTokenFile(file: string, token: string): void {
  const tmp = `${file}.tmp`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, `${token}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dir = openSync(dirname(file), 'r');
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}

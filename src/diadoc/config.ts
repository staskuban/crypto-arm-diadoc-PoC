import { readFile as fsReadFile } from 'node:fs/promises';

import { DiadocConfigError } from './errors.js';

export type DiadocEnv = Record<string, string | undefined>;

export interface DiadocEnvConfig {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  /** Set when the token came from `DIADOC_REFRESH_TOKEN_FILE`: write a rotated token back there. */
  refreshTokenFile?: string;
  tokenUrl?: string;
  timeoutMs?: number;
}

/** Timers overflow above 2^31-1 ms and would fire immediately. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Reads Diadoc settings from env: `DIADOC_API_URL` (required, no prod default so a test run never
 * hits production by accident), `DIADOC_CLIENT_ID`, `DIADOC_CLIENT_SECRET`, and
 * `DIADOC_REFRESH_TOKEN_FILE` (preferred: rotated tokens can be persisted) or `DIADOC_REFRESH_TOKEN`.
 * Optional: `DIADOC_TOKEN_URL`, `DIADOC_TIMEOUT_MS`.
 */
export async function loadDiadocEnv(
  env: DiadocEnv = process.env,
  readFile: (path: string) => Promise<string> = (path) => fsReadFile(path, 'utf8'),
): Promise<DiadocEnvConfig> {
  const baseUrl = checkUrl('DIADOC_API_URL', required(env, 'DIADOC_API_URL'));
  const config: DiadocEnvConfig = {
    baseUrl,
    clientId: required(env, 'DIADOC_CLIENT_ID'),
    clientSecret: required(env, 'DIADOC_CLIENT_SECRET'),
    refreshToken: '',
  };

  const tokenFile = env.DIADOC_REFRESH_TOKEN_FILE;
  if (tokenFile) {
    let text: string;
    try {
      text = await readFile(tokenFile);
    } catch (error) {
      throw new DiadocConfigError(`cannot read DIADOC_REFRESH_TOKEN_FILE ${tokenFile}`, {
        cause: error,
      });
    }
    config.refreshToken = text.trim();
    if (config.refreshToken === '') {
      throw new DiadocConfigError(`DIADOC_REFRESH_TOKEN_FILE ${tokenFile} is empty`);
    }
    config.refreshTokenFile = tokenFile;
  } else if (env.DIADOC_REFRESH_TOKEN?.trim()) {
    config.refreshToken = required(env, 'DIADOC_REFRESH_TOKEN');
  } else {
    throw new DiadocConfigError('DIADOC_REFRESH_TOKEN or DIADOC_REFRESH_TOKEN_FILE is not set');
  }

  if (env.DIADOC_TOKEN_URL) config.tokenUrl = checkUrl('DIADOC_TOKEN_URL', env.DIADOC_TOKEN_URL);
  const timeout = env.DIADOC_TIMEOUT_MS;
  if (timeout) {
    const timeoutMs = Number(timeout);
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new DiadocConfigError(
        `DIADOC_TIMEOUT_MS must be an integer in 1..${String(MAX_TIMEOUT_MS)}, got ${JSON.stringify(timeout)}`,
      );
    }
    config.timeoutMs = timeoutMs;
  }
  return config;
}

/** `.env.example` placeholder: fail here, not with an opaque `invalid_client` from the IdP. */
const PLACEHOLDER = 'changeme';

function required(env: DiadocEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new DiadocConfigError(`${name} is not set`);
  if (value === PLACEHOLDER) throw new DiadocConfigError(`${name} is still the placeholder`);
  return value;
}

/** Bearer tokens and client secrets must not travel over plain HTTP, except to a local stub. */
function checkUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new DiadocConfigError(`${name} is not a URL`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname))) {
    throw new DiadocConfigError(
      `${name} must use https (http only for localhost): ${url.protocol}//${url.host}`,
    );
  }
  return value;
}

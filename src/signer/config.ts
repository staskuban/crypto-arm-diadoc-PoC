import { readFile as fsReadFile } from 'node:fs/promises';

import { SignerConfigError } from './errors.js';
import { MAX_TIMEOUT_MS, type ServerCmsSignerOptions } from './server-cms-signer.js';

export type SignerEnv = Record<string, string | undefined>;

/**
 * Builds `ServerCmsSigner` options from env:
 * `CRYPTOARM_SERVER_URL`, `SIGNER_CERT_PATH` (public .cer), optional `CRYPTOARM_SERVER_API_KEY`,
 * `CRYPTOARM_SERVER_TIMEOUT_MS` and `CRYPTOARM_SERVER_MAX_REQUEST_BYTES` (bytes, = server `JSON_LIMIT`).
 */
export async function loadServerCmsSignerOptions(
  env: SignerEnv = process.env,
  readFile: (path: string) => Promise<Buffer> = fsReadFile,
): Promise<ServerCmsSignerOptions> {
  const baseUrl = required(env, 'CRYPTOARM_SERVER_URL');
  const certPath = required(env, 'SIGNER_CERT_PATH');
  if (/\.(pfx|p12)$/i.test(certPath)) {
    throw new SignerConfigError(
      `SIGNER_CERT_PATH points to a PKCS#12 container (${certPath}); pass only the public .cer`,
    );
  }

  let certificate: Buffer;
  try {
    certificate = await readFile(certPath);
  } catch (error) {
    throw new SignerConfigError(`cannot read SIGNER_CERT_PATH ${certPath}`, { cause: error });
  }

  const options: ServerCmsSignerOptions = { baseUrl, certificate };
  const apiKey = env.CRYPTOARM_SERVER_API_KEY;
  if (apiKey) options.apiKey = apiKey;
  const timeout = env.CRYPTOARM_SERVER_TIMEOUT_MS;
  if (timeout) {
    const timeoutMs = Number(timeout);
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new SignerConfigError(
        `CRYPTOARM_SERVER_TIMEOUT_MS must be an integer in 1..${String(MAX_TIMEOUT_MS)}, got ${JSON.stringify(timeout)}`,
      );
    }
    options.timeoutMs = timeoutMs;
  }
  const maxRequest = env.CRYPTOARM_SERVER_MAX_REQUEST_BYTES;
  if (maxRequest) {
    const maxRequestBytes = Number(maxRequest);
    if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes <= 0) {
      throw new SignerConfigError(
        `CRYPTOARM_SERVER_MAX_REQUEST_BYTES must be a positive integer (bytes), got ${JSON.stringify(maxRequest)}`,
      );
    }
    options.maxRequestBytes = maxRequestBytes;
  }
  return options;
}

function required(env: SignerEnv, name: string): string {
  const value = env[name];
  if (!value) throw new SignerConfigError(`${name} is not set`);
  return value;
}

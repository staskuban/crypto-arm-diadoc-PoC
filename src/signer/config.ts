import { readFile as fsReadFile } from 'node:fs/promises';

import {
  DocumentsCloudSigner,
  type DocumentsAuth,
  type DocumentsCloudSignerOptions,
} from './documents-cloud-signer.js';
import { SignerConfigError } from './errors.js';
import {
  MAX_TIMEOUT_MS,
  ServerCmsSigner,
  type ServerCmsSignerOptions,
} from './server-cms-signer.js';
import type { Signer } from './signer.js';

export type SignerEnv = Record<string, string | undefined>;
type ReadFile = (path: string) => Promise<Buffer>;

/**
 * Builds the signer `SIGNER_KIND` selects: `server` (default, `ServerCmsSigner`, see
 * `loadServerCmsSignerOptions`) or `documents` (`DocumentsCloudSigner`, see
 * `loadDocumentsCloudSignerEnv`; it verifies on КриптоАРМ Server, so the server env is required too).
 */
export async function createSignerFromEnv(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
): Promise<Signer> {
  const kind = nonEmpty(env.SIGNER_KIND) ?? 'server';
  if (kind === 'server')
    return new ServerCmsSigner(await loadServerCmsSignerOptions(env, readFile));
  if (kind !== 'documents') {
    throw new SignerConfigError(
      `SIGNER_KIND must be "server" or "documents", got ${JSON.stringify(kind)}`,
    );
  }
  const options = await loadDocumentsCloudSignerEnv(env, readFile);
  let verifier: ServerCmsSigner;
  try {
    verifier = new ServerCmsSigner(await loadServerCmsSignerOptions(env, readFile));
  } catch (error) {
    if (!(error instanceof SignerConfigError)) throw error;
    throw new SignerConfigError(
      `${error.message} (SIGNER_KIND=documents verifies signatures on КриптоАРМ Server /cms/verify)`,
      { cause: error },
    );
  }
  return new DocumentsCloudSigner({ ...options, verifier });
}

/**
 * Builds `ServerCmsSigner` options from env:
 * `CRYPTOARM_SERVER_URL`, `SIGNER_CERT_PATH` (public .cer), optional `CRYPTOARM_SERVER_API_KEY`,
 * `CRYPTOARM_SERVER_TIMEOUT_MS` and `CRYPTOARM_SERVER_MAX_REQUEST_BYTES` (bytes, = server `JSON_LIMIT`).
 */
export async function loadServerCmsSignerOptions(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
): Promise<ServerCmsSignerOptions> {
  const baseUrl = required(env, 'CRYPTOARM_SERVER_URL');
  const certificate = await readCertificate(env, readFile);
  const options: ServerCmsSignerOptions = { baseUrl, certificate };
  const apiKey = env.CRYPTOARM_SERVER_API_KEY;
  if (apiKey) options.apiKey = apiKey;
  const timeoutMs = optionalTimeout(env, 'CRYPTOARM_SERVER_TIMEOUT_MS');
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  const maxRequestBytes = optionalByteLimit(env, 'CRYPTOARM_SERVER_MAX_REQUEST_BYTES');
  if (maxRequestBytes !== undefined) options.maxRequestBytes = maxRequestBytes;
  return options;
}

/**
 * Builds `DocumentsCloudSigner` options (without the verifier) from env: `DOCUMENTS_URL`,
 * `SIGNER_CERT_PATH` (the public .cer the CA service maps to the service user's e-mail), auth by
 * `DOCUMENTS_JWT_FILE` / `DOCUMENTS_JWT` or `DOCUMENTS_LOGIN` + `DOCUMENTS_PASSWORD_FILE` /
 * `DOCUMENTS_PASSWORD`, optional `DOCUMENTS_UPLOAD_CONTENT_TYPE` and `DOCUMENTS_TIMEOUT_MS`.
 * Errors name variables and files, never secret values.
 */
export async function loadDocumentsCloudSignerEnv(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
): Promise<Omit<DocumentsCloudSignerOptions, 'verifier'>> {
  const baseUrl = required(env, 'DOCUMENTS_URL');
  const certificate = await readCertificate(env, readFile);
  const options: Omit<DocumentsCloudSignerOptions, 'verifier'> = {
    baseUrl,
    certificate,
    auth: await documentsAuth(env, readFile),
  };
  const contentType = env.DOCUMENTS_UPLOAD_CONTENT_TYPE;
  if (contentType) options.uploadContentType = contentType;
  const timeoutMs = optionalTimeout(env, 'DOCUMENTS_TIMEOUT_MS');
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  return options;
}

async function documentsAuth(env: SignerEnv, readFile: ReadFile): Promise<DocumentsAuth> {
  const hasJwt = Boolean(env.DOCUMENTS_JWT) || Boolean(env.DOCUMENTS_JWT_FILE);
  const hasLogin = Boolean(env.DOCUMENTS_LOGIN);
  if (hasJwt && hasLogin) {
    throw new SignerConfigError(
      'set either DOCUMENTS_JWT_FILE / DOCUMENTS_JWT or DOCUMENTS_LOGIN (+ password), not both',
    );
  }
  if (hasJwt) {
    const jwt = await secret(env, 'DOCUMENTS_JWT', readFile);
    return { jwt: jwt?.trim() ?? '' };
  }
  if (hasLogin) {
    const password = await secret(env, 'DOCUMENTS_PASSWORD', readFile);
    if (password === undefined) {
      throw new SignerConfigError(
        'DOCUMENTS_LOGIN needs DOCUMENTS_PASSWORD_FILE or DOCUMENTS_PASSWORD',
      );
    }
    return { login: env.DOCUMENTS_LOGIN ?? '', password: password.replace(/\r?\n$/, '') };
  }
  throw new SignerConfigError(
    'set DOCUMENTS_JWT_FILE (or DOCUMENTS_JWT) or DOCUMENTS_LOGIN with DOCUMENTS_PASSWORD_FILE (or DOCUMENTS_PASSWORD)',
  );
}

/** `<NAME>_FILE` (preferred) or `<NAME>`; both set is an error. */
async function secret(
  env: SignerEnv,
  name: string,
  readFile: ReadFile,
): Promise<string | undefined> {
  const file = env[`${name}_FILE`];
  const value = env[name];
  if (file && value) throw new SignerConfigError(`set ${name}_FILE or ${name}, not both`);
  if (!file) return nonEmpty(value);
  try {
    return (await readFile(file)).toString('utf8');
  } catch (error) {
    throw new SignerConfigError(`cannot read ${name}_FILE ${file}`, { cause: error });
  }
}

async function readCertificate(env: SignerEnv, readFile: ReadFile): Promise<Buffer> {
  const certPath = required(env, 'SIGNER_CERT_PATH');
  if (/\.(pfx|p12)$/i.test(certPath)) {
    throw new SignerConfigError(
      `SIGNER_CERT_PATH points to a PKCS#12 container (${certPath}); pass only the public .cer`,
    );
  }
  try {
    return await readFile(certPath);
  } catch (error) {
    throw new SignerConfigError(`cannot read SIGNER_CERT_PATH ${certPath}`, { cause: error });
  }
}

function optionalTimeout(env: SignerEnv, name: string): number | undefined {
  const timeout = env[name];
  if (!timeout) return undefined;
  const timeoutMs = Number(timeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new SignerConfigError(
      `${name} must be an integer in 1..${String(MAX_TIMEOUT_MS)}, got ${JSON.stringify(timeout)}`,
    );
  }
  return timeoutMs;
}

function optionalByteLimit(env: SignerEnv, name: string): number | undefined {
  const raw = env[name];
  if (!raw) return undefined;
  const bytes = Number(raw);
  if (!Number.isSafeInteger(bytes) || bytes <= 0) {
    throw new SignerConfigError(
      `${name} must be a positive integer (bytes), got ${JSON.stringify(raw)}`,
    );
  }
  return bytes;
}

/** Env convention: an empty value means unset. */
function nonEmpty(value: string | undefined): string | undefined {
  return value === '' ? undefined : value;
}

function required(env: SignerEnv, name: string): string {
  const value = env[name];
  if (!value) throw new SignerConfigError(`${name} is not set`);
  return value;
}

import { readFile as fsReadFile } from 'node:fs/promises';

import { Asn1Error, isDerFramed, parseCertificate } from '../asn1/index.js';
import { toDerCertificate } from './certificate.js';
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
 * Hosts reachable over plain `http` (D20), per variable: loopback, plus for КриптоАРМ Server the
 * compose service name the `app` container uses (`docker-compose.yml`). The Документы signer runs
 * on the host only, so `DOCUMENTS_URL` gets loopback only. Anything else must be `https`: the API
 * key, the Документы password/JWT and the document travel in these requests. A single-label name
 * may resolve through a DNS search domain outside compose — that residual risk is D20's.
 */
const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];
const HTTP_HOSTS: Record<'CRYPTOARM_SERVER_URL' | 'DOCUMENTS_URL', ReadonlySet<string>> = {
  CRYPTOARM_SERVER_URL: new Set([...LOOPBACK, 'cryptoarm-server']),
  DOCUMENTS_URL: new Set(LOOPBACK),
};
/** `.env.example` placeholders: fail at start, not with a 401 from the service (D20). */
const PLACEHOLDERS = new Set(['changeme', 'change-me-api-key']);
/**
 * A configured `DOCUMENTS_JWT` must stay valid at least this long after start: it is never renewed,
 * and upload + `cloud-sign` may take a request timeout (120 s) plus retry pauses (≤ 120 s).
 */
const JWT_MIN_LIFETIME_MS = 5 * 60_000;

/**
 * Builds the signer `SIGNER_KIND` selects: `server` (default, `ServerCmsSigner`, see
 * `loadServerCmsSignerOptions`) or `documents` (`DocumentsCloudSigner`, see
 * `loadDocumentsCloudSignerEnv`; it verifies on КриптоАРМ Server, so the server env is required too).
 */
export async function createSignerFromEnv(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
  now: () => number = Date.now,
): Promise<Signer> {
  const kind = nonEmpty(env.SIGNER_KIND) ?? 'server';
  if (kind === 'server')
    return new ServerCmsSigner(await loadServerCmsSignerOptions(env, readFile));
  if (kind !== 'documents') {
    throw new SignerConfigError(
      `SIGNER_KIND must be "server" or "documents", got ${JSON.stringify(kind)}`,
    );
  }
  const options = await loadDocumentsCloudSignerEnv(env, readFile, now);
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
 * `CRYPTOARM_SERVER_URL` (https; http only for {@link HTTP_HOSTS}), `SIGNER_CERT_PATH` (public
 * .cer, DER or PEM, parsed here and returned as DER), optional `CRYPTOARM_SERVER_API_KEY` (not the
 * `.env.example` placeholder), `CRYPTOARM_SERVER_TIMEOUT_MS` and
 * `CRYPTOARM_SERVER_MAX_REQUEST_BYTES` (bytes, = server `JSON_LIMIT`).
 */
export async function loadServerCmsSignerOptions(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
): Promise<ServerCmsSignerOptions> {
  const baseUrl = serviceUrl(env, 'CRYPTOARM_SERVER_URL');
  const certificate = await readCertificate(env, readFile);
  const options: ServerCmsSignerOptions = { baseUrl, certificate };
  const apiKey = env.CRYPTOARM_SERVER_API_KEY;
  if (apiKey) options.apiKey = notPlaceholder('CRYPTOARM_SERVER_API_KEY', apiKey);
  const timeoutMs = optionalTimeout(env, 'CRYPTOARM_SERVER_TIMEOUT_MS');
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  const maxRequestBytes = optionalByteLimit(env, 'CRYPTOARM_SERVER_MAX_REQUEST_BYTES');
  if (maxRequestBytes !== undefined) options.maxRequestBytes = maxRequestBytes;
  return options;
}

/**
 * Builds `DocumentsCloudSigner` options (without the verifier) from env: `DOCUMENTS_URL` (https;
 * http only for {@link HTTP_HOSTS}), `SIGNER_CERT_PATH` (the public .cer the CA service maps to the
 * service user's e-mail, parsed as for the server), auth by `DOCUMENTS_JWT_FILE` / `DOCUMENTS_JWT`
 * (a JWT whose `exp`, if any, is at least 5 minutes after `now`) or `DOCUMENTS_LOGIN` +
 * `DOCUMENTS_PASSWORD_FILE` / `DOCUMENTS_PASSWORD`, optional `DOCUMENTS_UPLOAD_CONTENT_TYPE` and
 * `DOCUMENTS_TIMEOUT_MS`. `.env.example` placeholders are refused. Errors name variables and
 * files, never secret values.
 */
export async function loadDocumentsCloudSignerEnv(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
  now: () => number = Date.now,
): Promise<Omit<DocumentsCloudSignerOptions, 'verifier'>> {
  const baseUrl = serviceUrl(env, 'DOCUMENTS_URL');
  const certificate = await readCertificate(env, readFile);
  const options: Omit<DocumentsCloudSignerOptions, 'verifier'> = {
    baseUrl,
    certificate,
    auth: await documentsAuth(env, readFile, now),
  };
  const contentType = env.DOCUMENTS_UPLOAD_CONTENT_TYPE;
  if (contentType) options.uploadContentType = contentType;
  const timeoutMs = optionalTimeout(env, 'DOCUMENTS_TIMEOUT_MS');
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  return options;
}

async function documentsAuth(
  env: SignerEnv,
  readFile: ReadFile,
  now: () => number,
): Promise<DocumentsAuth> {
  const hasJwt = Boolean(env.DOCUMENTS_JWT) || Boolean(env.DOCUMENTS_JWT_FILE);
  const hasLogin = Boolean(env.DOCUMENTS_LOGIN);
  if (hasJwt && hasLogin) {
    throw new SignerConfigError(
      'set either DOCUMENTS_JWT_FILE / DOCUMENTS_JWT or DOCUMENTS_LOGIN (+ password), not both',
    );
  }
  if (hasJwt) {
    const jwt = notPlaceholder(
      'DOCUMENTS_JWT',
      (await secret(env, 'DOCUMENTS_JWT', readFile))?.trim() ?? '',
    );
    checkJwtExpiry(jwt, now());
    return { jwt };
  }
  if (hasLogin) {
    const password = await secret(env, 'DOCUMENTS_PASSWORD', readFile);
    if (password === undefined) {
      throw new SignerConfigError(
        'DOCUMENTS_LOGIN needs DOCUMENTS_PASSWORD_FILE or DOCUMENTS_PASSWORD',
      );
    }
    return {
      login: notPlaceholder('DOCUMENTS_LOGIN', env.DOCUMENTS_LOGIN ?? ''),
      password: notPlaceholder('DOCUMENTS_PASSWORD', password.replace(/\r?\n$/, '')),
    };
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
  let raw: Buffer;
  try {
    raw = await readFile(certPath);
  } catch (error) {
    throw new SignerConfigError(`cannot read SIGNER_CERT_PATH ${certPath}`, { cause: error });
  }
  // Parse now (R2 minor 17): a bad file is a SIGNER_CONFIG error at start, not a misleading
  // CERTIFICATE_INVALID after the УПД was parsed. PEM ("Base-64" .cer) is converted to DER.
  let der: Buffer;
  try {
    der = toDerCertificate(raw);
  } catch (error) {
    if (!(error instanceof SignerConfigError)) throw error;
    throw new SignerConfigError(`SIGNER_CERT_PATH ${certPath}: ${error.message}`, { cause: error });
  }
  if (!isDerFramed(der)) {
    throw new SignerConfigError(
      `SIGNER_CERT_PATH ${certPath} must be DER (definite minimal lengths) or PEM; re-export the certificate`,
    );
  }
  try {
    parseCertificate(der);
  } catch (error) {
    if (!(error instanceof Asn1Error)) throw error;
    throw new SignerConfigError(
      `SIGNER_CERT_PATH ${certPath} is not an X.509 certificate: ${error.message}`,
      { cause: error },
    );
  }
  return der;
}

/** A service base URL: https, or http to a host in {@link HTTP_HOSTS}. Never echoes the value. */
function serviceUrl(env: SignerEnv, name: keyof typeof HTTP_HOSTS): string {
  const value = required(env, name);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new SignerConfigError(`${name} is not a valid URL`);
  }
  const httpHosts = HTTP_HOSTS[name];
  if (url.protocol === 'http:' && !httpHosts.has(url.hostname)) {
    throw new SignerConfigError(
      `${name} must use https (http only for ${[...httpHosts].join(', ')}): ${url.protocol}//${url.host}`,
    );
  }
  return value;
}

function notPlaceholder(name: string, value: string): string {
  if (PLACEHOLDERS.has(value.trim())) {
    throw new SignerConfigError(`${name} is still the placeholder`);
  }
  return value;
}

/**
 * A pre-issued JWT is used as is and never renewed (R2 minor 3): refuse one whose payload is not a
 * JSON object or whose `exp` has passed or is less than {@link JWT_MIN_LIFETIME_MS} away. Only a
 * sanity check: the signature, `nbf` and the header are left to Документы; no `exp` = accepted.
 */
function checkJwtExpiry(jwt: string, now: number): void {
  const parts = jwt.split('.');
  let payload: unknown;
  try {
    if (parts.length !== 3) throw new Error('not three parts');
    payload = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8'));
  } catch {
    payload = undefined;
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SignerConfigError(
      'DOCUMENTS_JWT is not a JWT (header.payload.signature with a JSON payload)',
    );
  }
  if (!('exp' in payload)) return;
  const { exp } = payload;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) {
    throw new SignerConfigError('DOCUMENTS_JWT has a non-numeric exp claim');
  }
  const expiresAt = exp * 1000;
  if (expiresAt - now >= JWT_MIN_LIFETIME_MS) return;
  const date = new Date(expiresAt);
  const when = Number.isNaN(date.getTime()) ? `exp=${String(exp)}` : date.toISOString();
  const hint = 'issue a new one (GET /api/v1/auth/jwt) or use DOCUMENTS_LOGIN';
  throw new SignerConfigError(
    expiresAt <= now
      ? `DOCUMENTS_JWT expired at ${when}; ${hint}`
      : `DOCUMENTS_JWT expires at ${when}, in less than 5 minutes; ${hint}`,
  );
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

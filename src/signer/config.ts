import { readFile as fsReadFile } from 'node:fs/promises';

import { Asn1Error, isDerFramed, parseCertificate } from '../asn1/index.js';
import { toDerCertificate } from './certificate.js';
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
 * Hosts `CRYPTOARM_SERVER_URL` may reach over plain `http` (D20): loopback, plus the compose service
 * name the `app` container uses (`docker-compose.yml`). Anything else must be `https`: the API key
 * and the document travel in these requests. A single-label name may resolve through a DNS search
 * domain outside compose — that residual risk is D20's.
 */
const HTTP_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '[::1]',
  'cryptoarm-server',
]);
/** `.env.example` placeholders: fail at start, not with a 401 from the service (D20). */
const PLACEHOLDERS = new Set(['changeme', 'change-me-api-key']);
/**
 * `SIGNER_KIND`: `server` (default, КриптоАРМ Server) or `diadoc-test` (no signer of ours: Diadoc
 * signs with its test certificate, test boxes only; the pipeline checks the boxes, D202).
 * `documents` (КриптоАРМ Документы) was removed in F21, see docs/compare-documents.md.
 */
export type SignerKind = 'server' | 'diadoc-test';

export function signerKind(env: SignerEnv = process.env): SignerKind {
  const kind = nonEmpty(env.SIGNER_KIND) ?? 'server';
  if (kind === 'server' || kind === 'diadoc-test') return kind;
  throw new SignerConfigError(
    `SIGNER_KIND must be "server" or "diadoc-test", got ${JSON.stringify(kind)}`,
  );
}

/**
 * Builds the signer `SIGNER_KIND` selects: `server` (default, `ServerCmsSigner`, see
 * `loadServerCmsSignerOptions`); `diadoc-test` has none.
 */
export async function createSignerFromEnv(
  env: SignerEnv = process.env,
  readFile: ReadFile = fsReadFile,
): Promise<Signer> {
  if (signerKind(env) === 'diadoc-test') {
    throw new SignerConfigError(
      'SIGNER_KIND=diadoc-test has no signer: the pipeline posts with the Diadoc test signature',
    );
  }
  return new ServerCmsSigner(await loadServerCmsSignerOptions(env, readFile));
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
  const baseUrl = serverUrl(env);
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

/** `CRYPTOARM_SERVER_URL`: https, or http to a host in {@link HTTP_HOSTS}. Never echoes the value. */
function serverUrl(env: SignerEnv): string {
  const name = 'CRYPTOARM_SERVER_URL';
  const value = required(env, name);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new SignerConfigError(`${name} is not a valid URL`);
  }
  if (url.protocol === 'http:' && !HTTP_HOSTS.has(url.hostname)) {
    throw new SignerConfigError(
      `${name} must use https (http only for ${[...HTTP_HOSTS].join(', ')}): ${url.protocol}//${url.host}`,
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

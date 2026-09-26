// Helpers of the Signer implementation (ServerCmsSigner).
import { Asn1Error, berToDer } from '../asn1/index.js';
import { SignerConfigError, SignerResponseError, type SignerOperation } from './errors.js';
import type { SignResult } from './signer.js';

/** Timers overflow above 2^31-1 ms and would fire immediately. */
export const MAX_TIMEOUT_MS = 2 ** 31 - 1;
/** Visible ASCII only: anything else is rejected by fetch with the value in the message. */
export const HEADER_TOKEN = /^[\x21-\x7e]+$/;
/** OID 1.2.840.113549.1.7.2 (pkcs7-signedData), DER encoded with tag and length. */
const SIGNED_DATA_OID = Buffer.from('06092a864886f70d010702', 'hex');

/**
 * Parses a service base URL; error messages never echo it since it may carry secrets. `service`
 * names the setting in messages, e.g. "КриптоАРМ Server URL".
 */
export function parseBaseUrl(raw: string, service: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SignerConfigError(`${service} is not a valid URL`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SignerConfigError(`${service} must be http(s), got ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new SignerConfigError(`${service} must not contain credentials`);
  }
  if (url.search || url.hash) {
    // A query such as ?apiKey= would be silently dropped when resolving endpoint paths.
    throw new SignerConfigError(`${service} must not contain a query or fragment`);
  }
  // Resolve relative paths against the prefix: "https://gw/cryptoarm" + "cms/sign".
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}

export function validateTimeout(timeoutMs: number, name = 'timeoutMs'): number {
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new SignerConfigError(
      `${name} must be an integer in 1..${String(MAX_TIMEOUT_MS)}, got ${String(timeoutMs)}`,
    );
  }
  return timeoutMs;
}

/**
 * Normalizes a CMS as a service returned it to DER (Диадок requires DER; КриптоАРМ Server emits
 * BER with indefinite lengths, docs/plan.md D1, D11) and keeps the raw bytes when they differ.
 * `what` names the value in errors, e.g. `"cms"`.
 */
export function toDerSignature(operation: SignerOperation, raw: Buffer, what: string): SignResult {
  let signature: Buffer;
  try {
    signature = berToDer(raw);
  } catch (error) {
    if (error instanceof Asn1Error) {
      throw new SignerResponseError(operation, `${what} is not valid BER: ${error.message}`);
    }
    throw error;
  }
  if (!isCmsSignedData(signature)) {
    throw new SignerResponseError(operation, `${what} is not a CMS SignedData`);
  }
  return signature.equals(raw) ? { signature } : { signature, rawSignature: raw };
}

/**
 * Checks the ContentInfo envelope: a SEQUENCE starting with the pkcs7-signedData OID. The input
 * must come from `berToDer` (one well-formed element spanning the buffer), so the header is
 * trusted. The rest is left to the verifier.
 */
function isCmsSignedData(der: Buffer): boolean {
  if (der[0] !== 0x30) return false;
  const first = der[1] ?? 0;
  const offset = first < 0x80 ? 2 : 2 + (first & 0x7f);
  return der.subarray(offset, offset + SIGNED_DATA_OID.length).equals(SIGNED_DATA_OID);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

import { Asn1Error, berToDer } from '../asn1/index.js';
import { toDerCertificate } from './certificate.js';
import {
  SignerConfigError,
  SignerError,
  SignerHttpError,
  SignerKeyNotFoundError,
  SignerNetworkError,
  SignerResponseError,
  SignerTimeoutError,
  type SignerOperation,
} from './errors.js';
import type { SignResult, Signer, SignerCallOptions, SignerInfo, VerifyResult } from './signer.js';

export const DEFAULT_TIMEOUT_MS = 120_000;
/** Timers overflow above 2^31-1 ms and would fire immediately. */
export const MAX_TIMEOUT_MS = 2 ** 31 - 1;
const MAX_ERROR_TEXT = 500;
/** OID 1.2.840.113549.1.7.2 (pkcs7-signedData), DER encoded with tag and length. */
const SIGNED_DATA_OID = Buffer.from('06092a864886f70d010702', 'hex');
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Visible ASCII only: anything else is rejected by fetch with the value in the message. */
const HEADER_TOKEN = /^[\x21-\x7e]+$/;
/**
 * КриптоАРМ Server 400 text when the certificate's key is not in `uMy` (seen 2026-09-24:
 * «Закрытый ключ для переданного сертификата не найден в хранилище КриптоПро. …»). Loose on
 * purpose: the text between the two phrases may name the certificate (dots, line breaks).
 */
const KEY_NOT_FOUND = /закрытый ключ.*не найден/is;

export interface ServerCmsSignerOptions {
  /** КриптоАРМ Server base URL, e.g. `http://127.0.0.1:3037`. A path prefix is kept. */
  baseUrl: string;
  /** Public signing certificate (DER or PEM). The private key must be in the server's `uMy`. */
  certificate: Buffer;
  /** Sent as `X-API-Key` (server `AUTH_MODE=apikey`). */
  apiKey?: string;
  /** Per-request timeout; default 120 s (the x86_64 image is slow under emulation). */
  timeoutMs?: number;
  /** Injected for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

/** Signs via КриптоАРМ Server `POST /cms/sign` (detached CAdES-BES) and verifies via `/cms/verify`. */
export class ServerCmsSigner implements Signer {
  /** The configured public certificate (DER); every signature must be made by its key. */
  readonly certificate: Buffer;
  readonly #baseUrl: URL;
  readonly #certificate: string;
  readonly #apiKey: string | undefined;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: ServerCmsSignerOptions) {
    this.#baseUrl = parseBaseUrl(options.baseUrl);
    this.certificate = toDerCertificate(options.certificate);
    this.#certificate = this.certificate.toString('base64');
    if (options.apiKey !== undefined && !HEADER_TOKEN.test(options.apiKey)) {
      throw new SignerConfigError('apiKey must be non-empty visible ASCII without spaces');
    }
    this.#apiKey = options.apiKey;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (
      !Number.isInteger(this.#timeoutMs) ||
      this.#timeoutMs <= 0 ||
      this.#timeoutMs > MAX_TIMEOUT_MS
    ) {
      throw new SignerConfigError(
        `timeoutMs must be an integer in 1..${String(MAX_TIMEOUT_MS)}, got ${String(this.#timeoutMs)}`,
      );
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async sign(data: Buffer, options: SignerCallOptions = {}): Promise<SignResult> {
    requireNonEmpty('sign', data, 'data');
    const body = await this.#post(
      'sign',
      'cms/sign',
      {
        cert: this.#certificate,
        data: data.toString('base64'),
        detached: true,
        cadesStandard: 'CAdES-BES',
      },
      options.signal,
    );
    const cms = isRecord(body) ? body.cms : undefined;
    if (typeof cms !== 'string' || cms === '') {
      throw new SignerResponseError('sign', 'missing "cms"');
    }
    const compact = cms.replace(/\s+/g, '');
    if (!BASE64.test(compact)) {
      throw new SignerResponseError('sign', '"cms" is not Base64');
    }
    const raw = Buffer.from(compact, 'base64');
    let signature: Buffer;
    try {
      signature = berToDer(raw);
    } catch (error) {
      if (error instanceof Asn1Error) {
        throw new SignerResponseError('sign', `"cms" is not valid BER: ${error.message}`);
      }
      throw error;
    }
    if (!isCmsSignedData(signature)) {
      throw new SignerResponseError('sign', '"cms" is not a CMS SignedData');
    }
    // Диадок requires DER; the server emits BER with indefinite lengths (docs/plan.md D1).
    return signature.equals(raw) ? { signature } : { signature, rawSignature: raw };
  }

  async verify(
    data: Buffer,
    signature: Buffer,
    options: SignerCallOptions = {},
  ): Promise<VerifyResult> {
    requireNonEmpty('verify', data, 'data');
    requireNonEmpty('verify', signature, 'signature');
    const body = await this.#post(
      'verify',
      'cms/verify',
      { cms: signature.toString('base64'), data: data.toString('base64') },
      options.signal,
    );
    if (!isRecord(body) || typeof body.isValidSign !== 'boolean') {
      throw new SignerResponseError('verify', 'missing boolean "isValidSign"');
    }
    const signs = Array.isArray(body.signs) ? body.signs.filter(isRecord) : [];
    const signers = signs.map(toSignerInfo);
    const valid = body.isValidSign && signers.length > 0 && signers.every((s) => s.valid);
    if (valid) return { valid, signers };

    const reasons = [
      typeof body.message === 'string' ? body.message : undefined,
      ...signs.map((s) => s.cadesVfyStatusDescription),
    ].filter((r): r is string => typeof r === 'string' && r !== '');
    if (signers.length === 0) reasons.push('no signatures in CMS');
    return { valid, signers, reason: reasons.join('; ') || 'signature is not valid' };
  }

  async #post(
    operation: SignerOperation,
    path: string,
    payload: object,
    callerSignal: AbortSignal | undefined,
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (this.#apiKey !== undefined) headers['X-API-Key'] = this.#apiKey;
    const timeout = AbortSignal.timeout(this.#timeoutMs);
    const signal = callerSignal ? AbortSignal.any([timeout, callerSignal]) : timeout;

    let response: Response;
    let text: string;
    try {
      response = await this.#fetch(new URL(path, this.#baseUrl), {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal,
        // Never follow redirects: X-API-Key would be forwarded to the new host and POST turned into GET.
        redirect: 'error',
      });
      text = await response.text();
    } catch (error) {
      if (callerSignal?.aborted) throw callerSignal.reason;
      if (timeout.aborted || (error instanceof Error && error.name === 'TimeoutError')) {
        throw new SignerTimeoutError(operation, this.#timeoutMs);
      }
      throw new SignerNetworkError(operation, { cause: error });
    }

    if (!response.ok) {
      const message = upstreamMessage(text);
      const requestId = response.headers.get('x-request-id') ?? undefined;
      const HttpError =
        response.status === 400 && KEY_NOT_FOUND.test(message)
          ? SignerKeyNotFoundError
          : SignerHttpError;
      throw new HttpError(operation, response.status, message, requestId);
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new SignerResponseError(
        operation,
        `body is not JSON (HTTP ${String(response.status)})`,
      );
    }
  }
}

/** Parses the base URL; error messages never echo it since it may carry secrets. */
function parseBaseUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SignerConfigError('КриптоАРМ Server URL is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SignerConfigError(`КриптоАРМ Server URL must be http(s), got ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new SignerConfigError('КриптоАРМ Server URL must not contain credentials');
  }
  if (url.search || url.hash) {
    // A query such as ?apiKey= would be silently dropped when resolving endpoint paths.
    throw new SignerConfigError('КриптоАРМ Server URL must not contain a query or fragment');
  }
  // Resolve relative paths against the prefix: "https://gw/cryptoarm" + "cms/sign".
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
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

function requireNonEmpty(operation: SignerOperation, value: Buffer, name: string): void {
  if (value.length === 0) throw new SignerError(`${operation}: ${name} must not be empty`);
}

/** NestJS errors: `{ message: string | string[], error, statusCode }`; otherwise the raw text. */
function upstreamMessage(text: string): string {
  let message = text.trim();
  try {
    const body: unknown = JSON.parse(text);
    if (isRecord(body)) {
      if (typeof body.message === 'string') message = body.message;
      else if (Array.isArray(body.message)) message = body.message.map(String).join('; ');
    }
  } catch {
    // not JSON: keep the raw text
  }
  return message.slice(0, MAX_ERROR_TEXT);
}

function toSignerInfo(sign: Record<string, unknown>): SignerInfo {
  const certificate = isRecord(sign.certificate) ? sign.certificate : {};
  const ext = isRecord(sign.extVerifyInfo) ? sign.extVerifyInfo : {};
  const info: SignerInfo = { valid: sign.isValidSign === true };
  if (typeof certificate.subjectName === 'string') info.subject = certificate.subjectName;
  if (typeof certificate.thumbprint === 'string') info.thumbprint = certificate.thumbprint;
  if (typeof sign.signingTime === 'string') info.signingTime = sign.signingTime;
  if (typeof certificate.notAfter === 'string') info.notAfter = certificate.notAfter;
  if (typeof ext.mathValidity === 'boolean') info.mathValid = ext.mathValidity;
  if (typeof sign.isCertChainValid === 'boolean') info.chainValid = sign.isCertChainValid;
  if (typeof sign.isCertValid === 'boolean') info.certValid = sign.isCertValid;
  if (typeof sign.isDetached === 'boolean') info.detached = sign.isDetached;
  return info;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

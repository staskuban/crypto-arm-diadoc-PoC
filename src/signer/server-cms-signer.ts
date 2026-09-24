import { toDerCertificate } from './certificate.js';
import {
  SignerConfigError,
  SignerError,
  SignerHttpError,
  SignerKeyNotFoundError,
  SignerNetworkError,
  SignerPayloadTooLargeError,
  SignerResponseError,
  SignerTimeoutError,
  type SignerOperation,
} from './errors.js';
import { HEADER_TOKEN, isRecord, parseBaseUrl, toDerSignature, validateTimeout } from './shared.js';
import type { SignResult, Signer, SignerCallOptions, SignerInfo, VerifyResult } from './signer.js';

export { MAX_TIMEOUT_MS } from './shared.js';

export const DEFAULT_TIMEOUT_MS = 120_000;
/**
 * КриптоАРМ Server `JSON_LIMIT` default `50mb` = 52 428 800 B of request body, exact on the stand
 * (2026-09-24: 52 428 800 B parsed, 52 428 801 B → 400 «request entity too large»).
 */
export const DEFAULT_MAX_REQUEST_BYTES = 52_428_800;
const MAX_ERROR_TEXT = 500;
/** body-parser text; the stand sends it with HTTP 400, not 413 (docs/plan.md D30). */
const TOO_LARGE = /request entity too large/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
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
  /**
   * Largest JSON request body sent, in bytes; default {@link DEFAULT_MAX_REQUEST_BYTES}. Keep it
   * equal to the server `JSON_LIMIT`. Larger requests fail with `SignerPayloadTooLargeError`
   * before encoding. The verify body (data + signature) is the larger of the two.
   */
  maxRequestBytes?: number;
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
  readonly #maxRequestBytes: number;
  readonly #fetch: typeof fetch;

  constructor(options: ServerCmsSignerOptions) {
    this.#baseUrl = parseBaseUrl(options.baseUrl, 'КриптоАРМ Server URL');
    this.certificate = toDerCertificate(options.certificate);
    this.#certificate = this.certificate.toString('base64');
    if (options.apiKey !== undefined && !HEADER_TOKEN.test(options.apiKey)) {
      throw new SignerConfigError('apiKey must be non-empty visible ASCII without spaces');
    }
    this.#apiKey = options.apiKey;
    this.#timeoutMs = validateTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    this.#maxRequestBytes = options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
    if (!Number.isSafeInteger(this.#maxRequestBytes) || this.#maxRequestBytes <= 0) {
      throw new SignerConfigError(
        `maxRequestBytes must be a positive integer, got ${String(this.#maxRequestBytes)}`,
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
        data,
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
    // Диадок requires DER; the server emits BER with indefinite lengths (docs/plan.md D1).
    return toDerSignature('sign', Buffer.from(compact, 'base64'), '"cms"');
  }

  async verify(
    data: Buffer,
    signature: Buffer,
    options: SignerCallOptions = {},
  ): Promise<VerifyResult> {
    requireNonEmpty('verify', data, 'data');
    requireNonEmpty('verify', signature, 'signature');
    const body = await this.#post('verify', 'cms/verify', { cms: signature, data }, options.signal);
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

  /** Posts `payload` as JSON, `Buffer` values as Base64 strings, within `maxRequestBytes`. */
  async #post(
    operation: SignerOperation,
    path: string,
    payload: Record<string, string | boolean | Buffer>,
    callerSignal: AbortSignal | undefined,
  ): Promise<unknown> {
    // Size the body before encoding: a Base64 string of a few hundred MB would not even fit
    // into a V8 string. Base64 needs no JSON escaping, so the sum is exact.
    const encode = (base64: (value: Buffer) => string) =>
      JSON.stringify(
        Object.fromEntries(
          Object.entries(payload).map(([key, value]) => [
            key,
            Buffer.isBuffer(value) ? base64(value) : value,
          ]),
        ),
      );
    let requestBytes = Buffer.byteLength(encode(() => ''));
    for (const value of Object.values(payload)) {
      if (Buffer.isBuffer(value)) requestBytes += 4 * Math.ceil(value.length / 3);
    }
    if (requestBytes > this.#maxRequestBytes) {
      throw new SignerPayloadTooLargeError(operation, requestBytes, this.#maxRequestBytes);
    }
    const body = encode((value) => value.toString('base64'));

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
        body,
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
      if (response.status === 413 || (response.status === 400 && TOO_LARGE.test(message))) {
        throw new SignerPayloadTooLargeError(operation, requestBytes, this.#maxRequestBytes, {
          status: response.status,
          upstreamMessage: message,
          requestId,
        });
      }
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

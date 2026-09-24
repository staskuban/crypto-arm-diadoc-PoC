// Signs through КриптоАРМ Документы with the corporate cloud key (docs/plan.md T7, D9–D13):
// upload the exact bytes -> POST /api/v1/signatures/cloud-sign/{id} -> export the detached signature.
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

import {
  DEFAULT_RETRY_POLICY,
  fetchWithRetry,
  isTransientFetchError,
  type RetryPolicy,
} from '../diadoc/http-retry.js';
import { toDerCertificate } from './certificate.js';
import {
  SignerConfigError,
  SignerError,
  SignerHttpError,
  SignerKeyNotFoundError,
  SignerNetworkError,
  SignerResponseError,
  SignerTimeoutError,
} from './errors.js';
import { HEADER_TOKEN, isRecord, parseBaseUrl, toDerSignature, validateTimeout } from './shared.js';
import type { SignResult, Signer, SignerCallOptions, VerifyResult } from './signer.js';

export const DEFAULT_DOCUMENTS_TIMEOUT_MS = 120_000;
/** Lifetime asked of `GET /api/v1/auth/jwt` for a login session: short, renewed as needed. */
const LOGIN_JWT_EXPIRES_IN = '15m';
/** Renew a login JWT this long before it expires. */
const JWT_MARGIN_MS = 60_000;
const MAX_ERROR_TEXT = 500;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MIME_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i;
/**
 * `cloud-sign` 400 text when the CA service has no certificate for the user's e-mail (I2, D12):
 * «Не удалось получить корпоративный сертификат пользователя».
 */
const NO_CORPORATE_CERT = /не удалось получить корпоративный сертификат/i;
/** КриптоАРМ Server's «Закрытый ключ … не найден», if Документы relays it (status unverified). */
const KEY_NOT_FOUND = /закрытый ключ.*не найден/is;

/**
 * `jwt`: a Bearer token issued beforehand (`GET /api/v1/auth/jwt` of the service user), used as
 * is until it expires. `login`: local login (`POST /api/v1/login`), exchanged for a 15 min JWT that
 * is renewed automatically. `X-API-KEY` does not work in this Документы version (D9).
 */
export type DocumentsAuth = { jwt: string } | { login: string; password: string };

export interface DocumentsCloudSignerOptions {
  /** КриптоАРМ Документы base URL, e.g. `http://127.0.0.1:3040`. A path prefix is kept. */
  baseUrl: string;
  /**
   * The public certificate (DER or PEM) the CA service maps to the service user's e-mail. Документы
   * picks the key by e-mail, not by this certificate (D12): it is exposed as `Signer.certificate`
   * so the pipeline's signature policy catches a wrong mapping (thumbprint mismatch).
   */
  certificate: Buffer;
  auth: DocumentsAuth;
  /**
   * Checks a signature over the exact bytes, e.g. a `ServerCmsSigner` of the КриптоАРМ Server that
   * Документы signs with. Документы itself offers no usable verify: `/documents/{id}/verify` is a
   * PDF (D10) and a signature that fails its check on upload is deleted without details.
   */
  verifier: Pick<Signer, 'verify'>;
  /** MIME type of the upload part; must match the service's `ALLOWED_FILE_TYPES`. */
  uploadContentType?: string;
  /** Per-request timeout; default 120 s. */
  timeoutMs?: number;
  /** Repeats of 408/429/5xx/network/timeout; default 4 attempts, ≤ 120 s of pauses per request. */
  retry?: Readonly<RetryPolicy>;
  /** Injected for tests. */
  fetch?: typeof fetch;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

type Step = 'login' | 'jwt' | 'upload' | 'cloud-sign' | 'export';

interface Token {
  value: string;
  /** Renew after this time (`now()` scale); Infinity for a configured JWT. */
  renewAt: number;
}

/** Signs via КриптоАРМ Документы `cloud-sign` (detached CAdES-BES by КриптоАРМ Server). */
export class DocumentsCloudSigner implements Signer {
  /** The expected signer certificate (DER), from our config — never from the service. */
  readonly certificate: Buffer;
  readonly #baseUrl: URL;
  readonly #auth: DocumentsAuth;
  readonly #verifier: Pick<Signer, 'verify'>;
  readonly #uploadContentType: string;
  readonly #timeoutMs: number;
  readonly #retry: Readonly<RetryPolicy>;
  readonly #fetch: typeof fetch;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  readonly #now: () => number;
  #token: Promise<Token> | undefined;

  constructor(options: DocumentsCloudSignerOptions) {
    this.#baseUrl = parseBaseUrl(options.baseUrl, 'КриптоАРМ Документы URL');
    this.certificate = toDerCertificate(options.certificate);
    this.#auth = validateAuth(options.auth);
    this.#verifier = options.verifier;
    this.#uploadContentType = options.uploadContentType ?? 'application/octet-stream';
    if (!MIME_TYPE.test(this.#uploadContentType)) {
      throw new SignerConfigError(
        `upload content type must be a MIME type such as application/xml, got ${JSON.stringify(this.#uploadContentType)}`,
      );
    }
    this.#timeoutMs = validateTimeout(options.timeoutMs ?? DEFAULT_DOCUMENTS_TIMEOUT_MS);
    this.#retry = options.retry ?? DEFAULT_RETRY_POLICY;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#sleep =
      options.sleep ??
      ((ms, signal) => delay(ms, undefined, signal === undefined ? {} : { signal }));
    this.#now = options.now ?? Date.now;
    if ('jwt' in this.#auth) {
      this.#token = Promise.resolve({ value: this.#auth.jwt, renewAt: Number.POSITIVE_INFINITY });
    }
  }

  /**
   * Uploads `data` as a new document (a user may sign a document only once), cloud-signs it with
   * the key the CA service maps to the logged-in user, and exports that signature detached. The
   * uploaded document and its signature stay in Документы.
   */
  async sign(data: Buffer, options: SignerCallOptions = {}): Promise<SignResult> {
    if (data.length === 0) throw new SignerError('sign: data must not be empty');
    const { signal } = options;
    signal?.throwIfAborted();

    const uploaded = await this.#json('upload', 'api/v1/documents/upload', {
      method: 'POST',
      body: () => {
        const form = new FormData();
        const file = new Blob([new Uint8Array(data)], { type: this.#uploadContentType });
        form.append('file', file, 'document');
        return form;
      },
      idempotent: true,
      signal,
    });
    const documentId =
      isRecord(uploaded) && isRecord(uploaded.document) ? uploaded.document.id : undefined;
    if (!isId(documentId)) throw new SignerResponseError('sign', 'upload: missing "document.id"');

    const signed = await this.#json(
      'cloud-sign',
      `api/v1/signatures/cloud-sign/${String(documentId)}`,
      {
        method: 'POST',
        json: {},
        idempotent: true,
        signal,
      },
    );
    if (!isRecord(signed) || signed.success !== true || !isId(signed.signatureId)) {
      throw new SignerResponseError('sign', 'cloud-sign: no "success" with a "signatureId"');
    }
    const copy = typeof signed.signature === 'string' ? signed.signature.replace(/\s+/g, '') : '';

    const response = await this.#call(
      'export',
      `api/v1/documents/${String(documentId)}/signature`,
      {
        method: 'POST',
        json: { signatureId: signed.signatureId, attached: false },
        signal,
      },
    );
    const raw = Buffer.from(await this.#read('export', response, (r) => r.arrayBuffer(), signal));
    if (raw.length === 0) throw new SignerResponseError('sign', 'export: empty signature');
    if (copy !== '' && (!BASE64.test(copy) || !Buffer.from(copy, 'base64').equals(raw))) {
      throw new SignerResponseError(
        'sign',
        'export: differs from the signature cloud-sign returned',
      );
    }
    // The stored signature is КриптоАРМ Server's BER with indefinite lengths (D11).
    return toDerSignature('sign', raw, 'export');
  }

  verify(data: Buffer, signature: Buffer, options: SignerCallOptions = {}): Promise<VerifyResult> {
    return this.#verifier.verify(data, signature, options);
  }

  async #json(step: Step, path: string, request: Request): Promise<unknown> {
    const response = await this.#call(step, path, request);
    const text = await this.#read(step, response, (r) => r.text(), request.signal);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new SignerResponseError(
        'sign',
        `${step}: body is not JSON (HTTP ${String(response.status)})`,
      );
    }
  }

  /** An authorized call; a rejected login JWT is renewed once. Returns a 2xx response. */
  async #call(step: Step, path: string, request: Request): Promise<Response> {
    for (let attempt = 1; ; attempt++) {
      const token = await this.#currentToken(request.signal);
      const sent = await this.#send(path, request, {
        authorization: `Bearer ${token.value}`,
      });
      const { response } = sent;
      if (response.status === 401 && 'login' in this.#auth && attempt === 1) {
        await response.body?.cancel().catch(() => undefined);
        // Drop the rejected token only if no other caller has started a new login meanwhile.
        const current = this.#token;
        const value = await current?.catch(() => undefined);
        if (value === token && this.#token === current) this.#token = undefined;
        continue;
      }
      return this.#ok(step, sent);
    }
  }

  /** The cached token, or one login shared by concurrent callers. */
  async #currentToken(signal: AbortSignal | undefined): Promise<Token> {
    const cached = this.#token;
    if (cached !== undefined) {
      const token = await cached.catch(() => undefined);
      if (token !== undefined && this.#now() < token.renewAt) return token;
      if (this.#token === cached) this.#token = undefined;
    }
    this.#token ??= this.#login(signal).catch((error: unknown) => {
      this.#token = undefined;
      throw error;
    });
    return this.#token;
  }

  async #login(signal: AbortSignal | undefined): Promise<Token> {
    if (!('login' in this.#auth)) throw new SignerError('sign: no login configured');
    const { login, password } = this.#auth;
    const session = await this.#ok(
      'login',
      await this.#send('api/v1/login', {
        method: 'POST',
        json: { username: login, password },
        signal,
      }),
    );
    await session.body?.cancel().catch(() => undefined);
    const cookie = session.headers
      .getSetCookie()
      .map((c) => c.split(';', 1)[0]?.trim() ?? '')
      .filter((c) => c.includes('='))
      .join('; ');
    if (cookie === '') throw new SignerResponseError('sign', 'login: no session cookie');

    const path = `api/v1/auth/jwt?expiresIn=${LOGIN_JWT_EXPIRES_IN}`;
    const response = await this.#ok(
      'jwt',
      await this.#send(path, { method: 'GET', signal }, { cookie }),
    );
    const text = await this.#read('jwt', response, (r) => r.text(), signal);
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    if (!isRecord(body) || typeof body.token !== 'string' || !HEADER_TOKEN.test(body.token)) {
      throw new SignerResponseError('sign', 'jwt: no usable "token"');
    }
    const now = this.#now();
    const expiresAt =
      typeof body.expiresAt === 'string' && !Number.isNaN(Date.parse(body.expiresAt))
        ? Date.parse(body.expiresAt)
        : typeof body.expiresInSeconds === 'number'
          ? now + body.expiresInSeconds * 1000
          : now + 15 * 60_000;
    return { value: body.token, renewAt: expiresAt - JWT_MARGIN_MS };
  }

  /**
   * One request with the shared bounded retry (408/429 with Retry-After/5xx/network/timeout). The
   * identical request is repeated: same Idempotency-Key, new X-Request-Id per attempt.
   */
  async #send(
    path: string,
    request: Request,
    extraHeaders: Record<string, string> = {},
  ): Promise<Sent> {
    const idempotencyKey = request.idempotent ? randomUUID() : undefined;
    const callerSignal = request.signal;
    let requestId = '';
    try {
      const response = await fetchWithRetry(
        () => {
          requestId = randomUUID();
          const headers: Record<string, string> = {
            Accept: 'application/json',
            'X-Request-Id': requestId,
            ...extraHeaders,
          };
          if (idempotencyKey !== undefined) headers['Idempotency-Key'] = idempotencyKey;
          let body: string | FormData | undefined;
          if (request.json !== undefined) {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify(request.json);
          } else if (request.body !== undefined) {
            body = request.body();
          }
          const timeout = AbortSignal.timeout(this.#timeoutMs);
          return this.#fetch(new URL(path, this.#baseUrl), {
            method: request.method,
            headers,
            ...(body === undefined ? {} : { body }),
            signal: callerSignal ? AbortSignal.any([timeout, callerSignal]) : timeout,
            // Never follow redirects: the JWT or the password would be forwarded to another host.
            redirect: 'error',
          });
        },
        this.#retry,
        { sleep: this.#sleep, now: this.#now, signal: callerSignal },
      );
      return { response, requestId };
    } catch (error) {
      throw this.#fetchError(error, callerSignal);
    }
  }

  async #read<T>(
    step: Step,
    response: Response,
    read: (r: Response) => Promise<T>,
    signal: AbortSignal | undefined,
  ): Promise<T> {
    try {
      return await read(response);
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      if (error instanceof SignerError) throw error;
      throw new SignerNetworkError('sign', {
        cause: new Error(`${step}: reading the response failed`, { cause: error }),
      });
    }
  }

  #fetchError(error: unknown, signal: AbortSignal | undefined): unknown {
    if (signal?.aborted) return signal.reason;
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      return new SignerTimeoutError('sign', this.#timeoutMs);
    }
    if (error instanceof TypeError || isTransientFetchError(error)) {
      return new SignerNetworkError('sign', { cause: error });
    }
    return error;
  }

  /** Passes a 2xx response through; maps anything else to SignerHttpError. */
  async #ok(step: Step, { response, requestId: sentId }: Sent): Promise<Response> {
    if (response.ok) return response;
    const text = await response.text().catch(() => '');
    const message = `${step}: ${upstreamMessage(text)}`;
    // The service echoes the X-Request-Id it was sent; a proxy error page may not.
    const requestId = response.headers.get('x-request-id') ?? sentId;
    const HttpError =
      response.status >= 400 &&
      response.status < 500 &&
      (NO_CORPORATE_CERT.test(message) || KEY_NOT_FOUND.test(message))
        ? SignerKeyNotFoundError
        : SignerHttpError;
    throw new HttpError('sign', response.status, message, requestId);
  }
}

interface Sent {
  response: Response;
  /** X-Request-Id of the last attempt. */
  requestId: string;
}

interface Request {
  method: 'GET' | 'POST';
  json?: unknown;
  /** Built per attempt (a FormData body is not reusable across fetches in every runtime). */
  body?: () => FormData;
  /** Send an Idempotency-Key (the same one on every repeat). */
  idempotent?: boolean;
  signal: AbortSignal | undefined;
}

function validateAuth(auth: DocumentsAuth): DocumentsAuth {
  if ('jwt' in auth) {
    if (!HEADER_TOKEN.test(auth.jwt)) {
      throw new SignerConfigError('Документы JWT must be non-empty visible ASCII without spaces');
    }
    return { jwt: auth.jwt };
  }
  if (auth.login === '') throw new SignerConfigError('Документы login must not be empty');
  if (auth.password === '') throw new SignerConfigError('Документы password must not be empty');
  return { login: auth.login, password: auth.password };
}

function isId(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/**
 * Документы errors: `{ error: { code, message, hint?, field?, details? } }`; NestJS
 * `{ message: string | string[] }`; otherwise the raw text.
 */
function upstreamMessage(text: string): string {
  let message = text.trim();
  try {
    const body: unknown = JSON.parse(text);
    if (isRecord(body)) {
      const error = isRecord(body.error) ? body.error : undefined;
      if (error !== undefined && typeof error.message === 'string') {
        message =
          typeof error.code === 'string' ? `${error.message} [${error.code}]` : error.message;
      } else if (typeof body.message === 'string') message = body.message;
      else if (Array.isArray(body.message)) message = body.message.map(String).join('; ');
    }
  } catch {
    // not JSON: keep the raw text
  }
  return message.slice(0, MAX_ERROR_TEXT);
}

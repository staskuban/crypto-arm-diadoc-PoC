export type SignerOperation = 'sign' | 'verify';

/** Base class for every error raised by a Signer implementation. */
export class SignerError extends Error {
  override name = 'SignerError';
}

/** Invalid signer configuration: missing env, bad URL, PKCS#12 instead of a public certificate. */
export class SignerConfigError extends SignerError {
  override name = 'SignerConfigError';
}

/** The signing service answered with a non-2xx HTTP status. */
export class SignerHttpError extends SignerError {
  override name = 'SignerHttpError';

  constructor(
    readonly operation: SignerOperation,
    readonly status: number,
    /** Message reported by the service (NestJS `message`), or the raw body text. */
    readonly upstreamMessage: string,
    readonly requestId?: string,
  ) {
    super(
      `${operation}: HTTP ${String(status)}${upstreamMessage ? `: ${upstreamMessage}` : ''}` +
        (requestId ? ` (request id ${requestId})` : ''),
    );
  }
}

/**
 * No usable signing key; detected from the message text only (no error codes): the certificate's
 * private key is not in the КриптоАРМ Server store (`uMy`) — fix the store or `SIGNER_CERT_PATH`.
 * Retrying does not help.
 */
export class SignerKeyNotFoundError extends SignerHttpError {
  override name = 'SignerKeyNotFoundError';
}

/**
 * A request body is over a service limit; retrying does not help. КриптоАРМ Server: the JSON body is
 * over `JSON_LIMIT` (default `50mb` = 52 428 800 B), refused before sending when it exceeds
 * `maxRequestBytes` (`status` is then undefined), or rejected by the server anyway (the stand
 * answers HTTP 400 «request entity too large», a plain body-parser setup 413).
 */
export class SignerPayloadTooLargeError extends SignerError {
  override name = 'SignerPayloadTooLargeError';
  /** HTTP status when the service (or a proxy in front of it) rejected the body. */
  readonly status: number | undefined;
  readonly upstreamMessage: string | undefined;
  readonly requestId: string | undefined;

  constructor(
    readonly operation: SignerOperation,
    /** The JSON body that was too large. */
    readonly requestBytes: number,
    /** The limit `requestBytes` is measured against, when known. */
    readonly limitBytes: number | undefined,
    response?: { status: number; upstreamMessage: string; requestId?: string | undefined },
  ) {
    super(
      `${operation}: ` +
        (response === undefined
          ? `request body of ${String(requestBytes)} B is too large for КриптоАРМ Server ` +
            `(limit ${String(limitBytes)} B = server JSON_LIMIT / CRYPTOARM_SERVER_MAX_REQUEST_BYTES; ` +
            `data travels as Base64, so files up to about 3/4 of it fit); not sent`
          : `request body of ${String(requestBytes)} B rejected as too large ` +
            `(HTTP ${String(response.status)}${response.upstreamMessage ? `: ${response.upstreamMessage}` : ''})` +
            (response.requestId ? ` (request id ${response.requestId})` : '') +
            `; КриптоАРМ Server answers 400 over its JSON_LIMIT, a 413 usually comes from a proxy in front of it ` +
            `(e.g. nginx client_max_body_size); keep CRYPTOARM_SERVER_MAX_REQUEST_BYTES (now ${String(limitBytes)} B) ` +
            `at or below both`),
    );
    this.status = response?.status;
    this.upstreamMessage = response?.upstreamMessage;
    this.requestId = response?.requestId;
  }
}

/** The request, or reading its response body, did not complete within the configured timeout. */
export class SignerTimeoutError extends SignerError {
  override name = 'SignerTimeoutError';

  constructor(
    readonly operation: SignerOperation,
    readonly timeoutMs: number,
  ) {
    super(`${operation}: no response within ${String(timeoutMs)} ms`);
  }
}

/**
 * The service could not be reached (DNS, connection refused, TLS, a refused redirect, ...) or the
 * connection broke while the response was read. The message carries the root cause, since fetch
 * reports all of them as "fetch failed".
 */
export class SignerNetworkError extends SignerError {
  override name = 'SignerNetworkError';

  constructor(
    readonly operation: SignerOperation,
    options: {
      cause: unknown;
      /** What failed; default "request failed". */
      what?: string | undefined;
    },
  ) {
    const { what = 'request failed' } = options;
    super(`${operation}: ${what}: ${describe(options.cause)}`, { cause: options.cause });
  }
}

/** A 2xx response that does not match the expected shape. */
export class SignerResponseError extends SignerError {
  override name = 'SignerResponseError';

  constructor(
    readonly operation: SignerOperation,
    detail: string,
  ) {
    super(`${operation}: unexpected response: ${detail}`);
  }
}

/**
 * The messages along the `cause` chain, e.g. "fetch failed: connect ECONNREFUSED 127.0.0.1:3037".
 * An `AggregateError` (every address of a host name refused) lists its errors. Beware: undici puts
 * an invalid header value into its message, so every secret header must be checked beforehand
 * (`HEADER_TOKEN`), and a base URL never carries credentials or a query (`parseBaseUrl`).
 */
function describe(cause: unknown): string {
  const parts: string[] = [];
  let current = cause;
  for (let depth = 0; depth < 5 && current !== undefined && current !== null; depth++) {
    const part = messageOf(current);
    if (part !== '' && parts.at(-1) !== part) parts.push(part);
    current = current instanceof Error ? current.cause : undefined;
  }
  return parts.join(': ') || String(cause);
}

function messageOf(error: unknown): string {
  if (error instanceof AggregateError && error.errors.length > 0) {
    return [...new Set(error.errors.map(messageOf))].filter((m) => m !== '').join(', ');
  }
  if (!(error instanceof Error)) return String(error);
  if (error.message !== '') return error.message;
  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : '';
}

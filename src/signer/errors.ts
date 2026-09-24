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
 * No usable signing key; detected from message texts only (no error codes). КриптоАРМ Server (also
 * when relayed by Документы): the certificate's private key is not in the server store (`uMy`) —
 * fix the store or `SIGNER_CERT_PATH`. КриптоАРМ Документы `cloud-sign`: the CA service has no
 * certificate for the user's e-mail — fix that mapping (stand: `ca-stub/nginx.conf`). Retrying
 * does not help.
 */
export class SignerKeyNotFoundError extends SignerHttpError {
  override name = 'SignerKeyNotFoundError';
}

/**
 * The JSON request body is over the КриптоАРМ Server body limit (`JSON_LIMIT`, default `50mb` =
 * 52 428 800 B). Raised before sending when the body exceeds `maxRequestBytes` (`status` is then
 * undefined), or when the server rejects it anyway: the stand answers HTTP 400 «request entity
 * too large», a plain body-parser setup would answer 413. Retrying does not help.
 */
export class SignerPayloadTooLargeError extends SignerError {
  override name = 'SignerPayloadTooLargeError';
  /** HTTP status when the server (or a proxy in front of it) rejected the body. */
  readonly status: number | undefined;
  readonly upstreamMessage: string | undefined;
  readonly requestId: string | undefined;

  constructor(
    readonly operation: SignerOperation,
    readonly requestBytes: number,
    readonly limitBytes: number,
    response?: { status: number; upstreamMessage: string; requestId?: string | undefined },
  ) {
    super(
      response === undefined
        ? `${operation}: request body of ${String(requestBytes)} B is too large for КриптоАРМ Server ` +
            `(limit ${String(limitBytes)} B = server JSON_LIMIT / CRYPTOARM_SERVER_MAX_REQUEST_BYTES; ` +
            `data travels as Base64, so files up to about 3/4 of it fit); not sent`
        : `${operation}: request body of ${String(requestBytes)} B rejected as too large ` +
            `(HTTP ${String(response.status)}${response.upstreamMessage ? `: ${response.upstreamMessage}` : ''})` +
            (response.requestId ? ` (request id ${response.requestId})` : '') +
            `; КриптоАРМ Server answers 400 over its JSON_LIMIT, a 413 usually comes from a proxy in front of it ` +
            `(e.g. nginx client_max_body_size); keep CRYPTOARM_SERVER_MAX_REQUEST_BYTES (now ${String(limitBytes)} B) ` +
            `at or below both`,
    );
    this.status = response?.status;
    this.upstreamMessage = response?.upstreamMessage;
    this.requestId = response?.requestId;
  }
}

/** The request did not complete within the configured timeout. */
export class SignerTimeoutError extends SignerError {
  override name = 'SignerTimeoutError';

  constructor(
    readonly operation: SignerOperation,
    readonly timeoutMs: number,
  ) {
    super(`${operation}: no response within ${String(timeoutMs)} ms`);
  }
}

/** The service could not be reached (DNS, connection refused, TLS, ...). */
export class SignerNetworkError extends SignerError {
  override name = 'SignerNetworkError';

  constructor(
    readonly operation: SignerOperation,
    options: { cause: unknown },
  ) {
    super(`${operation}: request failed: ${describe(options.cause)}`, options);
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

function describe(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

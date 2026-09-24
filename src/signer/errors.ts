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

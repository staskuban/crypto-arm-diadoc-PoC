const MAX_BODY_IN_MESSAGE = 1000;

/** Non-2xx response from the Diadoc API. `body` is the raw response text (Diadoc often answers text/plain). */
export class DiadocError extends Error {
  readonly method: string;
  readonly path: string;
  readonly status: number;
  readonly body: string;

  constructor(method: string, path: string, status: number, body: string) {
    super(`Diadoc ${method} ${path} -> ${String(status)}: ${body.slice(0, MAX_BODY_IN_MESSAGE)}`);
    this.name = 'DiadocError';
    this.method = method;
    this.path = path;
    this.status = status;
    this.body = body;
  }
}

/**
 * PostMessage answered 409: a message with this operationId/content was already posted,
 * or the recipient's settings (Sociability) forbid it. `body` says which.
 */
export class DiadocConflictError extends DiadocError {
  constructor(method: string, path: string, body: string) {
    super(method, path, 409, body);
    this.name = 'DiadocConflictError';
  }
}

/** PostMessage kept answering 204 (operation in progress) for all allowed attempts. */
export class DiadocOperationPendingError extends Error {
  readonly operationId: string;
  readonly attempts: number;

  constructor(operationId: string, attempts: number) {
    super(
      `Diadoc PostMessage operation ${operationId} still in progress after ${String(attempts)} attempts`,
    );
    this.name = 'DiadocOperationPendingError';
    this.operationId = operationId;
    this.attempts = attempts;
  }
}

/** Token endpoint failure. Never carries client_secret or refresh_token. */
export class DiadocAuthError extends Error {
  readonly status: number;
  /** OAuth `error` field, e.g. `invalid_client`, `invalid_grant`. */
  readonly oauthError: string | undefined;

  constructor(message: string, status: number, oauthError?: string) {
    super(message);
    this.name = 'DiadocAuthError';
    this.status = status;
    this.oauthError = oauthError;
  }
}

export type PipelineStep = 'parse' | 'sign' | 'verify' | 'attach' | 'precheck' | 'upload' | 'post';

export type PipelineErrorCode =
  /** УПД rejected by parseUtd (see `cause`: UtdError). Fix the document. */
  | 'INVALID_UTD'
  /** Above the single-request ShelfUpload limit; chunked upload is not implemented. */
  | 'CONTENT_TOO_LARGE'
  | 'SIGN_FAILED'
  /** The verify call itself failed (network, HTTP). */
  | 'VERIFY_FAILED'
  /** The signer's own signature does not verify over the exact bytes. */
  | 'SIGNATURE_INVALID'
  /** The signer returned something that is not a DER CMS. */
  | 'INVALID_SIGNATURE'
  /** CanPostMessage reported blocking errors (`details`). */
  | 'PRECHECK_REJECTED'
  | 'PRECHECK_FAILED'
  | 'SHELF_UPLOAD_FAILED'
  /**
   * 409 whose text says the document was already posted. Diadoc gives no ids here; find the message
   * in the Diadoc UI (or GetDocuments) before deciding anything. Texts unverified (D4).
   */
  | 'ALREADY_SENT'
  /** 409: the recipient's settings forbid documents from this sender. */
  | 'RECIPIENT_FORBIDS'
  /** 409 whose text matches neither known case (see `conflict.ts`). */
  | 'POST_CONFLICT'
  | 'POST_FAILED'
  /**
   * Diadoc kept answering 204 (still processing): the message may or may not exist yet. Running the
   * same send again is the way to find out (same operationId; see D7 for what is unverified).
   */
  | 'POST_PENDING'
  /** Posted (`messageId` is set) but the response has no document entity to track. */
  | 'NO_DOCUMENT_ENTITY';

export interface PipelineErrorOptions {
  cause?: unknown;
  operationId?: string;
  messageId?: string;
  details?: readonly unknown[];
}

/** A УПД could not be sent. The original error, if any, is `cause`. */
export class PipelineError extends Error {
  override readonly name = 'PipelineError';
  readonly operationId: string | undefined;
  readonly messageId: string | undefined;
  readonly details: readonly unknown[] | undefined;

  constructor(
    readonly code: PipelineErrorCode,
    readonly step: PipelineStep,
    message: string,
    options: PipelineErrorOptions = {},
  ) {
    super(`${step}: ${message}`, options.cause === undefined ? {} : { cause: options.cause });
    this.operationId = options.operationId;
    this.messageId = options.messageId;
    this.details = options.details;
  }
}

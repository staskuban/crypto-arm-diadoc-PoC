export type UtdErrorCode =
  | 'MISSING_XML_DECLARATION'
  | 'UNSUPPORTED_ENCODING'
  | 'MALFORMED_XML'
  | 'INVALID_ROOT'
  | 'MISSING_ELEMENT'
  | 'MISSING_ATTRIBUTE'
  | 'FILE_NAME_MISMATCH'
  | 'UNSUPPORTED_KND'
  | 'UNKNOWN_FUNCTION'
  | 'UNKNOWN_FORMAT_VERSION'
  | 'INVALID_CONTENT'
  | 'INVALID_SIGNATURE';

/** A УПД that cannot be sent as is. Never retryable: the input itself must change. */
export class UtdError extends Error {
  override readonly name = 'UtdError';

  constructor(
    readonly code: UtdErrorCode,
    message: string,
  ) {
    super(message);
  }
}

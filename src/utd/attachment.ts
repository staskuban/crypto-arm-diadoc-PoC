// Input for a Diadoc PostMessage (V3) DocumentAttachment of a УПД, as a plain object with raw
// bytes. The Diadoc client serialises it (base64 or ShelfUpload + NameOnShelf); no HTTP here.
import { UtdError } from './errors.js';
import type { UtdDocument, UtdFunction } from './parse.js';

export const UTD_TYPE_NAMED_ID = 'UniversalTransferDocument';

/**
 * proto/SignedContent: `Content` may be inline only below 500 KB, otherwise ShelfUpload +
 * NameOnShelf. Assumption: KB is read as 1000 bytes — the stricter reading, so shelf is never
 * skipped when Diadoc means 500 000.
 */
export const INLINE_CONTENT_LIMIT = 500_000;

export type ContentPlacement = 'inline' | 'shelf';

export function contentPlacement(size: number): ContentPlacement {
  return size < INLINE_CONTENT_LIMIT ? 'inline' : 'shelf';
}

/**
 * Domain view of a Diadoc `DocumentAttachment` with raw bytes. Deliberately not the wire shape
 * (camelCase, Buffers): the Diadoc client maps it to `TypeNamedId`/`Function`/`Version`/
 * `CustomDocumentId` and `SignedContent { Content | NameOnShelf, Signature }` (base64).
 */
export interface UtdAttachmentInput {
  readonly typeNamedId: typeof UTD_TYPE_NAMED_ID;
  readonly function: UtdFunction;
  readonly version: string;
  /** The exact bytes that were signed. */
  readonly content: Buffer;
  /** Detached CMS SignedData, DER. */
  readonly signature: Buffer;
  /** `inline`: send `Content` as base64; `shelf`: ShelfUpload first and send `NameOnShelf`. */
  readonly contentPlacement: ContentPlacement;
  /** `ИдФайл.xml`, for logs and error messages; the shelf name is the Diadoc client's choice. */
  readonly fileName: string;
  readonly customDocumentId?: string;
}

export function buildUtdAttachment(
  document: UtdDocument,
  signature: Buffer,
  options: { readonly customDocumentId?: string } = {},
): UtdAttachmentInput {
  if (document.content.length === 0) {
    throw new UtdError('INVALID_CONTENT', 'УПД content is empty');
  }
  // CMS ContentInfo is a DER SEQUENCE; catches base64/PEM passed where DER is expected.
  if (signature[0] !== 0x30) {
    throw new UtdError('INVALID_SIGNATURE', 'Signature must be a DER-encoded CMS SignedData');
  }
  return {
    typeNamedId: UTD_TYPE_NAMED_ID,
    function: document.function,
    version: document.version,
    content: document.content,
    signature,
    contentPlacement: contentPlacement(document.content.length),
    fileName: document.fileName,
    ...(options.customDocumentId === undefined
      ? {}
      : { customDocumentId: options.customDocumentId }),
  };
}

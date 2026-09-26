// PostMessage (V3) DocumentAttachment for a УПД seller title.

export const UTD_TYPE = 'UniversalTransferDocument';
/** proto/SignedContent: Content may be inline only below 500 KB, otherwise ShelfUpload + NameOnShelf. */
export const INLINE_CONTENT_LIMIT = 500 * 1024;

export type SignedContent = { Content: string; Signature?: string; SignWithTestSignature?: boolean };
export type DocumentAttachment = {
  TypeNamedId: string;
  Function: string;
  Version: string;
  CustomDocumentId?: string;
  SignedContent: SignedContent;
};

export function buildUtdAttachment(a: {
  content: Buffer;
  function: string;
  version: string;
  /** detached CMS SignedData (DER) or 'test' for Diadoc's SignWithTestSignature */
  signature: Buffer | 'test';
  customDocumentId?: string;
}): DocumentAttachment {
  if (a.content.length >= INLINE_CONTENT_LIMIT) {
    throw new Error(`Content is ${a.content.length} bytes (>= 500 KB): use ShelfUpload + NameOnShelf, not supported by the spike`);
  }
  const signedContent: SignedContent =
    a.signature === 'test'
      ? { Content: a.content.toString('base64'), SignWithTestSignature: true }
      : { Content: a.content.toString('base64'), Signature: a.signature.toString('base64') };
  return {
    TypeNamedId: UTD_TYPE,
    Function: a.function,
    Version: a.version,
    ...(a.customDocumentId === undefined ? {} : { CustomDocumentId: a.customDocumentId }),
    SignedContent: signedContent,
  };
}

/** Accepts a detached CMS as DER, bare base64 or PEM and returns DER. */
export function readSignatureFile(raw: Buffer): Buffer {
  if (raw[0] === 0x30) return raw; // DER SEQUENCE
  const text = raw.toString('ascii').replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '');
  const der = /^[A-Za-z0-9+/]+=*$/.test(text) ? Buffer.from(text, 'base64') : Buffer.alloc(0);
  if (der[0] !== 0x30) throw new Error('Signature file is not a CMS SignedData (expected DER, base64 or PEM)');
  return der;
}

type DocumentTypeDescription = { Name?: string; [k: string]: unknown };

export function pickUtdType(resp: { DocumentTypes?: DocumentTypeDescription[] }): DocumentTypeDescription | undefined {
  return resp.DocumentTypes?.find((t) => t.Name === UTD_TYPE);
}

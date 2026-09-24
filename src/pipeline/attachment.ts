// Maps the УПД domain attachment (src/utd, camelCase + Buffers) to the Diadoc wire types (docs/plan.md D2).
import type { DocumentAttachment, DocumentPrototype, MessagePrototype } from '../diadoc/index.js';
import type { UtdAttachmentInput } from '../utd/index.js';

/** `nameOnShelf` is required for, and only allowed with, `contentPlacement: 'shelf'`. */
export function toDocumentAttachment(
  a: UtdAttachmentInput,
  nameOnShelf?: string,
): DocumentAttachment {
  if ((a.contentPlacement === 'shelf') !== (nameOnShelf !== undefined)) {
    throw new Error(
      `${a.fileName}: contentPlacement ${a.contentPlacement} ` +
        (nameOnShelf === undefined ? 'needs a NameOnShelf' : 'must not have a NameOnShelf'),
    );
  }
  return {
    TypeNamedId: a.typeNamedId,
    Function: a.function,
    Version: a.version,
    SignedContent:
      nameOnShelf === undefined
        ? { Content: a.content, Signature: a.signature }
        : { NameOnShelf: nameOnShelf, Signature: a.signature },
    ...(a.customDocumentId === undefined ? {} : { CustomDocumentId: a.customDocumentId }),
  };
}

export function toDocumentPrototype(a: UtdAttachmentInput): DocumentPrototype {
  return {
    TypeNamedId: a.typeNamedId,
    Function: a.function,
    Version: a.version,
    ...(a.customDocumentId === undefined ? {} : { CustomDocumentId: a.customDocumentId }),
  };
}

export function toMessagePrototype(
  fromBoxId: string,
  toBoxId: string,
  a: UtdAttachmentInput,
): MessagePrototype {
  return { FromBoxId: fromBoxId, ToBoxId: toBoxId, DocumentPrototypes: [toDocumentPrototype(a)] };
}

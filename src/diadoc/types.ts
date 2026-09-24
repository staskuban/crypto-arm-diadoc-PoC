// Subset of the Diadoc JSON contracts (developer.kontur.ru/doc/diadoc-api/proto/*.html) the pipeline uses.
// Responses keep unknown fields: Diadoc adds fields over time and we only type what we read.

export interface Box {
  BoxId: string;
  BoxIdGuid?: string;
  Title?: string;
  [key: string]: unknown;
}

export interface Organization {
  OrgId?: string;
  Inn?: string;
  Kpp?: string;
  FullName?: string;
  ShortName?: string;
  /** Participant id from the УПД file name (ИдОтпр / ИдПол). */
  FnsParticipantId?: string;
  Boxes?: Box[];
  [key: string]: unknown;
}

export interface OrganizationList {
  Organizations: Organization[];
  [key: string]: unknown;
}

export interface DocumentTitle {
  XsdUrl?: string;
  UserDataXsdUrl?: string;
  [key: string]: unknown;
}

export interface DocumentVersion {
  Version: string;
  IsActual?: boolean;
  Titles?: DocumentTitle[];
  [key: string]: unknown;
}

export interface DocumentFunction {
  Name: string;
  Versions: DocumentVersion[];
  [key: string]: unknown;
}

export interface DocumentTypeDescription {
  /** TypeNamedId, e.g. `UniversalTransferDocument`. */
  Name: string;
  Title?: string;
  Functions: DocumentFunction[];
  [key: string]: unknown;
}

export interface DocumentTypesResponse {
  DocumentTypes: DocumentTypeDescription[];
  [key: string]: unknown;
}

export interface DocumentPrototype {
  TypeNamedId: string;
  Function?: string;
  Version?: string;
  CustomDocumentId?: string;
}

/** CanPostMessage body: checks boxes and types, not content or signatures. */
export interface MessagePrototype {
  FromBoxId: string;
  ToBoxId: string;
  DocumentPrototypes: DocumentPrototype[];
}

export interface MessageValidationError {
  Severity?: string;
  UserMessage?: string;
  ApiMessage?: string;
  CustomDocumentId?: string;
  [key: string]: unknown;
}

export interface MessageValidationResult {
  Errors?: MessageValidationError[];
  [key: string]: unknown;
}

/** Document bytes: inline `Content` (< 500 KB) or `NameOnShelf` after ShelfUpload. */
export type SignedContentBody =
  { Content: Buffer; NameOnShelf?: never } | { NameOnShelf: string; Content?: never };

/** Detached CMS SignedData (DER), or Diadoc's `SignWithTestSignature` (test boxes only). */
export type SignedContentSignature =
  | { Signature: Buffer; SignWithTestSignature?: never }
  | { SignWithTestSignature: true; Signature?: never };

/** Buffers go over the wire as base64. */
export type SignedContent = SignedContentBody & SignedContentSignature;

export interface MetadataItem {
  Key: string;
  Value: string;
}

export interface DocumentAttachment {
  TypeNamedId: string;
  Function: string;
  Version: string;
  SignedContent: SignedContent;
  CustomDocumentId?: string;
  Comment?: string;
  NeedRecipientSignature?: boolean;
  Metadata?: MetadataItem[];
}

export interface MessageToPost {
  FromBoxId: string;
  ToBoxId: string;
  DocumentAttachments: DocumentAttachment[];
}

export interface Entity {
  EntityType?: string;
  EntityId?: string;
  ParentEntityId?: string;
  AttachmentType?: string;
  [key: string]: unknown;
}

export interface Message {
  MessageId: string;
  FromBoxId?: string;
  ToBoxId?: string;
  Entities?: Entity[];
  [key: string]: unknown;
}

export interface StatusModel {
  /** `Info` | `Success` | `Warning` | `Error` (kept open for new values). */
  Severity?: string;
  StatusText?: string;
  StatusHint?: string;
  [key: string]: unknown;
}

export interface DocflowStatus {
  PrimaryStatus?: StatusModel;
  SecondaryStatus?: StatusModel;
  [key: string]: unknown;
}

export interface Document {
  MessageId?: string;
  EntityId?: string;
  DocflowStatus?: DocflowStatus;
  [key: string]: unknown;
}

export interface DocumentRef {
  boxId: string;
  messageId: string;
  entityId: string;
}

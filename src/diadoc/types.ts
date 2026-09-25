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
  /** Base64 `Data` is present for small entities even without `injectEntityContent` (live, S1). */
  Content?: { Size?: number; Data?: string; [key: string]: unknown };
  /** On a `DeliveryFailureNotification`: the MessageId that was not delivered. */
  NotDeliveredEventId?: string;
  /** On a `Signature`: `<hex>@diadoc.ru` of the signer's box. */
  SignerBoxId?: string;
  /** On a `Signature`: e.g. `PowerOfAttorneyRequired` for a certificate of another organisation. */
  PowerOfAttorneyAttachmentStatus?: {
    StatusName?: string;
    Comment?: string;
    [key: string]: unknown;
  };
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
  /** Warning «Не приложена доверенность» when no МЧД is attached (D204). */
  PowerOfAttorneyGeneralStatus?: StatusModel;
  [key: string]: unknown;
}

export interface Document {
  MessageId?: string;
  EntityId?: string;
  DocflowStatus?: DocflowStatus;
  /** E.g. `SenderSignatureCheckedAndValid`, `SenderSignatureCheckedAndInvalid` (live, S1). */
  SenderSignatureStatus?: string;
  [key: string]: unknown;
}

export interface CertificateChainElement {
  /** CryptoAPI `CERT_TRUST_*` error flags of this element. */
  CertificateChainStatusFlags?: number;
  DerCertificate?: string;
  [key: string]: unknown;
}

/** GetSignatureInfo (shapes from the S1 live run). */
export interface SignatureInfo {
  SignatureVerificationResult?: {
    /** The signature math over the content. */
    IsValid?: boolean;
    CertificateStatus?: {
      /** Chain, validity and revocation as Diadoc sees them. */
      IsValid?: boolean;
      CertificateChain?: CertificateChainElement[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  Thumbprint?: string;
  SerialNumber?: string;
  Issuer?: string;
  StartDate?: string;
  EndDate?: string;
  OrgName?: string;
  OrgInn?: string;
  CertificateSubjectType?: string;
  [key: string]: unknown;
}

export interface DocumentRef {
  boxId: string;
  messageId: string;
  entityId: string;
}

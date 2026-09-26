// Why Diadoc rejected the sender signature of a posted document (D203): the docflow status says only
// «Ошибка в подписи»; the reason is in SenderSignatureStatus, GetSignatureInfo and the
// DeliveryFailureNotification entity of the message. Shapes from the S1 live run.
import type {
  DiadocClient,
  Document,
  DocumentRef,
  Entity,
  Message,
  RequestOptions,
  SignatureInfo,
} from '../diadoc/index.js';

/** The lookups the check makes; `DiadocClient` satisfies it. */
export type SignatureCheckDiadoc = Pick<DiadocClient, 'getMessage' | 'getSignatureInfo'>;

/**
 * `certificate`: the math is valid, the certificate or its chain is not (e.g. the КриптоПро test CA,
 * D202). `signature`: the math is invalid. `none`: Diadoc accepted the signature. `unknown`: the
 * lookups did not say.
 */
export type SignatureRejectionReason = 'certificate' | 'signature' | 'none' | 'unknown';

export interface SignatureCheck {
  /** From GetDocument, e.g. `SenderSignatureCheckedAndInvalid`. */
  senderSignatureStatus?: string;
  reason: SignatureRejectionReason;
  /** GetSignatureInfo `SignatureVerificationResult.IsValid`. */
  mathValid?: boolean;
  /** GetSignatureInfo `CertificateStatus.IsValid`. */
  certificateValid?: boolean;
  /** CryptoAPI trust errors of the certificate chain, see `certificateChainProblems`. */
  chainProblems: string[];
  certificate?: {
    thumbprint?: string;
    serialNumber?: string;
    issuer?: string;
    validTo?: string;
    orgName?: string;
    orgInn?: string;
  };
  /** `false` when Diadoc added a DeliveryFailureNotification for this message. */
  delivered?: false;
  /** The notification text (cut to MAX_TEXT characters). */
  deliveryFailure?: string;
  /** МЧД findings: warnings only, Diadoc does not reject another organisation's certificate (D204). */
  powerOfAttorney: string[];
  /** Lookups that failed or were skipped; the rest of the check still stands. */
  lookupErrors: string[];
}

const MAX_TEXT = 500;

/** CryptoAPI `CERT_TRUST_*` error status bits (wincrypt.h), without the prefix. */
const CHAIN_FLAGS: readonly (readonly [number, string])[] = [
  [0x1, 'NOT_TIME_VALID'],
  [0x2, 'NOT_TIME_NESTED'],
  [0x4, 'REVOKED'],
  [0x8, 'NOT_SIGNATURE_VALID'],
  [0x10, 'NOT_VALID_FOR_USAGE'],
  [0x20, 'UNTRUSTED_ROOT'],
  [0x40, 'REVOCATION_STATUS_UNKNOWN'],
  [0x80, 'CYCLIC'],
  [0x100, 'INVALID_EXTENSION'],
  [0x200, 'INVALID_POLICY_CONSTRAINTS'],
  [0x400, 'INVALID_BASIC_CONSTRAINTS'],
  [0x800, 'INVALID_NAME_CONSTRAINTS'],
  [0x1000, 'HAS_NOT_SUPPORTED_NAME_CONSTRAINT'],
  [0x2000, 'HAS_NOT_DEFINED_NAME_CONSTRAINT'],
  [0x4000, 'HAS_NOT_PERMITTED_NAME_CONSTRAINT'],
  [0x8000, 'HAS_EXCLUDED_NAME_CONSTRAINT'],
  [0x10000, 'PARTIAL_CHAIN'],
  [0x20000, 'CTL_NOT_TIME_VALID'],
  [0x40000, 'CTL_NOT_SIGNATURE_VALID'],
  [0x80000, 'CTL_NOT_VALID_FOR_USAGE'],
  [0x100000, 'HAS_WEAK_SIGNATURE'],
  [0x1000000, 'OFFLINE_REVOCATION'],
  [0x2000000, 'NO_ISSUANCE_CHAIN_POLICY'],
  [0x4000000, 'EXPLICIT_DISTRUST'],
  [0x8000000, 'HAS_NOT_SUPPORTED_CRITICAL_EXT'],
];

/**
 * Names of the set bits, lowest first; an unknown bit stays as hex. A negative value is read as the
 * uint32 a signed `int` serialisation made of it; anything else that is not a 32-bit integer is
 * reported as is (and never loops: `1e400` parses to Infinity).
 */
export function certificateChainProblems(flags: number): string[] {
  if (!Number.isInteger(flags) || flags < -(2 ** 31) || flags >= 2 ** 32) {
    return [`invalid flags ${String(flags)}`];
  }
  const value = flags < 0 ? flags + 2 ** 32 : flags;
  const names = new Map(CHAIN_FLAGS);
  const problems: string[] = [];
  // Arithmetic, not bitwise: the flags may use bit 31, which `&` would turn negative.
  for (let bit = 1; bit <= value; bit *= 2) {
    if (Math.floor(value / bit) % 2 === 1) {
      problems.push(names.get(bit) ?? `0x${bit.toString(16).padStart(8, '0')}`);
    }
  }
  return problems;
}

export interface SignatureCheckInput {
  /** The document (Attachment) entity whose sender signature is checked. */
  entityId: string;
  /** Picks the signature made in this box. */
  fromBoxId?: string | undefined;
  /** The last GetDocument answer. */
  document: Document;
  message?: Message | undefined;
  signatureInfo?: SignatureInfo | undefined;
  lookupErrors?: string[];
}

/** The check from what was read; pure. */
export function signatureCheckFrom(input: SignatureCheckInput): SignatureCheck {
  const { document, message, signatureInfo: info } = input;
  const check: SignatureCheck = {
    reason: 'unknown',
    chainProblems: [],
    powerOfAttorney: [],
    lookupErrors: input.lookupErrors ?? [],
  };
  if (document.SenderSignatureStatus !== undefined) {
    check.senderSignatureStatus = document.SenderSignatureStatus;
  }

  const result = info?.SignatureVerificationResult;
  if (typeof result?.IsValid === 'boolean') check.mathValid = result.IsValid;
  const certificateStatus = result?.CertificateStatus;
  if (typeof certificateStatus?.IsValid === 'boolean') {
    check.certificateValid = certificateStatus.IsValid;
  }
  for (const element of certificateStatus?.CertificateChain ?? []) {
    const flags = element.CertificateChainStatusFlags;
    if (typeof flags !== 'number') continue;
    for (const problem of certificateChainProblems(flags)) {
      if (!check.chainProblems.includes(problem)) check.chainProblems.push(problem);
    }
  }
  if (info !== undefined) {
    const certificate = definedOnly({
      thumbprint: info.Thumbprint,
      serialNumber: info.SerialNumber,
      issuer: info.Issuer,
      validTo: info.EndDate,
      orgName: info.OrgName,
      orgInn: info.OrgInn,
    });
    if (Object.keys(certificate).length > 0) check.certificate = certificate;
  }

  check.reason =
    check.mathValid === false
      ? 'signature'
      : check.certificateValid === false
        ? 'certificate'
        : check.mathValid === true && check.certificateValid === true
          ? 'none'
          : document.SenderSignatureStatus === 'SenderSignatureCheckedAndValid'
            ? 'none'
            : 'unknown';

  const attorney = senderSignatureEntity(
    message,
    input.entityId,
    input.fromBoxId,
  )?.PowerOfAttorneyAttachmentStatus;
  if (attorney?.StatusName && attorney.StatusName !== 'PowerOfAttorneyNotRequired') {
    check.powerOfAttorney.push(
      attorney.Comment ? `${attorney.StatusName}: ${attorney.Comment}` : attorney.StatusName,
    );
  }
  const general = document.DocflowStatus?.PowerOfAttorneyGeneralStatus;
  const generalSeverity = general?.Severity?.toLowerCase();
  if (general?.StatusText && (generalSeverity === 'warning' || generalSeverity === 'error')) {
    check.powerOfAttorney.push(general.StatusText);
  }

  const messageId = document.MessageId ?? message?.MessageId;
  const failure = message?.Entities?.find(
    (e) =>
      e.AttachmentType === 'DeliveryFailureNotification' &&
      (e.NotDeliveredEventId === undefined || e.NotDeliveredEventId === messageId),
  );
  if (failure !== undefined) {
    check.delivered = false;
    const text = notificationText(failure);
    if (text !== undefined) check.deliveryFailure = text;
  }
  return check;
}

/**
 * Reads the message (its signature and notification entities) and GetSignatureInfo of the sender
 * signature under `ref.entityId`. Never throws: the message is already posted; a failed lookup ends up
 * in `lookupErrors`.
 */
export async function checkSenderSignature(
  ref: DocumentRef,
  document: Document,
  diadoc: SignatureCheckDiadoc,
  options: RequestOptions = {},
): Promise<SignatureCheck> {
  const lookupErrors: string[] = [];
  const done = (message?: Message, signatureInfo?: SignatureInfo): SignatureCheck =>
    signatureCheckFrom({
      entityId: ref.entityId,
      fromBoxId: ref.boxId,
      document,
      message,
      signatureInfo,
      lookupErrors,
    });
  if (options.signal?.aborted) {
    lookupErrors.push('interrupted');
    return done();
  }

  let message: Message;
  try {
    message = await diadoc.getMessage(ref.boxId, ref.messageId, options);
  } catch (error) {
    lookupErrors.push(`GetMessage: ${describe(error)}`);
    return done();
  }
  const signature = senderSignatureEntity(message, ref.entityId, ref.boxId);
  if (!signature?.EntityId) {
    lookupErrors.push('no sender signature entity in the message');
    return done(message);
  }
  try {
    const info = await diadoc.getSignatureInfo({ ...ref, entityId: signature.EntityId }, options);
    return done(message, info);
  } catch (error) {
    lookupErrors.push(`GetSignatureInfo: ${describe(error)}`);
    return done(message);
  }
}

/**
 * Diadoc rejected the sender signature: the certificate or the math failed, or the lookups did not
 * say why but SenderSignatureStatus is invalid.
 */
export function isSignatureRejected(check: SignatureCheck): boolean {
  return (
    check.reason === 'certificate' ||
    check.reason === 'signature' ||
    (check.reason === 'unknown' &&
      check.senderSignatureStatus === 'SenderSignatureCheckedAndInvalid')
  );
}

/**
 * A code for scripts plus one line for people, e.g. for the CLI's stderr. `statusText` (the
 * DocflowStatus text) goes first: for an error that is not about the signature it is the reason.
 */
export function describeSignatureCheck(check: SignatureCheck, statusText?: string): string {
  const code = !isSignatureRejected(check)
    ? 'DOCFLOW_ERROR'
    : check.reason === 'certificate'
      ? 'SENDER_CERTIFICATE_REJECTED'
      : 'SENDER_SIGNATURE_REJECTED';

  const parts: string[] = [];
  if (statusText) parts.push(statusText);
  if (check.senderSignatureStatus !== undefined) parts.push(check.senderSignatureStatus);
  if (check.mathValid !== undefined) {
    parts.push(`signature math is ${check.mathValid ? 'valid' : 'invalid'}`);
  }
  if (check.certificateValid === false) {
    const { thumbprint, issuer, validTo } = check.certificate ?? {};
    const about = [issuer && `issuer ${issuer}`, validTo && `valid to ${validTo}`].filter(Boolean);
    parts.push(
      `Diadoc does not accept certificate ${thumbprint ?? '(thumbprint unknown)'}` +
        (about.length > 0 ? ` (${about.join(', ')})` : '') +
        (check.chainProblems.length > 0 ? `: ${check.chainProblems.join(', ')}` : ''),
    );
  }
  if (check.powerOfAttorney.length > 0) {
    parts.push(`power of attorney: ${check.powerOfAttorney.join('; ')}`);
  }
  if (check.delivered === false) {
    parts.push(`not delivered${check.deliveryFailure ? `: ${check.deliveryFailure}` : ''}`);
  }
  if (check.lookupErrors.length > 0) parts.push(`lookups failed: ${check.lookupErrors.join('; ')}`);
  return `[${code}] ${parts.length > 0 ? parts.join('; ') : 'no signature problem found'}`;
}

/**
 * The Signature under the document made in the sender's box (`SignerBoxId` is `<hex>@diadoc.ru`, the
 * configured box id may be a GUID with dashes); without a match the first one (the recipient signs
 * later).
 */
function senderSignatureEntity(
  message: Message | undefined,
  entityId: string,
  fromBoxId?: string,
): Entity | undefined {
  const signatures = (message?.Entities ?? []).filter(
    (e) => e.EntityType === 'Signature' && e.ParentEntityId === entityId,
  );
  const box = fromBoxId === undefined ? undefined : boxKey(fromBoxId);
  return (
    signatures.find((e) => e.SignerBoxId !== undefined && boxKey(e.SignerBoxId) === box) ??
    signatures[0]
  );
}

function boxKey(boxId: string): string {
  return (boxId.split('@')[0] ?? '').replaceAll('-', '').toLowerCase();
}

function notificationText(entity: Entity): string | undefined {
  const data = entity.Content?.Data;
  if (typeof data !== 'string' || data === '') return undefined;
  const text = Buffer.from(data, 'base64').toString('utf8').replace(/\s+/g, ' ').trim();
  if (text === '') return undefined;
  return text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}…` : text;
}

function definedOnly<T extends Record<string, string | undefined>>(
  value: T,
): { [K in keyof T]?: string } {
  return Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== undefined && v !== ''),
  ) as { [K in keyof T]?: string };
}

/** Cut like the notification text: a Diadoc error message may carry a response body. */
function describe(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  return text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}…` : text;
}

// УПД → sign → verify → DocumentAttachment → (CanPostMessage) → (ShelfUpload) → PostMessage → status.
// With the Diadoc test signature: УПД → test-box check → DocumentAttachment → … (no signer, D202).
import { setTimeout as delay } from 'node:timers/promises';

import {
  DiadocAuthError,
  DiadocConflictError,
  DiadocOperationPendingError,
  DiadocPostOutcomeUnknownError,
  DiadocTokenDeadlineError,
  findDocumentEntity,
  SHELF_MAX_BYTES,
  type DiadocClient,
  type DocflowStatus,
  type MessageValidationError,
  type Organization,
} from '../diadoc/index.js';
import { Asn1Error } from '../asn1/index.js';
import type { Signer } from '../signer/index.js';
import {
  buildUtdAttachment,
  DIADOC_TEST_SIGNATURE,
  parseUtd,
  UtdError,
  type ContentPlacement,
  type ParseUtdOptions,
  type UtdDocument,
  type UtdSignature,
} from '../utd/index.js';
import { toDocumentAttachment, toMessagePrototype } from './attachment.js';
import { classifyConflict } from './conflict.js';
import { PipelineError, type PipelineErrorCode, type PipelineStep } from './errors.js';
import { customDocumentIdFor, isGuid } from './custom-document-id.js';
import { isResendSalt, operationIdFor } from './operation-id.js';
import {
  checkSenderSignature,
  describeSignatureCheck,
  type SignatureCheck,
  type SignatureCheckDiadoc,
} from './signature-check.js';
import {
  classifyVerifyFailure,
  cmsPolicyViolations,
  readSignerCertificate,
  validityProblem,
  verifiedSignerViolations,
} from './signature-policy.js';
import {
  DEFAULT_POLL_OPTIONS,
  pollDocflowStatus,
  type DocflowOutcome,
  type PollOptions,
} from './status.js';

/** The Diadoc calls the pipeline makes; `DiadocClient` satisfies it. */
export type PipelineDiadoc = Pick<
  DiadocClient,
  'canPostMessage' | 'shelfUpload' | 'postMessage' | 'getDocument' | 'getOrganization'
> &
  SignatureCheckDiadoc;

export interface SendUtdInput {
  /** Bare file name; must be `ИдФайл.xml`. */
  fileName: string;
  /** The УПД bytes exactly as produced (windows-1251). Signed and sent unchanged. */
  content: Buffer;
}

export interface SendUtdDeps {
  /**
   * Our signer, or DIADOC_TEST_SIGNATURE: Diadoc signs with its test certificate
   * (`SignWithTestSignature`), our signer and the signature policy are skipped, and both boxes must
   * be test organisations (`GetOrganization` → `IsTest`), checked before any side effect.
   */
  signer: Signer | typeof DIADOC_TEST_SIGNATURE;
  diadoc: PipelineDiadoc;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  /** Progress lines (no secrets, no document content). */
  log?: (message: string) => void;
}

export interface SendUtdOptions {
  fromBoxId: string;
  toBoxId: string;
  /** Call CanPostMessage before uploading/posting. Default true. */
  precheck?: boolean;
  poll?: Partial<PollOptions>;
  /** PostMessage attempts while Diadoc answers 204. Default: the client's. */
  postMaxAttempts?: number;
  /**
   * Sent as the attachment's CustomDocumentId (CanPostMessage and PostMessage); part of the
   * operationId. Must be a GUID (D192). Default: derived from the operationId (D200).
   */
  customDocumentId?: string;
  /**
   * Deliberate resend of a УПД that was already posted (e.g. after the recipient rejected it): the
   * salt goes into the operationId, so Diadoc sees a new operation. Reuse the same salt to retry that
   * resend idempotently. Without it a repeated send reuses the operationId (see `sendUtd`). Must pass
   * `isResendSalt`.
   */
  resend?: string;
  resolveVersion?: ParseUtdOptions['resolveVersion'];
  /**
   * Checked between steps and passed to the signer, CanPostMessage, the shelf upload (between parts
   * too) and GetDocument. PostMessage is not interrupted: it ends within its time budget
   * (POST_MESSAGE_BUDGET_MS). Before PostMessage an abort rejects with the signal's reason; after it,
   * polling stops and the result is returned.
   */
  signal?: AbortSignal;
}

export interface SendUtdResult {
  operationId: string;
  /** Given, or derived from the operationId. */
  customDocumentId: string;
  /** The resend salt, when this was a deliberate resend. */
  resend?: string;
  /** Signed with the Diadoc test signature (test boxes only), not by our signer. */
  testSignature?: true;
  fileName: string;
  fromBoxId: string;
  toBoxId: string;
  messageId: string;
  /** The document (Attachment) entity: use with messageId in GetDocument. */
  entityId: string;
  contentPlacement: ContentPlacement;
  nameOnShelf?: string;
  outcome: DocflowOutcome;
  /** `outcome` is `success` or `error`; false when polling ended at the deadline. */
  final: boolean;
  /** Last DocflowStatus read. */
  status?: DocflowStatus;
  /** Set when the last GetDocument failed. */
  statusError?: unknown;
  polls: number;
  /** Non-blocking CanPostMessage findings. */
  warnings: MessageValidationError[];
  /**
   * Why Diadoc rejected the sender signature (D203): set when the docflow ended in an error or
   * SenderSignatureStatus says the signature is invalid.
   */
  signatureCheck?: SignatureCheck;
}

/**
 * Deadline for GetMessage/GetSignatureInfo after polling (which may have used up its own). A soft
 * one, like every RequestOptions deadline: it bounds retry pauses and token refreshes, each request
 * keeps its own timeout. Above the IdP's 30 s, so a token refresh can still start (auth.ts starts one
 * only if its full timeout ends before the deadline).
 */
const SIGNATURE_CHECK_TIMEOUT_MS = 90_000;

/**
 * Signs a УПД and posts it to Diadoc. The operationId is derived from boxes + ИдФайл + content +
 * customDocumentId (+ the resend salt), so a repeated call sends the same operationId. Unverified
 * (D7): that Diadoc answers a repeat whose body differs (new signature, new NameOnShelf) with the
 * original message rather than a 409. `resend` makes a new operationId on purpose.
 */
export async function sendUtd(
  input: SendUtdInput,
  deps: SendUtdDeps,
  options: SendUtdOptions,
): Promise<SendUtdResult> {
  const { fromBoxId, toBoxId, signal } = options;
  if (fromBoxId === '' || toBoxId === '') throw new Error('fromBoxId and toBoxId must be set');
  if (fromBoxId === toBoxId) throw new Error('fromBoxId and toBoxId must differ');
  const { resend } = options;
  if (resend !== undefined && !isResendSalt(resend)) {
    throw new Error(
      `resend salt ${JSON.stringify(resend)} is invalid: use 1-128 of [A-Za-z0-9._:-]`,
    );
  }
  if (options.customDocumentId !== undefined && !isGuid(options.customDocumentId)) {
    throw new Error(
      `customDocumentId ${JSON.stringify(options.customDocumentId)} must be a GUID ` +
        '(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): CanPostMessage refuses anything else (D192)',
    );
  }
  const log = deps.log ?? (() => undefined);
  const callOptions = signal === undefined ? {} : { signal };
  signal?.throwIfAborted();

  // 1. Parse: the exact bytes, no re-encoding. Size first: a file the shelf cannot take is not parsed.
  if (input.content.length > SHELF_MAX_BYTES) {
    throw new PipelineError(
      'CONTENT_TOO_LARGE',
      'parse',
      `${input.fileName} is ${String(input.content.length)} bytes; the Diadoc shelf takes at most ` +
        String(SHELF_MAX_BYTES),
    );
  }
  let utd: UtdDocument;
  try {
    utd = parseUtd(
      input,
      options.resolveVersion === undefined ? {} : { resolveVersion: options.resolveVersion },
    );
  } catch (error) {
    // Before the operationId exists (it hashes ИдФайл), so not through `step`.
    throw new PipelineError('INVALID_UTD', 'parse', describe(error), { cause: error });
  }
  const testSignature = deps.signer === DIADOC_TEST_SIGNATURE;
  const operationId = operationIdFor({
    fromBoxId,
    toBoxId,
    idFile: utd.idFile,
    content: utd.content,
    customDocumentId: options.customDocumentId,
    resend,
    testSignature,
  });
  const customDocumentId = options.customDocumentId ?? customDocumentIdFor(operationId);
  log(
    `parsed ${utd.fileName}: ${utd.function} ${utd.version}, ${String(utd.content.length)} bytes`,
  );

  // 2–3. Sign (or check the boxes may take the Diadoc test signature).
  const now = deps.now ?? Date.now;
  const signature: UtdSignature =
    deps.signer === DIADOC_TEST_SIGNATURE
      ? await checkTestBoxes()
      : await signAndCheck(deps.signer);

  // 4. Domain attachment (checks DER framing).
  const attachment = step('attach', 'INVALID_SIGNATURE', () =>
    buildUtdAttachment(utd, signature, { customDocumentId }),
  );

  // 5. Pre-check before any side effect on Diadoc (shelf upload, post).
  const warnings: MessageValidationError[] = [];
  if (options.precheck ?? true) {
    signal?.throwIfAborted();
    const check = await stepAsync('precheck', 'PRECHECK_FAILED', async () => {
      try {
        return await deps.diadoc.canPostMessage(
          toMessagePrototype(fromBoxId, toBoxId, attachment),
          callOptions,
        );
      } catch (error) {
        // An aborted retry pause rejects with its own AbortError, not the signal's reason.
        throw signal?.aborted ? signal.reason : error;
      }
    });
    const blocking: MessageValidationError[] = [];
    for (const e of check.Errors ?? []) (isBlocking(e) ? blocking : warnings).push(e);
    if (blocking.length > 0) {
      throw new PipelineError(
        'PRECHECK_REJECTED',
        'precheck',
        `CanPostMessage rejected ${utd.fileName}: ${blocking.map(describeValidation).join('; ')}`,
        { details: blocking, operationId },
      );
    }
    log(`precheck ok${warnings.length > 0 ? ` (${String(warnings.length)} warnings)` : ''}`);
  }

  // 6. Diadoc attachment (D2); large content goes to the shelf first.
  let nameOnShelf: string | undefined;
  if (attachment.contentPlacement === 'shelf') {
    signal?.throwIfAborted();
    nameOnShelf = await stepAsync('upload', 'SHELF_UPLOAD_FAILED', async () => {
      try {
        return await deps.diadoc.shelfUpload(attachment.content, {
          fileExtension: '.xml',
          ...callOptions,
        });
      } catch (error) {
        // An aborted fetch or retry pause rejects with its own AbortError, not the signal's reason.
        throw signal?.aborted ? signal.reason : error;
      }
    });
    log(`uploaded to shelf as ${nameOnShelf}`);
  }
  const documentAttachment = toDocumentAttachment(attachment, nameOnShelf);

  // 7. Post with a deterministic operationId.
  signal?.throwIfAborted();
  let message;
  try {
    message = await deps.diadoc.postMessage(
      { FromBoxId: fromBoxId, ToBoxId: toBoxId, DocumentAttachments: [documentAttachment] },
      {
        operationId,
        ...(options.postMaxAttempts === undefined ? {} : { maxAttempts: options.postMaxAttempts }),
      },
    );
  } catch (error) {
    throw postError(error, operationId, resend);
  }
  const entity = findDocumentEntity(message);
  if (!entity?.EntityId) {
    throw new PipelineError(
      'NO_DOCUMENT_ENTITY',
      'post',
      `message ${message.MessageId} has no document entity`,
      { operationId, messageId: message.MessageId },
    );
  }
  log(`posted: message ${message.MessageId}, entity ${entity.EntityId}`);

  // 8. Poll the docflow status.
  const poll = await pollDocflowStatus(
    { boxId: fromBoxId, messageId: message.MessageId, entityId: entity.EntityId },
    {
      getDocument: (ref, o) => deps.diadoc.getDocument(ref, o),
      sleep: deps.sleep ?? ((ms) => delay(ms, undefined, callOptions)),
      now,
      signal,
    },
    { ...DEFAULT_POLL_OPTIONS, ...options.poll },
  );
  let signatureCheck: SignatureCheck | undefined;
  const document = poll.document;
  if (
    document !== undefined &&
    (poll.outcome === 'error' ||
      document.SenderSignatureStatus === 'SenderSignatureCheckedAndInvalid')
  ) {
    signatureCheck = await checkSenderSignature(
      { boxId: fromBoxId, messageId: message.MessageId, entityId: entity.EntityId },
      document,
      deps.diadoc,
      { deadline: now() + SIGNATURE_CHECK_TIMEOUT_MS, ...callOptions },
    );
  }
  log(
    `status: ${poll.outcome}${poll.status?.PrimaryStatus?.StatusText ? ` (${poll.status.PrimaryStatus.StatusText})` : ''} after ${String(poll.polls)} polls`,
  );

  if (signatureCheck !== undefined) {
    const statusText = poll.status?.PrimaryStatus?.StatusText;
    log(`sender signature: ${describeSignatureCheck(signatureCheck, statusText)}`);
  }

  return {
    operationId,
    customDocumentId,
    ...(resend === undefined ? {} : { resend }),
    ...(testSignature ? { testSignature: true as const } : {}),
    fileName: utd.fileName,
    fromBoxId,
    toBoxId,
    messageId: message.MessageId,
    entityId: entity.EntityId,
    contentPlacement: attachment.contentPlacement,
    ...(nameOnShelf === undefined ? {} : { nameOnShelf }),
    outcome: poll.outcome,
    final: poll.outcome !== 'pending',
    ...(poll.status === undefined ? {} : { status: poll.status }),
    ...(poll.statusError === undefined ? {} : { statusError: poll.statusError }),
    polls: poll.polls,
    warnings,
    ...(signatureCheck === undefined ? {} : { signatureCheck }),
  };

  /** Our own signature, checked before anything leaves the building. */
  async function signAndCheck(signer: Signer): Promise<Buffer> {
    // 2–3. Sign and check our own signature before anything leaves the building: the structure
    // (detached, one signer, the configured certificate) locally, then the math and chain upstream.
    const certificate = step('sign', 'CERTIFICATE_INVALID', () =>
      readSignerCertificate(signer.certificate),
    );
    const expired = validityProblem(certificate, now());
    if (expired !== undefined) {
      throw new PipelineError('CERTIFICATE_INVALID', 'sign', expired, { operationId });
    }
    const { signature } = await stepAsync('sign', 'SIGN_FAILED', () =>
      signer.sign(utd.content, callOptions),
    );
    log(`signed: ${String(signature.length)} bytes of CMS`);
    let structure: string[];
    try {
      structure = cmsPolicyViolations(signature, certificate);
    } catch (error) {
      if (!(error instanceof Asn1Error)) throw error;
      throw new PipelineError(
        'INVALID_SIGNATURE',
        'policy',
        `the signer returned no DER CMS SignedData: ${error.message}`,
        { cause: error, operationId },
      );
    }
    if (structure.length > 0) {
      throw new PipelineError('SIGNATURE_POLICY_VIOLATION', 'policy', structure.join('; '), {
        operationId,
      });
    }
    const verification = await stepAsync('verify', 'VERIFY_FAILED', () =>
      signer.verify(utd.content, signature, callOptions),
    );
    if (!verification.valid) {
      const failed = classifyVerifyFailure(verification, certificate, now());
      throw new PipelineError(
        failed.code,
        'verify',
        `signature over ${utd.fileName} is rejected: ${failed.message}`,
        { details: verification.signers, operationId },
      );
    }
    const verified = verifiedSignerViolations(verification, certificate);
    if (verified.length > 0) {
      throw new PipelineError('SIGNATURE_POLICY_VIOLATION', 'verify', verified.join('; '), {
        details: verification.signers,
        operationId,
      });
    }
    log(`verified: signer ${certificate.thumbprint}`);
    return signature;
  }

  /**
   * The Diadoc test signature is for test boxes only: both boxes must be test organisations, so it
   * can never reach a real counteragent. Runs with or without the precheck.
   */
  async function checkTestBoxes(): Promise<typeof DIADOC_TEST_SIGNATURE> {
    for (const [role, boxId] of [
      ['sender', fromBoxId],
      ['recipient', toBoxId],
    ] as const) {
      signal?.throwIfAborted();
      const organization = await stepAsync('precheck', 'PRECHECK_FAILED', async () => {
        try {
          return await deps.diadoc.getOrganization(boxId, callOptions);
        } catch (error) {
          throw signal?.aborted ? signal.reason : error;
        }
      });
      if (organization.IsTest !== true) {
        throw new PipelineError(
          'TEST_SIGNATURE_REFUSED',
          'precheck',
          `the Diadoc test signature is only for test boxes, but the ${role} box ${boxId} ` +
            `(${organizationName(organization)}) is not a test organisation ` +
            `(IsTest: ${JSON.stringify(organization.IsTest ?? null)})`,
          { operationId },
        );
      }
    }
    log('signature: the Diadoc test signature (SignWithTestSignature), both boxes are test boxes');
    return DIADOC_TEST_SIGNATURE;
  }

  function step<T>(name: PipelineStep, code: PipelineErrorCode, fn: () => T): T {
    try {
      return fn();
    } catch (error) {
      throw wrap(name, code, error);
    }
  }

  async function stepAsync<T>(
    name: PipelineStep,
    code: PipelineErrorCode,
    fn: () => Promise<T>,
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      throw wrap(name, code, error);
    }
  }

  /** An abort is not a pipeline failure: rethrow the signal's reason as is. */
  function wrap(name: PipelineStep, code: PipelineErrorCode, error: unknown): unknown {
    if (signal?.aborted && error === signal.reason) return error;
    // Only the Diadoc steps: no other step talks to the IdP.
    const diadocStep = name === 'precheck' || name === 'upload';
    const authCode = diadocStep && isAuthFailure(error) ? 'DIADOC_AUTH' : code;
    return new PipelineError(authCode, name, describe(error), { cause: error, operationId });
  }
}

function organizationName(o: Organization): string {
  return o.ShortName ?? o.FullName ?? (o.Inn === undefined ? 'unknown' : `ИНН ${o.Inn}`);
}

function postError(error: unknown, operationId: string, resend: string | undefined): unknown {
  // Only the same salt reproduces the operationId of a resend.
  const sameSalt = resend === undefined ? '' : ` with the same resend salt ${resend}`;
  if (error instanceof DiadocOperationPendingError) {
    return new PipelineError(
      'POST_PENDING',
      'post',
      `${error.message}; run send again${sameSalt} later to get the result`,
      { cause: error, operationId },
    );
  }
  if (error instanceof DiadocPostOutcomeUnknownError) {
    return new PipelineError(
      'POST_FAILED',
      'post',
      `${describe(error.cause)}; the message may have been posted: look it up in Diadoc before ` +
        `sending again${sameSalt} (a repeat reuses the operationId, D7)`,
      { cause: error, operationId },
    );
  }
  if (!(error instanceof DiadocConflictError)) {
    // Checked after DiadocPostOutcomeUnknownError: a token failure after a sent request stays "may
    // have been posted".
    const code = isAuthFailure(error) ? 'DIADOC_AUTH' : 'POST_FAILED';
    return new PipelineError(code, 'post', describe(error), { cause: error, operationId });
  }
  const code = (
    { duplicate: 'ALREADY_SENT', forbidden: 'RECIPIENT_FORBIDS', unknown: 'POST_CONFLICT' } as const
  )[classifyConflict(error.body)];
  const body =
    error.body.length > MAX_CONFLICT_BODY
      ? `${error.body.slice(0, MAX_CONFLICT_BODY)}… (${String(error.body.length)} chars)`
      : error.body;
  return new PipelineError(code, 'post', `409: ${body}`, { cause: error, operationId });
}

/**
 * A DiadocAuthError, or an error caused by one; not a refresh skipped for lack of time before a
 * deadline (DiadocTokenDeadlineError), which says nothing about the credentials.
 */
export function isAuthFailure(error: unknown): boolean {
  for (let e: unknown = error, depth = 0; e instanceof Error && depth < 8; e = e.cause, depth++) {
    if (e instanceof DiadocTokenDeadlineError) return false;
    if (e instanceof DiadocAuthError) return true;
  }
  return false;
}

/** Same bound as DiadocError.message; the full body stays on `cause`. */
const MAX_CONFLICT_BODY = 1000;

/** Missing severity counts as an error: the stricter reading of an undocumented field. */
function isBlocking(e: MessageValidationError): boolean {
  const severity = e.Severity?.toLowerCase();
  return severity !== 'warning' && severity !== 'info';
}

function describeValidation(e: MessageValidationError): string {
  return e.UserMessage ?? e.ApiMessage ?? JSON.stringify(e);
}

function describe(error: unknown): string {
  if (error instanceof UtdError) return `${error.code}: ${error.message}`;
  if (!(error instanceof Error)) return String(error);
  // fetch() hides the useful part (ECONNREFUSED, DNS, TLS) in `cause`; signer errors already
  // carry the whole cause chain in their message.
  return error.cause instanceof Error && !error.message.includes(error.cause.message)
    ? `${error.message}: ${error.cause.message}`
    : error.message;
}

// Typed client for the Контур.Диадок methods the pipeline needs. JSON over HTTPS, Bearer auth.
import { setTimeout as delay } from 'node:timers/promises';

import type { AccessTokenProvider } from './auth.js';
import {
  DiadocConflictError,
  DiadocError,
  DiadocOperationPendingError,
  DiadocPostOutcomeUnknownError,
} from './errors.js';
import {
  DEFAULT_RETRY_POLICY,
  fetchWithRetry,
  isConnectPhaseError,
  isTransientFetchError,
  type RetryPolicy,
} from './http-retry.js';
import { MAX_RETRY_AFTER_MS, retryAfterMs } from './retry-after.js';
import type {
  DocflowStatus,
  Document,
  DocumentAttachment,
  DocumentRef,
  DocumentTypesResponse,
  Entity,
  Message,
  MessagePrototype,
  MessageToPost,
  MessageValidationResult,
  Organization,
  OrganizationList,
  SignatureInfo,
} from './types.js';

export const DIADOC_HOSTS = {
  prod: 'https://diadoc-api.kontur.ru',
  staging: 'https://diadoc-api-staging.kontur.ru',
} as const;

export type DiadocEnvironment = keyof typeof DIADOC_HOSTS;

export interface DiadocClientOptions {
  auth: AccessTokenProvider;
  /** Box ids differ between environments. Ignored when `baseUrl` is set. */
  environment?: DiadocEnvironment;
  baseUrl?: string;
  /** Per HTTP request. Default 60 s. */
  timeoutMs?: number;
  /**
   * Repeats of the identical request on 429 (honouring Retry-After), 408, 5xx, network errors and
   * timeouts, for every method: GETs and CanPostMessage are reads, PostMessage is idempotent by
   * operationId, and an extra ShelfUpload only leaves an unused shelf file.
   */
  retry?: Partial<RetryPolicy>;
  fetch?: typeof fetch;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

export interface RequestOptions {
  /** Aborts the request and any pause between retries. */
  signal?: AbortSignal | undefined;
  /**
   * Absolute time (per the client's `now`) no retry pause may run past. A request already started
   * still runs up to `timeoutMs`.
   */
  deadline?: number | undefined;
}

export interface PostMessageOptions {
  /** Idempotency key: Diadoc returns the same result for the same operationId. Keep it stable across retries. */
  operationId: string;
  /** Attempts while Diadoc answers 204 (still processing). Default 10. */
  maxAttempts?: number;
  /**
   * Wall-clock time for the whole call: 204 rounds, retries, their pauses, token refreshes and each
   * request's timeout all end within it. Default POST_MESSAGE_BUDGET_MS.
   */
  budgetMs?: number;
}

/**
 * Default PostMessage time budget. The CLI does not interrupt PostMessage on the first signal, so
 * `stop_grace_period` of the `app` service (root docker-compose.yml) must exceed it.
 */
export const POST_MESSAGE_BUDGET_MS = 180_000;

/**
 * Pause after a PostMessage 204 without a usable Retry-After (R2 M2): 1 s would spend all attempts
 * in seconds and turn a slow operation into a re-run.
 */
export const POST_PENDING_FALLBACK_MS = 5_000;

/**
 * No PostMessage request (first attempt aside) starts with less of the budget left: it would be cut
 * almost at once after its body left, turning a plain 429/503 into "may have been posted".
 */
export const POST_MIN_REQUEST_MS = 5_000;

export interface ShelfUploadOptions {
  /** With the dot, e.g. `.xml`: only affects the name of a downloaded file. */
  fileExtension?: string;
  /** Aborts the running request, any retry pause, and the upload between parts. */
  signal?: AbortSignal | undefined;
}

export interface ShelfUploadPartsOptions extends ShelfUploadOptions {
  /** Bytes per part, 1..SHELF_UPLOAD_MAX_BYTES. Default SHELF_UPLOAD_MAX_BYTES. */
  partSize?: number;
}

/**
 * One shelf request carries at most 3 MB: V2/ShelfUpload takes a whole file up to that, and so does
 * each ShelfUploadPartInit/ShelfUploadPart part (http/ShelfUpload.html, http/ShelfUploadPart.html).
 * Assumption: MB = 10^6 bytes, the stricter reading (the C# SDK uses 3 MiB parts).
 */
export const SHELF_UPLOAD_MAX_BYTES = 3_000_000;

/** A file uploaded in parts may be up to 400 MB (http/ShelfUploadPartInit.html); read as 10^6. */
export const SHELF_MAX_BYTES = 400_000_000;

/**
 * Rounds of ShelfUploadPart, the first upload included: up to 2 re-sends of the parts the last answer
 * lists as missing. Same count as the C# SDK (`UploadLargeFileToShelf`: 3 attempts, the first one
 * uploading every part); each request also has its own transient retries.
 */
export const SHELF_UPLOAD_MAX_ROUNDS = 3;

type Query = Record<string, string>;
type Body = { data: string; type: string } | { data: Buffer; type: string };

/** Set once a PostMessage request may have reached Diadoc without us learning the outcome. */
interface Uncertainty {
  maybeReceived: boolean;
}

interface SendOptions extends RequestOptions {
  uncertainty?: Uncertainty;
  /**
   * The deadline also cuts each request, and a retry only starts with POST_MIN_REQUEST_MS left
   * (PostMessage's budget).
   */
  hardDeadline?: boolean;
}

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const BINARY_CONTENT_TYPE = 'application/octet-stream';
const DEFAULT_POST_ATTEMPTS = 10;
const DEFAULT_TIMEOUT_MS = 60_000;

export class DiadocClient {
  private readonly baseUrl: string;
  private readonly auth: AccessTokenProvider;
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly retry: Readonly<RetryPolicy>;

  constructor(o: DiadocClientOptions) {
    const baseUrl = o.baseUrl ?? DIADOC_HOSTS[o.environment ?? 'prod'];
    // Paths are appended to the base as text: a query or fragment would swallow them.
    if (/[?#]/.test(baseUrl)) {
      throw new Error('Diadoc baseUrl must not contain a query or fragment');
    }
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.auth = o.auth;
    this.fetchFn = o.fetch ?? fetch;
    this.sleep =
      o.sleep ?? ((ms, signal) => delay(ms, undefined, signal === undefined ? {} : { signal }));
    this.now = o.now ?? Date.now;
    this.timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retry = { ...DEFAULT_RETRY_POLICY, ...o.retry };
  }

  /** `autoRegister=false`: never silently register the user into an organization. */
  getMyOrganizations(): Promise<OrganizationList> {
    return this.getJson('/GetMyOrganizations', { autoRegister: 'false' });
  }

  /** `IsTest` tells the test organisations (quickstart boxes) from real ones. */
  getOrganization(boxId: string, o: RequestOptions = {}): Promise<Organization> {
    return this.getJson('/GetOrganization', { boxId }, o);
  }

  getDocumentTypes(boxId: string): Promise<DocumentTypesResponse> {
    return this.getJson('/V3/GetDocumentTypes', { boxId });
  }

  /** A read: the signal may abort it at any time. */
  async canPostMessage(
    prototype: MessagePrototype,
    o: RequestOptions = {},
  ): Promise<MessageValidationResult> {
    const res = await this.send('POST', '/CanPostMessage', {}, json(prototype), o);
    return readJson<MessageValidationResult>(res, 'POST', '/CanPostMessage');
  }

  /**
   * V3/PostMessage. The body is serialized once and every repeat sends the identical bytes with the
   * same operationId: `204` + `Retry-After` (still running), 429, 5xx, network errors and timeouts
   * (see `retry`). `409` (duplicate or forbidden by the recipient) becomes DiadocConflictError. Any
   * other failure after a request whose outcome is unknown becomes DiadocPostOutcomeUnknownError; a
   * request that never connected (refused, DNS) is not one. Everything ends within `budgetMs`; a 204
   * whose next pause would reach it ends as DiadocOperationPendingError.
   */
  async postMessage(message: MessageToPost, o: PostMessageOptions): Promise<Message> {
    if (o.operationId === '') throw new Error('PostMessage needs a non-empty operationId');
    const maxAttempts = o.maxAttempts ?? DEFAULT_POST_ATTEMPTS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
      throw new Error(
        `PostMessage maxAttempts must be an integer >= 1, got ${String(maxAttempts)}`,
      );
    }
    const budgetMs = o.budgetMs ?? POST_MESSAGE_BUDGET_MS;
    if (!(budgetMs > 0)) {
      throw new Error(`PostMessage budgetMs must be > 0, got ${String(budgetMs)}`);
    }
    const deadline = this.now() + budgetMs;
    const path = '/V3/PostMessage';
    const body = json(toWireMessage(message));
    const uncertainty: Uncertainty = { maybeReceived: false };
    try {
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const res = await this.send('POST', path, { operationId: o.operationId }, body, {
          uncertainty,
          deadline,
          hardDeadline: true,
        });
        // Any 2xx (204 included) means Diadoc took the request.
        uncertainty.maybeReceived = true;
        if (res.status !== 204) return await readJson<Message>(res, 'POST', path);
        if (attempt < maxAttempts) {
          const now = this.now();
          const pause = retryAfterMs(
            res.headers.get('retry-after'),
            now,
            MAX_RETRY_AFTER_MS,
            POST_PENDING_FALLBACK_MS,
          );
          // A pause must leave time for the next request.
          if (now + pause > deadline - POST_MIN_REQUEST_MS) {
            throw new DiadocOperationPendingError(o.operationId, attempt, budgetMs);
          }
          await this.sleep(pause);
        }
      }
    } catch (error) {
      if (
        !uncertainty.maybeReceived ||
        error instanceof DiadocConflictError ||
        error instanceof DiadocOperationPendingError
      ) {
        throw error;
      }
      throw new DiadocPostOutcomeUnknownError(o.operationId, error);
    }
    throw new DiadocOperationPendingError(o.operationId, maxAttempts);
  }

  /**
   * Stores `content` on the shelf for `SignedContent.NameOnShelf` and returns the generated name:
   * V2/ShelfUpload up to SHELF_UPLOAD_MAX_BYTES, above that `shelfUploadParts`. Not idempotent (each
   * call makes a new name), which is harmless: an unused shelf file is not sent.
   */
  async shelfUpload(content: Buffer, o: ShelfUploadOptions = {}): Promise<string> {
    checkShelfContent(content);
    if (content.length > SHELF_UPLOAD_MAX_BYTES) return this.shelfUploadParts(content, o);
    const path = '/V2/ShelfUpload';
    const res = await this.send('POST', path, extensionQuery(o), binary(content), {
      signal: o.signal,
    });
    return readShelfName(res, path);
  }

  /**
   * ShelfUploadPartInit with the first part (makes the name; its answer is the name even when it is
   * the only part), then ShelfUploadPart with `partIndex` 1, 2, … and `isLastPart=true` on the last
   * one. The answer to the last part lists the indexes Diadoc failed to store; those are sent again,
   * the last of them with `isLastPart=true` as the C# SDK does, within SHELF_UPLOAD_MAX_ROUNDS rounds.
   * Every request repeats its identical bytes and query on transient failures. Docs-only (T6):
   * whether a repeated part overwrites the stored one, whether `isLastPart=true` on a re-sent middle
   * part is read as "check now" (SDK) rather than "the file ends here", and what a repeat of an
   * already accepted last part answers (e.g. after a 502 with unknown outcome): a 4xx there fails the
   * whole upload. Failing is harmless: a partial shelf file is never sent, and `send` can be re-run.
   * An abort stops the running request, a retry pause, or the loop between parts.
   */
  async shelfUploadParts(content: Buffer, o: ShelfUploadPartsOptions = {}): Promise<string> {
    checkShelfContent(content);
    const partSize = o.partSize ?? SHELF_UPLOAD_MAX_BYTES;
    if (!Number.isInteger(partSize) || partSize < 1 || partSize > SHELF_UPLOAD_MAX_BYTES) {
      throw new Error(
        `ShelfUpload partSize must be an integer in 1..${String(SHELF_UPLOAD_MAX_BYTES)}, got ` +
          String(partSize),
      );
    }
    const parts: Buffer[] = [];
    for (let at = 0; at < content.length; at += partSize) {
      parts.push(content.subarray(at, at + partSize));
    }
    const { signal } = o;
    const initPath = '/ShelfUploadPartInit';
    const init = await this.send(
      'POST',
      initPath,
      { ...extensionQuery(o), isLastPart: String(parts.length === 1) },
      binary(parts[0] ?? content),
      { signal },
    );
    const fileName = await readShelfName(init, initPath);

    const partPath = '/ShelfUploadPart';
    let pending = parts.map((_, i) => i).slice(1);
    for (let round = 1; pending.length > 0; round++) {
      if (round > SHELF_UPLOAD_MAX_ROUNDS) {
        throw new DiadocError(
          'POST',
          partPath,
          200,
          `${fileName}: parts still missing after ${String(SHELF_UPLOAD_MAX_ROUNDS)} rounds: ` +
            pending.join(', '),
        );
      }
      let missing: number[] = [];
      for (const [i, index] of pending.entries()) {
        signal?.throwIfAborted();
        const isLastPart = i === pending.length - 1;
        const res = await this.send(
          'POST',
          partPath,
          { fileName, partIndex: String(index), isLastPart: String(isLastPart) },
          binary(parts[index] ?? Buffer.alloc(0)),
          { signal },
        );
        const text = await res.text();
        // Only the answer to the last part is the complete list (the SDK ignores the others).
        if (isLastPart) missing = parseMissingParts(text, parts.length, res.status, partPath);
      }
      pending = missing;
    }
    return fileName;
  }

  getDocument(ref: DocumentRef, o: RequestOptions = {}): Promise<Document> {
    return this.getJson(
      '/V3/GetDocument',
      {
        boxId: ref.boxId,
        messageId: ref.messageId,
        entityId: ref.entityId,
        injectEntityContent: 'false',
      },
      o,
    );
  }

  /** V5/GetMessage without entity content: the entities (signatures, notifications) of a message. */
  getMessage(boxId: string, messageId: string, o: RequestOptions = {}): Promise<Message> {
    return this.getJson('/V5/GetMessage', { boxId, messageId, injectEntityContent: 'false' }, o);
  }

  /** The raw bytes of an entity (e.g. the document content as Diadoc stored it). */
  async getEntityContent(ref: DocumentRef, o: RequestOptions = {}): Promise<Buffer> {
    const res = await this.send(
      'GET',
      '/V4/GetEntityContent',
      { boxId: ref.boxId, messageId: ref.messageId, entityId: ref.entityId },
      undefined,
      o,
    );
    return Buffer.from(await res.arrayBuffer());
  }

  /** How Diadoc verified a signature entity (`ref.entityId` is the Signature entity). */
  getSignatureInfo(ref: DocumentRef, o: RequestOptions = {}): Promise<SignatureInfo> {
    return this.getJson(
      '/GetSignatureInfo',
      { boxId: ref.boxId, messageId: ref.messageId, entityId: ref.entityId },
      o,
    );
  }

  async getDocflowStatus(ref: DocumentRef): Promise<DocflowStatus> {
    const doc = await this.getDocument(ref);
    if (!doc.DocflowStatus) {
      throw new Error(`Diadoc document ${ref.messageId}/${ref.entityId} has no DocflowStatus`);
    }
    return doc.DocflowStatus;
  }

  private async getJson<T>(path: string, query: Query, o: RequestOptions = {}): Promise<T> {
    const res = await this.send('GET', path, query, undefined, o);
    return readJson<T>(res, 'GET', path);
  }

  /**
   * Repeats transient failures per `retry` and retries once per call on 401 with a fresh token (the
   * cached one may have been revoked). Never follows redirects: a 3xx to another host would carry
   * the request body (the signed document) there. The deadline and signal also bound a token refresh.
   */
  private async send(
    method: string,
    path: string,
    query: Query,
    body?: Body,
    o: SendOptions = {},
  ): Promise<Response> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    const { signal, deadline, uncertainty } = o;
    const hardDeadline = o.hardDeadline === true ? deadline : undefined;

    let refreshed = false;
    const fetchTracked = async (token: string): Promise<Response> => {
      try {
        const res = await this.fetchOnce(method, url, token, body, signal, hardDeadline);
        if (res.status >= 500 && uncertainty) uncertainty.maybeReceived = true;
        return res;
      } catch (error) {
        if (
          uncertainty &&
          !signal?.aborted &&
          isTransientFetchError(error) &&
          !isConnectPhaseError(error)
        ) {
          uncertainty.maybeReceived = true;
        }
        throw error;
      }
    };
    const tokenOptions = { signal, deadline };
    const res = await fetchWithRetry(
      async () => {
        signal?.throwIfAborted();
        const token = await this.auth.getAccessToken(tokenOptions);
        const first = await fetchTracked(token);
        if (first.status !== 401 || !this.auth.invalidate || refreshed) return first;
        refreshed = true;
        await first.body?.cancel().catch(() => undefined);
        this.auth.invalidate(token);
        return fetchTracked(await this.auth.getAccessToken(tokenOptions));
      },
      this.retry,
      {
        sleep: this.sleep,
        now: this.now,
        signal,
        deadline: hardDeadline === undefined ? deadline : hardDeadline - POST_MIN_REQUEST_MS,
      },
    );
    if (res.ok) return res;

    const text = await res.text();
    if (res.status === 409) throw new DiadocConflictError(method, path, text);
    throw new DiadocError(method, path, res.status, text);
  }

  private fetchOnce(
    method: string,
    url: URL,
    token: string,
    body: Body | undefined,
    signal: AbortSignal | undefined,
    deadline: number | undefined,
  ): Promise<Response> {
    const left = deadline === undefined ? this.timeoutMs : deadline - this.now();
    // Not transient: nothing is sent, so fetchWithRetry stops here.
    if (left <= 0)
      return Promise.reject(new Error(`no time left before the deadline for ${url.pathname}`));
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: JSON_CONTENT_TYPE,
    };
    if (body !== undefined) headers['content-type'] = body.type;
    const timeout = AbortSignal.timeout(Math.min(this.timeoutMs, left));
    return this.fetchFn(url.href, {
      method,
      headers,
      redirect: 'error',
      signal: signal === undefined ? timeout : AbortSignal.any([signal, timeout]),
      ...(body === undefined ? {} : { body: body.data }),
    });
  }
}

function checkShelfContent(content: Buffer): void {
  if (content.length === 0) throw new Error('ShelfUpload content is empty');
  if (content.length > SHELF_MAX_BYTES) {
    throw new Error(
      `the shelf takes at most ${String(SHELF_MAX_BYTES)} bytes per file, got ${String(content.length)}`,
    );
  }
}

const extensionQuery = (o: ShelfUploadOptions): Query =>
  o.fileExtension === undefined ? {} : { fileExtension: o.fileExtension };

const binary = (data: Buffer): Body => ({ data, type: BINARY_CONTENT_TYPE });

/** Documented as "a string"; tolerate both text/plain and a JSON string literal. */
async function readShelfName(res: Response, path: string): Promise<string> {
  const text = (await res.text()).trim();
  let name = text;
  if (text.startsWith('"')) {
    try {
      name = String(JSON.parse(text));
    } catch {
      // keep the raw text; validated below
    }
  }
  if (name === '' || /\s/.test(name)) {
    throw new DiadocError('POST', path, res.status, `unexpected shelf name: ${text}`);
  }
  return name;
}

/**
 * A JSON array of part indexes, sorted and deduplicated. An empty body counts as `[]`, as in the C#
 * SDK; anything else that is not an array of known indexes is an error.
 */
function parseMissingParts(text: string, parts: number, status: number, path: string): number[] {
  if (text.trim() === '') return [];
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    value = undefined;
  }
  if (
    !Array.isArray(value) ||
    !value.every((i): i is number => Number.isInteger(i) && i >= 0 && i < parts)
  ) {
    throw new DiadocError('POST', path, status, `unexpected missing-parts answer: ${text}`);
  }
  return [...new Set(value)].sort((a, b) => a - b);
}

const json = (value: unknown): Body => ({ data: JSON.stringify(value), type: JSON_CONTENT_TYPE });

/** The posted document is the Attachment entity without a parent (signatures hang under it). */
export function findDocumentEntity(message: Message): Entity | undefined {
  return message.Entities?.find(
    (e) => e.EntityType === 'Attachment' && (e.ParentEntityId ?? '') === '',
  );
}

/** A 2xx with a non-JSON body (e.g. a proxy page) is reported like any other Diadoc failure. */
async function readJson<T>(res: Response, method: string, path: string): Promise<T> {
  const text = await res.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new DiadocError(method, path, res.status, `non-JSON response: ${text}`);
  }
}

function toWireMessage(m: MessageToPost): unknown {
  const { DocumentAttachments, ...rest } = m;
  return { ...rest, DocumentAttachments: DocumentAttachments.map(toWireAttachment) };
}

function toWireAttachment(a: DocumentAttachment): unknown {
  const { SignedContent: sc, ...rest } = a;
  return {
    ...rest,
    SignedContent: {
      ...(sc.Content === undefined ? {} : { Content: sc.Content.toString('base64') }),
      ...(sc.Signature === undefined ? {} : { Signature: sc.Signature.toString('base64') }),
      ...(sc.NameOnShelf === undefined ? {} : { NameOnShelf: sc.NameOnShelf }),
      ...(sc.SignWithTestSignature === undefined
        ? {}
        : { SignWithTestSignature: sc.SignWithTestSignature }),
    },
  };
}

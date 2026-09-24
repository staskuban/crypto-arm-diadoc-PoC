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
  isTransientFetchError,
  type RetryPolicy,
} from './http-retry.js';
import { retryAfterMs } from './retry-after.js';
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
}

export interface ShelfUploadOptions {
  /** With the dot, e.g. `.xml`: only affects the name of a downloaded file. */
  fileExtension?: string;
}

/**
 * V2/ShelfUpload takes the whole file in one request up to 3 MB (http/ShelfUpload.html). Assumption:
 * MB = 10^6 bytes, the stricter reading. Larger files need ShelfUploadPartInit/ShelfUploadPart, not
 * implemented.
 */
export const SHELF_UPLOAD_MAX_BYTES = 3_000_000;

type Query = Record<string, string>;
type Body = { data: string; type: string } | { data: Buffer; type: string };

/** Set once a PostMessage request may have reached Diadoc without us learning the outcome. */
interface Uncertainty {
  maybeReceived: boolean;
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

  getOrganization(boxId: string): Promise<Organization> {
    return this.getJson('/GetOrganization', { boxId });
  }

  getDocumentTypes(boxId: string): Promise<DocumentTypesResponse> {
    return this.getJson('/V3/GetDocumentTypes', { boxId });
  }

  async canPostMessage(prototype: MessagePrototype): Promise<MessageValidationResult> {
    const res = await this.send('POST', '/CanPostMessage', {}, json(prototype));
    return readJson<MessageValidationResult>(res, 'POST', '/CanPostMessage');
  }

  /**
   * V3/PostMessage. The body is serialized once and every repeat sends the identical bytes with the
   * same operationId: `204` + `Retry-After` (still running), 429, 5xx, network errors and timeouts
   * (see `retry`). `409` (duplicate or forbidden by the recipient) becomes DiadocConflictError. Any
   * other failure after a request whose outcome is unknown becomes DiadocPostOutcomeUnknownError.
   */
  async postMessage(message: MessageToPost, o: PostMessageOptions): Promise<Message> {
    if (o.operationId === '') throw new Error('PostMessage needs a non-empty operationId');
    const maxAttempts = o.maxAttempts ?? DEFAULT_POST_ATTEMPTS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
      throw new Error(
        `PostMessage maxAttempts must be an integer >= 1, got ${String(maxAttempts)}`,
      );
    }
    const path = '/V3/PostMessage';
    const body = json(toWireMessage(message));
    const uncertainty: Uncertainty = { maybeReceived: false };
    try {
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const res = await this.send('POST', path, { operationId: o.operationId }, body, {
          uncertainty,
        });
        // Any 2xx (204 included) means Diadoc took the request.
        uncertainty.maybeReceived = true;
        if (res.status !== 204) return await readJson<Message>(res, 'POST', path);
        if (attempt < maxAttempts) {
          await this.sleep(retryAfterMs(res.headers.get('retry-after'), this.now()));
        }
      }
    } catch (error) {
      if (!uncertainty.maybeReceived || error instanceof DiadocConflictError) throw error;
      throw new DiadocPostOutcomeUnknownError(o.operationId, error);
    }
    throw new DiadocOperationPendingError(o.operationId, maxAttempts);
  }

  /**
   * V2/ShelfUpload: stores `content` for `SignedContent.NameOnShelf` and returns the generated name.
   * Not idempotent (each call makes a new name), which is harmless: an unused shelf file is not sent.
   */
  async shelfUpload(content: Buffer, o: ShelfUploadOptions = {}): Promise<string> {
    const path = '/V2/ShelfUpload';
    if (content.length === 0) throw new Error('ShelfUpload content is empty');
    if (content.length > SHELF_UPLOAD_MAX_BYTES) {
      throw new Error(
        `ShelfUpload takes at most ${String(SHELF_UPLOAD_MAX_BYTES)} bytes in one request, got ` +
          `${String(content.length)}; ShelfUploadPartInit/ShelfUploadPart are not implemented`,
      );
    }
    const query: Query = o.fileExtension === undefined ? {} : { fileExtension: o.fileExtension };
    const res = await this.send('POST', path, query, { data: content, type: BINARY_CONTENT_TYPE });
    const text = (await res.text()).trim();
    // Documented as "a string"; tolerate both text/plain and a JSON string literal.
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
   * the request body (the signed document) there.
   */
  private async send(
    method: string,
    path: string,
    query: Query,
    body?: Body,
    o: RequestOptions & { uncertainty?: Uncertainty } = {},
  ): Promise<Response> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    const { signal, uncertainty } = o;

    let refreshed = false;
    const fetchTracked = async (token: string): Promise<Response> => {
      try {
        const res = await this.fetchOnce(method, url, token, body, signal);
        if (res.status >= 500 && uncertainty) uncertainty.maybeReceived = true;
        return res;
      } catch (error) {
        if (uncertainty && !signal?.aborted && isTransientFetchError(error)) {
          uncertainty.maybeReceived = true;
        }
        throw error;
      }
    };
    const res = await fetchWithRetry(
      async () => {
        signal?.throwIfAborted();
        const token = await this.auth.getAccessToken();
        const first = await fetchTracked(token);
        if (first.status !== 401 || !this.auth.invalidate || refreshed) return first;
        refreshed = true;
        await first.body?.cancel().catch(() => undefined);
        this.auth.invalidate(token);
        return fetchTracked(await this.auth.getAccessToken());
      },
      this.retry,
      { sleep: this.sleep, now: this.now, signal, deadline: o.deadline },
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
  ): Promise<Response> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: JSON_CONTENT_TYPE,
    };
    if (body !== undefined) headers['content-type'] = body.type;
    const timeout = AbortSignal.timeout(this.timeoutMs);
    return this.fetchFn(url.href, {
      method,
      headers,
      redirect: 'error',
      signal: signal === undefined ? timeout : AbortSignal.any([signal, timeout]),
      ...(body === undefined ? {} : { body: body.data }),
    });
  }
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

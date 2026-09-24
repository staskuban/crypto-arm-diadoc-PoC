// Typed client for the Контур.Диадок methods the pipeline needs. JSON over HTTPS, Bearer auth.
import type { AccessTokenProvider } from './auth.js';
import { DiadocConflictError, DiadocError, DiadocOperationPendingError } from './errors.js';
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
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface PostMessageOptions {
  /** Idempotency key: Diadoc returns the same result for the same operationId. Keep it stable across retries. */
  operationId: string;
  /** Attempts while Diadoc answers 204 (still processing). Default 10. */
  maxAttempts?: number;
}

type Query = Record<string, string>;

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const DEFAULT_POST_ATTEMPTS = 10;
const DEFAULT_TIMEOUT_MS = 60_000;

export class DiadocClient {
  private readonly baseUrl: string;
  private readonly auth: AccessTokenProvider;
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly timeoutMs: number;

  constructor(o: DiadocClientOptions) {
    this.baseUrl = (o.baseUrl ?? DIADOC_HOSTS[o.environment ?? 'prod']).replace(/\/+$/, '');
    this.auth = o.auth;
    this.fetchFn = o.fetch ?? fetch;
    this.sleep = o.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = o.now ?? Date.now;
    this.timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
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
    const res = await this.send('POST', '/CanPostMessage', {}, JSON.stringify(prototype));
    return readJson<MessageValidationResult>(res, 'POST', '/CanPostMessage');
  }

  /**
   * V3/PostMessage. `204` + `Retry-After` means the operation is still running: the identical request is
   * repeated. `409` (duplicate or forbidden by the recipient) becomes DiadocConflictError.
   */
  async postMessage(message: MessageToPost, o: PostMessageOptions): Promise<Message> {
    if (o.operationId === '') throw new Error('PostMessage needs a non-empty operationId');
    const maxAttempts = o.maxAttempts ?? DEFAULT_POST_ATTEMPTS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
      throw new Error(
        `PostMessage maxAttempts must be an integer >= 1, got ${String(maxAttempts)}`,
      );
    }
    const body = JSON.stringify(toWireMessage(message));
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const res = await this.send('POST', '/V3/PostMessage', { operationId: o.operationId }, body);
      if (res.status !== 204) return readJson<Message>(res, 'POST', '/V3/PostMessage');
      if (attempt < maxAttempts) {
        await this.sleep(retryAfterMs(res.headers.get('retry-after'), this.now()));
      }
    }
    throw new DiadocOperationPendingError(o.operationId, maxAttempts);
  }

  getDocument(ref: DocumentRef): Promise<Document> {
    return this.getJson('/V3/GetDocument', {
      boxId: ref.boxId,
      messageId: ref.messageId,
      entityId: ref.entityId,
      injectEntityContent: 'false',
    });
  }

  async getDocflowStatus(ref: DocumentRef): Promise<DocflowStatus> {
    const doc = await this.getDocument(ref);
    if (!doc.DocflowStatus) {
      throw new Error(`Diadoc document ${ref.messageId}/${ref.entityId} has no DocflowStatus`);
    }
    return doc.DocflowStatus;
  }

  private async getJson<T>(path: string, query: Query): Promise<T> {
    const res = await this.send('GET', path, query);
    return readJson<T>(res, 'GET', path);
  }

  /** Retries once on 401 with a fresh token (the cached one may have been revoked). */
  private async send(method: string, path: string, query: Query, body?: string): Promise<Response> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);

    let token = await this.auth.getAccessToken();
    let res = await this.fetchOnce(method, url, token, body);
    if (res.status === 401 && this.auth.invalidate) {
      await res.body?.cancel();
      this.auth.invalidate(token);
      token = await this.auth.getAccessToken();
      res = await this.fetchOnce(method, url, token, body);
    }
    if (res.ok) return res;

    const text = await res.text();
    if (res.status === 409) throw new DiadocConflictError(method, path, text);
    throw new DiadocError(method, path, res.status, text);
  }

  private fetchOnce(
    method: string,
    url: URL,
    token: string,
    body: string | undefined,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: JSON_CONTENT_TYPE,
    };
    if (body !== undefined) headers['content-type'] = JSON_CONTENT_TYPE;
    return this.fetchFn(url.href, {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
      ...(body === undefined ? {} : { body }),
    });
  }
}

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

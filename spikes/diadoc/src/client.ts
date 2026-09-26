// Thin HTTP client for the Diadoc methods the spike needs. JSON everywhere except GenerateTitleXml.
export class DiadocError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(method: string, path: string, status: number, body: string) {
    super(`${method} ${path} -> ${status}: ${body.slice(0, 1000)}`);
    this.name = 'DiadocError';
    this.status = status;
    this.body = body;
  }
}

type Query = Record<string, string | undefined>;

const MAX_RETRY_AFTER_MS = 60_000;

/** Retry-After is either delay-seconds or an HTTP-date; anything unusable falls back to 1 s. */
export function retryAfterMs(header: string | null, now = Date.now()): number {
  const v = header?.trim() ?? '';
  const ms = /^\d+$/.test(v) ? Number(v) * 1000 : Date.parse(v) - now;
  return Number.isFinite(ms) && ms > 0 ? Math.min(ms, MAX_RETRY_AFTER_MS) : 1000;
}

export class DiadocClient {
  private readonly baseUrl: string;
  private readonly accessToken: string;
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(o: { baseUrl: string; accessToken: string; fetchFn?: typeof fetch; sleep?: (ms: number) => Promise<void> }) {
    this.baseUrl = o.baseUrl.replace(/\/+$/, '');
    this.accessToken = o.accessToken;
    this.fetchFn = o.fetchFn ?? fetch;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  private url(path: string, query: Query = {}): string {
    const u = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(query)) if (v !== undefined) u.searchParams.set(k, v);
    return u.href;
  }

  private async send(method: string, path: string, query: Query, body?: string, contentType?: string): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.accessToken}`, accept: 'application/json; charset=utf-8' };
    if (contentType) headers['content-type'] = contentType;
    const res = await this.fetchFn(this.url(path, query), { method, headers, body });
    if (!res.ok) throw new DiadocError(method, path, res.status, await res.text());
    return res;
  }

  private async json<T>(method: string, path: string, query: Query = {}, body?: unknown): Promise<T> {
    const res = await this.send(method, path, query, body === undefined ? undefined : JSON.stringify(body), body === undefined ? undefined : 'application/json; charset=utf-8');
    return (await res.json()) as T;
  }

  /** autoRegister=false: never auto-register the user into an organization from a spike. */
  getMyOrganizations(): Promise<any> {
    return this.json('GET', '/GetMyOrganizations', { autoRegister: 'false' });
  }

  getOrganizationByBoxId(boxId: string): Promise<any> {
    return this.json('GET', '/GetOrganization', { boxId });
  }

  getDocumentTypes(boxId: string): Promise<any> {
    return this.json('GET', '/V3/GetDocumentTypes', { boxId });
  }

  canPostMessage(prototype: unknown): Promise<any> {
    return this.json('POST', '/CanPostMessage', {}, prototype);
  }

  /** 204 + Retry-After means the same operationId is still being processed: repeat the identical request. */
  async postMessage(message: unknown, operationId: string, maxAttempts = 10): Promise<any> {
    const body = JSON.stringify(message);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const res = await this.send('POST', '/V3/PostMessage', { operationId }, body, 'application/json; charset=utf-8');
      if (res.status !== 204) return res.json();
      await this.sleep(retryAfterMs(res.headers.get('retry-after')));
    }
    throw new Error(`PostMessage operation ${operationId} still in progress after ${maxAttempts} attempts`);
  }

  getDocument(boxId: string, messageId: string, entityId: string): Promise<any> {
    return this.json('GET', '/V3/GetDocument', { boxId, messageId, entityId, injectEntityContent: 'false' });
  }

  async generateTitleXml(o: { boxId: string; function: string; version: string; userDataXml: Buffer }): Promise<{ content: Buffer; fileName?: string }> {
    const res = await this.fetchFn(
      this.url('/GenerateTitleXml', {
        boxId: o.boxId,
        documentTypeNamedId: 'UniversalTransferDocument',
        documentFunction: o.function,
        documentVersion: o.version,
        titleIndex: '0',
      }),
      {
        method: 'POST',
        headers: { authorization: `Bearer ${this.accessToken}`, 'content-type': 'application/xml; charset=utf-8' },
        body: new Uint8Array(o.userDataXml),
      },
    );
    if (!res.ok) throw new DiadocError('POST', '/GenerateTitleXml', res.status, await res.text());
    const fileName = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(res.headers.get('content-disposition') ?? '')?.[1];
    return { content: Buffer.from(await res.arrayBuffer()), fileName: fileName && decodeURIComponent(fileName) };
  }
}

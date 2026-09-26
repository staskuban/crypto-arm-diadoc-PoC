import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';

import { type AccessTokenProvider, RefreshTokenAuth, type TokenRequestOptions } from './auth.js';
import {
  DIADOC_HOSTS,
  DiadocClient,
  type DiadocClientOptions,
  findDocumentEntity,
  POST_MESSAGE_BUDGET_MS,
  POST_MIN_REQUEST_MS,
  POST_PENDING_FALLBACK_MS,
  SHELF_MAX_BYTES,
  SHELF_UPLOAD_MAX_BYTES,
  SHELF_UPLOAD_MAX_ROUNDS,
} from './client.js';
import {
  DiadocConflictError,
  DiadocError,
  DiadocOperationPendingError,
  DiadocPostOutcomeUnknownError,
} from './errors.js';
import type { Message, MessageToPost, SignedContent } from './types.js';

interface Call {
  url: URL;
  init: RequestInit;
  body: string;
}

const urlOf = (input: string | URL | Request): string =>
  typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

const bodyOf = (init?: RequestInit): string => (typeof init?.body === 'string' ? init.body : '');

function fakeFetch(responses: Response[]): { calls: Call[]; fetchFn: typeof fetch } {
  const calls: Call[] = [];
  const fetchFn = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: new URL(urlOf(input)), init: init ?? {}, body: bodyOf(init) });
    const res = responses.shift();
    return res ? Promise.resolve(res) : Promise.reject(new Error('unexpected request'));
  };
  return { calls, fetchFn };
}

const jsonResponse = (
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });

class FakeAuth implements AccessTokenProvider {
  tokens: string[];
  constructor(...tokens: string[]) {
    this.tokens = tokens;
  }
  requests: (TokenRequestOptions | undefined)[] = [];
  getAccessToken(o?: TokenRequestOptions): Promise<string> {
    this.requests.push(o);
    return Promise.resolve(this.tokens[0] ?? 'none');
  }
  invalidated: string[] = [];
  invalidate(token: string): void {
    this.invalidated.push(token);
    if (this.tokens[0] === token) this.tokens.shift();
  }
}

function makeClient(
  responses: Response[],
  overrides: Partial<DiadocClientOptions> = {},
): { client: DiadocClient; calls: Call[]; slept: number[]; auth: FakeAuth } {
  const { calls, fetchFn } = fakeFetch(responses);
  const slept: number[] = [];
  const auth = new FakeAuth('AT');
  const client = new DiadocClient({
    environment: 'staging',
    auth,
    fetch: fetchFn,
    sleep: (ms) => {
      slept.push(ms);
      return Promise.resolve();
    },
    ...overrides,
  });
  return { client, calls, slept, auth };
}

const headerOf = (call: Call | undefined, name: string): string | null =>
  new Headers(call?.init.headers).get(name);

describe('DiadocClient hosts', () => {
  it('knows prod and staging hosts', () => {
    expect(DIADOC_HOSTS).toEqual({
      prod: 'https://diadoc-api.kontur.ru',
      staging: 'https://diadoc-api-staging.kontur.ru',
    });
  });

  it.each([
    ['prod', 'diadoc-api.kontur.ru'],
    ['staging', 'diadoc-api-staging.kontur.ru'],
  ] as const)('%s environment → %s', async (environment, host) => {
    const { client, calls } = makeClient([jsonResponse({ Organizations: [] })], { environment });
    await client.getMyOrganizations();
    expect(calls[0]?.url.host).toBe(host);
  });

  it.each(['https://api.test/?x=1', 'https://api.test/#frag'])(
    'rejects a baseUrl with a query or fragment (%s)',
    (baseUrl) => {
      expect(() => makeClient([], { baseUrl })).toThrow(/query or fragment/);
    },
  );

  it('accepts an explicit baseUrl (trailing slash tolerated)', async () => {
    const { client, calls } = makeClient([jsonResponse({ Organizations: [] })], {
      baseUrl: 'http://localhost:8080/diadoc/',
    });
    await client.getMyOrganizations();
    expect(calls[0]?.url.href).toBe(
      'http://localhost:8080/diadoc/GetMyOrganizations?autoRegister=false',
    );
  });
});

describe('DiadocClient requests', () => {
  it('GetMyOrganizations: GET, Bearer token, JSON accept, autoRegister=false', async () => {
    const orgs = { Organizations: [{ Inn: '7700000016', Boxes: [{ BoxId: 'x@diadoc.ru' }] }] };
    const { client, calls } = makeClient([jsonResponse(orgs)]);

    expect(await client.getMyOrganizations()).toEqual(orgs);

    expect(calls[0]?.init.method).toBe('GET');
    expect(calls[0]?.url.href).toBe(
      'https://diadoc-api-staging.kontur.ru/GetMyOrganizations?autoRegister=false',
    );
    expect(headerOf(calls[0], 'authorization')).toBe('Bearer AT');
    expect(headerOf(calls[0], 'accept')).toMatch(/application\/json/);
  });

  it('GetOrganization by boxId', async () => {
    const { client, calls } = makeClient([jsonResponse({ Inn: '1', FnsParticipantId: '2BM-1' })]);
    expect(await client.getOrganization('box-guid')).toMatchObject({ FnsParticipantId: '2BM-1' });
    expect(calls[0]?.url.pathname).toBe('/GetOrganization');
    expect(calls[0]?.url.searchParams.get('boxId')).toBe('box-guid');
  });

  it('GetOrganization honours the abort signal', async () => {
    const { client, calls } = makeClient([jsonResponse({ IsTest: true })]);
    const controller = new AbortController();
    controller.abort(new Error('stop'));
    await expect(client.getOrganization('box-guid', { signal: controller.signal })).rejects.toThrow(
      'stop',
    );
    expect(calls).toHaveLength(0);
  });

  it('V4/GetEntityContent returns the raw bytes', async () => {
    const bytes = Buffer.from([0xcf, 0xf0, 0xe8, 0x00, 0xff]);
    const { client, calls } = makeClient([new Response(bytes, { status: 200 })]);
    const content = await client.getEntityContent({
      boxId: 'box',
      messageId: 'msg',
      entityId: 'ent',
    });
    expect(content.equals(bytes)).toBe(true);
    expect(calls[0]?.init.method).toBe('GET');
    expect(calls[0]?.url.pathname).toBe('/V4/GetEntityContent');
    expect(Object.fromEntries(calls[0]?.url.searchParams ?? [])).toEqual({
      boxId: 'box',
      messageId: 'msg',
      entityId: 'ent',
    });
  });

  it('V4/GetEntityContent: a 404 is a DiadocError', async () => {
    const { client } = makeClient([new Response('Entity not found', { status: 404 })]);
    await expect(
      client.getEntityContent({ boxId: 'b', messageId: 'm', entityId: 'e' }),
    ).rejects.toMatchObject({ status: 404 });
  });

  it('V3/GetDocumentTypes by boxId', async () => {
    const types = { DocumentTypes: [{ Name: 'UniversalTransferDocument', Functions: [] }] };
    const { client, calls } = makeClient([jsonResponse(types)]);
    expect(await client.getDocumentTypes('box-guid')).toEqual(types);
    expect(calls[0]?.url.pathname).toBe('/V3/GetDocumentTypes');
    expect(calls[0]?.url.searchParams.get('boxId')).toBe('box-guid');
  });

  it('CanPostMessage posts the prototype as UTF-8 JSON', async () => {
    const prototype = {
      FromBoxId: 'a',
      ToBoxId: 'b',
      DocumentPrototypes: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФДОП',
          Version: 'utd970_05_03_01',
          CustomDocumentId: 'doc-1',
        },
      ],
    };
    const { client, calls } = makeClient([jsonResponse({ Errors: [] })]);

    expect(await client.canPostMessage(prototype)).toEqual({ Errors: [] });

    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.url.pathname).toBe('/CanPostMessage');
    expect(headerOf(calls[0], 'content-type')).toBe('application/json; charset=utf-8');
    expect(JSON.parse(calls[0]?.body ?? '')).toEqual(prototype);
  });

  it('V5/GetMessage without entity content (D203)', async () => {
    const message = { MessageId: 'm', Entities: [{ EntityType: 'Attachment', EntityId: 'e' }] };
    const { client, calls } = makeClient([jsonResponse(message)]);
    const deadline = Date.now() + 60_000;

    expect(await client.getMessage('box', 'm', { deadline })).toEqual(message);
    expect(calls[0]?.init.method).toBe('GET');
    expect(calls[0]?.url.pathname).toBe('/V5/GetMessage');
    expect(Object.fromEntries(calls[0]?.url.searchParams ?? [])).toEqual({
      boxId: 'box',
      messageId: 'm',
      injectEntityContent: 'false',
    });
  });

  it('GetSignatureInfo for a signature entity (D203)', async () => {
    const info = { SignatureVerificationResult: { IsValid: true }, Thumbprint: 'AB' };
    const { client, calls } = makeClient([jsonResponse(info)]);

    expect(await client.getSignatureInfo({ boxId: 'box', messageId: 'm', entityId: 's' })).toEqual(
      info,
    );
    expect(calls[0]?.init.method).toBe('GET');
    expect(calls[0]?.url.pathname).toBe('/GetSignatureInfo');
    expect(Object.fromEntries(calls[0]?.url.searchParams ?? [])).toEqual({
      boxId: 'box',
      messageId: 'm',
      entityId: 's',
    });
  });

  it('V3/GetDocument without entity content; getDocflowStatus extracts DocflowStatus', async () => {
    const docflowStatus = { PrimaryStatus: { Severity: 'Success', StatusText: 'Подписан' } };
    const { client, calls } = makeClient([
      jsonResponse({ MessageId: 'm', EntityId: 'e', DocflowStatus: docflowStatus }),
      jsonResponse({ MessageId: 'm', EntityId: 'e', DocflowStatus: docflowStatus }),
    ]);
    const ids = { boxId: 'box', messageId: 'm', entityId: 'e' };

    expect(await client.getDocument(ids)).toMatchObject({ DocflowStatus: docflowStatus });
    expect(await client.getDocflowStatus(ids)).toEqual(docflowStatus);

    expect(calls[0]?.url.pathname).toBe('/V3/GetDocument');
    expect(Object.fromEntries(calls[0]?.url.searchParams ?? [])).toEqual({
      boxId: 'box',
      messageId: 'm',
      entityId: 'e',
      injectEntityContent: 'false',
    });
  });

  it('getDocflowStatus fails when the document has no DocflowStatus', async () => {
    const { client } = makeClient([jsonResponse({ MessageId: 'm' })]);
    await expect(
      client.getDocflowStatus({ boxId: 'b', messageId: 'm', entityId: 'e' }),
    ).rejects.toThrow(/DocflowStatus/);
  });
});

describe('DiadocClient.postMessage', () => {
  const content = Buffer.from([0x3c, 0x3f, 0xc0, 0xff, 0x00]); // windows-1251 bytes stay bytes
  const signature = Buffer.from([0x30, 0x82, 0x01, 0x02]);
  const message: MessageToPost = {
    FromBoxId: 'from',
    ToBoxId: 'to',
    DocumentAttachments: [
      {
        TypeNamedId: 'UniversalTransferDocument',
        Function: 'СЧФДОП',
        Version: 'utd970_05_03_01',
        CustomDocumentId: 'doc-1',
        SignedContent: { Content: content, Signature: signature },
      },
    ],
  };
  const posted: Message = {
    MessageId: 'msg',
    Entities: [
      { EntityType: 'Attachment', EntityId: 'sig', ParentEntityId: 'doc' },
      { EntityType: 'Attachment', EntityId: 'doc', ParentEntityId: '' },
    ],
  };

  it('sends operationId and serializes Buffers as base64', async () => {
    const { client, calls } = makeClient([jsonResponse(posted)]);

    expect(await client.postMessage(message, { operationId: 'op-1' })).toEqual(posted);

    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.url.pathname).toBe('/V3/PostMessage');
    expect(calls[0]?.url.searchParams.get('operationId')).toBe('op-1');
    expect(headerOf(calls[0], 'content-type')).toBe('application/json; charset=utf-8');
    expect(JSON.parse(calls[0]?.body ?? '')).toEqual({
      FromBoxId: 'from',
      ToBoxId: 'to',
      DocumentAttachments: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФДОП',
          Version: 'utd970_05_03_01',
          CustomDocumentId: 'doc-1',
          SignedContent: {
            Content: content.toString('base64'),
            Signature: signature.toString('base64'),
          },
        },
      ],
    });
  });

  it('serializes NameOnShelf and SignWithTestSignature without binary fields', async () => {
    const { client, calls } = makeClient([jsonResponse(posted)]);
    const attachment = message.DocumentAttachments[0];
    if (!attachment) throw new Error('fixture');
    await client.postMessage(
      {
        ...message,
        DocumentAttachments: [
          { ...attachment, SignedContent: { NameOnShelf: 'shelf-1', SignWithTestSignature: true } },
        ],
      },
      { operationId: 'op' },
    );
    const body = JSON.parse(calls[0]?.body ?? '') as MessageToPostWire;
    expect(body.DocumentAttachments[0]?.SignedContent).toEqual({
      NameOnShelf: 'shelf-1',
      SignWithTestSignature: true,
    });
  });

  it('SignedContent requires a body and a signature at the type level', () => {
    expectTypeOf({ Content: content, Signature: signature }).toExtend<SignedContent>();
    expectTypeOf({
      NameOnShelf: 's',
      SignWithTestSignature: true as const,
    }).toExtend<SignedContent>();
    expectTypeOf({ Content: content }).not.toExtend<SignedContent>();
    expectTypeOf({ Signature: signature }).not.toExtend<SignedContent>();
    expectTypeOf({
      Content: content,
      NameOnShelf: 's',
      Signature: signature,
    }).not.toExtend<SignedContent>();
  });

  it('repeats the identical request on 204 + Retry-After', async () => {
    const { client, calls, slept } = makeClient([
      new Response(null, { status: 204, headers: { 'retry-after': '2' } }),
      new Response(null, { status: 204 }),
      jsonResponse(posted),
    ]);

    expect(await client.postMessage(message, { operationId: 'op-1' })).toEqual(posted);

    expect(calls).toHaveLength(3);
    // Without Retry-After a 1 s pause would spend the attempts in seconds (R2 M2).
    expect(POST_PENDING_FALLBACK_MS).toBeGreaterThanOrEqual(5000);
    expect(slept).toEqual([2000, POST_PENDING_FALLBACK_MS]);
    expect(new Set(calls.map((c) => c.url.href)).size).toBe(1);
    expect(new Set(calls.map((c) => c.body)).size).toBe(1);
  });

  it('gives up with DiadocOperationPendingError after maxAttempts', async () => {
    const { client, calls } = makeClient([
      new Response(null, { status: 204 }),
      new Response(null, { status: 204 }),
    ]);
    const err = await client
      .postMessage(message, { operationId: 'op-1', maxAttempts: 2 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocOperationPendingError);
    expect(err).toMatchObject({ operationId: 'op-1' });
    expect(calls).toHaveLength(2);
  });

  it('stops the 204 loop when the next pause would end at or past the time budget', async () => {
    const clock = { t: 0 };
    const pending = (): Response =>
      new Response(null, { status: 204, headers: { 'retry-after': '60' } });
    const { client, calls, slept } = makeClient([pending(), pending(), pending(), pending()], {
      now: () => clock.t,
      sleep: (ms) => {
        slept.push(ms);
        clock.t += ms;
        return Promise.resolve();
      },
    });
    const err = await client
      .postMessage(message, { operationId: 'op-1', budgetMs: 180_000 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocOperationPendingError);
    expect((err as Error).message).toMatch(/op-1.*3 attempts.*180 s/);
    expect(calls).toHaveLength(3);
    expect(clock.t).toBe(120_000);
  });

  it('does not start a retry that would have less than the minimum time left', async () => {
    const clock = { t: 0 };
    const sleep = (ms: number): Promise<void> => {
      clock.t += ms;
      return Promise.resolve();
    };
    expect(POST_MIN_REQUEST_MS).toBe(5000);
    // 503 without Retry-After: pauses 1 s, 2 s; the 4 s one would end past 10 s - 5 s.
    const unavailable = makeClient(
      [0, 1, 2, 3].map(() => new Response('unavailable', { status: 503 })),
      { now: () => clock.t, sleep },
    );
    const err = await unavailable.client
      .postMessage(message, { operationId: 'op', budgetMs: 10_000 })
      .catch((e: unknown) => e);
    expect(unavailable.calls).toHaveLength(3);
    expect(err).toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect((err as Error).cause).toMatchObject({ status: 503 });

    // Only 429s: the honest result is the last 429, not a budget error.
    clock.t = 0;
    const tooMany = makeClient(
      [0, 1, 2].map(() => new Response('slow', { status: 429, headers: { 'retry-after': '3' } })),
      { now: () => clock.t, sleep },
    );
    const err429 = await tooMany.client
      .postMessage(message, { operationId: 'op', budgetMs: 10_000 })
      .catch((e: unknown) => e);
    expect(tooMany.calls).toHaveLength(2);
    expect(err429).not.toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect(err429).toMatchObject({ status: 429 });
  });

  it('has a default time budget of a few minutes', () => {
    expect(POST_MESSAGE_BUDGET_MS).toBeGreaterThanOrEqual(60_000);
    expect(POST_MESSAGE_BUDGET_MS).toBeLessThanOrEqual(300_000);
  });

  it('cuts a hanging request at the end of the time budget: the outcome is unknown', async () => {
    const hanging = (_input: string | URL | Request, init?: RequestInit): Promise<Response> =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(init.signal?.reason as Error);
        });
      });
    const client = new DiadocClient({
      environment: 'staging',
      auth: new FakeAuth('AT'),
      fetch: hanging,
      timeoutMs: 60_000,
    });
    const started = Date.now();
    const err = await client
      .postMessage(message, { operationId: 'op-1', budgetMs: 50 })
      .catch((e: unknown) => e);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(err).toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect((err as Error).cause).toMatchObject({ name: 'TimeoutError' });
  });

  it('passes the budget deadline (and no signal) to the token provider', async () => {
    const { client, auth } = makeClient([jsonResponse(posted)], { now: () => 1000 });
    await client.postMessage(message, { operationId: 'op-1', budgetMs: 30_000 });
    expect(auth.requests).toEqual([{ deadline: 31_000 }]);
  });

  it.each([0, -1, Number.NaN])('rejects budgetMs=%s without sending', async (budgetMs) => {
    const { client, calls } = makeClient([]);
    await expect(client.postMessage(message, { operationId: 'op', budgetMs })).rejects.toThrow(
      /budgetMs/,
    );
    expect(calls).toHaveLength(0);
  });

  it('maps 409 to DiadocConflictError with the response text', async () => {
    const { client } = makeClient([
      new Response('Message with the same operationId already exists', { status: 409 }),
    ]);
    const err = await client.postMessage(message, { operationId: 'op-1' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocConflictError);
    expect(err).toBeInstanceOf(DiadocError);
    expect(err).toMatchObject({
      status: 409,
      body: 'Message with the same operationId already exists',
    });
  });

  it('rejects an empty operationId', async () => {
    const { client, calls } = makeClient([]);
    await expect(client.postMessage(message, { operationId: '' })).rejects.toThrow(/operationId/);
    expect(calls).toHaveLength(0);
  });

  it.each([0, -1, 1.5, Number.NaN])(
    'rejects maxAttempts=%s without sending',
    async (maxAttempts) => {
      const { client, calls } = makeClient([]);
      await expect(client.postMessage(message, { operationId: 'op', maxAttempts })).rejects.toThrow(
        /maxAttempts/,
      );
      expect(calls).toHaveLength(0);
    },
  );

  it('repeats the identical request after a 401', async () => {
    const { client, calls, auth } = makeClient([
      new Response('Invalid auth token', { status: 401 }),
      jsonResponse(posted),
    ]);
    auth.tokens = ['OLD', 'NEW'];
    await client.postMessage(message, { operationId: 'op-1' });
    expect(calls).toHaveLength(2);
    expect(calls[1]?.url.href).toBe(calls[0]?.url.href);
    expect(calls[1]?.body).toBe(calls[0]?.body);
  });

  it('maps 204 followed by 409 to DiadocConflictError', async () => {
    const { client } = makeClient([
      new Response(null, { status: 204 }),
      new Response('duplicate', { status: 409 }),
    ]);
    await expect(client.postMessage(message, { operationId: 'op-1' })).rejects.toBeInstanceOf(
      DiadocConflictError,
    );
  });

  it('findDocumentEntity picks the parentless Attachment', () => {
    expect(findDocumentEntity(posted)?.EntityId).toBe('doc');
    expect(findDocumentEntity({ MessageId: 'm' })).toBeUndefined();
  });
});

describe('DiadocClient errors and auth', () => {
  it('throws DiadocError with status, method, path and text body', async () => {
    const { client } = makeClient([new Response('Box not found', { status: 403 })]);
    const err = await client.getDocumentTypes('box').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocError);
    expect(err).toMatchObject({
      status: 403,
      method: 'GET',
      path: '/V3/GetDocumentTypes',
      body: 'Box not found',
    });
  });

  it('on 401 invalidates the token and retries once with a fresh one', async () => {
    const { client, calls, auth } = makeClient([
      new Response('Invalid auth token', { status: 401 }),
      jsonResponse({ Organizations: [] }),
    ]);
    auth.tokens = ['OLD', 'NEW'];

    await client.getMyOrganizations();

    expect(auth.invalidated).toEqual(['OLD']);
    expect(calls.map((c) => headerOf(c, 'authorization'))).toEqual(['Bearer OLD', 'Bearer NEW']);
  });

  it('passes a timeout signal to fetch', async () => {
    const { client, calls } = makeClient([jsonResponse({ Organizations: [] })]);
    await client.getMyOrganizations();
    expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
  });

  it('turns a non-JSON success body into DiadocError', async () => {
    const { client } = makeClient([new Response('<html>proxy</html>', { status: 200 })]);
    const err = await client.getMyOrganizations().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocError);
    expect(err).toMatchObject({ status: 200, path: '/GetMyOrganizations' });
  });

  it('with RefreshTokenAuth, concurrent 401s cause a single token refresh', async () => {
    const token = (t: string): Response =>
      jsonResponse({ access_token: t, expires_in: 3600, refresh_token: 'RT' });
    const unauthorized = (): Response => new Response('Invalid auth token', { status: 401 });
    const ok = (): Response => jsonResponse({ Organizations: [] });
    // order of fetch calls: token, 2 API (401), 1 token refresh, 2 API retries (ok)
    const { calls, fetchFn } = fakeFetch([
      token('T1'),
      unauthorized(),
      unauthorized(),
      token('T2'),
      ok(),
      ok(),
    ]);
    const auth = new RefreshTokenAuth({
      clientId: 'c',
      clientSecret: 's',
      refreshToken: 'RT',
      fetch: fetchFn,
    });
    const client = new DiadocClient({ environment: 'staging', auth, fetch: fetchFn });

    await Promise.all([client.getMyOrganizations(), client.getMyOrganizations()]);

    const tokenCalls = calls.filter((c) => c.url.host === 'identity.kontur.ru');
    expect(tokenCalls).toHaveLength(2);
    expect(calls.slice(-2).map((c) => headerOf(c, 'authorization'))).toEqual([
      'Bearer T2',
      'Bearer T2',
    ]);
  });

  it('does not retry a second 401', async () => {
    const { client, calls } = makeClient([
      new Response('Invalid auth token', { status: 401 }),
      new Response('Invalid auth token', { status: 401 }),
    ]);
    await expect(client.getMyOrganizations()).rejects.toMatchObject({ status: 401 });
    expect(calls).toHaveLength(2);
  });
});

interface MessageToPostWire {
  DocumentAttachments: { SignedContent: Record<string, unknown> }[];
}

describe('DiadocClient.shelfUpload', () => {
  const textResponse = (body: string, status = 200): Response =>
    new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });

  it('POSTs raw bytes to V2/ShelfUpload and returns the generated name (plain text)', async () => {
    const { client, calls } = makeClient([textResponse('dd-api-6831e2e9')]);
    const content = Buffer.from([0xcf, 0xf0, 0xe8, 0x00]);

    expect(await client.shelfUpload(content, { fileExtension: '.xml' })).toBe('dd-api-6831e2e9');

    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.url.pathname).toBe('/V2/ShelfUpload');
    expect(calls[0]?.url.searchParams.get('fileExtension')).toBe('.xml');
    expect(headerOf(calls[0], 'content-type')).toBe('application/octet-stream');
    expect(Buffer.from(calls[0]?.init.body as Uint8Array)).toEqual(content);
  });

  it('accepts the name as a JSON string and omits fileExtension when not given', async () => {
    const { client, calls } = makeClient([jsonResponse('dd-api-1')]);
    expect(await client.shelfUpload(Buffer.from('x'))).toBe('dd-api-1');
    expect(calls[0]?.url.search).toBe('');
  });

  it('sends content above the single-request limit in parts of that size', async () => {
    const { client, calls } = makeClient([textResponse('dd-api-big'), jsonResponse([])]);
    const content = Buffer.alloc(SHELF_UPLOAD_MAX_BYTES + 1, 0x41);
    content[SHELF_UPLOAD_MAX_BYTES] = 0x42;

    expect(await client.shelfUpload(content, { fileExtension: '.xml' })).toBe('dd-api-big');

    expect(calls.map((c) => c.url.pathname)).toEqual(['/ShelfUploadPartInit', '/ShelfUploadPart']);
    expect(Buffer.from(calls[0]?.init.body as Uint8Array).length).toBe(SHELF_UPLOAD_MAX_BYTES);
    expect(Buffer.from(calls[1]?.init.body as Uint8Array)).toEqual(Buffer.from('B'));
  });

  it('rejects content above the documented shelf maximum without a request', async () => {
    const { client, calls } = makeClient([]);
    await expect(client.shelfUpload(Buffer.alloc(SHELF_MAX_BYTES + 1))).rejects.toThrow(
      /400000000/,
    );
    expect(calls).toHaveLength(0);
  });

  it('passes the abort signal to a single-request upload', async () => {
    const controller = new AbortController();
    controller.abort(new Error('stop'));
    const { client, calls } = makeClient([textResponse('dd-api-1')]);
    await expect(
      client.shelfUpload(Buffer.from('x'), { signal: controller.signal }),
    ).rejects.toThrow('stop');
    expect(calls).toHaveLength(0);
  });

  it('rejects empty content and an empty returned name', async () => {
    const { client } = makeClient([textResponse('  ')]);
    await expect(client.shelfUpload(Buffer.alloc(0))).rejects.toThrow(/empty/);
    await expect(client.shelfUpload(Buffer.from('x'))).rejects.toBeInstanceOf(DiadocError);
  });

  it('maps a non-2xx answer to DiadocError', async () => {
    const { client } = makeClient([textResponse('bad', 400)]);
    await expect(client.shelfUpload(Buffer.from('x'))).rejects.toMatchObject({
      status: 400,
      path: '/V2/ShelfUpload',
    });
  });

  it('resends the same bytes after a 401', async () => {
    const auth = new FakeAuth('OLD', 'NEW');
    const { client, calls } = makeClient([textResponse('', 401), textResponse('dd-api-2')], {
      auth,
    });
    expect(await client.shelfUpload(Buffer.from('abc'))).toBe('dd-api-2');
    expect(headerOf(calls[1], 'authorization')).toBe('Bearer NEW');
    expect(Buffer.from(calls[1]?.init.body as Uint8Array).toString()).toBe('abc');
  });
});

describe('DiadocClient.shelfUploadParts', () => {
  const text = (body: string, status = 200, headers: Record<string, string> = {}): Response =>
    new Response(body, { status, headers: { 'content-type': 'text/plain', ...headers } });
  const bodyText = (call: Call | undefined): string =>
    Buffer.from(call?.init.body as Uint8Array).toString();
  const query = (call: Call | undefined): Record<string, string> =>
    Object.fromEntries(call?.url.searchParams ?? []);
  const content = Buffer.from('0123456789');

  it('uploads the first part with ShelfUploadPartInit and the rest with ShelfUploadPart', async () => {
    const { client, calls } = makeClient([text('dd-api-p'), text('[]'), jsonResponse([])]);

    expect(await client.shelfUploadParts(content, { fileExtension: '.xml', partSize: 4 })).toBe(
      'dd-api-p',
    );

    expect(calls.map((c) => [c.init.method, c.url.pathname, query(c), bodyText(c)])).toEqual([
      ['POST', '/ShelfUploadPartInit', { fileExtension: '.xml', isLastPart: 'false' }, '0123'],
      [
        'POST',
        '/ShelfUploadPart',
        { fileName: 'dd-api-p', partIndex: '1', isLastPart: 'false' },
        '4567',
      ],
      [
        'POST',
        '/ShelfUploadPart',
        { fileName: 'dd-api-p', partIndex: '2', isLastPart: 'true' },
        '89',
      ],
    ]);
    for (const call of calls) {
      expect(headerOf(call, 'content-type')).toBe('application/octet-stream');
      expect(call.init.redirect).toBe('error');
    }
  });

  it('marks a single part as the last one and accepts the name as a JSON string', async () => {
    const { client, calls } = makeClient([jsonResponse('dd-api-1')]);
    expect(await client.shelfUploadParts(Buffer.from('abc'), { partSize: 4 })).toBe('dd-api-1');
    expect(calls.map((c) => [c.url.pathname, query(c)])).toEqual([
      ['/ShelfUploadPartInit', { isLastPart: 'true' }],
    ]);
  });

  it('re-sends the parts the last response lists as missing, the last of them with isLastPart', async () => {
    const { client, calls } = makeClient([
      text('dd-api-p'),
      text(''),
      text('[0, 2]'),
      text(''),
      text('[]'),
    ]);

    expect(await client.shelfUploadParts(content, { partSize: 4 })).toBe('dd-api-p');

    expect(calls.slice(3).map((c) => [query(c), bodyText(c)])).toEqual([
      [{ fileName: 'dd-api-p', partIndex: '0', isLastPart: 'false' }, '0123'],
      [{ fileName: 'dd-api-p', partIndex: '2', isLastPart: 'true' }, '89'],
    ]);
  });

  it('treats an empty last response as nothing missing, like the official SDK', async () => {
    const { client } = makeClient([text('dd-api-p'), text(''), text('')]);
    expect(await client.shelfUploadParts(content, { partSize: 4 })).toBe('dd-api-p');
  });

  it(`gives up after ${String(SHELF_UPLOAD_MAX_ROUNDS)} rounds with parts still missing`, async () => {
    const responses = [text('dd-api-p'), text(''), text('[1]')];
    for (let i = 1; i < SHELF_UPLOAD_MAX_ROUNDS; i++) responses.push(text('[1]'));
    const { client, calls } = makeClient(responses);

    const error: unknown = await client
      .shelfUploadParts(content, { partSize: 4 })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(DiadocError);
    expect(error).toMatchObject({ path: '/ShelfUploadPart' });
    expect((error as Error).message).toMatch(/dd-api-p.*missing.*1/s);
    expect(calls).toHaveLength(2 + SHELF_UPLOAD_MAX_ROUNDS);
  });

  it.each(['[3]', '[-1]', '[1.5]', '{"a":1}', 'oops', '["1"]'])(
    'rejects a malformed missing-parts answer %s',
    async (answer) => {
      const { client } = makeClient([text('dd-api-p'), text(''), text(answer)]);
      await expect(client.shelfUploadParts(content, { partSize: 4 })).rejects.toBeInstanceOf(
        DiadocError,
      );
    },
  );

  it('repeats a part with the same bytes and query after a transient failure', async () => {
    const { client, calls, slept } = makeClient([
      text('dd-api-p'),
      text('busy', 503, { 'retry-after': '1' }),
      text(''),
      text('[]'),
    ]);
    expect(await client.shelfUploadParts(content, { partSize: 4 })).toBe('dd-api-p');
    expect(slept).toEqual([1000]);
    expect([calls[1], calls[2]].map((c) => [query(c), bodyText(c)])).toEqual([
      [{ fileName: 'dd-api-p', partIndex: '1', isLastPart: 'false' }, '4567'],
      [{ fileName: 'dd-api-p', partIndex: '1', isLastPart: 'false' }, '4567'],
    ]);
  });

  it('resends the same part with a fresh token after a 401 mid-upload', async () => {
    const auth = new FakeAuth('OLD', 'NEW');
    const { client, calls } = makeClient([text('dd-api-p'), text('', 401), text(''), text('[]')], {
      auth,
    });
    expect(await client.shelfUploadParts(content, { partSize: 4 })).toBe('dd-api-p');
    expect(
      [calls[1], calls[2]].map((c) => [headerOf(c, 'authorization'), query(c), bodyText(c)]),
    ).toEqual([
      ['Bearer OLD', { fileName: 'dd-api-p', partIndex: '1', isLastPart: 'false' }, '4567'],
      ['Bearer NEW', { fileName: 'dd-api-p', partIndex: '1', isLastPart: 'false' }, '4567'],
    ]);
  });

  it('stops at a non-transient error of a part', async () => {
    const { client, calls } = makeClient([text('dd-api-p'), text('bad part', 400)]);
    await expect(client.shelfUploadParts(content, { partSize: 4 })).rejects.toMatchObject({
      status: 400,
      path: '/ShelfUploadPart',
    });
    expect(calls).toHaveLength(2);
  });

  it('rejects a bad name from ShelfUploadPartInit', async () => {
    const { client, calls } = makeClient([text('two words')]);
    await expect(client.shelfUploadParts(content, { partSize: 4 })).rejects.toMatchObject({
      path: '/ShelfUploadPartInit',
    });
    expect(calls).toHaveLength(1);
  });

  it('stops between parts when the signal is aborted', async () => {
    const controller = new AbortController();
    const reason = new Error('stop');
    const { client, calls } = makeClient([], {
      fetch: () => {
        controller.abort(reason);
        return Promise.resolve(text('dd-api-p'));
      },
    });
    await expect(
      client.shelfUploadParts(content, { partSize: 4, signal: controller.signal }),
    ).rejects.toBe(reason);
    expect(calls).toHaveLength(0); // the custom fetch above does not record
  });

  it.each([0, -1, 1.5, SHELF_UPLOAD_MAX_BYTES + 1])('rejects partSize %s', async (partSize) => {
    const { client, calls } = makeClient([]);
    await expect(client.shelfUploadParts(content, { partSize })).rejects.toThrow(/partSize/);
    expect(calls).toHaveLength(0);
  });

  it('rejects empty content and content above the shelf maximum', async () => {
    const { client, calls } = makeClient([]);
    await expect(client.shelfUploadParts(Buffer.alloc(0))).rejects.toThrow(/empty/);
    await expect(client.shelfUploadParts(Buffer.alloc(SHELF_MAX_BYTES + 1))).rejects.toThrow(
      /400000000/,
    );
    expect(calls).toHaveLength(0);
  });
});

const fetchFailed = (cause: string): TypeError =>
  new TypeError('fetch failed', { cause: new Error(cause) });

describe('DiadocClient transient failures', () => {
  const message: MessageToPost = {
    FromBoxId: 'from',
    ToBoxId: 'to',
    DocumentAttachments: [
      {
        TypeNamedId: 'UniversalTransferDocument',
        Function: 'СЧФДОП',
        Version: 'utd970_05_03_01',
        SignedContent: { Content: Buffer.from('c'), Signature: Buffer.from([0x30, 0x00]) },
      },
    ],
  };
  const posted: Message = { MessageId: 'msg' };

  /** fetch that fails with the given errors first, then answers from `responses`. */
  function flaky(outcomes: (Response | Error)[]): { calls: Call[]; fetchFn: typeof fetch } {
    const calls: Call[] = [];
    const fetchFn = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      calls.push({ url: new URL(urlOf(input)), init: init ?? {}, body: bodyOf(init) });
      const next = outcomes.shift();
      if (next === undefined) return Promise.reject(new Error('unexpected request'));
      return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
    };
    return { calls, fetchFn };
  }

  it('sends every request with redirect: error', async () => {
    const { client, calls } = makeClient([
      jsonResponse({ Organizations: [] }),
      jsonResponse({ Errors: [] }),
      new Response('shelf-1'),
      jsonResponse(posted),
    ]);
    await client.getMyOrganizations();
    await client.canPostMessage({ FromBoxId: 'a', ToBoxId: 'b', DocumentPrototypes: [] });
    await client.shelfUpload(Buffer.from('x'));
    await client.postMessage(message, { operationId: 'op' });
    expect(calls.map((c) => c.init.redirect)).toEqual(['error', 'error', 'error', 'error']);
  });

  it.each([
    ['a 502', new Response('bad gateway', { status: 502 })],
    ['a 503', new Response('unavailable', { status: 503 })],
    ['a reset connection', fetchFailed('ECONNRESET')],
    ['a timeout', new DOMException('timed out', 'TimeoutError')],
  ])('repeats PostMessage with the identical request after %s', async (_name, first) => {
    const { calls, fetchFn } = flaky([first, jsonResponse(posted)]);
    const { client, slept } = makeClient([], { fetch: fetchFn });

    expect(await client.postMessage(message, { operationId: 'op-1' })).toEqual(posted);

    expect(calls).toHaveLength(2);
    expect(calls[1]?.url.href).toBe(calls[0]?.url.href);
    expect(calls[1]?.url.searchParams.get('operationId')).toBe('op-1');
    expect(calls[1]?.body).toBe(calls[0]?.body);
    expect(slept).toEqual([1000]);
  });

  it('honours Retry-After on a PostMessage 429', async () => {
    const { client, calls, slept } = makeClient([
      new Response('slow down', { status: 429, headers: { 'retry-after': '5' } }),
      jsonResponse(posted),
    ]);
    await client.postMessage(message, { operationId: 'op-1' });
    expect(slept).toEqual([5000]);
    expect(calls[1]?.body).toBe(calls[0]?.body);
  });

  it('after the retries says the message may have been posted, keeping the cause', async () => {
    const { client, calls } = makeClient(
      [0, 1, 2].map(() => new Response('bad gateway', { status: 502 })),
      { retry: { maxAttempts: 3 } },
    );
    const err = await client.postMessage(message, { operationId: 'op-1' }).catch((e: unknown) => e);
    expect(calls).toHaveLength(3);
    expect(err).toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect(err).toMatchObject({ operationId: 'op-1' });
    expect((err as Error).message).toMatch(/may have been posted/);
    expect((err as Error).cause).toMatchObject({ status: 502 });
  });

  it('a PostMessage 500 may have been processed too', async () => {
    const { client } = makeClient(
      [0, 1].map(() => new Response('internal error', { status: 500 })),
      { retry: { maxAttempts: 2 } },
    );
    const err = await client.postMessage(message, { operationId: 'op-1' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect((err as Error).cause).toMatchObject({ status: 500 });
  });

  it('refreshes the token at most once per call (401, 503, 401)', async () => {
    const { client, calls, auth } = makeClient([
      new Response('Invalid auth token', { status: 401 }),
      new Response('unavailable', { status: 503 }),
      new Response('Invalid auth token', { status: 401 }),
    ]);
    auth.tokens = ['OLD', 'NEW', 'NEWER'];
    await expect(client.getMyOrganizations()).rejects.toMatchObject({ status: 401 });
    expect(auth.invalidated).toEqual(['OLD']);
    expect(calls.map((c) => headerOf(c, 'authorization'))).toEqual([
      'Bearer OLD',
      'Bearer NEW',
      'Bearer NEW',
    ]);
  });

  it('a lost response followed by a plain rejection is still ambiguous', async () => {
    const { calls, fetchFn } = flaky([
      fetchFailed('ECONNRESET'),
      new Response('Invalid auth token', { status: 401 }),
      new Response('Invalid auth token', { status: 401 }),
    ]);
    const { client } = makeClient([], { fetch: fetchFn });
    const err = await client.postMessage(message, { operationId: 'op' }).catch((e: unknown) => e);
    expect(calls).toHaveLength(3);
    expect(err).toBeInstanceOf(DiadocPostOutcomeUnknownError);
  });

  it('a 2xx PostMessage answer that is not JSON may have been posted', async () => {
    const { client } = makeClient([new Response('<html>proxy</html>', { status: 200 })]);
    await expect(client.postMessage(message, { operationId: 'op' })).rejects.toBeInstanceOf(
      DiadocPostOutcomeUnknownError,
    );
  });

  it.each([
    ['a 400', [new Response('bad request', { status: 400 })]],
    ['only 429s', [0, 1, 2].map(() => new Response('slow', { status: 429 }))],
  ])('a PostMessage rejected with %s was not posted: plain DiadocError', async (_n, responses) => {
    const { client } = makeClient(responses, { retry: { maxAttempts: 3 } });
    const err = await client.postMessage(message, { operationId: 'op' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocError);
    expect(err).not.toBeInstanceOf(DiadocPostOutcomeUnknownError);
  });

  it('a PostMessage that never connected was not posted: no "may have been posted"', async () => {
    const refused = (): TypeError =>
      new TypeError('fetch failed', {
        cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), {
          code: 'ECONNREFUSED',
        }),
      });
    const { calls, fetchFn } = flaky([refused(), refused(), refused(), refused()]);
    const { client } = makeClient([], { fetch: fetchFn });
    const err = await client.postMessage(message, { operationId: 'op' }).catch((e: unknown) => e);
    expect(calls).toHaveLength(4);
    expect(err).not.toBeInstanceOf(DiadocPostOutcomeUnknownError);
    expect(err).toMatchObject({ message: 'fetch failed' });
  });

  it('a refused connection after a lost response is still ambiguous', async () => {
    const refused = new TypeError('fetch failed', {
      cause: Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }),
    });
    const { fetchFn } = flaky([fetchFailed('ECONNRESET'), refused, refused, refused]);
    const { client } = makeClient([], { fetch: fetchFn });
    await expect(client.postMessage(message, { operationId: 'op' })).rejects.toBeInstanceOf(
      DiadocPostOutcomeUnknownError,
    );
  });

  it('CanPostMessage passes the abort signal to fetch and to the token provider', async () => {
    const controller = new AbortController();
    const { client, calls, auth } = makeClient([jsonResponse({ Errors: [] })]);
    await client.canPostMessage(
      { FromBoxId: 'a', ToBoxId: 'b', DocumentPrototypes: [] },
      { signal: controller.signal },
    );
    expect(auth.requests).toEqual([{ signal: controller.signal }]);
    controller.abort(new Error('stop'));
    expect(calls[0]?.init.signal?.aborted).toBe(true);
  });

  it('getDocument passes its deadline and signal to the token provider', async () => {
    const controller = new AbortController();
    const { client, auth } = makeClient([jsonResponse({})]);
    await client.getDocument(
      { boxId: 'b', messageId: 'm', entityId: 'e' },
      { deadline: 5000, signal: controller.signal },
    );
    expect(auth.requests).toEqual([{ deadline: 5000, signal: controller.signal }]);
  });

  it('a 409 after a lost response stays a conflict', async () => {
    const { calls, fetchFn } = flaky([
      fetchFailed('ECONNRESET'),
      new Response('dup', { status: 409 }),
    ]);
    const { client } = makeClient([], { fetch: fetchFn });
    await expect(client.postMessage(message, { operationId: 'op' })).rejects.toBeInstanceOf(
      DiadocConflictError,
    );
    expect(calls).toHaveLength(2);
  });

  it('a refused redirect is not retried', async () => {
    const redirect = fetchFailed('unexpected redirect');
    const { calls, fetchFn } = flaky([redirect]);
    const { client } = makeClient([], { fetch: fetchFn });
    await expect(client.getMyOrganizations()).rejects.toBe(redirect);
    expect(calls).toHaveLength(1);
  });

  it('retries 429 with Retry-After on GET, CanPostMessage and ShelfUpload (same bytes)', async () => {
    const tooMany = (): Response =>
      new Response('slow down', { status: 429, headers: { 'retry-after': '2' } });
    const { client, calls, slept } = makeClient([
      tooMany(),
      jsonResponse({ Organizations: [] }),
      tooMany(),
      jsonResponse({ Errors: [] }),
      tooMany(),
      new Response('shelf-1'),
    ]);
    await client.getMyOrganizations();
    await client.canPostMessage({ FromBoxId: 'a', ToBoxId: 'b', DocumentPrototypes: [] });
    expect(await client.shelfUpload(Buffer.from('abc'))).toBe('shelf-1');
    expect(slept).toEqual([2000, 2000, 2000]);
    expect(Buffer.from(calls[5]?.init.body as Uint8Array).toString()).toBe('abc');
  });

  it('getDocument does not wait past the given deadline', async () => {
    const { client, calls, slept } = makeClient(
      [new Response('bad gateway', { status: 502 }), jsonResponse({})],
      { now: () => 0 },
    );
    const ref = { boxId: 'b', messageId: 'm', entityId: 'e' };
    await expect(client.getDocument(ref, { deadline: 500 })).rejects.toMatchObject({
      status: 502,
    });
    expect(calls).toHaveLength(1);
    expect(slept).toEqual([]);
  });

  it('getDocument aborts the request with the caller signal', async () => {
    const controller = new AbortController();
    const reason = new Error('shutdown');
    const fetchFn = (_input: string | URL | Request, init?: RequestInit): Promise<Response> =>
      new Promise((_resolve, reject) => {
        const signal = init?.signal;
        if (signal?.aborted) reject(signal.reason as Error);
        signal?.addEventListener('abort', () => {
          reject(signal.reason as Error);
        });
      });
    const { client } = makeClient([], { fetch: fetchFn });
    const pending = client.getDocument(
      { boxId: 'b', messageId: 'm', entityId: 'e' },
      { signal: controller.signal },
    );
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });
});

describe('redirects against a real HTTP server', () => {
  const servers: Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
    const server = createServer(handler);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  }

  it('neither the API nor the IdP request follows a 307 to another host', async () => {
    const received: string[] = [];
    const target = await listen((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => (body += chunk.toString()));
      req.on('end', () => {
        received.push(body);
        res.end('{}');
      });
    });
    let redirects = 0;
    const redirector = await listen((_req, res) => {
      redirects++;
      res.writeHead(307, { location: `${target.replace('127.0.0.1', 'localhost')}/steal` });
      res.end();
    });

    const auth = new RefreshTokenAuth({
      clientId: 'c',
      clientSecret: 'SECRET',
      refreshToken: 'RT',
      tokenUrl: `${redirector}/token`,
    });
    // Not retried: a refused redirect is permanent (one request each).
    await expect(auth.getAccessToken()).rejects.toMatchObject({
      name: 'TypeError',
      cause: { message: 'unexpected redirect' },
    });
    expect(redirects).toBe(1);

    const client = new DiadocClient({ auth: new FakeAuth('AT'), baseUrl: redirector });
    await expect(client.getMyOrganizations()).rejects.toMatchObject({
      name: 'TypeError',
      cause: { message: 'unexpected redirect' },
    });
    expect(redirects).toBe(2);

    expect(received).toEqual([]);
  });
});

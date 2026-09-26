import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DiadocClient, DiadocError } from '../src/client.ts';

type Call = { url: URL; init: RequestInit };

function fakeFetch(responses: Response[]) {
  const calls: Call[] = [];
  const fetchFn = async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: new URL(String(url)), init: init ?? {} });
    const r = responses.shift();
    if (!r) throw new Error('unexpected request');
    return r;
  };
  return { calls, fetchFn };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

const client = (fetchFn: typeof fetch) =>
  new DiadocClient({ baseUrl: 'https://diadoc-api-staging.kontur.ru', accessToken: 'AT', fetchFn, sleep: async () => {} });

test('GetMyOrganizations: GET with Bearer token and JSON accept', async () => {
  const { calls, fetchFn } = fakeFetch([json({ Organizations: [] })]);
  assert.deepEqual(await client(fetchFn).getMyOrganizations(), { Organizations: [] });
  assert.equal(calls[0].url.href, 'https://diadoc-api-staging.kontur.ru/GetMyOrganizations?autoRegister=false');
  const h = new Headers(calls[0].init.headers);
  assert.equal(h.get('authorization'), 'Bearer AT');
  assert.match(h.get('accept')!, /application\/json/);
});

test('GetDocumentTypes V3 passes boxId', async () => {
  const { calls, fetchFn } = fakeFetch([json({ DocumentTypes: [] })]);
  await client(fetchFn).getDocumentTypes('box-guid');
  assert.equal(calls[0].url.pathname, '/V3/GetDocumentTypes');
  assert.equal(calls[0].url.searchParams.get('boxId'), 'box-guid');
});

test('GetOrganization by boxId', async () => {
  const { calls, fetchFn } = fakeFetch([json({ Inn: '1' })]);
  await client(fetchFn).getOrganizationByBoxId('b');
  assert.equal(calls[0].url.pathname, '/GetOrganization');
  assert.equal(calls[0].url.searchParams.get('boxId'), 'b');
});

test('CanPostMessage posts the prototype as JSON', async () => {
  const { calls, fetchFn } = fakeFetch([json({ Errors: [] })]);
  const proto = { FromBoxId: 'a', ToBoxId: 'b', DocumentPrototypes: [{ TypeNamedId: 'UniversalTransferDocument', Function: 'СЧФДОП', Version: 'v' }] };
  await client(fetchFn).canPostMessage(proto);
  assert.equal(calls[0].url.pathname, '/CanPostMessage');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(new Headers(calls[0].init.headers).get('content-type'), 'application/json; charset=utf-8');
  assert.deepEqual(JSON.parse(String(calls[0].init.body)), proto);
});

test('PostMessage V3 sends operationId and repeats on 204 + Retry-After', async () => {
  const slept: number[] = [];
  const { calls, fetchFn } = fakeFetch([
    new Response(null, { status: 204, headers: { 'retry-after': '2' } }),
    json({ MessageId: 'm', Entities: [] }),
  ]);
  const c = new DiadocClient({ baseUrl: 'https://h', accessToken: 'AT', fetchFn, sleep: async (ms) => void slept.push(ms) });
  const msg = { FromBoxId: 'a', ToBoxId: 'b', DocumentAttachments: [] };
  assert.deepEqual(await c.postMessage(msg, 'op-1'), { MessageId: 'm', Entities: [] });
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.url.pathname, '/V3/PostMessage');
    assert.equal(call.url.searchParams.get('operationId'), 'op-1');
    assert.equal(String(call.init.body), JSON.stringify(msg));
  }
  assert.deepEqual(slept, [2000]);
});

test('GetDocument V3 passes ids and disables content injection', async () => {
  const { calls, fetchFn } = fakeFetch([json({ DocflowStatus: { PrimaryStatus: { Severity: 'Info' } } })]);
  await client(fetchFn).getDocument('b', 'm', 'e');
  assert.equal(calls[0].url.pathname, '/V3/GetDocument');
  assert.deepEqual(Object.fromEntries(calls[0].url.searchParams), { boxId: 'b', messageId: 'm', entityId: 'e', injectEntityContent: 'false' });
});

test('GenerateTitleXml returns raw bytes and the file name from Content-Disposition', async () => {
  const bytes = Buffer.from([0x3c, 0xc0]);
  const { calls, fetchFn } = fakeFetch([
    new Response(bytes, { status: 200, headers: { 'content-disposition': "attachment; filename=\"ON_NSCHFDOPPR_x.xml\"" } }),
  ]);
  const r = await client(fetchFn).generateTitleXml({ boxId: 'b', function: 'СЧФДОП', version: 'utd970_05_03_01', userDataXml: Buffer.from('<x/>') });
  assert.deepEqual(r.content, bytes);
  assert.equal(r.fileName, 'ON_NSCHFDOPPR_x.xml');
  const u = calls[0].url;
  assert.equal(u.pathname, '/GenerateTitleXml');
  assert.deepEqual(Object.fromEntries(u.searchParams), {
    boxId: 'b', documentTypeNamedId: 'UniversalTransferDocument', documentFunction: 'СЧФДОП', documentVersion: 'utd970_05_03_01', titleIndex: '0',
  });
  assert.equal(new Headers(calls[0].init.headers).get('content-type'), 'application/xml; charset=utf-8');
});

test('non-2xx becomes DiadocError with status, method, path and body text', async () => {
  const { fetchFn } = fakeFetch([new Response('Box not found', { status: 403, headers: { 'X-Kontur-Request-Id': 'rid' } })]);
  await assert.rejects(client(fetchFn).getDocumentTypes('b'), (e: unknown) => {
    assert.ok(e instanceof DiadocError);
    assert.equal(e.status, 403);
    assert.match(e.message, /GET \/V3\/GetDocumentTypes -> 403: Box not found/);
    return true;
  });
});

test('PostMessage gives up after too many 204 responses', async () => {
  const many = Array.from({ length: 10 }, () => new Response(null, { status: 204, headers: { 'retry-after': '1' } }));
  const { fetchFn } = fakeFetch(many);
  await assert.rejects(client(fetchFn).postMessage({ FromBoxId: 'a', DocumentAttachments: [] }, 'op', 3), /still in progress/);
});

test('retryAfterMs handles seconds, HTTP-date, garbage and caps the wait', async () => {
  const { retryAfterMs } = await import('../src/client.ts');
  const now = Date.parse('2026-09-24T10:00:00Z');
  assert.equal(retryAfterMs('3', now), 3000);
  assert.equal(retryAfterMs('Thu, 24 Sep 2026 10:00:05 GMT', now), 5000);
  assert.equal(retryAfterMs(null, now), 1000);
  assert.equal(retryAfterMs('', now), 1000);
  assert.equal(retryAfterMs('soon', now), 1000);
  assert.equal(retryAfterMs('-5', now), 1000);
  assert.equal(retryAfterMs('100000', now), 60_000);
});

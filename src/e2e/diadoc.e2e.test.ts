// Live e2e against Контур.Диадок (T6, D202 option a). Opt-in: DIADOC_E2E=1, skipped otherwise.
// Every PostMessage creates a real document in the test boxes, so each case is its own `it` (pick
// with -t) and the HTTP trace refuses PostMessage calls beyond DIADOC_E2E_MAX_POSTS (default 10).
//
// Env: the Диадок settings as for the CLI (DIADOC_E2E_ENV_FILE=<.env> is read like
// `node --env-file`, the process env wins), DIADOC_REFRESH_TOKEN_FILE required (a rotated token is
// written back). The negative case also needs CRYPTOARM_SERVER_URL, CRYPTOARM_SERVER_API_KEY
// and SIGNER_CERT_PATH of a running КриптоАРМ Server stand; it is skipped without them. Probes of
// open Диадок questions (D3 inline limit, D7 cached 400) run only with DIADOC_E2E_PROBES=1.
// DIADOC_E2E_TRACE_FILE=<path> writes the HTTP trace (no bodies, tokens or document content).
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { EXIT, main, onRefreshTokenRotated, type CliEnv } from '../cli.js';
import {
  DEFAULT_TOKEN_URL,
  DiadocClient,
  DiadocError,
  loadDiadocEnv,
  lockRefreshTokenFile,
  RefreshTokenAuth,
  type Document,
  type DocumentRef,
  type Message,
} from '../diadoc/index.js';
import { customDocumentIdFor, type SendUtdResult } from '../pipeline/index.js';
import { buildTestUtd, partyFromOrganization, type Party, type TestUtd } from './test-utd.js';

const enabled = process.env.DIADOC_E2E === '1';
const probes = enabled && process.env.DIADOC_E2E_PROBES === '1';
const MAX_POSTS = Number(process.env.DIADOC_E2E_MAX_POSTS ?? '10');
if (!Number.isInteger(MAX_POSTS) || MAX_POSTS < 0) {
  throw new Error('DIADOC_E2E_MAX_POSTS must be a non-negative integer');
}
/** Delivery and the signature check took ~20 s in S1; the shelf cases may take longer. */
const DELIVERY_TIMEOUT_MS = 240_000;
const CASE_TIMEOUT_MS = 600_000;

function loadEnv(): CliEnv {
  const file = process.env.DIADOC_E2E_ENV_FILE;
  const fromFile = file === undefined ? {} : parseEnv(readFileSync(file, 'utf8'));
  return { ...fromFile, ...process.env };
}
const ENV: CliEnv = enabled ? loadEnv() : {};
/** The IdP host: its answers and query parameters stay out of the trace. */
const IDP_HOST = new URL(ENV.DIADOC_TOKEN_URL ?? DEFAULT_TOKEN_URL).host;
const serverSigner =
  enabled &&
  Boolean(ENV.CRYPTOARM_SERVER_URL) &&
  Boolean(ENV.SIGNER_CERT_PATH) &&
  Boolean(ENV.CRYPTOARM_SERVER_API_KEY);

// --- HTTP trace (and the PostMessage cap) ---------------------------------------------------

interface TraceEntry {
  at: string;
  method: string;
  host: string;
  path: string;
  /** Diadoc query parameters (ids, operationId, part numbers); none for the IdP. */
  query?: Record<string, string>;
  status?: number;
  error?: string;
  retryAfter?: string;
  requestBytes?: number;
  /** Small non-secret answers: shelf names, missing-part lists, error texts. */
  answer?: string;
  ms?: number;
  /** A request the test answered itself instead of sending (a dropped shelf part). */
  dropped?: true;
}

const trace: TraceEntry[] = [];
let posts = 0;
/** Answers this request itself (returns a Response) instead of sending it. */
let intercept: ((url: URL) => Response | undefined) | undefined;
const realFetch = globalThis.fetch;

const ANSWER_PATHS = new Set([
  '/V2/ShelfUpload',
  '/ShelfUploadPartInit',
  '/ShelfUploadPart',
  '/V3/PostMessage',
  '/CanPostMessage',
]);

async function tracingFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : input);
  const isIdp = url.host === IDP_HOST;
  const entry: TraceEntry = {
    at: new Date().toISOString(),
    method: init?.method ?? 'GET',
    host: url.host,
    path: url.pathname,
    ...(isIdp ? {} : { query: Object.fromEntries(url.searchParams) }),
  };
  const body = init?.body;
  if (typeof body === 'string') entry.requestBytes = Buffer.byteLength(body);
  else if (body instanceof Uint8Array) entry.requestBytes = body.byteLength;
  trace.push(entry);
  if (url.pathname === '/V3/PostMessage' && ++posts > MAX_POSTS) {
    entry.error = `refused: more than ${String(MAX_POSTS)} PostMessage calls in this run`;
    throw new Error(entry.error);
  }
  const fake = intercept?.(url);
  if (fake !== undefined) {
    entry.status = fake.status;
    entry.dropped = true;
    return fake;
  }
  const started = Date.now();
  try {
    const res = await realFetch(input, init);
    entry.status = res.status;
    entry.ms = Date.now() - started;
    const retryAfter = res.headers.get('retry-after');
    if (retryAfter !== null) entry.retryAfter = retryAfter;
    if (!isIdp && (ANSWER_PATHS.has(url.pathname) || !res.ok)) {
      const text = await res.clone().text();
      entry.answer =
        url.pathname === '/V3/PostMessage' && res.ok ? summarizeMessage(text) : text.slice(0, 500);
    }
    return res;
  } catch (error) {
    entry.error = error instanceof Error ? error.message : String(error);
    entry.ms = Date.now() - started;
    throw error;
  }
}

function summarizeMessage(text: string): string {
  try {
    const m = JSON.parse(text) as Message;
    return `MessageId ${m.MessageId}, ${String(m.Entities?.length ?? 0)} entities`;
  } catch {
    return text.slice(0, 200);
  }
}

// --- helpers ----------------------------------------------------------------------------------

/** A Diadoc client holding the refresh-token lock (the CLI takes it itself, so never both). */
async function withDiadoc<T>(fn: (client: DiadocClient) => Promise<T>): Promise<T> {
  const tokenFile = ENV.DIADOC_REFRESH_TOKEN_FILE;
  if (!tokenFile) throw new Error('the e2e needs DIADOC_REFRESH_TOKEN_FILE');
  const warn = (m: string): void => {
    process.stderr.write(`warning: ${m}\n`);
  };
  const lock = await lockRefreshTokenFile(tokenFile, { warn });
  try {
    const config = await loadDiadocEnv(ENV);
    const auth = new RefreshTokenAuth({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      refreshToken: config.refreshToken,
      ...(config.tokenUrl === undefined ? {} : { tokenUrl: config.tokenUrl }),
      onRefreshTokenRotated: onRefreshTokenRotated(config.refreshTokenFile, (t) =>
        process.stderr.write(t),
      ),
    });
    return await fn(new DiadocClient({ auth, baseUrl: config.baseUrl }));
  } finally {
    await lock.release();
  }
}

const FROM = ENV.DIADOC_FROM_BOX_ID ?? '';
const TO = ENV.DIADOC_TO_BOX_ID ?? '';
let dir = '';
let parties: { seller: Party; buyer: Party };

async function newUtd(minBytes?: number): Promise<{ path: string; utd: TestUtd }> {
  const utd = buildTestUtd({
    ...parties,
    date: new Date(),
    guid: randomUUID(),
    ...(minBytes === undefined ? {} : { minBytes }),
  });
  const path = join(dir, utd.fileName);
  await writeFile(path, utd.content);
  return { path, utd };
}

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
  result?: SendUtdResult;
}

async function runCli(args: string[], env: CliEnv): Promise<CliRun> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(args, {
    env: {
      ...ENV,
      PIPELINE_STATUS_TIMEOUT_MS: '30000',
      PIPELINE_STATUS_MAX_DELAY_MS: '10000',
      ...env,
    },
    fileSize: async (p) => (await stat(p)).size,
    readFile: (p) => readFile(p),
    stdout: (t) => out.push(t),
    stderr: (t) => {
      err.push(t);
      process.stderr.write(t);
    },
    // Stops the CLI (and frees the token lock) before vitest gives up on the case.
    signal: AbortSignal.timeout(CASE_TIMEOUT_MS - 60_000),
  });
  const stdout = out.join('');
  const run: CliRun = { code, stdout, stderr: err.join('') };
  if (stdout.trim().startsWith('{')) run.result = JSON.parse(stdout) as SendUtdResult;
  process.stderr.write(`exit ${String(code)}\n${stdout}`);
  return run;
}

const testSignature = (args: string[]): Promise<CliRun> =>
  runCli(args, { SIGNER_KIND: 'diadoc-test' });

interface Delivery {
  document: Document;
  message: Message;
}

/**
 * Delivered = Diadoc checked the sender signature as valid, the status waits for the recipient (or
 * is final and not an error) and the message has no DeliveryFailureNotification.
 */
async function waitForDelivery(ref: DocumentRef): Promise<Delivery> {
  return withDiadoc(async (client) => {
    const deadline = Date.now() + DELIVERY_TIMEOUT_MS;
    for (let pause = 2_000; ; pause = Math.min(pause * 2, 15_000)) {
      const document = await client.getDocument(ref);
      const message = await client.getMessage(ref.boxId, ref.messageId);
      const primary = document.DocflowStatus?.PrimaryStatus;
      const failed = (message.Entities ?? []).some(
        (e) => e.AttachmentType === 'DeliveryFailureNotification',
      );
      if (
        failed ||
        primary?.Severity === 'Error' ||
        document.SenderSignatureStatus === 'SenderSignatureCheckedAndInvalid'
      ) {
        throw new Error(
          `not delivered: ${JSON.stringify({ primary, sig: document.SenderSignatureStatus, failed })}`,
        );
      }
      const waiting =
        primary?.Severity === 'Success' ||
        (primary?.StatusText ?? '').includes('Ожидается подпись контрагента');
      if (document.SenderSignatureStatus === 'SenderSignatureCheckedAndValid' && waiting) {
        process.stderr.write(
          `delivered: ${JSON.stringify({
            PrimaryStatus: primary,
            SenderSignatureStatus: document.SenderSignatureStatus,
            RecipientResponseStatus: document.RecipientResponseStatus,
            CustomDocumentId: document.CustomDocumentId,
          })}\n`,
        );
        return { document, message };
      }
      if (Date.now() + pause > deadline) {
        throw new Error(`not delivered within ${String(DELIVERY_TIMEOUT_MS)} ms`);
      }
      await new Promise((r) => setTimeout(r, pause));
    }
  });
}

function refOf(result: SendUtdResult | undefined): DocumentRef {
  if (result === undefined) throw new Error('no CLI result');
  return { boxId: result.fromBoxId, messageId: result.messageId, entityId: result.entityId };
}

/** Diadoc stores the exact bytes that were sent (inline, shelf or shelf parts). */
async function expectStoredContent(ref: DocumentRef, content: Buffer): Promise<void> {
  const stored = await withDiadoc((client) => client.getEntityContent(ref));
  expect(stored.length).toBe(content.length);
  expect(stored.equals(content)).toBe(true);
}

// --- cases ------------------------------------------------------------------------------------

describe.skipIf(!enabled)('Диадок e2e (live, test boxes)', () => {
  beforeAll(async () => {
    vi.stubGlobal('fetch', tracingFetch);
    dir = await mkdtemp(join(tmpdir(), 'diadoc-e2e-'));
    // Both boxes must be test organisations; the pipeline checks it again for the test signature.
    const [from, to] = await withDiadoc((client) =>
      Promise.all([client.getOrganization(FROM), client.getOrganization(TO)]),
    );
    expect(from.IsTest).toBe(true);
    expect(to.IsTest).toBe(true);
    parties = { seller: partyFromOrganization(from), buyer: partyFromOrganization(to) };
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    const file = process.env.DIADOC_E2E_TRACE_FILE;
    if (file !== undefined) await writeFile(file, `${JSON.stringify(trace, null, 2)}\n`);
    process.stderr.write(`PostMessage calls in this run: ${String(posts)}\n`);
  });

  let inline: { path: string; result: SendUtdResult } | undefined;

  it(
    'test signature, inline: posted with our GUID CustomDocumentId and delivered (D202 a, D211)',
    async () => {
      const { path, utd } = await newUtd();
      const run = await testSignature(['send', path]);

      expect(run.code).toBe(EXIT.ok);
      const result = run.result;
      expect(result).toMatchObject({
        testSignature: true,
        contentPlacement: 'inline',
        fromBoxId: FROM,
        toBoxId: TO,
      });
      expect(result?.operationId).toMatch(/^[0-9a-f]{64}$/);
      expect(result?.customDocumentId).toBe(customDocumentIdFor(result?.operationId ?? ''));
      expect(run.stderr).toMatch(/Diadoc test signature/);
      expect(run.stderr).not.toMatch(/docflow error/);

      const { document } = await waitForDelivery(refOf(result));
      // D211: PostMessage keeps our derived (v8) GUID.
      expect(document.CustomDocumentId).toBe(result?.customDocumentId);
      await expectStoredContent(refOf(result), utd.content);
      if (result !== undefined) inline = { path, result };
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'sending the same file again replays the message: same operationId and MessageId (D7)',
    async () => {
      if (inline === undefined) throw new Error('needs the inline case first');
      const run = await testSignature(['send', inline.path]);

      expect(run.code).toBe(EXIT.ok);
      expect(run.result?.operationId).toBe(inline.result.operationId);
      expect(run.result?.messageId).toBe(inline.result.messageId);
      expect(run.result?.entityId).toBe(inline.result.entityId);
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'test signature, just over 500 000 B: one V2/ShelfUpload, delivered, bytes intact (D3)',
    async () => {
      const { path, utd } = await newUtd(500_100);
      const before = trace.length;
      const run = await testSignature(['send', path]);

      expect(run.code).toBe(EXIT.ok);
      expect(run.result?.contentPlacement).toBe('shelf');
      const paths = trace.slice(before).map((e) => e.path);
      expect(paths.filter((p) => p === '/V2/ShelfUpload')).toHaveLength(1);
      expect(paths).not.toContain('/ShelfUploadPartInit');
      await waitForDelivery(refOf(run.result));
      await expectStoredContent(refOf(run.result), utd.content);
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'test signature, 6.5 MB in shelf parts: a middle part Diadoc misses is re-sent with ' +
      'isLastPart=true and the stored file is complete (D14)',
    async () => {
      const { path, utd } = await newUtd(6_500_000);
      const before = trace.length;
      let dropped = false;
      intercept = (url) => {
        if (
          !dropped &&
          url.pathname === '/ShelfUploadPart' &&
          url.searchParams.get('partIndex') === '1' &&
          url.searchParams.get('isLastPart') === 'false'
        ) {
          dropped = true;
          return new Response('', { status: 200 });
        }
        return undefined;
      };
      let run: CliRun;
      try {
        run = await testSignature(['send', path]);
      } finally {
        intercept = undefined;
      }

      expect(run.code).toBe(EXIT.ok);
      expect(run.result?.contentPlacement).toBe('shelf');
      const parts = trace
        .slice(before)
        .filter((e) => e.path.startsWith('/ShelfUploadPart'))
        .map((e) => ({
          path: e.path,
          partIndex: e.query?.partIndex,
          isLastPart: e.query?.isLastPart,
          dropped: e.dropped === true,
          answer: e.dropped === true || e.path === '/ShelfUploadPartInit' ? undefined : e.answer,
        }));
      process.stderr.write(`shelf parts: ${JSON.stringify(parts)}\n`);
      expect(parts).toEqual([
        {
          path: '/ShelfUploadPartInit',
          partIndex: undefined,
          isLastPart: 'false',
          dropped: false,
          answer: undefined,
        },
        {
          path: '/ShelfUploadPart',
          partIndex: '1',
          isLastPart: 'false',
          dropped: true,
          answer: undefined,
        },
        {
          path: '/ShelfUploadPart',
          partIndex: '2',
          isLastPart: 'true',
          dropped: false,
          answer: expect.stringMatching(/^\[\s*1\s*\]$/) as unknown,
        },
        {
          path: '/ShelfUploadPart',
          partIndex: '1',
          isLastPart: 'true',
          dropped: false,
          answer: expect.stringMatching(/^\[\s*\]$/) as unknown,
        },
      ]);
      await waitForDelivery(refOf(run.result));
      await expectStoredContent(refOf(run.result), utd.content);
    },
    CASE_TIMEOUT_MS,
  );

  async function testCaNegative(): Promise<void> {
    const { path } = await newUtd();
    // Polling ends at the error status; the long deadline only covers a slow signature check.
    const run = await runCli(['send', path], {
      SIGNER_KIND: 'server',
      PIPELINE_STATUS_TIMEOUT_MS: '120000',
    });

    expect(run.code).toBe(EXIT.docflowError);
    expect(run.stderr).toMatch(/^docflow error \[SENDER_CERTIFICATE_REJECTED\] /m);
    expect(run.result).toMatchObject({
      outcome: 'error',
      status: { PrimaryStatus: { Severity: 'Error', StatusText: 'Ошибка в подписи' } },
      signatureCheck: {
        senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
        reason: 'certificate',
        mathValid: true,
        certificateValid: false,
        delivered: false,
      },
    });
    expect(run.result?.testSignature).toBeUndefined();
  }

  it.skipIf(!serverSigner)(
    'КриптоАРМ Server CMS from the test CA: posted, «Ошибка в подписи», exit 3 with the reason (D202)',
    testCaNegative,
    CASE_TIMEOUT_MS,
  );

  describe.skipIf(!probes)('probes of open Диадок questions', () => {
    const attachment = (utd: TestUtd, version: string) => ({
      TypeNamedId: 'UniversalTransferDocument',
      Function: 'СЧФДОП',
      Version: version,
      SignedContent: { Content: utd.content, SignWithTestSignature: true as const },
      CustomDocumentId: randomUUID(),
    });
    const post = (utd: TestUtd, operationId: string, version = 'utd970_05_03_01') =>
      withDiadoc((client) =>
        client
          .postMessage(
            { FromBoxId: FROM, ToBoxId: TO, DocumentAttachments: [attachment(utd, version)] },
            { operationId },
          )
          .then(
            (m) => ({ ok: true as const, messageId: m.MessageId }),
            (e: unknown) => {
              if (!(e instanceof DiadocError)) throw e;
              return { ok: false as const, status: e.status, text: e.body.slice(0, 300) };
            },
          ),
      );

    // Live 2026-09-26 (D220): accepted, so "500 KB" is not 500 000 B; the pipeline keeps 500 000.
    it(
      'D3: 510 000 B inline Content is accepted (the pipeline would use the shelf)',
      async () => {
        const { utd } = await newUtd(510_000);
        const outcome = await post(utd, randomBytes(32).toString('hex'));
        process.stderr.write(
          `D3 inline ${String(utd.content.length)} B: ${JSON.stringify(outcome)}\n`,
        );
        expect(outcome.ok).toBe(true);
      },
      CASE_TIMEOUT_MS,
    );

    it(
      'D7: a PostMessage rejected with 400, then the same operationId with a valid body',
      async () => {
        const { utd } = await newUtd();
        const operationId = randomBytes(32).toString('hex');
        const first = await post(utd, operationId, 'utd970_99_99_99');
        process.stderr.write(`D7 rejected body: ${JSON.stringify(first)}\n`);
        expect(first.ok).toBe(false);
        const second = await post(utd, operationId);
        process.stderr.write(`D7 same operationId, valid body: ${JSON.stringify(second)}\n`);
        // Live 2026-09-26 (D221): a 400 is not replayed; the fixed body posts a new message.
        expect(second.ok).toBe(true);
      },
      CASE_TIMEOUT_MS,
    );
  });
});

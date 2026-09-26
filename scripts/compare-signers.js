#!/usr/bin/env node
// C1: SIGNER_KIND=server (ServerCmsSigner) vs SIGNER_KIND=documents (DocumentsCloudSigner) on the
// same inputs, against running stands. Writes one JSON report to stdout, progress to stderr.
// Never touches containers: failures of a dependency are simulated on the client side only
// (a closed port, a local socket that never answers, a short client timeout).
//
//   npm run build && node scripts/compare-signers.js > compare.json
//
// Env (same names as the CLI, secrets from files only; values are never printed):
//   CRYPTOARM_SERVER_URL            default http://127.0.0.1:3037
//   CRYPTOARM_SERVER_API_KEY_FILE   server API key (optional when the server runs AUTH_MODE=none)
//   SIGNER_CERT_PATH                the .cer both signers must sign with (the CA stub maps the
//                                   Документы login's e-mail to it)
//   DOCUMENTS_URL                   default http://127.0.0.1:3040
//   DOCUMENTS_LOGIN                 default admin
//   DOCUMENTS_PASSWORD_FILE         required
//   COMPARE_PHASES                  default result,latency,limits,failures
//   COMPARE_SIZES                   generated УПД sizes in bytes, default 10000,1000000,10000000,35000000
//   COMPARE_RUNS                    single runs per size (default 10 below 5 MB, 5 below 20 MB, else 3)
//   COMPARE_BATCH                   documents per batch, default 10; in flight at once: as many as fit
//                                   in COMPARE_BATCH_INFLIGHT_BYTES (default 40 000 000, at least 1)
//   COMPARE_TIMEOUT_MS              client timeout of the failure cases, default 3000
//   COMPARE_DOCKER_STATS=1          sample `docker stats` (read-only) every 2 s during the latency phase
//   COMPARE_CLEANUP=1               delete the Документы documents this run uploaded (by the ids its
//                                   own uploads returned; nothing else on the stand is touched)
import { AsyncLocalStorage } from 'node:async_hooks';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import { promisify } from 'node:util';

import {
  cmsProfile,
  generateUtd,
  latencySummary,
  structuralDiff,
} from '../dist/bench/signer-compare.js';
import {
  cmsPolicyViolations,
  readSignerCertificate,
  verifiedSignerViolations,
} from '../dist/pipeline/signature-policy.js';
import {
  DocumentsCloudSigner,
  ServerCmsSigner,
  loadDocumentsCloudSignerEnv,
  loadServerCmsSignerOptions,
} from '../dist/signer/index.js';

const env = process.env;
const log = (text) => process.stderr.write(`compare: ${text}\n`);
const phases = new Set((env.COMPARE_PHASES ?? 'result,latency,limits,failures').split(','));
const sizes = (env.COMPARE_SIZES ?? '10000,1000000,10000000,35000000').split(',').map(Number);
const batchSize = Number(env.COMPARE_BATCH ?? '10');
const inflightBytes = Number(env.COMPARE_BATCH_INFLIGHT_BYTES ?? '40000000');
const failureTimeoutMs = Number(env.COMPARE_TIMEOUT_MS ?? '3000');
const runsFor = (bytes) =>
  env.COMPARE_RUNS ? Number(env.COMPARE_RUNS) : bytes < 5e6 ? 10 : bytes < 20e6 ? 5 : 3;

const serverApiKey = env.CRYPTOARM_SERVER_API_KEY_FILE
  ? (await readFile(env.CRYPTOARM_SERVER_API_KEY_FILE, 'utf8')).trim()
  : undefined;
const signerEnv = {
  CRYPTOARM_SERVER_URL: env.CRYPTOARM_SERVER_URL ?? 'http://127.0.0.1:3037',
  SIGNER_CERT_PATH: env.SIGNER_CERT_PATH,
  DOCUMENTS_URL: env.DOCUMENTS_URL ?? 'http://127.0.0.1:3040',
  DOCUMENTS_LOGIN: env.DOCUMENTS_LOGIN ?? 'admin',
  DOCUMENTS_PASSWORD_FILE: env.DOCUMENTS_PASSWORD_FILE,
  ...(serverApiKey === undefined ? {} : { CRYPTOARM_SERVER_API_KEY: serverApiKey }),
};

// --- signers with per-step timing ------------------------------------------------------------

/** Time to response headers per request step (login, upload, cloud-sign, …), per signing. */
const stepLog = new AsyncLocalStorage();
const record = (entry) => stepLog.getStore()?.push(entry);
function timedFetch(input, init) {
  const url = new URL(input instanceof Request ? input.url : input);
  const step = stepOf(url.pathname);
  const started = performance.now();
  return fetch(input, init).then(
    (res) => {
      record({ step, ms: Math.round(performance.now() - started), status: res.status });
      if (step === 'documents:upload' && res.ok) void rememberUpload(res.clone());
      return res;
    },
    (error) => {
      record({ step, ms: Math.round(performance.now() - started), error: String(error) });
      throw error;
    },
  );
}
/** Ids of the Документы documents this run uploaded: the only ones cleanup may delete. */
const uploadedIds = new Set();
const uploads = [];
function rememberUpload(response) {
  const task = response
    .json()
    .then((body) => {
      if (Number.isSafeInteger(body?.document?.id)) uploadedIds.add(body.document.id);
    })
    .catch(() => undefined);
  uploads.push(task);
  return task;
}

function stepOf(path) {
  if (path.endsWith('/cms/sign')) return 'server:/cms/sign';
  if (path.endsWith('/cms/verify')) return 'server:/cms/verify';
  if (path.includes('/documents/upload')) return 'documents:upload';
  if (path.includes('/cloud-sign/')) return 'documents:cloud-sign';
  if (path.endsWith('/signature')) return 'documents:export';
  if (path.endsWith('/login')) return 'documents:login';
  if (path.includes('/auth/jwt')) return 'documents:jwt';
  return path;
}

async function makeSigners(overrides = {}) {
  const e = { ...signerEnv, ...overrides };
  const serverOptions = await loadServerCmsSignerOptions(e);
  const server = new ServerCmsSigner({ ...serverOptions, fetch: timedFetch });
  const verifier = new ServerCmsSigner({ ...serverOptions, fetch: timedFetch });
  const documents = new DocumentsCloudSigner({
    ...(await loadDocumentsCloudSignerEnv(e)),
    verifier,
    fetch: timedFetch,
  });
  return { server, documents };
}

const errorInfo = (error) => ({
  name: error?.name ?? typeof error,
  message: String(error?.message ?? error).slice(0, 400),
  ...(error?.cause ? { cause: String(error.cause?.message ?? error.cause).slice(0, 200) } : {}),
});

/** One pipeline signing: sign, verify, F5 policy. Never throws. */
function signOnce(signer, cert, data) {
  const steps = [];
  return stepLog.run(steps, () => signAndVerify(signer, cert, data, steps));
}

async function signAndVerify(signer, cert, data, steps) {
  const t0 = performance.now();
  try {
    const signed = await signer.sign(data);
    const t1 = performance.now();
    const verified = await signer.verify(data, signed.signature);
    const t2 = performance.now();
    const policy = [
      ...cmsPolicyViolations(signed.signature, cert),
      ...verifiedSignerViolations(verified, cert),
    ];
    // A signing counts as ok only when it verifies and passes the F5 policy, as in the pipeline.
    return {
      ok: verified.valid && policy.length === 0,
      signMs: Math.round(t1 - t0),
      verifyMs: Math.round(t2 - t1),
      totalMs: Math.round(t2 - t0),
      steps,
      signed,
      verified,
      policy,
    };
  } catch (error) {
    return {
      ok: false,
      totalMs: Math.round(performance.now() - t0),
      steps,
      error: errorInfo(error),
    };
  }
}

// --- inputs ----------------------------------------------------------------------------------

async function inputs() {
  const dir = new URL('../src/utd/fixtures/', import.meta.url);
  const list = [];
  for (const name of (await readdir(dir)).filter((n) => n.endsWith('.xml'))) {
    list.push({
      label: `fixture ${String((await readFile(new URL(name, dir))).length)} B`,
      content: await readFile(new URL(name, dir)),
    });
  }
  for (const bytes of sizes) {
    const utd = generateUtd(bytes, new Date(), randomUUID());
    list.push({ label: `generated ${String(bytes)} B`, bytes, content: utd.content });
  }
  return list;
}

// --- phases ----------------------------------------------------------------------------------

async function resultPhase(signers, cert, list) {
  const out = [];
  for (const input of list) {
    log(`result: ${input.label}`);
    const row = { input: input.label, bytes: input.content.length };
    for (const kind of ['server', 'documents']) {
      const r = await signOnce(signers[kind], cert, input.content);
      row[kind] = r.error
        ? { error: r.error }
        : {
            profile: cmsProfile(r.signed.signature),
            raw: r.signed.rawSignature ? cmsProfile(r.signed.rawSignature) : undefined,
            verify: r.verified,
            policyViolations: r.policy,
            signMs: r.signMs,
            verifyMs: r.verifyMs,
            steps: r.steps,
            signature: r.signed.signature,
          };
    }
    if (row.server.signature && row.documents.signature) {
      row.structuralDiff = structuralDiff(row.server.signature, row.documents.signature);
      row.sameLength = row.server.signature.length === row.documents.signature.length;
    }
    for (const kind of ['server', 'documents']) delete row[kind].signature;
    out.push(row);
  }
  return out;
}

async function latencyPhase(signers, cert) {
  const out = [];
  for (const bytes of sizes) {
    const data = generateUtd(bytes, new Date(), randomUUID()).content;
    for (const kind of ['server', 'documents']) {
      const runs = runsFor(bytes);
      log(`latency: ${kind} ${String(bytes)} B × ${String(runs)} single`);
      const single = [];
      for (let i = 0; i < runs; i++) single.push(await signOnce(signers[kind], cert, data));
      const inFlight = Math.max(1, Math.min(batchSize, Math.floor(inflightBytes / bytes)));
      log(
        `latency: ${kind} ${String(bytes)} B batch of ${String(batchSize)} (${String(inFlight)} in flight)`,
      );
      const started = performance.now();
      const batch = await pool(batchSize, inFlight, () => signOnce(signers[kind], cert, data));
      const wallMs = Math.round(performance.now() - started);
      out.push({
        kind,
        bytes: data.length,
        single: summary(single),
        batch: {
          ...summary(batch),
          size: batchSize,
          inFlight,
          wallMs,
          docsPerMinute: Math.round((batchSize * 60000) / wallMs),
        },
      });
    }
  }
  return out;
}

function summary(runs) {
  const ok = runs.filter((r) => r.ok);
  const stepTimes = {};
  for (const r of ok) for (const s of r.steps) (stepTimes[s.step] ??= []).push(s.ms);
  return {
    runs: runs.length,
    errors: runs.length - ok.length,
    errorRate: (runs.length - ok.length) / runs.length,
    /** Repeated requests (F3 retry) and their statuses, e.g. 429 from the Документы rate limit. */
    failedRequests: countBy(
      runs.flatMap((r) => r.steps.filter((s) => s.error || s.status >= 400)),
      (s) => `${s.step}:${String(s.status ?? 'ERR')}`,
    ),
    errorSamples: runs
      .filter((r) => !r.ok)
      .slice(0, 3)
      .map((r) => r.error ?? r.verified?.reason),
    ...(ok.length === 0
      ? {}
      : {
          total: latencySummary(ok.map((r) => r.totalMs)),
          sign: latencySummary(ok.map((r) => r.signMs)),
          verify: latencySummary(ok.map((r) => r.verifyMs)),
          steps: Object.fromEntries(
            Object.entries(stepTimes).map(([k, v]) => [k, latencySummary(v)]),
          ),
        }),
  };
}

function countBy(items, key) {
  const out = {};
  for (const item of items) out[key(item)] = (out[key(item)] ?? 0) + 1;
  return out;
}

async function pool(count, width, task) {
  const results = [];
  let next = 0;
  await Promise.all(
    Array.from({ length: width }, async () => {
      while (next < count) {
        next++;
        results.push(await task());
      }
    }),
  );
  return results;
}

/** Around the Документы pre-check limit (D50/F14) and the server's JSON_LIMIT (T10). */
async function limitsPhase(signers, cert) {
  const out = [];
  for (const bytes of [39_305_199, 39_305_200, 39_320_000]) {
    const data = Buffer.alloc(bytes, 0x41);
    for (const kind of ['server', 'documents']) {
      log(`limits: ${kind} ${String(bytes)} B`);
      const r = await signOnce(signers[kind], cert, data);
      out.push({
        kind,
        bytes,
        ok: r.ok,
        totalMs: r.totalMs,
        error: r.error,
        steps: r.steps.map((s) => s.step),
      });
    }
  }
  return out;
}

async function failuresPhase(cert) {
  const data = generateUtd(10_000, new Date(), randomUUID()).content;
  const closed = await closedPort();
  const hang = await hangingServer();
  const cases = [
    [
      'server stopped (connection refused)',
      'server',
      { CRYPTOARM_SERVER_URL: `http://127.0.0.1:${String(closed)}` },
    ],
    [
      'Документы stopped (connection refused)',
      'documents',
      { DOCUMENTS_URL: `http://127.0.0.1:${String(closed)}` },
    ],
    [
      'verifier (server) stopped, Документы up',
      'documents',
      { CRYPTOARM_SERVER_URL: `http://127.0.0.1:${String(closed)}` },
    ],
    [
      `server hangs, client timeout ${String(failureTimeoutMs)} ms`,
      'server',
      {
        CRYPTOARM_SERVER_URL: `http://127.0.0.1:${String(hang.port)}`,
        CRYPTOARM_SERVER_TIMEOUT_MS: String(failureTimeoutMs),
      },
    ],
    [
      `Документы hangs, client timeout ${String(failureTimeoutMs)} ms`,
      'documents',
      {
        DOCUMENTS_URL: `http://127.0.0.1:${String(hang.port)}`,
        DOCUMENTS_TIMEOUT_MS: String(failureTimeoutMs),
      },
    ],
    [
      `live Документы, 10 MB, client timeout ${String(failureTimeoutMs)} ms`,
      'documents',
      { DOCUMENTS_TIMEOUT_MS: String(failureTimeoutMs) },
      10_000_000,
    ],
    [
      `live server, 10 MB, client timeout ${String(failureTimeoutMs)} ms`,
      'server',
      { CRYPTOARM_SERVER_TIMEOUT_MS: String(failureTimeoutMs) },
      10_000_000,
    ],
  ];
  const out = [];
  for (const [name, kind, overrides, bytes] of cases) {
    log(`failures: ${name}`);
    const signers = await makeSigners(overrides);
    const input = bytes ? generateUtd(bytes, new Date(), randomUUID()).content : data;
    const r = await signOnce(signers[kind], cert, input);
    out.push({
      case: name,
      kind,
      ok: r.ok,
      elapsedMs: r.totalMs,
      error: r.error,
      requests: r.steps.map((s) => `${s.step}:${String(s.status ?? 'ERR')}`),
      documentsUploaded: r.steps.filter((s) => s.step === 'documents:upload' && s.status < 300)
        .length,
    });
  }
  hang.close();
  return out;
}

function closedPort() {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** Accepts connections and never answers: a hung dependency, seen from the client. */
function hangingServer() {
  const sockets = new Set();
  const s = createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => undefined);
  });
  return new Promise((resolve) => {
    s.listen(0, '127.0.0.1', () =>
      resolve({
        port: s.address().port,
        close: () => {
          for (const socket of sockets) socket.destroy();
          s.close();
        },
      }),
    );
  });
}

// --- Документы admin view (counts, storage, cleanup) ----------------------------------------

let cookie;
/** An admin-session request; repeats a 429 after its Retry-After (the API allows 120 per 60 s). */
async function documentsApi(path, init = {}) {
  const base = signerEnv.DOCUMENTS_URL;
  if (cookie === undefined) {
    const password = (await readFile(signerEnv.DOCUMENTS_PASSWORD_FILE, 'utf8')).replace(
      /\r?\n$/,
      '',
    );
    const res = await fetch(new URL('api/v1/login', base), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: signerEnv.DOCUMENTS_LOGIN, password }),
    });
    await res.body?.cancel();
    if (!res.ok) throw new Error(`Документы login: HTTP ${String(res.status)}`);
    cookie = res.headers
      .getSetCookie()
      .map((c) => c.split(';', 1)[0])
      .join('; ');
  }
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(new URL(path, base), { ...init, headers: { ...init.headers, cookie } });
    if (res.status !== 429 || attempt === 5) {
      if (!res.ok) {
        await res.body?.cancel();
        throw new Error(`Документы ${init.method ?? 'GET'} ${path}: HTTP ${String(res.status)}`);
      }
      return res;
    }
    await res.body?.cancel();
    const seconds = Number(res.headers.get('retry-after') ?? '5');
    await new Promise((r) => setTimeout(r, (Number.isFinite(seconds) ? seconds : 5) * 1000 + 250));
  }
}
async function storage() {
  const profile = await (await documentsApi('api/v1/profile')).json();
  return { ...profile.storage, availableSignatureLicenses: profile.availableSignatureLicenses };
}
async function cleanup() {
  let deleted = 0;
  const failed = [];
  for (const id of uploadedIds) {
    try {
      const r = await documentsApi(`api/v1/documents/${String(id)}`, { method: 'DELETE' });
      await r.body?.cancel();
      deleted++;
    } catch (error) {
      failed.push(`${String(id)}: ${String(error.message)}`);
    }
  }
  return { deleted, failed };
}
/** Runs a bookkeeping step; a failure is recorded in the report instead of losing it. */
async function safely(report, name, fn) {
  try {
    report[name] = await fn();
  } catch (error) {
    (report.bookkeepingErrors ??= []).push(`${name}: ${String(error?.message ?? error)}`);
  }
}

// --- docker stats (read-only) ----------------------------------------------------------------

function dockerStats() {
  const samples = {};
  let running = true;
  const run = promisify(execFile);
  const loop = (async () => {
    while (running) {
      try {
        const { stdout } = await run('docker', ['stats', '--no-stream', '--format', '{{json .}}']);
        for (const line of stdout.trim().split('\n')) {
          const s = JSON.parse(line);
          if (!/cryptoarm|kryptoarm/.test(s.Name)) continue;
          const mem = parseSize(s.MemUsage.split('/')[0]);
          const cpu = Number.parseFloat(s.CPUPerc);
          const agg = (samples[s.Name] ??= {
            n: 0,
            cpuMax: 0,
            cpuSum: 0,
            memMaxMiB: 0,
            memLimit: s.MemUsage.split('/')[1]?.trim(),
          });
          agg.n++;
          agg.cpuMax = Math.max(agg.cpuMax, cpu);
          agg.cpuSum += cpu;
          agg.memMaxMiB = Math.max(agg.memMaxMiB, Math.round(mem / 2 ** 20));
        }
      } catch {
        // docker unavailable: no samples
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  })();
  return async () => {
    running = false;
    await loop;
    return Object.fromEntries(
      Object.entries(samples).map(([name, a]) => [
        name,
        {
          samples: a.n,
          cpuMaxPercent: a.cpuMax,
          cpuMeanPercent: Math.round(a.cpuSum / a.n),
          memMaxMiB: a.memMaxMiB,
          memLimit: a.memLimit,
        },
      ]),
    );
  };
}
function parseSize(text) {
  const m = /([\d.]+)\s*([KMG]?i?B)/.exec(text.trim());
  if (!m) return 0;
  const unit =
    { B: 1, KiB: 2 ** 10, MiB: 2 ** 20, GiB: 2 ** 30, kB: 1e3, KB: 1e3, MB: 1e6, GB: 1e9 }[m[2]] ??
    1;
  return Number(m[1]) * unit;
}

// --- main ------------------------------------------------------------------------------------

const signers = await makeSigners();
const cert = readSignerCertificate(signers.server.certificate);
const report = {
  startedAt: new Date().toISOString(),
  signerCertificate: cert.thumbprint,
  node: process.version,
};
await safely(report, 'storageBefore', storage);

try {
  if (phases.has('result')) report.result = await resultPhase(signers, cert, await inputs());
  if (phases.has('latency')) {
    const stop = env.COMPARE_DOCKER_STATS === '1' ? dockerStats() : undefined;
    try {
      report.latency = await latencyPhase(signers, cert);
    } finally {
      if (stop) report.dockerStatsDuringLatency = await stop();
    }
  }
  if (phases.has('limits')) report.limits = await limitsPhase(signers, cert);
  if (phases.has('failures')) report.failures = await failuresPhase(cert);
} catch (error) {
  report.aborted = errorInfo(error);
}

await Promise.all(uploads);
report.documentsUploaded = uploadedIds.size;
await safely(report, 'storageAfter', storage);
if (env.COMPARE_CLEANUP === '1') {
  await safely(report, 'cleanup', cleanup);
  await safely(report, 'storageAfterCleanup', storage);
}
report.finishedAt = new Date().toISOString();
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

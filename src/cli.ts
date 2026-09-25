#!/usr/bin/env node
// Thin CLI over the pipeline: `send <file.xml>` signs a УПД via КриптоАРМ Server (or КриптоАРМ
// Документы cloud-sign, SIGNER_KIND=documents) and posts it to Diadoc.
// Settings come from env (see .env.example); `npm run cli -- send <file.xml>` loads ./.env.
import { writeSync } from 'node:fs';
import { readFile as fsReadFile, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:os';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DiadocClient,
  loadDiadocEnv,
  lockRefreshTokenFile,
  POST_MESSAGE_BUDGET_MS,
  RefreshTokenAuth,
  SHELF_MAX_BYTES,
  writeRefreshTokenFile,
} from './diadoc/index.js';
import {
  describeSignatureCheck,
  isResendSalt,
  isSignatureRejected,
  loadPipelineConfig,
  PipelineError,
  sendUtd,
  type PipelineDiadoc,
  type SendUtdResult,
} from './pipeline/index.js';
import { createSignerFromEnv, type Signer } from './signer/index.js';

export type CliEnv = Record<string, string | undefined>;

export const EXIT = {
  /** Posted; the docflow status has no error (it may still be pending). */
  ok: 0,
  /** Nothing was posted, or the post failed or is still pending (see the `[CODE]` on stderr). */
  failed: 1,
  usage: 2,
  /**
   * Posted, but Diadoc reports an error status or rejected the sender signature (why: the
   * `docflow error [CODE]` line on stderr and `signatureCheck` in the JSON, D203).
   */
  docflowError: 3,
  /** Posted (messageId on stderr), but the response had no document entity to track. */
  postedUntracked: 4,
} as const;

/**
 * `close` releases what the client holds for the run (the refresh-token file lock); `closeSync` does
 * the same synchronously for a process that exits at once.
 */
export type CliDiadoc = PipelineDiadoc & { close?: () => Promise<void>; closeSync?: () => void };

/** What the second signal needs: filled by `main` while it runs. */
export interface RunState {
  /** Set when PostMessage starts. */
  operationId?: string;
  /** Set when PostMessage answered. */
  messageId?: string;
  releaseLockSync?: () => void;
  /** The token file while a rotated refresh token is being written to it. */
  savingTokenFile?: string;
}

export interface CliDeps {
  env: CliEnv;
  /** Size in bytes, checked before `readFile` (a file the shelf cannot take is never read). */
  fileSize: (path: string) => Promise<number>;
  readFile: (path: string) => Promise<Buffer>;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  createSigner?: (env: CliEnv) => Promise<Signer>;
  createDiadoc?: (
    env: CliEnv,
    stderr: (text: string) => void,
    state: RunState,
  ) => Promise<CliDiadoc>;
  send?: typeof sendUtd;
  signal?: AbortSignal;
  state?: RunState;
}

const USAGE = `Usage: cli send <file.xml> [--no-precheck] [--resend[=<salt>]]

Signs the УПД with КриптоАРМ Server (SIGNER_KIND=documents: КриптоАРМ Документы cloud-sign)
and posts it to Контур.Диадок.
The file name must be ИдФайл + ".xml"; the bytes are signed and sent unchanged.
Sending the same file again reuses its operationId (Diadoc treats it as the same send).
--resend posts it once more on purpose under a new operationId (random salt, printed on stderr);
--resend=<salt> (1-128 of [A-Za-z0-9._:-]) repeats that resend idempotently.
Prints the result as JSON. Exit codes: 0 posted, 1 failed, 2 usage, 3 posted but docflow error
or sender signature rejected (reason on stderr), 4 posted but not trackable. Run one process at a time per refresh token.
Everything after -- is the file name (for a name that starts with -).
The first Ctrl+C/SIGTERM stops after the current step (a running PostMessage ends within its time
budget); a second one exits at once (130/143), printing the operationId known so far.
`;

export async function main(argv: readonly string[], deps: CliDeps): Promise<number> {
  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h') {
    deps.stdout(USAGE);
    return EXIT.ok;
  }
  const end = rest.indexOf('--');
  const options = end === -1 ? rest : rest.slice(0, end);
  const files = [
    ...options.filter((a) => !a.startsWith('-')),
    ...(end === -1 ? [] : rest.slice(end + 1)),
  ];
  const flags = options.filter((a) => a.startsWith('-'));
  const [path] = files;
  const resendFlags = flags.filter((f) => f === '--resend' || f.startsWith('--resend='));
  if (
    command !== 'send' ||
    path === undefined ||
    files.length !== 1 ||
    resendFlags.length > 1 ||
    flags.some((f) => f !== '--no-precheck' && !resendFlags.includes(f))
  ) {
    deps.stderr(USAGE);
    return EXIT.usage;
  }
  const [resendFlag] = resendFlags;
  const resend =
    resendFlag === undefined
      ? undefined
      : resendFlag === '--resend'
        ? randomUUID()
        : resendFlag.slice('--resend='.length);
  if (resend !== undefined && !isResendSalt(resend)) {
    deps.stderr(
      `invalid --resend salt ${JSON.stringify(resend)} (use --resend=<salt>)\n\n${USAGE}`,
    );
    return EXIT.usage;
  }

  const state = deps.state ?? {};
  let diadoc: CliDiadoc | undefined;
  try {
    const config = await setupStep('PIPELINE_CONFIG', () => loadPipelineConfig(deps.env));
    const size = await setupStep('READ_FAILED', () => deps.fileSize(path));
    if (size > SHELF_MAX_BYTES) {
      // Same refusal as sendUtd's, before a file of up to gigabytes is loaded into memory.
      throw new PipelineError(
        'CONTENT_TOO_LARGE',
        'parse',
        `${basename(path)} is ${String(size)} bytes; the Diadoc shelf takes at most ` +
          String(SHELF_MAX_BYTES),
      );
    }
    const content = await setupStep('READ_FAILED', () => deps.readFile(path));
    const signer = await setupStep('SIGNER_CONFIG', () =>
      (deps.createSigner ?? createSigner)(deps.env),
    );
    diadoc = await setupStep('DIADOC_CONFIG', () =>
      (deps.createDiadoc ?? createDiadoc)(deps.env, deps.stderr, state),
    );
    const { closeSync } = diadoc;
    if (closeSync !== undefined && state.releaseLockSync === undefined) {
      state.releaseLockSync = () => {
        closeSync.call(diadoc);
      };
    }
    if (resend !== undefined) {
      deps.stderr(
        `resend: new operationId with salt ${resend}; to repeat this resend, use --resend=${resend}\n`,
      );
    }
    const result = await (deps.send ?? sendUtd)(
      { fileName: basename(path), content },
      {
        signer,
        diadoc: tracked(diadoc, state),
        log: (m) => {
          deps.stderr(`${m}\n`);
        },
      },
      {
        fromBoxId: config.fromBoxId,
        toBoxId: config.toBoxId,
        precheck: config.precheck && !flags.includes('--no-precheck'),
        poll: config.poll,
        ...(resend === undefined ? {} : { resend }),
        ...(deps.signal === undefined ? {} : { signal: deps.signal }),
      },
    );
    deps.stdout(`${JSON.stringify(printable(result), null, 2)}\n`);
    if (!isDocflowFailure(result)) return EXIT.ok;
    deps.stderr(`${describeDocflowFailure(result)}\n`);
    return EXIT.docflowError;
  } catch (error) {
    const interrupted = deps.signal?.aborted === true && error === deps.signal.reason;
    deps.stderr(
      `${interrupted ? `error [INTERRUPTED] ${describe(error)}` : describeFailure(error)}\n`,
    );
    return error instanceof PipelineError && error.code === 'NO_DOCUMENT_ENTITY'
      ? EXIT.postedUntracked
      : EXIT.failed;
  } finally {
    // The exit code is already decided (and the JSON printed); a failing release must not change it.
    await diadoc?.close?.().catch((error: unknown) => {
      deps.stderr(`warning: ${error instanceof Error ? error.message : String(error)}\n`);
    });
  }
}

/** Records the operationId and messageId of PostMessage in `state` for the second signal. */
function tracked(diadoc: PipelineDiadoc, state: RunState): PipelineDiadoc {
  return {
    canPostMessage: (prototype, o) => diadoc.canPostMessage(prototype, o),
    shelfUpload: (content, o) => diadoc.shelfUpload(content, o),
    getDocument: (ref, o) => diadoc.getDocument(ref, o),
    getMessage: (boxId, messageId, o) => diadoc.getMessage(boxId, messageId, o),
    getSignatureInfo: (ref, o) => diadoc.getSignatureInfo(ref, o),
    postMessage: async (message, o) => {
      state.operationId = o.operationId;
      const posted = await diadoc.postMessage(message, o);
      state.messageId = posted.MessageId;
      return posted;
    },
  };
}

/** SIGNER_KIND=server (default) or documents, see createSignerFromEnv. */
function createSigner(env: CliEnv): Promise<Signer> {
  return createSignerFromEnv(env);
}

/**
 * With DIADOC_REFRESH_TOKEN_FILE the file is locked (and checked to be replaceable) before the token
 * is read, and stays locked until `close`.
 */
async function createDiadoc(
  env: CliEnv,
  stderr: (text: string) => void,
  state: RunState,
): Promise<CliDiadoc> {
  // Same condition as loadDiadocEnv, which reads the token only after the lock is taken.
  const lock = env.DIADOC_REFRESH_TOKEN_FILE
    ? await lockRefreshTokenFile(env.DIADOC_REFRESH_TOKEN_FILE, {
        warn: (message) => {
          stderr(`warning: ${message}\n`);
        },
      })
    : undefined;
  // At once, so a second signal from here on never leaves the lock behind.
  if (lock !== undefined) {
    state.releaseLockSync = () => {
      lock.releaseSync();
    };
  }
  try {
    const config = await loadDiadocEnv(env);
    // No DIADOC_TIMEOUT_MS here (D-6): a longer IdP timeout would keep a token refresh from starting
    // inside the PostMessage budget (auth.ts starts one only if its full timeout fits).
    const auth = new RefreshTokenAuth({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      refreshToken: config.refreshToken,
      ...(config.tokenUrl === undefined ? {} : { tokenUrl: config.tokenUrl }),
      onRefreshTokenRotated: onRefreshTokenRotated(config.refreshTokenFile, stderr, state),
    });
    const client = new DiadocClient({
      auth,
      baseUrl: config.baseUrl,
      ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }),
    });
    return Object.assign(client, {
      close: () => lock?.release() ?? Promise.resolve(),
      closeSync: () => lock?.releaseSync(),
    });
  } catch (error) {
    await lock?.release();
    throw error;
  }
}

/** Persists a rotated refresh token (see writeRefreshTokenFile); without a file only warns. */
export function onRefreshTokenRotated(
  tokenFile: string | undefined,
  stderr: (text: string) => void,
  state: RunState = {},
): (token: string) => Promise<void> {
  return async (token) => {
    if (tokenFile === undefined) {
      stderr(
        'warning: Diadoc rotated the refresh token and it was not saved; ' +
          'set DIADOC_REFRESH_TOKEN_FILE so rotated tokens are persisted\n',
      );
      return;
    }
    state.savingTokenFile = tokenFile;
    try {
      await writeRefreshTokenFile(tokenFile, token, {
        warn: (message) => {
          stderr(`warning: ${message}\n`);
        },
      });
    } finally {
      delete state.savingTokenFile;
    }
  };
}

/**
 * The first signal aborts: signing, CanPostMessage, a shelf upload (leaving a harmless unused shelf
 * file) and polling stop at once; a running PostMessage finishes within POST_MESSAGE_BUDGET_MS, which
 * `stop_grace_period` of the compose `app` service covers. The second signal exits at once: it
 * removes the refresh-token lock synchronously and prints the operationId (and messageId) known so
 * far. Exit code 128 + the signal number.
 */
export function interruptHandler(
  controller: AbortController,
  stderr: (text: string) => void,
  state: RunState = {},
  exit: (code: number) => void = (code) => process.exit(code),
): (signal: NodeJS.Signals) => void {
  let received = 0;
  return (signal) => {
    received++;
    if (received === 1) {
      stderr(
        `${signal}: stopping after the current step (a running PostMessage ends within ` +
          `${String(POST_MESSAGE_BUDGET_MS / 1000)} s); send ${signal} again to exit at once\n`,
      );
      controller.abort(new Error(`interrupted (${signal})`));
      return;
    }
    try {
      state.releaseLockSync?.();
    } catch (error) {
      stderr(
        `warning: the refresh-token lock was not removed, delete it by hand: ${describe(error)}\n`,
      );
    }
    const { operationId, messageId, savingTokenFile } = state;
    if (savingTokenFile !== undefined) {
      stderr(
        `warning: a rotated refresh token was being saved: if ${savingTokenFile} is not updated, ` +
          `${savingTokenFile}.tmp holds the new token, move it there by hand\n`,
      );
    }
    stderr(
      `${signal} again: exiting now; ` +
        (operationId === undefined
          ? 'nothing was posted to Diadoc\n'
          : `operationId ${operationId}${messageId === undefined ? '' : `, messageId ${messageId}`}: ` +
            'the message may have been posted, look it up in Diadoc before sending again ' +
            '(a repeated send reuses the operationId)\n'),
    );
    exit(128 + constants.signals[signal]);
  };
}

function printable(result: SendUtdResult): unknown {
  const { statusError, ...rest } = result;
  if (statusError === undefined) return rest;
  const text =
    statusError instanceof Error
      ? `${statusError.name}: ${statusError.message}`
      : JSON.stringify(statusError);
  return { ...rest, statusError: text };
}

/** An error status, or a sender signature Diadoc rejected while the status is not final yet. */
function isDocflowFailure(result: SendUtdResult): boolean {
  const check = result.signatureCheck;
  return result.outcome === 'error' || (check !== undefined && isSignatureRejected(check));
}

function describeDocflowFailure(result: SendUtdResult): string {
  const statusText = result.status?.PrimaryStatus?.StatusText;
  const why =
    result.signatureCheck === undefined
      ? `[DOCFLOW_ERROR] ${statusText ?? result.outcome}`
      : describeSignatureCheck(result.signatureCheck, statusText);
  return `docflow error ${why} (operationId ${result.operationId}, messageId ${result.messageId})`;
}

function describeFailure(error: unknown): string {
  if (error instanceof PipelineError) {
    const ids = [
      error.operationId && `operationId ${error.operationId}`,
      error.messageId && `messageId ${error.messageId}`,
    ].filter(Boolean);
    return `error [${error.code}] ${error.message}${ids.length > 0 ? ` (${ids.join(', ')})` : ''}`;
  }
  if (error instanceof CliSetupError) return `error [${error.code}] ${error.message}`;
  return `error [UNEXPECTED] ${describe(error)}`;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Codes for failures before the pipeline starts, printed like `PipelineError` codes. */
export type CliSetupCode = 'PIPELINE_CONFIG' | 'READ_FAILED' | 'SIGNER_CONFIG' | 'DIADOC_CONFIG';

class CliSetupError extends Error {
  override readonly name = 'CliSetupError';

  constructor(
    readonly code: CliSetupCode,
    options: { cause: unknown },
  ) {
    super(options.cause instanceof Error ? options.cause.message : String(options.cause), options);
  }
}

async function setupStep<T>(code: CliSetupCode, fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    throw new CliSetupError(code, { cause: error });
  }
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  const controller = new AbortController();
  const state: RunState = {};
  // SIGTERM is how `docker stop` ends the container: abort so a posted message still reports its ids.
  // Synchronous: the second signal calls process.exit right after writing (a pipe on macOS is async).
  const onSignal = interruptHandler(controller, (text) => writeSync(2, text), state);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, onSignal);
  process.exitCode = await main(process.argv.slice(2), {
    env: process.env,
    state,
    fileSize: async (path) => (await stat(path)).size,
    readFile: (path) => fsReadFile(path),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    signal: controller.signal,
  });
}

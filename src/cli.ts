#!/usr/bin/env node
// Thin CLI over the pipeline: `send <file.xml>` signs a УПД via КриптоАРМ Server and posts it to Diadoc.
// Settings come from env (see .env.example); `npm run cli -- send <file.xml>` loads ./.env.
import { readFile as fsReadFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DiadocClient,
  loadDiadocEnv,
  lockRefreshTokenFile,
  RefreshTokenAuth,
  writeRefreshTokenFile,
} from './diadoc/index.js';
import {
  isResendSalt,
  loadPipelineConfig,
  PipelineError,
  sendUtd,
  type PipelineDiadoc,
  type SendUtdResult,
} from './pipeline/index.js';
import { loadServerCmsSignerOptions, ServerCmsSigner, type Signer } from './signer/index.js';

export type CliEnv = Record<string, string | undefined>;

export const EXIT = {
  /** Posted; the docflow status has no error (it may still be pending). */
  ok: 0,
  /** Nothing was posted, or the post failed or is still pending (see the `[CODE]` on stderr). */
  failed: 1,
  usage: 2,
  /** Posted, but Diadoc reports an error status (e.g. the signature was rejected). */
  docflowError: 3,
  /** Posted (messageId on stderr), but the response had no document entity to track. */
  postedUntracked: 4,
} as const;

/** `close` releases what the client holds for the run (the refresh-token file lock). */
export type CliDiadoc = PipelineDiadoc & { close?: () => Promise<void> };

export interface CliDeps {
  env: CliEnv;
  readFile: (path: string) => Promise<Buffer>;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  createSigner?: (env: CliEnv) => Promise<Signer>;
  createDiadoc?: (env: CliEnv, stderr: (text: string) => void) => Promise<CliDiadoc>;
  send?: typeof sendUtd;
  signal?: AbortSignal;
}

const USAGE = `Usage: cli send <file.xml> [--no-precheck] [--resend[=<salt>]]

Signs the УПД with КриптоАРМ Server and posts it to Контур.Диадок.
The file name must be ИдФайл + ".xml"; the bytes are signed and sent unchanged.
Sending the same file again reuses its operationId (Diadoc treats it as the same send).
--resend posts it once more on purpose under a new operationId (random salt, printed on stderr);
--resend=<salt> (1-128 of [A-Za-z0-9._:-]) repeats that resend idempotently.
Prints the result as JSON. Exit codes: 0 posted, 1 failed, 2 usage, 3 posted but docflow error,
4 posted but not trackable. Run one process at a time per refresh token.
`;

export async function main(argv: readonly string[], deps: CliDeps): Promise<number> {
  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h') {
    deps.stdout(USAGE);
    return EXIT.ok;
  }
  const files = rest.filter((a) => !a.startsWith('-'));
  const flags = rest.filter((a) => a.startsWith('-'));
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

  let diadoc: CliDiadoc | undefined;
  try {
    const config = await setupStep('PIPELINE_CONFIG', () => loadPipelineConfig(deps.env));
    const content = await setupStep('READ_FAILED', () => deps.readFile(path));
    const signer = await setupStep('SIGNER_CONFIG', () =>
      (deps.createSigner ?? createSigner)(deps.env),
    );
    diadoc = await setupStep('DIADOC_CONFIG', () =>
      (deps.createDiadoc ?? createDiadoc)(deps.env, deps.stderr),
    );
    if (resend !== undefined) {
      deps.stderr(
        `resend: new operationId with salt ${resend}; to repeat this resend, use --resend=${resend}\n`,
      );
    }
    const result = await (deps.send ?? sendUtd)(
      { fileName: basename(path), content },
      {
        signer,
        diadoc,
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
    return result.outcome === 'error' ? EXIT.docflowError : EXIT.ok;
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

async function createSigner(env: CliEnv): Promise<Signer> {
  return new ServerCmsSigner(await loadServerCmsSignerOptions(env));
}

/**
 * With DIADOC_REFRESH_TOKEN_FILE the file is locked (and checked to be replaceable) before the token
 * is read, and stays locked until `close`.
 */
async function createDiadoc(env: CliEnv, stderr: (text: string) => void): Promise<CliDiadoc> {
  // Same condition as loadDiadocEnv, which reads the token only after the lock is taken.
  const lock = env.DIADOC_REFRESH_TOKEN_FILE
    ? await lockRefreshTokenFile(env.DIADOC_REFRESH_TOKEN_FILE)
    : undefined;
  try {
    const config = await loadDiadocEnv(env);
    const auth = new RefreshTokenAuth({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      refreshToken: config.refreshToken,
      ...(config.tokenUrl === undefined ? {} : { tokenUrl: config.tokenUrl }),
      onRefreshTokenRotated: onRefreshTokenRotated(config.refreshTokenFile, stderr),
    });
    const client = new DiadocClient({
      auth,
      baseUrl: config.baseUrl,
      ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }),
    });
    return Object.assign(client, { close: () => lock?.release() ?? Promise.resolve() });
  } catch (error) {
    await lock?.release();
    throw error;
  }
}

/** Persists a rotated refresh token (see writeRefreshTokenFile); without a file only warns. */
export function onRefreshTokenRotated(
  tokenFile: string | undefined,
  stderr: (text: string) => void,
): (token: string) => Promise<void> {
  return async (token) => {
    if (tokenFile === undefined) {
      stderr(
        'warning: Diadoc rotated the refresh token and it was not saved; ' +
          'set DIADOC_REFRESH_TOKEN_FILE so rotated tokens are persisted\n',
      );
      return;
    }
    await writeRefreshTokenFile(tokenFile, token, {
      warn: (message) => {
        stderr(`warning: ${message}\n`);
      },
    });
  };
}

/**
 * The first signal aborts between steps (a running PostMessage/CanPostMessage and its retries finish
 * first; a shelf upload stops at once, leaving a harmless unused shelf file);
 * the handler is registered with `once`, so a second signal kills the process.
 */
export function interruptHandler(
  controller: AbortController,
  stderr: (text: string) => void,
): (signal: NodeJS.Signals) => void {
  return (signal) => {
    stderr(
      `${signal}: stopping after the current step; send ${signal} again to kill ` +
        '(then check Diadoc by operationId and delete a left-over refresh-token .lock file)\n',
    );
    controller.abort(new Error(`interrupted (${signal})`));
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
  // SIGTERM is how `docker stop` ends the container: abort so a posted message still reports its ids.
  const onSignal = interruptHandler(controller, (text) => process.stderr.write(text));
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, onSignal);
  process.exitCode = await main(process.argv.slice(2), {
    env: process.env,
    readFile: (path) => fsReadFile(path),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    signal: controller.signal,
  });
}

#!/usr/bin/env node
// Thin CLI over the pipeline: `send <file.xml>` signs a УПД via КриптоАРМ Server and posts it to Diadoc.
// Settings come from env (see .env.example); `npm run cli -- send <file.xml>` loads ./.env.
import { constants } from 'node:fs';
import { access, readFile as fsReadFile, rename, writeFile } from 'node:fs/promises';
import { basename, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

import { DiadocClient, loadDiadocEnv, RefreshTokenAuth } from './diadoc/index.js';
import {
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

export interface CliDeps {
  env: CliEnv;
  readFile: (path: string) => Promise<Buffer>;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  createSigner?: (env: CliEnv) => Promise<Signer>;
  createDiadoc?: (env: CliEnv, stderr: (text: string) => void) => Promise<PipelineDiadoc>;
  send?: typeof sendUtd;
  signal?: AbortSignal;
}

const USAGE = `Usage: cli send <file.xml> [--no-precheck]

Signs the УПД with КриптоАРМ Server and posts it to Контур.Диадок.
The file name must be ИдФайл + ".xml"; the bytes are signed and sent unchanged.
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
  if (
    command !== 'send' ||
    path === undefined ||
    files.length !== 1 ||
    flags.some((f) => f !== '--no-precheck')
  ) {
    deps.stderr(USAGE);
    return EXIT.usage;
  }

  try {
    const config = loadPipelineConfig(deps.env);
    const content = await deps.readFile(path);
    const signer = await (deps.createSigner ?? createSigner)(deps.env);
    const diadoc = await (deps.createDiadoc ?? createDiadoc)(deps.env, deps.stderr);
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
        ...(deps.signal === undefined ? {} : { signal: deps.signal }),
      },
    );
    deps.stdout(`${JSON.stringify(printable(result), null, 2)}\n`);
    return result.outcome === 'error' ? EXIT.docflowError : EXIT.ok;
  } catch (error) {
    deps.stderr(`${describeFailure(error)}\n`);
    return error instanceof PipelineError && error.code === 'NO_DOCUMENT_ENTITY'
      ? EXIT.postedUntracked
      : EXIT.failed;
  }
}

async function createSigner(env: CliEnv): Promise<Signer> {
  return new ServerCmsSigner(await loadServerCmsSignerOptions(env));
}

async function createDiadoc(env: CliEnv, stderr: (text: string) => void): Promise<PipelineDiadoc> {
  const config = await loadDiadocEnv(env);
  const tokenFile = config.refreshTokenFile;
  if (tokenFile !== undefined) await checkTokenFileWritable(tokenFile);
  const auth = new RefreshTokenAuth({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    refreshToken: config.refreshToken,
    ...(config.tokenUrl === undefined ? {} : { tokenUrl: config.tokenUrl }),
    onRefreshTokenRotated: onRefreshTokenRotated(tokenFile, stderr),
  });
  return new DiadocClient({
    auth,
    baseUrl: config.baseUrl,
    ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }),
  });
}

/**
 * A rotated refresh token that cannot be saved is lost for good (the old one may already be dead), so
 * the file and its directory are checked before the first token exchange.
 */
export async function checkTokenFileWritable(tokenFile: string): Promise<void> {
  try {
    await access(tokenFile, constants.R_OK | constants.W_OK);
    await access(dirname(tokenFile), constants.W_OK);
  } catch (error) {
    throw new Error(
      `DIADOC_REFRESH_TOKEN_FILE ${tokenFile}: the file and its directory must be writable`,
      { cause: error },
    );
  }
}

/** Persists a rotated refresh token (write-then-rename, mode 600); without a file only warns. */
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
    // Per-process temp name; the rename is atomic, so a crash never leaves a truncated token file.
    const tmp = `${tokenFile}.${String(process.pid)}.tmp`;
    await writeFile(tmp, `${token}\n`, { mode: 0o600 });
    await rename(tmp, tokenFile);
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
  return `error: ${error instanceof Error ? error.message : String(error)}`;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  const controller = new AbortController();
  process.once('SIGINT', () => {
    controller.abort(new Error('interrupted'));
  });
  process.exitCode = await main(process.argv.slice(2), {
    env: process.env,
    readFile: (path) => fsReadFile(path),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    signal: controller.signal,
  });
}

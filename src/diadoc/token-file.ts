// DIADOC_REFRESH_TOKEN_FILE: the refresh token may rotate on every exchange, and the old one may be
// dead right away, so a rotated token must reach the disk durably, and only one process may use it.
import { constants, unlinkSync } from 'node:fs';
import { access, lstat, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { hostname } from 'node:os';
import { dirname } from 'node:path';

import { DiadocConfigError } from './errors.js';

export interface WriteRefreshTokenFileOptions {
  /** Non-fatal findings (a stale temp file, a directory that cannot be fsynced). */
  warn?: (message: string) => void;
  /** For tests: fsync of the directory. */
  syncDir?: (dir: string) => Promise<void>;
}

export interface LockRefreshTokenFileOptions {
  /** Non-fatal findings (a left-over temp file). */
  warn?: (message: string) => void;
  /** For tests: the device id of a path (`st_dev`). */
  deviceOf?: (path: string) => Promise<number | bigint>;
}

export interface RefreshTokenFileLock {
  readonly lockPath: string;
  /** Removes the lock file; safe to call more than once. */
  release(): Promise<void>;
  /**
   * Removes the lock file synchronously, for a process that exits right away (second signal); never
   * throws for a missing file. `release` afterwards is a no-op.
   */
  releaseSync(): void;
}

/**
 * Checks that the token file can be replaced and takes `<file>.lock` (O_EXCL) for the whole run: two
 * processes exchanging one refresh token would invalidate each other's. Take it before reading the
 * token. A lock left by a killed process (kill -9, OOM, `docker stop` after its grace period) has to
 * be deleted by hand; it records pid, host and start time to tell whose it is. Warns when a
 * `<file>.tmp` from a failed earlier write-back exists: it may hold a newer token than the file.
 */
export async function lockRefreshTokenFile(
  tokenFile: string,
  o: LockRefreshTokenFileOptions = {},
): Promise<RefreshTokenFileLock> {
  await checkReplaceable(tokenFile, o.deviceOf ?? deviceOf);
  const lockPath = `${tokenFile}.lock`;
  let handle;
  try {
    handle = await open(lockPath, 'wx', 0o600);
  } catch (error) {
    if (errorCode(error) !== 'EEXIST') {
      throw new DiadocConfigError(`cannot create the lock file ${lockPath}`, { cause: error });
    }
    const holder = (await readFile(lockPath, 'utf8').catch(() => ''))
      .split('\n')[0]
      ?.replace(/[^\w .:@-]/g, '')
      .slice(0, 200);
    throw new DiadocConfigError(
      `${lockPath} exists: another send is using this refresh token` +
        `${holder ? ` (${holder})` : ''}. If none is running (e.g. after kill -9 or docker stop), ` +
        'delete the lock file',
    );
  }
  try {
    await handle.writeFile(
      `pid ${String(process.pid)} host ${hostname()} since ${new Date().toISOString()}\n`,
    );
    await handle.close();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(lockPath).catch(() => undefined);
    throw new DiadocConfigError(`cannot write the lock file ${lockPath}`, { cause: error });
  }
  const tmp = `${tokenFile}.tmp`;
  if (
    await lstat(tmp).then(
      () => true,
      () => false,
    )
  ) {
    o.warn?.(
      `${tmp} exists: an earlier run could not replace ${tokenFile}, so it may hold a newer ` +
        `refresh token than the file. If this run fails with invalid_grant, stop and move it over ` +
        `${tokenFile}; the next token rotation removes it`,
    );
  }
  let released = false;
  const releaseSync = (): void => {
    if (released) return;
    released = true;
    try {
      unlinkSync(lockPath);
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') throw error;
    }
  };
  return {
    lockPath,
    // Synchronous inside, so a releaseSync racing with it never returns before the file is gone.
    release: async () => {
      releaseSync();
      return Promise.resolve();
    },
    releaseSync,
  };
}

/**
 * Replaces the file atomically and durably: a fresh temp file (O_EXCL, mode 600, a stale one is
 * removed first), fsync, rename, fsync of the directory. Call it under the lock. Errors name the temp
 * file and whether it holds the new token; they never contain the token.
 */
export async function writeRefreshTokenFile(
  tokenFile: string,
  token: string,
  o: WriteRefreshTokenFileOptions = {},
): Promise<void> {
  const tmp = `${tokenFile}.tmp`;
  const warn = o.warn ?? (() => undefined);
  try {
    const stale = await unlink(tmp).then(
      () => true,
      (error: unknown) => {
        if (errorCode(error) !== 'ENOENT') throw error;
        return false;
      },
    );
    // A failed rename in an earlier run leaves the then-newest token there (see below).
    if (stale) warn(`removed a stale ${tmp} left by an earlier run`);
    const handle = await open(tmp, 'wx', 0o600);
    try {
      await handle.writeFile(`${token}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    await unlink(tmp).catch(() => undefined);
    throw new Error(
      `cannot save the rotated Diadoc refresh token: writing ${tmp} failed. The token in ` +
        `${tokenFile} may already be revoked; if so, issue a new one in the integrator cabinet`,
      { cause: error },
    );
  }
  try {
    await rename(tmp, tokenFile);
  } catch (error) {
    throw new Error(
      `cannot replace ${tokenFile}: ${tmp} holds the new refresh token, move it there by hand`,
      { cause: error },
    );
  }
  // The token is in place; some file systems (FUSE, virtiofs) cannot fsync a directory. Failing here
  // would refresh, rotate and fail again on every call.
  try {
    await (o.syncDir ?? syncDir)(dirname(tokenFile));
  } catch (error) {
    warn(
      `saved ${tokenFile}, but could not fsync its directory ` +
        `(${error instanceof Error ? error.message : String(error)}); a power loss may undo the rename`,
    );
  }
}

async function syncDir(dir: string): Promise<void> {
  const handle = await open(dir, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function deviceOf(path: string): Promise<number> {
  return (await stat(path)).dev;
}

async function checkReplaceable(
  tokenFile: string,
  device: (path: string) => Promise<number | bigint>,
): Promise<void> {
  const prefix = `DIADOC_REFRESH_TOKEN_FILE ${tokenFile}`;
  let stats;
  try {
    stats = await lstat(tokenFile);
  } catch (error) {
    throw new DiadocConfigError(`${prefix} cannot be read`, { cause: error });
  }
  // rename() would replace the link itself and leave its target (e.g. a mounted secret) stale.
  if (stats.isSymbolicLink()) {
    throw new DiadocConfigError(`${prefix} is a symlink; point it at the real file`);
  }
  if (!stats.isFile()) throw new DiadocConfigError(`${prefix} is not a regular file`);
  try {
    await access(tokenFile, constants.R_OK | constants.W_OK);
    await access(dirname(tokenFile), constants.W_OK);
  } catch (error) {
    throw new DiadocConfigError(`${prefix}: the file and its directory must be writable`, {
      cause: error,
    });
  }
  // A file mounted on its own (docker `-v host-file:/path`) is a mount point: rename() over it fails
  // with EBUSY, but only at the first rotation, after the IdP has already replaced the token.
  if ((await device(tokenFile)) !== (await device(dirname(tokenFile)))) {
    throw new DiadocConfigError(
      `${prefix} is a mount point (a single-file bind mount?); a rotated token cannot replace it ` +
        'there: mount its directory instead',
    );
  }
}

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
}

import { chmod, mkdir, mkdtemp, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { DiadocConfigError } from './errors.js';
import { lockRefreshTokenFile, writeRefreshTokenFile } from './token-file.js';

const isRoot = process.getuid?.() === 0;
const dirs: string[] = [];

async function tokenFile(content = 'old\n'): Promise<{ dir: string; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'diadoc-rt-'));
  dirs.push(dir);
  const file = join(dir, 'rt');
  await writeFile(file, content, { mode: 0o600 });
  return { dir, file };
}

afterEach(async () => {
  // Restore permissions so vitest's tmp cleanup (and the next test) are not blocked.
  for (const dir of dirs.splice(0)) await chmod(dir, 0o700).catch(() => undefined);
});

const mode = async (path: string): Promise<number> => (await stat(path)).mode & 0o777;

describe('writeRefreshTokenFile', () => {
  it('replaces the file with the token, mode 600, leaving no temp file', async () => {
    const { file } = await tokenFile();
    await writeRefreshTokenFile(file, 'new-token');
    expect(await readFile(file, 'utf8')).toBe('new-token\n');
    expect(await mode(file)).toBe(0o600);
    await expect(stat(`${file}.tmp`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not reuse a stale world-readable temp file', async () => {
    const { file } = await tokenFile();
    await writeFile(`${file}.tmp`, 'stale junk that is longer than the token', { mode: 0o644 });
    await chmod(`${file}.tmp`, 0o644);
    await writeRefreshTokenFile(file, 'new-token');
    expect(await readFile(file, 'utf8')).toBe('new-token\n');
    expect(await mode(file)).toBe(0o600);
  });

  it('warns (does not fail) when the directory cannot be fsynced', async () => {
    const { file } = await tokenFile();
    const warnings: string[] = [];
    await writeRefreshTokenFile(file, 'new-token', {
      warn: (m) => warnings.push(m),
      syncDir: () => Promise.reject(new Error('EINVAL')),
    });
    expect(await readFile(file, 'utf8')).toBe('new-token\n');
    expect(warnings.join('')).toMatch(/could not fsync its directory.*EINVAL/);
  });

  it('warns when it removes a stale temp file', async () => {
    const { file } = await tokenFile();
    await writeFile(`${file}.tmp`, 'older-token\n');
    const warnings: string[] = [];
    await writeRefreshTokenFile(file, 'new-token', { warn: (m) => warnings.push(m) });
    expect(warnings.join('')).toContain(`stale ${file}.tmp`);
    expect(warnings.join('')).not.toContain('older-token');
  });

  it('when the rename fails, names the temp file that still holds the new token', async () => {
    const { dir } = await tokenFile();
    const target = join(dir, 'is-a-dir');
    await mkdir(target);
    await writeFile(join(target, 'x'), '');

    const error = (await writeRefreshTokenFile(target, 'new-token').catch((e: unknown) => e)) as
      Error | undefined;

    expect(error?.message).toContain(`${target}.tmp`);
    expect(error?.message).toMatch(/holds the new refresh token/);
    expect(error?.message).not.toContain('new-token\n');
    expect(await readFile(`${target}.tmp`, 'utf8')).toBe('new-token\n');
  });

  it.skipIf(isRoot)('when the temp file cannot be written, says the token is lost', async () => {
    const { dir, file } = await tokenFile();
    await chmod(dir, 0o500);
    const error = (await writeRefreshTokenFile(file, 'secret-token').catch((e: unknown) => e)) as
      Error | undefined;
    expect(error?.message).toContain(`${file}.tmp`);
    expect(error?.message).toMatch(/integrator cabinet/);
    expect(error?.message).not.toContain('secret-token');
    expect(await readFile(file, 'utf8')).toBe('old\n');
  });
});

describe('lockRefreshTokenFile', () => {
  it('creates an exclusive lock (mode 600) and releases it', async () => {
    const { file } = await tokenFile();
    const lock = await lockRefreshTokenFile(file);
    expect(lock.lockPath).toBe(`${file}.lock`);
    expect(await mode(lock.lockPath)).toBe(0o600);
    expect(await readFile(lock.lockPath, 'utf8')).toMatch(
      new RegExp(`^pid ${String(process.pid)} host \\S+ since \\d{4}-`),
    );

    await lock.release();
    await expect(stat(lock.lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await lock.release(); // idempotent
    await (await lockRefreshTokenFile(file)).release();
  });

  it('refuses a second lock, naming the lock file and the holder', async () => {
    const { file } = await tokenFile();
    const lock = await lockRefreshTokenFile(file);
    const error = await lockRefreshTokenFile(file).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DiadocConfigError);
    expect((error as Error).message).toContain(`${file}.lock`);
    expect((error as Error).message).toContain(`pid ${String(process.pid)} host`);
    expect((error as Error).message).toMatch(/delete/);
    await lock.release();
  });

  it('refuses a symlink (a rename would replace the link, not the target)', async () => {
    const { dir, file } = await tokenFile();
    const link = join(dir, 'link');
    await symlink(file, link);
    await expect(lockRefreshTokenFile(link)).rejects.toThrow(
      new DiadocConfigError(
        `DIADOC_REFRESH_TOKEN_FILE ${link} is a symlink; point it at the real file`,
      ),
    );
    await expect(stat(`${link}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('refuses a missing file or a directory', async () => {
    const { dir } = await tokenFile();
    await expect(lockRefreshTokenFile(join(dir, 'missing'))).rejects.toBeInstanceOf(
      DiadocConfigError,
    );
    await expect(lockRefreshTokenFile(dir)).rejects.toThrow(/not a regular file/);
  });

  it.skipIf(isRoot)('refuses a file whose directory is not writable', async () => {
    const { dir, file } = await tokenFile();
    await chmod(dir, 0o500);
    await expect(lockRefreshTokenFile(file)).rejects.toThrow(
      /the file and its directory must be writable/,
    );
  });
});

import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { checkTokenFileWritable, EXIT, main, onRefreshTokenRotated, type CliDeps } from './cli.js';
import type { PipelineDiadoc, SendUtdResult } from './pipeline/index.js';
import { PipelineError } from './pipeline/index.js';
import type { Signer } from './signer/index.js';

const ENV = { DIADOC_FROM_BOX_ID: 'from', DIADOC_TO_BOX_ID: 'to' };

const RESULT: SendUtdResult = {
  operationId: 'op',
  fileName: 'f.xml',
  fromBoxId: 'from',
  toBoxId: 'to',
  messageId: 'm',
  entityId: 'e',
  contentPlacement: 'inline',
  outcome: 'pending',
  final: false,
  polls: 3,
  warnings: [],
};

function setup(send: CliDeps['send'] = () => Promise.resolve(RESULT), env = ENV) {
  const out: string[] = [];
  const err: string[] = [];
  const sent: { fileName: string; content: Buffer; precheck: boolean | undefined }[] = [];
  const deps: CliDeps = {
    env,
    readFile: (path) =>
      path === '/data/f.xml'
        ? Promise.resolve(Buffer.from('bytes'))
        : Promise.reject(new Error(`ENOENT: ${path}`)),
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    createSigner: () => Promise.resolve({} as Signer),
    createDiadoc: () => Promise.resolve({} as PipelineDiadoc),
    send: (input, d, options) => {
      sent.push({ ...input, precheck: options.precheck });
      return send(input, d, options);
    },
  };
  return { deps, out, err, sent };
}

describe('cli', () => {
  it('prints usage and exits 2 without a command', async () => {
    const { deps, err } = setup();
    expect(await main([], deps)).toBe(EXIT.usage);
    expect(err.join('')).toMatch(/send <file\.xml>/);
    expect(await main(['send'], deps)).toBe(EXIT.usage);
    expect(await main(['send', 'a.xml', '--bogus'], deps)).toBe(EXIT.usage);
    expect(await main(['send', 'a.xml', '-x'], deps)).toBe(EXIT.usage);
  });

  it('--help exits 0', async () => {
    const { deps, out } = setup();
    expect(await main(['--help'], deps)).toBe(EXIT.ok);
    expect(out.join('')).toMatch(/Usage/);
  });

  it('sends the file under its base name and prints the result as JSON', async () => {
    const { deps, out, sent } = setup();
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(sent[0]).toEqual({ fileName: 'f.xml', content: Buffer.from('bytes'), precheck: true });
    expect(JSON.parse(out.join(''))).toMatchObject({ messageId: 'm', outcome: 'pending' });
  });

  it('--no-precheck overrides the config', async () => {
    const { deps, sent } = setup();
    await main(['send', '/data/f.xml', '--no-precheck'], deps);
    expect(sent[0]?.precheck).toBe(false);
  });

  it('exits 3 when the docflow ended in an error, with the status error serialised', async () => {
    const { deps, out } = setup(() =>
      Promise.resolve({ ...RESULT, outcome: 'error', final: true, statusError: new Error('x') }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(JSON.parse(out.join(''))).toMatchObject({ statusError: 'Error: x' });
  });

  it('exits 1 with the pipeline code on stderr', async () => {
    const { deps, err } = setup(() =>
      Promise.reject(
        new PipelineError('SIGNATURE_INVALID', 'verify', 'bad', { operationId: 'op-1' }),
      ),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/SIGNATURE_INVALID.*verify: bad.*op-1/s);
  });

  it('exits 4 when posted but not trackable, printing the messageId', async () => {
    const { deps, err } = setup(() =>
      Promise.reject(
        new PipelineError('NO_DOCUMENT_ENTITY', 'post', 'no entity', { messageId: 'm-9' }),
      ),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.postedUntracked);
    expect(err.join('')).toMatch(/messageId m-9/);
  });

  it('exits 1 on an unreadable file or bad config', async () => {
    const missing = setup();
    expect(await main(['send', '/nope.xml'], missing.deps)).toBe(EXIT.failed);
    expect(missing.err.join('')).toMatch(/^error \[READ_FAILED\] .*ENOENT/);

    const noBoxes = setup(undefined, { DIADOC_FROM_BOX_ID: 'from', DIADOC_TO_BOX_ID: '' });
    expect(await main(['send', '/data/f.xml'], noBoxes.deps)).toBe(EXIT.failed);
    expect(noBoxes.err.join('')).toMatch(/^error \[PIPELINE_CONFIG\] DIADOC_TO_BOX_ID is not set/);
  });

  it('default factories report missing signer env without any network call', async () => {
    const { deps, err } = setup();
    const rest: CliDeps = { ...deps };
    delete rest.createSigner;
    delete rest.createDiadoc;
    expect(await main(['send', '/data/f.xml'], rest)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/^error \[SIGNER_CONFIG\] CRYPTOARM_SERVER_URL is not set/);
  });

  it('prints [DIADOC_CONFIG] when the Diadoc client cannot be set up', async () => {
    const { deps, err } = setup();
    deps.createDiadoc = () => Promise.reject(new Error('DIADOC_CLIENT_ID is not set'));
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/^error \[DIADOC_CONFIG\] DIADOC_CLIENT_ID is not set/);
  });

  it('prints [INTERRUPTED] when aborted by a signal', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGTERM)');
    const { deps, err } = setup(() => {
      controller.abort(reason);
      return Promise.reject(reason);
    });
    deps.signal = controller.signal;
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/^error \[INTERRUPTED\] interrupted \(SIGTERM\)/);
  });

  it('prints [UNEXPECTED] for a failure outside the pipeline error codes', async () => {
    const { deps, err } = setup(() => Promise.reject(new Error('boom')));
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/^error \[UNEXPECTED\] boom/);
  });
});

describe('refresh token persistence', () => {
  it('writes the rotated token atomically with mode 600', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'old\n');
    await onRefreshTokenRotated(file, () => undefined)('new-token');
    expect(await readFile(file, 'utf8')).toBe('new-token\n');
    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it('without a file only warns, never printing the token', async () => {
    const err: string[] = [];
    await onRefreshTokenRotated(undefined, (s) => err.push(s))('secret-token');
    expect(err.join('')).toMatch(/DIADOC_REFRESH_TOKEN_FILE/);
    expect(err.join('')).not.toMatch(/secret-token/);
  });

  it('checks up front that the token file can be replaced', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'x');
    await expect(checkTokenFileWritable(file)).resolves.toBeUndefined();
    await expect(checkTokenFileWritable(join(dir, 'missing', 'rt'))).rejects.toThrow(
      /DIADOC_REFRESH_TOKEN_FILE/,
    );
  });
});

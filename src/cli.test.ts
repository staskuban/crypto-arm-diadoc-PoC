import { access, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  EXIT,
  interruptHandler,
  main,
  onRefreshTokenRotated,
  type CliDeps,
  type CliEnv,
  type RunState,
} from './cli.js';
import { POST_MESSAGE_BUDGET_MS, SHELF_MAX_BYTES, type Message } from './diadoc/index.js';
import type { PipelineDiadoc, SendUtdResult } from './pipeline/index.js';
import { PipelineError } from './pipeline/index.js';
import type { Signer } from './signer/index.js';

const ENV = { DIADOC_FROM_BOX_ID: 'from', DIADOC_TO_BOX_ID: 'to' };

const RESULT: SendUtdResult = {
  operationId: 'op',
  customDocumentId: '6f9619ff-8b86-d011-b42d-00cf4fc964ff',
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

function setup(send: CliDeps['send'] = () => Promise.resolve(RESULT), env: CliEnv = ENV) {
  const out: string[] = [];
  const err: string[] = [];
  const sent: {
    fileName: string;
    content: Buffer;
    precheck: boolean | undefined;
    resend?: string | undefined;
  }[] = [];
  const deps: CliDeps = {
    env,
    readFile: (path) =>
      path === '/data/f.xml'
        ? Promise.resolve(Buffer.from('bytes'))
        : Promise.reject(new Error(`ENOENT: ${path}`)),
    fileSize: (path) =>
      path === '/data/f.xml' ? Promise.resolve(5) : Promise.reject(new Error(`ENOENT: ${path}`)),
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    createSigner: () => Promise.resolve({} as Signer),
    createDiadoc: () => Promise.resolve({} as PipelineDiadoc),
    send: (input, d, options) => {
      sent.push({
        ...input,
        precheck: options.precheck,
        ...('resend' in options ? { resend: options.resend } : {}),
      });
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

  it('takes everything after -- as the file, so a name may start with -', async () => {
    const { deps, sent } = setup();
    const read: string[] = [];
    deps.fileSize = () => Promise.resolve(5);
    deps.readFile = (path) => {
      read.push(path);
      return Promise.resolve(Buffer.from('bytes'));
    };
    expect(await main(['send', '--no-precheck', '--', '-f.xml'], deps)).toBe(EXIT.ok);
    expect(read).toEqual(['-f.xml']);
    expect(sent[0]).toMatchObject({ fileName: '-f.xml', precheck: false });
  });

  it.each([
    [['send', '--', 'a.xml', '--no-precheck']],
    [['send', '--', 'a.xml', 'b.xml']],
    [['send', '--']],
    [['send', 'a.xml', '--', 'b.xml']],
  ])('%j is usage', async (argv) => {
    const { deps, sent } = setup();
    expect(await main(argv, deps)).toBe(EXIT.usage);
    expect(sent).toHaveLength(0);
  });

  it('refuses a file above the shelf maximum by its size, before reading it', async () => {
    const { deps, err, sent } = setup();
    const read: string[] = [];
    deps.fileSize = () => Promise.resolve(SHELF_MAX_BYTES + 1);
    deps.readFile = (path) => {
      read.push(path);
      return Promise.resolve(Buffer.from('bytes'));
    };
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(
      new RegExp(
        `^error \\[CONTENT_TOO_LARGE\\] .*f\\.xml is ${String(SHELF_MAX_BYTES + 1)} bytes`,
      ),
    );
    expect(read).toEqual([]);
    expect(sent).toHaveLength(0);
  });

  it('a failing size check is READ_FAILED', async () => {
    const { deps, err } = setup();
    deps.fileSize = () => Promise.reject(new Error('EACCES: permission denied'));
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/^error \[READ_FAILED\] EACCES/);
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

  it('--resend passes a fresh random salt and says how to repeat that resend', async () => {
    const first = setup();
    const second = setup();
    expect(await main(['send', '/data/f.xml', '--resend'], first.deps)).toBe(EXIT.ok);
    await main(['send', '--resend', '/data/f.xml'], second.deps);
    const salt = first.sent[0]?.resend ?? '';
    expect(salt).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(second.sent[0]?.resend).not.toBe(salt);
    expect(first.err.join('')).toContain(`--resend=${salt}`);
  });

  it('--resend=<salt> passes that salt', async () => {
    const { deps, sent, err } = setup();
    expect(await main(['send', '/data/f.xml', '--resend=retry-2'], deps)).toBe(EXIT.ok);
    expect(sent[0]?.resend).toBe('retry-2');
    expect(err.join('')).toContain('--resend=retry-2');
  });

  it('without --resend no salt is passed', async () => {
    const { deps, sent, err } = setup();
    await main(['send', '/data/f.xml'], deps);
    expect(sent[0]).not.toHaveProperty('resend');
    expect(err.join('')).not.toMatch(/resend/);
  });

  it.each([['--resend='], ['--resend=a b'], ['--resend=-x'], ['--resend', '--resend=a']])(
    'rejects %j as usage',
    async (...flags) => {
      const { deps, err, sent } = setup();
      expect(await main(['send', '/data/f.xml', ...flags], deps)).toBe(EXIT.usage);
      expect(err.join('')).toMatch(/resend/);
      expect(sent).toHaveLength(0);
    },
  );

  it('exits 3 when the docflow ended in an error, with the status error serialised', async () => {
    const { deps, out } = setup(() =>
      Promise.resolve({ ...RESULT, outcome: 'error', final: true, statusError: new Error('x') }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(JSON.parse(out.join(''))).toMatchObject({ statusError: 'Error: x' });
  });

  it('names why Diadoc rejected the sender signature (D203), still exit 3', async () => {
    const { deps, out, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        outcome: 'error',
        final: true,
        status: { PrimaryStatus: { Severity: 'Error', StatusText: 'Ошибка в подписи' } },
        signatureCheck: {
          senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
          reason: 'certificate',
          mathValid: true,
          certificateValid: false,
          chainProblems: ['PARTIAL_CHAIN'],
          delivered: false,
          deliveryFailure: 'не была доставлена',
          powerOfAttorney: [],
          lookupErrors: [],
        },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(err.join('')).toMatch(
      /^docflow error \[SENDER_CERTIFICATE_REJECTED\] .*PARTIAL_CHAIN.*not delivered: не была доставлена.* \(operationId op, messageId m\)$/m,
    );
    expect(JSON.parse(out.join(''))).toMatchObject({ signatureCheck: { reason: 'certificate' } });
  });

  it('exits 3 for a rejected sender signature while the status is still pending', async () => {
    const { deps, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        signatureCheck: {
          reason: 'signature',
          mathValid: false,
          chainProblems: [],
          powerOfAttorney: [],
          lookupErrors: [],
        },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(err.join('')).toMatch(/^docflow error \[SENDER_SIGNATURE_REJECTED\] /m);
  });

  it('exits 3 for an invalid SenderSignatureStatus whose lookups failed (pending status)', async () => {
    const { deps, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        signatureCheck: {
          reason: 'unknown',
          senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
          chainProblems: [],
          powerOfAttorney: [],
          lookupErrors: ['GetMessage: busy'],
        },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(err.join('')).toMatch(/^docflow error \[SENDER_SIGNATURE_REJECTED\] /m);
  });

  it('keeps the status text of an error that is not about the signature', async () => {
    const { deps, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        outcome: 'error',
        final: true,
        status: { PrimaryStatus: { Severity: 'Error', StatusText: 'Ошибка доставки' } },
        signatureCheck: {
          reason: 'none',
          chainProblems: [],
          powerOfAttorney: [],
          lookupErrors: [],
        },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(err.join('')).toMatch(/^docflow error \[DOCFLOW_ERROR\] Ошибка доставки/m);
  });

  it('exits 0 when the check found no problem and the status is not an error', async () => {
    const { deps, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        signatureCheck: {
          reason: 'none',
          chainProblems: [],
          powerOfAttorney: [],
          lookupErrors: [],
        },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(err.join('')).not.toMatch(/docflow error/);
  });

  it('prints a plain docflow error line without a signature check', async () => {
    const { deps, err } = setup(() =>
      Promise.resolve({
        ...RESULT,
        outcome: 'error',
        final: true,
        status: { PrimaryStatus: { Severity: 'Error', StatusText: 'Ошибка' } },
      }),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.docflowError);
    expect(err.join('')).toMatch(
      /^docflow error \[DOCFLOW_ERROR\] Ошибка \(operationId op, messageId m\)$/m,
    );
  });

  it('passes GetMessage, GetSignatureInfo and GetOrganization through to the Diadoc client', async () => {
    const seen: string[] = [];
    const { deps } = setup(async (_input, d) => {
      await d.diadoc.getOrganization('b');
      await d.diadoc.getMessage('b', 'm');
      await d.diadoc.getSignatureInfo({ boxId: 'b', messageId: 'm', entityId: 's' });
      return RESULT;
    });
    deps.createDiadoc = () =>
      Promise.resolve({
        getOrganization: () => {
          seen.push('getOrganization');
          return Promise.resolve({ IsTest: true });
        },
        getMessage: () => {
          seen.push('getMessage');
          return Promise.resolve({ MessageId: 'm' });
        },
        getSignatureInfo: () => {
          seen.push('getSignatureInfo');
          return Promise.resolve({});
        },
      } as unknown as PipelineDiadoc);
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(seen).toEqual(['getOrganization', 'getMessage', 'getSignatureInfo']);
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

  it('exits 1 with DIADOC_AUTH and the hint for a rejected refresh token', async () => {
    const { deps, err } = setup(() =>
      Promise.reject(
        new PipelineError(
          'DIADOC_AUTH',
          'precheck',
          'Token endpoint https://idp/token -> 400: {"error":"invalid_grant"}; the refresh token ' +
            'was rejected (…): issue a new one in the integrator cabinet',
          { operationId: 'op-1' },
        ),
      ),
    );
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(
      /^error \[DIADOC_AUTH\] precheck: .*invalid_grant.*integrator cabinet.*\(operationId op-1\)$/m,
    );
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

  it.each([
    [{ SIGNER_KIND: 'documents' }, /^error \[SIGNER_CONFIG\] DOCUMENTS_URL is not set/],
    [
      { SIGNER_KIND: 'hsm' },
      /^error \[SIGNER_CONFIG\] SIGNER_KIND must be "server", "documents" or "diadoc-test"/,
    ],
  ])('default signer factory honours SIGNER_KIND %j', async (extra, message) => {
    const { deps, err } = setup(undefined, { ...ENV, ...extra });
    const rest: CliDeps = { ...deps };
    delete rest.createSigner;
    expect(await main(['send', '/data/f.xml'], rest)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(message);
  });

  it('SIGNER_KIND=diadoc-test passes the Diadoc test signature without any signer env', async () => {
    const signers: unknown[] = [];
    const { deps, out } = setup(
      (_input, d) => {
        signers.push(d.signer);
        return Promise.resolve({ ...RESULT, testSignature: true });
      },
      { ...ENV, SIGNER_KIND: 'diadoc-test' },
    );
    const rest: CliDeps = { ...deps };
    delete rest.createSigner;
    expect(await main(['send', '/data/f.xml'], rest)).toBe(EXIT.ok);
    expect(signers).toEqual(['diadoc-test']);
    expect(JSON.parse(out.join(''))).toMatchObject({ testSignature: true });
  });

  it('default signer factory refuses a bad certificate and plain http at start (F13)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-cert-'));
    const cert = join(dir, 'signer.cer');
    await writeFile(
      cert,
      '-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n',
    );
    const cases: [CliEnv, RegExp][] = [
      [
        { CRYPTOARM_SERVER_URL: 'http://127.0.0.1:3037', SIGNER_CERT_PATH: cert },
        /^error \[SIGNER_CONFIG\] SIGNER_CERT_PATH .*signer\.cer/,
      ],
      [
        { CRYPTOARM_SERVER_URL: 'http://cryptoarm.example.com', SIGNER_CERT_PATH: cert },
        /^error \[SIGNER_CONFIG\] CRYPTOARM_SERVER_URL must use https/,
      ],
    ];
    for (const [extra, message] of cases) {
      const { deps, err, sent } = setup(undefined, { ...ENV, ...extra });
      const rest: CliDeps = { ...deps };
      delete rest.createSigner;
      expect(await main(['send', '/data/f.xml'], rest)).toBe(EXIT.failed);
      expect(err.join('')).toMatch(message);
      expect(sent).toEqual([]);
    }
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

  const diadocEnv = (file: string) => ({
    ...ENV,
    DIADOC_API_URL: 'https://diadoc-api-staging.kontur.ru',
    DIADOC_CLIENT_ID: 'cid',
    DIADOC_CLIENT_SECRET: 'secret',
    DIADOC_REFRESH_TOKEN_FILE: file,
  });

  it('holds <file>.lock while sending and removes it afterwards', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    let lockedDuringSend = false;
    const { deps } = setup(async () => {
      lockedDuringSend = await access(`${file}.lock`).then(
        () => true,
        () => false,
      );
      return RESULT;
    }, diadocEnv(file));
    delete deps.createDiadoc;

    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(lockedDuringSend).toBe(true);
    await expect(access(`${file}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('refuses to run while another process holds the lock, and keeps its lock', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    await writeFile(`${file}.lock`, 'pid 4242 host box since 2026-09-24T00:00:00.000Z\n');
    const { deps, err, sent } = setup(undefined, diadocEnv(file));
    delete deps.createDiadoc;

    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/lock.*pid 4242/);
    expect(sent).toHaveLength(0);
    expect(await readFile(`${file}.lock`, 'utf8')).toMatch(/^pid 4242/);
  });

  it('releases the lock when the Diadoc config is invalid', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    const { deps, err } = setup(undefined, { ...diadocEnv(file), DIADOC_CLIENT_ID: '' });
    delete deps.createDiadoc;

    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    expect(err.join('')).toMatch(/DIADOC_CLIENT_ID/);
    await expect(access(`${file}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('a failing lock release is a warning and keeps the exit code', async () => {
    const { deps, err } = setup();
    deps.createDiadoc = () =>
      Promise.resolve({
        close: () => Promise.reject(new Error('EROFS: lock not removed')),
      } as unknown as PipelineDiadoc);
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(err.join('')).toMatch(/warning: EROFS/);
  });
});

describe('interrupt', () => {
  it('first signal aborts and says PostMessage finishes within its budget', () => {
    const controller = new AbortController();
    const err: string[] = [];
    const exits: number[] = [];
    interruptHandler(
      controller,
      (t) => err.push(t),
      {},
      (code) => exits.push(code),
    )('SIGINT');
    expect(controller.signal.aborted).toBe(true);
    expect(err.join('')).toMatch(/after the current step.*again/s);
    expect(err.join('')).toContain(`${String(POST_MESSAGE_BUDGET_MS / 1000)} s`);
    expect(exits).toEqual([]);
  });

  it('second signal removes the lock synchronously, prints the operationId and exits', () => {
    const controller = new AbortController();
    const err: string[] = [];
    const exits: number[] = [];
    const released: string[] = [];
    const state: RunState = {
      operationId: 'op-7',
      releaseLockSync: () => released.push('lock'),
    };
    const handler = interruptHandler(
      controller,
      (t) => err.push(t),
      state,
      (code) => exits.push(code),
    );
    handler('SIGTERM');
    handler('SIGTERM');
    expect(released).toEqual(['lock']);
    expect(err.join('')).toMatch(/operationId op-7.*may have been posted.*look it up/s);
    expect(exits).toEqual([143]);
  });

  it('second signal before PostMessage says nothing was posted; SIGINT exits 130', () => {
    const err: string[] = [];
    const exits: number[] = [];
    const handler = interruptHandler(
      new AbortController(),
      (t) => err.push(t),
      {},
      (code) => exits.push(code),
    );
    handler('SIGINT');
    handler('SIGINT');
    expect(err.join('')).toMatch(/nothing was posted/);
    expect(exits).toEqual([130]);
  });

  it('second signal after the post prints messageId too; a failing unlink is only a warning', () => {
    const err: string[] = [];
    const exits: number[] = [];
    const state: RunState = {
      operationId: 'op-7',
      messageId: 'm-1',
      releaseLockSync: () => {
        throw new Error('EROFS');
      },
    };
    const handler = interruptHandler(
      new AbortController(),
      (t) => err.push(t),
      state,
      (code) => exits.push(code),
    );
    handler('SIGTERM');
    handler('SIGINT');
    expect(err.join('')).toMatch(/operationId op-7, messageId m-1/);
    expect(err.join('')).toMatch(/warning: .*EROFS/);
    expect(exits).toEqual([130]);
  });
});

describe('second signal while a rotated token is being saved', () => {
  it('names the temp file that may hold the new token', () => {
    const err: string[] = [];
    const handler = interruptHandler(
      new AbortController(),
      (t) => err.push(t),
      { savingTokenFile: '/v/rt' },
      () => undefined,
    );
    handler('SIGTERM');
    handler('SIGTERM');
    expect(err.join('')).toMatch(/rotated refresh token was being saved.*\/v\/rt\.tmp/s);
  });

  it('onRefreshTokenRotated marks the save in the run state while it runs', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'old\n');
    const state: RunState = {};
    const saving = onRefreshTokenRotated(file, () => undefined, state)('new-token');
    expect(state.savingTokenFile).toBe(file);
    await saving;
    expect(state.savingTokenFile).toBeUndefined();
  });
});

describe('run state for the second signal', () => {
  const posted: Message = { MessageId: 'm-1' };

  it('records the operationId when PostMessage starts and the messageId when it answers', async () => {
    const state: RunState = {};
    const seen: RunState[] = [];
    const { deps } = setup(async (_input, d) => {
      const message = d.diadoc.postMessage(
        { FromBoxId: 'from', ToBoxId: 'to', DocumentAttachments: [] },
        { operationId: 'op-7' },
      );
      seen.push({ ...state });
      await message;
      seen.push({ ...state });
      return RESULT;
    });
    deps.state = state;
    deps.createDiadoc = () =>
      Promise.resolve({
        postMessage: () => Promise.resolve(posted),
      } as unknown as PipelineDiadoc);
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(seen[0]).toMatchObject({ operationId: 'op-7' });
    expect(seen[0]?.messageId).toBeUndefined();
    expect(seen[1]).toMatchObject({ operationId: 'op-7', messageId: 'm-1' });
  });

  it('can remove the lock as soon as it is taken, before the Diadoc config is read', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    const state: RunState = {};
    const env = {
      ...ENV,
      DIADOC_API_URL: 'https://diadoc-api-staging.kontur.ru',
      DIADOC_CLIENT_ID: '',
      DIADOC_REFRESH_TOKEN_FILE: file,
    };
    const { deps } = setup(undefined, env);
    delete deps.createDiadoc;
    deps.state = state;
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.failed);
    // The config failed after the lock was taken: releaseLockSync was set by then.
    expect(state.releaseLockSync).toBeTypeOf('function');
  });

  it('can remove the real refresh-token lock synchronously while sending', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    const state: RunState = {};
    let lockGone = false;
    const { deps } = setup(
      async () => {
        state.releaseLockSync?.();
        lockGone = await access(`${file}.lock`).then(
          () => false,
          () => true,
        );
        return RESULT;
      },
      {
        ...ENV,
        DIADOC_API_URL: 'https://diadoc-api-staging.kontur.ru',
        DIADOC_CLIENT_ID: 'cid',
        DIADOC_CLIENT_SECRET: 'secret',
        DIADOC_REFRESH_TOKEN_FILE: file,
      },
    );
    delete deps.createDiadoc;
    deps.state = state;
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(lockGone).toBe(true);
  });

  it('warns at start about a left-over refresh-token temp file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'cli-rt-'));
    const file = join(dir, 'rt');
    await writeFile(file, 'rt\n', { mode: 0o600 });
    await writeFile(`${file}.tmp`, 'tmp-token-value\n', { mode: 0o600 });
    const { deps, err } = setup(undefined, {
      ...ENV,
      DIADOC_API_URL: 'https://diadoc-api-staging.kontur.ru',
      DIADOC_CLIENT_ID: 'cid',
      DIADOC_CLIENT_SECRET: 'secret',
      DIADOC_REFRESH_TOKEN_FILE: file,
    });
    delete deps.createDiadoc;
    expect(await main(['send', '/data/f.xml'], deps)).toBe(EXIT.ok);
    expect(err.join('')).toContain(`warning: ${file}.tmp`);
    expect(err.join('')).not.toContain('tmp-token-value');
  });
});

describe('docker compose app service', () => {
  it('stop_grace_period covers the PostMessage time budget plus a margin', async () => {
    const compose = await readFile(new URL('../docker-compose.yml', import.meta.url), 'utf8');
    const app = /^ {2}app:\n((?: {4}.*\n|\s*\n)+)/m.exec(compose)?.[1] ?? '';
    const grace = /^ {4}stop_grace_period: (\d+)s$/m.exec(app)?.[1];
    expect(grace).toBeDefined();
    expect(Number(grace) * 1000).toBeGreaterThanOrEqual(POST_MESSAGE_BUDGET_MS + 15_000);
  });
});

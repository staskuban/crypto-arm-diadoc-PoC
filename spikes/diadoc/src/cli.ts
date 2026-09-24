// S1 spike CLI. Usage: node src/cli.ts <command> [options]; see README.md.
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { basename, join, dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { loadEnv, requireVars } from './env.ts';
import { chooseRefreshToken, refreshAccessToken } from './auth.ts';
import { DiadocClient } from './client.ts';
import { buildMinimalUtd, readIdFile, type Party, type UtdParams } from './utd.ts';
import { buildUtdAttachment, pickUtdType, readSignatureFile, UTD_TYPE } from './attachment.ts';
import { mainEntity, partyFromOrganization, toBoxGuid } from './org.ts';

const ROOT = join(dirname(new URL(import.meta.url).pathname), '..');
const STATE = join(ROOT, '.state'); // git-ignored: tokens and last message ids
const OUT = join(ROOT, 'out'); // git-ignored: raw API responses
const FUNCTION = 'СЧФДОП';
const VERSION = 'utd970_05_03_01';

const env = loadEnv(join(ROOT, '.env'));
const apiUrl = env.DIADOC_API_URL || 'https://diadoc-api-staging.kontur.ru';
const tokenUrl = env.DIADOC_TOKEN_URL || 'https://identity.kontur.ru/connect/token';

function save(dir: string, name: string, data: unknown): string {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, name);
  // .state holds live tokens: owner-only
  writeFileSync(file, Buffer.isBuffer(data) ? data : JSON.stringify(data, null, 2) + '\n', { mode: dir === STATE ? 0o600 : 0o644 });
  return file;
}

function load<T>(dir: string, name: string): T | undefined {
  const file = join(dir, name);
  return existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as T) : undefined;
}

type Tokens = { accessToken: string; refreshToken: string; sourceRefreshToken: string; expiresAt: number; tokenUrl: string; clientId: string };

/**
 * Reuses a cached access token of the same IdP/client; otherwise refreshes with the rotated refresh token
 * from .state, unless DIADOC_REFRESH_TOKEN in .env was replaced since (see chooseRefreshToken).
 */
async function accessToken(force = false): Promise<string> {
  const v = requireVars(env, ['DIADOC_CLIENT_ID', 'DIADOC_CLIENT_SECRET', 'DIADOC_REFRESH_TOKEN']);
  const stored = load<Tokens>(STATE, 'tokens.json');
  const cached = stored?.tokenUrl === tokenUrl && stored.clientId === v.DIADOC_CLIENT_ID ? stored : undefined;
  if (!force && cached && cached.sourceRefreshToken === v.DIADOC_REFRESH_TOKEN && cached.expiresAt - Date.now() > 5 * 60_000) {
    return cached.accessToken;
  }
  const refreshToken = chooseRefreshToken(v.DIADOC_REFRESH_TOKEN, cached);
  let t;
  try {
    t = await refreshAccessToken({ tokenUrl, clientId: v.DIADOC_CLIENT_ID, clientSecret: v.DIADOC_CLIENT_SECRET, refreshToken });
  } catch (e) {
    if (/invalid_grant/.test((e as Error).message)) {
      console.error(
        refreshToken === v.DIADOC_REFRESH_TOKEN
          ? 'hint: the refresh token in .env is expired/revoked or was already rotated; issue a new one in the integrator cabinet'
          : 'hint: the rotated refresh token in .state/tokens.json is no longer valid; issue a new one in the integrator cabinet and put it into .env',
      );
    }
    throw e;
  }
  save(STATE, 'tokens.json', {
    accessToken: t.accessToken,
    refreshToken: t.refreshToken,
    sourceRefreshToken: v.DIADOC_REFRESH_TOKEN,
    expiresAt: Date.now() + t.expiresIn * 1000,
    tokenUrl,
    clientId: v.DIADOC_CLIENT_ID,
  } satisfies Tokens);
  console.log(`token: ok, expires_in=${t.expiresIn}s, refresh_token ${t.refreshToken !== refreshToken ? 'ROTATED (saved to .state/tokens.json)' : 'unchanged'}`);
  return t.accessToken;
}

const client = async () => new DiadocClient({ baseUrl: apiUrl, accessToken: await accessToken() });
/** Message bodies get the id as configured (Diadoc samples use <hex>@diadoc.ru); query strings need the GUID. */
function boxes() {
  const v = requireVars(env, ['DIADOC_FROM_BOX_ID', 'DIADOC_TO_BOX_ID']);
  return { from: v.DIADOC_FROM_BOX_ID, to: v.DIADOC_TO_BOX_ID, fromGuid: toBoxGuid(v.DIADOC_FROM_BOX_ID), toGuid: toBoxGuid(v.DIADOC_TO_BOX_ID) };
}
const fromBoxGuid = () => toBoxGuid(requireVars(env, ['DIADOC_FROM_BOX_ID']).DIADOC_FROM_BOX_ID);

/** Online documents need the real signer (the service account / certificate owner); only the offline fixture uses a placeholder. */
function signer(offline: boolean): UtdParams['signer'] {
  if (offline) return { lastName: 'Иванов', firstName: 'Иван', middleName: 'Иванович', position: 'Генеральный директор' };
  const v = requireVars(env, ['UTD_SIGNER_LAST_NAME', 'UTD_SIGNER_FIRST_NAME']);
  return {
    lastName: v.UTD_SIGNER_LAST_NAME,
    firstName: v.UTD_SIGNER_FIRST_NAME,
    middleName: env.UTD_SIGNER_MIDDLE_NAME || undefined,
    position: env.UTD_SIGNER_POSITION || undefined,
  };
}

// Placeholder parties for the committed offline fixture: synthetic checksum-valid INNs, fake participant ids.
const OFFLINE_SELLER: Party = {
  name: 'ООО «Тестовый продавец»', inn: '7700000016', kpp: '773601001',
  fnsParticipantId: '2BM-7700000016-773601001-000000000000000000001', regionCode: '77', regionName: 'г. Москва',
};
const OFFLINE_BUYER: Party = {
  name: 'ООО «Тестовый покупатель»', inn: '7700000023', kpp: '773601001',
  fnsParticipantId: '2BM-7700000023-773601001-000000000000000000002', regionCode: '77', regionName: 'г. Москва',
};

async function buildUtd(offline: boolean) {
  let seller = OFFLINE_SELLER;
  let buyer = OFFLINE_BUYER;
  if (!offline) {
    const c = await client();
    const b = boxes();
    const [from, to] = await Promise.all([c.getOrganizationByBoxId(b.fromGuid), c.getOrganizationByBoxId(b.toGuid)]);
    seller = partyFromOrganization(from);
    buyer = partyFromOrganization(to);
  }
  const now = new Date();
  return buildMinimalUtd({ seller, buyer, signer: signer(offline), documentNumber: `S1-${now.getTime()}`, date: now, guid: randomUUID(), signerPowers: env.UTD_SIGNER_POWERS === '6' ? '6' : '1' });
}

const commands: Record<string, (o: Record<string, string | boolean | undefined>) => Promise<void>> = {
  async token() {
    await accessToken(true);
  },

  async orgs() {
    const r = await (await client()).getMyOrganizations();
    console.log(`GetMyOrganizations -> ${save(OUT, 'my-organizations.json', r)}`);
    for (const o of r.Organizations ?? []) {
      console.log(`- ${o.ShortName ?? o.FullName} INN=${o.Inn} KPP=${o.Kpp} IsTest=${o.IsTest} FnsParticipantId=${o.FnsParticipantId}`);
      for (const b of o.Boxes ?? []) console.log(`    box ${b.BoxIdGuid} (${b.BoxId}) "${b.Title}"`);
    }
  },

  async types() {
    const box = fromBoxGuid();
    const r = await (await client()).getDocumentTypes(box);
    save(OUT, 'document-types.json', r);
    const utd = pickUtdType(r);
    if (!utd) throw new Error(`${UTD_TYPE} is not available in box ${box}`);
    console.log(`GetDocumentTypes(V3) ${UTD_TYPE} -> ${save(OUT, 'utd-type.json', utd)}`);
    for (const f of (utd.Functions as any[]) ?? []) {
      const versions = (f.Versions ?? []).map((v: any) => `${v.Version}${v.IsActual ? '' : ' (not actual)'}`);
      console.log(`- ${f.Name}: ${versions.join(', ')}`);
    }
  },

  async fixture(o) {
    const utd = await buildUtd(Boolean(o.offline));
    const dir = o.offline ? join(ROOT, 'fixtures') : OUT;
    console.log(`УПД ${FUNCTION} ${VERSION}: ${save(dir, utd.fileName, utd.content)} (${utd.content.length} bytes, windows-1251)`);
  },

  async generate(o) {
    if (typeof o['user-data'] !== 'string') throw new Error('--user-data <UserContract XML file> is required');
    const box = fromBoxGuid();
    const r = await (await client()).generateTitleXml({ boxId: box, function: FUNCTION, version: VERSION, userDataXml: readFileSync(o['user-data']) });
    const name = r.fileName ?? `${readIdFile(r.content) ?? 'generated'}.xml`;
    console.log(`GenerateTitleXml -> ${save(OUT, name, r.content)}`);
  },

  async post(o) {
    // A PostMessage that did not finish is re-sent with the same operationId and body, so Diadoc
    // returns the original result instead of creating a duplicate document.
    const pending = load<{ operationId: string; message: unknown; signature: string }>(STATE, 'pending-post.json');
    if (pending && !o.resume) throw new Error('.state/pending-post.json exists: re-run with --resume, or delete it to start over');
    if (!pending && o.resume) throw new Error('nothing to resume');

    let op = pending;
    if (!op) {
      if (!o['test-signature'] && typeof o.signature !== 'string') throw new Error('pass --test-signature or --signature <detached CMS file>');
      // a detached CMS covers specific bytes: never pair it with a freshly generated document
      if (typeof o.signature === 'string' && typeof o.xml !== 'string') throw new Error('--signature needs --xml <the exact file that was signed>');
      const b = boxes();
      const c = await client();

      let content: Buffer;
      if (typeof o.xml === 'string') {
        content = readFileSync(o.xml);
        const idFile = readIdFile(content);
        if (`${idFile}.xml` !== basename(o.xml)) console.warn(`WARNING: file name ${basename(o.xml)} != @ИдФайл ${idFile} (ФНС rule 0400400007)`);
      } else {
        const utd = await buildUtd(false);
        content = utd.content;
        console.log(`УПД -> ${save(OUT, utd.fileName, content)}`);
      }

      const customDocumentId = randomUUID();
      const can = await c.canPostMessage({
        FromBoxId: b.from,
        ToBoxId: b.to,
        DocumentPrototypes: [{ CustomDocumentId: customDocumentId, TypeNamedId: UTD_TYPE, Function: FUNCTION, Version: VERSION }],
      });
      console.log(`CanPostMessage -> ${save(OUT, 'can-post-message.json', can)}`);
      if (can.Errors?.length) throw new Error(`CanPostMessage errors: ${JSON.stringify(can.Errors)}`);

      const signature = o['test-signature'] ? 'test' : readSignatureFile(readFileSync(o.signature as string));
      const message = {
        FromBoxId: b.from,
        ToBoxId: b.to,
        DocumentAttachments: [buildUtdAttachment({ content, function: FUNCTION, version: VERSION, signature, customDocumentId })],
      };
      op = { operationId: randomUUID(), message, signature: o['test-signature'] ? 'test' : (o.signature as string) };
      save(STATE, 'pending-post.json', op);
    }

    const r = await (await client()).postMessage(op.message, op.operationId);
    console.log(`PostMessage(V3) operationId=${op.operationId} -> ${save(OUT, 'post-message.json', r)}`);
    rmSync(join(STATE, 'pending-post.json'));
    const entity = mainEntity(r);
    if (!entity?.EntityId) throw new Error('PostMessage response has no document entity');
    save(STATE, 'last-post.json', { messageId: r.MessageId, entityId: entity.EntityId, signature: op.signature });
    console.log(`MessageId=${r.MessageId} EntityId=${entity.EntityId}`);
  },

  async status(o) {
    const last = load<{ messageId: string; entityId: string }>(STATE, 'last-post.json');
    const messageId = (o['message-id'] as string | undefined) ?? last?.messageId;
    const entityId = (o['entity-id'] as string | undefined) ?? last?.entityId;
    if (!messageId || !entityId) throw new Error('no --message-id/--entity-id and no .state/last-post.json');
    const box = fromBoxGuid();
    const r = await (await client()).getDocument(box, messageId, entityId);
    console.log(`GetDocument(V3) -> ${save(OUT, 'document.json', r)}`);
    console.log(`DocflowStatus: ${JSON.stringify(r.DocflowStatus, null, 2)}`);
  },

  async all(o) {
    for (const step of ['token', 'orgs', 'types', 'post', 'status'] as const) {
      console.log(`\n== ${step}`);
      await commands[step](o);
    }
  },
};

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    offline: { type: 'boolean' },
    'test-signature': { type: 'boolean' },
    resume: { type: 'boolean' },
    signature: { type: 'string' },
    xml: { type: 'string' },
    'user-data': { type: 'string' },
    'message-id': { type: 'string' },
    'entity-id': { type: 'string' },
  },
});

const cmd = commands[positionals[0] ?? ''];
if (!cmd) {
  console.error(`usage: node src/cli.ts <${Object.keys(commands).join('|')}> [options]  (see README.md)`);
  process.exit(2);
}
try {
  await cmd(values);
} catch (e) {
  console.error(`ERROR: ${(e as Error).message}`);
  process.exit(1);
}

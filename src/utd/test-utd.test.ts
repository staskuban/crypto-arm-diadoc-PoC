import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseUtd } from './index.js';
import type { Organization } from '../diadoc/index.js';
import {
  buildTestUtd,
  makeTestUtd,
  MAX_TEST_UTD_BYTES,
  partyFromOrganization,
  TestUtdRefusedError,
  type TestUtdParams,
} from './test-utd.js';

const XSD = new URL('../../spikes/diadoc/xsd/ON_NSCHFDOPPR_1_997_01_05_03_05.xsd', import.meta.url)
  .pathname;

const PARAMS: TestUtdParams = {
  seller: partyFromOrganization({
    FullName: 'Тестовая организация №2031675',
    Inn: '9620316755',
    Kpp: '962001000',
    FnsParticipantId: '2BM-9620316755-962001000-202609250245017009189',
    Address: { RussianAddress: { Region: '' } },
  }),
  buyer: partyFromOrganization({
    ShortName: 'Тестовая организация №5999872',
    Inn: '9659998725',
    Kpp: '965901000',
    FnsParticipantId: '2BM-9659998725-965901000-202609250235309299170',
  }),
  date: new Date(2026, 8, 26, 10, 11, 12),
  guid: '0f8fad5b-d9cb-469f-a165-70867728950e',
};

let xmllint = true;
try {
  execFileSync('xmllint', ['--version'], { stdio: 'pipe' });
} catch {
  xmllint = false;
}

function validate(fileName: string, content: Buffer): void {
  const file = join(mkdtempSync(join(tmpdir(), 'test-utd-')), fileName);
  writeFileSync(file, content);
  execFileSync('xmllint', ['--noout', '--schema', XSD, file], { stdio: 'pipe' });
}

describe('buildTestUtd', () => {
  it('builds a windows-1251 СЧФДОП 5.03 that parseUtd accepts, named after ИдФайл', () => {
    const utd = buildTestUtd(PARAMS);

    expect(utd.fileName).toBe(
      'ON_NSCHFDOPPR_2BM-9659998725-965901000-202609250235309299170_' +
        '2BM-9620316755-962001000-202609250245017009189_20260926_' +
        '0f8fad5b-d9cb-469f-a165-70867728950e_0_0_0_0_0_00.xml',
    );
    const parsed = parseUtd(utd);
    expect(parsed).toMatchObject({ function: 'СЧФДОП', version: 'utd970_05_03_01' });
    expect(parsed.idFile).toBe(utd.fileName.slice(0, -4));
    const text = new TextDecoder('windows-1251').decode(utd.content);
    expect(text).toContain('ИННЮЛ="9620316755"');
    expect(text).toContain('<ВсегоОпл СтТовБезНДСВсего="100.00" СтТовУчНалВсего="122.00">');
    // An empty region in Diadoc falls back to 77.
    expect(text).toContain('КодРегион="77"');
  });

  it.each([500_100, 6_500_000])(
    'pads with goods rows to at least %i bytes',
    (minBytes) => {
      const utd = buildTestUtd({ ...PARAMS, minBytes });
      expect(utd.content.length).toBeGreaterThanOrEqual(minBytes);
      expect(utd.content.length).toBeLessThan(minBytes + 1_000);
      const text = new TextDecoder('windows-1251').decode(utd.content);
      const rows = text.match(/<СведТов /g)?.length ?? 0;
      expect(rows).toBeGreaterThan(1);
      expect(text).toContain(
        `<ВсегоОпл СтТовБезНДСВсего="${String(rows * 100)}.00" ` +
          `СтТовУчНалВсего="${String(rows * 122)}.00">`,
      );
      expect(parseUtd(utd).function).toBe('СЧФДОП');
      // The 6.5 MB case takes 3–7 s (binary search over row counts); the default 5 s was flaky.
    },
    30_000,
  );

  it.skipIf(!xmllint)('validates against the ФНС XSD 5.03 (xmllint), one row and many', () => {
    for (const minBytes of [undefined, 20_000]) {
      const utd = buildTestUtd(minBytes === undefined ? PARAMS : { ...PARAMS, minBytes });
      expect(() => {
        validate(utd.fileName, utd.content);
      }).not.toThrow();
    }
  });

  it('refuses an organisation that is not a legal entity with ИНН(10) + КПП', () => {
    expect(() => partyFromOrganization({ Inn: '123456789012', FnsParticipantId: '2BM-1' })).toThrow(
      /legal entity/,
    );
    expect(() => partyFromOrganization({ Inn: '9620316755', Kpp: '962001000' })).toThrow(
      /FnsParticipantId/,
    );
  });
});

describe('makeTestUtd', () => {
  const SELLER: Organization = {
    FullName: 'Тестовая организация №2031675',
    Inn: '9620316755',
    Kpp: '962001000',
    FnsParticipantId: '2BM-9620316755-962001000-202609250245017009189',
    IsTest: true,
  };
  const BUYER: Organization = {
    FullName: 'Тестовая организация №5999872',
    Inn: '9659998725',
    Kpp: '965901000',
    FnsParticipantId: '2BM-9659998725-965901000-202609250235309299170',
    IsTest: true,
  };

  // Diadoc leaves IsTest out for a real organisation.
  function withoutIsTest(org: Organization): Organization {
    const copy = { ...org };
    delete copy.IsTest;
    return copy;
  }

  function lookup(orgs: Record<string, Organization>) {
    const calls: { boxId: string; signal: AbortSignal | undefined }[] = [];
    const getOrganization = (boxId: string, o: { signal?: AbortSignal | undefined } = {}) => {
      calls.push({ boxId, signal: o.signal });
      const org = orgs[boxId];
      return org === undefined ? Promise.reject(new Error(`404 ${boxId}`)) : Promise.resolve(org);
    };
    return { getOrganization, calls };
  }

  it('builds the УПД from the sender (seller) and recipient (buyer) boxes', async () => {
    const { getOrganization, calls } = lookup({ from: SELLER, to: BUYER });
    const signal = new AbortController().signal;
    const utd = await makeTestUtd(
      { getOrganization },
      { fromBoxId: 'from', toBoxId: 'to', date: PARAMS.date, guid: PARAMS.guid, signal },
    );

    expect(calls).toEqual([
      { boxId: 'from', signal },
      { boxId: 'to', signal },
    ]);
    expect(utd.fileName).toBe(buildTestUtd(PARAMS).fileName);
    expect(utd.seller).toMatchObject({ inn: '9620316755', kpp: '962001000' });
    expect(utd.buyer).toMatchObject({ inn: '9659998725', kpp: '965901000' });
    expect(parseUtd(utd).function).toBe('СЧФДОП');
  });

  it('passes minBytes through', async () => {
    const { getOrganization } = lookup({ from: SELLER, to: BUYER });
    const utd = await makeTestUtd(
      { getOrganization },
      { fromBoxId: 'from', toBoxId: 'to', date: PARAMS.date, guid: PARAMS.guid, minBytes: 20_000 },
    );
    expect(utd.content.length).toBeGreaterThanOrEqual(20_000);
  });

  it.each([
    ['sender', { from: { ...SELLER, IsTest: false }, to: BUYER }, /sender box from/],
    ['recipient', { from: SELLER, to: withoutIsTest(BUYER) }, /recipient box to/],
  ])('refuses a %s box that is not a test organisation', async (_, orgs, message) => {
    const { getOrganization } = lookup(orgs);
    const made = makeTestUtd(
      { getOrganization },
      { fromBoxId: 'from', toBoxId: 'to', date: PARAMS.date, guid: PARAMS.guid },
    );
    await expect(made).rejects.toBeInstanceOf(TestUtdRefusedError);
    await expect(made).rejects.toThrow(message);
    await expect(made).rejects.toMatchObject({ code: 'TEST_UTD_REFUSED' });
  });
  it('stops before a lookup once aborted, with the signal reason', async () => {
    const { getOrganization, calls } = lookup({ from: SELLER, to: BUYER });
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGINT)');
    controller.abort(reason);
    const made = makeTestUtd(
      { getOrganization },
      {
        fromBoxId: 'from',
        toBoxId: 'to',
        date: PARAMS.date,
        guid: PARAMS.guid,
        signal: controller.signal,
      },
    );
    await expect(made).rejects.toBe(reason);
    expect(calls).toHaveLength(0);
  });

  it('turns a lookup aborted by the signal (AbortError) into the signal reason', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGTERM)');
    const getOrganization = () => {
      controller.abort(reason);
      return Promise.reject(new DOMException('This operation was aborted', 'AbortError'));
    };
    const made = makeTestUtd(
      { getOrganization },
      {
        fromBoxId: 'from',
        toBoxId: 'to',
        date: PARAMS.date,
        guid: PARAMS.guid,
        signal: controller.signal,
      },
    );
    await expect(made).rejects.toBe(reason);
  });

  it('refuses minBytes above MAX_TEST_UTD_BYTES before any lookup', async () => {
    const { getOrganization, calls } = lookup({ from: SELLER, to: BUYER });
    const made = makeTestUtd(
      { getOrganization },
      {
        fromBoxId: 'from',
        toBoxId: 'to',
        date: PARAMS.date,
        guid: PARAMS.guid,
        minBytes: MAX_TEST_UTD_BYTES + 1,
      },
    );
    await expect(made).rejects.toThrow(RangeError);
    expect(calls).toHaveLength(0);
    expect(() => buildTestUtd({ ...PARAMS, minBytes: MAX_TEST_UTD_BYTES + 1 })).toThrow(RangeError);
  });
});

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseUtd } from '../utd/index.js';
import { buildTestUtd, partyFromOrganization, type TestUtdParams } from './test-utd.js';

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

  it.each([500_100, 6_500_000])('pads with goods rows to at least %i bytes', (minBytes) => {
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
  });

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

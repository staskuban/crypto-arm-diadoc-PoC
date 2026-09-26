import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildMinimalUtd, readIdFile, type UtdParams } from '../src/utd.ts';

const XSD = new URL('../xsd/ON_NSCHFDOPPR_1_997_01_05_03_05.xsd', import.meta.url).pathname;

const params: UtdParams = {
  seller: { name: 'ООО «Продавец»', inn: '7700000016', kpp: '773601001', fnsParticipantId: '2BM-7700000016-773601001-000000000000000000001', regionCode: '77', regionName: 'г. Москва' },
  buyer: { name: 'ООО «Покупатель»', inn: '7700000023', kpp: '773601001', fnsParticipantId: '2BM-7700000023-773601001-000000000000000000002', regionCode: '77', regionName: 'г. Москва' },
  signer: { lastName: 'Иванов', firstName: 'Иван', middleName: 'Иванович', position: 'Генеральный директор' },
  documentNumber: 'S1-1',
  date: new Date(2026, 8, 24, 13, 5, 9),
  guid: '8c703486-75df-46f8-8f0a-959b09f807a9',
};

test('file id follows ON_NSCHFDOPPR_<recipient>_<sender>_<yyyymmdd>_<guid>_N2.._N7', () => {
  const utd = buildMinimalUtd(params);
  assert.equal(
    utd.idFile,
    'ON_NSCHFDOPPR_2BM-7700000023-773601001-000000000000000000002_2BM-7700000016-773601001-000000000000000000001_20260924_8c703486-75df-46f8-8f0a-959b09f807a9_0_0_0_0_0_00',
  );
  assert.equal(utd.fileName, `${utd.idFile}.xml`);
});

test('content is windows-1251 bytes with a windows-1251 prolog', () => {
  const { content } = buildMinimalUtd(params);
  assert.ok(Buffer.isBuffer(content));
  assert.ok(content.subarray(0, 45).toString('latin1').startsWith('<?xml version="1.0" encoding="windows-1251"?>'));
  assert.ok(content.includes(Buffer.from([0xcf, 0xf0, 0xee, 0xe4, 0xe0, 0xe2, 0xe5, 0xf6])), 'contains "Продавец" in cp1251');
  assert.equal(content.indexOf(Buffer.from('Продавец', 'utf8')), -1, 'no UTF-8 Cyrillic inside');
});

test('readIdFile returns @ИдФайл from the raw bytes', () => {
  const utd = buildMinimalUtd(params);
  assert.equal(readIdFile(utd.content), utd.idFile);
});

test('fills СЧФДОП essentials: signer before signing, totals, date/time formats', () => {
  const xml = new TextDecoder('windows-1251').decode(buildMinimalUtd(params).content);
  assert.match(xml, /Функция="СЧФДОП"/);
  assert.match(xml, /ДатаИнфПр="24\.09\.2026" ВремИнфПр="13\.05\.09"/);
  assert.match(xml, /<Подписант СпосПодтПолном="1" Должн="Генеральный директор"><ФИО Фамилия="Иванов" Имя="Иван" Отчество="Иванович"\/><\/Подписант>/);
  assert.match(xml, /СтТовБезНДСВсего="100\.00" СтТовУчНалВсего="122\.00"/);
  assert.match(xml, /НаимОрг="ООО &#171;Продавец&#187;"|НаимОрг="ООО «Продавец»"/);
});

test('escapes XML special characters in attribute values', () => {
  const xml = new TextDecoder('windows-1251').decode(
    buildMinimalUtd({ ...params, seller: { ...params.seller, name: 'ООО "A&B" <x>' } }).content,
  );
  assert.match(xml, /НаимОрг="ООО &quot;A&amp;B&quot; &lt;x&gt;"/);
});

test('validates against the ФНС XSD 5.03 (xmllint)', () => {
  const utd = buildMinimalUtd(params);
  const dir = mkdtempSync(join(tmpdir(), 'utd-'));
  const file = join(dir, utd.fileName);
  writeFileSync(file, utd.content);
  // throws with xmllint's stderr on validation failure
  execFileSync('xmllint', ['--noout', '--schema', XSD, file], { stdio: 'pipe' });
});

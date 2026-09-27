// Test УПД: a minimal СЧФДОП seller title, ФНС format 5.03 (приказ ЕД-7-26/970@, XSD
// ON_NSCHFDOPPR_1_997_01_05_03_05), windows-1251, ported from the S1 spike (spikes/diadoc/src/utd.ts).
// Goods rows pad it to a size (inline vs shelf vs shelf parts). Used by the live e2e (T6) and the CLI
// `make-test-utd` (F22), for the Diadoc test boxes only: real УПД come from the ERP.
import type { Organization, RequestOptions } from '../diadoc/index.js';

export interface Party {
  name: string;
  inn: string;
  kpp: string;
  /** Diadoc `Organization.FnsParticipantId` (2BM-…), used in the file name. */
  fnsParticipantId: string;
  regionCode: string;
  regionName: string;
}

export interface TestUtdParams {
  seller: Party;
  buyer: Party;
  date: Date;
  /** N1 of the file name; a new one per send makes a new document. */
  guid: string;
  /** Adds goods rows until the file has at least this many bytes. */
  minBytes?: number;
}

export interface TestUtd {
  fileName: string;
  content: Buffer;
}

// НаимРегион is mandatory in АдрРФ and Diadoc returns only the code; the test organisations have
// none at all (D201), so 77 is the fallback.
const REGION_NAMES: Record<string, string> = { '77': 'г. Москва' };

/** Seller/buyer from `GetOrganization` (legal entities only: СвЮЛУч). */
export function partyFromOrganization(
  org: Organization & { Address?: { RussianAddress?: { Region?: string } } },
): Party {
  if (!org.FnsParticipantId) {
    throw new Error(`organisation ${org.Inn ?? '?'} has no FnsParticipantId (file name)`);
  }
  if (org.Inn?.length !== 10 || !org.Kpp) {
    throw new Error(`organisation ${org.Inn ?? '?'} is not a legal entity with ИНН(10) + КПП`);
  }
  const region = org.Address?.RussianAddress?.Region;
  const regionCode = region === undefined || region === '' ? '77' : region;
  return {
    name: org.FullName ?? org.ShortName ?? org.Inn,
    inn: org.Inn,
    kpp: org.Kpp,
    fnsParticipantId: org.FnsParticipantId,
    regionCode,
    regionName: REGION_NAMES[regionCode] ?? `Субъект РФ ${regionCode}`,
  };
}

/**
 * Largest `minBytes`: enough for the КриптоАРМ Server signing limit (≈ 39.3 MB, T10). The builder keeps
 * the whole УПД as a string (UTF-16) plus the goods rows and searches the row count, so far larger
 * sizes would exhaust memory rather than make a useful test file (F23).
 */
export const MAX_TEST_UTD_BYTES = 40_000_000;

/** A box of `makeTestUtd` is not a test organisation: nothing was built. */
export class TestUtdRefusedError extends Error {
  override readonly name = 'TestUtdRefusedError';
  readonly code = 'TEST_UTD_REFUSED';
}

export interface MakeTestUtdOptions {
  fromBoxId: string;
  toBoxId: string;
  date: Date;
  guid: string;
  minBytes?: number;
  signal?: AbortSignal;
}

export type MadeTestUtd = TestUtd & { seller: Party; buyer: Party };

/**
 * A test УПД from the sender (seller) to the recipient (buyer) box, with the parties' details from
 * `GetOrganization`. Refuses unless both boxes are test organisations (`IsTest`), so a made-up УПД
 * never goes to a real counteragent (F22).
 */
export async function makeTestUtd(
  diadoc: { getOrganization(boxId: string, o?: RequestOptions): Promise<Organization> },
  options: MakeTestUtdOptions,
): Promise<MadeTestUtd> {
  checkMinBytes(options.minBytes);
  const { signal } = options;
  const o = signal === undefined ? {} : { signal };
  const parties: Party[] = [];
  for (const [role, boxId] of [
    ['sender', options.fromBoxId],
    ['recipient', options.toBoxId],
  ] as const) {
    signal?.throwIfAborted();
    let org: Organization;
    try {
      org = await diadoc.getOrganization(boxId, o);
    } catch (error) {
      // An aborted fetch or retry pause rejects with its own AbortError, not the signal's reason.
      throw signal?.aborted ? signal.reason : error;
    }
    if (org.IsTest !== true) {
      throw new TestUtdRefusedError(
        `test УПД are only for test boxes, but the ${role} box ${boxId} ` +
          `(${org.FullName ?? org.ShortName ?? org.Inn ?? '?'}) is not a test organisation ` +
          `(IsTest: ${JSON.stringify(org.IsTest ?? null)})`,
      );
    }
    parties.push(partyFromOrganization(org));
  }
  const [seller, buyer] = parties as [Party, Party];
  const utd = buildTestUtd({
    seller,
    buyer,
    date: options.date,
    guid: options.guid,
    ...(options.minBytes === undefined ? {} : { minBytes: options.minBytes }),
  });
  return { ...utd, seller, buyer };
}

function checkMinBytes(minBytes: number | undefined): void {
  if (minBytes !== undefined && minBytes > MAX_TEST_UTD_BYTES) {
    throw new RangeError(
      `minBytes ${String(minBytes)} is above ${String(MAX_TEST_UTD_BYTES)} (MAX_TEST_UTD_BYTES)`,
    );
  }
}

export function buildTestUtd(p: TestUtdParams): TestUtd {
  checkMinBytes(p.minBytes);
  const idFile =
    `ON_NSCHFDOPPR_${p.buyer.fnsParticipantId}_${p.seller.fnsParticipantId}_` +
    `${yyyymmdd(p.date)}_${p.guid}_0_0_0_0_0_00`;
  const one = build(idFile, p, 1);
  const minBytes = p.minBytes ?? 0;
  if (one.length >= minBytes) return { fileName: `${idFile}.xml`, content: one };
  // The fewest rows that reach minBytes (rows grow with НомСтр, so search rather than estimate).
  let low = 1;
  let high = 2;
  while (build(idFile, p, high).length < minBytes) high *= 2;
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (build(idFile, p, mid).length < minBytes) low = mid;
    else high = mid;
  }
  const content = build(idFile, p, high);
  return { fileName: `${idFile}.xml`, content };
}

function build(idFile: string, p: TestUtdParams, rows: number): Buffer {
  const date = ddmmyyyy(p.date);
  const goods: string[] = [];
  for (let n = 1; n <= rows; n++) {
    goods.push(
      `<СведТов НомСтр="${String(n)}" НаимТов="Тестовый товар" ОКЕИ_Тов="796" НаимЕдИзм="шт" ` +
        'КолТов="1" ЦенаТов="100.00" СтТовБезНДС="100.00" НалСт="22%" СтТовУчНал="122.00">' +
        '<Акциз><БезАкциз>без акциза</БезАкциз></Акциз><СумНал><СумНал>22.00</СумНал></СумНал>' +
        '</СведТов>',
    );
  }
  const xml =
    '<?xml version="1.0" encoding="windows-1251"?>\n' +
    `<Файл${attrs({ ИдФайл: idFile, ВерсФорм: '5.03', ВерсПрог: 'kryptoarm-plus-diadoc e2e' })}>` +
    `<Документ${attrs({
      КНД: '1115131',
      Функция: 'СЧФДОП',
      ПоФактХЖ:
        'Документ об отгрузке товаров (выполнении работ), передаче имущественных прав ' +
        '(документ об оказании услуг)',
      НаимДокОпр:
        'Счет-фактура и документ об отгрузке товаров (выполнении работ), передаче ' +
        'имущественных прав (документ об оказании услуг)',
      ДатаИнфПр: date,
      ВремИнфПр: hhmmss(p.date),
      НаимЭконСубСост: p.seller.name,
    })}>` +
    `<СвСчФакт${attrs({ НомерДок: `E2E-${p.guid.slice(0, 8)}`, ДатаДок: date })}>` +
    party('СвПрод', p.seller) +
    party('СвПокуп', p.buyer) +
    '<ДенИзм КодОКВ="643" НаимОКВ="Российский рубль"/>' +
    '</СвСчФакт>' +
    '<ТаблСчФакт>' +
    goods.join('') +
    `<ВсегоОпл СтТовБезНДСВсего="${String(rows * 100)}.00" СтТовУчНалВсего="${String(rows * 122)}.00">` +
    `<СумНалВсего><СумНал>${String(rows * 22)}.00</СумНал></СумНалВсего></ВсегоОпл>` +
    '</ТаблСчФакт>' +
    `<СвПродПер><СвПер${attrs({ СодОпер: 'Товары переданы', ДатаПер: date })}>` +
    '<БезДокОснПер>1</БезДокОснПер></СвПер></СвПродПер>' +
    '<Подписант СпосПодтПолном="1" Должн="Директор"><ФИО Фамилия="Тестов" Имя="Тест"/></Подписант>' +
    '</Документ></Файл>\n';
  return encodeCp1251(xml);
}

function party(tag: string, p: Party): string {
  return (
    `<${tag}><ИдСв><СвЮЛУч${attrs({ НаимОрг: p.name, ИННЮЛ: p.inn, КПП: p.kpp })}/></ИдСв>` +
    `<Адрес><АдрРФ${attrs({ КодРегион: p.regionCode, НаимРегион: p.regionName })}/></Адрес></${tag}>`
  );
}

function attrs(a: Record<string, string>): string {
  return Object.entries(a)
    .map(([k, v]) => ` ${k}="${escape(v)}"`)
    .join('');
}

function escape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const pad = (n: number): string => String(n).padStart(2, '0');
const ddmmyyyy = (d: Date): string =>
  `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${String(d.getFullYear())}`;
const yyyymmdd = (d: Date): string =>
  `${String(d.getFullYear())}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
const hhmmss = (d: Date): string =>
  `${pad(d.getHours())}.${pad(d.getMinutes())}.${pad(d.getSeconds())}`;

// TextEncoder has no windows-1251; the reverse table comes from the decoder.
const CP1251 = new Map<string, number>();
{
  const decoder = new TextDecoder('windows-1251');
  for (let b = 0x80; b <= 0xff; b++) {
    const ch = decoder.decode(Uint8Array.of(b));
    if (ch !== '�') CP1251.set(ch, b);
  }
}

function encodeCp1251(text: string): Buffer {
  const out = Buffer.alloc(text.length);
  let i = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    const b = code < 0x80 ? code : CP1251.get(ch);
    if (b === undefined) throw new Error(`${JSON.stringify(ch)} is not in windows-1251`);
    out[i++] = b;
  }
  return out.subarray(0, i);
}

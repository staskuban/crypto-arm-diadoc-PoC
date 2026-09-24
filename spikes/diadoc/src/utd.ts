// Minimal УПД (СЧФДОП) seller title, ФНС format 5.03 (приказ ЕД-7-26/970@, XSD ON_NSCHFDOPPR_1_997_01_05_03_05).
// The result is the exact byte sequence that must be signed and sent — never re-encode it.
import { encodeCp1251 } from './cp1251.ts';

export type Party = {
  name: string;
  inn: string;
  kpp: string;
  /** Diadoc `Organization.FnsParticipantId` (2BM-...), used in the file name */
  fnsParticipantId: string;
  regionCode: string;
  regionName: string;
};

export type Signer = { lastName: string; firstName: string; middleName?: string; position?: string };

export type UtdParams = {
  seller: Party;
  buyer: Party;
  signer: Signer;
  documentNumber: string;
  date: Date;
  guid: string;
  /** СпосПодтПолном: 1 = by the signature certificate data (default), 6 = other */
  signerPowers?: '1' | '6';
};

export type Utd = { idFile: string; fileName: string; content: Buffer };

const pad = (n: number) => String(n).padStart(2, '0');
const ddmmyyyy = (d: Date) => `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
const yyyymmdd = (d: Date) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
const hhmmss = (d: Date) => `${pad(d.getHours())}.${pad(d.getMinutes())}.${pad(d.getSeconds())}`;

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function attrs(a: Record<string, string | undefined>): string {
  return Object.entries(a)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => ` ${k}="${esc(v!)}"`)
    .join('');
}

function party(tag: string, p: Party): string {
  return (
    `<${tag}><ИдСв><СвЮЛУч${attrs({ НаимОрг: p.name, ИННЮЛ: p.inn, КПП: p.kpp })}/></ИдСв>` +
    `<Адрес><АдрРФ${attrs({ КодРегион: p.regionCode, НаимРегион: p.regionName })}/></Адрес></${tag}>`
  );
}

/**
 * File name per приказ 970 §4: ON_NSCHFDOPPR_<recipient>_<sender>_<YYYYMMDD>_<N1 guid>_<N2>_<N3>_<N4>_<N5>_<N6>_<N7>.
 * N2..N6 flag traceable / marked / alcohol / tobacco / oil goods, N7 is a two-digit reserve; all zero for plain goods.
 */
export function utdIdFile(p: Pick<UtdParams, 'seller' | 'buyer' | 'date' | 'guid'>): string {
  return `ON_NSCHFDOPPR_${p.buyer.fnsParticipantId}_${p.seller.fnsParticipantId}_${yyyymmdd(p.date)}_${p.guid}_0_0_0_0_0_00`;
}

export function buildMinimalUtd(p: UtdParams): Utd {
  const idFile = utdIdFile(p);
  const date = ddmmyyyy(p.date);
  const xml =
    '<?xml version="1.0" encoding="windows-1251"?>\n' +
    `<Файл${attrs({ ИдФайл: idFile, ВерсФорм: '5.03', ВерсПрог: 'spike-diadoc 0.1' })}>` +
    `<Документ${attrs({
      КНД: '1115131',
      Функция: 'СЧФДОП',
      ПоФактХЖ: 'Документ об отгрузке товаров (выполнении работ), передаче имущественных прав (документ об оказании услуг)',
      НаимДокОпр: 'Счет-фактура и документ об отгрузке товаров (выполнении работ), передаче имущественных прав (документ об оказании услуг)',
      ДатаИнфПр: date,
      ВремИнфПр: hhmmss(p.date),
      НаимЭконСубСост: p.seller.name,
    })}>` +
    `<СвСчФакт${attrs({ НомерДок: p.documentNumber, ДатаДок: date })}>` +
    party('СвПрод', p.seller) +
    party('СвПокуп', p.buyer) +
    '<ДенИзм КодОКВ="643" НаимОКВ="Российский рубль"/>' +
    '</СвСчФакт>' +
    '<ТаблСчФакт>' +
    '<СведТов НомСтр="1" НаимТов="Тестовый товар" ОКЕИ_Тов="796" НаимЕдИзм="шт" КолТов="1" ЦенаТов="100.00" СтТовБезНДС="100.00" НалСт="22%" СтТовУчНал="122.00">' +
    '<Акциз><БезАкциз>без акциза</БезАкциз></Акциз><СумНал><СумНал>22.00</СумНал></СумНал>' +
    '</СведТов>' +
    '<ВсегоОпл СтТовБезНДСВсего="100.00" СтТовУчНалВсего="122.00"><СумНалВсего><СумНал>22.00</СумНал></СумНалВсего></ВсегоОпл>' +
    '</ТаблСчФакт>' +
    `<СвПродПер><СвПер${attrs({ СодОпер: 'Товары переданы', ДатаПер: date })}><БезДокОснПер>1</БезДокОснПер></СвПер></СвПродПер>` +
    `<Подписант${attrs({ СпосПодтПолном: p.signerPowers ?? '1', Должн: p.signer.position })}>` +
    `<ФИО${attrs({ Фамилия: p.signer.lastName, Имя: p.signer.firstName, Отчество: p.signer.middleName })}/>` +
    '</Подписант>' +
    '</Документ></Файл>\n';
  return { idFile, fileName: `${idFile}.xml`, content: encodeCp1251(xml) };
}

/** Reads @ИдФайл from raw windows-1251 bytes (decoding only for inspection; the bytes stay untouched). */
export function readIdFile(content: Buffer): string | undefined {
  const text = new TextDecoder('windows-1251').decode(content);
  // no \b: JS word boundaries are ASCII-only and do not work next to Cyrillic
  return /<Файл\s(?:[^>]*\s)?ИдФайл="([^"]*)"/.exec(text)?.[1];
}

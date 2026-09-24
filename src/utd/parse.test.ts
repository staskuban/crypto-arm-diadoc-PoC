import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { UtdError, type UtdErrorCode } from './errors.js';
import { parseUtd, UTD_FUNCTIONS, UTD_VERSIONS } from './parse.js';

const ID_FILE =
  'ON_NSCHFDOPPR_2BM-7700000023-773601001-000000000000000000002_2BM-7700000016-773601001-000000000000000000001_20260924_16ad2de0-fadd-47fb-8838-b02d9f37d40b_0_0_0_0_0_00';
const FILE_NAME = `${ID_FILE}.xml`;
const fixture = readFileSync(new URL(`fixtures/${FILE_NAME}`, import.meta.url));
const xsd = readFileSync(new URL('fixtures/ON_NSCHFDOPPR_1_997_01_05_03_05.xsd', import.meta.url));

const cp1251 = new TextDecoder('windows-1251');
const reverse = new Map<string, number>();
for (let b = 0x80; b <= 0xff; b++) reverse.set(cp1251.decode(Uint8Array.of(b)), b);

/** Test-only windows-1251 encoder, used to build mutated fixtures. */
function encodeCp1251(text: string): Buffer {
  return Buffer.from(
    Array.from(text, (ch) => {
      const code = ch.codePointAt(0) ?? 0;
      const b = code < 0x80 ? code : reverse.get(ch);
      if (b === undefined) throw new Error(`not in windows-1251: ${ch}`);
      return b;
    }),
  );
}

/** Rewrites the fixture as text and re-encodes it to windows-1251 (test inputs only). */
function mutate(fn: (xml: string) => string): Buffer {
  return encodeCp1251(fn(cp1251.decode(fixture)));
}

function expectUtdError(action: () => unknown, code: UtdErrorCode): void {
  let caught: unknown;
  try {
    action();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(UtdError);
  expect((caught as UtdError).code).toBe(code);
}

describe('parseUtd on the S1 fixture', () => {
  it('extracts ИдФайл, Function, ВерсФорм and the Diadoc version', () => {
    const doc = parseUtd({ fileName: FILE_NAME, content: fixture });
    expect(doc).toMatchObject({
      fileName: FILE_NAME,
      idFile: ID_FILE,
      function: 'СЧФДОП',
      formatVersion: '5.03',
      version: 'utd970_05_03_01',
    });
  });

  it('keeps the exact input Buffer: no copy, no re-encoding', () => {
    const before = Buffer.from(fixture);
    const doc = parseUtd({ fileName: FILE_NAME, content: fixture });
    expect(doc.content).toBe(fixture);
    expect(doc.content.equals(before)).toBe(true);
  });
});

describe('XML declaration', () => {
  it('accepts windows-1251 in any case and with single quotes', () => {
    const content = mutate((x) =>
      x.replace(
        '<?xml version="1.0" encoding="windows-1251"?>',
        "<?xml version='1.0' encoding='WINDOWS-1251' ?>",
      ),
    );
    expect(parseUtd({ fileName: FILE_NAME, content }).function).toBe('СЧФДОП');
  });

  it('accepts a standalone declaration after the encoding', () => {
    const content = mutate((x) =>
      x.replace('encoding="windows-1251"?>', 'encoding="windows-1251" standalone="yes"?>'),
    );
    expect(parseUtd({ fileName: FILE_NAME, content }).idFile).toBe(ID_FILE);
  });

  it('rejects a document without a declaration', () => {
    const content = mutate((x) => x.replace(/^<\?xml[^>]*\?>\s*/, ''));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'MISSING_XML_DECLARATION');
  });

  it('rejects a declaration that is not at the very start (e.g. after a BOM)', () => {
    const content = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), fixture]);
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'MISSING_XML_DECLARATION');
  });

  it('rejects a declaration without encoding (XML default is UTF-8)', () => {
    const content = mutate((x) => x.replace(' encoding="windows-1251"', ''));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNSUPPORTED_ENCODING');
  });

  it('rejects any other encoding', () => {
    const content = Buffer.from(
      cp1251.decode(fixture).replace('encoding="windows-1251"', 'encoding="utf-8"'),
      'utf8',
    );
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNSUPPORTED_ENCODING');
  });

  it('rejects UTF-8 bytes that claim to be windows-1251', () => {
    const content = Buffer.from(cp1251.decode(fixture), 'utf8');
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'INVALID_ROOT');
  });
});

describe('ИдФайл and file name', () => {
  it('rejects a file name that differs from ИдФайл', () => {
    expectUtdError(
      () => parseUtd({ fileName: `${ID_FILE}_copy.xml`, content: fixture }),
      'FILE_NAME_MISMATCH',
    );
  });

  it('requires the .xml extension (case-insensitive)', () => {
    expect(parseUtd({ fileName: `${ID_FILE}.XML`, content: fixture }).idFile).toBe(ID_FILE);
    expectUtdError(() => parseUtd({ fileName: ID_FILE, content: fixture }), 'FILE_NAME_MISMATCH');
  });

  it('does not accept a path instead of a bare file name', () => {
    expectUtdError(
      () => parseUtd({ fileName: `in/${FILE_NAME}`, content: fixture }),
      'FILE_NAME_MISMATCH',
    );
  });

  it('rejects a missing ИдФайл', () => {
    const content = mutate((x) => x.replace(/ ИдФайл="[^"]*"/, ''));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'MISSING_ATTRIBUTE');
  });

  it('decodes entities in attribute values', () => {
    const content = mutate((x) => x.replace(`ИдФайл="${ID_FILE}"`, `ИдФайл="${ID_FILE}&#95;x"`));
    expect(parseUtd({ fileName: `${ID_FILE}_x.xml`, content }).idFile).toBe(`${ID_FILE}_x`);
  });

  it('rejects a root element other than Файл', () => {
    const content = mutate((x) => x.replace('<Файл ', '<Файлы ').replace('</Файл>', '</Файлы>'));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'INVALID_ROOT');
  });

  it('skips comments and processing instructions before the root element', () => {
    const content = mutate((x) =>
      x.replace('?>\n<Файл', '?>\n<!-- <Файл ИдФайл="fake"> --><?pi x?>\n<Файл'),
    );
    expect(parseUtd({ fileName: FILE_NAME, content }).idFile).toBe(ID_FILE);
  });
});

describe('Function', () => {
  it.each(UTD_FUNCTIONS)('reads Функция="%s"', (fn) => {
    const content = mutate((x) => x.replace('Функция="СЧФДОП"', `Функция="${fn}"`));
    expect(parseUtd({ fileName: FILE_NAME, content }).function).toBe(fn);
  });

  it('rejects an unknown Функция', () => {
    const content = mutate((x) => x.replace('Функция="СЧФДОП"', 'Функция="УКД"'));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNKNOWN_FUNCTION');
  });

  it('requires the УПД seller title КНД 1115131', () => {
    const content = mutate((x) => x.replace('КНД="1115131"', 'КНД="1115132"'));
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNSUPPORTED_KND');
  });

  it('rejects a document without Документ', () => {
    const content = mutate((x) =>
      x.replace(/<Документ [^>]*>/, '<Док>').replace('</Документ>', '</Док>'),
    );
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'MISSING_ELEMENT');
  });

  it('ignores a commented-out Документ', () => {
    const content = mutate((x) =>
      x.replace('<Документ ', '<!-- <Документ КНД="1" Функция="СЧФ"> --><Документ '),
    );
    expect(parseUtd({ fileName: FILE_NAME, content }).function).toBe('СЧФДОП');
  });
});

describe('format version', () => {
  const v504 = (x: string) => x.replace('ВерсФорм="5.03"', 'ВерсФорм="5.04"');

  it('rejects an unknown ВерсФорм by default', () => {
    const content = mutate(v504);
    expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNKNOWN_FORMAT_VERSION');
  });

  it('asks the resolver (e.g. backed by GetDocumentTypes) for an unknown ВерсФорм', () => {
    const content = mutate(v504);
    const seen: unknown[] = [];
    const doc = parseUtd(
      { fileName: FILE_NAME, content },
      {
        resolveVersion: (meta) => {
          seen.push(meta);
          return 'utd970_05_04_01';
        },
      },
    );
    expect(seen).toEqual([{ formatVersion: '5.04', function: 'СЧФДОП' }]);
    expect(doc).toMatchObject({ formatVersion: '5.04', version: 'utd970_05_04_01' });
  });

  it('rejects when the resolver has no answer or an empty one', () => {
    const content = mutate(v504);
    for (const answer of [undefined, ' ']) {
      expectUtdError(
        () => parseUtd({ fileName: FILE_NAME, content }, { resolveVersion: () => answer }),
        'UNKNOWN_FORMAT_VERSION',
      );
    }
  });

  it('never lets the resolver override a known ВерсФорм', () => {
    const doc = parseUtd(
      { fileName: FILE_NAME, content: fixture },
      { resolveVersion: () => 'utd970_05_02_01' },
    );
    expect(doc.version).toBe('utd970_05_03_01');
  });

  it.each(['constructor', 'toString', '__proto__'])(
    'does not resolve the Object.prototype key ВерсФорм="%s"',
    (key) => {
      const content = mutate((x) => x.replace('ВерсФорм="5.03"', `ВерсФорм="${key}"`));
      expectUtdError(() => parseUtd({ fileName: FILE_NAME, content }), 'UNKNOWN_FORMAT_VERSION');
    },
  );
});

describe('scanner edge cases', () => {
  const parse = (fn: (xml: string) => string) =>
    parseUtd({ fileName: FILE_NAME, content: mutate(fn) });

  it('rejects truncated XML (no closing </Файл>)', () => {
    expectUtdError(() => parse((x) => x.slice(0, x.indexOf('<СвСчФакт'))), 'MALFORMED_XML');
  });

  it('accepts trailing whitespace and comments after the root', () => {
    expect(parse((x) => `${x}<!-- end -->\r\n`).idFile).toBe(ID_FILE);
  });

  it('rejects a self-closing root', () => {
    const xml = (x: string) => x.replace(/(<Файл [^>]*)>[\s\S]*$/, '$1/>');
    expectUtdError(() => parse(xml), 'MISSING_ELEMENT');
  });

  it('finds Документ as a child of Файл, not a nested one, past CDATA and PIs', () => {
    const doc = parse((x) =>
      x.replace(
        '<Документ ',
        '<Доп><Документ КНД="1115131" Функция="СЧФ"/><x/></Доп><![CDATA[<Документ>]]><?pi <Документ>?><Документ ',
      ),
    );
    expect(doc.function).toBe('СЧФДОП');
  });

  it('handles single-quoted attributes, > inside values and entities in Функция', () => {
    const doc = parse((x) =>
      x
        .replace('Функция="СЧФДОП"', "Функция='&#1057;ЧФ'")
        .replace('ВерсПрог="spike-diadoc 0.1"', 'ВерсПрог="a > b"'),
    );
    expect(doc.function).toBe('СЧФ');
  });

  it.each([
    ['a duplicate attribute', (x: string) => x.replace('КНД="1115131"', 'КНД="1115131" КНД="1"')],
    [
      'an unknown entity',
      (x: string) => x.replace(`ИдФайл="${ID_FILE}"`, 'ИдФайл="a&constructor;"'),
    ],
    ['a NUL character reference', (x: string) => x.replace('ВерсПрог="', 'ВерсПрог="&#0;')],
    ['a surrogate reference', (x: string) => x.replace('ВерсПрог="', 'ВерсПрог="&#xD800;')],
    ['an unterminated comment', (x: string) => x.replace('<Документ ', '<!-- <Документ ')],
    ['a DOCTYPE', (x: string) => x.replace('?>\n<Файл', '?>\n<!DOCTYPE Файл>\n<Файл')],
  ])('rejects %s as MALFORMED_XML', (_, fn) => {
    expectUtdError(() => parse(fn), 'MALFORMED_XML');
  });

  it('treats NBSP (cp1251 0xA0) as a name character, not XML whitespace', () => {
    expectUtdError(() => parse((x) => x.replace('<Файл ', '<Файл\u00a0')), 'INVALID_ROOT');
  });

  it('does not expand entities in the XML declaration and requires version', () => {
    expectUtdError(
      () => parse((x) => x.replace('encoding="windows-1251"', 'encoding="windows&#45;1251"')),
      'UNSUPPORTED_ENCODING',
    );
    expectUtdError(
      () => parse((x) => x.replace('<?xml version="1.0" ', '<?xml ')),
      'MISSING_XML_DECLARATION',
    );
  });

  it('requires the Подписант block (it must be filled before signing)', () => {
    expectUtdError(
      () => parse((x) => x.replace(/<Подписант[\s\S]*<\/Подписант>/, '')),
      'MISSING_ELEMENT',
    );
  });
});

describe('consistency with the ФНС XSD 5.03', () => {
  const schema = cp1251.decode(xsd);
  const enumerationOf = (attr: string): string[] => {
    const start = schema.indexOf(`<xs:attribute name="${attr}"`);
    const end = schema.indexOf('</xs:attribute>', start);
    return [...schema.slice(start, end).matchAll(/<xs:enumeration value="([^"]*)"/g)].map(
      (m) => m[1] ?? '',
    );
  };

  it('covers exactly the Функция values allowed by the XSD', () => {
    expect([...UTD_FUNCTIONS].sort()).toEqual(enumerationOf('Функция').sort());
  });

  it('maps every ВерсФорм allowed by the XSD', () => {
    expect([...UTD_VERSIONS.keys()].sort()).toEqual(enumerationOf('ВерсФорм').sort());
  });
});

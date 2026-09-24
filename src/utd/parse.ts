// Reads the metadata Diadoc needs from a УПД (ФНС format 5.03, приказ ЕД-7-26/970@).
// The content Buffer is only decoded for inspection; the same bytes are what gets signed and sent.
import { UtdError } from './errors.js';

/** `Документ/@Функция`, as enumerated in ON_NSCHFDOPPR_1_997_01_05_03_05.xsd. */
export const UTD_FUNCTIONS = ['СЧФ', 'СЧФДОП', 'ДОП', 'СвРК', 'СвЗК'] as const;
export type UtdFunction = (typeof UTD_FUNCTIONS)[number];

/** `Файл/@ВерсФорм` → Diadoc `Version`. `utd970_05_02_01` (5.02) is obsolete in Diadoc. */
export const UTD_VERSIONS: ReadonlyMap<string, string> = new Map([['5.03', 'utd970_05_03_01']]);

/** КНД of the УПД seller title (the only title this pipeline sends). */
export const UTD_SELLER_KND = '1115131';

export const UTD_ENCODING = 'windows-1251';

export interface UtdDocument {
  /** Bare file name; equals `${idFile}.xml`. */
  readonly fileName: string;
  /** `Файл/@ИдФайл`. */
  readonly idFile: string;
  /** The exact input bytes. Sign and send these; never decode and re-encode them. */
  readonly content: Buffer;
  readonly function: UtdFunction;
  /** `Файл/@ВерсФорм`, e.g. `5.03`. */
  readonly formatVersion: string;
  /** Diadoc `Version`, e.g. `utd970_05_03_01`. */
  readonly version: string;
}

export interface ParseUtdOptions {
  /**
   * Called only for a `ВерсФорм` missing from {@link UTD_VERSIONS}; returns the Diadoc `Version`
   * (e.g. looked up in `GetDocumentTypes (V3)`) or `undefined` to reject the document.
   * A known `ВерсФорм` always uses the built-in mapping.
   */
  readonly resolveVersion?: (meta: {
    readonly formatVersion: string;
    readonly function: UtdFunction;
  }) => string | undefined;
}

/**
 * Checks what Diadoc needs before signing: windows-1251 declaration, file name == `ИдФайл.xml`,
 * seller-title КНД, `Функция`, a `Подписант` block, a known format version.
 * This is not an XSD validator: it scans the root, `Документ` and the closing `</Файл>` only.
 */
export function parseUtd(
  input: { readonly fileName: string; readonly content: Buffer },
  options: ParseUtdOptions = {},
): UtdDocument {
  const { fileName, content } = input;
  const afterDeclaration = checkDeclaration(content);
  const xml = new TextDecoder(UTD_ENCODING).decode(content);

  const root = readRoot(xml, afterDeclaration);
  if (!root.selfClosing) checkClosed(xml, root.name);
  const idFile = requireAttr(root, 'ИдФайл');
  if (!/\.xml$/i.test(fileName) || fileName.slice(0, -'.xml'.length) !== idFile) {
    throw new UtdError(
      'FILE_NAME_MISMATCH',
      `File name "${fileName}" must be ИдФайл + ".xml" ("${idFile}.xml")`,
    );
  }

  const document = findChild(xml, root, 'Документ');
  const knd = requireAttr(document, 'КНД');
  if (knd !== UTD_SELLER_KND) {
    throw new UtdError(
      'UNSUPPORTED_KND',
      `КНД ${knd} is not a УПД seller title (${UTD_SELLER_KND})`,
    );
  }
  const fn = requireAttr(document, 'Функция');
  if (!isUtdFunction(fn)) {
    throw new UtdError(
      'UNKNOWN_FUNCTION',
      `Функция "${fn}" is not one of ${UTD_FUNCTIONS.join(', ')}`,
    );
  }
  findChild(xml, document, 'Подписант');

  const formatVersion = requireAttr(root, 'ВерсФорм');
  return {
    fileName,
    idFile,
    content,
    function: fn,
    formatVersion,
    version: resolveVersion(formatVersion, fn, options.resolveVersion),
  };
}

function isUtdFunction(value: string): value is UtdFunction {
  return (UTD_FUNCTIONS as readonly string[]).includes(value);
}

function resolveVersion(
  formatVersion: string,
  fn: UtdFunction,
  resolve: ParseUtdOptions['resolveVersion'],
): string {
  const version = UTD_VERSIONS.get(formatVersion) ?? resolve?.({ formatVersion, function: fn });
  if (version === undefined || version.trim() === '') {
    throw new UtdError(
      'UNKNOWN_FORMAT_VERSION',
      `ВерсФорм "${formatVersion}" has no known Diadoc version (see GetDocumentTypes)`,
    );
  }
  return version;
}

// XML whitespace is only these four; JS `\s` also matches NBSP, which is 0xA0 in windows-1251.
const WS = '[ \\t\\r\\n]';

/** Checks the XML declaration on the raw bytes (it is ASCII) and returns the offset after it. */
function checkDeclaration(content: Buffer): number {
  const head = content.subarray(0, 512).toString('latin1');
  const decl = new RegExp(`^<\\?xml(${WS}[^?]*)\\?>`).exec(head);
  const body = decl?.[1] ?? '';
  if (!decl || !new RegExp(`^${WS}+version${WS}*=${WS}*(["'])1\\.[0-9]+\\1`).test(body)) {
    throw new UtdError(
      'MISSING_XML_DECLARATION',
      `Content must start with <?xml version="1.0" encoding="${UTD_ENCODING}"?> (no BOM)`,
    );
  }
  // EncName allows no entity references, so the raw value is compared.
  const encoding = new RegExp(`${WS}encoding${WS}*=${WS}*(["'])([^"']*)\\1`).exec(body)?.[2];
  if (encoding?.toLowerCase() !== UTD_ENCODING) {
    throw new UtdError(
      'UNSUPPORTED_ENCODING',
      `XML encoding is "${encoding ?? 'UTF-8 (not declared)'}", ФНС requires ${UTD_ENCODING}`,
    );
  }
  // latin1 and windows-1251 are both single-byte, so the offset is valid in the decoded text.
  return decl[0].length;
}

interface StartTag {
  readonly name: string;
  readonly attrs: ReadonlyMap<string, string>;
  /** Offset right after the tag's `>`. */
  readonly end: number;
  readonly selfClosing: boolean;
}

function readRoot(xml: string, from: number): StartTag {
  const pos = skipMisc(xml, from);
  if (xml.startsWith('<!', pos)) {
    throw new UtdError('MALFORMED_XML', 'DOCTYPE and other declarations are not allowed');
  }
  const root = xml.startsWith('<', pos) ? readStartTag(xml, pos) : undefined;
  if (root?.name !== 'Файл') {
    throw new UtdError(
      'INVALID_ROOT',
      `Root element must be <Файл> (got ${root ? `<${root.name}>` : 'no element'}); ` +
        `check that the bytes really are ${UTD_ENCODING}`,
    );
  }
  return root;
}

/** Finds the first child element `name` of `parent`, skipping comments, PIs, CDATA and text. */
function findChild(xml: string, parent: StartTag, name: string): StartTag {
  let pos = parent.end;
  let depth = 0;
  while (!parent.selfClosing) {
    const lt = xml.indexOf('<', pos);
    if (lt === -1) break;
    if (xml.startsWith('<!--', lt)) pos = skipPast(xml, lt, '-->');
    else if (xml.startsWith('<![CDATA[', lt)) pos = skipPast(xml, lt, ']]>');
    else if (xml.startsWith('<?', lt)) pos = skipPast(xml, lt, '?>');
    else if (xml.startsWith('<!', lt)) {
      throw new UtdError('MALFORMED_XML', `Unexpected declaration at offset ${String(lt)}`);
    } else if (xml.startsWith('</', lt)) {
      if (depth === 0) break;
      depth--;
      pos = skipPast(xml, lt, '>');
    } else {
      const tag = readStartTag(xml, lt);
      if (depth === 0 && tag.name === name) return tag;
      if (!tag.selfClosing) depth++;
      pos = tag.end;
    }
  }
  throw new UtdError('MISSING_ELEMENT', `<${parent.name}> has no <${name}>`);
}

/** Rejects truncated input: after `</root>` only whitespace and comments may follow. */
function checkClosed(xml: string, root: string): void {
  let end = xml.length;
  for (;;) {
    while (end > 0 && ' \t\r\n'.includes(xml.charAt(end - 1))) end--;
    if (!xml.endsWith('-->', end)) break;
    const open = xml.lastIndexOf('<!--', end - 3);
    if (open === -1) break;
    end = open;
  }
  const tail = xml.slice(Math.max(0, end - root.length - 16), end);
  if (!new RegExp(`</${root}${WS}*>$`).test(tail)) {
    throw new UtdError('MALFORMED_XML', `Document does not end with </${root}> (truncated?)`);
  }
}

/** Skips whitespace, comments and processing instructions before the root element. */
function skipMisc(xml: string, from: number): number {
  let pos = from;
  for (;;) {
    while (pos < xml.length && ' \t\r\n'.includes(xml.charAt(pos))) pos++;
    if (xml.startsWith('<!--', pos)) pos = skipPast(xml, pos, '-->');
    else if (xml.startsWith('<?', pos)) pos = skipPast(xml, pos, '?>');
    else return pos;
  }
}

function skipPast(xml: string, from: number, terminator: string): number {
  const at = xml.indexOf(terminator, from);
  if (at === -1) {
    throw new UtdError('MALFORMED_XML', `Unterminated markup at offset ${String(from)}`);
  }
  return at + terminator.length;
}

function readStartTag(xml: string, lt: number): StartTag {
  const name = /[^ \t\r\n/>]+/y;
  name.lastIndex = lt + 1;
  const tagName = name.exec(xml)?.[0];
  if (tagName === undefined) {
    throw new UtdError('MALFORMED_XML', `Bad tag at offset ${String(lt)}`);
  }
  const attrs = new Map<string, string>();
  const attr = new RegExp(`${WS}+([^ \\t\\r\\n=/>]+)${WS}*=${WS}*(?:"([^"<]*)"|'([^'<]*)')`, 'y');
  attr.lastIndex = name.lastIndex;
  let end = name.lastIndex;
  for (let m = attr.exec(xml); m; m = attr.exec(xml)) {
    const key = m[1] ?? '';
    if (attrs.has(key)) throw new UtdError('MALFORMED_XML', `Duplicate attribute ${key}`);
    attrs.set(key, unescapeXml(m[2] ?? m[3] ?? ''));
    end = attr.lastIndex;
  }
  const close = new RegExp(`${WS}*(/?)>`, 'y');
  close.lastIndex = end;
  const closed = close.exec(xml);
  if (!closed) throw new UtdError('MALFORMED_XML', `Bad attributes in <${tagName}>`);
  return { name: tagName, attrs, end: close.lastIndex, selfClosing: closed[1] === '/' };
}

const NAMED_ENTITIES: ReadonlyMap<string, string> = new Map([
  ['lt', '<'],
  ['gt', '>'],
  ['amp', '&'],
  ['quot', '"'],
  ['apos', "'"],
]);

/** XML 1.0 `Char` production. */
function isXmlChar(code: number): boolean {
  return (
    code === 0x9 ||
    code === 0xa ||
    code === 0xd ||
    (code >= 0x20 && code <= 0xd7ff) ||
    (code >= 0xe000 && code <= 0xfffd) ||
    (code >= 0x10000 && code <= 0x10ffff)
  );
}

function unescapeXml(value: string): string {
  return value.replace(/&([^;]*);|&/g, (whole, ref: string | undefined) => {
    const named = ref === undefined ? undefined : NAMED_ENTITIES.get(ref);
    if (named !== undefined) return named;
    const num = ref === undefined ? undefined : /^#(?:x([0-9a-f]+)|([0-9]+))$/i.exec(ref);
    const code = num ? parseInt(num[1] ?? num[2] ?? '', num[1] ? 16 : 10) : NaN;
    if (!isXmlChar(code)) throw new UtdError('MALFORMED_XML', `Bad entity reference ${whole}`);
    return String.fromCodePoint(code);
  });
}

function requireAttr(tag: StartTag, name: string): string {
  const value = tag.attrs.get(name);
  if (value === undefined || value === '') {
    throw new UtdError('MISSING_ATTRIBUTE', `<${tag.name}> has no ${name}`);
  }
  return value;
}

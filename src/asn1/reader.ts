// Minimal DER reader for walking known structures (CMS SignedData, X.509). Definite lengths and
// low tag numbers only — enough for CMS/X.509; run BER input through `berToDer` first.
import { Asn1Error } from './der.js';

const CONSTRUCTED = 0x20;
/** Length octets beyond 4 would exceed any buffer we handle. */
const MAX_LENGTH_OCTETS = 4;

export interface DerElement {
  /** The identifier octet (class, constructed bit and tag number), e.g. 0x30 SEQUENCE, 0xa0 [0]. */
  tag: number;
  constructed: boolean;
  /** Content octets. */
  content: Buffer;
  /** The whole encoding: identifier, length and content. */
  raw: Buffer;
  /** Offset of `raw` in the buffer passed to `readDer`, for error messages. */
  offset: number;
}

/**
 * Reads one DER element spanning the whole input.
 * @throws Asn1Error on malformed input, an indefinite length or a high tag number.
 */
export function readDer(input: Buffer): DerElement {
  if (input.length === 0) throw new Asn1Error('empty input', 0);
  const element = readAt(input, 0, input.length, 0);
  if (element.raw.length !== input.length) {
    throw new Asn1Error('trailing bytes after the element', element.raw.length);
  }
  return element;
}

/** The elements inside a constructed element, in order. */
export function derChildren(element: DerElement): DerElement[] {
  if (!element.constructed) {
    throw new Asn1Error('a primitive element has no children', element.offset);
  }
  const base = element.offset + element.raw.length - element.content.length;
  const children: DerElement[] = [];
  let pos = 0;
  while (pos < element.content.length) {
    const child = readAt(element.content, pos, element.content.length, base);
    children.push(child);
    pos += child.raw.length;
  }
  return children;
}

function readAt(buf: Buffer, start: number, limit: number, base: number): DerElement {
  let pos = start;
  const byte = (): number => {
    if (pos >= limit) throw new Asn1Error('unexpected end of data', base + pos);
    return buf[pos++] ?? 0;
  };
  const tag = byte();
  if ((tag & 0x1f) === 0x1f)
    throw new Asn1Error('high tag numbers are not supported', base + start);
  const lengthStart = pos;
  const first = byte();
  let length = first;
  if (first === 0x80) throw new Asn1Error('indefinite length in DER', base + lengthStart);
  if (first > 0x80) {
    const count = first & 0x7f;
    if (count > MAX_LENGTH_OCTETS) throw new Asn1Error('length too long', base + lengthStart);
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + byte();
  }
  if (length > limit - pos) {
    throw new Asn1Error('length exceeds the available data', base + lengthStart);
  }
  const end = pos + length;
  return {
    tag,
    constructed: (tag & CONSTRUCTED) !== 0,
    content: buf.subarray(pos, end),
    raw: buf.subarray(start, end),
    offset: base + start,
  };
}

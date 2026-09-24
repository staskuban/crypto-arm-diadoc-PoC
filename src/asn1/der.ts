// Schema-less BER -> DER *framing* normalizer (X.690 §10), enough for CMS from КриптоПро/КриптоАРМ.
// Hand-written instead of asn1js/pkijs: those re-encode through a schema, and we must guarantee
// that signed subtrees keep their exact bytes; this is ~250 lines with no dependencies.
//
// Rewritten: indefinite lengths -> definite; non-minimal lengths -> minimal; constructed universal
// string types -> primitive. Kept byte for byte: every primitive value and the order of elements.
// A subtree that is already DER framed is copied verbatim, so certificates and
// SignerInfo.signedAttrs (covered by signatures) do not change as long as they arrive DER framed
// — true for КриптоАРМ Server, whose BER is only in the outer SignedData layers. A certificate with
// BER inside would be re-encoded and its CA signature broken; verify the result (/cms/verify).
//
// Not enforced (needs a schema or would alter signed data): SET OF sorting (§11.6 — matters once a
// CMS carries several certificates), value canonicalization (BOOLEAN, INTEGER, BIT STRING padding),
// and IMPLICIT-tagged constructed strings, e.g. SignerIdentifier `subjectKeyIdentifier [0]
// IMPLICIT OCTET STRING` in constructed form stays constructed (КриптоПро uses
// issuerAndSerialNumber).

/** Malformed or unsupported BER input. */
export class Asn1Error extends Error {
  override name = 'Asn1Error';

  constructor(
    detail: string,
    /** Byte offset in the input where the problem was found. */
    readonly offset: number,
  ) {
    super(`${detail} at offset ${String(offset)}`);
  }
}

/** Nesting limit: CMS needs ~20 levels; bounds recursion on hostile input. */
const MAX_DEPTH = 64;
/** Length octets beyond 4 would exceed any buffer we handle. */
const MAX_LENGTH_OCTETS = 4;
const CONSTRUCTED = 0x20;
const CLASS_MASK = 0xc0;
const UNIVERSAL = 0x00;
const BIT_STRING = 3;
/** Universal types whose BER encoding may be constructed (X.690 §8.21, §8.6, §8.7) — DER forbids it. */
const STRING_TAGS = new Set([3, 4, 7, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30]);

interface Node {
  /** Offset of the element in the input, for error messages. */
  start: number;
  /** Identifier octets, copied as is. */
  identifier: Buffer;
  /** Universal string type number when constructed (to be flattened), else undefined. */
  stringTag: number | undefined;
  /** Whole encoding in the input (identifier, length, content, end-of-contents). */
  raw: Buffer;
  /** The input encoding of this subtree is already DER framed. */
  der: boolean;
  /** Primitive content, or undefined for constructed. */
  content: Buffer | undefined;
  children: Node[];
}

/**
 * Re-encodes a single BER element spanning the whole input with DER framing (see the file
 * header for what is and is not changed). DER input is returned unchanged.
 * @throws Asn1Error on malformed input.
 */
export function berToDer(input: Buffer): Buffer {
  const root = parseRoot(input);
  return root.der ? root.raw : Buffer.concat(encode(root));
}

/**
 * True when the input is one element spanning the buffer with DER framing throughout: definite
 * minimal lengths and primitive universal strings. Not a full DER check (see the file header):
 * an unsorted SET OF or a non-canonical value still passes.
 */
export function isDerFramed(input: Buffer): boolean {
  try {
    return parseRoot(input).der;
  } catch (error) {
    if (error instanceof Asn1Error) return false;
    throw error;
  }
}

function parseRoot(input: Buffer): Node {
  if (input.length === 0) throw new Asn1Error('empty input', 0);
  const node = parse(input, 0, input.length, 0);
  if (node.identifier[0] === 0 && node.raw.length === 2) {
    throw new Asn1Error('unexpected end-of-contents', 0);
  }
  if (node.raw.length !== input.length) {
    throw new Asn1Error('trailing bytes after the element', node.raw.length);
  }
  return node;
}

/** Parses one element starting at `start`, not reading past `limit`. */
function parse(buf: Buffer, start: number, limit: number, depth: number): Node {
  if (depth > MAX_DEPTH) throw new Asn1Error(`nesting deeper than ${String(MAX_DEPTH)}`, start);
  let pos = start;
  const byte = (): number => {
    if (pos >= limit) throw new Asn1Error('unexpected end of data', pos);
    return buf[pos++] ?? 0;
  };

  const first = byte();
  const constructed = (first & CONSTRUCTED) !== 0;
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    const tagStart = pos;
    let b = byte();
    if (b === 0x80) throw new Asn1Error('non-minimal high tag number', tagStart);
    tagNumber = 0;
    for (;;) {
      tagNumber = tagNumber * 128 + (b & 0x7f);
      if (tagNumber > Number.MAX_SAFE_INTEGER / 128)
        throw new Asn1Error('tag number too large', tagStart);
      if ((b & 0x80) === 0) break;
      b = byte();
    }
    if (tagNumber < 0x1f) throw new Asn1Error('high tag form for a low tag number', tagStart);
  }
  const identifier = buf.subarray(start, pos);
  const universal = (first & CLASS_MASK) === UNIVERSAL;

  const lengthStart = pos;
  const lengthByte = byte();
  let length: number | undefined; // undefined = indefinite
  let minimalLength = true;
  if (lengthByte < 0x80) {
    length = lengthByte;
  } else if (lengthByte === 0x80) {
    if (!constructed) throw new Asn1Error('indefinite length on a primitive', lengthStart);
    minimalLength = false;
  } else {
    const count = lengthByte & 0x7f;
    if (count === 0x7f) throw new Asn1Error('reserved length octet', lengthStart);
    if (count > MAX_LENGTH_OCTETS) throw new Asn1Error('length too long', lengthStart);
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + byte();
    minimalLength = length >= 0x80 && buf[lengthStart + 1] !== 0;
  }

  const contentStart = pos;
  if (length !== undefined && length > limit - contentStart) {
    throw new Asn1Error('length exceeds the available data', lengthStart);
  }

  if (universal && tagNumber === 0 && first === 0) {
    // End-of-contents: only valid as a terminator, handled by the caller.
    if (length !== 0 || pos !== start + 2)
      throw new Asn1Error('end-of-contents must be two zero octets', start);
    return {
      start,
      identifier,
      stringTag: undefined,
      raw: buf.subarray(start, pos),
      der: false,
      content: undefined,
      children: [],
    };
  }

  if (!constructed) {
    const end = contentStart + (length ?? 0);
    return {
      start,
      identifier,
      stringTag: undefined,
      raw: buf.subarray(start, end),
      der: minimalLength,
      content: buf.subarray(contentStart, end),
      children: [],
    };
  }

  const children: Node[] = [];
  let end: number;
  if (length === undefined) {
    for (;;) {
      const child = parse(buf, pos, limit, depth + 1);
      pos += child.raw.length;
      if (isEndOfContents(child)) break;
      children.push(child);
    }
    end = pos;
  } else {
    end = contentStart + length;
    while (pos < end) {
      const child = parse(buf, pos, end, depth + 1);
      if (isEndOfContents(child)) throw new Asn1Error('end-of-contents in a definite length', pos);
      pos += child.raw.length;
      children.push(child);
    }
  }

  const stringTag = universal && STRING_TAGS.has(tagNumber) ? tagNumber : undefined;
  if (stringTag !== undefined) checkSegments(stringTag, children);
  return {
    start,
    identifier,
    stringTag,
    raw: buf.subarray(start, end),
    der: minimalLength && stringTag === undefined && children.every((c) => c.der),
    content: undefined,
    children,
  };
}

function isEndOfContents(node: Node): boolean {
  return node.identifier.length === 1 && node.identifier[0] === 0;
}

/** X.690 §8.6.4, §8.7.3, §8.21.5: segments of a constructed string have the same universal type. */
function checkSegments(tag: number, segments: Node[]): void {
  for (const segment of segments) {
    const segmentTag = (segment.identifier[0] ?? 0) & ~CONSTRUCTED;
    if (segment.identifier.length !== 1 || segmentTag !== tag) {
      throw new Asn1Error('constructed string segment of another type', segment.start);
    }
  }
  if (tag === BIT_STRING) {
    // X.690 §8.6.4: each primitive segment starts with an unused-bits octet; only the last may
    // leave bits unused. Checked across nesting levels, as flattening joins them all.
    const primitives = primitiveSegments(segments);
    primitives.forEach((segment, i) => {
      const unused = segment.content?.[0];
      if (unused === undefined) {
        throw new Asn1Error('BIT STRING segment without unused-bits octet', segment.start);
      }
      const last = i === primitives.length - 1;
      if (unused > 7 || (unused !== 0 && (!last || segment.content?.length === 1))) {
        throw new Asn1Error('BIT STRING unused bits outside the last segment', segment.start);
      }
    });
  }
}

function primitiveSegments(segments: Node[]): Node[] {
  return segments.flatMap((s) => (s.content === undefined ? primitiveSegments(s.children) : [s]));
}

function encode(node: Node): Buffer[] {
  if (node.der) return [node.raw];
  if (node.content !== undefined) return withHeader(node.identifier, [node.content]);
  if (node.stringTag !== undefined) {
    const identifier = Buffer.from([node.stringTag]);
    return withHeader(identifier, flatten(node.stringTag, node));
  }
  return withHeader(node.identifier, node.children.flatMap(encode));
}

/** Concatenates primitive segments; for BIT STRING keeps one unused-bits octet (from the last). */
function flatten(tag: number, node: Node): Buffer[] {
  const primitives = primitiveSegments(node.children).map((s) => s.content ?? Buffer.alloc(0));
  if (tag !== BIT_STRING) return primitives;
  const unused = primitives.at(-1)?.[0] ?? 0;
  return [Buffer.from([unused]), ...primitives.map((p) => p.subarray(1))];
}

function withHeader(identifier: Buffer, content: Buffer[]): Buffer[] {
  const length = content.reduce((sum, part) => sum + part.length, 0);
  return [identifier, encodeLength(length), ...content];
}

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { Asn1Error } from './der.js';
import { derChildren, readDer } from './reader.js';

const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');
const cms = readFileSync(new URL('fixtures/server-cms-detached.openssl.der', import.meta.url));

describe('readDer', () => {
  it('reads a primitive element', () => {
    const el = readDer(hex('02 02 01 00'));
    expect(el).toMatchObject({ tag: 0x02, constructed: false });
    expect(el.content).toEqual(hex('0100'));
    expect(el.raw).toEqual(hex('02020100'));
  });

  it('reads long-form lengths and constructed children in order', () => {
    const el = readDer(cms);
    expect(el.tag).toBe(0x30);
    expect(el.constructed).toBe(true);
    expect(el.raw.length).toBe(cms.length);
    const [oid, content] = derChildren(el);
    expect(oid?.content).toEqual(hex('2a864886f70d010702'));
    expect(content?.tag).toBe(0xa0);
    // Offsets from `openssl asn1parse`: SignedData at 19, 2175 content bytes after a 4-byte header.
    const [signedData] = derChildren(content ?? el);
    expect(signedData?.raw.length).toBe(4 + 2175);
    expect(derChildren(signedData ?? el).map((c) => c.tag)).toEqual([0x02, 0x31, 0x30, 0xa0, 0x31]);
  });

  it('rejects indefinite lengths, trailing bytes, truncation and high tags', () => {
    expect(() => readDer(hex('30 80 00 00'))).toThrow(Asn1Error);
    expect(() => readDer(hex('02 01 00 00'))).toThrow(/trailing/);
    expect(() => readDer(hex('02 05 00'))).toThrow(/exceeds/);
    expect(() => readDer(hex('1f 81 00 00'))).toThrow(/high tag/);
    expect(() => readDer(Buffer.alloc(0))).toThrow(Asn1Error);
  });

  it('rejects children of a primitive and garbage inside a constructed element', () => {
    expect(() => derChildren(readDer(hex('04 01 00')))).toThrow(/primitive/);
    expect(() => derChildren(readDer(hex('30 02 02 05')))).toThrow(Asn1Error);
  });
});

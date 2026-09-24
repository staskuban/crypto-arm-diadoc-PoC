import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { Asn1Error, berToDer, isDerFramed } from './der.js';

const fixture = (name: string): Buffer =>
  readFileSync(new URL(`fixtures/${name}`, import.meta.url));

// Real detached CAdES-BES over `server-cms-detached.data`, as returned by КриптоАРМ Server
// `/cms/sign` (2026-09-24). The `.openssl.der` file is `openssl cms -cmsout -outform DER` of it.
const serverBer = fixture('server-cms-detached.ber');
const opensslDer = fixture('server-cms-detached.openssl.der');

const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

describe('berToDer on a real КриптоАРМ Server CMS', () => {
  const der = berToDer(serverBer);

  it('replaces indefinite lengths with definite ones', () => {
    expect(serverBer.subarray(0, 2)).toEqual(hex('3080'));
    expect(isDerFramed(serverBer)).toBe(false);
    expect(der.subarray(0, 4)).toEqual(hex('308208 92'));
    expect(isDerFramed(der)).toBe(true);
  });

  it('matches the OpenSSL DER re-encoding byte for byte', () => {
    expect(der).toEqual(opensslDer);
  });

  it('keeps certificates, signedAttrs and the signature value byte for byte', () => {
    // Offsets from `openssl asn1parse`: in the BER input, certificates [0] start at 49 and the
    // signerInfos SET ends at 2194; the DER output shifts them by 4 header bytes.
    expect(der.subarray(53, 2198)).toEqual(serverBer.subarray(49, 2194));
    const signedAttrs = serverBer.subarray(1625, 1625 + 4 + 487);
    expect(signedAttrs[0]).toBe(0xa0);
    expect(der.includes(signedAttrs)).toBe(true);
  });

  it('is idempotent and returns DER input unchanged', () => {
    expect(berToDer(der)).toEqual(der);
    expect(berToDer(opensslDer)).toEqual(opensslDer);
  });
});

describe('berToDer', () => {
  it.each([
    ['indefinite SEQUENCE', '30 80 02 01 05 00 00', '30 03 02 01 05'],
    ['nested indefinite', '30 80 a0 80 04 00 00 00 00 00', '30 04 a0 02 04 00'],
    ['non-minimal short length', '04 81 02 aa bb', '04 02 aa bb'],
    ['length with leading zero', '04 82 00 01 aa', '04 01 aa'],
    ['constructed OCTET STRING', '24 80 04 02 aa bb 04 01 cc 00 00', '04 03 aa bb cc'],
    ['definite constructed OCTET STRING', '24 07 04 02 aa bb 04 01 cc', '04 03 aa bb cc'],
    ['nested constructed OCTET STRING', '24 80 24 80 04 01 aa 00 00 04 01 bb 00 00', '04 02 aa bb'],
    ['empty constructed OCTET STRING', '24 80 00 00', '04 00'],
    ['constructed BIT STRING', '23 80 03 02 00 aa 03 02 04 b0 00 00', '03 03 04 aa b0'],
    ['constructed UTF8String', '2c 80 0c 01 41 0c 01 42 00 00', '0c 02 41 42'],
    ['SET element order kept', '31 80 02 01 02 02 01 01 00 00', '31 06 02 01 02 02 01 01'],
    ['high tag number', 'bf 1f 80 02 01 01 00 00', 'bf 1f 03 02 01 01'],
    ['implicit context-specific kept constructed', 'a1 80 04 01 aa 00 00', 'a1 03 04 01 aa'],
  ])('%s', (_name, input, output) => {
    const der = berToDer(hex(input));
    expect(der).toEqual(hex(output));
    expect(isDerFramed(der)).toBe(true);
  });

  it('encodes long definite lengths minimally', () => {
    for (const size of [127, 128, 255, 256, 65_536]) {
      const content = Buffer.alloc(size, 0xab);
      const ber = Buffer.concat([hex('24 80 04 84'), u32(size), content, hex('00 00')]);
      const der = berToDer(ber);
      expect(isDerFramed(der)).toBe(true);
      expect(der.subarray(der.length - size)).toEqual(content);
      expect(der.length).toBe(1 + lengthOfLength(size) + size);
    }
  });

  it.each([
    ['empty input', ''],
    ['truncated header', '30'],
    ['truncated content', '04 05 aa'],
    ['trailing bytes', '04 01 aa 00'],
    ['two top-level elements', '04 01 aa 04 01 bb'],
    ['top-level end-of-contents', '00 00'],
    ['missing end-of-contents', '30 80 02 01 05'],
    ['end-of-contents with length', '30 80 00 01 00 00 00'],
    ['end-of-contents in a definite length', '30 02 00 00'],
    ['end-of-contents with long-form length', '30 80 00 81 00'],
    ['top-level end-of-contents with long-form length', '00 81 00'],
    ['BIT STRING last segment of one octet with unused bits', '23 80 03 01 04 00 00'],
    ['indefinite length on a primitive', '04 80 aa 00 00'],
    ['reserved length octet', '04 ff'],
    ['length too long', '04 89 01 00 00 00 00 00 00 00 00'],
    ['length beyond the buffer', '04 84 7f ff ff ff aa'],
    ['definite content overruns its parent', '30 03 04 03 aa bb cc'],
    ['constructed string with a foreign segment', '24 80 02 01 01 00 00'],
    ['BIT STRING segment with unused bits not last', '23 80 03 02 04 a0 03 02 00 aa 00 00'],
    ['BIT STRING segment without unused-bits octet', '23 80 03 00 00 00'],
    ['non-minimal high tag number', 'bf 80 1f 00'],
    ['high tag form for a low tag number', '9f 05 00'],
  ])('rejects %s with Asn1Error', (_name, input) => {
    expect(() => berToDer(hex(input))).toThrow(Asn1Error);
    expect(isDerFramed(hex(input))).toBe(false);
  });

  it('rejects deep nesting with Asn1Error instead of overflowing the stack', () => {
    const depth = 10_000;
    const bomb = Buffer.concat([
      Buffer.alloc(depth * 2).fill(Buffer.from([0x30, 0x80])),
      Buffer.alloc(depth * 2),
    ]);
    expect(() => berToDer(bomb)).toThrow(Asn1Error);
  });
});

describe('isDerFramed', () => {
  it.each([
    ['unsorted SET OF', '31 06 02 01 02 02 01 01'],
    ['non-canonical BOOLEAN', '01 01 01'],
    ['non-minimal INTEGER', '02 02 00 01'],
  ])('checks framing only, not value canonicalization: %s', (_name, input) => {
    expect(isDerFramed(hex(input))).toBe(true);
    expect(berToDer(hex(input))).toEqual(hex(input));
  });

  it.each([
    ['indefinite length', '30 80 00 00'],
    ['non-minimal length', '04 81 01 aa'],
    ['constructed OCTET STRING', '24 03 04 01 aa'],
  ])('is false for BER-only encodings: %s', (_name, input) => {
    expect(isDerFramed(hex(input))).toBe(false);
  });
});

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

function lengthOfLength(n: number): number {
  if (n < 0x80) return 1;
  return 1 + Math.ceil(n.toString(16).length / 2);
}

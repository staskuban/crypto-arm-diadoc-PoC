import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { parseCertificate, parseCmsSignedData } from './cms.js';
import { Asn1Error } from './der.js';
import { derChildren, readDer, type DerElement } from './reader.js';

const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');
// Real detached CAdES-BES from КриптоАРМ Server, signed by CN=cryptoarm.server.test (see der.test.ts).
const cms = readFileSync(new URL('fixtures/server-cms-detached.openssl.der', import.meta.url));

/** DER TLV with a short or long length; enough for test structures. */
function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const content = Buffer.concat(parts);
  const n = content.length;
  const length =
    n < 0x80
      ? Buffer.from([n])
      : n < 0x100
        ? Buffer.from([0x81, n])
        : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, content]);
}

const child = (el: DerElement, i: number): DerElement => {
  const c = derChildren(el)[i];
  if (c === undefined) throw new Error(`no child ${String(i)}`);
  return c;
};

// ContentInfo -> [0] -> SignedData { version, digestAlgorithms, encapContentInfo, [0] certs, signerInfos }
const signedData = child(child(readDer(cms), 1), 0);
const [version, digestAlgorithms, encap, certificates, signerInfos] = derChildren(signedData).map(
  (c) => c.raw,
) as [Buffer, Buffer, Buffer, Buffer, Buffer];
const signerInfo = child(readDer(signerInfos), 0).raw;
const certificate = child(readDer(certificates), 0).raw;
const SIGNED_DATA_OID = hex('06092a864886f70d010702');
const DATA_OID = hex('06092a864886f70d010701');

function contentInfo(...signedDataParts: Buffer[]): Buffer {
  return tlv(0x30, SIGNED_DATA_OID, tlv(0xa0, tlv(0x30, ...signedDataParts)));
}

describe('parseCertificate', () => {
  it('reads issuer, serial, subject, validity and the subject key identifier', () => {
    const info = parseCertificate(certificate);
    expect(info.serialNumber).toEqual(hex('7C003B00DFEF3FBCA12EAFB41B0015003B00DF'));
    expect(info.notBefore.toISOString()).toBe('2026-09-10T15:36:37.000Z');
    expect(info.notAfter.toISOString()).toBe('2026-10-28T12:32:11.000Z');
    expect(info.subjectKeyIdentifier).toEqual(hex('B098F21D302597CBC4D71EA248E9A034458326A4'));
    expect(info.subject.includes(Buffer.from('cryptoarm.server.test'))).toBe(true);
    expect(info.issuer[0]).toBe(0x30);
    expect(info.issuer.includes(Buffer.from('Москва'))).toBe(true);
  });

  it('reads the КриптоПро test CA root (no SKI order assumptions)', () => {
    const root = readFileSync(
      new URL('../signer/fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
    );
    const info = parseCertificate(root);
    expect(info.issuer).toEqual(info.subject); // self-signed
    expect(info.notAfter.getTime()).toBeGreaterThan(info.notBefore.getTime());
  });

  const name = tlv(0x30);
  const tbs = (validity: Buffer) =>
    tlv(
      0x30,
      tlv(0x30, tlv(0x02, hex('01')), tlv(0x30), name, validity, name, tlv(0x30)),
      tlv(0x30),
      tlv(0x03, hex('00')),
    );
  const utc = (s: string) => tlv(0x17, Buffer.from(s));
  const gen = (s: string) => tlv(0x18, Buffer.from(s));
  const notBefore = (time: Buffer) =>
    parseCertificate(tbs(tlv(0x30, time, utc('991231000000Z')))).notBefore;

  it('parses GeneralizedTime and UTCTime around the 2050 pivot', () => {
    const info = parseCertificate(tbs(tlv(0x30, utc('491231235959Z'), gen('20500101000000Z'))));
    expect(info.notBefore.toISOString()).toBe('2049-12-31T23:59:59.000Z');
    expect(info.notAfter.toISOString()).toBe('2050-01-01T00:00:00.000Z');
    expect(info.subjectKeyIdentifier).toBeUndefined();
    expect(
      parseCertificate(
        tbs(tlv(0x30, utc('500101000000Z'), utc('991231000000Z'))),
      ).notBefore.getUTCFullYear(),
    ).toBe(1950);
    expect(() =>
      parseCertificate(tbs(tlv(0x30, utc('2601010000Z'), utc('991231000000Z')))),
    ).toThrow(Asn1Error);
  });

  it('keeps a GeneralizedTime year below 100 (Date.UTC would map it to 19xx)', () => {
    expect(notBefore(gen('00990101000000Z')).toISOString()).toBe('0099-01-01T00:00:00.000Z');
  });

  it.each([
    ['a UTCTime text under the GeneralizedTime tag', gen('260101000000Z')],
    ['a GeneralizedTime text under the UTCTime tag', utc('20260101000000Z')],
    ['another tag', tlv(0x04, Buffer.from('260101000000Z'))],
    ['bytes after the Z', utc('260101000000Z1')],
    ['a time zone offset', utc('260101000000+0300')],
    ['a fraction of a second', gen('20260101000000.5Z')],
  ])('rejects %s as not an RFC 5280 time', (_name, time) => {
    expect(() => notBefore(time)).toThrow(/notBefore is not an RFC 5280 time/);
  });

  it.each([
    ['month 13', utc('261301000000Z')],
    ['month 00', gen('20260001000000Z')],
    ['30 February', utc('260230000000Z')],
    ['hour 24', utc('260101240000Z')],
    ['minute 60', utc('260101106000Z')],
    ['second 60', utc('260101100060Z')],
  ])('rejects %s as not a valid date', (_name, time) => {
    expect(() => notBefore(time)).toThrow(/notBefore is not a valid date/);
  });

  it('rejects something that is not a certificate', () => {
    expect(() => parseCertificate(hex('3003020101'))).toThrow(Asn1Error);
    expect(() => parseCertificate(cms)).toThrow(Asn1Error);
  });

  it('requires exactly three Certificate elements', () => {
    const parts = derChildren(readDer(certificate)).map((c) => c.raw);
    expect(() => parseCertificate(tlv(0x30, ...parts, tlv(0x05)))).toThrow(/3 elements/);
    expect(() => parseCertificate(tlv(0x30, ...parts.slice(0, 2)))).toThrow(/3 elements/);
  });
});

describe('parseCmsSignedData', () => {
  it('reads a real detached CMS: one signer by issuer and serial, one embedded certificate', () => {
    const info = parseCmsSignedData(cms);
    expect(info.detached).toBe(true);
    expect(info.certificates).toEqual([certificate]);
    expect(info.signers).toHaveLength(1);
    const cert = parseCertificate(certificate);
    expect(info.signers[0]).toEqual({ issuer: cert.issuer, serialNumber: cert.serialNumber });
  });

  it('reports an attached CMS (eContent present)', () => {
    const attached = tlv(0x30, DATA_OID, tlv(0xa0, tlv(0x04, Buffer.from('payload'))));
    const info = parseCmsSignedData(
      contentInfo(version, digestAlgorithms, attached, certificates, signerInfos),
    );
    expect(info.detached).toBe(false);
    expect(encap).toEqual(tlv(0x30, DATA_OID)); // the real one has no eContent
  });

  it('lists every signer, including a subjectKeyIdentifier one, and tolerates no certificates', () => {
    const [, , ...rest] = derChildren(readDer(signerInfo)).map((c) => c.raw);
    const byKeyId = tlv(0x30, tlv(0x02, hex('03')), tlv(0x80, hex('aabb')), ...rest);
    const info = parseCmsSignedData(
      contentInfo(version, digestAlgorithms, encap, tlv(0x31, signerInfo, byKeyId)),
    );
    expect(info.certificates).toEqual([]);
    expect(info.signers).toHaveLength(2);
    expect(info.signers[1]).toEqual({ subjectKeyIdentifier: hex('aabb') });
  });

  it('skips crls and non-certificate choices in the certificates set', () => {
    const other = tlv(0xa1, hex('00')); // [1] extendedCertificate (obsolete choice)
    const info = parseCmsSignedData(
      contentInfo(
        version,
        digestAlgorithms,
        encap,
        tlv(0xa0, certificate, other),
        tlv(0xa1),
        signerInfos,
      ),
    );
    expect(info.certificates).toEqual([certificate]);
    expect(info.signers).toHaveLength(1);
  });

  it('rejects a SignerIdentifier with more than issuer and serial', () => {
    const [, sid, ...rest] = derChildren(readDer(signerInfo)).map((c) => c.raw);
    const sidParts = derChildren(readDer(sid ?? hex('3000'))).map((c) => c.raw);
    const extended = tlv(0x30, version, tlv(0x30, ...sidParts, hex('0500')), ...rest);
    expect(() =>
      parseCmsSignedData(contentInfo(version, digestAlgorithms, encap, tlv(0x31, extended))),
    ).toThrow(/SignerIdentifier must have 2 elements/);
  });

  it('requires the SignerInfo version that matches the sid form (RFC 5652 5.3)', () => {
    const [, sid, ...rest] = derChildren(readDer(signerInfo)).map((c) => c.raw);
    const v3BySerial = tlv(0x30, tlv(0x02, hex('03')), sid ?? hex('3000'), ...rest);
    const v1ByKeyId = tlv(0x30, tlv(0x02, hex('01')), tlv(0x80, hex('aabb')), ...rest);
    for (const bad of [v3BySerial, v1ByKeyId]) {
      expect(() =>
        parseCmsSignedData(contentInfo(version, digestAlgorithms, encap, tlv(0x31, bad))),
      ).toThrow(/SignerInfo version/);
    }
  });

  it('rejects an element after signerInfos', () => {
    expect(() =>
      parseCmsSignedData(
        contentInfo(version, digestAlgorithms, encap, certificates, signerInfos, tlv(0x05)),
      ),
    ).toThrow(/unexpected element after signerInfos/);
  });

  it('requires exactly one SignedData inside the [0] wrapper and nothing after it', () => {
    const body = tlv(0x30, version, digestAlgorithms, encap, signerInfos);
    expect(() => parseCmsSignedData(tlv(0x30, SIGNED_DATA_OID, tlv(0xa0, body, body)))).toThrow(
      /unexpected elements in ContentInfo/,
    );
    expect(() =>
      parseCmsSignedData(tlv(0x30, SIGNED_DATA_OID, tlv(0xa0, body), tlv(0x05))),
    ).toThrow(/unexpected elements in ContentInfo/);
  });

  it('rejects a non-SignedData ContentInfo and a malformed SignedData', () => {
    expect(() => parseCmsSignedData(tlv(0x30, DATA_OID, tlv(0xa0, tlv(0x04))))).toThrow(
      /not a CMS SignedData/,
    );
    expect(() => parseCmsSignedData(contentInfo(version, digestAlgorithms))).toThrow(Asn1Error);
    expect(() => parseCmsSignedData(hex('3080'))).toThrow(Asn1Error);
  });
});

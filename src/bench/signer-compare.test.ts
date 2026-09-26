import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { parseUtd } from '../utd/index.js';
import {
  cmsProfile,
  generateUtd,
  latencySummary,
  percentile,
  structuralDiff,
} from './signer-compare.js';

// Real detached CAdES-BES from КриптоАРМ Server, signed by CN=cryptoarm.server.test (asn1 fixtures).
const cms = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
const ber = readFileSync(new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url));
/** Offsets in the fixture (openssl asn1parse): signingTime UTCTime content, signature value. */
const SIGNING_TIME_CONTENT = 1676;
const SIGNATURE_VALUE = 2134;
const CERT_SERIAL_CONTENT = 72;

function patched(offset: number, byte = 0x00): Buffer {
  const copy = Buffer.from(cms);
  copy[offset] = (copy[offset] ?? 0) ^ (byte === 0 ? 0x01 : byte);
  return copy;
}

describe('cmsProfile', () => {
  it('describes the КриптоАРМ Server detached CAdES-BES', () => {
    const embedded = cms.subarray(57, 57 + 1254);
    expect(cmsProfile(cms)).toEqual({
      der: true,
      bytes: 2198,
      version: 1,
      detached: true,
      eContentType: '1.2.840.113549.1.7.1',
      digestAlgorithms: ['1.2.643.7.1.1.2.2'],
      certificates: [createHash('sha1').update(embedded).digest('hex')],
      crls: false,
      signerInfos: 1,
      signer: {
        version: 1,
        sid: 'issuerAndSerialNumber',
        digestAlgorithm: '1.2.643.7.1.1.2.2',
        signatureAlgorithm: '1.2.643.7.1.1.1.1',
        signedAttributes: ['contentType', 'signingTime', 'messageDigest', 'signingCertificateV2'],
        unsignedAttributes: [],
        signingTime: '2026-09-24T11:10:05.000Z',
        signatureBytes: 64,
      },
      cades: 'CAdES-BES',
    });
  });

  it('reports BER input as not DER and still reads it after normalisation', () => {
    const profile = cmsProfile(ber);
    expect(profile.der).toBe(false);
    expect(profile.bytes).toBe(2200);
    expect(profile.signer?.signedAttributes).toContain('signingCertificateV2');
  });
});

describe('structuralDiff', () => {
  it('is empty for the same structure with another signing time and signature value', () => {
    const other = patched(SIGNING_TIME_CONTENT + 11);
    other[SIGNATURE_VALUE + 5] = 0xff - (other[SIGNATURE_VALUE + 5] ?? 0);
    expect(other.equals(cms)).toBe(false);
    expect(structuralDiff(cms, other)).toEqual([]);
  });

  it('names the path of any other difference', () => {
    const diff = structuralDiff(cms, patched(CERT_SERIAL_CONTENT));
    expect(diff).toHaveLength(1);
    expect(diff[0]).toMatch(/^0\.1\.0\.3\.0\.0\.1 /);
  });

  it('refuses a truncated CMS', () => {
    const shorter = Buffer.concat([cms.subarray(0, cms.length - 1)]);
    expect(structuralDiff(cms, shorter)).toEqual(['not comparable: second is not a CMS']);
  });
});

describe('latency', () => {
  it('uses the nearest-rank percentile', () => {
    const values = [5, 1, 4, 2, 3, 10, 9, 8, 7, 6];
    expect(percentile(values, 50)).toBe(5);
    expect(percentile(values, 95)).toBe(10);
    expect(percentile([42], 95)).toBe(42);
    expect(() => percentile([], 50)).toThrow();
  });

  it('summarises milliseconds', () => {
    expect(latencySummary([100, 300, 200])).toEqual({
      n: 3,
      min: 100,
      p50: 200,
      p95: 300,
      max: 300,
      mean: 200,
    });
  });
});

describe('generateUtd', () => {
  it('builds a parseable windows-1251 УПД of at least the requested size', () => {
    const utd = generateUtd(
      200_000,
      new Date('2026-09-26T10:00:00Z'),
      'c1c1c1c1-0000-4000-8000-000000000001',
    );
    expect(utd.content.length).toBeGreaterThanOrEqual(200_000);
    expect(utd.content.length).toBeLessThan(201_000);
    const parsed = parseUtd({ fileName: utd.fileName, content: utd.content });
    expect(`${parsed.idFile}.xml`).toBe(utd.fileName);
  });
});

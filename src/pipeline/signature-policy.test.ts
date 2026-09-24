import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { Asn1Error, berToDer, derChildren, parseCmsSignedData, readDer } from '../asn1/index.js';
import type { SignerInfo, VerifyResult } from '../signer/index.js';
import {
  classifyVerifyFailure,
  cmsPolicyViolations,
  readSignerCertificate,
  validityProblem,
  verifiedSignerViolations,
} from './signature-policy.js';

// Real detached CMS from КриптоАРМ Server by CN=cryptoarm.server.test; its certificate is embedded.
const CMS = readFileSync(
  new URL('../asn1/fixtures/server-cms-detached.openssl.der', import.meta.url),
);
const CERT = parseCmsSignedData(CMS).certificates[0] ?? Buffer.alloc(0);
const OTHER_CERT = readFileSync(
  new URL('../signer/fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
);
const THUMBPRINT = '0e84b59e46e4648fc3dc808eb94d58f4de673f1f';
const NOT_AFTER = Date.parse('2026-10-28T12:32:11Z');
const NOW = Date.parse('2026-10-01T00:00:00Z');

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

const [OID, WRAPPER] = derChildren(readDer(CMS));
const SIGNED_DATA = derChildren(derChildren(WRAPPER ?? readDer(CMS))[0] ?? readDer(CMS)).map(
  (c) => c.raw,
);
const [VERSION, DIGESTS, ENCAP, CERTS, SIGNER_INFOS] = SIGNED_DATA as [
  Buffer,
  Buffer,
  Buffer,
  Buffer,
  Buffer,
];
const SIGNER_INFO = derChildren(readDer(SIGNER_INFOS))[0]?.raw ?? Buffer.alloc(0);

function cms(parts: { encap?: Buffer; certs?: Buffer | null; signerInfos?: Buffer[] } = {}) {
  const certs = parts.certs === null ? [] : [parts.certs ?? CERTS];
  return tlv(
    0x30,
    OID?.raw ?? Buffer.alloc(0),
    tlv(
      0xa0,
      tlv(
        0x30,
        VERSION,
        DIGESTS,
        parts.encap ?? ENCAP,
        ...certs,
        tlv(0x31, ...(parts.signerInfos ?? [SIGNER_INFO])),
      ),
    ),
  );
}

/** The real SignerInfo with its sid replaced. */
function signerInfoWithSid(sid: Buffer): Buffer {
  const [version, , ...rest] = derChildren(readDer(SIGNER_INFO)).map((c) => c.raw);
  return tlv(0x30, version ?? Buffer.alloc(0), sid, ...rest);
}

const signer = readSignerCertificate(CERT);
const other = readSignerCertificate(OTHER_CERT);

describe('readSignerCertificate', () => {
  it('parses the certificate and computes the SHA-1 thumbprint the verifier reports', () => {
    expect(signer.thumbprint).toBe(THUMBPRINT);
    expect(signer.info.notAfter.getTime()).toBe(NOT_AFTER);
    expect(signer.der).toBe(CERT);
  });

  it('throws Asn1Error on something that is not a certificate', () => {
    expect(() => readSignerCertificate(Buffer.from([0x30, 0x00]))).toThrow(Asn1Error);
  });
});

describe('validityProblem', () => {
  it('is undefined inside the validity period', () => {
    expect(validityProblem(signer, NOW)).toBeUndefined();
    expect(validityProblem(signer, NOT_AFTER)).toBeUndefined();
  });

  it('names the expiry date once the certificate has expired', () => {
    expect(validityProblem(signer, NOT_AFTER + 1000)).toMatch(
      new RegExp(`${THUMBPRINT}.*expired on 2026-10-28T12:32:11.000Z`),
    );
  });

  it('reports a certificate that is not valid yet', () => {
    expect(validityProblem(signer, Date.parse('2026-09-01T00:00:00Z'))).toMatch(
      /not valid before 2026-09-10T15:36:37.000Z/,
    );
  });
});

describe('cmsPolicyViolations', () => {
  it('accepts the real detached single-signer CMS by the configured certificate', () => {
    expect(cmsPolicyViolations(CMS, signer)).toEqual([]);
    expect(cmsPolicyViolations(cms({ certs: null }), signer)).toEqual([]);
  });

  it('rejects an attached CMS', () => {
    const encap = tlv(
      0x30,
      derChildren(readDer(ENCAP))[0]?.raw ?? Buffer.alloc(0),
      tlv(0xa0, tlv(0x04, Buffer.from('УПД'))),
    );
    expect(cmsPolicyViolations(cms({ encap }), signer)).toEqual([
      expect.stringMatching(/attached/),
    ]);
  });

  it('requires exactly one signer', () => {
    expect(cmsPolicyViolations(cms({ signerInfos: [SIGNER_INFO, SIGNER_INFO] }), signer)).toEqual([
      expect.stringMatching(/2 signers; exactly one/),
    ]);
    expect(cmsPolicyViolations(cms({ signerInfos: [] }), signer)).toEqual([
      expect.stringMatching(/0 signers/),
    ]);
  });

  it('rejects a signature by another certificate (thumbprint mismatch)', () => {
    const violations = cmsPolicyViolations(CMS, other);
    expect(violations).toEqual([expect.stringMatching(/not by the configured certificate/)]);
    expect(violations[0]).toContain(other.thumbprint);
  });

  it('rejects an embedded signer certificate that differs from the configured one', () => {
    // Same issuer and serial in the sid, but the embedded certificate bytes differ.
    const tampered = Buffer.from(CERT);
    tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 0xff;
    expect(cmsPolicyViolations(cms({ certs: tlv(0xa0, tampered) }), signer)).toEqual([
      expect.stringMatching(/embedded certificate.*differs/),
    ]);
  });

  it('matches a subjectKeyIdentifier signer against the certificate SKI', () => {
    const ski = signer.info.subjectKeyIdentifier ?? Buffer.alloc(0);
    const byKeyId = (id: Buffer) => cms({ signerInfos: [signerInfoWithSid(tlv(0x80, id))] });
    expect(cmsPolicyViolations(byKeyId(ski), signer)).toEqual([]);
    expect(cmsPolicyViolations(byKeyId(Buffer.from('nope')), signer)).toEqual([
      expect.stringMatching(/not by the configured certificate/),
    ]);
  });

  it('accepts the real КриптоАРМ Server BER output once normalized to DER', () => {
    const ber = readFileSync(new URL('../asn1/fixtures/server-cms-detached.ber', import.meta.url));
    expect(cmsPolicyViolations(berToDer(ber), signer)).toEqual([]);
  });

  it('rejects a CMS that is not DER framed (non-minimal length) and extra ContentInfo elements', () => {
    const inner = CMS.subarray(4); // body of the outer 30 82 08 92
    const nonMinimal = Buffer.concat([Buffer.from([0x30, 0x83, 0x00, 0x08, 0x92]), inner]);
    expect(() => cmsPolicyViolations(nonMinimal, signer)).toThrow(/not DER/);
    const extra = tlv(0x30, inner, Buffer.from([0x05, 0x00]));
    expect(() => cmsPolicyViolations(extra, signer)).toThrow(Asn1Error);
  });

  it('throws Asn1Error when the signature is not a DER CMS SignedData', () => {
    expect(() => cmsPolicyViolations(Buffer.from([0x30, 0x80, 0x00, 0x00]), signer)).toThrow(
      Asn1Error,
    );
  });
});

describe('verifiedSignerViolations', () => {
  const ok: SignerInfo = { valid: true, thumbprint: THUMBPRINT.toUpperCase(), detached: true };

  it('accepts one signer with the expected thumbprint in any case', () => {
    expect(verifiedSignerViolations({ valid: true, signers: [ok] }, signer)).toEqual([]);
  });

  it('fails closed when the verifier reports no thumbprint', () => {
    expect(verifiedSignerViolations({ valid: true, signers: [{ valid: true }] }, signer)).toEqual([
      expect.stringMatching(/no signer thumbprint/),
    ]);
  });

  it('rejects a thumbprint mismatch, several signers and an attached signature', () => {
    expect(
      verifiedSignerViolations({ valid: true, signers: [{ ...ok, thumbprint: 'ab' }] }, signer),
    ).toEqual([expect.stringMatching(/thumbprint ab, expected 0e84/)]);
    expect(verifiedSignerViolations({ valid: true, signers: [ok, ok] }, signer)).toEqual([
      expect.stringMatching(/2 signers/),
    ]);
    expect(
      verifiedSignerViolations({ valid: true, signers: [{ ...ok, detached: false }] }, signer),
    ).toEqual([expect.stringMatching(/attached/)]);
  });
});

describe('classifyVerifyFailure', () => {
  const failed = (signers: SignerInfo[], reason = 'upstream says no'): VerifyResult => ({
    valid: false,
    signers,
    reason,
  });

  it('reports broken signature math as SIGNATURE_INVALID', () => {
    const result = classifyVerifyFailure(
      failed([{ valid: false, mathValid: false, chainValid: true }]),
      signer,
      NOW,
    );
    expect(result.code).toBe('SIGNATURE_INVALID');
    expect(result.message).toMatch(/signature math is invalid.*upstream says no/);
  });

  it('reports a valid math with a broken chain as CERTIFICATE_INVALID', () => {
    const result = classifyVerifyFailure(
      failed([{ valid: false, mathValid: true, chainValid: false, certValid: true }]),
      signer,
      NOW,
    );
    expect(result.code).toBe('CERTIFICATE_INVALID');
    expect(result.message).toMatch(/math is valid.*chain.*upstream says no/);
    expect(result.message).toMatch(/valid until 2026-10-28T12:32:11.000Z/);
    expect(result.message).not.toMatch(/expired/);
  });

  it('says clearly when the signer certificate has expired', () => {
    const result = classifyVerifyFailure(
      failed([{ valid: false, mathValid: true, chainValid: false, certValid: false }]),
      signer,
      NOT_AFTER + 1,
    );
    expect(result.code).toBe('CERTIFICATE_INVALID');
    expect(result.message).toMatch(/expired on 2026-10-28T12:32:11.000Z/);
  });

  it('reports a verifier-side signer with another thumbprint as a policy violation first', () => {
    const result = classifyVerifyFailure(
      failed([{ valid: false, mathValid: true, chainValid: false, thumbprint: 'ab' }]),
      signer,
      NOW,
    );
    expect(result.code).toBe('SIGNATURE_POLICY_VIOLATION');
    expect(result.message).toMatch(/thumbprint ab, expected 0e84/);
  });

  it('does not blame the certificate when the verifier names no failing check', () => {
    const result = classifyVerifyFailure(
      failed([{ valid: false, mathValid: true, chainValid: true, certValid: true }]),
      signer,
      NOW,
    );
    expect(result.code).toBe('SIGNATURE_INVALID');
    expect(result.message).toMatch(/upstream says no/);
  });

  it('keeps SIGNATURE_INVALID when the math result is missing or there is no signer', () => {
    expect(classifyVerifyFailure(failed([{ valid: false }]), signer, NOW)).toMatchObject({
      code: 'SIGNATURE_INVALID',
      message: expect.stringMatching(/did not report the math result/) as unknown,
    });
    expect(classifyVerifyFailure(failed([], ''), signer, NOW)).toMatchObject({
      code: 'SIGNATURE_INVALID',
    });
  });

  it('treats one broken signer among several as broken math', () => {
    const result = classifyVerifyFailure(
      failed([
        { valid: false, mathValid: true, chainValid: false },
        { valid: false, mathValid: false },
      ]),
      signer,
      NOW,
    );
    expect(result.code).toBe('SIGNATURE_INVALID');
  });
});

// What a signature must look like before it is posted (R1 M5, M6): detached, exactly one signer,
// made by the configured certificate; and why a signature that does not verify is rejected.
import { createHash } from 'node:crypto';

import {
  Asn1Error,
  isDerFramed,
  parseCertificate,
  parseCmsSignedData,
  type CertificateInfo,
  type CmsSignerId,
} from '../asn1/index.js';
import type { SignerInfo, VerifyResult } from '../signer/index.js';

export interface SignerCertificate {
  /** DER, as configured (e.g. `SIGNER_CERT_PATH`). */
  der: Buffer;
  info: CertificateInfo;
  /** SHA-1 over the DER, lowercase hex: the thumbprint КриптоПро and КриптоАРМ Server report. */
  thumbprint: string;
}

export interface VerifyFailure {
  /**
   * `SIGNATURE_POLICY_VIOLATION`: the verifier names another signer; `SIGNATURE_INVALID`: the math
   * is broken (or the reason is unknown); `CERTIFICATE_INVALID`: math ok, certificate/chain not.
   */
  code: 'SIGNATURE_POLICY_VIOLATION' | 'SIGNATURE_INVALID' | 'CERTIFICATE_INVALID';
  message: string;
}

/** @throws Asn1Error when the input is not a DER X.509 certificate. */
export function readSignerCertificate(der: Buffer): SignerCertificate {
  return {
    der,
    info: parseCertificate(der),
    thumbprint: createHash('sha1').update(der).digest('hex'),
  };
}

/** A reason the certificate cannot sign at `now` (outside its validity period), else undefined. */
export function validityProblem(cert: SignerCertificate, now: number): string | undefined {
  const { notBefore, notAfter } = cert.info;
  if (now > notAfter.getTime()) {
    return `signer certificate ${cert.thumbprint} expired on ${notAfter.toISOString()}; install a new one`;
  }
  if (now < notBefore.getTime()) {
    return `signer certificate ${cert.thumbprint} is not valid before ${notBefore.toISOString()}`;
  }
  return undefined;
}

/**
 * Structural policy on the CMS itself: detached, exactly one SignerInfo, whose SignerIdentifier
 * names the configured certificate; every embedded certificate that sid also names (by issuer and
 * serial, or by subjectKeyIdentifier) must be byte-identical to the configured one (one this parser
 * cannot read is skipped: the verifier thumbprint check still covers it).
 * The sid is only a claim: that the named key made the signature is proven by the verifier
 * (`verifiedSignerViolations`). Countersignatures (unsigned attributes) are not inspected.
 * @throws Asn1Error when the signature is not a DER-framed CMS SignedData.
 */
export function cmsPolicyViolations(signature: Buffer, cert: SignerCertificate): string[] {
  if (!isDerFramed(signature)) throw new Asn1Error('CMS is not DER framed', 0);
  const cms = parseCmsSignedData(signature);
  const violations: string[] = [];
  if (!cms.detached) {
    violations.push('CMS is attached (encapContentInfo carries eContent); detached is required');
  }
  if (cms.signers.length !== 1) {
    violations.push(`CMS has ${String(cms.signers.length)} signers; exactly one is required`);
  }
  const [sid] = cms.signers;
  if (cms.signers.length === 1 && sid !== undefined) {
    if (!identifies(sid, cert.info)) {
      violations.push(
        `CMS is signed, but not by the configured certificate ${cert.thumbprint}: ${describeSid(sid)}`,
      );
    } else if (cms.certificates.some((der) => !der.equals(cert.der) && namedBySid(der, sid))) {
      violations.push(
        `the embedded certificate of the signer differs from the configured one ${cert.thumbprint}`,
      );
    }
  }
  return violations;
}

/**
 * Cross-check of what the verifier saw: one signer, the expected thumbprint (required: fails closed
 * when the verifier does not report one), not attached.
 */
export function verifiedSignerViolations(result: VerifyResult, cert: SignerCertificate): string[] {
  if (result.signers.length !== 1) {
    return [`verifier reports ${String(result.signers.length)} signers; exactly one is required`];
  }
  const [signer] = result.signers as [SignerInfo];
  const violations: string[] = [];
  if (signer.thumbprint === undefined) {
    violations.push('verifier reports no signer thumbprint; cannot confirm the signer');
  }
  const mismatch = thumbprintMismatch(result, cert);
  if (mismatch !== undefined) violations.push(mismatch);
  if (signer.detached === false) violations.push('verifier reports an attached signature');
  return violations;
}

/**
 * Tells a broken signature (math) from a good signature by an unusable certificate (expired,
 * revoked, chain not trusted by the server) — the fixes differ: the first is a signer bug or
 * tampering, the second needs a new certificate or the CA root installed on the server.
 */
export function classifyVerifyFailure(
  result: VerifyResult,
  cert: SignerCertificate,
  now: number,
): VerifyFailure {
  const mismatch = thumbprintMismatch(result, cert);
  if (mismatch !== undefined) return { code: 'SIGNATURE_POLICY_VIOLATION', message: mismatch };
  const reason = result.reason ? `: ${result.reason}` : '';
  const math = result.signers.map((s) => s.mathValid);
  if (math.length === 0 || math.some((m) => m === false)) {
    return {
      code: 'SIGNATURE_INVALID',
      message:
        math.length === 0
          ? `signature does not verify${reason}`
          : `signature math is invalid (the signature does not match the signed bytes)${reason}`,
    };
  }
  if (math.some((m) => m === undefined)) {
    return {
      code: 'SIGNATURE_INVALID',
      message: `signature does not verify${reason} (the verifier did not report the math result)`,
    };
  }
  const broken = [
    result.signers.some((s) => s.certValid === false) ? 'certificate' : undefined,
    result.signers.some((s) => s.chainValid === false) ? 'chain' : undefined,
  ].filter(Boolean);
  if (broken.length === 0) {
    return {
      code: 'SIGNATURE_INVALID',
      message: `signature does not verify${reason} (math is valid; the verifier names no failing check)`,
    };
  }
  const notAfter = cert.info.notAfter.toISOString();
  const expired = now > cert.info.notAfter.getTime();
  // Blame the configured certificate only when the verifier says it saw that one.
  const confirmed = result.signers.some(
    (s) => s.thumbprint !== undefined && normalizeThumbprint(s.thumbprint) === cert.thumbprint,
  );
  const expiry = !confirmed
    ? 'the verifier names no signer certificate (signer not confirmed); ' +
      (expired
        ? `the configured certificate ${cert.thumbprint} expired on ${notAfter}`
        : 'check the CA chain (root and intermediates) in the server store')
    : expired
      ? `signer certificate ${cert.thumbprint} expired on ${notAfter}; install a new one`
      : `signer certificate ${cert.thumbprint} is valid until ${notAfter}; ` +
        'check the CA chain (root and intermediates) in the server store';
  return {
    code: 'CERTIFICATE_INVALID',
    message:
      `signature math is valid, but the signer certificate or its chain is not` +
      ` (invalid: ${broken.join(', ')})${reason}; ${expiry}`,
  };
}

/**
 * The first thumbprint the verifier reports that is not the configured certificate's. Separators
 * (`AB:CD`, `ab cd`, `ab-cd`) and case do not matter; nothing else is dropped.
 */
function thumbprintMismatch(result: VerifyResult, cert: SignerCertificate): string | undefined {
  const other = result.signers
    .map((s) => s.thumbprint)
    .find((t) => t !== undefined && normalizeThumbprint(t) !== cert.thumbprint);
  return other === undefined
    ? undefined
    : `verifier reports signer thumbprint ${other}, expected ${cert.thumbprint}`;
}

function normalizeThumbprint(thumbprint: string): string {
  return thumbprint.replace(/[\s:-]/g, '').toLowerCase();
}

function identifies(sid: CmsSignerId, cert: CertificateInfo): boolean {
  if ('subjectKeyIdentifier' in sid) {
    return cert.subjectKeyIdentifier?.equals(sid.subjectKeyIdentifier) ?? false;
  }
  return sid.issuer.equals(cert.issuer) && sid.serialNumber.equals(cert.serialNumber);
}

/** Whether the sid also names this embedded certificate. */
function namedBySid(der: Buffer, sid: CmsSignerId): boolean {
  let info: CertificateInfo;
  try {
    info = parseCertificate(der);
  } catch {
    return false; // an unparsable extra certificate cannot be the signer's
  }
  return identifies(sid, info);
}

function describeSid(sid: CmsSignerId): string {
  return 'subjectKeyIdentifier' in sid
    ? `subjectKeyIdentifier ${sid.subjectKeyIdentifier.toString('hex')}`
    : `serial ${sid.serialNumber.toString('hex')}`;
}

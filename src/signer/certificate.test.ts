import { describe, expect, it } from 'vitest';

import { toDerCertificate } from './certificate.js';
import { SignerConfigError } from './errors.js';

// Minimal DER shapes: only the outer structure matters for the check.
// X.509 Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
const fakeCertDer = Buffer.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x05, 0x01, 0x00]);
// PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo, ... }
const fakePfxDer = Buffer.from([0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]);

const toPem = (label: string, der: Buffer): Buffer =>
  Buffer.from(`-----BEGIN ${label}-----\n${der.toString('base64')}\n-----END ${label}-----\n`);

describe('toDerCertificate', () => {
  it('returns DER certificate bytes unchanged', () => {
    expect(toDerCertificate(fakeCertDer)).toEqual(fakeCertDer);
  });

  it('accepts a DER certificate with long-form length', () => {
    const inner = Buffer.concat([Buffer.from([0x30, 0x81, 0x80]), Buffer.alloc(0x80)]);
    const der = Buffer.concat([Buffer.from([0x30, 0x81, inner.length]), inner]);
    expect(toDerCertificate(der)).toEqual(der);
  });

  it('decodes a PEM certificate to DER', () => {
    expect(toDerCertificate(toPem('CERTIFICATE', fakeCertDer))).toEqual(fakeCertDer);
  });

  it('rejects a PKCS#12 container', () => {
    expect(() => toDerCertificate(fakePfxDer)).toThrow(SignerConfigError);
    expect(() => toDerCertificate(fakePfxDer)).toThrow(/PKCS#12/);
  });

  it('rejects PEM private keys', () => {
    expect(() => toDerCertificate(toPem('PRIVATE KEY', fakeCertDer))).toThrow(/private key/);
  });

  it('rejects a PEM file that has a private key after the certificate', () => {
    const pem = Buffer.concat([
      toPem('CERTIFICATE', fakeCertDer),
      toPem('EC PRIVATE KEY', fakeCertDer),
    ]);
    expect(() => toDerCertificate(pem)).toThrow(/private key/);
  });

  it('rejects a BER indefinite-length PKCS#12', () => {
    const ber = Buffer.from([0x30, 0x80, 0x02, 0x01, 0x03, 0x00, 0x00]);
    expect(() => toDerCertificate(ber)).toThrow(SignerConfigError);
  });

  it.each([
    ['empty input', Buffer.alloc(0)],
    ['not a SEQUENCE', Buffer.from([0x04, 0x01, 0x00])],
    ['truncated', fakeCertDer.subarray(0, 6)],
    ['trailing bytes', Buffer.concat([fakeCertDer, Buffer.from([0x00])])],
    ['random text', Buffer.from('hello world')],
  ])('rejects %s', (_name, input) => {
    expect(() => toDerCertificate(input)).toThrow(SignerConfigError);
  });
});

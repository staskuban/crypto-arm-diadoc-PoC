import { SignerConfigError } from './errors.js';

const SEQUENCE = 0x30;
const INTEGER = 0x02;
const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;
const PEM_PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

/**
 * Normalizes a public X.509 certificate (DER or PEM) to DER.
 *
 * КриптоАРМ Server also accepts a PKCS#12 container in `cert` and would install it per request;
 * we refuse that so private keys never leave the server store.
 */
export function toDerCertificate(input: Buffer): Buffer {
  const der = decodePem(input) ?? input;
  const inner = derSequenceBody(der);
  if (inner === undefined) {
    throw new SignerConfigError('certificate is not a DER or PEM encoded X.509 certificate');
  }
  // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
  // PFX         ::= SEQUENCE { version INTEGER (3), ... }
  if (inner[0] === INTEGER) {
    throw new SignerConfigError(
      'certificate is a PKCS#12 container or a private key; pass only the public .cer (the key stays on the server)',
    );
  }
  if (inner[0] !== SEQUENCE) {
    throw new SignerConfigError('certificate is not an X.509 certificate');
  }
  return der;
}

function decodePem(input: Buffer): Buffer | undefined {
  const text = input.toString('latin1');
  if (PEM_PRIVATE_KEY.test(text)) {
    throw new SignerConfigError(
      'certificate file contains a private key; pass only the public .cer',
    );
  }
  const match = PEM_BLOCK.exec(text);
  if (!match) return undefined;
  const [, label = '', body = ''] = match;
  if (label !== 'CERTIFICATE') {
    throw new SignerConfigError(`unsupported PEM block "${label}", expected CERTIFICATE`);
  }
  return Buffer.from(body.replace(/\s+/g, ''), 'base64');
}

/** Returns the body of a single top-level DER SEQUENCE spanning the whole buffer. */
function derSequenceBody(der: Buffer): Buffer | undefined {
  if (der.length < 2 || der[0] !== SEQUENCE) return undefined;
  const first = der[1] ?? 0;
  let length: number;
  let offset: number;
  if (first < 0x80) {
    length = first;
    offset = 2;
  } else {
    const count = first & 0x7f;
    if (count === 0 || count > 4 || der.length < 2 + count) return undefined;
    length = der.readUIntBE(2, count);
    offset = 2 + count;
  }
  if (length === 0 || offset + length !== der.length) return undefined;
  return der.subarray(offset);
}

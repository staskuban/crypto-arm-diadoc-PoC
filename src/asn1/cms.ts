// Read-only views of CMS SignedData (RFC 5652) and X.509 certificates (RFC 5280): only the fields
// the signature policy needs. No signature math — that is the verifier's job.
import { Asn1Error } from './der.js';
import { derChildren, readDer, type DerElement } from './reader.js';

const SEQUENCE = 0x30;
const SET = 0x31;
const INTEGER = 0x02;
const OID = 0x06;
const OCTET_STRING = 0x04;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;
const CONTEXT_0 = 0xa0;
const CONTEXT_1 = 0xa1;
const CONTEXT_3 = 0xa3;
/** SignerIdentifier `subjectKeyIdentifier [0] IMPLICIT OCTET STRING` (primitive). */
const IMPLICIT_0 = 0x80;
/** 1.2.840.113549.1.7.2 pkcs7-signedData, content octets. */
const SIGNED_DATA_OID = Buffer.from('2a864886f70d010702', 'hex');
/** 2.5.29.14 subjectKeyIdentifier, content octets. */
const SKI_OID = Buffer.from('551d0e', 'hex');

export interface CertificateInfo {
  /** Issuer Name, whole DER encoding (compare byte for byte with IssuerAndSerialNumber). */
  issuer: Buffer;
  /** Subject Name, whole DER encoding. */
  subject: Buffer;
  /** Content octets of the serialNumber INTEGER. */
  serialNumber: Buffer;
  notBefore: Date;
  notAfter: Date;
  /** The subjectKeyIdentifier extension value, if present. */
  subjectKeyIdentifier?: Buffer;
}

/** CMS SignerIdentifier: issuerAndSerialNumber or subjectKeyIdentifier. */
export type CmsSignerId =
  { issuer: Buffer; serialNumber: Buffer } | { subjectKeyIdentifier: Buffer };

export interface CmsSignedDataInfo {
  /** `encapContentInfo` has no `eContent`: the signed data travels separately. */
  detached: boolean;
  /** One entry per SignerInfo, in order. */
  signers: CmsSignerId[];
  /** Embedded X.509 certificates (whole DER encodings); other CertificateChoices are skipped. */
  certificates: Buffer[];
}

/**
 * Reads a DER X.509 certificate.
 * @throws Asn1Error when the input is not a certificate.
 */
export function parseCertificate(der: Buffer): CertificateInfo {
  const cert = expect(readDer(der), SEQUENCE, 'Certificate');
  const parts = derChildren(cert);
  if (parts.length !== 3) throw new Asn1Error('Certificate must have 3 elements', cert.offset);
  const tbs = derChildren(expect(parts[0], SEQUENCE, 'tbsCertificate'));
  let i = tbs[0]?.tag === CONTEXT_0 ? 1 : 0; // [0] EXPLICIT version
  const serial = expect(tbs[i++], INTEGER, 'serialNumber');
  expect(tbs[i++], SEQUENCE, 'signature');
  const issuer = expect(tbs[i++], SEQUENCE, 'issuer');
  const validity = derChildren(expect(tbs[i++], SEQUENCE, 'validity'));
  const subject = expect(tbs[i++], SEQUENCE, 'subject');
  expect(tbs[i++], SEQUENCE, 'subjectPublicKeyInfo');
  const info: CertificateInfo = {
    issuer: issuer.raw,
    subject: subject.raw,
    serialNumber: serial.content,
    notBefore: parseTime(validity[0], 'notBefore'),
    notAfter: parseTime(validity[1], 'notAfter'),
  };
  const extensions = tbs.slice(i).find((e) => e.tag === CONTEXT_3);
  if (extensions !== undefined) {
    const ski = findExtension(extensions, SKI_OID);
    if (ski !== undefined) {
      info.subjectKeyIdentifier = expect(
        readDer(ski),
        OCTET_STRING,
        'subjectKeyIdentifier',
      ).content;
    }
  }
  return info;
}

/**
 * Reads the structure of a DER ContentInfo carrying SignedData.
 * @throws Asn1Error when the input is not a CMS SignedData.
 */
export function parseCmsSignedData(der: Buffer): CmsSignedDataInfo {
  const contentInfo = derChildren(expect(readDer(der), SEQUENCE, 'ContentInfo'));
  const type = expect(contentInfo[0], OID, 'contentType');
  if (!type.content.equals(SIGNED_DATA_OID)) {
    throw new Asn1Error('not a CMS SignedData', type.offset);
  }
  const wrapper = derChildren(expect(contentInfo[1], CONTEXT_0, 'content'));
  if (contentInfo.length !== 2 || wrapper.length !== 1) {
    throw new Asn1Error('unexpected elements in ContentInfo', type.offset);
  }
  const signedData = derChildren(expect(wrapper[0], SEQUENCE, 'SignedData'));
  expect(signedData[0], INTEGER, 'version');
  expect(signedData[1], SET, 'digestAlgorithms');
  const encap = derChildren(expect(signedData[2], SEQUENCE, 'encapContentInfo'));
  expect(encap[0], OID, 'eContentType');

  let i = 3;
  const certificates: Buffer[] = [];
  const certificateSet = signedData[i];
  if (certificateSet?.tag === CONTEXT_0) {
    i++;
    for (const choice of derChildren(certificateSet)) {
      if (choice.tag === SEQUENCE) certificates.push(choice.raw);
    }
  }
  if (signedData[i]?.tag === CONTEXT_1) i++; // crls
  const signerInfos = expect(signedData[i++], SET, 'signerInfos');
  if (i !== signedData.length) {
    throw new Asn1Error('unexpected element after signerInfos', signedData[i]?.offset ?? 0);
  }
  return {
    detached: encap.length === 1,
    signers: derChildren(signerInfos).map(signerId),
    certificates,
  };
}

/** RFC 5652 §5.3: SignerInfo version 1 goes with issuerAndSerialNumber, 3 with subjectKeyIdentifier. */
function signerId(signerInfo: DerElement): CmsSignerId {
  const [version, sid] = derChildren(expect(signerInfo, SEQUENCE, 'SignerInfo'));
  const v = expect(version, INTEGER, 'SignerInfo version');
  const byKeyId = sid?.tag === IMPLICIT_0;
  if (!v.content.equals(Buffer.from([byKeyId ? 3 : 1]))) {
    throw new Asn1Error(
      `SignerInfo version must be ${byKeyId ? '3 with subjectKeyIdentifier' : '1 with issuerAndSerialNumber'}`,
      v.offset,
    );
  }
  if (sid?.tag === IMPLICIT_0) return { subjectKeyIdentifier: sid.content };
  const bySerial = expect(sid, SEQUENCE, 'SignerIdentifier');
  const parts = derChildren(bySerial);
  if (parts.length !== 2) {
    throw new Asn1Error('SignerIdentifier must have 2 elements (issuer, serial)', bySerial.offset);
  }
  const [issuer, serial] = parts;
  return {
    issuer: expect(issuer, SEQUENCE, 'issuer').raw,
    serialNumber: expect(serial, INTEGER, 'serialNumber').content,
  };
}

/** Returns the `extnValue` content of the extension with the given OID. */
function findExtension(extensions: DerElement, oid: Buffer): Buffer | undefined {
  const [list] = derChildren(extensions);
  for (const extension of derChildren(expect(list, SEQUENCE, 'extensions'))) {
    const fields = derChildren(expect(extension, SEQUENCE, 'Extension'));
    if (!expect(fields[0], OID, 'extnID').content.equals(oid)) continue;
    return expect(fields.at(-1), OCTET_STRING, 'extnValue').content;
  }
  return undefined;
}

/** RFC 5280 §4.1.2.5: UTCTime YYMMDDHHMMSSZ (YY < 50 → 20YY) or GeneralizedTime YYYYMMDDHHMMSSZ. */
function parseTime(element: DerElement | undefined, name: string): Date {
  if (element === undefined) throw new Asn1Error(`missing ${name}`, 0);
  const text = element.content.toString('latin1');
  let match: RegExpExecArray | null;
  let year: number;
  if (element.tag === UTC_TIME && (match = /^(\d{2})(\d{10})Z$/.exec(text))) {
    const yy = Number(match[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
  } else if (element.tag === GENERALIZED_TIME && (match = /^(\d{4})(\d{10})Z$/.exec(text))) {
    year = Number(match[1]);
  } else {
    throw new Asn1Error(`${name} is not an RFC 5280 time`, element.offset);
  }
  const rest = match[2] ?? '';
  const [month, day, hour, minute, second] = [0, 2, 4, 6, 8].map((at) =>
    Number(rest.slice(at, at + 2)),
  ) as [number, number, number, number, number];
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new Asn1Error(`${name} is not a valid date`, element.offset);
  }
  // Date.UTC maps years 0..99 to 1900..1999; set the year explicitly for GeneralizedTime.
  date.setUTCFullYear(year);
  return date;
}

function expect(element: DerElement | undefined, tag: number, name: string): DerElement {
  if (element?.tag !== tag) {
    throw new Asn1Error(
      `${name}: expected tag 0x${tag.toString(16)}${element ? `, got 0x${element.tag.toString(16)}` : ', missing'}`,
      element?.offset ?? 0,
    );
  }
  return element;
}

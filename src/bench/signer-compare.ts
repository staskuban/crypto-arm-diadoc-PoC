// Helpers of the C1 signer comparison (`scripts/compare-signers.js`): what a CMS looks like, a
// structural diff of two CMS that ignores the parts that differ on every signing, latency
// percentiles, and generated test УПД. Not used by the pipeline.
import { createHash } from 'node:crypto';

import { berToDer, derChildren, readDer, type DerElement } from '../asn1/index.js';
import { buildTestUtd, type Party, type TestUtd } from '../e2e/test-utd.js';

const SEQUENCE = 0x30;
const SET = 0x31;
const OID = 0x06;
const INTEGER = 0x02;
const CONTEXT_0 = 0xa0;
const CONTEXT_1 = 0xa1;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

/** CAdES / CMS attribute OIDs worth naming. */
const ATTRIBUTE_NAMES: Record<string, string> = {
  '1.2.840.113549.1.9.3': 'contentType',
  '1.2.840.113549.1.9.4': 'messageDigest',
  '1.2.840.113549.1.9.5': 'signingTime',
  '1.2.840.113549.1.9.16.2.12': 'signingCertificate',
  '1.2.840.113549.1.9.16.2.47': 'signingCertificateV2',
  '1.2.840.113549.1.9.16.2.14': 'signatureTimeStampToken',
  '1.2.840.113549.1.9.16.2.21': 'completeCertificateRefs',
  '1.2.840.113549.1.9.16.2.22': 'completeRevocationRefs',
};

export interface CmsProfile {
  /** The input itself is DER-framed (КриптоАРМ Server emits BER; the signers normalise it). */
  der: boolean;
  bytes: number;
  version: number;
  detached: boolean;
  eContentType: string;
  digestAlgorithms: string[];
  /** SHA-1 thumbprints of the embedded certificates. */
  certificates: string[];
  crls: boolean;
  signerInfos: number;
  signer?: {
    version: number;
    sid: 'issuerAndSerialNumber' | 'subjectKeyIdentifier';
    digestAlgorithm: string;
    signatureAlgorithm: string;
    /** Names (or OIDs) of the signed attributes, in encoding order. */
    signedAttributes: string[];
    unsignedAttributes: string[];
    signingTime?: string;
    signatureBytes: number;
  };
  /** CAdES-BES needs contentType, messageDigest and signingCertificate(V2) signed attributes. */
  cades: 'CAdES-BES' | 'CAdES-T' | 'CMS';
}

/**
 * Describes a CMS SignedData (BER or DER; BER is normalised first).
 * @throws Asn1Error when the input is not a CMS SignedData.
 */
export function cmsProfile(input: Buffer): CmsProfile {
  const der = berToDer(input);
  const signedData = signedDataParts(der);
  const [version, digestAlgorithms, encap] = signedData;
  let i = 3;
  const certificates: string[] = [];
  if (signedData[i]?.tag === CONTEXT_0) {
    for (const c of derChildren(at(signedData, i))) {
      if (c.tag === SEQUENCE) certificates.push(createHash('sha1').update(c.raw).digest('hex'));
    }
    i++;
  }
  const crls = signedData[i]?.tag === CONTEXT_1;
  if (crls) i++;
  const signerInfos = derChildren(at(signedData, i));
  const encapParts = derChildren(must(encap));
  const profile: CmsProfile = {
    der: der.equals(input),
    bytes: input.length,
    version: integer(must(version)),
    detached: encapParts.length === 1,
    eContentType: oid(must(encapParts[0])),
    digestAlgorithms: derChildren(must(digestAlgorithms)).map((a) => oid(at(derChildren(a), 0))),
    certificates,
    crls,
    signerInfos: signerInfos.length,
    cades: 'CMS',
  };
  const first = signerInfos[0];
  if (first !== undefined) {
    const parts = derChildren(first);
    let j = 2;
    const signed = parts[3]?.tag === CONTEXT_0 ? parts[3] : undefined;
    const digestAlgorithm = oid(at(derChildren(at(parts, j)), 0));
    j += signed === undefined ? 1 : 2;
    const signatureAlgorithm = oid(at(derChildren(at(parts, j++)), 0));
    const signatureValue = at(parts, j++);
    const unsigned = parts[j]?.tag === CONTEXT_1 ? parts[j] : undefined;
    const signedAttributes = signed === undefined ? [] : attributes(signed);
    const unsignedAttributes = unsigned === undefined ? [] : attributes(unsigned);
    const time = signed === undefined ? undefined : signingTime(signed);
    profile.signer = {
      version: integer(at(parts, 0)),
      sid: parts[1]?.tag === SEQUENCE ? 'issuerAndSerialNumber' : 'subjectKeyIdentifier',
      digestAlgorithm,
      signatureAlgorithm,
      signedAttributes,
      unsignedAttributes,
      ...(time === undefined ? {} : { signingTime: time }),
      signatureBytes: signatureValue.content.length,
    };
    const bes =
      ['contentType', 'messageDigest'].every((a) => signedAttributes.includes(a)) &&
      signedAttributes.some((a) => a === 'signingCertificate' || a === 'signingCertificateV2');
    if (bes) {
      profile.cades = unsignedAttributes.includes('signatureTimeStampToken')
        ? 'CAdES-T'
        : 'CAdES-BES';
    }
  }
  return profile;
}

/**
 * Differences between two CMS (BER or DER) element by element, ignoring what changes on every
 * signing of the same data by the same key: the signingTime value and the signature value of each
 * SignerInfo. Empty = the same structure and the same bytes everywhere else. Each entry is
 * `<path> <what>`, the path being child indexes from ContentInfo.
 */
export function structuralDiff(a: Buffer, b: Buffer): string[] {
  let left: DerElement;
  let right: DerElement;
  try {
    left = readDer(masked(berToDer(a)));
  } catch {
    return ['not comparable: first is not a CMS'];
  }
  try {
    right = readDer(masked(berToDer(b)));
  } catch {
    return ['not comparable: second is not a CMS'];
  }
  const out: string[] = [];
  compare(left, right, '0', out);
  return out;
}

function compare(a: DerElement, b: DerElement, path: string, out: string[]): void {
  if (a.tag !== b.tag) {
    out.push(`${path} tag 0x${a.tag.toString(16)} ≠ 0x${b.tag.toString(16)}`);
    return;
  }
  if (!a.constructed) {
    if (!a.content.equals(b.content)) {
      out.push(
        `${path} content differs (${String(a.content.length)} B vs ${String(b.content.length)} B)`,
      );
    }
    return;
  }
  const ac = derChildren(a);
  const bc = derChildren(b);
  if (ac.length !== bc.length) {
    out.push(`${path} ${String(ac.length)} ≠ ${String(bc.length)} children`);
  }
  for (let k = 0; k < Math.min(ac.length, bc.length); k++) {
    compare(at(ac, k), at(bc, k), `${path}.${String(k)}`, out);
  }
}

/** A copy of a DER CMS with every signingTime value and signature value zeroed. */
function masked(der: Buffer): Buffer {
  const copy = Buffer.from(der);
  const signedData = signedDataParts(copy);
  const infos = signedData.at(-1);
  if (infos?.tag !== SET) throw new Error('no signerInfos');
  for (const info of derChildren(infos)) {
    const parts = derChildren(info);
    const signed = parts[3]?.tag === CONTEXT_0 ? parts[3] : undefined;
    const signatureValue = parts[signed === undefined ? 4 : 5];
    signatureValue?.content.fill(0);
    if (signed === undefined) continue;
    for (const attribute of derChildren(signed)) {
      const [type, values] = derChildren(attribute);
      if (type === undefined || values === undefined) continue;
      if (ATTRIBUTE_NAMES[oid(type)] !== 'signingTime') continue;
      for (const v of derChildren(values)) v.content.fill(0);
    }
  }
  return copy;
}

function signedDataParts(der: Buffer): DerElement[] {
  const contentInfo = derChildren(readDer(der));
  return derChildren(at(derChildren(at(contentInfo, 1)), 0));
}

function attributes(set: DerElement): string[] {
  return derChildren(set).map((attribute) => {
    const id = oid(at(derChildren(attribute), 0));
    return ATTRIBUTE_NAMES[id] ?? id;
  });
}

function signingTime(set: DerElement): string | undefined {
  for (const attribute of derChildren(set)) {
    const [type, values] = derChildren(attribute);
    if (type === undefined || values === undefined) continue;
    if (ATTRIBUTE_NAMES[oid(type)] !== 'signingTime') continue;
    const value = derChildren(values)[0];
    if (value?.tag === UTC_TIME || value?.tag === GENERALIZED_TIME) {
      return parseTime(value.tag, value.content.toString('latin1'));
    }
  }
  return undefined;
}

function parseTime(tag: number, text: string): string {
  const m = /^(\d{2,4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (m === null) return text;
  const [, y = '', mo, d, h, mi, s] = m;
  const year = tag === UTC_TIME ? (Number(y) >= 50 ? 1900 : 2000) + Number(y) : Number(y);
  return new Date(
    Date.UTC(year, Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)),
  ).toISOString();
}

function oid(element: DerElement): string {
  if (element.tag !== OID) throw new Error(`expected an OID at ${String(element.offset)}`);
  const bytes = element.content;
  const arcs: number[] = [];
  let value = 0;
  for (const byte of bytes) {
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  const [first = 0, ...rest] = arcs;
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...rest].join('.');
}

function integer(element: DerElement): number {
  if (element.tag !== INTEGER) throw new Error(`expected an INTEGER at ${String(element.offset)}`);
  return element.content.reduce((n, byte) => n * 256 + byte, 0);
}

function at(list: DerElement[], index: number): DerElement {
  return must(list[index]);
}

function must(element: DerElement | undefined): DerElement {
  if (element === undefined) throw new Error('unexpected CMS structure');
  return element;
}

/** Nearest-rank percentile (p in 0..100) of a non-empty list. */
export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) throw new Error('percentile of an empty list');
  const sorted = [...values].sort((x, y) => x - y);
  const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
  return sorted[rank - 1] ?? Number.NaN;
}

export interface LatencySummary {
  n: number;
  min: number;
  p50: number;
  p95: number;
  max: number;
  mean: number;
}

export function latencySummary(ms: readonly number[]): LatencySummary {
  return {
    n: ms.length,
    min: Math.min(...ms),
    p50: percentile(ms, 50),
    p95: percentile(ms, 95),
    max: Math.max(...ms),
    mean: Math.round(ms.reduce((s, v) => s + v, 0) / ms.length),
  };
}

// Parties of the committed УПД fixture (src/utd/fixtures): made-up test organisations, no Диадок.
const SELLER: Party = {
  name: 'ООО "Тестовый продавец"',
  inn: '7700000016',
  kpp: '773601001',
  fnsParticipantId: '2BM-7700000016-773601001-000000000000000000001',
  regionCode: '77',
  regionName: 'г. Москва',
};
const BUYER: Party = {
  name: 'ООО "Тестовый покупатель"',
  inn: '7700000023',
  kpp: '773601001',
  fnsParticipantId: '2BM-7700000023-773601001-000000000000000000002',
  regionCode: '77',
  regionName: 'г. Москва',
};

/** A СЧФДОП 5.03 УПД (windows-1251) of at least `minBytes`, padded with goods rows. */
export function generateUtd(minBytes: number, date: Date, guid: string): TestUtd {
  return buildTestUtd({ seller: SELLER, buyer: BUYER, date, guid, minBytes });
}

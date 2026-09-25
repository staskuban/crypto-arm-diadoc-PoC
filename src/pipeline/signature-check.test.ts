import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  DiadocError,
  type Document,
  type DocumentRef,
  type Message,
  type RequestOptions,
  type SignatureInfo,
} from '../diadoc/index.js';
import {
  certificateChainProblems,
  checkSenderSignature,
  describeSignatureCheck,
  isSignatureRejected,
  signatureCheckFrom,
  type SignatureCheckDiadoc,
} from './signature-check.js';

// Live answers from the S1 run (2026-09-25, test boxes on the prod host), without certificates, user
// ids, СНИЛС and e-mail. doc1: SignWithTestSignature (valid); doc2: КриптоАРМ Server CMS with
// cryptoarm.server.test.cer; doc3: the same with o2-platforma.test.cer (another organisation).
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`./fixtures/diadoc-s1/${name}.json`, import.meta.url), 'utf8'));

const doc1 = {
  document: fixture('doc1-document') as Document,
  info: fixture('doc1-signatureinfo') as SignatureInfo,
};
const doc2 = {
  document: fixture('doc2-document') as Document,
  message: fixture('doc2-message') as Message,
  info: fixture('doc2-signatureinfo') as SignatureInfo,
};
const doc3 = {
  document: fixture('doc3-document') as Document,
  message: fixture('doc3-message') as Message,
  info: fixture('doc3-signatureinfo') as SignatureInfo,
};

const refOf = (doc: Document, boxId = 'e5938990-18eb-40ee-bd7e-b252e394aa15'): DocumentRef => ({
  boxId,
  messageId: doc.MessageId ?? '',
  entityId: doc.EntityId ?? '',
});

describe('certificateChainProblems', () => {
  it('names the CryptoAPI trust flags Diadoc reported live', () => {
    // doc2: 0x01010040, doc3: 0x01000060.
    expect(certificateChainProblems(0x01010040)).toEqual([
      'REVOCATION_STATUS_UNKNOWN',
      'PARTIAL_CHAIN',
      'OFFLINE_REVOCATION',
    ]);
    expect(certificateChainProblems(0x01000060)).toEqual([
      'UNTRUSTED_ROOT',
      'REVOCATION_STATUS_UNKNOWN',
      'OFFLINE_REVOCATION',
    ]);
  });

  it('never loops and reads a negative int32 as uint32', () => {
    expect(certificateChainProblems(Infinity)).toEqual(['invalid flags Infinity']);
    expect(certificateChainProblems(Number.NaN)).toEqual(['invalid flags NaN']);
    expect(certificateChainProblems(1.5)).toEqual(['invalid flags 1.5']);
    expect(certificateChainProblems(2 ** 32)).toEqual([`invalid flags ${String(2 ** 32)}`]);
    expect(certificateChainProblems(-(2 ** 31) + 0x20)).toEqual(['UNTRUSTED_ROOT', '0x80000000']);
    expect(certificateChainProblems(0x100000)).toEqual(['HAS_WEAK_SIGNATURE']);
  });

  it('keeps unknown bits as hex and returns nothing for 0', () => {
    expect(certificateChainProblems(0)).toEqual([]);
    expect(certificateChainProblems(0x40000000)).toEqual(['0x40000000']);
  });
});

describe('signatureCheckFrom (live S1 shapes)', () => {
  it('doc2: math valid, certificate not trusted, not delivered', () => {
    const check = signatureCheckFrom({
      entityId: doc2.document.EntityId ?? '',
      document: doc2.document,
      message: doc2.message,
      signatureInfo: doc2.info,
    });
    expect(check).toEqual({
      senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
      reason: 'certificate',
      mathValid: true,
      certificateValid: false,
      chainProblems: ['REVOCATION_STATUS_UNKNOWN', 'PARTIAL_CHAIN', 'OFFLINE_REVOCATION'],
      certificate: {
        thumbprint: '0E84B59E46E4648FC3DC808EB94D58F4DE673F1F',
        serialNumber: '7C003B00DFEF3FBCA12EAFB41B0015003B00DF',
        issuer: 'Тестовый УЦ ООО "КРИПТО-ПРО"',
        validTo: '28.10.26',
      },
      delivered: false,
      deliveryFailure: expect.stringMatching(
        /^Ваше сообщение \(id = 3d6e7a22-4987-4866-a534-9fa94099178b\) или его часть не была доставлена/,
      ) as unknown,
      powerOfAttorney: [],
      lookupErrors: [],
    });
  });

  it('doc3: another organisation certificate is only an МЧД warning (D204), the chain is the error', () => {
    const check = signatureCheckFrom({
      entityId: doc3.document.EntityId ?? '',
      document: doc3.document,
      message: doc3.message,
      signatureInfo: doc3.info,
    });
    expect(check).toMatchObject({
      reason: 'certificate',
      mathValid: true,
      certificateValid: false,
      chainProblems: ['UNTRUSTED_ROOT', 'REVOCATION_STATUS_UNKNOWN', 'OFFLINE_REVOCATION'],
      certificate: { orgInn: '2311386400', orgName: 'ООО "О2 ПЛАТФОРМА"' },
      delivered: false,
      powerOfAttorney: [
        'PowerOfAttorneyRequired: Документ подписан сертификатом другого ЮЛ/ИП, возможно, требуется МЧД',
        'Не приложена доверенность',
      ],
    });
  });

  it('doc1: the test signature is valid, nothing to report', () => {
    const check = signatureCheckFrom({
      entityId: doc1.document.EntityId ?? '',
      document: doc1.document,
      signatureInfo: doc1.info,
    });
    expect(check).toMatchObject({
      senderSignatureStatus: 'SenderSignatureCheckedAndValid',
      reason: 'none',
      mathValid: true,
      certificateValid: true,
      chainProblems: [],
    });
    expect(check.delivered).toBeUndefined();
  });

  it('broken math is a signature problem, whatever the certificate says', () => {
    const info: SignatureInfo = {
      ...doc2.info,
      SignatureVerificationResult: {
        ...doc2.info.SignatureVerificationResult,
        IsValid: false,
      },
    };
    expect(
      signatureCheckFrom({ entityId: 'x', document: doc2.document, signatureInfo: info }),
    ).toMatchObject({
      reason: 'signature',
      mathValid: false,
    });
  });

  it('without GetSignatureInfo falls back to SenderSignatureStatus', () => {
    expect(signatureCheckFrom({ entityId: 'x', document: doc2.document })).toMatchObject({
      reason: 'unknown',
      senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
    });
    expect(signatureCheckFrom({ entityId: 'x', document: doc1.document })).toMatchObject({
      reason: 'none',
    });
  });

  it('a delivery failure of another message does not count', () => {
    const message: Message = {
      ...doc2.message,
      Entities: (doc2.message.Entities ?? []).map((e) =>
        e.AttachmentType === 'DeliveryFailureNotification'
          ? { ...e, NotDeliveredEventId: 'other-message' }
          : e,
      ),
    };
    const check = signatureCheckFrom({ entityId: 'x', document: doc2.document, message });
    expect(check.delivered).toBeUndefined();
    expect(check.deliveryFailure).toBeUndefined();
  });

  it('cuts a long or undecodable notification text', () => {
    const long = Buffer.from('ы'.repeat(2000), 'utf8').toString('base64');
    const message: Message = {
      MessageId: doc2.document.MessageId ?? '',
      Entities: [
        {
          EntityType: 'Attachment',
          AttachmentType: 'DeliveryFailureNotification',
          ParentEntityId: '',
          NotDeliveredEventId: doc2.document.MessageId ?? '',
          Content: { Data: long },
        },
      ],
    };
    const check = signatureCheckFrom({ entityId: 'x', document: doc2.document, message });
    expect(check.delivered).toBe(false);
    expect(check.deliveryFailure?.length).toBeLessThanOrEqual(501);
    const empty = signatureCheckFrom({
      entityId: 'x',
      document: doc2.document,
      message: { ...message, Entities: [{ ...message.Entities?.[0], Content: {} }] },
    });
    expect(empty).toMatchObject({ delivered: false });
    expect(empty.deliveryFailure).toBeUndefined();
  });
});

describe('sender signature choice', () => {
  it('takes the signature made in the sender box, not an earlier recipient one', () => {
    const entities = doc3.message.Entities ?? [];
    const sender = entities.find((e) => e.EntityType === 'Signature');
    const message: Message = {
      ...doc3.message,
      Entities: [
        {
          ...sender,
          EntityId: 'recipient-sig',
          SignerBoxId: '5321fa94c203493ca66e3a45f5dd6c8b@diadoc.ru',
          PowerOfAttorneyAttachmentStatus: { StatusName: 'Other' },
        },
        ...entities,
      ],
    };
    const check = signatureCheckFrom({
      entityId: doc3.document.EntityId ?? '',
      fromBoxId: 'E5938990-18EB-40EE-BD7E-B252E394AA15',
      document: doc3.document,
      message,
    });
    expect(check.powerOfAttorney[0]).toMatch(/^PowerOfAttorneyRequired/);
  });
});

describe('isSignatureRejected', () => {
  it('counts an invalid SenderSignatureStatus even when the lookups failed', () => {
    const base = { chainProblems: [], powerOfAttorney: [], lookupErrors: [] };
    expect(isSignatureRejected({ ...base, reason: 'certificate' })).toBe(true);
    expect(isSignatureRejected({ ...base, reason: 'signature' })).toBe(true);
    expect(
      isSignatureRejected({
        ...base,
        reason: 'unknown',
        senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
      }),
    ).toBe(true);
    expect(isSignatureRejected({ ...base, reason: 'unknown' })).toBe(false);
    expect(isSignatureRejected({ ...base, reason: 'none' })).toBe(false);
  });
});

describe('describeSignatureCheck', () => {
  it('puts the docflow status text first (the reason of a non-signature error)', () => {
    expect(
      describeSignatureCheck(
        {
          reason: 'none',
          senderSignatureStatus: 'SenderSignatureCheckedAndValid',
          chainProblems: [],
          powerOfAttorney: [],
          lookupErrors: [],
        },
        'Отказано в подписи',
      ),
    ).toBe('[DOCFLOW_ERROR] Отказано в подписи; SenderSignatureCheckedAndValid');
  });

  it('names the certificate, the chain and the non-delivery', () => {
    const text = describeSignatureCheck(
      signatureCheckFrom({
        entityId: doc2.document.EntityId ?? '',
        document: doc2.document,
        message: doc2.message,
        signatureInfo: doc2.info,
      }),
    );
    expect(text).toMatch(/^\[SENDER_CERTIFICATE_REJECTED\] /);
    expect(text).toMatch(/signature math is valid/);
    expect(text).toMatch(/certificate 0E84B59E46E4648FC3DC808EB94D58F4DE673F1F/);
    expect(text).toMatch(/Тестовый УЦ ООО "КРИПТО-ПРО"/);
    expect(text).toMatch(/PARTIAL_CHAIN/);
    expect(text).toMatch(/not delivered: Ваше сообщение/);
  });

  it('math errors and unknown reasons get their own codes', () => {
    expect(
      describeSignatureCheck({
        reason: 'signature',
        mathValid: false,
        chainProblems: [],
        powerOfAttorney: [],
        lookupErrors: [],
      }),
    ).toMatch(/^\[SENDER_SIGNATURE_REJECTED\] .*signature math is invalid/);
    expect(
      describeSignatureCheck({
        reason: 'unknown',
        senderSignatureStatus: 'SenderSignatureCheckedAndInvalid',
        chainProblems: [],
        powerOfAttorney: [],
        lookupErrors: ['GetSignatureInfo: 500'],
      }),
    ).toMatch(
      /^\[SENDER_SIGNATURE_REJECTED\] SenderSignatureCheckedAndInvalid.*GetSignatureInfo: 500/,
    );
    expect(
      describeSignatureCheck({
        reason: 'none',
        chainProblems: [],
        powerOfAttorney: [],
        lookupErrors: [],
      }),
    ).toMatch(/^\[DOCFLOW_ERROR\] /);
  });
});

class FakeLookups implements SignatureCheckDiadoc {
  calls: { name: string; args: unknown[] }[] = [];
  message: Message | Error = doc2.message;
  info: SignatureInfo | Error = doc2.info;

  getMessage(boxId: string, messageId: string, o?: RequestOptions): Promise<Message> {
    this.calls.push({ name: 'getMessage', args: [boxId, messageId, o] });
    return this.message instanceof Error
      ? Promise.reject(this.message)
      : Promise.resolve(this.message);
  }

  getSignatureInfo(ref: DocumentRef, o?: RequestOptions): Promise<SignatureInfo> {
    this.calls.push({ name: 'getSignatureInfo', args: [ref, o] });
    return this.info instanceof Error ? Promise.reject(this.info) : Promise.resolve(this.info);
  }
}

describe('checkSenderSignature', () => {
  it('reads the message, then the signature under the document', async () => {
    const lookups = new FakeLookups();
    const ref = refOf(doc2.document);
    const options = { deadline: 1234 };
    const check = await checkSenderSignature(ref, doc2.document, lookups, options);

    expect(lookups.calls).toEqual([
      { name: 'getMessage', args: [ref.boxId, ref.messageId, options] },
      {
        name: 'getSignatureInfo',
        args: [{ ...ref, entityId: '763850b8-f00d-4938-b46b-ba2e8a9e5f89' }, options],
      },
    ]);
    expect(check).toMatchObject({ reason: 'certificate', delivered: false, lookupErrors: [] });
  });

  it('cuts a long lookup error', async () => {
    const lookups = new FakeLookups();
    lookups.message = new Error('x'.repeat(5000));
    const check = await checkSenderSignature(refOf(doc2.document), doc2.document, lookups);
    expect(check.lookupErrors[0]?.length).toBeLessThanOrEqual('GetMessage: '.length + 501);
  });

  it('never throws: a failed lookup is reported and the rest still used', async () => {
    const lookups = new FakeLookups();
    lookups.info = new DiadocError('GET', '/GetSignatureInfo', 500, 'boom');
    const check = await checkSenderSignature(refOf(doc2.document), doc2.document, lookups);
    expect(check).toMatchObject({ reason: 'unknown', delivered: false });
    expect(check.lookupErrors).toEqual([
      expect.stringMatching(/^GetSignatureInfo: .*500/) as unknown,
    ]);

    const noMessage = new FakeLookups();
    noMessage.message = new Error('network down');
    const other = await checkSenderSignature(refOf(doc2.document), doc2.document, noMessage);
    expect(noMessage.calls.map((c) => c.name)).toEqual(['getMessage']);
    expect(other).toMatchObject({ reason: 'unknown', lookupErrors: ['GetMessage: network down'] });
  });

  it('skips GetSignatureInfo when the message has no signature under the document', async () => {
    const lookups = new FakeLookups();
    lookups.message = { MessageId: 'm', Entities: [] };
    const check = await checkSenderSignature(refOf(doc2.document), doc2.document, lookups);
    expect(lookups.calls.map((c) => c.name)).toEqual(['getMessage']);
    expect(check.lookupErrors).toEqual(['no sender signature entity in the message']);
  });

  it('does nothing once aborted', async () => {
    const lookups = new FakeLookups();
    const controller = new AbortController();
    controller.abort(new Error('stop'));
    const check = await checkSenderSignature(refOf(doc2.document), doc2.document, lookups, {
      signal: controller.signal,
    });
    expect(lookups.calls).toEqual([]);
    expect(check).toMatchObject({ reason: 'unknown', lookupErrors: ['interrupted'] });
  });
});

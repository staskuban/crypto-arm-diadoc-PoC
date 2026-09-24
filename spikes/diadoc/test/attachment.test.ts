import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildUtdAttachment, readSignatureFile, pickUtdType, INLINE_CONTENT_LIMIT } from '../src/attachment.ts';

const content = Buffer.from([0x3c, 0xc0, 0xff]);

test('test-signature attachment sets SignWithTestSignature and no Signature', () => {
  const a = buildUtdAttachment({ content, function: 'СЧФДОП', version: 'utd970_05_03_01', signature: 'test', customDocumentId: 'x' });
  assert.deepEqual(a, {
    TypeNamedId: 'UniversalTransferDocument',
    Function: 'СЧФДОП',
    Version: 'utd970_05_03_01',
    CustomDocumentId: 'x',
    SignedContent: { Content: content.toString('base64'), SignWithTestSignature: true },
  });
});

test('detached CMS attachment carries base64 of the exact bytes', () => {
  const cms = Buffer.from([0x30, 0x82, 0x01]);
  const a = buildUtdAttachment({ content, function: 'СЧФДОП', version: 'utd970_05_03_01', signature: cms });
  assert.equal(a.SignedContent.Content, 'PMD/');
  assert.equal(a.SignedContent.Signature, cms.toString('base64'));
  assert.equal(a.SignedContent.SignWithTestSignature, undefined);
});

test('refuses inline content at or above 500 KB (shelf upload is out of spike scope)', () => {
  assert.throws(
    () => buildUtdAttachment({ content: Buffer.alloc(INLINE_CONTENT_LIMIT), function: 'СЧФДОП', version: 'v', signature: 'test' }),
    /ShelfUpload/,
  );
});

test('readSignatureFile accepts DER, base64 and PEM', () => {
  const der = Buffer.from([0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x01]);
  assert.deepEqual(readSignatureFile(der), der);
  assert.deepEqual(readSignatureFile(Buffer.from(der.toString('base64') + '\n')), der);
  const pem = `-----BEGIN CMS-----\n${der.toString('base64')}\n-----END CMS-----\n`;
  assert.deepEqual(readSignatureFile(Buffer.from(pem)), der);
});

test('readSignatureFile rejects data that is not CMS', () => {
  assert.throws(() => readSignatureFile(Buffer.from('hello world')), /CMS/);
});

const typesResponse = {
  DocumentTypes: [
    { Name: 'Invoice', Functions: [] },
    {
      Name: 'UniversalTransferDocument',
      Title: 'УПД',
      Functions: [
        { Name: 'СЧФ', Versions: [{ Version: 'utd970_05_03_01', IsActual: true }] },
        { Name: 'СЧФДОП', Versions: [{ Version: 'utd970_05_02_01', IsActual: false }, { Version: 'utd970_05_03_01', IsActual: true }] },
      ],
    },
  ],
};

test('pickUtdType returns only UniversalTransferDocument', () => {
  const t = pickUtdType(typesResponse);
  assert.equal(t?.Name, 'UniversalTransferDocument');
  assert.equal(pickUtdType({ DocumentTypes: [] }), undefined);
});

test('pickUtdType tolerates missing fields', () => {
  assert.equal(pickUtdType({}), undefined);
});

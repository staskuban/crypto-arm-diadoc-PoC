import { describe, expect, it } from 'vitest';

import { isResendSalt, operationIdFor, type OperationKey } from './operation-id.js';

const KEY: OperationKey = {
  fromBoxId: 'from-box',
  toBoxId: 'to-box',
  idFile: 'ON_NSCHFDOPPR_1_2_20260924_abc',
  content: Buffer.from('<Файл/>', 'latin1'),
};

describe('operationIdFor', () => {
  it('is a deterministic SHA-256 hex over the key', () => {
    const id = operationIdFor(KEY);
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    expect(operationIdFor({ ...KEY, content: Buffer.from(KEY.content) })).toBe(id);
  });

  it.each<[string, Partial<OperationKey>]>([
    ['swapped boxes', { fromBoxId: KEY.toBoxId, toBoxId: KEY.fromBoxId }],
    ['another ИдФайл', { idFile: `${KEY.idFile}x` }],
    ['other content', { content: Buffer.from('<Файл />', 'latin1') }],
    ['a customDocumentId', { customDocumentId: 'inv-42' }],
    ['an empty customDocumentId', { customDocumentId: '' }],
    ['a resend salt', { resend: 'r1' }],
    ['the Diadoc test signature', { testSignature: true }],
  ])('changes with %s', (_name, change) => {
    expect(operationIdFor({ ...KEY, ...change })).not.toBe(operationIdFor(KEY));
  });

  it('keeps field boundaries unambiguous', () => {
    expect(operationIdFor({ ...KEY, fromBoxId: 'ab', toBoxId: 'c' })).not.toBe(
      operationIdFor({ ...KEY, fromBoxId: 'a', toBoxId: 'bc' }),
    );
    // An optional field cannot be confused with another one holding the same text.
    expect(operationIdFor({ ...KEY, customDocumentId: 'x' })).not.toBe(
      operationIdFor({ ...KEY, resend: 'x' }),
    );
  });

  it('gives each resend salt its own key and repeats it for the same salt', () => {
    const a = operationIdFor({ ...KEY, resend: 'a' });
    expect(operationIdFor({ ...KEY, resend: 'a' })).toBe(a);
    expect(operationIdFor({ ...KEY, resend: 'b' })).not.toBe(a);
  });

  it('keeps the golden values (a change here re-sends every document under a new key)', () => {
    expect(operationIdFor(KEY)).toBe(
      '370b4a95ffd2747fb06c74f911250928ae9840a695c35cd58fdc057d4a34848b',
    );
    expect(operationIdFor({ ...KEY, customDocumentId: 'inv-42' })).toBe(
      'aa0725aa39f7d513be8cdaae0648292bdb2f3e65c19722eff0b6a01244d4664a',
    );
    expect(operationIdFor({ ...KEY, resend: 'r1' })).toBe(
      '707f39ea5d54fad1b810560a3d58b2411121ada1cb9727eea796241ffe331ddb',
    );
    expect(operationIdFor({ ...KEY, customDocumentId: 'inv-42', resend: 'r1' })).toBe(
      'b902b35d96a4fb6b098808caf0e79616f4f96fb84b5b16c5bfcafd957552e87a',
    );
  });

  it('adds the test-signature marker only when set (the golden values above stay)', () => {
    expect(operationIdFor({ ...KEY, testSignature: false })).toBe(operationIdFor(KEY));
    expect(operationIdFor({ ...KEY, testSignature: true })).toBe(
      operationIdFor({ ...KEY, testSignature: true }),
    );
    expect(operationIdFor({ ...KEY, testSignature: true, resend: 'r1' })).not.toBe(
      operationIdFor({ ...KEY, resend: 'r1' }),
    );
  });

  it('tells a present value from absent even when the bytes look alike', () => {
    // Without the presence tag, absent (one 0x00 byte) and "\u0000" would hash the same.
    expect(operationIdFor({ ...KEY, customDocumentId: '\u0000' })).not.toBe(operationIdFor(KEY));
    expect(operationIdFor({ ...KEY, resend: '\u0000' })).not.toBe(operationIdFor(KEY));
  });

  it('treats an undefined optional field as absent', () => {
    expect(operationIdFor({ ...KEY, customDocumentId: undefined, resend: undefined })).toBe(
      operationIdFor(KEY),
    );
  });
});

describe('isResendSalt', () => {
  it.each(['a', 'retry-2', '8c0e3a52-0b7c-4c1e-9f3a-2d1b6f0a9e11', 'x.y_z:1', 'a'.repeat(128)])(
    'accepts %s',
    (salt) => {
      expect(isResendSalt(salt)).toBe(true);
    },
  );

  it.each(['', ' ', 'a b', 'a/b', 'ф', 'a'.repeat(129), '--x'])('rejects %j', (salt) => {
    expect(isResendSalt(salt)).toBe(false);
  });
});

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

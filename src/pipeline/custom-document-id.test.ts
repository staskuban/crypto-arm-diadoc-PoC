import { describe, expect, it } from 'vitest';

import { customDocumentIdFor, isGuid } from './custom-document-id.js';

const OP = 'a'.repeat(64);

describe('isGuid', () => {
  it.each([
    '3d6e7a22-4987-4866-a534-9fa94099178b',
    '3D6E7A22-4987-4866-A534-9FA94099178B',
    '00000000-0000-0000-0000-000000000000',
  ])('accepts %s', (value) => {
    expect(isGuid(value)).toBe(true);
  });

  it.each([
    ['a free-form id (D192)', 'inv-42'],
    ['an empty string', ''],
    ['no dashes', '3d6e7a2249874866a5349fa94099178b'],
    ['braces', '{3d6e7a22-4987-4866-a534-9fa94099178b}'],
    ['surrounding whitespace', ' 3d6e7a22-4987-4866-a534-9fa94099178b'],
    ['a trailing newline', '3d6e7a22-4987-4866-a534-9fa94099178b\n'],
    ['a non-hex digit', '3d6e7a22-4987-4866-a534-9fa94099178g'],
  ])('refuses %s', (_name, value) => {
    expect(isGuid(value)).toBe(false);
  });
});

describe('customDocumentIdFor', () => {
  it('derives a lower-case GUID from the operationId (D200)', () => {
    const id = customDocumentIdFor(OP);
    expect(isGuid(id)).toBe(true);
    expect(id).toBe(id.toLowerCase());
  });

  it('is stable: a retry of the same send gets the same id', () => {
    expect(customDocumentIdFor(OP)).toBe(customDocumentIdFor(OP));
  });

  it('differs per operationId (a resend gets a new one)', () => {
    expect(customDocumentIdFor(OP)).not.toBe(customDocumentIdFor('b'.repeat(64)));
  });

  it('marks the id as an RFC 9562 version 8 (custom) UUID with the RFC variant', () => {
    const id = customDocumentIdFor(OP);
    expect(id[14]).toBe('8');
    expect('89ab').toContain(id[19]);
  });

  it('is not a prefix of the operationId (a domain-separated hash)', () => {
    const op = customDocumentIdFor(OP).replaceAll('-', '');
    expect(customDocumentIdFor(op).replaceAll('-', '')).not.toBe(op);
    expect(OP.startsWith(op.slice(0, 8))).toBe(false);
  });

  it('refuses an empty operationId', () => {
    expect(() => customDocumentIdFor('')).toThrow(/operationId/);
  });
});

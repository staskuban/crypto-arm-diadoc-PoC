import { createHash } from 'node:crypto';

const DOMAIN = 'kryptoarm-plus-diadoc/custom-document-id/v1';

/**
 * The form Diadoc accepts for `CustomDocumentId` in CanPostMessage (D192: anything else is
 * `400 "CanPostMessage.CustomDocumentId could not be parsed"`). Only the canonical 8-4-4-4-12 hex
 * form, any case: no braces, no whitespace.
 */
export function isGuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

/**
 * CanPostMessage requires a GUID `CustomDocumentId` (D200). Derived from the operationId, so a retry
 * of the same send gets the same id and a resend (new salt → new operationId) a new one. An RFC 9562
 * version 8 (custom) UUID over SHA-256.
 */
export function customDocumentIdFor(operationId: string): string {
  if (operationId === '') throw new Error('customDocumentIdFor needs a non-empty operationId');
  const bytes = createHash('sha256')
    .update(DOMAIN)
    .update(Buffer.from([0]))
    .update(operationId, 'utf8')
    .digest()
    .subarray(0, 16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x80;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

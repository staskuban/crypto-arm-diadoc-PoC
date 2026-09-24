import { createHash } from 'node:crypto';

const DOMAIN = 'kryptoarm-plus-diadoc/utd-send/v1';

/**
 * Idempotency key for V3/PostMessage: SHA-256 (hex) over the boxes, the file name and the exact
 * content, each length-prefixed. Deliberately not over the signature: re-signing the same УПД on a
 * retry yields a new CMS (signing time), and the retry must still be recognised as the same send.
 */
export function operationIdFor(
  fromBoxId: string,
  toBoxId: string,
  fileName: string,
  content: Buffer,
): string {
  const hash = createHash('sha256');
  for (const part of [DOMAIN, fromBoxId, toBoxId, fileName, content]) {
    const bytes = typeof part === 'string' ? Buffer.from(part, 'utf8') : part;
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}

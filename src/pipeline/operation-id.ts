import { createHash } from 'node:crypto';

/** v2: ИдФайл instead of the file name, plus customDocumentId and the resend salt (T8). */
const DOMAIN = 'kryptoarm-plus-diadoc/utd-send/v2';

/** What makes two sends "the same send" for Diadoc's idempotency. */
export interface OperationKey {
  fromBoxId: string;
  toBoxId: string;
  /** `@ИдФайл` from the parsed УПД, not the file name: `X.xml` and `X.XML` are one document. */
  idFile: string;
  /** The exact bytes that are signed and sent. */
  content: Buffer;
  customDocumentId?: string | undefined;
  /** Set only for a deliberate resend: every distinct salt is a new send. */
  resend?: string | undefined;
  /**
   * Signed by Diadoc's test signature instead of our signer: another send than a real one of the
   * same file. Hashed only when true, so the keys of real sends stay as they were.
   */
  testSignature?: boolean | undefined;
}

/**
 * Idempotency key for V3/PostMessage: SHA-256 (hex) over the key, each field length-prefixed, the
 * optional ones with a presence tag (absent ≠ empty). Deliberately not over the signature: re-signing
 * the same УПД on a retry yields a new CMS (signing time), and the retry must still be recognised as
 * the same send. Whether Diadoc replays the original message for that different body is open (D7).
 */
export function operationIdFor(key: OperationKey): string {
  const hash = createHash('sha256');
  const update = (bytes: Buffer): void => {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length).update(bytes);
  };
  for (const part of [DOMAIN, key.fromBoxId, key.toBoxId, key.idFile]) {
    update(Buffer.from(part, 'utf8'));
  }
  update(key.content);
  for (const optional of [key.customDocumentId, key.resend]) {
    if (optional === undefined) {
      update(ABSENT);
    } else {
      update(PRESENT);
      update(Buffer.from(optional, 'utf8'));
    }
  }
  if (key.testSignature === true) {
    update(PRESENT);
    update(Buffer.from('diadoc-test-signature', 'utf8'));
  }
  return hash.digest('hex');
}

const ABSENT = Buffer.from([0]);
const PRESENT = Buffer.from([1]);

/**
 * A resend salt: 1–128 ASCII letters, digits and `._:-`, not starting with a punctuation mark (so it
 * never reads as a CLI flag). A UUID fits.
 */
export function isResendSalt(salt: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(salt);
}

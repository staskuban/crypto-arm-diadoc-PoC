export interface SignResult {
  /**
   * Detached CMS SignedData, binary (for Диадок `SignedContent.Signature`). КриптоАРМ Server emits
   * BER with indefinite lengths, not strict DER.
   */
  signature: Buffer;
}

export interface SignerInfo {
  subject?: string;
  thumbprint?: string;
  signingTime?: string;
  /** Signature math and certificate chain are valid. */
  valid: boolean;
  /** Pure cryptographic check of the signature over the data, if reported. */
  mathValid?: boolean;
  chainValid?: boolean;
}

export interface VerifyResult {
  /** At least one signature is present and every one is valid (math + certificate chain). */
  valid: boolean;
  signers: SignerInfo[];
  /** Upstream explanation when `valid` is false. */
  reason?: string;
}

export interface SignerCallOptions {
  /** Cancels the call (e.g. pipeline shutdown); the promise rejects with the signal's reason. */
  signal?: AbortSignal;
}

/**
 * Makes detached CMS signatures over exact bytes. The data is never re-encoded: the УПД XML is
 * windows-1251 and Диадок checks the signature against the same bytes that are sent.
 */
export interface Signer {
  sign(data: Buffer, options?: SignerCallOptions): Promise<SignResult>;
  /** Resolves `valid: false` for a signature that does not match; rejects only on call failures. */
  verify(data: Buffer, signature: Buffer, options?: SignerCallOptions): Promise<VerifyResult>;
}

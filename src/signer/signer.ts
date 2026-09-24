export interface SignResult {
  /** Detached CMS SignedData, DER (for Диадок `SignedContent.Signature`). */
  signature: Buffer;
  /**
   * The signature exactly as the service returned it, set only when it differed from `signature`
   * (e.g. КриптоАРМ Server emits BER with indefinite lengths). For debugging only: never send it,
   * and log a digest or prefix rather than the whole binary.
   */
  rawSignature?: Buffer;
}

export interface SignerInfo {
  subject?: string;
  thumbprint?: string;
  signingTime?: string;
  /** Signer certificate expiry as the verifier reports it (ISO 8601). */
  notAfter?: string;
  /** Signature math and certificate chain are valid. */
  valid: boolean;
  /** Pure cryptographic check of the signature over the data, if reported. */
  mathValid?: boolean;
  chainValid?: boolean;
  /** The signer certificate itself is valid (period, usage), as the verifier reports it. */
  certValid?: boolean;
  /** The verifier saw a detached signature. */
  detached?: boolean;
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
  /**
   * The public certificate (DER) the signer is configured with, e.g. from `SIGNER_CERT_PATH`. It
   * comes from our config, not from the service: the pipeline checks that every signature was
   * made by exactly this certificate.
   */
  readonly certificate: Buffer;
  sign(data: Buffer, options?: SignerCallOptions): Promise<SignResult>;
  /** Resolves `valid: false` for a signature that does not match; rejects only on call failures. */
  verify(data: Buffer, signature: Buffer, options?: SignerCallOptions): Promise<VerifyResult>;
}

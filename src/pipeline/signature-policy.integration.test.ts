// Opt-in: runs only when CRYPTOARM_SERVER_URL is set, against a live КриптоАРМ Server
// (docker/cryptoarm-server), with the same env as src/signer/server-cms-signer.integration.test.ts.
// Proves the signature policy on real signatures: the configured certificate passes, another
// certificate (thumbprint mismatch) is rejected before and after /cms/verify.
import { readFileSync, readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { PipelineDiadoc } from './send.js';
import { loadServerCmsSignerOptions, ServerCmsSigner, type Signer } from '../signer/index.js';
import { PipelineError } from './errors.js';
import { sendUtd } from './send.js';
import {
  cmsPolicyViolations,
  readSignerCertificate,
  verifiedSignerViolations,
} from './signature-policy.js';

const enabled = Boolean(process.env.CRYPTOARM_SERVER_URL);
const TIMEOUT = 300_000;
const FIXTURES = new URL('../utd/fixtures/', import.meta.url);
const FILE_NAME = readdirSync(FIXTURES).find((f) => f.endsWith('.xml')) ?? '';
const CONTENT = readFileSync(new URL(FILE_NAME, FIXTURES));
// The КриптоПро test CA root: a real certificate that did not make the signature.
const OTHER_CERT = readFileSync(
  new URL('../signer/fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
);

/** Stops the pipeline at its first Диадок call: everything before it has passed. */
const REACHED_DIADOC = new Error('reached Диадок');
const diadoc: PipelineDiadoc = {
  canPostMessage: () => Promise.reject(REACHED_DIADOC),
  shelfUpload: () => Promise.reject(REACHED_DIADOC),
  postMessage: () => Promise.reject(REACHED_DIADOC),
  getDocument: () => Promise.reject(REACHED_DIADOC),
};

async function send(signer: Signer): Promise<PipelineError> {
  const error = await sendUtd(
    { fileName: FILE_NAME, content: CONTENT },
    { signer, diadoc },
    { fromBoxId: 'from', toBoxId: 'to' },
  ).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(PipelineError);
  return error as PipelineError;
}

describe.skipIf(!enabled)('signature policy against КриптоАРМ Server', () => {
  it(
    'a real signature by the configured certificate passes; another thumbprint fails',
    async () => {
      const signer = new ServerCmsSigner(await loadServerCmsSignerOptions());
      const own = readSignerCertificate(signer.certificate);
      const other = readSignerCertificate(OTHER_CERT);
      const { signature } = await signer.sign(CONTENT);

      expect(cmsPolicyViolations(signature, own)).toEqual([]);
      const verification = await signer.verify(CONTENT, signature);
      expect(verification.valid, verification.reason).toBe(true);
      expect(verification.signers[0]?.thumbprint?.toLowerCase()).toBe(own.thumbprint);
      expect(verifiedSignerViolations(verification, own)).toEqual([]);

      expect(cmsPolicyViolations(signature, other)).toEqual([
        expect.stringMatching(/not by the configured certificate/),
      ]);
      expect(verifiedSignerViolations(verification, other)).toEqual([
        expect.stringMatching(`expected ${other.thumbprint}`),
      ]);
    },
    TIMEOUT,
  );

  it(
    'sendUtd: the real signer reaches Диадок; a signer claiming another certificate is stopped',
    async () => {
      const signer = new ServerCmsSigner(await loadServerCmsSignerOptions());
      const passed = await send(signer);
      expect(passed).toMatchObject({ code: 'PRECHECK_FAILED', cause: REACHED_DIADOC });

      // Same server key, but the pipeline expects another certificate (thumbprint mismatch).
      const mismatched: Signer = {
        certificate: OTHER_CERT,
        sign: (data, options) => signer.sign(data, options),
        verify: (data, sig, options) => signer.verify(data, sig, options),
      };
      const rejected = await send(mismatched);
      expect(rejected).toMatchObject({ code: 'SIGNATURE_POLICY_VIOLATION', step: 'policy' });
    },
    TIMEOUT,
  );
});

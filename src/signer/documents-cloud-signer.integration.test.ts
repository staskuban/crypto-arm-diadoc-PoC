// Opt-in: runs only when DOCUMENTS_URL is set, against a live КриптоАРМ Документы stand
// (docker/cryptoarm-documents) and the КриптоАРМ Server it signs with (the verifier):
//   DOCUMENTS_URL=http://127.0.0.1:3040 DOCUMENTS_LOGIN=admin \
//   DOCUMENTS_PASSWORD_FILE=docker/cryptoarm-documents/secrets/admin_password \
//   SIGNER_CERT_PATH=docker/cryptoarm-server/certs/cryptoarm.server.test.cer \
//   CRYPTOARM_SERVER_URL=http://127.0.0.1:3037 CRYPTOARM_SERVER_API_KEY=… \
//   npm test -- src/signer/documents-cloud-signer.integration.test.ts
// SIGNER_CERT_PATH must be the certificate the stand's CA stub maps to the login's e-mail.
// Every signing uploads a new document (and leaves it and its signature on the stand).
import { readFileSync, readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { PipelineError } from '../pipeline/errors.js';
import { sendUtd, type PipelineDiadoc } from '../pipeline/send.js';
import {
  cmsPolicyViolations,
  readSignerCertificate,
  verifiedSignerViolations,
} from '../pipeline/signature-policy.js';
import {
  createSignerFromEnv,
  loadDocumentsCloudSignerEnv,
  loadServerCmsSignerOptions,
} from './config.js';
import { DocumentsCloudSigner } from './documents-cloud-signer.js';
import { SignerPayloadTooLargeError } from './errors.js';
import { ServerCmsSigner } from './server-cms-signer.js';
import type { Signer } from './signer.js';

const enabled = Boolean(process.env.DOCUMENTS_URL);
const TIMEOUT = 300_000;
const FIXTURES = new URL('../utd/fixtures/', import.meta.url);
const FILE_NAME = readdirSync(FIXTURES).find((f) => f.endsWith('.xml')) ?? '';
const CONTENT = readFileSync(new URL(FILE_NAME, FIXTURES));
// The КриптоПро test CA root: a real certificate that the CA stub does not map to the user.
const OTHER_CERT = readFileSync(
  new URL('./fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
);

/** Stops the pipeline at its first Диадок call: everything before it has passed. */
const REACHED_DIADOC = new Error('reached Диадок');
const diadoc: PipelineDiadoc = {
  canPostMessage: () => Promise.reject(REACHED_DIADOC),
  shelfUpload: () => Promise.reject(REACHED_DIADOC),
  postMessage: () => Promise.reject(REACHED_DIADOC),
  getDocument: () => Promise.reject(REACHED_DIADOC),
  getMessage: () => Promise.reject(REACHED_DIADOC),
  getSignatureInfo: () => Promise.reject(REACHED_DIADOC),
  getOrganization: () => Promise.reject(REACHED_DIADOC),
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

function documentsSigner(): Promise<Signer> {
  return createSignerFromEnv({ ...process.env, SIGNER_KIND: 'documents' });
}

describe.skipIf(!enabled)('DocumentsCloudSigner against КриптоАРМ Документы', () => {
  it(
    'cloud-signs the exact УПД bytes; the DER signature passes the F5 policy and verifies',
    async () => {
      const signer = await documentsSigner();
      expect(signer).toBeInstanceOf(DocumentsCloudSigner);
      const own = readSignerCertificate(signer.certificate);
      const { signature, rawSignature } = await signer.sign(CONTENT);

      // D11: Документы hands out the server's BER; the signer returns DER.
      expect(rawSignature?.subarray(0, 2)).toEqual(Buffer.from([0x30, 0x80]));
      expect(signature.subarray(0, 2)).not.toEqual(Buffer.from([0x30, 0x80]));
      expect(cmsPolicyViolations(signature, own)).toEqual([]);

      const verification = await signer.verify(CONTENT, signature);
      expect(verification.valid, verification.reason).toBe(true);
      expect(verification.signers[0]?.thumbprint?.toLowerCase()).toBe(own.thumbprint);
      expect(verifiedSignerViolations(verification, own)).toEqual([]);

      const tampered = Buffer.concat([CONTENT, Buffer.from(' ')]);
      expect((await signer.verify(tampered, signature)).valid).toBe(false);
    },
    TIMEOUT,
  );

  it(
    'sendUtd: the Документы signer reaches Диадок; a wrong e-mail -> certificate mapping is stopped',
    async () => {
      const passed = await send(await documentsSigner());
      expect(passed).toMatchObject({ code: 'PRECHECK_FAILED', cause: REACHED_DIADOC });

      // The stand signs with the key mapped to the login's e-mail, but we expect another
      // certificate: the F5 policy must reject it (D12).
      const options = await loadDocumentsCloudSignerEnv();
      const verifier = await documentsSigner();
      const mismatched = new DocumentsCloudSigner({
        ...options,
        certificate: OTHER_CERT,
        verifier,
      });
      const rejected = await send(mismatched);
      expect(rejected).toMatchObject({ code: 'SIGNATURE_POLICY_VIOLATION', step: 'policy' });
    },
    TIMEOUT,
  );

  it(
    'signs with a configured Bearer JWT (issued by GET /api/v1/auth/jwt)',
    async () => {
      const options = await loadDocumentsCloudSignerEnv();
      if (!('login' in options.auth)) return; // already a JWT run: covered by the first test
      const base = new URL(options.baseUrl.endsWith('/') ? options.baseUrl : `${options.baseUrl}/`);
      const login = await fetch(new URL('api/v1/login', base), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: options.auth.login, password: options.auth.password }),
        redirect: 'error',
      });
      expect(login.status).toBe(200);
      const cookie = login.headers
        .getSetCookie()
        .map((c) => c.split(';', 1)[0] ?? '')
        .join('; ');
      const issued = await fetch(new URL('api/v1/auth/jwt?expiresIn=15m', base), {
        headers: { cookie },
        redirect: 'error',
      });
      expect(issued.status).toBe(200);
      const { token } = (await issued.json()) as { token: string };

      const verifier = await documentsSigner();
      const signer = new DocumentsCloudSigner({ ...options, auth: { jwt: token }, verifier });
      const { signature } = await signer.sign(CONTENT);
      expect(cmsPolicyViolations(signature, readSignerCertificate(signer.certificate))).toEqual([]);
    },
    TIMEOUT,
  );

  it(
    'D50: refuses data too large to verify before uploading; the stand relays JSON_LIMIT and MAX_FILE_SIZE',
    async () => {
      const options = await loadDocumentsCloudSignerEnv();
      const server = new ServerCmsSigner(await loadServerCmsSignerOptions());
      const calls: string[] = [];
      const countingFetch: typeof fetch = (input, init) => {
        calls.push(input instanceof URL ? input.pathname : 'other');
        return fetch(input, init);
      };
      // Base64 of 40 000 000 B is 53 333 336 B: over the server's 50 MiB JSON_LIMIT.
      const big = Buffer.alloc(40_000_000, 0x41);

      const guarded = new DocumentsCloudSigner({
        ...options,
        verifier: server,
        fetch: countingFetch,
      });
      const refused = await guarded.sign(big).catch((e: unknown) => e);
      expect(refused).toBeInstanceOf(SignerPayloadTooLargeError);
      expect(refused).toMatchObject({ status: undefined, limitBytes: server.maxRequestBytes });
      expect(calls).toEqual([]); // not even the login

      // Without the verifier's limit the file is uploaded and cloud-sign relays the server's 400.
      const unguarded = new DocumentsCloudSigner({
        ...options,
        verifier: { verify: (...args) => server.verify(...args) },
      });
      const relayed = await unguarded.sign(big).catch((e: unknown) => e);
      expect(relayed).toBeInstanceOf(SignerPayloadTooLargeError);
      expect(relayed).toMatchObject({ status: 400 });
      expect((relayed as Error).message).toMatch(/^sign: cloud-sign of 40000000 B rejected/);

      // MAX_FILE_SIZE=50 (MiB) on the stand: a file of exactly 50 MiB is refused with 413.
      const tooBig = Buffer.alloc(52_428_800, 0x41);
      const rejected = await unguarded.sign(tooBig).catch((e: unknown) => e);
      expect(rejected).toBeInstanceOf(SignerPayloadTooLargeError);
      expect(rejected).toMatchObject({ status: 413 });
      expect((rejected as Error).message).toMatch(/^sign: upload of 52428800 B rejected/);
    },
    TIMEOUT,
  );
});

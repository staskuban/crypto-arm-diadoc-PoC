// Opt-in: runs only when CRYPTOARM_SERVER_URL is set, against a live КриптоАРМ Server
// (docker/cryptoarm-server). Also needs SIGNER_CERT_PATH (public .cer whose key is installed in the
// server store) and CRYPTOARM_SERVER_API_KEY when the server runs with AUTH_MODE=apikey.
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { berToDer, isDerFramed } from '../asn1/index.js';
import { loadServerCmsSignerOptions } from './config.js';
import { SignerHttpError, SignerKeyNotFoundError } from './errors.js';
import { ServerCmsSigner } from './server-cms-signer.js';

const enabled = Boolean(process.env.CRYPTOARM_SERVER_URL);
const TIMEOUT = 300_000;

describe.skipIf(!enabled)('ServerCmsSigner against КриптоАРМ Server', () => {
  // windows-1251 УПД-like bytes plus a random marker; not valid UTF-8 on purpose.
  const marker = randomBytes(16).toString('hex');
  const data = Buffer.concat([
    Buffer.from('<?xml version="1.0" encoding="windows-1251"?><Файл ИдФайл="', 'latin1'),
    Buffer.from([0xd3, 0xcf, 0xc4]),
    Buffer.from(`${marker}"/>`, 'latin1'),
  ]);

  it(
    'signs detached and verifies the exact bytes; tampered data is rejected',
    async () => {
      const signer = new ServerCmsSigner(await loadServerCmsSignerOptions());

      const { signature, rawSignature } = await signer.sign(data);
      expect(signature[0]).toBe(0x30);
      // Normalized to DER: re-encoding is a no-op.
      expect(isDerFramed(signature)).toBe(true);
      expect(berToDer(signature).equals(signature)).toBe(true);
      expect(signature.includes(Buffer.from(marker, 'latin1'))).toBe(false); // detached

      const result = await signer.verify(data, signature);
      expect(result.valid, result.reason).toBe(true);
      expect(result.signers).toHaveLength(1);
      expect(result.signers[0]?.mathValid).toBe(true);

      // The stand returns BER with indefinite lengths (docs/plan.md D1); the raw form verifies
      // too. If this fails because the server switched to DER, drop the expectation.
      expect(rawSignature).toBeDefined();
      if (rawSignature !== undefined) {
        expect(isDerFramed(rawSignature)).toBe(false);
        expect((await signer.verify(data, rawSignature)).valid).toBe(true);
      }

      // The stand answers a mismatch with 201 { isValidSign: false } (checked 2026-09-24).
      const tampered = Buffer.concat([data, Buffer.from(' ')]);
      const rejected = await signer.verify(tampered, signature);
      expect(rejected.valid).toBe(false);
      expect(rejected.reason).toBeTruthy();
    },
    TIMEOUT,
  );

  it(
    'verifies the committed BER fixture after DER normalization',
    async () => {
      const signer = new ServerCmsSigner(await loadServerCmsSignerOptions());
      const fixture = (name: string) =>
        readFile(new URL(`../asn1/fixtures/server-cms-detached.${name}`, import.meta.url));
      const der = berToDer(await fixture('ber'));
      const result = await signer.verify(await fixture('data'), der);
      // Math only: the chain check starts failing once the test certificate expires (2026-10-28).
      expect(result.signers).toHaveLength(1);
      expect(result.signers[0]?.mathValid).toBe(true);
    },
    TIMEOUT,
  );

  it(
    'surfaces an upstream rejection of an unusable certificate as SignerHttpError',
    async () => {
      const options = await loadServerCmsSignerOptions();
      // Passes our DER shape check but is not a real certificate, so the server rejects it.
      const foreign = Buffer.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x05, 0x01, 0x00]);
      const signer = new ServerCmsSigner({ ...options, certificate: foreign });
      const error = await signer.sign(data).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SignerHttpError);
      expect((error as SignerHttpError).status).toBeGreaterThanOrEqual(400);
      expect((error as SignerHttpError).upstreamMessage).not.toBe('');
    },
    TIMEOUT,
  );

  it(
    'maps a real certificate whose key is not on the server to SignerKeyNotFoundError',
    async () => {
      const options = await loadServerCmsSignerOptions();
      // The КриптоПро test CA root: a real GOST certificate whose private key we never have.
      // Expires 2026-10-28 together with the test signer certificate.
      const certificate = await readFile(
        new URL('fixtures/cryptopro-test-ca-2012-21.cer', import.meta.url),
      );
      const signer = new ServerCmsSigner({ ...options, certificate });
      const error = await signer.sign(data).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SignerKeyNotFoundError);
      expect((error as SignerKeyNotFoundError).status).toBe(400);
    },
    TIMEOUT,
  );
});

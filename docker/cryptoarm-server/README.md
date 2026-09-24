# КриптоАРМ Server (local stand)

Dockerized [КриптоАРМ Server](https://git.digtlab.ru/trusted/cryptoarm/server) that holds the signing
keys and signs via `POST /cms/sign`. `Dockerfile` and `docker-compose.yml` follow upstream commit
`af98d55e`. Local changes: an empty `TRUSTED_LICENSE` warns instead of aborting the start script (see the
`Dockerfile` header); compose adds project-scoped names, `linux/amd64`, a loopback-only port, a read-only
`certs` mount and a healthcheck.

## Manual prerequisites

1. Log in at cryptopro.ru and download **КриптоПро CSP 5.0 for Linux, x64, deb**
   (`linux-amd64_deb.tgz`, https://cryptopro.ru/products/csp/downloads).
2. Put it at `docker/cryptoarm-server/cryptopro/linux-amd64_deb.tgz`. It is git-ignored.
3. Obtain a **КриптоАРМ Server license key** (test key from the vendor) and set `TRUSTED_LICENSE` in `.env`.

| Variable            | Empty value means (verified 2026-09-24)                                                                                                                                                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CRYPTOPRO_LICENSE` | КриптоПро CSP trial: `License type: Demo`, 94 days left on first start                                                                                                                                                                                                                         |
| `TRUSTED_LICENSE`   | start script warns and continues; CSP and keys get installed, then `node dist/main.js` exits with `Trusted Crypto license is invalid` and the container restarts in a loop. **No signing without it.** A wrong key fails the same way even though `setup_license` prints "saved successfully". |

The image is `linux/amd64` only. On Apple Silicon it runs under emulation, so it is slower.

## Run

```sh
scripts/fetch-test-certs.sh                  # upstream test certs → docker/cryptoarm-server/certs (git-ignored)
cp docker/cryptoarm-server/.env.example docker/cryptoarm-server/.env   # set TRUSTED_LICENSE, API_KEYS
docker compose -f docker/cryptoarm-server/docker-compose.yml up -d --build
docker compose -f docker/cryptoarm-server/docker-compose.yml ps   # wait for "healthy"
CRYPTOARM_SERVER_API_KEY=<key from API_KEYS> scripts/smoke-server.sh
```

Stop with `docker compose -f docker/cryptoarm-server/docker-compose.yml down` (project
`kryptoarm-diadoc-cryptoarm-server`). Swagger is at http://localhost:3037/docs. The healthcheck calls `GET /health/memory`, which needs no API key.

## Certificates and keys

At start, the container installs everything under the `./certs` mount (read-only):

- `certs/root/*.cer` go to the `mroot` store.
- `certs/user/*.pfx` go to the `uMy` store. These containers must have no PIN. For containers with a PIN, use
  `CERT_PFX_BASE64` + `CERT_PFX_PIN` in `.env`.

The CSP key store lives in `./cert_storage` (git-ignored), so installed keys survive restarts.

Clients send **only the public certificate** as `cert`. The server finds the private key in `uMy` by
thumbprint. The smoke script refuses `.pfx`/`.p12`.

`scripts/fetch-test-certs.sh` downloads the test material and checks SHA-256:

- `certs/cryptoarm.server.test.cer` (upstream): public certificate `CN=cryptoarm.server.test`, used by the smoke
  script. It is **valid until 2026-10-28**.
- `certs/user/cryptoarm.server.test.pfx` (upstream): its key container (no PIN).
- `certs/root/cryptopro-test-ca-2012-21.cer`: the self-signed root of the issuer, `Тестовый УЦ ООО "КРИПТО-ПРО"`.
  It is downloaded from the certificate's AIA URL `http://testgost2012.cryptopro.ru/CertEnroll/testgost2012(21).crt`
  and is also valid only until 2026-10-28. Upstream's `certs/crypto.root.test.cer` is **byte-identical to the leaf
  certificate**. With only that file installed, `/cms/verify` returns `isValidSign=false` with the message «Не удалось
  проверить цепочку сертификатов» even though `extVerifyInfo.mathValidity=true`. For that reason it is not used.

## Signer certificate of ООО «О2 ПЛАТФОРМА» (test CA)

`scripts/issue-test-cert.sh` issues a certificate from the public КриптоПро test CA
(http://testgost2012.cryptopro.ru/certsrv/, Microsoft ADCS web enrollment). The key is generated inside the running
container and is never copied out by the script. The script talks to it only through `docker exec`, as root, the
same user as the server, so the key lands in root's `uMy`.

1. `cryptcp -createrqst` in the container creates a new key container `\\.\HDIMAGE\o2-platforma-test-<UTC time>`
   (GOST R 34.10-2012 256, signature key, no PIN, **not exportable**) in `/var/opt/cprocsp`, that is the
   `cert_storage` volume, and a PKCS#10 request. The container has no seeded CPSD random source, so CSP asks for
   keyboard entropy (`BIO_TUI`). The script answers it with `expect`, sending bytes from the container's
   `/dev/urandom`. `expect` ships with the base image `registry.digtlab.ru/trusted/cryptoarm/server`; the script
   checks for it first. This entropy source is acceptable **for a test key only**. A production key needs a proper
   RNG, such as a seeded CPSD or hardware.
2. The request goes to `certfnsh.asp` (`Mode=newreq`). The certificate comes from `certnew.cer?ReqID=N&Enc=bin`.
   The issuer comes from the certificate's AIA URL (http/https only). It is trusted only if it is self-signed and its
   subject equals the certificate's issuer. The GOST signature is not checked on the host, which has no GOST
   provider. The CA issues at once, with no manual approval. `https://` fails
   with an untrusted TLS chain, so the script uses `http://`, the same scheme as the AIA/CRL URLs in the certificates.
3. `certmgr -inst -store mroot` installs the issuer. `certmgr -inst -store uMy -cont … -at_signature -to-container`
   binds the certificate to the key. Without `-at_signature`, certmgr looks for an exchange key and fails with
   `0x8009000d Key does not exist`.
4. Only public certificates are written on the host: `certs/o2-platforma.test.cer` and
   `certs/root/cryptopro-test-ca-2012-<N>.cer`. Both are git-ignored.

The script refuses to run if the key container already exists, so it never deletes a key it did not create. If a
step fails before the certificate is bound, the new key container is deleted again, and a keygen still running in
the container is killed first. An issuer that was already installed into `mroot` stays there.

```sh
docker compose -f docker/cryptoarm-server/docker-compose.yml ps     # the stand must be running
scripts/issue-test-cert.sh                                           # ~1 min under amd64 emulation
CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer SMOKE_STRICT=1 \
  CRYPTOARM_SERVER_API_KEY=<key> scripts/smoke-server.sh
```

Env: `CRYPTOARM_CONTAINER`, `TEST_CA_URL`, `CERTS_DIR` (for example, the certs dir of the worktree the stand
runs from), `CERT_NAME`, `KEY_CONTAINER` (must not exist yet), `KEYGEN_TIMEOUT` (default 300 s), and the subject values `ORG_*` / `SIGNER_*` (see the script header). The
signer person is a **placeholder** (`SN=Тестов`, `G=Тест Тестович`, `T=Генеральный директор`). Tests with a fake
`docker` and a fake CA: `scripts/test/issue-test-cert.test.sh`.

Result of the run on 2026-09-24 (ReqID 3928972, key container `\\.\HDIMAGE\o2-platforma-test-20260924123430`):

| Field                  | Value                                                                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Subject                | `CN` = `O` = `ООО "О2 ПЛАТФОРМА"`, `SN=Тестов`, `G=Тест Тестович`, `T=Генеральный директор`, `L=Краснодар`, `ST=Краснодарский край`, `C=RU` |
| ИНН ЮЛ `1.2.643.100.4` | `2311386400`: **honoured** (NumericString)                                                                                                  |
| ОГРН `1.2.643.100.1`   | `1252300058977`: **honoured** (NumericString)                                                                                               |
| КПП                    | not requested. The certificate profile (Приказ ФСБ № 795) has no КПП attribute.                                                             |
| Validity               | 2026-09-24 12:29:31 UTC – **2026-10-28 12:32:11 UTC**                                                                                       |
| SHA-1 thumbprint       | `9fe820c07bfa7ffbc5fb9272f0f4936d69944037`                                                                                                  |
| Key usage / EKU        | Digital Signature, Non Repudiation / client auth, e-mail protection                                                                         |
| Issuer                 | `Тестовый УЦ ООО "КРИПТО-ПРО"` (renewal 21)                                                                                                 |

Notes:

- **Validity is capped by the CA certificate.** The test CA currently has a single certificate, renewal 21
  (2026-07-28 – 2026-10-28), and it issues nothing past its own expiry. Any certificate issued now therefore expires
  on 2026-10-28, the same day as the upstream test certificate. Assumption, based on this one renewal only: the CA rolls its key
  about every 3 months. After it does, re-run the script: it picks up the new issuer from AIA, installs it into `mroot` and stores it under
  `certs/root/`. `scripts/fetch-test-certs.sh` hardcodes renewal 21 and its SHA-256, so it must be updated then too.
- Subject strings are `BMPString`, because cryptcp encodes them that way in the request and the CA copies them.
  ИНН/ОГРН are `NumericString`.
- "Never leaves the container" is only half true. `/var/opt/cprocsp` is a **bind mount** of `cert_storage/` in the
  worktree the stand runs from, so the key container files (`keys/root/*.000/`) sit on the host disk, without a PIN,
  protected only by file permissions. Anyone who copies that directory has the key. That is acceptable for a
  test-CA key and must not be done with a real КЭП. `certmgr -export -pfx` is refused with `0x8009000b`
  (non-exportable), but that does not protect the files. If `cert_storage/` is wiped (or that worktree is removed),
  the key is gone: re-run the script.
- Every run creates a new key container. Old ones stay installed. The upstream `cryptoarm.server.test` certificate
  is not touched, and both certificates sign.

## Smoke script

`scripts/smoke-server.sh` does four things:

1. Signs a random payload with `{cert: <.cer>, data, detached: true}`.
2. Checks that the CMS does not embed the payload, so the signature is detached.
3. Verifies with `POST /cms/verify` and requires `isValidSign=true`. On the real server this flag includes the
   certificate chain. If verification fails, the script prints the server's `cadesVfyStatusDescription`.
4. Checks that tampered data is rejected.

Env: `CRYPTOARM_SERVER_URL` (default `http://localhost:3037`), `CRYPTOARM_SERVER_API_KEY`, `CERT_FILE`,
`SMOKE_STRICT`. Requires `curl`, `jq`, `base64`.

Tests (they use a fake server, so no Docker is needed): `scripts/test/smoke-server.test.sh` and
`scripts/test/setup-trusted-license.test.sh`.

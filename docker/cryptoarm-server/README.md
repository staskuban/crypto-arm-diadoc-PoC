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

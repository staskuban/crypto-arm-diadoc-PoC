# КриптоАРМ Server (local stand)

Dockerized [КриптоАРМ Server](https://git.digtlab.ru/trusted/cryptoarm/server) that holds the signing
keys and signs via `POST /cms/sign`. `Dockerfile` and `docker-compose.yml` follow upstream commit
`af98d55e`. Local changes (see the `Dockerfile` header):

- The base image is pinned: `server:1.4.25@sha256:065293ad…` (the same digest as `latest` on 2026-09-24).
- The CSP tgz is bind-mounted into the install step, so it never ends up in an image layer.
- `start.sh` (exec-form `ENTRYPOINT`) replaces upstream's shell-form `CMD`. It reads secrets from files and logs
  `certmgr` errors, then execs the server under `init`. An empty `TRUSTED_LICENSE` warns instead of aborting.
- Compose adds project-scoped names, `linux/amd64`, a loopback-only port, read-only `certs` and `secrets`
  mounts, `cap_drop: [ALL]`, `no-new-privileges` and a healthcheck.
- It also splits build and run (D8, see [Build and run](#run)).
- `LOG_LEVEL` defaults to `warn,error`. At the `log` level the server prints the first 8 characters of the API key
  on every request.
- `JSON_LIMIT` (default `50mb`) caps the request body at exactly 52 428 800 B; one byte more is answered with
  HTTP 400 «request entity too large» (not 413). With Base64 data and the CMS in the verify body the largest
  signable file is about 39.3 MB (measured in T10). If you change it, set `CRYPTOARM_SERVER_MAX_REQUEST_BYTES` for
  the pipeline to the same number of bytes.

## Manual prerequisites

1. Log in at cryptopro.ru and download **КриптоПро CSP 5.0 for Linux, x64, deb**
   (`linux-amd64_deb.tgz`, https://cryptopro.ru/products/csp/downloads).
2. Put it at `docker/cryptoarm-server/cryptopro/linux-amd64_deb.tgz`. It is git-ignored.
3. Obtain a **КриптоАРМ Server license key** (test key from the vendor) and put it in `secrets/trusted_license`
   (see [Secrets](#secrets)).

| Variable            | Empty value means (verified 2026-09-24)                                                                                                                                                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CRYPTOPRO_LICENSE` | КриптоПро CSP trial: `License type: Demo`, 94 days left on first start                                                                                                                                                                                                                         |
| `TRUSTED_LICENSE`   | start script warns and continues; CSP and keys get installed, then `node dist/main.js` exits with `Trusted Crypto license is invalid` and the container restarts in a loop. **No signing without it.** A wrong key fails the same way even though `setup_license` prints "saved successfully". |

The image is `linux/amd64` only. On Apple Silicon it runs under emulation, so it is slower.

## Run

```sh
scripts/fetch-test-certs.sh                  # upstream test certs → docker/cryptoarm-server/certs (git-ignored)
cd docker/cryptoarm-server
(umask 077; cp .env.example .env)            # non-secret settings only
(umask 077; printf '%s' '<license key>' > secrets/trusted_license; openssl rand -hex 24 > secrets/api_keys)
docker compose build cryptoarm-server-image  # build-only service (profile "build")
docker compose up -d
docker compose ps                            # wait for "healthy"
CRYPTOARM_SERVER_API_KEY="$(head -1 secrets/api_keys)" SMOKE_STRICT=1 ../../scripts/smoke-server.sh
```

From the repo root, the same commands work, because the root compose file `include`s this one. Pick one place
and stick to it. The project name is `kryptoarm-diadoc-cryptoarm-server` in this directory and the worktree
directory name from the root: the shared stand is project `graph-root`. The container name is fixed either way.
Stop with `docker compose down`.
Swagger is at http://localhost:3037/docs. The healthcheck calls `GET /health/memory`, which needs no API key.

**Build and run are separate (D8).** `cryptoarm-server` has no `build` section and `pull_policy: never`. The image
comes only from the build-only service `cryptoarm-server-image` (same tag, profile `build`). So `up`, and
`docker compose run --build app` from the root, can never rebuild the server image or recreate the container
because of a new image. `up` on a machine without the image fails with "No such image": build it first. The
container is still recreated when its _config_ changes (another worktree, a changed `.env` or compose file).
Check with `docker compose --dry-run up -d` that it stays `Running`. The image tag is shared by all worktrees:
building `cryptoarm-server-image` with the default tag anywhere else moves `…:local`, and the next `up` (or `run app`
without `--no-deps`) in `graph-root` recreates the shared stand on that image. Build the default tag only from
`graph-root`, override `CRYPTOARM_SERVER_IMAGE` elsewhere, and keep using `run --rm --no-deps app`.

**Throwaway stand** next to the shared one (other project, container, image tag and port; its own `cert_storage`
and `secrets` in that worktree):

```sh
export CRYPTOARM_SERVER_IMAGE=kryptoarm-diadoc/cryptoarm-server:i5 \
  CRYPTOARM_CONTAINER_NAME=kryptoarm-diadoc-i5-cryptoarm-server CRYPTOARM_SERVER_PORT=3038 \
  APP_IMAGE=kryptoarm-diadoc/app:i5
docker compose -p kryptoarm-diadoc-i5 build cryptoarm-server-image
docker compose -p kryptoarm-diadoc-i5 up -d
# ... tests against http://127.0.0.1:3038 ...
docker compose -p kryptoarm-diadoc-i5 down
```

`scripts/issue-test-cert.sh` names the container with `CRYPTOARM_CONTAINER` (not `CRYPTOARM_CONTAINER_NAME`): set
both on a throwaway stand, or it enrolls into the shared one.

## Secrets

`start.sh` reads each of `TRUSTED_LICENSE`, `CRYPTOPRO_LICENSE`, `CRYPTOPRO_TSP_LICENSE`,
`CRYPTOPRO_OCSP_LICENSE` and `API_KEYS` from the first source that exists:

1. `<VAR>_FILE`: an explicit path. The start fails if it is not readable.
2. `/run/secrets/<var>`, lower-case: the files in `./secrets`, mounted read-only.
3. The env value from `.env`. This is the legacy path; a file wins over it, with a warning.

`./secrets` is git-ignored except `.gitkeep`. Create the files with `umask 077`. Values in `.env` reach the
container config (`docker inspect`) and `/proc/*/environ`. Values in files do not.

The server process gets `TRUSTED_LICENSE=""` and `CRYPTOPRO_LICENSE=""`: it only checks that they are defined.
The КриптоАРМ license is written to `/etc/opt/Trusted/CryptoARM Server/license.lic`, the same file upstream's
`setup_license` writes. `API_KEYS` must stay in the server's env, because the server reads it only from there.
The file may hold one key per line.

What is still exposed: `cpconfig`/`tsputil`/`ocsputil`/`certmgr` accept the CSP licenses and PFX PINs only as
argv. They are visible in the container's process list for the duration of that call at start.

**Migration of an existing stand:** build the new image **first**
(`docker compose build cryptoarm-server-image`). The compose config of the server changed (`init`, `cap_drop`,
the `secrets` mount), so the next `up -d` or `run app` without `--no-deps` recreates the container. If the tag
still points to the old image, the old start script cannot read `secrets/`, and with the license already moved
out of `.env` the server restart-loops. Then move `TRUSTED_LICENSE`, `CRYPTOPRO_LICENSE` and `API_KEYS` from `.env`
into `secrets/`, leave them empty in `.env`, set `LOG_LEVEL=warn,error`, and run `up -d`. Unchanged `.env` values
keep working. `cert_storage` (installed keys) is kept.

**Linux hosts:** on Docker Desktop, bind-mounted files appear as `root:root` in the container, so the server
reads 0600 files with no capabilities (verified). On a Linux host they keep the owner's uid, and root without
`CAP_DAC_READ_SEARCH` cannot read another user's 0600 file or 0700 directory (verified with `--cap-drop ALL`).
There, either `chown root` the `secrets`/`certs` files, or add `cap_add: [DAC_READ_SEARCH]` in a
`docker-compose.override.yml`. `cert_storage` must be owned by root; Docker creates it that way if it is missing.

## Certificates and keys

At start, the container installs everything under the `./certs` mount (read-only):

- `certs/root/*.cer` go to the `mroot` store.
- `certs/user/*.pfx` go to the `uMy` store. These containers must have no PIN.
- `secrets/*.pfx|*.p12` go to `uMy` too, with the PIN from `secrets/<name>.pfx.pin` if that file exists. Put real
  keys here.
- `CERT_PFX_BASE64` + `CERT_PFX_PIN` in `.env` are for **test keys only**: env is readable via `docker inspect`.
  The PINs match the containers by index, or one PIN applies to all.

A failed install is logged with `certmgr`'s output, with the PIN redacted. The start continues, so a broken PFX
shows up in `docker logs` as `cryptoarm-start: ERROR: installing key container … failed`, and a summary
`WARNING: N certificate/key install(s) failed` follows it. Re-installing on restart succeeds (verified).

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

The API key is passed to curl as a header file (`-H @file`), so it does not appear in `ps`.

Tests (they use fakes, so no Docker is needed): `scripts/test/smoke-server.test.sh` and
`scripts/test/cryptoarm-start.test.sh` (the entrypoint, with fake CSP tools).

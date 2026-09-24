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
- It also splits build and run (D8, see [Build and run](#run)) and binds the compose file to its own image tag
  `…:stand-i6` (F10), so an older image is never run under it.
- Read-only root filesystem with tmpfs for the paths the server writes, and CPU/memory/PID limits (I6, see
  [Container hardening](#container-hardening)).
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
# from the repo root (the root compose file `include`s this one)
scripts/fetch-test-certs.sh                  # upstream test certs → docker/cryptoarm-server/certs (git-ignored)
(umask 077; cp docker/cryptoarm-server/.env.example docker/cryptoarm-server/.env)   # non-secret settings only
(umask 077; printf '%s' '<license key>' > docker/cryptoarm-server/secrets/trusted_license
  openssl rand -hex 24 > docker/cryptoarm-server/secrets/api_keys)
docker compose build cryptoarm-server-image  # build-only service (profile "build"), tags …:stand-i6
docker compose up -d --wait cryptoarm-server # fails unless "healthy"
docker compose ps cryptoarm-server
CRYPTOARM_SERVER_API_KEY="$(head -1 docker/cryptoarm-server/secrets/api_keys)" SMOKE_STRICT=1 scripts/smoke-server.sh
```

Run compose from the repo root. The project name is then the worktree directory name: the shared stand is project
`graph-root`, run from the `graph-root` worktree, with the network `graph-root_default` that the Документы stand
joins. From this directory (or with `-f docker/cryptoarm-server/docker-compose.yml`) the same file is another
project, `kryptoarm-diadoc-cryptoarm-server`, with its own network: `ps` there shows nothing of the shared stand,
and `up` there would hit the fixed container name. Stop with `docker compose stop` (the Документы stand first, see
its README).
Swagger is at http://localhost:3037/docs. The healthcheck calls `GET /health/memory`, which needs no API key.

**Build and run are separate (D8).** `cryptoarm-server` has no `build` section and `pull_policy: never`. The image
comes only from the build-only service `cryptoarm-server-image` (same tag, profile `build`). So `up`, and
`docker compose run --build app` from the root, can never rebuild the server image or recreate the container
because of a new image. `up` on a machine without the image fails with "No such image": build it first. The
container is still recreated when its _config_ changes (another worktree, a changed `.env` or compose file).
Check with `docker compose --dry-run up -d` that it stays `Running`. The image tag is shared by all worktrees:
building `cryptoarm-server-image` with the default tag anywhere else moves `…:stand-i6`, and the next `up` (or `run app`
without `--no-deps`) in `graph-root` recreates the shared stand on that image. Build the default tag only from
`graph-root`, override `CRYPTOARM_SERVER_IMAGE` elsewhere, and keep using `run --rm --no-deps app`.

**The compose file is bound to its image (F10).** Its default tag is `kryptoarm-diadoc/cryptoarm-server:stand-i6`, not
the older shared `…:local` (the I5 image): the I6 file needs the I6 `start.sh` (D40). On a host that has only the
old image, `docker compose up -d` and `docker compose run app …` without `--no-deps` fail with
`No such image: kryptoarm-diadoc/cryptoarm-server:stand-i6`, and the running (or stopped) container is left alone: same
container ID, same start time, no stop event (verified with compose 2.40.3 on a throwaway stand, both on an I6 test
image and on the I5 image under the I5 file; compose looks the image up before it stops the old container). `--dry-run up -d` shows
`Recreate` followed by the same error. The next change of the image contract gets a new tag in the same way
(`scripts/test/stand-rollout.test.sh` pins the current one). `stand-*` tags belong to the shared stand only: name
throwaway images after the task code (`:i5`, `:f10-…`), never `:stand-…`, or the next `up` in `graph-root` runs them.

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
The file may hold one key per line or comma-separated keys. `start.sh` trims the keys and drops empty ones, as the
server does (`dist/config.js`); a key with whitespace inside stops the start (F16).

`AUTH_MODE` (from `.env`) is checked at start, because the server's middleware compares it literally (F16, D160,
verified on a throwaway stand): `apikey` with no key rejects every request (401), and any value other than `none` or
`apikey` (`APIKEY`, an empty `AUTH_MODE=`, a typo) lets every request through without a key, and so does a missing
`AUTH_MODE` (upstream default `?? "none"`). So `apikey` without a key, any other value and a missing variable stop the
start with an error; an explicit `AUTH_MODE=none` starts with a warning.

`cpconfig -license -set` and `tsputil`/`ocsputil license -s` output is logged with the licence value redacted (also
without its dashes: `cpconfig -license -view` prints the serial without them); a rejected licence stops the start
with the tool's exit code. Checked with invalid serials only (the tools do not echo those); a real serial is D42.

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

## Container hardening

The container runs with `read_only: true` (I6). The writable paths below were found with `docker diff` on a
running stand after a smoke run. The tmpfs mounts are empty after every start or restart, and `start.sh` refills them.

| Path                        | Mount                 | Written by                                                                                                                    |
| --------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `/var/opt/cprocsp`          | bind `./cert_storage` | CSP store: keys, `uMy`/`mroot`, locks (unchanged)                                                                             |
| `/etc/opt/cprocsp`          | tmpfs 16 MB           | CSP configuration incl. `license.ini`; `start.sh` seeds it from `/etc/opt/cprocsp_default` (image)                            |
| `/etc/opt/Trusted`          | tmpfs 1 MB, 0700      | `license.lic` from `start.sh`                                                                                                 |
| `/var/lib/cryptoarm-server` | tmpfs 16 MB, 0700     | `cash.json`, the server's PKI store cache. It opens it relative to its working dir `/`, so the image links `/cash.json` there |
| `/tmp`                      | tmpfs 256 MB          | `os.tmpdir()`: temporary PFX files when `/cms/sign` gets a `.pfx` as `cert`                                                   |
| `/var/cache/fontconfig`     | tmpfs 16 MB           | font cache of the PDF reports                                                                                                 |

The tmpfs mounts are `noexec,nosuid,nodev`. Fontconfig also tries to write `.uuid` files into `/usr/share/fonts`;
that fails silently. The PDF report of the Документы smoke still works. The upstream TSL auto-update
(`TSL_AUTO_UPDATE_ENABLED`, off by default) writes into `./certs`, which is mounted read-only: leave it off.

Limits (override them from the shell or in `docker/cryptoarm-server/.env`; compose interpolates the included file with the `.env` of its own directory, and the same file is also the container's `env_file`, see `.env.example`). A value above the CPUs of the Docker VM fails the start ("range of CPUs is from 0.01 to N"): `CRYPTOARM_SERVER_CPUS` (default `2`), `CRYPTOARM_SERVER_MEMORY`
(`2g`), `CRYPTOARM_SERVER_PIDS` (`256`). Measured on the throwaway stand: ~190–320 MiB and 13 PIDs idle, and a 30 MB
payload signs in 1.4 s under these limits. tmpfs contents count towards the memory limit.

The healthcheck also requires `/etc/opt/cprocsp/config64.ini`. With an **image older than I6** under this compose
file, nothing seeds the tmpfs: the API answers, but CSP fails with `Provider DLL failed to initialize correctly
[0x8009001d]` and `/cms/sign` returns "key not found" (verified, D40). The check turns that into `unhealthy`, so
`up --wait` fails instead of reporting a working stand. The other direction is safe: the new image under an older
compose file starts and signs as before (verified).

**Rollout on the shared stand** (I6 + F10). Run it in the `graph-root` worktree **after** F10 is merged there, in a
fresh terminal (no `CRYPTOARM_*` exports left over from a throwaway stand). Order: this server first, then the
Документы stand of project `kryptoarm-diadoc-i2` (its README). The server container is recreated (~10 s until
`healthy` once the image is built), so warn whoever uses the stand. The git-ignored
`docker/cryptoarm-server/{secrets,certs,cert_storage}` of `graph-root` hold the licence, the API key and the keys
(including the I3 key of ООО «О2 ПЛАТФОРМА»): keep them, never `down -v` or `git clean` there. The blocks contain no
`#` comments on purpose: interactive zsh does not treat them as comments unless `interactivecomments` is set.

1. Checks. Expected: the F10 merge (or later); no `CRYPTOARM_` variables; `kryptoarm-diadoc/cryptoarm-server:stand-i6`;
   the image list has `local` (the I5 image) but **no** `stand-i6`. Stop if any of it differs (a `stand-i6` built
   elsewhere would be rolled out by the next `up` without further checks).

   ```sh
   cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
   git log -1 --oneline
   env | grep '^CRYPTOARM_'
   docker compose config --images
   docker image ls kryptoarm-diadoc/cryptoarm-server
   ```

2. Rollback tag (never overwritten on a re-run), build, dry run. Expected: `pre-i6` has the image ID of `local`;
   `stand-i6` is built and `local` did not move; the dry run shows `Recreate` for `kryptoarm-diadoc-cryptoarm-server` only.

   ```sh
   docker image inspect kryptoarm-diadoc/cryptoarm-server:pre-i6 >/dev/null 2>&1 || docker tag kryptoarm-diadoc/cryptoarm-server:local kryptoarm-diadoc/cryptoarm-server:pre-i6
   docker compose build cryptoarm-server-image
   docker image ls kryptoarm-diadoc/cryptoarm-server
   docker compose --dry-run up -d
   ```

3. Roll out and check. Expected: `up` reports `Healthy` (it fails if CSP is broken); `inspect` prints
   `kryptoarm-diadoc/cryptoarm-server:stand-i6 true 2147483648 256`; both smokes end with `smoke: OK`; the integration
   tests pass without skips.

   ```sh
   docker compose up -d --wait cryptoarm-server
   docker inspect -f '{{.Config.Image}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' kryptoarm-diadoc-cryptoarm-server
   K="$(head -1 docker/cryptoarm-server/secrets/api_keys)"
   CRYPTOARM_SERVER_API_KEY="$K" SMOKE_STRICT=1 scripts/smoke-server.sh
   CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer CRYPTOARM_SERVER_API_KEY="$K" SMOKE_STRICT=1 scripts/smoke-server.sh
   CRYPTOARM_SERVER_URL=http://127.0.0.1:3037 CRYPTOARM_SERVER_API_KEY="$K" SIGNER_CERT_PATH=docker/cryptoarm-server/certs/cryptoarm.server.test.cer npm test -- src/signer/server-cms-signer.integration.test.ts src/pipeline/signature-policy.integration.test.ts
   unset K
   ```

Then the Документы stand (its README, "Rollout on the shared stand"). It finds the new server container by name on
the network `graph-root_default`, which survives the server's recreation (a Документы stand still on the old file
kept signing, verified). `cert_storage` is a bind mount and is kept.

Until F10 is merged into them, worktrees branched from `graph-root` between F9 and F10 still carry the I6 file with
the old default `…:local`: do not build or start the server stand from them (a `build cryptoarm-server-image` there
moves `…:local`; the rollback below re-tags it from `…:pre-i6`).

Rehearsed end to end on throwaway stands (F10, 2026-09-24): an I5 stand (the I5 image under the I5 file, with a
freshly issued О2 key) and a pre-I6 Документы stand, both smoke-tested; then, with the F10 files, `up -d` and
`run app` before the build failed with "No such image" and left the container untouched; then the steps above
(with throwaway tags), both smokes with both certificates, the three signer integration tests (13 passed), the
Документы rollout with both users (DB, users and documents kept), the rollback below, and `down -v` (the throwaway
image tags `…:f10-*` stay on the host until removed by hand).

**Rollback** (server): back to the pre-I6 file, which runs `…:local` (the I5 image, untouched by the `…:stand-i6`
build). The `[ … ] ||` line re-tags `…:local` from `…:pre-i6` only if `…:local` moved. `56d7226` is `graph-root`
before I6 (F9). Commit the restored file, so that the next `up` does not re-apply it. The restored file fails
`scripts/test/stand-rollout.test.sh` and `stand-hardening.test.sh` in `graph-root`; for a lasting rollback revert
the F9 and F10 merges instead (`git revert -m 1 <merge>`), which restores file and tests together.

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
git checkout 56d7226 -- docker/cryptoarm-server/docker-compose.yml
[ "$(docker image inspect -f '{{.Id}}' kryptoarm-diadoc/cryptoarm-server:local)" = "$(docker image inspect -f '{{.Id}}' kryptoarm-diadoc/cryptoarm-server:pre-i6)" ] || docker tag kryptoarm-diadoc/cryptoarm-server:pre-i6 kryptoarm-diadoc/cryptoarm-server:local
docker compose up -d --wait cryptoarm-server
git commit -m "Roll back the server compose file to pre-I6" docker/cryptoarm-server/docker-compose.yml
```

The I6 image also works under the old file (verified), but never run the old image with the I6 file (D40): with F10
that needs an explicit `CRYPTOARM_SERVER_IMAGE=…:local`, so do not set it.

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
   The issuer comes from the certificate's AIA URL (http/https only). It is trusted only if it is self-signed, its
   subject equals the certificate's issuer, and its SHA-256 is in `scripts/test-ca-roots.sha256` (F16; the
   same allowlist `fetch-test-certs.sh` checks its download against). The GOST signature is not checked on the host, which has no GOST
   provider. The CA issues at once, with no manual approval. `https://` fails
   with an untrusted TLS chain, so the script uses `http://`, the same scheme as the AIA/CRL URLs in the certificates.
3. `certmgr -inst -store mroot` installs the issuer. `certmgr -inst -store uMy -cont … -at_signature -to-container`
   binds the certificate to the key. Without `-at_signature`, certmgr looks for an exchange key and fails with
   `0x8009000d Key does not exist`.
4. Only public certificates are written on the host: `certs/o2-platforma.test.cer` and
   `certs/root/cryptopro-test-ca-2012-<N>.cer`. Both are git-ignored.

The script refuses to run if the key container already exists, if `csptest -enum_cont` fails (a failed listing
must not read as "not found", R2 M3), or if another run holds the same name (lock directory
`/tmp/<KEY_CONTAINER>.lock` in the container, taken before the listing and removed on exit; `/tmp` is a tmpfs, so a
lock left by `kill -9` disappears with a restart), so it never deletes a key it did not create. If a
step fails before the certificate is bound, the new key container is deleted again, and a keygen still running in
the container is killed first. An issuer that was already installed into `mroot` stays there.

```sh
docker compose ps cryptoarm-server          # from the root of the worktree that runs the stand: must be healthy
scripts/issue-test-cert.sh                                           # ~1 min under amd64 emulation
CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer SMOKE_STRICT=1 \
  CRYPTOARM_SERVER_API_KEY=<key> scripts/smoke-server.sh
```

Env: `CRYPTOARM_CONTAINER`, `TEST_CA_URL`, `CERTS_DIR` (for example, the certs dir of the worktree the stand
runs from), `CERT_NAME`, `KEY_CONTAINER` (must not exist yet), `KEYGEN_TIMEOUT` (default 300 s), `TEST_CA_ROOTS_FILE`
(default `scripts/test-ca-roots.sha256`), and the subject values `ORG_*` / `SIGNER_*` (see the script header). The
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
  about every 3 months. After it does, check the new root out of band and add its SHA-256 to
  `scripts/test-ca-roots.sha256` (until then the script refuses it), then re-run the script: it picks up the new issuer
  from AIA, installs it into `mroot` and stores it under `certs/root/`. `scripts/fetch-test-certs.sh` hardcodes the
  renewal-21 URL and file name (its hash comes from the same allowlist), so it must be updated then too.
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

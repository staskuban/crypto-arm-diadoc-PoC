# КриптоАРМ Документы stand

The КриптоАРМ Документы API (`registry.digtlab.ru/trusted/cryptoarm/documents/api:1.0.209`, pinned by digest; the API reports itself as 1.0.211) with PostgreSQL and a CA stub. It runs as its own compose project and signs through an **already running** КриптоАРМ Server stand (`docker/cryptoarm-server`). It does not build, start or recreate that stand. It only joins the stand's network.

```
host 127.0.0.1:3040 ─► documents-api ──► documents-db (postgres 14.4, volume documents-db)
                          │  │
                          │  └─► ca-stub:8080 (nginx): e-mail -> public .cer from SIGNER_CERTS_DIR
                          └────► $SIGN_SERVICE_URL /cms/sign, /cms/verify (network $SIGN_SERVICE_NETWORK)
```

No web UI (`documents/app`) and no OIDC IdP. The stand uses local login only (`OAUTH2_ENABLED=false`, `POST /api/v1/login`).

## Run

Prerequisites:

- The КриптоАРМ Server stand is running and healthy. The shared one is container `kryptoarm-diadoc-cryptoarm-server` in network `graph-root_default`.
- The Документы licence key is in a file. The default is `docker/cryptoarm-server/secrets/documents_license_value`, git-ignored. Without it the API does not start.
- The public certificates named in `ca-stub/nginx.conf` are in `SIGNER_CERTS_DIR` (default `../cryptoarm-server/certs`, git-ignored). They must be the certificates whose keys are in the running server's `uMy`. In a fresh worktree, copy the `.cer` files from the worktree that runs the stand.

```sh
# once: licence + server API key copied, the rest generated (never printed; existing files are kept)
SIGN_SERVICE_API_KEYS_FILE=<stand worktree>/docker/cryptoarm-server/secrets/api_keys scripts/documents-secrets.sh
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml up -d --wait
scripts/smoke-documents.sh                                             # as the admin -> cryptoarm.server.test.cer
DOCUMENTS_SIGNER_EMAIL=o2-platforma@documents.local \
  CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer \
  DATA_FILE=src/utd/fixtures/<ИдФайл>.xml scripts/smoke-documents.sh   # as a second user -> o2-platforma.test.cer
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml stop     # or: down [-v]
```

The first start takes about 20 s under amd64 emulation on Apple Silicon. `--wait` returns once `/api/v1/ready` answers 200. Overrides go in `docker/cryptoarm-documents/.env`, see `.env.example`: port, server network/URL, certificate dir, admin login/e-mail. To run a second stand, use another `-p`, another `DOCUMENTS_API_PORT` and another `secrets/` copy.

Secrets are files in `./secrets`, mounted read-only at `/run/secrets`. `start.sh` exports them to the API process only, so they are not in `docker inspect`. It also builds `DB_URI` from `postgres_password`. `scripts/test/documents-stand.test.sh` covers `start.sh` and `documents-secrets.sh`. `scripts/test/smoke-documents.test.sh` covers the smoke script against a fake API.

### Caveats

- **Always pass `-p kryptoarm-diadoc-i2`** (or your own name) — without it compose uses the file's `name:` and creates a second project with its own volumes that collides on port 3040.
- **The stands are coupled through the network.** `documents-api` is attached to the server stand's network (`graph-root_default`): while it exists, `docker compose down` of the server stand cannot remove that network ("Resource is still in use"); if the network is recreated, `documents-api` cannot start (not even via `restart`) until this project's `up` runs again. Stop this stand before tearing down the server stand.
- **Licence location.** `documents-secrets.sh` reads the licence from `docker/cryptoarm-server/secrets/documents_license_value` by default. That directory is mounted into the КриптоАРМ Server container, which does not need the licence: on the worktree that runs the server stand keep it elsewhere (`DOCUMENTS_LICENSE_FILE=…`) or delete the source after copying — the copy in `docker/cryptoarm-documents/secrets/license_value` is what the stand uses.
- **Server API key is required.** Pass the `api_keys` of the worktree that runs the server (`SIGN_SERVICE_API_KEYS_FILE`); without it the script stops (`SIGN_SERVICE_API_KEY_OPTIONAL=1` only for `AUTH_MODE=none`), otherwise `cloud-sign` would fail with 401 at run time.
- **Linux hosts (unverified).** Secrets are 0600 files of the host user; checked on Docker Desktop only. On Linux, postgres reads `POSTGRES_PASSWORD_FILE` as uid 999 and the API runs with `cap_drop: [ALL]` (no `DAC_OVERRIDE`), so the files need matching ownership/permissions (same caveat as the server stand, I5).
- `ca-stub` mounts the whole `SIGNER_CERTS_DIR` (the server's `certs/` includes `user/` for PIN-less PFX) but serves only the mapped `.cer` files; point `SIGNER_CERTS_DIR` at a directory with only the `.cer` files if `certs/user` holds real keys. `postgres`/`nginx` images are pinned by tag only.
- `smoke-documents.sh` with `DOCUMENTS_SIGNER_EMAIL` resets that user's password on every run (`PUT /api/v1/users/{id} {password}` keeps login and e-mail — verified): test stands only.

## How `cloud-sign` picks the key

`POST /api/v1/signatures/cloud-sign/{documentId}` (body `{ "pin"?: string }`) takes the **e-mail of the logged-in user**. It then calls `GET {CA_API_URI}/cert/{email}?format=pfx`, with header `x-api-key: $CA_API_TOKEN` when set. The response body becomes the `cert` of `POST {SIGN_SERVICE_URL}/cms/sign`. For `application/json` the API reads the field `pfx`, `cert` or `data`; otherwise it base64-encodes the raw body. `pin` goes as `password`. The request sets neither `detached` nor `cadesStandard`, so the server defaults apply: detached `CAdES-BES`. The API key for the server is `SIGN_SERVICE_API_KEY`. The profile flag `corpCloudCertAvailable` comes from `GET {CA_API_URI}/cert/{email}/exists`, which must return `{exists, has_pfx, has_private_key}` all true.

There is no other setting and no per-request choice. Upstream expects a CA service that holds a **PFX per user**. This stand replaces it with `ca-stub` (nginx). The stub maps an e-mail to a **public `.cer`** file. КриптоАРМ Server then finds the key already installed in `uMy` by thumbprint, so no private key leaves the server. The mapping in `ca-stub/nginx.conf` is the key selection:

| Documents user (e-mail)                              | Certificate                  | Thumbprint (SHA-1) |
| ---------------------------------------------------- | ---------------------------- | ------------------ |
| `server-test@documents.local` (admin, `ADMIN_EMAIL`) | `cryptoarm.server.test.cer`  | `0e84b59e…3f1f`    |
| `o2-platforma@documents.local`                       | `o2-platforma.test.cer` (I3) | `9fe820c0…4037`    |

A user with an unmapped e-mail gets `400 "Не удалось получить корпоративный сертификат пользователя"`. The admin's e-mail is set only when the admin is created, on an empty DB. After a change, `down -v` or edit the user. Local login uses the user's `login`, not the e-mail. `smoke-documents.sh` creates signer users with `login` = e-mail.

## Findings on this version (verified on the stand, 2026-09-24)

- **Auth.** The global `X-API-KEY` is rejected in every case: `401 "API Key is wrong"`. The code is commented out. What works: the session cookie from `POST /api/v1/login`, and `Authorization: Bearer <jwt>` from `GET /api/v1/auth/jwt?expiresIn=` (15m…90d, for the current user). The API accepts **any** HS256 token signed with `MAIL_LINK_TOKEN_SECRET`, whatever e-mail it carries. An unknown e-mail is registered on the fly (`ALLOW_REGISTRATION` defaults to true). So this secret lets its holder act, and cloud-sign, as any mapped e-mail. It must be random: the image default is `change-me`. `documents-secrets.sh` generates it.
- **No access check on `cloud-sign`.** A user whose `GET /api/v1/documents/35` answers `403` could still cloud-sign document 35 with their own certificate. `SIGN_METHOD_CORP_CLOUD=false` only hides the method in `/api/v1/profile`: the endpoint still signs. What actually limits it: an authenticated user and a certificate for their e-mail in the CA API.
- **One signature per user and document.** A second `cloud-sign` returns `400 "Повторная подпись документа этим пользователем запрещена"`. To re-sign, upload the document again.
- **Signature format.** `cloud-sign` returns `signature` (base64). `POST /api/v1/documents/{id}/signature {signatureId, attached:false}` returns the same bytes (`Content-Type: documents/signatures`, file `<name>.sig`). This is the server's raw CMS: **BER with indefinite lengths** (`30 80`), detached. A Диадок client must normalise it to DER (`src/asn1`), as `ServerCmsSigner` does.
- **Verification.** `POST /api/v1/documents/{id}/verify` returns a **PDF** report, not JSON. The verification result (`/cms/verify` of the server, run when the signature is stored, `VERIFY_SIGNATURE_AFTER_RECEIVE`) is the signature's `meta`: `signValid`, `signers[].certificate.thumbprint`, `isCertChainValid`, `isDetached`, `cadesTypeName`. Read it with `GET /api/v1/signatures?filter={"documentId":<id>}`. `GET /api/v1/signatures/{id}` does not exist (404). If this check fails, the signature is deleted and `cloud-sign` fails.
- **Bytes.** An upload keeps the bytes exactly: `GET /api/v1/documents/{id}/download` is identical, checked with a windows-1251 УПД. The multipart `Content-Type` must match `ALLOWED_FILE_TYPES`. The upstream default has no `xml`; this stand adds it.
- **Licences.** `availableSignatureLicenses` stayed at 10 after cloud-signs by two users. In this version, `cloud-sign` does not use up the Документы signature licences.
- **One unexplained hang.** Once, after `verify` plus a request to a missing route, the API sat at ~120 % CPU and answered nothing, `/ready` included, until `docker restart`. It did not come back in later runs. The healthcheck marks such a container `unhealthy`, but `restart: unless-stopped` does not restart it.

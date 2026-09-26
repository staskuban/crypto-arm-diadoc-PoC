# КриптоАРМ Документы stand

The КриптоАРМ Документы API (`registry.digtlab.ru/trusted/cryptoarm/documents/api:1.0.209`, pinned by digest; the API reports itself as 1.0.211) with PostgreSQL and a CA stub. It runs as its own compose project and signs through an **already running** КриптоАРМ Server stand (`docker/cryptoarm-server`). It does not build, start or recreate that stand. It only joins the stand's network.

```
host 127.0.0.1:3041 ─► documents-app (nginx: SPA + /api proxy) ─┐
host 127.0.0.1:3040 ──────────────────────────────────────────► documents-api ──► documents-db (postgres 14.4, volume documents-db)
                                                                  │  │
                                                                  │  └─► ca-stub:8080 (nginx): e-mail -> public .cer from SIGNER_CERTS_DIR
                                                                  └────► $SIGN_SERVICE_URL /cms/sign, /cms/verify (network $SIGN_SERVICE_NETWORK)
```

No OIDC IdP. The stand uses local login only (`OAUTH2_ENABLED=false`, `POST /api/v1/login`), in the web UI too (I7, see [Web UI](#web-ui)).

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
open http://127.0.0.1:3041/                                            # web UI: log in as admin (secrets/admin_password)
DOCUMENTS_SIGNER_EMAIL=o2-platforma@documents.local \
  CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer \
  DATA_FILE=src/utd/fixtures/<ИдФайл>.xml scripts/smoke-documents.sh   # as a second user -> o2-platforma.test.cer
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml stop     # or: down [-v]
```

The first start takes about 20 s under amd64 emulation on Apple Silicon. `--wait` returns once `/api/v1/ready` answers 200. Overrides go in `docker/cryptoarm-documents/.env`, see `.env.example`: ports (`DOCUMENTS_API_PORT`, `DOCUMENTS_APP_PORT`), server network/URL, certificate dir, admin login/e-mail. To run a second stand, use another `-p`, another `DOCUMENTS_API_PORT` and `DOCUMENTS_APP_PORT`, and another `secrets/` copy (with its own `session_secret` if you log in with a browser, D231).

Secrets are files in `./secrets`, mounted read-only at `/run/secrets`. `start.sh` exports them to the API process only, so they are not in `docker inspect`. It also builds `DB_URI` from `postgres_password`. `scripts/test/documents-stand.test.sh` covers `start.sh` and `documents-secrets.sh`. `scripts/test/smoke-documents.test.sh` covers the smoke script against a fake API.

### Caveats

- **Always pass `-p kryptoarm-diadoc-i2`** (or your own name) — without it compose uses the file's `name:` and creates a second project with its own volumes that collides on port 3040.
- **The stands are coupled through the network.** `documents-api` is attached to the server stand's network (`graph-root_default`): while it exists, `docker compose down` of the server stand cannot remove that network ("Resource is still in use"); if the network is recreated, `documents-api` cannot start (not even via `restart`) until this project's `up` runs again. Stop this stand before tearing down the server stand.
- **Licence location.** `documents-secrets.sh` reads the licence from `docker/cryptoarm-server/secrets/documents_license_value` by default. That directory is mounted into the КриптоАРМ Server container, which does not need the licence: on the worktree that runs the server stand keep it elsewhere (`DOCUMENTS_LICENSE_FILE=…`) or delete the source after copying — the copy in `docker/cryptoarm-documents/secrets/license_value` is what the stand uses.
- **Server API key is required.** Pass the `api_keys` of the worktree that runs the server (`SIGN_SERVICE_API_KEYS_FILE`); without it the script stops (`SIGN_SERVICE_API_KEY_OPTIONAL=1` only for `AUTH_MODE=none`), otherwise `cloud-sign` would fail with 401 at run time.
- **Linux hosts (unverified).** Secrets are 0600 files of the host user; checked on Docker Desktop only (it shows a bind-mounted file as owned by whichever uid reads it). On Linux, postgres reads `POSTGRES_PASSWORD_FILE` as uid 999, `ca-stub` reads the `.cer` files as uid 101 (F17), and the API runs with `cap_drop: [ALL]` (no `DAC_OVERRIDE`), so the files need matching ownership/permissions (same caveat as the server stand, I5).
- `ca-stub` mounts the whole `SIGNER_CERTS_DIR` (the server's `certs/` includes `user/` for PIN-less PFX) but serves only the mapped `.cer` files; point `SIGNER_CERTS_DIR` at a directory with only the `.cer` files if `certs/user` holds real keys.
- `smoke-documents.sh` with `DOCUMENTS_SIGNER_EMAIL` resets that user's password on every run (`PUT /api/v1/users/{id} {password}` keeps login and e-mail — verified): test stands only. It refuses the admin's own e-mail (the found user's id equals the `userId` of the admin login; F16, checked against the shared stand with `server-test@documents.local`), since the new password is never saved.
- `documents-secrets.sh` picks the first server API key as `start.sh` reads the list (split on newlines and commas, trimmed, empty ones skipped, a key with inner whitespace refused) and removes its temp file when a write fails or it is interrupted.

## Web UI

`documents-app` (I7) is the upstream SPA image `registry.digtlab.ru/trusted/cryptoarm/documents/app:1.0.209` (the same version as the API; pinned by digest, anonymous pull, amd64 only). It is plain nginx (alpine) with the built React-admin bundle in `/usr/share/nginx/html`. Its entrypoint is `nginx -g 'daemon off;'` without the nginx image's `docker-entrypoint.sh`, so there is **no runtime configuration** (no env, no templates): the only setting is the nginx config, `app/nginx.conf` mounted over `conf.d/default.conf`.

How it talks to the API (read from the bundle and the API sources in the images; upstream `docker/docker-compose.yaml` + `docker/nginx.conf`, commit `b167d46a`):

- The SPA calls **relative** URLs (`/api/profile`, `/api/login`, `/api/documents…`) with `credentials: 'include'`; no API base URL is built in. So the UI and the API must share **one origin**: `app/nginx.conf` proxies `^/(api|.well-known|openapi.json|llms.txt)` to `documents-api:3000` (as upstream does) and serves everything else as the SPA. No CORS is involved.
- Login: with `OAUTH2_ENABLED=false`, `GET /api/login` (where `index.html` sends a user without a session) redirects to `/#/localLogin`; the form posts `{username, password}` to `POST /api/login` and gets the `cookie-session` cookie (`HttpOnly`, not `Secure`, so plain `http://127.0.0.1` works). Log in as `admin` (`DOCUMENTS_ADMIN_LOGIN`) with `secrets/admin_password`, or as any local user (the login, not the e-mail). The first page after login is «Подпись и шифрование» (desktop КриптоАРМ, not usable here); «Документы» lists the documents, a document's «Подписи» tab its signatures (a green tick = the stored `meta.signValid`).
- The browser also loads Google Fonts and links `https://sign.kloud.one/diagnostic/` (workplace check for the desktop methods); nothing else leaves the host. `app/nginx.conf` drops upstream's `/diagnostic` redirect.
- The API image could serve the SPA itself from `./public` (`setupPublicStatic` in `main.ts`), but ships none; the stand keeps the upstream split (two images, same tag).

Differences from upstream `docker/nginx.conf`: port 8080 as uid 101 (like `ca-stub`); `client_max_body_size 51m` instead of `12m` (upstream cuts uploads of 12–50 MB with nginx's 413; now the API decides at `MAX_FILE_SIZE=50`: 52 428 800 B → its `413 "File too large"`, one byte less → 201, verified); `proxy_request_buffering off` + `proxy_max_temp_file_size 0`, because with a read-only root and a 16 MB tmpfs a buffered 40 MB upload failed with nginx `500` (`pwrite() … No space left on device`, D230) — now 40 MB go up (also with `Transfer-Encoding: chunked`, which needs `proxy_http_version 1.1`: with HTTP/1.0 to the upstream nginx buffers a chunked body in full) and download byte-identical through the UI port; `Host $http_host` (keeps the port: `proxy_redirect` does not rewrite `Location` when `proxy_pass` is a variable); `X-Forwarded-For $remote_addr` (not the client's header); default header buffers (upstream's 512k per connection are for OIDC cookies and would let ~100 connections exhaust the 64m limit); the API paths are anchored (`/api`, `/api/…`, not `/apifoo`); `index.html` is served with `Cache-Control: no-cache`; the API name is re-resolved via Docker DNS (`resolver 127.0.0.11`), so a recreated `documents-api` with a new IP is reached without restarting the UI (verified by moving the API to a new IP on the throwaway stand); `proxy_read_timeout 180s` for `cloud-sign`.

Security: the UI port is loopback-only like the API port, and exposes the same API (it is the same login). Session cookies are scoped to the host, **not the port**: in one browser, a stand on `127.0.0.1:3041` and another on `127.0.0.1:3051` see each other's cookie, and a stand whose `secrets/` are a copy (same `session_secret`) accepts it — a throwaway admin session is then an admin session on the shared stand (D231). Give a throwaway stand its own `session_secret` (`openssl rand -hex 32 > secrets/session_secret`, then restart `documents-api`) or use a separate browser profile. The API sets its cookies (`session`, `session.sig`) `HttpOnly` but without `SameSite` and with `expires=Invalid Date` (unset `SESSION_EXPIRES`, so a browser-session cookie); the UI port adds `SameSite=Strict` (`proxy_cookie_flags`), the API port 3040 is unchanged. The UI adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: same-origin` and hides the nginx version; `server_name _` accepts any `Host` (DNS rebinding is limited by the loopback bind and `SameSite`, not excluded). `documents-app` shares the project network with `documents-db` and `ca-stub` (a separate app↔API network would add a network to the shared project; not done). Checked in the browser: the document viewer («Просмотреть») still opens (XML has no preview in this version), no console errors.

## Container hardening

All four containers run with `read_only: true` and CPU/memory/PID limits (I6). The writable paths were found with
`docker diff` on a running stand after a smoke run.

All four also run with `cap_drop: [ALL]`, no `cap_add` and `no-new-privileges` (API since I2, `ca-stub` and
`documents-db` since F17, `documents-app` since I7), and every image is pinned by tag + index digest (`postgres:14.4@sha256:9ceb24f8…`,
`nginx:1.27-alpine@sha256:65645c7b…`, the same images the I2 stand pulled; bump tag and digest together).
`postgres` and `nginx` start as root only to drop to their own user (`gosu postgres`, nginx workers as `nginx`),
which needs `SETUID`/`SETGID` (and `CHOWN`/`FOWNER` for the entrypoint's `chown`/`chmod` of `PGDATA`; read from the entrypoints, not measured). F17 runs them
as that user from the start instead — `documents-db` as `999:999`, `ca-stub` as `101:101` — so they need no
capability at all: the postgres entrypoint skips its root-only steps (the data volume is already owned by 999:
initdb always ran as `postgres`), nginx binds 8080 without privilege, and the `ca-stub` tmpfs mounts are owned by 101. Verified on a throwaway stand (F17): an existing DB volume created under the old file opens unchanged
(document ids went on counting), a fresh volume initialises, both smokes sign, and the old file runs again on the
new volume. `ca-stub` then logs `the "user" directive makes sense only if the master process runs with super-user
privileges, ignored`: expected.

| Service         | Writable                                                                                  | Limits (env override, default)                                                             |
| --------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `documents-api` | volumes `documents-uploads` (`/uploads`), `documents-logs` (`/logs`); tmpfs `/tmp` 128 MB | `DOCUMENTS_API_CPUS` 1, `DOCUMENTS_API_MEMORY` 1g, `DOCUMENTS_API_PIDS` 256                |
| `documents-db`  | volume `documents-db`; tmpfs `/run/postgresql` (socket, lock), `/tmp`                     | `DOCUMENTS_DB_CPUS` 1, `DOCUMENTS_DB_MEMORY` 512m, `DOCUMENTS_DB_PIDS` 128                 |
| `ca-stub`       | tmpfs `/var/cache/nginx`, `/run` (`nginx.pid`)                                            | `DOCUMENTS_CA_STUB_CPUS` 0.25, `DOCUMENTS_CA_STUB_MEMORY` 64m, `DOCUMENTS_CA_STUB_PIDS` 32 |
| `documents-app` | tmpfs `/var/cache/nginx` 16 MB (no proxy temp files, D230), `/run` (`nginx.pid`)          | `DOCUMENTS_APP_CPUS` 0.25, `DOCUMENTS_APP_MEMORY` 64m, `DOCUMENTS_APP_PIDS` 32             |

Measured on the throwaway stand: API ~120–170 MiB, 12 PIDs; db ~30 MiB; ca-stub ~7 MiB, 9 PIDs; app ~22 MiB, 9 PIDs (nginx starts one
worker per host CPU, so on a host with more than ~30 CPUs raise `DOCUMENTS_CA_STUB_PIDS` and `DOCUMENTS_APP_PIDS`). `documents-app` runs as `101:101` (the image's `nginx` user) and logs the same expected `"user" directive … ignored` warning as `ca-stub`; `docker diff` of it after uploads is empty. A `*_CPUS` value above the CPUs of the Docker VM fails the start. The tmpfs `/run/postgresql` is owned by uid/gid 999 (Debian `postgres` image); an alpine image (uid 70) needs another value.

**No pm2 (D41).** Upstream runs `pm2-runtime ecosystem.config.js`: one fork-mode instance of `dist/main.js`, with
copies of its output in `/logs/app-out.log` / `app-err.log`. pm2 keeps its pids, sockets and the `pm2-logrotate`
module from the image in `/root/.pm2`. A tmpfs there would hide the module; a writable volume would keep a stale copy
across image upgrades. So the stand runs `node dist/main.js` directly. The app log goes to stdout (`docker logs`),
and a crash restarts the container (`restart: unless-stopped`) instead of pm2 restarting the process. The app's own
winston files (`/logs/application-<date>.log`, 20 MB × 14 days) go to the `documents-logs` volume. `docker stop` takes ~1 s.
`nginx`'s entrypoint logs `can not modify /etc/nginx/conf.d/default.conf (read-only file system?)`: expected, the
config is mounted read-only anyway.

**Rollout on the shared stand** (I6). Run it in the `graph-root` worktree after F10 is merged there, **after** the
server rollout in `docker/cryptoarm-server/README.md` (that order is the documented one; the stand itself kept
signing across the server's recreation). Project `kryptoarm-diadoc-i2`: all three containers are recreated and the
API is down for ~20–30 s. The git-ignored `docker/cryptoarm-documents/secrets` of `graph-root` (licence, DB and
admin passwords, server API key) must be kept: the DB volume only opens with that `postgres_password`. Never `down -v`
this project: it deletes users, documents and signatures. No `#` comments in the block (interactive zsh).

Expected: `ps` shows the server `healthy`; the `docker cp` of the old logs (optional, outside the repo: they live in
the old container layer) succeeds or is skipped; the dry run shows 3 × `Recreate`; `up` reports 3 × `Healthy`;
`inspect` prints `true` for all three; both smokes end with `OK`; the integration test passes without skips.

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
docker compose ps cryptoarm-server
docker cp kryptoarm-diadoc-i2-documents-api-1:/logs ~/documents-logs-pre-i6
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml --dry-run up -d
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml up -d --wait
docker inspect -f '{{.Name}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Memory}}' $(docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml ps -q)
scripts/smoke-documents.sh
DOCUMENTS_SIGNER_EMAIL=o2-platforma@documents.local CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer DATA_FILE="$(ls src/utd/fixtures/*.xml | head -1)" scripts/smoke-documents.sh
CRYPTOARM_SERVER_URL=http://127.0.0.1:3037 CRYPTOARM_SERVER_API_KEY="$(head -1 docker/cryptoarm-server/secrets/api_keys)" SIGNER_CERT_PATH=docker/cryptoarm-server/certs/cryptoarm.server.test.cer DOCUMENTS_URL=http://127.0.0.1:3040 DOCUMENTS_LOGIN=admin DOCUMENTS_PASSWORD_FILE=docker/cryptoarm-documents/secrets/admin_password npm test -- src/signer/documents-cloud-signer.integration.test.ts
```

The volumes `documents-db` and `documents-uploads` are kept, and so are users, documents and signatures (the
document ids went on counting on the throwaway rehearsal, F10). The compose file runs neither `build` nor `pull` for
the API: its image is pinned by digest and already present.

**Rollback:** `git checkout 56d7226 -- docker/cryptoarm-documents/docker-compose.yml` (graph-root before I6), then
the same `up -d --wait`; commit the restored file (or revert the merge) in `graph-root`. The images do not change, so
there is no image to restore. The unused volume `kryptoarm-diadoc-i2_documents-logs` can be removed with
`docker volume rm`.

**Rollout on the shared stand** (F17: capability drop, own users, digests for `ca-stub` and `documents-db`). Run it
in the `graph-root` worktree after F17 is merged there, in a fresh terminal (no `DOCUMENTS_*` exports from a
throwaway stand). Only `ca-stub` and `documents-db` are recreated; `documents-api` keeps running and reconnects to the
DB (verified on the throwaway rehearsal): `cloud-sign` and every DB request fail for the ~5–10 s the DB needs to
come back, so warn whoever uses the stand. The images do not change (same content, now referenced by digest; both are
present locally, nothing is pulled). Keep the git-ignored `docker/cryptoarm-documents/secrets` and never `down -v`.
No `#` comments in the block (interactive zsh).

Expected: `git log` prints the F17 merge; the `.env` check prints `no-image-overrides` (an old `DOCUMENTS_DB_IMAGE`/`DOCUMENTS_CA_STUB_IMAGE` line there bypasses the digests: remove it first); the dry run shows `Recreate` for `ca-stub` and `documents-db` and `Running` for `documents-api`; `up`
reports 3 × `Healthy`; `inspect` prints `true [ALL] [no-new-privileges:true]` for all three, with `101:101` for
`ca-stub`, `999:999` for `documents-db` and an empty user for the API (the image runs as root, verified), and every image with `@sha256:`; the log check prints `db-clean` (a `FATAL:  the database system is starting up` from the API reconnecting during the restart is expected); both smokes end with `OK` and the document
id continues the old count.

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
git log --oneline -1 --merges --grep '^Merge F17-container-hardening-3 into graph-root$'
grep -n '_IMAGE' docker/cryptoarm-documents/.env || echo no-image-overrides
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml --dry-run up -d
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml up -d --wait
docker inspect -f '{{.Name}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.User}} {{.Config.Image}}' $(docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml ps -q)
docker logs --since 2m kryptoarm-diadoc-i2-documents-db-1 2>&1 | grep -iE 'permission denied|could not|panic' || echo db-clean
scripts/smoke-documents.sh
DOCUMENTS_SIGNER_EMAIL=o2-platforma@documents.local CERT_FILE=docker/cryptoarm-server/certs/o2-platforma.test.cer DATA_FILE="$(ls src/utd/fixtures/*.xml | head -1)" scripts/smoke-documents.sh
```

**Rollback (F17):** restore the file of the commit before the F17 merge and run the same `up -d --wait` (again only
`ca-stub` and `documents-db` are recreated; the old file on a volume used under F17 was verified on the throwaway
stand), then commit the restored file in `graph-root`. This restores the whole file as it was before the merge, so it also drops later changes to it; if there are any, use `git revert -m 1 <F17 merge>` instead:

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
git checkout "$(git log --format=%H -1 --merges --grep '^Merge F17-container-hardening-3 into graph-root$')^1" -- docker/cryptoarm-documents/docker-compose.yml
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml up -d --wait
scripts/smoke-documents.sh
```

**Rollout on the shared stand** (I7: web UI). Run it in the `graph-root` worktree after I7 is merged there, in a
fresh terminal (no `DOCUMENTS_*` exports from a throwaway stand). Only `documents-app` is created; `documents-api`,
`documents-db` and `ca-stub` stay as they are (same container IDs, verified on the throwaway rehearsal: old file
up + smoke, new file dry run and `up`, UI login with `secrets/admin_password` and the signed document visible). If
the stand is stopped (it was on 2026-09-26), `up` also starts the three existing containers (`Starting` instead of
`Running` in the dry run), nothing is recreated. Port 3041 must be free. Keep the git-ignored
`docker/cryptoarm-documents/secrets` and never `down -v`. No `#` comments in the block (interactive zsh).

**Stop** if the dry run shows `Recreate` for `documents-api`, `documents-db` or `ca-stub` (a local change of the file or `.env`): do not run `up`, find the drift first. Expected: `git log` prints the I7 merge; the `.env` check prints `no-overrides` (or only `DOCUMENTS_APP_PORT=3041`; an `_IMAGE` line bypasses the digests: remove it first); the port check prints `3041-free`;
the pull ends with the digest `sha256:3ddfa544…`; the dry run shows `Running` (or `Starting`) for the three
existing services and `Created`/`Started` only for `documents-app`; `up` reports 4 × `Healthy`; `inspect` prints
`true [ALL] [no-new-privileges:true] 101:101` and the image with `@sha256:`; the curls print `302
http://127.0.0.1:3041/#/localLogin` and `200`; the smoke ends with `OK`. Then open `http://127.0.0.1:3041/`, log
in as `admin` with `secrets/admin_password`, and check that «Документы» lists the smoke's document with one valid
signature in its «Подписи» tab.

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
git log --oneline -1 --merges --grep '^Merge I7-documents-ui into graph-root$'
grep -nE '_IMAGE|DOCUMENTS_APP_' docker/cryptoarm-documents/.env || echo no-overrides
nc -z 127.0.0.1 3041 && echo 3041-busy || echo 3041-free
docker pull --platform linux/amd64 registry.digtlab.ru/trusted/cryptoarm/documents/app:1.0.209@sha256:3ddfa544626e13206b4b03a2ca2b168dce6a8f1dff98296a00a71ad6abf2696f
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml --dry-run up -d
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml up -d --wait
docker inspect -f '{{.Name}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.User}} {{.Config.Image}}' $(docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml ps -q documents-app)
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://127.0.0.1:3041/api/login
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3041/api/v1/ready
scripts/smoke-documents.sh
```

**Rollback (I7):** remove the UI container **first** (with the old file, compose would only warn about an orphan and
leave it running), then revert the merge. The revert undoes the whole merge in `graph-root` (also `CLAUDE.md`,
`docs/plan.md` and this README), and re-merging I7 later applies nothing: revert the revert instead. If `graph-root`
changed the same files after I7, the revert stops on a conflict with the UI container already removed: resolve it or
`git revert --abort` and bring the UI back with `up -d --wait`. Then check that the dry run shows the three services `Running` and no
`documents-app` (verified on the throwaway stand: same container IDs, smoke `OK`). The pulled image can stay.

```sh
cd /Users/stassidoryuk/orca/workspaces/kryptoarm-plus-diadoc/graph-root
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml rm -s -f documents-app
git revert --no-edit -m 1 "$(git log --format=%H -1 --merges --grep '^Merge I7-documents-ui into graph-root$')"
docker compose -p kryptoarm-diadoc-i2 -f docker/cryptoarm-documents/docker-compose.yml --dry-run up -d
scripts/smoke-documents.sh
```

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

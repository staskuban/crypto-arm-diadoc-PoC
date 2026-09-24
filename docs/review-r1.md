# R1 — holistic review of graph-root (2026-09-24)

Scope: `graph-root` at `9f5f221` — `src/asn1`, `src/signer`, `src/diadoc`, `src/utd`, `src/pipeline`, `src/cli.ts`, `docker/`, `scripts/`, tests, `CLAUDE.md` / `docs/*`. No code was changed.

How it was checked:
- Own reading of the pipeline, Диадок client/auth, CLI, config, docker files. Three read-only reviewer passes (module seams; HTTP/security/CLI; docker/scripts/docs).
- Every finding below was confirmed by reading the code. Where marked **(run)**, it was also reproduced with a script, a test or a request to the I1 stand.
- Baseline on Node 22.23.2: `build`, `typecheck`, `lint` clean; `npm test` 321 passed / 4 skipped. Signer integration test against the stand passed 4/4. `scripts/test/*.test.sh` green.
- Note: under the system Node 25, `npm ci` fails on `engine-strict` (by design); use the `.nvmrc` Node.

**No blockers.** Byte handling across the seams is correct: parse → sign → send uses the same `Buffer` (identity checked), base64 is applied only at the wire, and `TextDecoder('windows-1251')` is read-only. BER→DER matches `openssl cms -outform DER` byte for byte, and `signedAttrs` are not re-sorted. `operationId` is length-prefixed, so there is no separator ambiguity. Exit codes 0–4 match `CLAUDE.md`; stdout carries only JSON. No secrets are in git history or tracked files.

## Major

### M1. Диадок fetches follow redirects; a cross-origin 307/308 forwards `client_secret` + `refresh_token` (and the signed УПД) to the new host — **(run)**
- Where: `src/diadoc/auth.ts:90-103`, `src/diadoc/client.ts:208-213` (no `redirect` option, so the default `follow` applies).
- Scenario: the IdP, a corporate proxy, or a misconfigured `DIADOC_TOKEN_URL` answers 307 to another origin.
  - undici drops `Authorization`, but it re-sends the POST body unchanged.
  - Reproduced on Node 22.23.2: a 307 from `127.0.0.1:A` to `localhost:B`. Server B received `client_secret=S&refresh_token=R`.
  - The redirect also bypasses the https-only check in `src/diadoc/config.ts:93`.
- The signer already does this correctly: `server-cms-signer.ts:158` sets `redirect: 'error'`, with a test at `server-cms-signer.test.ts:236`.
- Fix: set `redirect: 'error'` in both Диадок fetches and add the same test.

### M2. Transient PostMessage failures are not retried with the identical body; the only recovery is re-running `send`, which is the unverified D7 path
- Where: `src/diadoc/client.ts:114-121` retries only on 204. `client.ts:178-195` throws immediately on 5xx, 429, network errors and timeouts. `src/pipeline/send.ts:199-201` turns these into `POST_FAILED`, and the CLI exits 1.
- Scenario: Диадок created the message, but the response is lost (60 s `AbortSignal.timeout`, a 502 from the balancer, a 2xx with a non-JSON proxy page via `readJson`, `client.ts:227`).
  - The operator re-runs `send`. The `operationId` is the same, but the CMS is re-signed (new signing time), and on the shelf path `NameOnShelf` is new too.
  - Диадок may then answer with a duplicate, or with a 409 that carries no ids (D4/D7).
  - Retrying the same serialized `body` with the same `operationId` inside the process is the only retry that the idempotency contract actually covers.
- Fix:
  - Retry PostMessage a bounded number of times on network error, timeout, 5xx and 429, re-using the same `body` and honouring `Retry-After`.
  - For GET, retry at least on 429/5xx.
  - In the CLI, word `POST_FAILED` after a sent request as "may have been posted, operationId …" (`src/cli.ts:24`).

### M3. 429 / `Retry-After` is honoured only for PostMessage 204
- Where: `retryAfterMs` is used only at `src/diadoc/client.ts:118`.
- Scenario:
  - CanPostMessage or ShelfUpload gets a 429 → `PRECHECK_FAILED` / `SHELF_UPLOAD_FAILED`, exit 1.
  - During polling, `src/pipeline/status.ts:62-70` treats 429 as transient but sleeps on its own backoff and ignores the header.
- Fix: one 429 handler in `DiadocClient.send` (bounded by attempts and a total budget), or at least expose `Retry-After` on `DiadocError` so the poller can use it.

### M4. Refresh-token write-back is not robust — **(run: parts a, d)**
- Where: `src/cli.ts:142-158` (`onRefreshTokenRotated`) and `src/cli.ts:129-139` (`checkTokenFileWritable`).
- (a) `writeFile(tmp, …, { mode: 0o600 })` applies the mode only when the file is created. A stale `<file>.<pid>.tmp` keeps its old mode, e.g. `0644`. PIDs repeat, and inside a container the process is often PID 1.
- (b) There is no `fsync` of the file or the directory. After a power loss the file may hold the old, already-revoked token.
- (c) If the write or the rename fails, the error does not name the tmp file that still holds the only valid token.
- (d) If `DIADOC_REFRESH_TOKEN_FILE` is a symlink (docker/k8s secret layout), `rename` replaces the link with a regular file and leaves the target stale.
- (e) There is no lock, so two processes can use one refresh token. The docs say "run one process at a time", but nothing enforces it.
- Fix:
  - Write the tmp file with `open(tmp, 'wx', 0o600)` (unlink a stale one first), then `fsync(fd)`, `rename`, `fsync(dir)`.
  - On error, print the tmp path.
  - Reject symlinks, or resolve them with `realpath`, in `checkTokenFileWritable`.
  - Take an `O_EXCL` lock file for the duration of the run.

### M5. The verify step does not check *who* signed or that the CMS is detached
- Where: `src/signer/server-cms-signer.ts:106-133` (`valid` = `isValidSign` && every signer valid) and `server-cms-signer.ts:217-222` (`isCmsSignedData` checks only the OID).
- Scenario: a future signer (T7 `DocumentsCloudSigner`) or a server change returns an attached CMS, a second signer, or a signature by another key in the store. Verify still reports `valid`, and it is posted.
- Today the detached property is asserted only in the integration test (`signature.includes(marker) === false`).
- Fix: in the pipeline (not per signer), require:
  - exactly one signer;
  - the signer's thumbprint equals the thumbprint of `SIGNER_CERT_PATH`;
  - no `eContent` in `encapContentInfo`.

### M6. The pipeline requires a valid chain; the only signing cert expires 2026-10-28
- Where: `src/signer/server-cms-signer.ts:124` and `src/pipeline/send.ts:142`. `isValidSign` includes chain validation; `mathValid` is informational only.
- Scenario: from 2026-10-28 (about 5 weeks away), or on a stand without the test CA root, every `send` fails with `SIGNATURE_INVALID` even though the signature is mathematically correct. The cause is visible only inside `details`.
- Being strict is the right policy. Two gaps remain:
  - I3 (a new certificate) is the real mitigation and is time-critical.
  - The error message should say "chain invalid" vs "math invalid" explicitly.

### M7. The КриптоАРМ Server base image is unpinned
- Where: `docker/cryptoarm-server/Dockerfile:8` (`FROM registry.digtlab.ru/trusted/cryptoarm/server:latest`).
- The header (`Dockerfile:1-2`) and the README claim the files follow upstream commit `af98d55e`; `docs/research.md` names v1.4.25.
- Scenario: a rebuild on another machine, or after an upstream push, silently changes behaviour the code relies on:
  - BER output;
  - the text matched by `KEY_NOT_FOUND`;
  - the `setup_license` scripts.
  A replaced `latest` image also receives the PFX, PINs and licenses.
- Fix: pin the tag and the digest (`server:1.4.25@sha256:…`).

### M8. Keys, PINs and licenses travel via env and argv in the server container
- Where:
  - `docker/cryptoarm-server/docker-compose.yml:18-19` (`env_file`);
  - `docker/cryptoarm-server/.env.example:29-30` (`CERT_PFX_BASE64`, `CERT_PFX_PIN`);
  - `Dockerfile:65` (`certmgr … -pin "$pin"`);
  - `Dockerfile:34` and `setup-trusted-license-optional.sh:14` (license passed as argv).
- Scenario:
  - The whole PFX, its PIN, `TRUSTED_LICENSE` and `API_KEYS` are readable via `docker inspect` and `/proc/*/environ`.
  - The PIN and the license show up in `ps` at start-up.
  - This is acceptable for the public test key. It is not acceptable for a real organisation key (I3 and later).
- Fix:
  - Real keys only as mounted files (`certs/user`) or Docker secrets (`/run/secrets`).
  - Mark `CERT_PFX_*` as test-only in the README.
  - Check whether `certmgr` can read the PIN from stdin.

## Minor

1. **Stand errors are swallowed.** `Dockerfile:37,40,49,65,67` all end in `2>/dev/null || true`. A broken PFX or a wrong PIN still gives a *healthy* container, and the first symptom is `SignerKeyNotFoundError` in the pipeline. Fix: log `certmgr` stderr (without the PIN).
2. **PIN index shifts on an empty PFX element.** In `Dockerfile:56-71`, `idx=$((idx+1))` sits inside `[ -n "$pfx_b64" ] && { … }`. With `CERT_PFX_BASE64=a,,b`, element `b` gets PIN #2 instead of #3. Fix: increment outside the condition.
3. **The CSP distribution stays in an image layer.** `Dockerfile:10` uses `ADD cryptopro /tmp/src`; the later `rm -rf` does not remove the layer. This matters if the image is ever pushed (I4). Fix: `RUN --mount=type=bind,…` or a multi-stage build.
4. **No container hardening and a non-exec CMD.**
   - No `cap_drop: [ALL]`, `no-new-privileges`, `read_only` + tmpfs or resource limits; the server runs as root.
   - The shell-form `CMD` (`Dockerfile:27`) makes PID 1 a `sh`, so `docker stop` waits 10 s and then sends SIGKILL.
   - Blank continuation lines at `Dockerfile:35,42` trigger a Docker warning.
   - Mitigated today by the loopback-only port (compose:17).
5. **Host file modes.** The local `.env` files and `certs/user/cryptoarm.server.test.pfx` (no PIN) are `0644`. Fix: `umask 077` in `scripts/fetch-test-certs.sh`, and recommend `chmod 600 .env` in the README.
6. **API key in argv.** `scripts/smoke-server.sh:47` passes `-H "X-API-Key: $api_key"`, which shows up in `ps`. Fix: `curl -H @file`. Related: the server logs the first 8 characters of the API key on every request at the default `LOG_LEVEL=debug,…` (seen in `docker logs`; request bodies are *not* logged — checked with 3.9 MB requests). Default the stand to `log,warn,error`.
7. **The signer config is laxer than the Диадок config.**
   - `CRYPTOARM_SERVER_URL` accepts `http://` to any host (`src/signer/server-cms-signer.ts:197`), so `X-API-Key` and the document can travel in cleartext.
   - `changeme` is not rejected (`src/signer/config.ts:17-33`).
   - The same `changeme` gap exists for `DIADOC_FROM_BOX_ID` / `DIADOC_TO_BOX_ID` (`src/pipeline/config.ts:58-62`).
   - Fix: reuse the `checkUrl` / placeholder policy from `src/diadoc/config.ts:76-98`.
8. **`DIADOC_API_URL` with a query or fragment breaks URL building.** `client.ts:179` builds `this.baseUrl + path`, and `checkUrl` does not reject `search`/`hash`. The signer already rejects them (`server-cms-signer.ts:203`). Query values themselves are escaped by `searchParams.set`, so there is no injection.
9. **The polling deadline can overshoot.**
   - `status.ts:102-105` caps the sleep at the time left, but the next `getDocument` can take up to `DIADOC_TIMEOUT_MS` (60 s), plus a token refresh (30 s), plus one 401 retry.
   - The "never throws after post" guarantee holds.
10. **Ctrl+C gives no feedback.** `src/cli.ts:185` aborts only between steps (as documented). A PostMessage 204 loop can run for minutes, and the first Ctrl+C prints nothing. Fix: print "interrupting after the current step, Ctrl+C again to kill".
11. **409 texts are broad and printed unbounded (D4, unverified).**
    - `/already/i` would classify "operation already in progress" as `ALREADY_SENT` (`src/pipeline/conflict.ts:23`; `forbidden` is checked first, which is right).
    - `send.ts:299` prints `error.body` untruncated, unlike `DiadocError.message`, which is cut to 1000 characters.
12. **Extension case changes `operationId`.** — **(run)** `parseUtd` accepts `.XML` (`src/utd/parse.ts:59`, `/i`). The full `fileName` goes into `operationIdFor` (`send.ts:113`), so renaming `X.xml` to `X.XML` yields a different key for the same bytes, i.e. a second send. Fix: hash `utd.idFile` instead, or require lowercase `.xml`.
13. **`customDocumentId` is not part of `operationId`.** A repeat with a different `customDocumentId` reuses the key (`operation-id.ts:17`); the explicit resend belongs to T8.
14. **`KEY_NOT_FOUND` is brittle.** `/закрытый ключ[^.]*не найден/i` (`server-cms-signer.ts:25`) misses a message whose CN contains a dot. Only the dot-free text has been seen live.
15. **The shelf path lacks an automated test on the signer side.** The pipeline signs up to 3 000 000 B inline as base64 JSON. Checked manually on the stand today **(run)**:
    - `/cms/sign` of 600 000 B and of 2 900 000 B → 201 (about 8 s);
    - `/cms/verify` of 2.9 MB → `isValidSign: true`.

    There is no body-size limit problem, but no test pins it. Add a large-payload case to the signer integration test.
16. **Seam test gap.** `send.test.ts` uses `FakeSigner`/`FakeDiadoc` with a stub CMS, and `client.test.ts` tests base64 separately. No test runs the real `DiadocClient` (mock `fetch`) under `sendUtd` on the windows-1251 fixture and asserts that the base64-decoded `SignedContent.Content` (and the ShelfUpload body) equals the file byte for byte. Nor does any test run the real `ServerCmsSigner` with the BER fixture. The code is correct today; a regression would go unnoticed.
17. **ASN.1 leniency (documented).** `berToDer` accepts constructed universal tag 0 (`30 80 20 00 00 00` → `30022000`; `src/asn1/der.ts:146`). `isDerFramed` accepts a constructed string under an IMPLICIT context tag (`der.ts:194`). Both are harmless for the КриптоПро CMS (checked with `openssl asn1parse`), but `buildUtdAttachment`'s DER check is a framing check only (`src/utd/attachment.ts:52` → `isDerFramed`, `der.ts:73`).
18. **A rotated token when `expires_in` is missing.** `auth.ts:137`: with no lifetime, every API call triggers a refresh (and a file write if the token rotated). This widens the M4 window. Fix: fall back to a short default lifetime, e.g. 5 min.
19. **Non-standard token-file names are not git-ignored.** Only `.diadoc-refresh-token*` is covered (checked with `git check-ignore`). Recommend a path outside the repo in `.env.example`.

## Docs vs code drift

- `docs/plan.md`: T3, F2 and T5 still say "branch …, not merged"; they are merged (`a6b492b`, `e3619b8`, `98e17c4`).
- `docs/research.md:41` says "`ServerCmsSigner` accepts it as is; whether Диадок accepts BER … is checked in S1/T6". This is stale after F2 (DER normalisation; D1 is moot).
- `docs/research.md:42` lists `CRYPTOPRO_LICENSE` as required; `CLAUDE.md` and the README say empty = Demo trial.
- `CLAUDE.md`: "exit 1 failed (stderr has `[CODE]` from `PipelineError`)". Config and env failures (`SignerConfigError`, `DiadocConfigError`, `PipelineConfigError`, the token-file check) print `error: …` without a code (`src/cli.ts:171-180`).
- The root `.env.example` has `CRYPTOARM_SERVER_API_KEY=changeme` and `SIGNER_CERT_PATH=./certs/signer.cer` (no such file), while the stand has `API_KEYS=change-me-api-key` and `CLAUDE.md` uses `docker/cryptoarm-server/certs/cryptoarm.server.test.cer`. Copying both examples as is gives a 401 / ENOENT.

## Proposed follow-up tasks

| Id (proposed) | Task | Covers | Parent |
|---|---|---|---|
| F3 diadoc-http-hardening | `redirect: 'error'` for Диадок + IdP; bounded same-body PostMessage retry on network/5xx/429; common 429/`Retry-After`; reject query/hash in `DIADOC_API_URL`; `POST_FAILED` wording "may have been posted"; truncate the printed 409 body, narrow `/already/i` once S1 gives real texts; bound polling by a deadline signal; Ctrl+C feedback | M1, M2, M3, minor 8, 9, 10, 11 | T5 (graph-root) |
| F4 token-file | `O_EXCL` 0600 tmp + fsync + dir fsync, symlink check, tmp path in errors, lock file; default lifetime without `expires_in` | M4, minor 18, 19 | T5 |
| F5 verify-policy | Pipeline-level checks: one signer, expected thumbprint, detached; distinct chain-vs-math error; `[CODE]` for config errors in CLI; looser `KEY_NOT_FOUND` match | M5, M6 (message), minor 14, docs drift `[CODE]` | T5 |
| F6 operation-id | Hash `idFile` instead of `fileName` (or require `.xml`); fold into T8's salt/`--resend` design | minor 12, 13 | T8 |
| I5 stand-hardening | Pin base image digest; secrets as files/Docker secrets; log `certmgr` errors; fix PIN index; bind-mount the CSP tgz; exec-form CMD + `init`; `cap_drop`/`no-new-privileges`; `umask 077` in `fetch-test-certs.sh`; `curl -H @file`; `LOG_LEVEL` without debug | M7, M8, minor 1–6 | I1 (graph-root) |
| T9 seam-tests | Real `DiadocClient` + mock fetch under `sendUtd` on the fixture (inline and shelf, byte-for-byte); real `ServerCmsSigner` + BER fixture; large-payload signer integration case | minor 15, 16 | T5 |
| D-docs | Fix `plan.md` statuses, `research.md` BER/licence lines, `.env.example` alignment; signer config policy parity | drift, minor 7 | graph-root |

Minor 17 needs no task (documented leniency; revisit with T7).

**Time-critical:** I3 (new signing certificate) before **2026-10-28**. Otherwise M6 turns into a total outage of `send`.

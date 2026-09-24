# R2 — second review of graph-root (2026-09-24)

Scope: everything merged into `graph-root` since R1, i.e. `git diff 39601ac..4dbfdd8` (78 files, +9 051 / −600): F3, F5, F7, T8, T9, I5, I2, T7, F8, T10, I6, F9. No code was changed, and no stand or image was started, stopped, built or recreated.

How it was checked:
- Five read-only reviewer passes, one per area: (a) `src/signer` incl. `DocumentsCloudSigner` and the T10 size limit; (b) `src/diadoc` + `src/pipeline` + `src/cli.ts` (T8 shelf parts, `operationId`, retries, token file); (c) `src/asn1` + the F5 signature policy; (d) docker stands, `start.sh`, scripts, secrets, I6; (e) docs vs code drift. I re-checked every finding below against the code myself (file:line at `4dbfdd8`).
- **(probe)** means reproduced with a throw-away vitest file against the real module (deleted afterwards). **(mutation)** means a one-line code mutation that the test suite did not catch (reverted afterwards). **(fake)** means reproduced with the repo's shell-test fakes on a copy of the tree. **(read)** means confirmed by reading the code only. **UNVERIFIED** means it depends on behaviour of an external system that was not run.
- Baseline on Node 22.23.2: `build`, `typecheck` and `lint` are clean. `npm test`: 614 passed / 13 skipped. All six `scripts/test/*.test.sh` pass under bash, and `cryptoarm-start.test.sh` also passes under dash. `bash -n`/`dash -n` are clean. `docker compose … config` was used only to render the config (root, `--profile app`, server, Документы).
- 34 + 25 + ~20 mutations were run in areas (a), (b) and (c). Most were caught; the survivors are listed under "Test gaps".

**No blockers.** The byte path is still exact: parse → sign → verify → post uses the same `Buffer`. A shelf upload in parts gives back the file's bytes. The signature policy fails closed: no probe got a signature by a certificate other than the configured one through the local CMS check plus the verifier thumbprint check. Nothing marked "fixed" in R1 turned out to be unfixed, but three annotations are now stale (see D-2).

## Major

### M1. graph-root carries the I6 compose file while the shared server image is still I5, and two documented commands recreate the shared server — **(read + config render)**
- Where:
  - `docker/cryptoarm-server/docker-compose.yml:12` keeps the default tag `kryptoarm-diadoc/cryptoarm-server:local` (still the I5 image, `docs/plan.md` F9).
  - `:26-31` puts a tmpfs over `/etc/opt/cprocsp`, which only the I6 `start.sh` seeds.
  - `:58`: the healthcheck notices the missing seed only after the container was replaced.
  - `Dockerfile:2` and `.env.example:65` document `docker compose run --rm app send …` **without `--no-deps`**. `docker-compose.yml:20-22` makes `app` depend on `cryptoarm-server: service_healthy`.
  - `CLAUDE.md:37` ("`build cryptoarm-server-image`, then `up -d`") is, in graph-root today, an unannounced I6 rollout that skips the `:pre-i6` rollback tag the stand README asks for.
- Scenario: someone follows the app image header or the root `.env.example` in graph-root, runs `up -d`, or edits the stand `.env`. Compose recreates the shared `cryptoarm-server` from the old image under the new file. This is D40: CSP fails (`0x8009001d`), keys are not installed, `/cms/sign` answers "key not found", and the container is `unhealthy`. The working container is already gone at that point, and recovery is the manual rollback from the README. The F9 row and D40 warn about this, but only in prose. From another worktree the same command hits the `container_name` conflict instead.
- Fix:
  - (a) Bind the compose file to its image: give the I6 image its own default tag (e.g. `…:i6`) with `pull_policy: never`, so an `up` with only the old image fails with "No such image". UNVERIFIED: that compose v2 creates the new container before it removes the old one, so a missing image leaves the running container alone. Check on a throwaway project.
  - (b) Or roll I6 out to the shared stands now, following the README.
  - Either way, add `--no-deps` in `Dockerfile:2` and `.env.example:65`, and point `CLAUDE.md:37` at the README's "Container hardening" rollout.

### M2. A running PostMessage cannot finish inside `docker stop`'s grace period: SIGKILL loses the result and leaves the token lock — **(read + probe for the timing)**
- Where:
  - `src/diadoc/client.ts:178-188`: the 204 loop runs up to 10 rounds with a pause of up to 60 s each (`retry-after.ts:2`). Each round has its own F3 retry: up to 120 s of pauses plus 4 × `DIADOC_TIMEOUT_MS` (60 s).
  - `src/cli.ts:208-223`: by design, the first SIGTERM does not interrupt PostMessage.
  - `docker-compose.yml:14-47`: service `app` has no `stop_grace_period`, so Docker's default of 10 s applies. No `stop_grace_period` exists anywhere under `docker/` or in the root compose (grep).
- Scenario: `docker stop`, a host shutdown or CI cancelling `docker compose run app send …` during a slow PostMessage.
  - After 10 s the process gets SIGKILL. No JSON with `operationId`/`messageId` is printed, and `<token file>.lock` stays on the shared token volume, so every later `send` fails with `DIADOC_CONFIG` until someone deletes the lock by hand.
  - The operator then has to re-run `send`, and a re-run with a new signature is the unverified D7 path.
  - Worst case for the loop alone: 9 × 60 s of 204 pauses, i.e. 540 s (probe).
- Related, UNVERIFIED (T6): if Диадок answers 204 **without** `Retry-After`, the fallback pause is 1 s (`retry-after.ts:1`). The in-process idempotent window is then only ~9 s before `POST_PENDING`, and the next attempt is again a re-run under D7.
- Fix:
  - Give the whole PostMessage call one time budget, and document it next to `stop_grace_period` (set on `app` to that budget plus a margin).
  - Use a minimum pause of 5–10 s for a 204 without `Retry-After`.
  - On the second signal, remove the lock synchronously (`unlinkSync`) before the process exits, and print the `operationId` known so far.

### M3. `issue-test-cert.sh` can delete an existing non-exportable key container when the CSP enumeration fails — **(fake)**
- Where: `scripts/issue-test-cert.sh:77-80`. The existence check pipes `csptest -enum_cont … 2>/dev/null | grep -qixF`, so a failing enumeration looks like "not found". `:115` sets `key_created=1` before keygen. The EXIT trap at `:101` then runs `csptest -keyset -deletekeyset -cont "$fqcn"`.
- Scenario: `KEY_CONTAINER=<existing name>`, and the enumeration fails (CSP hiccup, trial expired). Keygen then fails too (assumption: `cryptcp -createrqst` refuses an existing container), and the cleanup deletes the **existing** key. The key cannot be exported, so the loss cannot be undone. This contradicts the stand README ("never deletes a key it did not create").
  - Reproduced on a copy of `issue-test-cert.test.sh` with an enumeration fake that exits 1 plus `FAKE_CRYPTCP_EXIT=7`: the log shows `csptest -keyset -deletekeyset -cont \\.\HDIMAGE\i3-test-cont`.
  - Low probability, irreversible outcome; today it only affects test keys.
- Fix: check the exit status of `docker exec … -enum_cont` separately from `grep` and abort when it is non-zero. Add a shell test for it. No stand needed.

## Minor

### Signer (area a)
1. **A body timeout in Документы becomes `SignerNetworkError`, not `SignerTimeoutError`** — **(probe)**. `src/signer/documents-cloud-signer.ts:327-341` (`#read`). The probe used a real HTTP server that sends 2xx headers and then stalls the body: the result was "sign: request failed: upload: reading the response failed" with cause `TimeoutError`. `ServerCmsSigner` maps this case correctly and has a test for it (`server-cms-signer.test.ts:285`). Fix: map a `TimeoutError` DOMException in `#read` to `SignerTimeoutError` and add a test.
2. **Network and timeout errors do not name the step** — **(read)**. `documents-cloud-signer.ts:344-353` and `errors.ts:99` (only `cause.message`).
   - The operator sees `SIGN_FAILED sign: no response within 120000 ms` and cannot tell upload, `cloud-sign` or export apart. It matters for `cloud-sign`: the signature may already be stored (D15).
   - A refused redirect and ECONNREFUSED both print "fetch failed"; the real reason is in `cause.cause`. `ServerCmsSigner` has the same problem (`server-cms-signer.ts:184`).
   - Fix: pass the step into the error, and append `cause.cause.message` to the message.
3. **A pre-issued `DOCUMENTS_JWT` is never checked for expiry** — **(read)**. `documents-cloud-signer.ts:117-119` sets `renewAt = Infinity`. An expired token gives a bare `SIGN_FAILED … HTTP 401: upload: …`. Fix: decode the `exp` claim at start (no signature check needed) and throw `SignerConfigError` if it has passed, or add a hint to the 401.
4. **In `DocumentsCloudSigner` mode, the `SignerPayloadTooLargeError` text misleads (D50)** — **(read)**. The error comes from the verifier after Документы has already signed, yet it says "… too large for КриптоАРМ Server … not sent". A 400/413 "too large" from Документы itself maps to a plain `SignerHttpError` (`:356-369`). Fix together with the D50 pre-check.
5. **Secrets written into `.env` are silently truncated at `#`** — **(run)**. `package.json:18` loads `.env` with `node --env-file-if-exists`. `DOCUMENTS_PASSWORD=ab#cd ef` is read as `ab` (checked with `node --env-file=… -e`); the same applies to `CRYPTOARM_SERVER_API_KEY`. Fix: add one line to `.env.example` (quote such values, or prefer the `*_FILE` variables).

### Диадок client, pipeline, CLI (area b)
6. **A non-JSON 2xx token response is echoed into the error message** — **(probe)**. `src/diadoc/auth.ts:160-164` includes `text.slice(0, 300)`. If the IdP or a proxy answers form-encoded (`access_token=…&refresh_token=…`), the fresh refresh token lands on stderr. Unlikely for identity.kontur.ru. Fix: for a 2xx, print only the status, content type and length.
7. **`DIADOC_API_URL` / `DIADOC_TOKEN_URL` accept userinfo, and the password is then printed** — **(probe)**. `src/diadoc/config.ts:90-103` (`checkUrl`). With `https://u:pw@host`, the first `fetch` throws `TypeError: Request cannot be constructed from a URL that includes credentials: https://u:pw@…`. The signer already rejects such URLs (`src/signer/shared.ts:17-37`). Fix: reject a non-empty `username`/`password`, without echoing the value.
8. **The poll deadline and Ctrl+C do not bound the token refresh inside a Диадок call** — **(probe)**.
   - Where: `src/diadoc/client.ts:336` calls `getAccessToken()` without deadline or signal. `auth.ts:122-137` runs `fetchWithRetry` without `deadline` or `signal`.
   - Probe: IdP 429 with `Retry-After: 40` and a 5 s poll deadline → the clock reached 120 s. Live, up to 4 × 30 s of timeouts come on top.
   - R1 minor 9 was annotated "overshoot ≤ one request + token refresh"; that holds, but one refresh can itself take ~240 s.
   - Fix: pass deadline and signal through `getAccessToken`, or restate the bound in `CLAUDE.md`.
9. **`expires_in` below the 60 s margin disables caching** — **(probe)**. `auth.ts:181`: with `expires_in: 30`, every API call refreshes the token and, if the IdP rotates it, rewrites the token file. This is the R1 minor 18 risk via a different input. Fix: use `min(expiryMarginMs, expires_in / 2)` as the margin.
10. **"May have been posted" is printed although the request never left** — **(probe)**. `client.ts:327-329` marks any transient fetch error as `maybeReceived`, including ECONNREFUSED/ENOTFOUND on all 4 attempts. This is safe (conservative), but it sends the operator to look in Диадок and towards the D7 path for nothing. Fix: leave `maybeReceived` unset for connect-phase error codes (`ECONNREFUSED`, `ENOTFOUND`, `EAI_AGAIN`).
11. **Auth failures take the step's code** — **(read)**. `src/pipeline/send.ts:233,253,280`: a burnt refresh token (`invalid_grant`) shows up as `PRECHECK_FAILED`, or as `SHELF_UPLOAD_FAILED`/`POST_FAILED` with `--no-precheck`.
    - Related: the IdP refresh is retried after a lost answer (`auth.ts:51-55`, a deliberate choice). If that answer had already rotated the token, the retry gets `invalid_grant`, with no hint. UNVERIFIED: whether Контур's IdP revokes the whole chain on reuse.
    - Fix: a separate `DIADOC_AUTH` code, plus a hint to re-issue the token on `invalid_grant`.
12. **`PRECHECK_REJECTED` carries no `operationId`** — **(read)**. `send.ts:239-244`; every other error after parsing has one. Fix: add it.
13. **The CLI reads the whole file before the 400 MB check** — **(read)**. `src/cli.ts:104`; the check itself is at `send.ts:142`. A 1 GB file is loaded into memory before the refusal; a file over 2 GB gives `READ_FAILED` instead of `CONTENT_TOO_LARGE`. Fix: `stat` the file before `readFile`.
14. **Token-file edge cases** — **(read)**.
    - (a) A `<file>.tmp` left by a failed rename holds the newest token, but the start does not look for it. The run then refreshes with the old, possibly revoked token and fails with `invalid_grant`, without pointing at the `.tmp` (`src/diadoc/token-file.ts:29-48`, `:85-93`).
    - (b) A single-file bind mount passes `checkReplaceable` (`:138-159`), but `rename` fails with EBUSY at the first rotation, i.e. after the IdP has already rotated the token. The new token stays in `.tmp`, and the message says so.
    - (c) There is no `--` in the argument parsing (`cli.ts:73-74`), so a path starting with `-` cannot be passed.
    - Fix: warn at start when `.tmp` exists; compare `st_dev` of the file and its directory; accept `--`.

### ASN.1 and signature policy (area c)
15. **Embedded-certificate check misses the SKI form of `sid`** — **(probe)**. `src/pipeline/signature-policy.ts:76-78` compares the embedded copy only by issuer + serial. With `sid = subjectKeyIdentifier`, a CMS can embed a different certificate with the same SKI, and `cmsPolicyViolations` returns `[]`. The verifier thumbprint check still rejects it, so this is not a bypass. The comment at `:55` promises more than the code does. Fix: treat an embedded certificate that matches by SKI and differs from `cert.der` as a violation too.
16. **The `sid` parser ignores extra elements, and versions are not checked** — **(probe)**. `src/asn1/cms.ts:130` destructures `[issuer, serial]`, so an `IssuerAndSerialNumber` with a trailing `05 00` is accepted. SignerInfo/SignedData versions (`cms.ts:101`) are not checked against the `sid` form (RFC 5652 §5.3). This extends R1 minor 17. Fix: require exactly two elements.
17. **A non-DER or PEM `SIGNER_CERT_PATH` fails late and with the wrong code** — **(read)**.
    - `src/signer/config.ts:139-151` only reads the file. The certificate is parsed only inside `sendUtd` (`send.ts:175`), after the УПД was parsed.
    - A PEM "Base-64" `.cer` (the usual Windows export) gives `error [CERTIFICATE_INVALID] … expected tag 0x30`, which reads like an expired certificate.
    - `readDer` also accepts non-minimal lengths (`04 81 01 aa`), and `readSignerCertificate` (`signature-policy.ts:33`) has no `isDerFramed` check. That case fails closed (thumbprint mismatch).
    - Fix: parse the certificate in the signer config and throw `SIGNER_CONFIG` "must be DER", or convert PEM to DER.
18. **`classifyVerifyFailure` blames our certificate when the verifier named none** — **(probe)**. `signature-policy.ts:116-156`: `{ valid: false, signers: [{ mathValid: true, chainValid: false }] }` without a thumbprint gives `CERTIFICATE_INVALID` "signer certificate <our thumbprint> is valid until …". The send is still refused; only the diagnosis is wrong. Fix: say "signer not confirmed" when the thumbprint is missing.
19. **Thumbprints are compared only case-insensitively** — **(probe)**. `signature-policy.ts:162`. `AB:CD:…` or hex with spaces (the КриптоПро/Windows formats) would give a false `SIGNATURE_POLICY_VIOLATION`. It fails closed, and today's server returns bare hex (integration test). Fix: strip non-hex characters before comparing.

### Stands and scripts (area d)
20. **`smoke-documents.sh` can reset the admin password to a value that is never saved** — **(read; live UNVERIFIED)**.
    - Where: `scripts/smoke-documents.sh:95-113`. With `DOCUMENTS_SIGNER_EMAIL` equal to the admin's e-mail (`server-test@documents.local`, the compose default, which is also in the ca-stub map), the script does `PUT /users/{admin}` with a random password.
    - Effect: `secrets/admin_password`, the T7 signer (`DOCUMENTS_LOGIN=admin`) and later smoke runs all break.
    - Fix: refuse when the found `user_id` equals the admin's `/profile` id.
21. **`API_KEYS` from `secrets/api_keys` is not normalised** — **(fake; server side UNVERIFIED)**.
    - `docker/cryptoarm-server/start.sh:159` turns `"\nkey-one\n key two \n"` into `,key-one, key two `: an empty first key and a key with spaces.
    - `scripts/documents-secrets.sh:57` trims the same file. So the Документы stand may send a key the server does not accept (401), or the server may accept an empty key.
    - Fix: trim the keys and drop empty ones in `start.sh`, with a test. The server's handling needs a stand.
22. **`AUTH_MODE=apikey` with an empty key list is not refused** — **UNVERIFIED**. `start.sh:158-159,240`. Upstream behaviour (deny all vs allow all) is unknown. Fix: warn or `die`; check on a throwaway stand.
23. **Документы stand hardening is uneven** — **(config render)**. `docker/cryptoarm-documents/docker-compose.yml:103-146`: `ca-stub` and `documents-db` have no `cap_drop`/`no-new-privileges`, and `postgres:14.4` and `nginx:1.27-alpine` are pinned by tag only. The tag pinning is in the README caveats; the missing capability drop is not. Needs a throwaway stand to find the minimal capabilities.
24. **The app image is the M7 of R1 again** — **(read)**.
    - `Dockerfile:1` uses `# syntax=docker/dockerfile:1` (unpinned frontend), which contradicts the reasoning in `docker/cryptoarm-server/Dockerfile:4-5`. `Dockerfile:5,13` use `node:22-bookworm-slim` without a digest.
    - Service `app` (`docker-compose.yml:14-47`) has no `cap_drop`, `no-new-privileges` or `read_only`, although it receives the whole root `.env` (`DIADOC_CLIENT_SECRET`, refresh token) as environment.
25. **Test-CA root trusted on first use over http** — **(read, documented)**. `scripts/issue-test-cert.sh:185-195,206` installs a self-signed AIA issuer into `mroot` of the shared server if only the DN matches. `fetch-test-certs.sh:46` already pins renewal 21 by SHA-256; reuse that allowlist.
26. **Licence-setting tools' output is not redacted** — **UNVERIFIED**. `start.sh:130,140,145` (`cpconfig -license -set`, `tsputil`/`ocsputil license -s`) log stdout/stderr as is, while `-view` is filtered (`:135`). Check with a real serial (D42).

### Test gaps (mutations the suite does not catch)
27. The code is correct today in each case; a regression would pass `npm test`.
    - Signer:
      - the `expiresAt` branch of the login JWT (`documents-cloud-signer.ts:271-272`: all mocks use exactly 15 min);
      - caller abort while reading a body (`:336`: without it the CLI prints `SIGN_FAILED` instead of `INTERRUPTED`);
      - the `status < 500` guard of `SignerKeyNotFoundError` (`:363-365`, relevant to D15).
    - Диадок / pipeline:
      - retry budget boundary (`http-retry.ts:88`);
      - HTTP 500 on PostMessage → "may have been posted" (`client.ts:324`; the seam tests use only 503);
      - exact 400 000 000 B (`send.ts:142`);
      - 404 during polling is transient (`status.ts:70`);
      - abort that coincides with a transient error (`http-retry.ts:66`);
      - one refresh per call on 401 → 503 → 401 (`client.ts:338-339`);
      - fsync of the token tmp file (`token-file.ts:97`);
      - no golden `operationId` with `customDocumentId`/`resend` set, so dropping the presence tag (`operation-id.ts:40`) passes.
    - ASN.1 / policy:
      - `issuer` in the `sid` and embedded-certificate comparisons (`signature-policy.ts:173,183`: serial alone would pass, although a serial is unique only per CA);
      - the `notBefore` boundary (`:47`);
      - `parseTime` rejections (`cms.ts:154,168-172,177`);
      - "element after signerInfos" (`:117`);
      - ContentInfo arity (`:56`);
      - `reader.ts:62,65` (the tests assert only `toThrow(Asn1Error)`, not the message).

### Things that can break on the first live Диадок run (T6), still docs-only
28. All of these are consistent with `docs/research.md` but have never been run:
    - query-parameter names and the `ShelfUploadPart` answer shape (JSON array of missing parts);
    - `Retry-After` on a PostMessage 204 (M2);
    - the accepted `operationId` length (64 hex characters);
    - the `CanPostMessage` request and answer shapes;
    - 409 texts (D4);
    - a re-sent middle part with `isLastPart=true` (D14);
    - replay vs 409 for the same `operationId` with a new signature (D7);
    - whether a lost refresh answer burns the rotating token (minor 11);
    - "500 KB" = 500 000 or 512 000 (D3).

    T6 should add them to its checklist before the first real send.

## Docs vs code drift

- D-1 (**part of M1**). `Dockerfile:2` and `.env.example:65` lack `--no-deps`; `CLAUDE.md:37` needs a pointer to the I6 rollout.
- D-2. Stale annotations:
  - `docs/review-r1.md` M6 still says "I3 still open" (I3 is done).
  - R1 minor 4 says "Not done: `read_only` …, resource limits" (done in I6, merged via F9, not rolled out).
  - R1 minor 15 and 16 are not marked as fixed by T10/T9.
  - `docs/research.md:49` says "`DocumentsCloudSigner` is T7 … not used yet" (T7 is merged).
  - The `docs/plan.md` DAG header has no F9. (The R2 row is updated in this task.)
- D-3. `CLAUDE.md:38`: "`run --rm --no-deps app` — waits for `cryptoarm-server` healthy". `--no-deps` skips `depends_on`, so there is no wait; the stand must already be healthy.
- D-4. `CLAUDE.md:90`: `parseBaseUrl` is in `src/signer/shared.ts:17`, not in `server-cms-signer.ts`, and both signers use it.
- D-5. **D20 misses Документы** (`CLAUDE.md:90`, `docs/plan.md` D20):
  - `DOCUMENTS_URL` goes through the same lax `parseBaseUrl` (`documents-cloud-signer.ts:100`). So `POST /api/v1/login` with the password, the Bearer JWT, the session cookie and the УПД may go over plain `http` to any host.
  - `DOCUMENTS_LOGIN`/`PASSWORD`/`JWT=changeme` from `.env.example` are accepted and fail only with a 401.
- D-6. `DIADOC_TIMEOUT_MS` does not apply to the IdP. `src/cli.ts:168-174` passes no `timeoutMs` to `RefreshTokenAuth`, which keeps its own 30 s (`auth.ts:16`). `.env.example:52` and the header of `src/diadoc/config.ts` suggest otherwise.
- D-7. D50 says an oversized document fails "after Документы has signed (one test licence spent)". `docs/research.md:54` and the Документы README (verified on I2) say `cloud-sign` does not use up `availableSignatureLicenses`. D50 should also mention `MAX_FILE_SIZE: '50'` (`docker/cryptoarm-documents/docker-compose.yml:63`) as the likely upload limit.
- D-8. `CLAUDE.md:62,64`: "the F3 retry with the same `Idempotency-Key`" / "retries are safe only with it". In the code, the key is sent only on upload and `cloud-sign`. Login and export are repeated without a key (harmless, both are reads in effect), and the request after a 401 re-login gets a new key (`documents-cloud-signer.ts:140,153,163-169,236-242,288`). Also not documented: an unmapped e-mail ("Не удалось получить корпоративный сертификат") maps to `SignerKeyNotFoundError` (`:37,362-366`).
- D-9. `src/diadoc/http-retry.ts:1-2` says "429/503 honour Retry-After" and "every Diadoc API and IdP request". The code honours `Retry-After` on every transient status (`:73`) and is also used by `DocumentsCloudSigner`.
- D-10. `docker/cryptoarm-server/README.md:236` (`docker compose -f docker/cryptoarm-server/docker-compose.yml ps`) and the header of that compose file (`:5-7`, build then `up -d`) address the standalone project `kryptoarm-diadoc-cryptoarm-server`, not the shared stand's `graph-root` project (config render). A standalone `up` would also create a network that the Документы stand (`graph-root_default`) does not join.

Checked and fine (short):
- **T8 part splitting.** ≤ 3 000 000 B is one `V2/ShelfUpload`; above that, parts with `partIndex`, and ≤ 3 rounds with termination.
- **Retry-After and retries.** `Retry-After` parsing (seconds, HTTP-date, garbage → 1 s, huge → give up). PostMessage repeats the same serialized body and `operationId`, and a 409 never becomes "outcome unknown". Retry loops do not multiply (`DiadocAuthError` is not transient).
- **Token file.** O_EXCL 0600 lock and tmp file, symlink refusal, the token never appears in an error, the lock is released on every `main` exit path. The access token is cached only after a successful persist.
- **Signer.** The `Idempotency-Key` is per logical request and the same across repeats. The 401 re-login is bounded. `redirect: 'error'` is set on every signer and Диадок fetch. `HEADER_TOKEN` keeps header values out of fetch errors. The T10 size arithmetic is exact (`Buffer.byteLength` parity; boundary mutations caught).
- **ASN.1.** The DER reader has no recursion, bounds every length and rejects high tag numbers. `detached` means an absent eContent (an empty OCTET STRING counts as attached). The UTCTime 49/50 pivot follows RFC 5280.
- **Scripts and stands.** Secrets are written with `umask 077` via mktemp + `mv`, passed with `curl -H @file`, and there is no `set -x`. Licences and `*_FILE` variables are unset before `exec`. The ca-stub cannot be path-traversed. Every host port is on `127.0.0.1`. Документы secrets are 256-bit.
- **R1 fixes** spot-checked in the code: M1, M4, M5, minor 2, 5 and 14.

## Proposed follow-up tasks

| Id | Task | Covers | Needs stands |
|---|---|---|---|
| F10 stand-rollout-guard | Close the D40 trap: I6 image under its own default tag (`pull_policy: never`, "No such image" instead of a broken recreate; check compose's create-before-remove on a throwaway project) **or** roll I6 out to both shared stands per the READMEs; `--no-deps` in `Dockerfile:2` and `.env.example:65`; `CLAUDE.md:37-38` rollout pointer and "no wait with `--no-deps`"; README `ps` command and compose header | M1, D-1, D-3, D-10 | yes (throwaway stand for the tag check; shared stands for a rollout) |
| F11 cli-shutdown-budget | One time budget for PostMessage (204 loop + retries) and `stop_grace_period` on `app` to match; minimum 204 pause without `Retry-After`; on the second signal, unlink the lock and print the `operationId`; deadline + signal through `getAccessToken`; no "may have been posted" for connect-phase errors; `stat` before `readFile`; `--` in argv; warn about a leftover `.tmp` at start; `st_dev` check of the token file | M2, minor 8, 10, 13, 14 | no (unit tests; one `docker compose run` + `docker stop` check is optional) |
| F12 diadoc-auth-errors | No 2xx body in token errors; reject userinfo in `DIADOC_*_URL`; margin `min(60 s, expires_in/2)`; `DIADOC_AUTH` code + `invalid_grant` hint; `operationId` on `PRECHECK_REJECTED`; pass `DIADOC_TIMEOUT_MS` to the IdP or document that it does not apply | minor 6, 7, 9, 11, 12, D-6 | no |
| F13 config-parity | D20 incl. Документы: `checkUrl`-style https policy (http only for loopback and the compose service names) for `CRYPTOARM_SERVER_URL` and `DOCUMENTS_URL`; placeholder rejection for the API key, `DOCUMENTS_*` and box ids; `exp` check of `DOCUMENTS_JWT`; parse `SIGNER_CERT_PATH` at start (`SIGNER_CONFIG`, PEM → DER or a clear refusal); `.env` `#` note | minor 3, 5, 17, D-5 | no |
| F14 documents-signer-polish | `SignerTimeoutError` for body timeouts; step + root cause in network/timeout errors (both signers); D50 pre-check from the verifier limit before the upload, with a truthful message; measure the Документы upload limit (`MAX_FILE_SIZE`) and the relayed `cloud-sign` error over `JSON_LIMIT`; D15 question whether 5xx answers are cached per `Idempotency-Key`; signer test gaps | minor 1, 2, 4, 27 (signer), D50 | partly (Документы stand for the limit and D15 measurements) |
| F15 asn1-policy-tests | SKI embedded-certificate check; exactly two `sid` elements (optionally version checks); "signer not confirmed" wording; thumbprint normalisation; the ASN.1/policy and Диадок/pipeline test gaps from minor 27 | minor 15, 16, 18, 19, 27 (asn1, diadoc, pipeline) | no |
| F16 scripts-safety | `issue-test-cert.sh`: abort on a failing `-enum_cont` + test; `smoke-documents.sh`: refuse the admin as signer; `start.sh`: normalise `API_KEYS`, warn/die on `apikey` with an empty list, redact licence-tool output; AIA root allowlist; `documents-secrets.sh` tmp trap | M3, minor 20, 21, 22, 25, 26 | partly (server `API_KEYS` semantics, licence output, D42 need a throwaway stand; the rest uses fakes) |
| F17 container-hardening-3 | App image: pin `node` by digest, drop or pin the `syntax` line, `cap_drop: [ALL]`, `no-new-privileges`, `read_only` + tmpfs; Документы `ca-stub`/`db`: capability drop, digests | minor 23, 24 | yes (throwaway stands) |
| F18 docs-drift-2 | Stale R1/research/plan annotations, `parseBaseUrl` path, `Idempotency-Key` scope and unmapped e-mail → `SignerKeyNotFoundError` in `CLAUDE.md`, D50 licence wording + `MAX_FILE_SIZE`, `http-retry.ts` header comment; add the minor 28 list to T6 | D-2, D-4, D-7, D-8, D-9, minor 28 | no |

Order: F10 first. It protects the shared stands, and any other graph-root work can trigger M1. F11 and F16 (M3) follow, before T6. F18 can go in parallel with anything. F12–F15 and F17 are independent of each other.

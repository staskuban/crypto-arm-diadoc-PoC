# C1: does the pipeline need КриптоАРМ Документы next to КриптоАРМ Server? (2026-09-26)

## Verdict: not needed for the automatic pipeline

Документы add nothing to the signature. They are needed only if people need a web archive, audit log, per-user or interactive signing next to the pipeline (then as a separate product, not in the signing path).

The evidence:

1. **Same signature.** `cloud-sign` relays the document to the same КриптоАРМ Server `/cms/sign` with the server defaults. Both paths produce the same CMS: DER after our normalisation (raw BER 2 200 B → DER 2 198 B), detached, CAdES-BES, one SignerInfo, the signer certificate embedded, the same thumbprint. The structural diff of the two CMS is **empty** for every input, from 1.7 KB to 35 MB. Only the signing time and the signature value differ, and they differ on every signing anyway.
2. **The same Диадок result.** One УПД signed through Документы was posted to the test boxes. It got «Ошибка в подписи» / `SENDER_CERTIFICATE_REJECTED`, exit 3, exactly as the server path did in T6 #5.
3. **Документы still need КриптоАРМ Server.** Документы sign on it (`SIGN_SERVICE_URL`), and our pipeline verifies on it (D16). So Документы never replace the server; they only add a hop.
4. **They are slower and fail more slowly.**
   - Per signing: +0.2 s at 10 KB, +1 s at 10 MB, +1.5 s at 35 MB (p50).
   - Batch of 10: 2.8× slower at 10 KB and 1.5–1.6× slower at 10–35 MB. The API rate limit (120 requests per 60 s per client, 3 requests per signing) caps **sustained** Документы throughput at ≤ 40 signings/min, against 391/min measured for the server at 10 KB. So for small documents the sustained gap is about 10×. The docs/min figures in the table are one burst of 10 that fits in the window. The 1 MB batch of run 2 hit the limit (six `429`; it had been used up by the phases before it) and took 37.8 s instead of 5.0 s.
   - An unreachable Документы costs 7–19 s of retries before the error. An unreachable server fails in 5 ms (refused) or at the client timeout (hang).
5. **They cost more to run.**
   - Four more containers, +1.77 GB of images, ≈ 0.5–0.9 GB more RAM.
   - A licence that expires on **2026-10-24**.
   - A PostgreSQL database and an upload volume that keeps every signed file (5 GiB quota per user).
   - In production, a CA service that does not exist yet (D12).
   - The D13 security properties: document ACLs are not enforced by `cloud-sign`, and `MAIL_LINK_TOKEN_SECRET` is equivalent to all keys.

## What was measured

- **Setup:**
  - Shared stands from `graph-root`: КриптоАРМ Server `:stand-i6` on `127.0.0.1:3037`; Документы `api:1.0.209` (reports 1.0.211) on `127.0.0.1:3040`, UI on `:3041`.
  - Host: Apple M1 Pro, Docker Desktop 29.0.1 with 8 CPUs and 11.7 GiB. All КриптоАРМ images are amd64 and ran **under emulation**.
  - Both signers used the same certificate, `cryptoarm.server.test.cer` (thumbprint `0e84b59e…`). The Документы user was `admin` (`server-test@documents.local`, which the CA stub maps to that `.cer`).
- **Build note:** `src/bench/signer-compare.ts` imports `src/e2e/test-utd.ts`, so `npm run build` emits `dist/bench/` and `dist/e2e/test-utd.js` (tsc follows imports despite `exclude`), and they land in the `app` image as dead code. Accepted for the PoC: the script needs them in `dist/`. If the module is kept, move the УПД generator out of `src/e2e` or give the bench its own tsconfig.
- **Script:** `scripts/compare-signers.js` (after `npm run build`; its header lists the env). The helpers live in `src/bench/signer-compare.ts` and are unit-tested: the CMS profile, a structural diff that masks the signing time and signature value, nearest-rank percentiles, and generated УПД.
- **Runs:**
  - Run 1 (08:04–08:10 UTC): all phases, `COMPARE_DOCKER_STATS=1 COMPARE_CLEANUP=1`, client timeout 3 s (the default). An older script version: per-step timings in concurrent batches were mixed up, so only its totals and wall times are used.
  - Run 2 (08:11–08:16 UTC): `COMPARE_PHASES=latency,failures COMPARE_TIMEOUT_MS=800 COMPARE_DOCKER_STATS=1 COMPARE_CLEANUP=1`, with an `AsyncLocalStorage` step log per signing.
  - Run 3 (after the review, current script): `COMPARE_PHASES=result,failures COMPARE_SIZES=10000 COMPARE_TIMEOUT_MS=800 COMPARE_CLEANUP=1`. It checks the id-based cleanup and repeats the failure cases.
  - Latency numbers below come from run 2, except where noted.
  - Every document the runs uploaded (76 + 70 + 4) was deleted through the API afterwards. Runs 1–2 matched documents named `document` created after the run started; the current script deletes only the ids its own uploads returned. The stand's storage is back to its level before C1, plus the one Диадок document (348).
- **Inputs:** the committed УПД fixture (1 767 B), plus generated СЧФДОП 5.03 УПД (windows-1251) of 10 081 B, 1 000 165 B, 10 000 195 B and 35 000 061 B. The limit probe used 39.3 MB of plain bytes.
- **One signing** = `sign` + `verify` on КриптоАРМ Server `/cms/verify`, as the pipeline does before its F5 policy.
  - Server: `/cms/sign`.
  - Документы: login/JWT (cached) → upload → `cloud-sign` → export `attached:false`.
- **Single** = sequential runs: 10 each for 10 KB and 1 MB, 5 for 10 MB, 3 for 35 MB. With n ≤ 10, p95 is the slowest or second-slowest run.
- **Batch** = 10 documents. As many run at once as fit in 40 MB: 10 for 10 KB and 1 MB, 4 for 10 MB, 1 for 35 MB. This keeps the 1 GiB Документы API container away from its limit.

## Comparison table

| | `SIGNER_KIND=server` | `SIGNER_KIND=documents` |
|---|---|---|
| **CMS** (all inputs) | DER 2 198 B (raw BER `30 80…` 2 200 B), detached, CAdES-BES (`contentType`, `signingTime`, `messageDigest`, `signingCertificateV2`), GOST R 34.11-2012/256 + 34.10-2012/256, 1 SignerInfo (v1, issuerAndSerialNumber), 1 embedded certificate `0e84b59e…`, no CRLs, no unsigned attributes | identical; structural diff with the server CMS = `[]` for 1.7 KB, 10 KB, 1 MB, 10 MB, 35 MB |
| Signing time | second resolution (UTCTime), server clock | the same (it is the same server) |
| `/cms/verify` | valid, math + chain + certificate valid, thumbprint `0e84b59e…` | the same |
| F5 policy | 0 violations | 0 violations |
| **Single signing p50 / p95, ms** | | |
| 10 KB | 163 / 509 | 398 / 1 379 |
| 1 MB | 285 / 449 | 511 / 872 |
| 10 MB | 997 / 1 270 | 2 017 / 2 566 |
| 35 MB | 3 507 / 3 762 | 4 997 / 5 199 |
| where the time goes (35 MB, p50) | `/cms/sign` 1.1–1.6 s, `/cms/verify` 1.4–1.9 s | upload 0.5 s, `cloud-sign` 2.5 s, export 17 ms, `/cms/verify` 1.5 s |
| **Batch of 10: wall time (docs/min)** | | |
| 10 KB, 10 at once | 1.5 s (391) | 4.2 s (142); run 1: 5.7 s (106) |
| 1 MB, 10 at once | 3.2 s (190) | **37.8 s (16)**: six `429` on export, rate limit; run 1: 5.0 s (120) |
| 10 MB, 4 at once | 8.7 s (69) | 13.4 s (45); run 1: 26.8 s (22) |
| 35 MB, 1 at once | 34.1 s (18) | 54.8 s (11) |
| Error rate (single + batch, runs 1–2) | 0 / 136 | 0 / 136 (the 429s were absorbed by the F3 retry) |
| | counts sign/verify failures; the F5 policy was checked in the result phase (0 violations); the current script also counts policy violations as errors | |
| **Max size** | 39 305 200 B signed + verified; 39 320 000 B → `SignerPayloadTooLargeError` at verify, after `/cms/sign` | 39 305 199 B; 39 305 200 B → `SignerPayloadTooLargeError` before upload (F14 pre-check, 16 KiB margin) |
| **Dependency down** (connection refused) | fails in 5 ms (`SignerNetworkError`, no retry) | fails after 7.0 s (login tried 4 times, F3 retry) |
| Dependency hangs (client timeout 0.8 s / 3 s) | 0.8 s / 3.0 s (`SignerTimeoutError`) | 10.2 s / 19.0 s (4 attempts + pauses) |
| Verifier (server) down, Документы up | — | `verify` fails after `cloud-sign`: a **signed orphan** stays in Документы |
| Live, 0.8 s client timeout, 10 MB | run 2: ok in 0.94 s; run 3: `SignerTimeoutError` at 0.86 s (`/cms/sign` took longer than 0.8 s; no retry) | run 2: ok in 2.6 s, `cloud-sign` timed out once and the repeat with the same `Idempotency-Key` answered 200 (whether the first attempt had already stored a signature was not checked); run 3: `cloud-sign` timed out twice, the third attempt got **400 «Повторная подпись документа этим пользователем запрещена»** after 5.7 s — D15 reproduced live: the document is signed, the signer reports a failure, and an orphan stays |
| **Containers** | 1 (`cryptoarm-server`) | +4: `documents-api`, `documents-db` (postgres 14.4), `ca-stub` (nginx), `documents-app` (UI) |
| Images | `cryptoarm-server:stand-i6` 2.22 GB | +1.77 GB (api 1.08 GB, postgres 514 MB, app 104 MB, nginx 76 MB) |
| RAM idle / peak | 538 MiB idle / 866 MiB of 2 GiB peak | +≈ 525 MiB idle (api 472, db 25, app 22, stub 7) / api peak **896 MiB of its 1 GiB** |
| | idle = one `docker stats --no-stream` right after run 2 (≈ 08:17 UTC); peak = the maximum of the 2 s samples over the whole latency phase (10 KB … 35 MB; the phase includes 4 × 10 MB at once and 35 MB one at a time), not tied to one size | |
| CPU peak / mean during the latency phase | server 118–155 % / 56–63 % | server as left + api 114–180 % / 27–35 %, db ≤ 48 % |
| Data at rest | none (keys in `cert_storage`) | every signed file stays: +720 MB for 76 signings (the same user's `usedSpace`; per-user quota `availableSpace` 5 GiB); deleting frees it (verified) |
| Secrets / licences | `TRUSTED_LICENSE`, КриптоПро CSP licence (or Demo), `API_KEYS` | + `LICENSE_VALUE` (test, **expires 2026-10-24**; 10 signature licences, not consumed by `cloud-sign`: 10 → 10 after 146 signings), `postgres_password`, `session_secret`, `secret`, `mail_link_token_secret` (= all keys, D13), `admin_password`, the server API key again; in prod a CA service + its token |
| Source / upgrades | upstream server source is public; our Dockerfile | **closed service** (the TS sources ship in the image, the repo has only docker/docs); behaviour changed silently (D9: `X-API-KEY` disabled), user docs lag the code (S2); single-arch amd64 |

## What Документы add (for people, not for the pipeline)

The UI was checked through `127.0.0.1:3041` without a browser login, to keep the admin password out of the agent transcript: the SPA bundle's resources and its API through the UI proxy (the same API, same origin). I7 already checked the login and the signature view in a browser.

- **Web UI.** Resources: documents (list, edit, «Подписи» per document with the verification `meta` and a PDF report), groups, users (admin only), events. The landing page is desktop КриптоАРМ via the browser plug-in (D233).
- **Roles.** There is only `isAdmin`, plus groups and per-document lists `accessUserIds` / `signatoryUserIds` (`signatureMode` parallel/sequential). There is no RBAC beyond that, and `cloud-sign` ignores the document ACL (D13a).
- **Audit log.** `GET /api/v1/events`, append-only through the API; there is no delete endpoint.
  - Seen on the stand: `USER_LOGIN`, `DOCUMENT_CREATED`, `DOCUMENT_DOWNLOADED`, `DOCUMENT_SIGNED` («корпоративная подпись»), `DOCUMENT_VERIFIED`, `DOCUMENT_DELETED`. The UI also knows `DOCUMENT_UPDATED`, `USER_LOGOUT` and `SIGN_PROXY_REQUEST`.
  - An event names the user and the document, not the certificate or the signature.
  - Our pipeline already has the equivalent evidence in Диадок: the message, its signatures and statuses.
- **Archive.** It stores whatever was uploaded, with its signatures. The pipeline uploads under the name `document`, so the archive is not browsable by УПД without a change. Диадок is the legally relevant archive of sent УПД anyway.
- **Per-user keys** (D12). `cloud-sign` picks the key by the logged-in user's e-mail, through an external CA service. The upstream design has that service hand out a PFX per user; we have only the stub (e-mail → public `.cer`, the key in the server's `uMy`). For one company key this is extra indirection. It is useful only if several people sign as themselves.
- **Other methods.**
  - `dss-sign` (КриптоПро DSS): off on the stand, not tried.
  - Desktop КриптоАРМ via browser plug-in and `operations/start`: a human at a PC.
  - Госключ: route B of S2. It needs our own ЕСИА/ЕПГУ registration and relabels the УПД as `.pdf`. S2 recommends route A (Диадок `DssSign`), which does not need Документы.
  - All of these are interactive, human-confirmed signing. None fits the unattended pipeline.

## Recommendation for the code (for the human to decide)

1. **Keep `DocumentsCloudSigner` as an optional, non-default module.** It is small, tested, and proven identical. `SIGNER_KIND=server` stays the default and the recommended path. Mark `documents` in `CLAUDE.md`/`.env.example` as "optional, not recommended for production" (proposed follow-up, not done here).
2. **Take the Документы stand out of the default local environment and docs flow.** Document it as an optional stand, kept only while its test licence lives (**2026-10-24**). After that date the API refuses to start without a new `LICENSE_VALUE` (research: no licence → no start; the exact behaviour at expiry is unverified). Keep its shell tests; skip its integration tests unless `DOCUMENTS_URL` is set (already the case).
3. **If Документы stay for people** (archive/UI), run them next to the pipeline, not in its signing path. Then:
   - fix the D13 findings upstream;
   - replace the CA stub with a real CA service or a PFX store;
   - raise the API memory above 1 GiB for large files;
   - add a retention/cleanup job, because every signing stores the file;
   - budget for the 120 requests/min per-client rate limit (3 requests per signing ⇒ ≤ 40 signings/min).
4. **Remove the D50/F14 pre-check and Документы error mapping only together with the module**, not before.

## Open questions for the human

1. Does anyone need a web archive, audit log or per-person signing of УПД outside Диадок? If not, Документы can go (keep the module only as a reference, or delete it in a follow-up).
2. Buy a production Документы licence, or let the test one lapse on 2026-10-24?
3. If per-person signing is wanted: Госключ via Диадок `DssSign` (S2 route A, no Документы) or КриптоПро DSS? Either would be a new interactive `Signer`, not `cloud-sign`.
4. The forged D13 test user `forged-…@documents.local` (id 68) still exists on the shared stand. Delete it? Harmless on a loopback stand.

## Диадок run (the only PostMessage of C1)

`src/e2e/diadoc.e2e.test.ts` gained the case «КриптоАРМ Документы cloud-sign CMS from the test CA: same result as the server path (C1)», the T6 negative case with `SIGNER_KIND=documents`. It ran once with `DIADOC_E2E_MAX_POSTS=1`. The trace shows one `V3/PostMessage`.

- The УПД: `ON_NSCHFDOPPR_2BM-9659998725-…_20260926_bf0a4fd3-…`, 1 756 B, inline.
- Signing: Документы document 348 → `cloud-sign` 542 ms → export → `/cms/verify` valid, signer `0e84b59e…`.
- Post: precheck ok → `MessageId` **`c4f54684-0f93-43a4-8efc-c46eb963030a`**, entity `b057fb79-…`, `operationId` `550714d7…`, `CustomDocumentId` `32bc312d-50c4-8518-941c-08ce7323df87`.
- After 2 polls:
  - `PrimaryStatus` Error «Ошибка в подписи», `SenderSignatureCheckedAndInvalid`;
  - math valid, certificate not accepted: REVOCATION_STATUS_UNKNOWN, PARTIAL_CHAIN, OFFLINE_REVOCATION;
  - not delivered (`DeliveryFailureNotification`);
  - CLI exit 3, `docflow error [SENDER_CERTIFICATE_REJECTED]`.
  This is the same as T6 #5, the server path: Диадок cannot tell the two apart.
- The refresh token was not rotated. The token file is unchanged, as in T6.

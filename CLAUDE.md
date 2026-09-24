# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Proof of concept, **no code yet**. Sections marked *(planned)* describe intent, not existing files — update them as soon as the scaffold lands.

- Task DAG, per-task status and done-criteria: `docs/plan.md` (source of truth for the Orca worktree tree; the `graph-root` worktree is the root parent of every task worktree).
- Research findings with sources (Диадок formats, signing infrastructure): `docs/research.md`.

## Goal

Automated pipeline for УПД (universal transfer document, ФНС format):
1. Centrally store signing keys/certificates and signing tools in **КриптоАРМ**.
2. Sign УПД documents automatically via the КриптоАРМ public API.
3. Send the signed documents to counterparties via **Контур.Диадок** public API.

**Current signing path (decided 2026-09-24):** КриптоАРМ Server holds the private keys and signs via `POST /cms/sign`; the pipeline depends on a `Signer` interface so a КриптоАРМ Документы `cloud-sign` implementation can be added later (blocked: no Документы `LICENSE_VALUE` yet).

Only public APIs of both systems are used. No database — state lives in КриптоАРМ (documents, signatures) and Диадок (messages, docflow status).

## Stack and conventions

- TypeScript + Docker (docker compose for local/test environment). No DB.
- **TDD is mandatory**: write a failing test first, then the implementation. Unit tests mock HTTP at the client boundary; integration tests run against the dockerized КриптоАРМ Server and the Диадок test environment.
- Build / lint / test commands: *(planned — fill in after scaffold: install, build, lint, unit tests, single-test invocation, integration tests, `docker compose up`)*.

## Development workflow (Orca worktrees)

Mandatory process for any multi-task work:
1. **Map dependencies first.** Before splitting into subtasks, identify all links between them (which task consumes interfaces/types/fixtures of another) and build a DAG.
2. **One worktree per subtask**, created via the `orca-cli` skill. Independent tasks run in parallel.
3. **Dependent worktrees get the dependency as parent**: a child worktree branches from its parent's worktree/branch, not from `master`.
4. **After each task completes**: merge it into its parent, then run integration tests on the parent.
5. **If integration breaks**: fix it in a **separate new worktree** (child of the broken parent), not by patching inside the finished task's worktree.
6. **Naming**: every task worktree name/display name starts with its task code from `docs/plan.md` (e.g. `T2-signer`, `I1-infra-server`).
7. **Board status**: when a task is finished (report written, `docs/plan.md` status updated), move its worktree to `in-review` on the Orca workspace board: `orca worktree set --worktree active --workspace-status in-review --json`.

Git: default branch is `master` (not `main`). The stash stack is shared across worktrees — never use bare `git stash`/`git stash pop`.

## External systems

### КриптоАРМ Документы API (hosted demo: https://demo.cryptoarm.ru)
- LLM index: `GET /llms.txt`; OpenAPI: `GET /openapi.json`; Swagger UI: `/api`. Re-download the spec rather than guessing endpoints.
- All endpoints under `/api/v1/*` (alias of `/api/*`). Prefer `/api/v1`.
- Auth: `X-API-KEY` header (global or per-document key), or `Authorization: Bearer <JWT>` (OIDC ID token from `https://id.kloud.one` or internal JWT from `GET /api/auth/jwt`).
- Key flows: upload `POST /api/v1/documents/upload`; server-side signing `POST /api/v1/signatures/cloud-sign/{documentId}` (corporate cloud key, off by default: `SIGN_METHOD_CORP_CLOUD=false`) or `signatures/dss-sign/{documentId}`. **`POST /api/v1/signatures` does not sign** — it only stores an externally made signature `{ documentId, signature }`. Get a single detached signature via `POST /api/v1/documents/{id}/signature` with `{ signatureId, attached: false }` (without `signatureId` it returns a merged signature of all signers); verify `POST /api/v1/documents/{id}/verify`; desktop КриптоАРМ operations are async: `POST /api/v1/operations/start` → poll `GET /api/v1/operations/result?operationId=`.
- Conventions the client must honour: `Idempotency-Key` header on mutating requests (retries are safe only with it); errors are `{ "error": { code, message, field?, hint?, details? } }` with real HTTP statuses; `429` → respect `Retry-After`; lists use react-admin style `range=[from,to]`, `sort`, `filter` with `X-Total-Count`/`Content-Range`; propagate/log `X-Request-Id`.
- Sources/docs: https://git.digtlab.ru/trusted/cryptoarm/documents/api (only docker/docs — the service itself is closed source), https://sign.kloud.one/docs.
- Self-hosting: public images `registry.digtlab.ru/trusted/cryptoarm/documents/{api,app}` (anonymous pull); needs `LICENSE_VALUE`, an OIDC IdP (КриптоАРМ ID) and `SIGN_SERVICE_URL` pointing at КриптоАРМ Server. How `cloud-sign` picks the corporate key is undocumented — verify on a live stand. The hosted demo cannot hold our keys, so it is not usable for automated signing.

### КриптоАРМ Server (self-hosted crypto backend, docker compose)
- Repo & install guide: https://git.digtlab.ru/trusted/cryptoarm/server (compose file, Dockerfile, `.env` are fetched from `docker/` in that repo).
- Default port `3037`, Swagger at `/docs`. Auth via `AUTH_MODE=none|apikey` + `API_KEYS`; key passed as `X-API-Key`, `Authorization: Bearer`, or `?apiKey=`.
- Signing: `POST /cms/sign` with `{ cert, data, password?, detached?, cadesStandard? }` (Base64) → `{ cms }`. `detached` defaults to **true**, `cadesStandard` to `CAdES-BES`. Also `/cms/verify`, `/cert/verify`, `/hash`, `/cms/attached-to-detached`.
- Keys stay on the server: install PFX at container start (`/certs/user/*.pfx`, or `CERT_PFX_BASE64` + `CERT_PFX_PIN`; roots in `/certs/root`), then pass only the public `.cer` as `cert` — the key is found in `uMy` by thumbprint. Passing a `.pfx` also works but installs it temporarily per request. Test cert/key from CRYPTO-PRO Test Center 2 ship in the upstream repo `certs/`.
- `.env` needs `TRUSTED_LICENSE` (КриптоАРМ Server test key — provided by the user, keep it only in the untracked `.env`) and `CRYPTOPRO_LICENSE`.
- **Manual prerequisite**: КриптоПро CSP 5.0 `linux-amd64_deb.tgz` must be downloaded by a human (requires cryptopro.ru login) into `cryptopro/`. Image is x86_64 only — on Apple Silicon it runs under emulation.

### Контур.Диадок API
- Docs: https://developer.kontur.ru/doc/diadoc-api/index.html (has an OpenAPI spec and SDKs linked from there).
- Auth: OIDC access token via **Refresh Token Flow** — `client_id`, `client_secret` (= API key from «Кабинет интегратора») and a `refresh_token` issued once in the integrator cabinet; refresh `access_token` automatically. Use a service account with rights to create and sign documents.
- Test space: OIDC scope `Diadoc.PublicAPI.Staging` (prod: `Diadoc.PublicAPI`); two test boxes created via the docs form and added as counteragents to each other.
- Sending: `PostMessage (V3)` with `MessageToPost { FromBoxId, ToBoxId, DocumentAttachments[] }`, each attachment has `TypeNamedId`, `Function`, `Version` and `SignedContent { Content, Signature }`. `Signature` is CMS SignedData in DER, separate from `Content` (i.e. **detached**; the official C# SDK signs with detached=true). `Content` inline only if < 500 KB, otherwise `ShelfUpload` + `NameOnShelf`; 70 MB per request. Pre-check with `CanPostMessage`. Status via `GetDocument` → `DocflowStatus`. `SignWithTestSignature` exists for test runs.
- УПД (verified): `TypeNamedId = "UniversalTransferDocument"`, `Function` ∈ `СЧФ | ДОП | СЧФДОП | СвРК | СвЗК`, `Version = utd970_05_03_01` (`utd970_05_02_01` is obsolete). Take values from `GetDocumentTypes (V3)` and tolerate unknown versions. The ФНС XSD is `windows-1251` and requires file name == `@ИдФайл` — sign and send the exact same bytes, never re-encode. Signer block (universal format) must be filled **before** signing.
- Open: whether Диадок test boxes accept a signature from the КриптоПро test CA (spike S1).

## Secrets

КриптоАРМ API keys, КриптоАРМ Server/КриптоПро licenses, Диадок `client_secret`/`refresh_token`, PFX containers and PINs go only into untracked `.env` files; commit `.env.example` with placeholders.

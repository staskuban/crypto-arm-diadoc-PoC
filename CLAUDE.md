# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Proof of concept, **no code yet** (only an empty initial commit). Sections marked *(planned)* describe intent, not existing files — update them as soon as the scaffold lands.

## Goal

Automated pipeline for УПД (universal transfer document, ФНС format):
1. Centrally store signing keys/certificates and signing tools in **КриптоАРМ**.
2. Sign УПД documents automatically via the КриптоАРМ public API.
3. Send the signed documents to counterparties via **Контур.Диадок** public API.

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

Git: default branch is `master` (not `main`). The stash stack is shared across worktrees — never use bare `git stash`/`git stash pop`.

## External systems

### КриптоАРМ Документы API (hosted demo: https://demo.cryptoarm.ru)
- LLM index: `GET /llms.txt`; OpenAPI: `GET /openapi.json`; Swagger UI: `/api`. Re-download the spec rather than guessing endpoints.
- All endpoints under `/api/v1/*` (alias of `/api/*`). Prefer `/api/v1`.
- Auth: `X-API-KEY` header (global or per-document key), or `Authorization: Bearer <JWT>` (OIDC ID token from `https://id.kloud.one` or internal JWT from `GET /api/auth/jwt`).
- Key flows: upload `POST /api/v1/documents/upload`; sign `POST /api/v1/signatures` (also `signatures/cloud-sign/{documentId}`, `signatures/dss-sign/{documentId}`); download signature `GET /api/v1/signatures/{documentId}/download`; verify `POST /api/v1/documents/{id}/verify`; desktop КриптоАРМ operations are async: `POST /api/v1/operations/start` → poll `GET /api/v1/operations/result?operationId=`.
- Conventions the client must honour: `Idempotency-Key` header on mutating requests (retries are safe only with it); errors are `{ "error": { code, message, field?, hint?, details? } }` with real HTTP statuses; `429` → respect `Retry-After`; lists use react-admin style `range=[from,to]`, `sort`, `filter` with `X-Total-Count`/`Content-Range`; propagate/log `X-Request-Id`.
- Sources/docs: https://git.digtlab.ru/trusted/cryptoarm/documents/api, https://sign.kloud.one/docs.

### КриптоАРМ Server (self-hosted crypto backend, docker compose)
- Repo & install guide: https://git.digtlab.ru/trusted/cryptoarm/server (compose file, Dockerfile, `.env` are fetched from `docker/` in that repo).
- Default port `3037`, Swagger at `/docs`. Auth via `AUTH_MODE=none|apikey` + `API_KEYS`; key passed as `X-API-Key`, `Authorization: Bearer`, or `?apiKey=`.
- Signing: `POST /cms/sign` with `{ cert, data, password }` (all Base64; `cert` may be a PKCS#12 `.pfx`) → `{ cms }`. Also `/cms/verify`, `/cert/verify`, `/hash`.
- `.env` needs `TRUSTED_LICENSE` (КриптоАРМ Server test key — provided by the user, keep it only in the untracked `.env`) and `CRYPTOPRO_LICENSE`.
- **Manual prerequisite**: КриптоПро CSP 5.0 `linux-amd64_deb.tgz` must be downloaded by a human (requires cryptopro.ru login) into `cryptopro/`. Image is x86_64 only — on Apple Silicon it runs under emulation.

### Контур.Диадок API
- Docs: https://developer.kontur.ru/doc/diadoc-api/index.html (has an OpenAPI spec and SDKs linked from there).
- Auth: OIDC access token via **Refresh Token Flow** — `client_id`, `client_secret` (= API key from «Кабинет интегратора») and a `refresh_token` issued once in the integrator cabinet; refresh `access_token` automatically. Use a service account with rights to create and sign documents.
- Sending: `PostMessage` with `MessageToPost { FromBoxId, ToBoxId, DocumentAttachments[] }`, each attachment has `TypeNamedId` and `SignedContent { Content, Signature }`. Status via `GetDocument` → `DocflowStatus`. `SignWithTestSignature` exists for test runs.
- *(assumption, verify in docs)* УПД uses `TypeNamedId = "UniversalTransferDocument"` with a function (`СЧФ`/`СЧФДОП`/`ДОП`) and format version; Диадок expects a **detached** CMS signature over the exact XML bytes (УПД XML is windows-1251 — never re-encode between signing and sending).

## Secrets

КриптоАРМ API keys, КриптоАРМ Server/КриптоПро licenses, Диадок `client_secret`/`refresh_token`, PFX containers and PINs go only into untracked `.env` files; commit `.env.example` with placeholders.

# Task DAG

Root worktree: `graph-root` (branch `graph-root`, from `master`). Every task worktree is a child of `graph-root` or of its dependency; finished tasks merge into their parent, then integration checks run on the parent (see `CLAUDE.md` → Development workflow).

Assumption: УПД XML arrives ready-made from the accounting system (no `GenerateTitleXml` step). Revisit if that changes.

```
T0 graph-root ─┬─ I1 infra-server
               ├─ S1 spike-diadoc
               └─ T1 scaffold ─┬─ T2 signer
                               ├─ T3 diadoc-client
                               └─ T4 utd-domain
T5 pipeline      ← T2, T3, T4
T6 integration   ← T5, I1, S1
Deferred (needs Документы LICENSE_VALUE):
I2 infra-documents ← I1;  T7 documents-cloud-signer ← I2, T2
```

| Id | Task | Depends on | Done when | Human inputs | Status |
|---|---|---|---|---|---|
| T0 | Research, DAG, CLAUDE.md fixes | — | this file + `docs/research.md` committed | — | done |
| I1 | `docker/cryptoarm-server`: Dockerfile from upstream, `cryptopro/` git-ignored, `.env.example`, `certs/` mount + `CERT_PFX_BASE64`, healthcheck, smoke script | T0 | `docker compose up` starts Server; smoke script: `/cms/sign` with test `.cer` → detached CMS, `/cms/verify` valid | CSP `linux-amd64_deb.tgz`, `TRUSTED_LICENSE`, `CRYPTOPRO_LICENSE` | todo |
| S1 | Diadoc spike: refresh-token auth (staging scope), `GetMyOrganizations`, `GetDocumentTypes`, `PostMessage` УПД with test-CA signature and with `SignWithTestSignature` | T0 | written answer: which signature the test boxes accept; working request samples | integrator `client_id`/`client_secret`/`refresh_token`, two test boxes | blocked — scripts, fixture, findings ready (`spikes/diadoc/`); live run waits for credentials, test-CA run also for I1 |
| T1 | Scaffold: TS, lint, vitest, root `docker-compose.yml` (includes I1 service once merged), `.env.example`, build/test commands in `CLAUDE.md` | T0 | `install`, `build`, `lint`, `test` green on empty suite | — | todo |
| T2 | `Signer` interface + `ServerCmsSigner` (`/cms/sign`, `detached: true`, `CAdES-BES`, `.cer` only; API key; error mapping) | T1 | unit tests with mocked HTTP green | — | todo |
| T3 | Diadoc client: OIDC refresh with auto-renew, `GetDocumentTypes (V3)`, `CanPostMessage`, `PostMessage (V3)`, `GetDocument` → `DocflowStatus`, `Retry-After` | T1 | unit tests with mocked HTTP green | — | todo |
| T4 | УПД domain: XML kept as `Buffer` end to end, check `encoding="windows-1251"`, file name == `@ИдФайл`, pick `Function`/`Version`, size → inline vs shelf | T1 | unit tests on fixture XML green | sample УПД XML (can use generated fixture) | todo |
| T5 | Pipeline: XML → sign → verify → PostMessage → poll status | T2, T3, T4 | unit tests with fake Signer/Diadoc green | — | todo |
| T6 | Integration/e2e against dockerized Server + Diadoc staging | T5, I1, S1 | test УПД reaches the test box, `DocflowStatus` has no signature errors | all of the above | todo |
| I2 | `docker/cryptoarm-documents` + IdP; `SIGN_METHOD_CORP_CLOUD=true`; find how `cloud-sign` picks the key | I1 | upload → cloud-sign → detached signature → verify | Документы `LICENSE_VALUE` | blocked |
| T7 | `DocumentsCloudSigner` implementing `Signer` | I2, T2 | unit + integration green | — | blocked |

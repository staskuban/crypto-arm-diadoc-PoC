# S1 spike: Контур.Диадок test boxes

Throwaway scripts that answer the S1 questions from `docs/plan.md`: refresh-token auth, test boxes (on the production host, D191), `GetMyOrganizations`, `GetDocumentTypes (V3)`, `CanPostMessage` + `PostMessage (V3)` of a УПД `utd970_05_03_01` `СЧФДОП` (test signature or a detached CMS file), `GetDocument (V3)` → `DocflowStatus`. Findings live in `docs/research.md` ("S1 spike findings", "S1 live run" of 2026-09-25). This is not production code: T3/T4 re-implement it properly.

Node ≥ 22.18 runs the `.ts` files directly (type stripping), no build step and no runtime dependencies.

```sh
npm install            # dev deps only: typescript, @types/node
npm test               # unit tests (mocked HTTP) + XSD validation of the generated УПД via xmllint
npm run typecheck
cp .env.example .env   # then fill in, see "Human inputs"
```

## Commands

| Command | What it does | Output |
|---|---|---|
| `node src/cli.ts token` | `POST https://identity.kontur.ru/connect/token` (`grant_type=refresh_token`) | `.state/tokens.json` (access token + rotated refresh token) |
| `node src/cli.ts orgs` | `GET /GetMyOrganizations?autoRegister=false` — prints INN/KPP/`FnsParticipantId`/box ids | `out/my-organizations.json` |
| `node src/cli.ts types` | `GET /V3/GetDocumentTypes?boxId=` filtered to `UniversalTransferDocument` | `out/utd-type.json` |
| `node src/cli.ts fixture [--offline]` | builds a minimal УПД 5.03 `СЧФДОП` seller title in windows-1251; online mode takes seller/buyer from `GET /GetOrganization?boxId=` for both boxes | `out/<ИдФайл>.xml` (`--offline`: `fixtures/`) |
| `node src/cli.ts post --test-signature` | builds the УПД online, `POST /CanPostMessage`, then `POST /V3/PostMessage?operationId=` with `SignWithTestSignature: true` | `out/post-message.json`, `.state/last-post.json` |
| `node src/cli.ts post --xml <file> --signature <cms>` | same, but sends the given bytes with a detached CMS (DER, base64 or PEM). `--signature` without `--xml` is refused: the CMS covers one specific file | same |
| `node src/cli.ts post --resume` | re-sends an unfinished PostMessage with the same `operationId` and body from `.state/pending-post.json`, so no duplicate is created | same |
| `node src/cli.ts status [--message-id --entity-id]` | `GET /V3/GetDocument?injectEntityContent=false`, prints `DocflowStatus` (defaults to the last post) | `out/document.json` |
| `node src/cli.ts generate --user-data <xml>` | `POST /GenerateTitleXml` (UserContract XML, XSD in `xsd/`; live-tested sample `fixtures/user-data-s1.xml` — the test boxes have no address, so parties go as `OrganizationDetails OrgType="2"` with an explicit `RussianAddress`, D201) | `out/<file from Content-Disposition>` |
| `node src/cli.ts all --test-signature` | token → orgs → types → post → status | |

`.env`, `.state/` and `out/` are git-ignored. With `DIADOC_REFRESH_TOKEN_FILE` (preferred, shared with the main CLI) the refresh token lives only in that file: a rotated token is written back to it and `.state/tokens.json` (0600) keeps the access token plus a hash. Without it `.state/tokens.json` holds the latest refresh token too; a newly issued token in `.env` wins over the cached one, and if the token endpoint rotated it, deleting `.state/` loses the only valid copy. (Live 2026-09-25: the IdP did not rotate it.)

Live-checked 2026-09-25: GUID box ids work in message bodies and query strings (answers echo `<hex>@diadoc.ru`); `CanPostMessage` needs a GUID `CustomDocumentId` (D200, D192). The test organisations have an empty `Address.RussianAddress.Region`, so the builder falls back to region 77.

## Test-CA signature run (after I1)

Result of the 2026-09-25 run: Диадок does not trust the КриптоПро test CA — «Ошибка в подписи», not delivered (D202). The main CLI does the same run in one step: `npm run cli -- send <file> --no-precheck` (from the repo root, `SIGNER_KIND=server`).

The signature must cover the exact bytes that are sent:

```sh
node src/cli.ts fixture                                  # out/ON_NSCHFDOPPR_....xml with real box requisites
# sign those bytes with КриптоАРМ Server: POST /cms/sign { cert, data: base64(file), detached: true } → cms
node src/cli.ts post --xml out/ON_NSCHFDOPPR_....xml --signature out/utd.p7s
node src/cli.ts status
```

## Human inputs

1. **Integrator access and `client_id`.** Leave a request on https://www.diadoc.ru/integrations/api («Интеграция»). A Kontur manager grants access to «Кабинет интегратора» and issues the application `client_id` → `DIADOC_CLIENT_ID`. Ask for test-platform (staging) access explicitly.
2. **`client_secret`.** Кабинет интегратора → «API-ключи» → «+ Выпустить ключ» → `DIADOC_CLIENT_SECRET`. It is shown once.
3. **`refresh_token`.** Кабинет интегратора → «Способ получения токенов (clientMode)» = `AuthorizationCode` → «Выпуск токенов» → select `Diadoc.PublicAPI.Staging` → «Получить refresh-токен». The first time, confirm and wait 2–5 minutes. Log in as the **service account** that will send documents (use «Скопировать ссылку» and open it in an incognito window if it is not your current account), grant access, enter the API key, copy the token → `DIADOC_REFRESH_TOKEN`. The account needs rights to create/edit and to sign documents.
4. **Two test boxes.** Create them with the form https://diadoc.kontur.ru/easyregistration (linked from the Диадок quickstart). Make the service account from step 3 an employee of the sender box. Add the boxes to each other's counteragents in the Диадок web UI (https://support.kontur.ru/pages/viewpage.action?pageId=83854105).
5. **Box ids.** Run `node src/cli.ts orgs` and copy the sender `BoxIdGuid` → `DIADOC_FROM_BOX_ID`. Copy the recipient box id from the Диадок UI or from `GetMyOrganizations` of its own account → `DIADOC_TO_BOX_ID`. Staging and production box ids are different; mixing them gives `403`.
6. **Signer.** Set `UTD_SIGNER_LAST_NAME`/`UTD_SIGNER_FIRST_NAME` (and optionally the middle name and position) for `Подписант`. Use the service account's name for the test signature, or the certificate owner's name for a real CMS. Whether Диадок cross-checks it is unverified.

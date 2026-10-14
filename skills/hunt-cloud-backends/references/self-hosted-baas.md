# Hasura, Directus, Strapi, PocketBase, Appwrite, Parse Server

These run on the client's own infrastructure or a vendor cloud, with the API
called straight from the frontend. Each has one "public" or "anonymous" role
whose permissions decide everything, and one admin credential that must never
reach the client. Version endpoints feed the CVE gates at the end of each
section; a version match is "in range", never "vulnerable", until confirmed.

Filter-language oracles in Strapi (CVE-2026-27886) and Directus
(CVE-2025-64748) are written up in
`hunt-sqli/references/orm-leak-and-filter-languages.md`; Parse's LDAP adapter
(CVE-2026-31828) in `hunt-ldap`. Not repeated here.

## Hasura (and Nhost, which runs Hasura)

| Request | Reading |
|---|---|
| `GET /v1/version`, `GET /healthz` | Version and liveness. |
| `GET /console` | Console served to the internet. Low on its own; Hasura Cloud projects get a random admin secret by default. |
| `POST /v1/graphql` `{"query":"{__typename}"}` with **no headers** (read) | 200 with data: either no admin secret at all, or an unauthenticated role is configured. |
| `POST /v1/metadata` `{"type":"export_metadata","version":2,"args":{}}` with **no headers** (read) | 200 with metadata: no admin secret, so every anonymous caller is admin. Critical. |

Hasura's deployment guide says an admin secret must be configured so that the
GraphQL endpoint and console are not publicly accessible. With a secret set,
unauthenticated requests are rejected unless `HASURA_GRAPHQL_UNAUTHORIZED_ROLE`
(`--unauthorized-role`) names a role for them; that role's permissions are then
the anonymous attack surface (`hunt-graphql`). `X-Hasura-Admin-Secret` with no
other session variables bypasses all permissions; in a bundle it is Critical.

`export_metadata` returns the whole configuration, which can include
connection strings or webhook headers. Save it locally, quote only the fact
that it answered, and redact. A smaller admin-only call such as
`{"type":"get_inconsistent_metadata","args":{}}` proves the same thing with
less data (verify it is admin-only on the target's version).

Advisories:

- GHSA-g7mj-g7f4-hgrg (Nov 2022, critical, no CVE): undisclosed bug in
  GraphQL Engine v2.10.0-v2.15.1, all editions; fixed in 2.10.2, 2.11.3,
  2.12.1, 2.13.2, 2.14.1, 2.15.2.
- CVE-2023-27588 / GHSA-c9rw-rw2f-mj4x (Mar 2023, critical): unauthenticated
  path traversal via the console assets path; fixed 1.3.4, 2.11.5, 2.20.1.
  Self-hosted only.
- CVE-2026-54698 / GHSA-r27x-gc74-qmxh (Jun 2026, high): a `where` on a table
  computed field acts as an oracle over rows the role cannot select; fixed
  2.49.2 and 2.45.5. Proof is a boolean differential on your own role,
  `hunt-graphql`.

## Directus

| Request | Reading |
|---|---|
| `GET /server/ping` | `pong`. Directus is there. |
| `GET /server/health` | Only `ok` / `warn` / `error` unless admin (Directus API docs). |
| `GET /server/info`, `/server/specs/oas`, `/server/specs/graphql` | Restricted on current versions; older versions leaked the exact version (CVE-2024-27296, CVE-2025-53887). |
| `GET /items/<collection>?limit=1` with no token | Data: the Public policy grants read on that collection. |
| `GET /users?limit=1` with no token | Users readable by Public. High. |

Advisories worth a version gate (all from GitHub advisories for `directus` /
`@directus/api`):

| ID | Issue | Fixed |
|---|---|---|
| CVE-2024-54151 / GHSA-849r-qrwj-8rv4 | With `WEBSOCKETS_GRAPHQL_AUTH` or `WEBSOCKETS_REST_AUTH` set to `public`, unauthenticated WebSocket clients had admin-level CRUD | 11.3.0 |
| CVE-2025-55746 / GHSA-mv33-9f6j-pfmc | Unauthenticated file upload and modification via the files update path | 11.9.3 |
| CVE-2025-53889 / GHSA-7cvf-pxgp-42fc | Manual-trigger Flows runnable without authentication | 11.9.0 |
| CVE-2025-30352 / GHSA-7wq3-jr35-275c | `search` enumerates fields the role cannot read | see advisory |
| CVE-2026-39942 / GHSA-393c-p46r-7c95 | Path traversal and broken access control in the file management API | see advisory |
| CVE-2026-35412 / GHSA-qqmv-5p3g-px89 | TUS upload authorization bypass allows arbitrary file overwrite | see advisory |

The WebSocket and upload issues are proven by version and setting, never by
connecting with admin rights or uploading to production.

## Strapi

| Request | Reading |
|---|---|
| `GET /admin/init` | `auth: false` in Strapi's admin routes. Returns `data.hasAdmin` (plus uuid and logos). `hasAdmin: false` on a reachable instance means `POST /admin/register-admin` (also `auth: false`) will create the first super admin for whoever calls it. Critical; report, never register. |
| `GET /admin/project-type` | `auth: false`; edition. |
| `GET /api/<plural>?pagination[pageSize]=1` with no token | Data: Public role has `find` on that content type. |
| `GET /api/users` with no token | users-permissions `find` granted to Public; often all users with emails. Read the first record only (pagination support on this route varies by version, verify; cut the response with `head -c`). |

Advisories (GitHub advisories for `@strapi/*`):

| ID | Issue | Fixed |
|---|---|---|
| CVE-2023-22621 / GHSA-2h87-4q2w-v4hf | SSTI to RCE in users-permissions email templates (needs admin access) | see advisory |
| CVE-2023-22893 / GHSA-583x-23h9-f5w7 | AWS Cognito login provider did not verify access or ID tokens; forged `alg: none` token impersonates any Cognito user | 4.6.0 |
| CVE-2023-22894 / GHSA-jjqf-j4w7-92w8 | Filtering on private fields leaks sensitive user data | see advisory |
| CVE-2023-39345 / GHSA-gc7p-j5xm-xxh2 | Private fields writable through the user registration API | 4.13.1 |
| CVE-2024-34065 / GHSA-wrvh-rcmr-9qfc | Open redirect plus token in URL leaks third-party tokens, auth bypass (one click) | 4.24.2 |
| CVE-2026-27886 / GHSA-rjg2-95x7-8qmx | Relational filtering oracle | `hunt-sqli` reference |

CVE-2023-39345 means open registration on Strapi 4.0-4.13.0 can set fields
like `role` or `confirmed` at signup: proving it is a Stage B registration.

## PocketBase

| Request | Reading |
|---|---|
| `GET /api/health` | `"API is healthy."`; extra data only for superusers (source). |
| `GET /_/` | Admin UI. Normal. |
| `GET /api/collections/<name>/records?perPage=1` with no token | 200 with items: the List rule is an empty string. 403: the rule is `null` (superuser only). 200 with empty items: a filter rule excluded you. |
| `GET /api/collections/<name>/records/<id>` | View rule; 404 means the filter rule failed. |

PocketBase docs: a `null` rule is "locked" (superuser only), an empty string
lets anyone (including guests) perform the action, any other string is a
filter. Superusers bypass rules. The `users` auth collection with an empty
List or View rule exposes every user's email unless `emailVisibility` is off.

First superuser: current PocketBase creates a temporary installer superuser and
prints a link with a 30-minute token (`/_/#/pbinstall/<token>`), so a fresh
instance is not claimable without that link (source, `apis/installer.go`).
Versions before the installer (pre-0.23) showed a first-admin form at `/_/`
to anyone (verify).

Advisories: CVE-2024-38351 / GHSA-m93w-4fxv-r35v (OAuth2 sign-up linked to an
unverified password account with the same email; fixed 0.22.14) and
CVE-2026-44166 / GHSA-pq7p-mc74-g65w (account pre-hijacking via unverified to
verified OAuth2 auto-linking). Both need a victim account you own to prove:
Stage B.

## Appwrite

- Client: `new Client().setEndpoint(<url>).setProject(<id>)`, header
  `X-Appwrite-Project`. Cloud endpoint `cloud.appwrite.io` or regional
  variants; self-hosted on the client's domain.
- Permissions (Appwrite docs): `Role.any()` "grants access to anyone",
  `Role.guests()` grants access to users without a session. Resources created
  by a server SDK or the console with no permissions are inaccessible;
  resources created by a client SDK give their creator read, update and delete
  by default. Row (document) security is opt-in per collection.
- Proof: list documents or files with only the project header. The list
  endpoints are `/v1/databases/<db>/collections/<collection>/documents` and
  `/v1/storage/buckets/<bucket>/files`; newer versions rename collections to
  tables in the console (verify the API path for the version in use). Limit to
  one result with the `queries[]` limit syntax of that version (verify).
- Version: `GET /v1/health/version` (verify it is unauthenticated on the
  target).
- Self-hosted console sign-up is controlled by `_APP_CONSOLE_WHITELIST_ROOT`
  (only one user can register when enabled), `_APP_CONSOLE_WHITELIST_EMAILS`
  and `_APP_CONSOLE_WHITELIST_IPS`. A self-hosted console that lets anyone
  create a console account is worth reporting; creating one is Stage B.
- Advisory: CVE-2023-27159, SSRF via `/v1/avatars/favicon` in Appwrite up to
  1.2.1 (cve.org). Version-gate.

## Parse Server and Back4App

- Client: `Parse.initialize(<appId>, <jsKey>)`, `Parse.serverURL = <url>`
  (default mount `/parse/`). Back4App's hosted API is `parseapi.back4app.com`
  (verify). Headers: `X-Parse-Application-Id`, `X-Parse-REST-API-Key` or
  `X-Parse-JavaScript-Key` (client keys are optional on modern Parse Server),
  `X-Parse-Master-Key` (never client-side; Critical if found).
- `/parse/schemas` "can be only accessed using the master key" (Parse REST
  docs): a 200 without it is Critical.
- Counting without reading:

```bash
S='https://<host>/parse'; H=(-H "X-Parse-Application-Id: <APP_ID>" -H "X-Parse-REST-API-Key: <CLIENT_KEY>")
curl -s -G "$S/classes/<Class>" "${H[@]}" --data-urlencode 'count=1' --data-urlencode 'limit=0'
curl -s -G "$S/users" "${H[@]}" --data-urlencode 'count=1' --data-urlencode 'limit=0'
```

`{"results":[],"count":5231}` on `_User` = Class-Level Permissions allow
public find on users. Protected fields (email) may still be hidden; one record
with `limit=1` shows which fields leak.

- GraphQL: Parse's GraphQL API exposed the schema publicly until
  CVE-2025-53364 (fixed 7.5.3 / 8.2.2; `graphQLPublicIntrospection` option).
- Advisories (GitHub advisories for `parse-server`; 2026 brought a large
  batch, so pin the version first):

| ID | Issue |
|---|---|
| CVE-2022-24760, CVE-2022-39396, CVE-2023-36475 | Prototype pollution to RCE (2022-2023) |
| CVE-2024-27298, CVE-2024-39309 | SQL injection in the PostgreSQL adapter (`literalizeRegexPart`) |
| CVE-2025-64502 | Public `explain` queries expose schema and performance data |
| CVE-2025-64430, CVE-2025-68150 | SSRF via file upload URI and the Instagram OAuth adapter |
| CVE-2026-30965 | Session token exfiltration via `redirectClassNameForKey` |
| CVE-2026-31800 | `_GraphQLConfig` and `_Audience` master-key bypass via generic class routes |
| CVE-2026-32248 | Account takeover via operator injection in the auth data identifier |
| CVE-2026-27804 | Account takeover via JWT algorithm confusion in the Google auth adapter |

Every one of these is a version gate in this skill. Their payloads write,
inject or take over accounts.

## Stage B on self-hosted BaaS

Registrations (Strapi `/api/auth/local/register`, Parse `POST /parse/users`,
PocketBase create on an auth collection, Appwrite `POST /v1/account`, Directus
public registration where enabled (verify the route for the version)), any write, upload, Flow trigger, WebSocket
subscription with elevated rights, or any call carrying a leaked admin
credential follow SKILL.md Step 4. A first-admin registration (`hasAdmin:
false`, an unconfigured installer) is never done, even with sign-off: it takes
over the instance.

## Sources (checked October 2026)

- Hasura securing the endpoint: <https://hasura.io/docs/2.0/deployment/securing-graphql-endpoint/>
- Hasura unauthenticated access: <https://hasura.io/docs/2.0/auth/authentication/unauthenticated-access/>
- Hasura metadata API: <https://hasura.io/docs/2.0/api-reference/metadata-api/manage-metadata/>
- Hasura advisories: <https://github.com/hasura/graphql-engine/security/advisories>
- Directus server API: <https://directus.com/docs/api/server>
- Strapi admin routes (source): <https://github.com/strapi/strapi/tree/develop/packages/core/admin/server/src/routes>
- PocketBase API rules: <https://pocketbase.io/docs/api-rules-and-filters/>; installer: <https://github.com/pocketbase/pocketbase/blob/master/apis/installer.go>
- Appwrite permissions: <https://appwrite.io/docs/advanced/platform/permissions>; env vars: <https://appwrite.io/docs/advanced/self-hosting/configuration/environment-variables>
- Parse REST guide: <https://docs.parseplatform.org/rest/guide/>
- GitHub advisory database: <https://github.com/advisories>

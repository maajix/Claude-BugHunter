---
name: hunt-cloud-backends
description: "Hunt misconfigured backend-as-a-service and managed-auth platforms that web and mobile apps embed client-side, tested from outside with only the public app config. Covers Firebase (Realtime Database, Firestore and Storage rules, Cloud Functions, Remote Config, legacy FCM server keys, Dynamic Links), Supabase (anon vs service_role and sb_ keys, RLS gaps, PostgREST, Storage, Edge Functions, Auth settings), AWS Amplify and Cognito user pools (self-signup, writable attributes, AppSync API-key auth), Auth0 / Okta CIC and Clerk tenants, Appwrite, PocketBase, Parse Server and Back4App, Hasura, Directus, Strapi, Convex, Nhost, and Maps or Gemini abuse of AIza keys. Finds the config in JS bundles and app packages, proves the misconfiguration with count-only reads and public settings endpoints, and keeps every write, signup, reset email or rule change behind Stage B sign-off. Use when a bundle or APK shows firebaseConfig, supabaseUrl, aws-exports, an Auth0 domain, a Clerk pk_ key or a BaaS SDK init."
sources: vendor_docs, github_security_advisories, cve_org, nvd, public_research, disclosed_incidents, project_source_code
report_count: 0
---

## When to use

Trigger when recon shows an app talking straight from the browser or phone to a
hosted backend: `firebaseConfig` / `google-services.json`, a `*.supabase.co`
URL, `aws-exports.js` or `amplify_outputs.json`, an Auth0 or Clerk domain, a
Hasura, Directus, Strapi, PocketBase, Appwrite, Parse, Convex or Nhost
endpoint. These platforms move authorization out of an app server and into
**rules, policies, grants or role settings** that the vendor evaluates. The
client config is public by design; the finding is always that the rules behind
it let an anonymous or self-registered user do more than the app intends.

`report_count` is 0 because this skill is built from vendor documentation,
project source, GitHub security advisories and public research and incident
write-ups, not from a counted corpus of disclosed bounty reports.

### Where the chain ends

Stop at **misconfiguration proved with the smallest possible read, impact
described, evidence captured**:

- Data exposure: stop at a row count or one record from one collection, table
  or class. Never dump a database, page through a collection or download a
  bucket "to show scale". The count is the scale.
- Open signup: stop at the setting or page that shows it is open. Creating an
  account is Stage B and only when the program allows test accounts.
- Writable data, writable attributes, writable rules: stop at "the rules allow
  it" inferred from reads, docs and the app's own code. A write is Stage B, on
  a record you created, and is never done to someone else's data (the Moltbook
  write test in 2026 could not be reverted by the researchers; see
  `references/supabase-convex-nhost.md`).
- Leaked secret key (Supabase `service_role` / `sb_secret_`, Clerk `sk_live_`,
  Hasura admin secret, Convex deploy key, Parse master key): stop at decoding it
  offline and proving where it is exposed. Calling an API with it is Stage B
  and only where the program allows validating leaked credentials.
- A CVE in range from a version endpoint: stop at the version gate.
  Exploitation is out of scope for this bundle (`SECURITY.md`).

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| Pulling and unpacking APK / IPA files, jadx, Frida, pinning bypass | `apk-redteam-pipeline`, `ios-redteam-pipeline`. This skill starts once `google-services.json`, `GoogleService-Info.plist` or strings are extracted. |
| Generic secret regexes (AWS, Stripe, Slack, generic Google `AIza`) and source maps | `hunt-source-leak`, `offensive-osint/references/secret-patterns.md` |
| Raw GCS / S3 / Azure listing (`storage.googleapis.com`, `*.s3.amazonaws.com`), Cloud Run, Lambda URLs, IMDS | `hunt-cloud-misconfig` |
| Cognito **identity pool** `GetId` → `GetCredentialsForIdentity` → IAM role abuse, any STS credential | `cloud-iam-deep`. Stop at "identity pool ID found, unauth identities possibly enabled" and hand off. |
| GraphQL technique (introspection, batching, aliases, field-level authz) on AppSync, Hasura, pg_graphql, Directus or Parse GraphQL | `hunt-graphql` |
| Account-takeover flows once a primitive exists (reset poisoning, email change) | `hunt-ato`, `hunt-forgot-password`, `hunt-oauth` |
| Workforce Okta, the Okta / Auth0 advisory table, the 2024 CIC cross-origin credential-stuffing incident | `okta-attack` |
| Strapi CVE-2026-27886 and Directus CVE-2025-64748 (filter-language oracles) | `hunt-sqli/references/orm-leak-and-filter-languages.md` |
| Parse Server CVE-2026-31828 (LDAP adapter) | `hunt-ldap` |
| Subdomain takeover of a dead Firebase Hosting / Dynamic Links custom domain | `hunt-subdomain` |
| Password spraying any of these auth APIs | `hunt-brute-force` (usually out of scope) |

---

## Step 1: Fingerprint the backend from the bundle or app

Work offline on files you already have: the SPA bundle and chunks, source maps
(`hunt-source-leak`), and the decoded app package (`apk-redteam-pipeline`
Stage 6, `ios-redteam-pipeline` Stage 3). Every value below is public by
design. Its presence is not a finding.

| Platform | Markers in JS / app | What to record |
|---|---|---|
| Firebase | `initializeApp({apiKey, authDomain, projectId, storageBucket, databaseURL, appId})`, `google-services.json` (`project_id`, `firebase_url`, `storage_bucket`, `current_key`), `GoogleService-Info.plist` (`API_KEY`, `PROJECT_ID`, `DATABASE_URL`) | project ID, RTDB URL, bucket, API key, collection and path names used in code |
| Supabase | `createClient(<url>, <key>)`, `*.supabase.co`, `SUPABASE_URL` / `SUPABASE_ANON_KEY` env names, `sb_publishable_` | project ref, key type, table, RPC, bucket and function names |
| Amplify / Cognito | `aws-exports.js` (`aws_user_pools_id`, `aws_user_pools_web_client_id`, `aws_cognito_identity_pool_id`, `aws_appsync_graphqlEndpoint`, `aws_appsync_apiKey`, `aws_appsync_authenticationType`), Gen 2 `amplify_outputs.json` (`auth.user_pool_id`, `auth.user_pool_client_id`, `auth.identity_pool_id`, `data.url`, `data.api_key`, `data.default_authorization_type`) | pool ID, client ID, AppSync URL and auth mode, API key |
| Auth0 / Okta CIC | `createAuth0Client` / `Auth0Provider` with `domain` + `clientId`, `*.auth0.com` or a custom domain, Android `com_auth0_domain`, iOS `Auth0.plist` | tenant domain, client ID, connection names, `audience` |
| Clerk | `pk_live_` / `pk_test_` publishable key, `CLERK_PUBLISHABLE_KEY`, `clerk.<domain>` | Frontend API host (base64 inside the key) |
| Hasura / Nhost | `/v1/graphql`, `x-hasura-admin-secret`, `x-hasura-role`, `NhostClient({subdomain, region})`, `*.nhost.run` | endpoint, any admin secret string |
| Directus / Strapi | `createDirectus(<url>)`, `/items/`; `/api/<plural>`, `/admin/init`, `STRAPI_` env names | base URL, collection names |
| PocketBase | `new PocketBase(<url>)`, `pb.collection('<name>')`, `/_/` admin UI | base URL, collection names |
| Appwrite | `.setEndpoint(<url>).setProject(<id>)`, `X-Appwrite-Project`, `cloud.appwrite.io` | endpoint, project, database, collection and bucket IDs |
| Parse / Back4App | `Parse.initialize(<appId>, <jsKey>)`, `Parse.serverURL`, `X-Parse-Application-Id`, `parseapi.back4app.com` (verify) | app ID, keys, class names; a **master key** in the client is critical |
| Convex | `ConvexReactClient(<url>)`, `*.convex.cloud`, `api.<module>.<fn>` property chains | deployment URL, function names |
| Google APIs | `AIza` key in a Maps loader, Places widget or Firebase config | which project the key belongs to (same as Firebase `apiKey`?) |

Decode tokens offline before any request. A Supabase legacy key is a JWT whose
payload `role` is `anon` or `service_role`; a Clerk publishable key decodes to
its Frontend API host (verify):

```bash
# Offline only. Print the JWT payload; never paste a real key into an online decoder.
KEY='<SUPABASE_KEY_FROM_BUNDLE>'
python3 -c 'import sys,base64,json;p=sys.argv[1].split(".")[1];print(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))))' "$KEY"
# "role": "service_role" in a client bundle = critical exposure on its own (Step 5)
```

Collection, table, class and function names come from the code, not from
guessing. Client SDKs generally cannot list collections (Baserunner's README
says this for the Firebase JS SDK), and schema endpoints are increasingly
closed (Supabase stopped serving the PostgREST OpenAPI document to the anon
key in 2026). Harvest names from `collection(`, `.from(`, `doc(`, `ref(`,
`.collection(`, `/items/`, `/api/`, `classes/` and GraphQL operation names.

---

## Step 2: Stage A rules and rate posture

**Stage A is read-only and is the default.** A Stage A request reads a setting,
a count, one record, or a public page. It never creates an account, sends an
email or SMS, uploads, writes, deletes, calls a mutation, registers a device or
installation, or changes a rule.

- **Minimise every read.** Use `shallow=true`, `pageSize=1`, `limit=1`,
  `perPage=1`, count-only headers or `count=1&limit=0`. Pipe responses into a
  file, not your terminal history, and redact before sharing (`evidence-hygiene`).
- **Rules are inferred, not read.** None of these platforms exposes its rules,
  RLS policies or API rules to an anonymous caller. Report "the rules allow
  anonymous list on `<collection>`" from the observed response. Do not claim a
  rules-read URL.
- **Read-only POSTs exist and are fine.** Firestore `:runQuery`, Supabase
  storage `object/list`, a GraphQL `query`, Convex `/api/query` and Hasura
  `export_metadata` are POST requests that read. Each is marked "(read)" where
  it appears. A GraphQL `mutation`, Convex mutation or action, or any PUT,
  PATCH, DELETE is not.
- **Supabase and PostgREST give you a guarantee.** PostgREST runs GET and HEAD
  in a READ ONLY transaction, including `GET /rest/v1/rpc/<fn>`; a function
  that writes fails under GET. A POST to `/rpc/` can write: Stage B.
- **Billable APIs bill the target.** Google Maps, Places and Gemini calls cost
  the key owner money. One request per API, no scanners in loops, and check the
  program's policy first: many list Maps keys as out of scope or informative.
- **One process, slow.** These are production tenants shared by real users.
  Sequential requests with a pause, stop at the first 429.

---

## Step 3: Stage A checks per platform

Full endpoint tables, response readings and history are in `references/`. The
minimum proof for each platform:

### 3a. Firebase (`references/firebase.md`)

```bash
P='<PROJECT_ID>'; K='<API_KEY>'
# Realtime Database: shallow = top-level keys only. 401 "Permission denied" = locked.
curl -s "https://$P-default-rtdb.firebaseio.com/.json?shallow=true" | head -c 600
# Firestore (read): one document from a collection named in the app code.
curl -s "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/<collection>?pageSize=1&key=$K" | head -c 1500
# Cloud Storage for Firebase (read): list one object name.
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o?maxResults=1" | head -c 800
```

Use the exact `databaseURL` from the config (regional databases live on
`*.firebasedatabase.app`) and the exact bucket (`<project>.appspot.com` before
30 Oct 2024, `<project>.firebasestorage.app` after). Repeat each read once as a
signed-in test user only if the program provides one: "any signed-in user can
read every user's documents" is the common real finding (Chattr.ai, 2024).

### 3b. Supabase (`references/supabase-convex-nhost.md`)

```bash
U='https://<ref>.supabase.co'; A='<ANON_OR_PUBLISHABLE_KEY>'
curl -s "$U/auth/v1/settings" -H "apikey: $A"          # disable_signup, external.*, mailer_autoconfirm
curl -s -o /dev/null -D - "$U/rest/v1/<table>?select=*" -H "apikey: $A" \
     -H "Prefer: count=exact" -H "Range: 0-0" | grep -i content-range   # count only
curl -s "$U/storage/v1/object/list/<bucket>" -H "apikey: $A" -H "Authorization: Bearer $A" \
     -H 'Content-Type: application/json' -d '{"prefix":"","limit":1}'  # (read)
```

`Content-Range: 0-0/48213` with the anon key on a table holding user data is
the finding. `*/0` or `[]` usually means RLS filtered everything; that is the
correct state, not a finding.

### 3c. Amplify / Cognito / AppSync (`references/aws-amplify-cognito.md`)

- Self-signup: load the managed login page
  (`https://<domain>.auth.<region>.amazoncognito.com/login?client_id=<id>&response_type=code&redirect_uri=<registered>`)
  and look for the sign-up link. AWS documents that the link is hidden when
  self-registration is off, but hiding it is not the control: `SignUp` stays
  callable with the client ID unless `AllowAdminCreateUserOnly` is true. A direct
  `SignUp` call is Stage B.
- AppSync with `API_KEY` mode: one `{__typename}` query (read) with
  `x-api-key`, then one list query with the smallest limit the schema allows.
  Introspection and further technique: `hunt-graphql`.
- Identity pool ID present: hand to `cloud-iam-deep`.

### 3d. Auth0 / Okta CIC and Clerk (`references/auth-platforms.md`)

- Auth0: `GET https://<tenant>/.well-known/openid-configuration`, then the
  Universal Login page for the app's own `client_id` and `redirect_uri` with
  `screen_hint=signup`. A rendered sign-up form on an internal or B2B-only app
  is the finding. `/dbconnections/signup` and `/dbconnections/change_password`
  are Stage B (one creates a user, the other emails one).
- Clerk: decode the publishable key, then read the instance environment from the
  Frontend API (verify the path and field names in `references/auth-platforms.md`).
  Sign-up mode `public` on an app meant to be invite-only is the finding.

### 3e. Self-hosted and smaller BaaS (`references/self-hosted-baas.md`)

| Platform | Version / state (read) | Exposure proof (read) |
|---|---|---|
| Hasura | `GET /v1/version`, `GET /healthz` | `POST /v1/metadata` `{"type":"export_metadata","version":2,"args":{}}` **with no headers** returning 200 = no admin secret = anonymous admin |
| Directus | `GET /server/ping`, `GET /server/health` | `GET /items/<collection>?limit=1`, `GET /users?limit=1` with no token |
| Strapi | `GET /admin/init` (`hasAdmin`), `GET /admin/project-type` | `GET /api/<plural>?pagination[pageSize]=1` with no token |
| PocketBase | `GET /api/health` | `GET /api/collections/<name>/records?perPage=1` with no token (rule set to empty string) |
| Appwrite | `GET /v1/health/version` (verify) | documents or files list with only `X-Appwrite-Project` (permission `Role.any()` or `Role.guests()` read) |
| Parse / Back4App | `GET /parse/health` (verify) | `GET /parse/classes/<Class>?count=1&limit=0` with the app ID (and client key if required) |
| Convex | none needed | `POST /api/query` (read) on a public query that returns other users' data |

`hasAdmin: false` on a reachable Strapi means the first visitor can register
the super admin: report it at once, do not register.

### 3f. Google `AIza` keys (`references/google-api-keys.md`)

```bash
K='<AIZA_KEY>'
# Gemini exposure (Truffle Security, Feb 2026): 200 = Generative Language API reachable with this key.
curl -s -o /dev/null -w '%{http_code}\n' "https://generativelanguage.googleapis.com/v1beta/models?key=$K"
```

`models` returns metadata, not customer data. The impact proof Truffle used is
`/v1beta/files?key=` (uploaded files) and `cachedContents`; read at most one
page and never call a generation endpoint (it bills). Maps checks are one
request per API, after the policy check.

---

## Step 4: Stage B, anything that writes, registers, emails or validates a secret

Stage B is **blocked by default**. It needs explicit written sign-off naming
the action, the tenant, the account or record, the number of requests and a
window. "The app is in scope" is not sign-off.

```
Stage B authorization
  Platform/tenant:  <project ref / pool ID / tenant domain>
  Action:           <e.g. one signup with tester+hcb1@yourdomain.example via SignUp>
  Blast radius:     creates one UNCONFIRMED user; may send one email to our inbox
  Reversibility:    account deleted by us via the app, or listed for the client to delete
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link>
```

| Always Stage B | Why |
|---|---|
| Any signup: Firebase `accounts:signUp` (including anonymous), Cognito `SignUp`, Supabase `/auth/v1/signup`, Auth0 `/dbconnections/signup`, Appwrite `POST /v1/account`, Parse `POST /parse/users`, PocketBase record create on an auth collection | Creates a user; often sends mail or SMS |
| Any reset, OTP, magic link or verification send | Emails or texts a person; never aim it at an address you do not own |
| Any write, update, delete, upload, mutation, Convex mutation or action, Supabase `POST /rpc/` | Changes production data; Moltbook's test write could not be reverted |
| Writing your own Cognito / Auth0 / Clerk attributes or metadata (`custom:*`, `user_metadata`, `unsafeMetadata`) | Changes authorization state, even on your own account |
| Calling any API with a leaked secret (service role, `sb_secret_`, `sk_live_`, admin secret, master key, deploy key) | Using a credential that is not yours; check the program's leaked-credential rule |
| Registering a Firebase installation or FCM token, any Remote Config fetch that needs one | A registration is a write |
| Password, ROPG or token-endpoint attempts, even with the test account | Lockout counters, alerts |
| Any rule, policy or setting change | Never done. Not even with a leaked admin key. |

The lowest-risk forms (one signup with your own address on a program that
allows test accounts, one write to a record you created, one validation call
with a leaked key) and their exact requests are in each reference file, each
under its own Stage B heading.

---

## Step 5: Grade on what you proved

| What you proved | Grade |
|---|---|
| Admin-equivalent secret in the client: Supabase `service_role` / `sb_secret_`, Parse master key, Hasura admin secret, Clerk `sk_live_`, Convex deploy key | Critical |
| Hasura with no admin secret (anonymous `export_metadata`), Strapi `hasAdmin: false` on prod, Directus public WebSocket with admin rights (CVE-2024-54151 range) | Critical |
| Anonymous read of PII, credentials, tokens or private messages (count-only proof plus one redacted record) | High to Critical, by data class and count |
| Any signed-in self-registered user can read all users' records | High (Medium if signup is invite-only) |
| Self-writable authorization attribute or metadata (`custom:role`, `user_metadata.role`, Firestore `isAdmin`) confirmed in Stage B on your own account | High to Critical |
| Write rules open to anonymous users, inferred from reads and app code, not exercised | Medium; High once a Stage B write on your own record confirms it |
| AIza key reaches Gemini `files` / `cachedContents` with customer data | High; Medium if only `models` answers |
| Open signup on an app documented as invite-only, with no data behind it yet | Low to Medium |
| AppSync `API_KEY` mode exposing non-public data | Medium to High |
| Public bucket holding user uploads (IDs, selfies) | High (Tea, 2025) |
| Unrestricted Maps key, billable APIs answer | Low or Informative; many programs exclude it |
| Version in range for a pre-auth CVE, unconfirmed | Medium, labelled unconfirmed |

### What is not a finding

| Observation | Why |
|---|---|
| Firebase `apiKey`, `projectId`, `appId`, `messagingSenderId` in a bundle | Identifiers by design; rules are the control |
| Supabase anon or `sb_publishable_` key | Public by design; RLS and grants are the control |
| Clerk `pk_live_`, Auth0 client ID and domain, Cognito pool and client IDs, Appwrite project ID, Parse app ID or JS key | Public client identifiers |
| AppSync API key in `API_KEY` mode guarding only public catalogue data | Working as designed |
| A Maps key restricted by referrer or app signature, or one only usable on Maps JavaScript | Restricted as Google recommends |
| A 401 / 403 / empty list on every read | Rules work |
| Open signup on a consumer app that is meant to be public | That is the product |
| A Firebase Dynamic Links URL returning 404 | The service shut down on 25 Aug 2025 |
| A legacy FCM server key | Legacy send API shutdown began 22 Jul 2024; Low at most unless it still sends (verify), and testing it sends a push |
| Introspection enabled with nothing sensitive in the schema | Informational at best; `hunt-graphql` decides |

---

## Step 6: Evidence

Follow `evidence-hygiene`: the exact request, timestamp and egress IP; the
count header or one record with every personal value redacted; where the config
was found (bundle URL and line, or app version and file); the sign-off reference
for any Stage B step; any test account you created, listed for deletion. Never
attach a dump. Never include a working secret: the first and last four
characters and its location are enough.

---

## Chain table

| Finding | Standalone | Where it goes next |
|---|---|---|
| Firebase / Supabase anonymous read of users | High | Report. Tokens or reset codes in the data feed `hunt-ato`. |
| Open signup + "any authenticated user" rules | High | One Stage B account proves cross-user read; `hunt-idor` for the per-record angle. |
| Cognito identity pool ID with unauth identities | Varies | `cloud-iam-deep` for the IAM role. |
| Cognito writable `custom:` attribute | High | Feeds the app's own role checks; `hunt-auth-bypass`. |
| Auth0 signup open on a B2B app, `user_metadata` trusted for roles | High | `hunt-oauth` for redirect URIs, `hunt-ato` for linking. |
| Hasura or Directus anonymous admin | Critical | Stop. Report the same day. |
| AppSync API key or Hasura unauthorized role | Medium | `hunt-graphql` for field-level authz and IDOR via `node`. |
| AIza key with Gemini enabled | Medium to High | Report to the program; Google's own VDP handled the platform side in 2025-26. |
| Strapi / Directus / Parse version in range | Medium | `hunt-sqli` references (filter oracles), `hunt-ldap` (Parse LDAP). |

---

## Validation checklist

- [ ] Asset and tenant confirmed in scope (`recon-scope-triage`); vendor-owned
      hosts were not tested beyond the client's own tenant.
- [ ] Config found offline; names harvested from code, not brute-forced.
- [ ] Every Stage A read used `shallow`, `pageSize=1`, `limit=1`, count-only or
      `count=1&limit=0`; nothing was paged or dumped.
- [ ] Every POST used was a read and is labelled as one.
- [ ] No signup, reset, OTP, write, mutation, installation registration or rule
      change without logged Stage B sign-off.
- [ ] Leaked secrets decoded offline; any validation call was Stage B and
      within the program's leaked-credential rule.
- [ ] Billable Google APIs: policy checked, one request per API, no generation.
- [ ] "Not a finding" table checked before writing the report.
- [ ] Test accounts created in Stage B listed for deletion; personal data redacted.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/firebase.md` | RTDB, Firestore, Storage, Auth / Identity Toolkit, Functions, Remote Config, FCM legacy keys, Dynamic Links, App Check, incidents 2024-2026 | firebaseio, firestore rules, firebase storage, google-services.json, accounts:signUp, remote config, fcm server key |
| `references/supabase-convex-nhost.md` | Supabase keys, PostgREST, RLS and grants, Auth settings, Storage, Edge Functions, pg_graphql, 2026 platform changes; Convex public functions; Nhost | supabase anon key, service_role, sb_secret, rls, rest/v1, convex.cloud, nhost.run |
| `references/aws-amplify-cognito.md` | aws-exports and amplify_outputs, user pool self-signup, user existence errors, writable attributes, AppSync API keys and introspection, Amplify CLI CVE | cognito user pool, amplify, appsync api key, da2-, custom attribute |
| `references/auth-platforms.md` | Auth0 / Okta CIC tenant discovery, signup, metadata, password reset, SDK CVEs; Clerk keys, Frontend API, SDK CVEs | auth0 tenant, dbconnections, user_metadata, clerk pk_live, clerk sk_live |
| `references/self-hosted-baas.md` | Hasura, Directus, Strapi, PocketBase, Appwrite, Parse Server and Back4App: state endpoints, exposure checks, first-admin states, CVEs 2022-2026 | hasura admin secret, directus public role, strapi hasAdmin, pocketbase api rules, appwrite role.any, parse master key |
| `references/google-api-keys.md` | AIza keys across Maps, Places and Gemini; billing, restrictions, program stance | google maps api key, places api, gmapsapiscanner, gemini api key |

---

## Related Skills & Chains

- `apk-redteam-pipeline`, `ios-redteam-pipeline`: extraction of the config
  files this skill starts from. Their Firebase probes are the 60-second
  version of Step 3a.
- `hunt-source-leak`, `offensive-osint`: bundles, source maps, secret regexes.
- `hunt-cloud-misconfig`: raw cloud storage, Cloud Run and serverless exposure.
- `cloud-iam-deep`: everything after a Cognito identity pool ID or a cloud key.
- `hunt-graphql`: AppSync, Hasura, pg_graphql and Parse GraphQL technique.
- `hunt-ato`, `hunt-forgot-password`, `hunt-oauth`, `okta-attack`: auth flows
  once a primitive exists.
- `hunt-sqli` (`orm-leak-and-filter-languages.md`), `hunt-ldap`: Strapi,
  Directus and Parse CVE classes already written up there.
- `evidence-hygiene`, `triage-validation`, `report-writing`: redaction, false
  positive gates, write-up.

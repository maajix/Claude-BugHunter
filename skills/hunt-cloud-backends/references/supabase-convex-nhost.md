# Supabase, Convex and Nhost

All three put a database-shaped API in front of the client and leave
authorization to something the developer configures: Postgres grants and Row
Level Security (Supabase), function code (Convex), Hasura permissions (Nhost).

## Supabase

### Keys

| Key | Form | Meaning |
|---|---|---|
| `anon` (legacy) | JWT, payload `"role":"anon"` | Public. Everything it can do is decided by grants and RLS. |
| `service_role` (legacy) | JWT, payload `"role":"service_role"` | Bypasses RLS. In a client bundle it is Critical by itself. |
| `sb_publishable_...` | opaque | Public replacement for `anon`. |
| `sb_secret_...` | opaque, not a JWT | Replacement for `service_role`; bypasses RLS. Supabase returns 401 when it is used from a browser (matched on User-Agent), so a page that "works" with it was not a browser call. |

Supabase's migration guide says the legacy JWT keys are deprecated by the end
of 2026. Decode JWT keys offline (SKILL.md Step 1); never send a key to an
online decoder.

### Platform changes that move the baseline (2026)

| Date | Change | Effect on testing |
|---|---|---|
| 17 Feb 2026 changelog; new projects 11 Mar, existing 8 Apr 2026 | `GET /rest/v1/` (the PostgREST OpenAPI document) no longer accepts the anon key: `"Access to schema is forbidden"`, hint "only allowed using a secret API key". | Table names now come from the bundle. Older guides that start with the OpenAPI dump are out of date. |
| Changelog Apr-May 2026 | pg_graphql no longer enabled by default on new projects (from 18 May 2026); pg_graphql 1.6.0 turns introspection off by default. | `/graphql/v1` may be absent, or answer data queries but not `__schema`. |
| 28 Apr 2026 changelog; new projects from 30 May 2026, existing projects **30 Oct 2026** | New tables in `public` no longer get automatic `select/insert/update/delete` grants for `anon` and `authenticated`. Existing tables keep their grants. | Tables created before the cut-over keep the old default: grants to `anon` plus whatever RLS says. Old projects remain the richer target. |

### Data API (PostgREST) reads

PostgREST executes GET and HEAD in a **READ ONLY** transaction, including GET
calls to `/rpc/<fn>` (functions marked VOLATILE are POST-only; a writing
function fails under GET). That makes GET a safe probe by construction.

```bash
U='https://<ref>.supabase.co'; A='<ANON_OR_PUBLISHABLE_KEY>'
# Count only (no rows returned).
curl -s -o /dev/null -D - "$U/rest/v1/<table>?select=*" -H "apikey: $A" \
     -H "Prefer: count=exact" -H "Range: 0-0" | grep -i '^content-range'
# One row, only the columns you need to classify the data.
curl -s "$U/rest/v1/<table>?select=id,email&limit=1" -H "apikey: $A"
# A STABLE / IMMUTABLE function named in the app code, via GET (read-only transaction).
curl -s "$U/rest/v1/rpc/<fn>?<arg>=<value>" -H "apikey: $A"
```

| Response | Reading |
|---|---|
| `Content-Range: 0-0/12345` | 12,345 rows visible to `anon`. With personal data, that is the finding. |
| `Content-Range: */0` or `[]` | RLS on and filtering everything, or an empty table. Not a finding. |
| `401` / `42501` permission denied | No grant to `anon` on that table. |
| `404` / `PGRST205` "Could not find the table" (verify code) | Not exposed through the Data API, or wrong name. Error hints sometimes suggest the right table name. |

Then repeat the count with a test user's access token (`Authorization: Bearer
<user JWT>`) if the program provides one: RLS policies written as
`using (true)` for `authenticated` expose every user's rows to every user. If
`GET /auth/v1/settings` shows `disable_signup: false`, anyone can become
`authenticated`.

RLS gaps that recur: RLS enabled with a permissive `select` policy; RLS on the
table but a **view** in `public` that reads it without `security_invoker`;
`security definer` RPC functions exposed to `anon`; storage policies that check
the bucket but not the path owner.

### Auth settings (read)

```bash
curl -s "$U/auth/v1/settings" -H "apikey: $A"
```

Fields (from `supabase/auth` `internal/api/settings.go`): `external.{email,
phone, anonymous_users, google, github, ...}`, `disable_signup`,
`mailer_autoconfirm`, `phone_autoconfirm`, `sms_provider`, `saml_enabled`.
`disable_signup: false` plus `mailer_autoconfirm: true` means anyone gets a
working `authenticated` session without verifying an email.
`external.anonymous_users: true` means anonymous sign-ins also yield
`authenticated`-role JWTs (with an `is_anonymous` claim). Policies that check
only the role treat them as real users.

### Storage

```bash
# (read, POST) one object name from a bucket named in the app code.
curl -s "$U/storage/v1/object/list/<bucket>" -H "apikey: $A" -H "Authorization: Bearer $A" \
     -H 'Content-Type: application/json' -d '{"prefix":"","limit":1}'
# Bucket list. Usually empty for anon unless storage.buckets has a select policy.
curl -s "$U/storage/v1/bucket" -H "apikey: $A" -H "Authorization: Bearer $A"
```

Objects in a **public** bucket are served from
`/storage/v1/object/public/<bucket>/<path>` to anyone who knows the path;
listing still depends on the `storage.objects` select policy. A public bucket
named `avatars` is intended. One named `kyc`, `documents` or `invoices` is not.

### Edge Functions

`https://<ref>.supabase.co/functions/v1/<name>`. JWT verification is on by
default and disabled per function with `--no-verify-jwt` (used for webhooks).
A function deployed that way and returning data without its own checks is the
finding. Calling one is only Stage A if the code shows it only reads.

### Supabase Stage B

Signup (`POST /auth/v1/signup`), recovery and OTP sends, any `POST`, `PATCH` or
`DELETE` to `/rest/v1/`, `POST /rpc/`, uploads, and any call with a
`service_role` / `sb_secret_` key are Stage B under SKILL.md Step 4.

Validating a leaked secret key, if the program allows it, is one count-only
request:

```bash
# Stage B: written sign-off required; the program must allow validating leaked keys.
curl -s -o /dev/null -D - "$U/rest/v1/<table>?select=id" -H "apikey: <SECRET_KEY>" \
     -H "Authorization: Bearer <SECRET_KEY>" -H "Prefer: count=exact" -H "Range: 0-0" | grep -i '^content-range'
```

A count higher than the anon count proves RLS bypass. Do not read rows with it.

### Supabase incidents, research and advisories

| Date | What | Source |
|---|---|---|
| Mar-May 2025 | CVE-2025-48757: Lovable-generated apps shipped Supabase tables without adequate RLS; Matt Palmer found about 170 of 1,645 showcased apps readable or writable with the anon key. NVD record notes the vendor disputes it (customer responsibility). | <https://mattpalmer.io/posts/CVE-2025-48757/>, <https://nvd.nist.gov/vuln/detail/CVE-2025-48757> |
| May 2025 | CVE-2025-48370: `auth-js` admin helpers did not require UUIDs, allowing path traversal to the wrong admin endpoint (fixed in 2.70.0). Server-side SDK misuse, not a client config issue. | <https://github.com/supabase/auth-js/security/advisories/GHSA-8r88-6cj9-9fh5> |
| Jul 2025 | General Analysis: a Supabase MCP server running with `service_role` read a private table on instructions planted in a support ticket (prompt injection), bypassing RLS. Hunt this through `hunt-llm-ai`. | <https://simonwillison.net/2025/Jul/06/supabase-mcp-lethal-trifecta/> |
| Nov 2024 | GHSA-3529-5m8x-rpv3: email link poisoning in self-hosted Supabase Auth v2.67.1-v2.163.0 (fixed v2.163.1); hosted platform patched. | <https://github.com/supabase/auth/security/advisories/GHSA-3529-5m8x-rpv3> |
| Feb 2026 | Moltbook (Wiz, 2 Feb 2026): Supabase URL and publishable key in a Next.js chunk; no RLS on `agents`, `owners` and others; about 1.5M agent API tokens, 35k emails and private messages readable; writes possible. Wiz's test `PATCH` on a post could not be reverted after write access was blocked. | <https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys> |
| Mar 2026 | CVE-2026-31813: Supabase Auth before 2.185.0 issued sessions for arbitrary users from crafted ID tokens when the Apple or Azure provider is enabled. Self-hosted version gate. | <https://github.com/supabase/auth/security/advisories/GHSA-v36f-qvww-8w8m> |

## Convex

- Deployment URL: `https://<name>.convex.cloud` (HTTP actions on
  `https://<name>.convex.site`). The JS client is built with
  `new ConvexReactClient(<url>)` or `ConvexHttpClient`.
- Convex docs: "By default your Convex functions are public and accessible to
  clients", and "Internal functions can only be called by other functions and
  cannot be called directly from a Convex client." Every exported `query`,
  `mutation` and `action` is an API endpoint; authorization is whatever the
  function checks in code (`ctx.auth`).
- Function names: the bundle calls `api.<module>.<fn>` (a proxy), which maps to
  the path `<module>:<fn>`; nested files become `<dir>/<file>:<fn>` (verify
  on the target's bundle).

```bash
# (read) One public query, no auth header. Docs form: path + args + format "json".
curl -s https://<name>.convex.cloud/api/query -H 'Content-Type: application/json' \
  -d '{"path":"<module>:<fn>","args":{},"format":"json"}' | head -c 1500
```

A query that returns other users' records without a session is the finding.
Mutations and actions (the `/api/mutation` and `/api/action` counterparts,
verify paths in the Convex HTTP API docs) are Stage B. A leaked deploy key
(`Authorization: Convex <key>`, docs: "full read and write access to your
Convex data") is Critical exposure; do not use it.

Advisory: GHSA-52c3-c7j7-vjx6 / CVE-2026-97691 (Aug 2026), an undisclosed
"unauthorized data access" bug in **self-hosted** Convex images before
`c0cb7ae`; details withheld by the vendor. Version-gate only.
<https://github.com/get-convex/convex-backend/security/advisories/GHSA-52c3-c7j7-vjx6>

## Nhost

- Nhost Cloud services follow `https://<subdomain>.<service>.<region>.nhost.run`
  with services `auth`, `graphql`, `hasura`, `storage`, `functions`, `db`
  (Nhost docs). Paths under each host, such as `/v1` on the GraphQL host, need
  checking against the SDK version in the bundle (verify).
- The data layer is Hasura: run the Hasura checks from `self-hosted-baas.md`
  (no admin secret, unauthorized role, leaked `x-hasura-admin-secret`). Nhost
  Cloud projects are created with an admin secret; a client bundle that carries
  it is the finding.
- Advisory: CVE-2026-41574 / GHSA-6g38-8j4p-j3pr (Apr 2026, critical): Nhost
  auto-linked OAuth identities to existing accounts by email while some provider
  adapters marked unverified emails as verified (Discord, Bitbucket, Microsoft).
  Account takeover by registering the victim's email at the provider; fixed in
  the April 2026 release. The test is `hunt-oauth` territory and needs a victim
  account you own: Stage B.
  <https://github.com/nhost/nhost/security/advisories/GHSA-6g38-8j4p-j3pr>

## Sources (checked October 2026)

- Supabase API keys: <https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys>
- OpenAPI change: <https://supabase.com/changelog/42949-breaking-change-removing-access-to-openapi-spec-via-the-anon-key>
- Grants change: <https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically>
- pg_graphql introspection: <https://supabase.com/changelog/46320-breaking-change-in-pg-graphql-1-6-0-graphql-introspection-disabled-by-default>
- PostgREST transactions: <https://docs.postgrest.org/en/stable/references/transactions.html>
- Supabase Auth settings source: <https://github.com/supabase/auth/blob/master/internal/api/settings.go>
- Supabase storage access control: <https://supabase.com/docs/guides/storage/security/access-control>
- Convex HTTP API: <https://docs.convex.dev/http-api/>; internal functions: <https://docs.convex.dev/functions/internal-functions>
- Nhost URL format: <https://docs.nhost.io/platform/cloud/subdomain>

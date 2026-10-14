# Auth0 / Okta Customer Identity Cloud and Clerk

Managed auth platforms embedded in SPAs and mobile apps. The client ID, tenant
domain and publishable key are public. Findings are tenant settings the app
owner chose: who may sign up, which grants a public client allows, which user
fields the app trusts for authorization.

Workforce Okta, the 2024 CIC cross-origin credential-stuffing incident and the
Okta / Auth0 advisory table are in `okta-attack`; this file does not repeat
them. Redirect URI and OAuth flow bugs go to `hunt-oauth`.

## Auth0 / Okta CIC

### Where the config is

- SPA: `createAuth0Client({ domain, clientId, authorizationParams: { audience } })`,
  `<Auth0Provider domain=... clientId=...>`, `nextjs-auth0` env names
  (`AUTH0_ISSUER_BASE_URL` / `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`).
- Android: `com_auth0_domain` and `com_auth0_client_id` string resources.
  iOS: `Auth0.plist` with `ClientId` and `Domain`.
- Tenant domains: `<tenant>.auth0.com`, `<tenant>.<region>.auth0.com`, or a
  custom domain (`login.<client>.example`) that CNAMEs to Auth0.
- `AUTH0_CLIENT_SECRET` or a Management API token (`/api/v2/` with a Bearer
  token) in a client bundle is the critical case. Do not use it.

### Stage A

```bash
T='https://<tenant-domain>'
curl -s "$T/.well-known/openid-configuration" | head -c 1200   # issuer, endpoints, grant types advertised
curl -s "$T/.well-known/jwks.json" | head -c 300
```

Sign-up visibility for the app's own client, read-only (a page load; the
`/authorize` request creates no account):

```
https://<tenant-domain>/authorize?client_id=<client-id>&response_type=code&redirect_uri=<app-callback>&scope=openid&screen_hint=signup
```

A rendered sign-up form for a B2B, staff-only or invite-only app is the
finding: the database connection's "Disable Sign Ups" switch is off. The
switch applies per connection, so the API path (`/dbconnections/signup`) can
stay open even when the hosted page is customised to hide the link.

Legacy Lock fetched client settings from `/client/<client_id>.js` (on the
tenant or `cdn.<region>.auth0.com`), and older guides read enabled
connections and sign-up flags from it. Auth0 community threads describe it as
a legacy URL for outdated Lock versions; whether it still answers in 2026 is
unconfirmed (verify). Do not build a finding on it.

### What the findings are

| Finding | Notes |
|---|---|
| Public sign-up on an app that should be closed | Self-registered users then hold tokens the API accepts. Prove the API trusts them in Stage B. |
| Authorization read from `user_metadata` | Auth0 docs: `user_metadata` "can be edited by logged in users" and "should not be used as a secure data store"; `app_metadata` cannot be edited by users. `/dbconnections/signup` accepts a `user_metadata` object (up to ten properties). An app or Action that copies `user_metadata.role` into a token claim is a privilege-escalation path. |
| Password (ROPG) grant enabled on a public client | Lets scripts sign in without the hosted page, skipping bot detection and some MFA flows. Proving it is an authentication attempt with the test account: Stage B. |
| Social or enterprise connection auto-linking on unverified email | Account linking keyed on email where the IdP does not verify email gives takeover. Auth0's linking is done in Actions or extensions by the tenant; test through `hunt-oauth` / `hunt-ato` with accounts you own. |
| Cross-origin authentication enabled with broad allowed origins | Context for credential stuffing (Okta advisory, 2024). `okta-attack` owns it. |

### SDK advisories with a client-visible footprint (version-gate only)

| ID | Package | Issue | Fixed |
|---|---|---|---|
| CVE-2026-42280 / GHSA-8qjv-jj2q-x832 | `auth0-js` 8.11.0-9.32.0 | Under specific preconditions returns user profile data for a valid access token paired with a crafted invalid ID token; matters when access control relies on Actions rules | 10.0.0 |
| CVE-2025-48947 / GHSA-f3fg-mf2q-fj3f | `@auth0/nextjs-auth0` | Session cookies could be cached by a CDN | see advisory |
| CVE-2025-67490 / GHSA-wcgj-f865-c7j7 | `@auth0/nextjs-auth0` | Improper request caching lookup | see advisory |
| CVE-2025-47275 / GHSA-g98g-r7gf-2r25 | `auth0/auth0-php` | Brute-forceable authentication tags of CookieStore sessions | see advisory |
| CVE-2025-48951 / GHSA-v9m8-9xxp-q492 | `auth0/auth0-php` | Deserialization of untrusted data | see advisory |
| CVE-2022-29172 / GHSA-7ww6-75fj-jcj7 | `auth0-lock` | Cross-site scripting | see advisory |

Version evidence: the loaded `auth0-js` / `auth0-spa-js` bundle version, the
`Auth0-Client` request header (base64 JSON naming the SDK and version), or
`package.json` from a source map.

### Auth0 Stage B

```bash
# Stage B: written sign-off required. Creates one user in the named connection; may send a verification email.
curl -s -X POST "https://<tenant-domain>/dbconnections/signup" -H 'Content-Type: application/json' \
  -d '{"client_id":"<client-id>","connection":"<connection>","email":"tester+hcb@yourdomain.example","password":"<policy-compliant>"}'
```

Auth0 documents 200 (created), 400 (bad request) and 409 (exists). A refusal
when sign-ups are disabled comes back as a 4xx with an error body; record it
verbatim (exact wording unconfirmed, verify).

`POST /dbconnections/change_password` sends a reset email. Auth0's reference
lists a 404 "User not found" response alongside the 200 text, so it may act
as an enumeration oracle on some tenants (verify). Only ever against your own
address, once, under sign-off. It is `hunt-forgot-password` territory beyond
that.

## Clerk

### Keys and hosts

- Publishable key: `pk_live_...` / `pk_test_...`, public. The part after the
  prefix is base64 of the instance's Frontend API host (verify against the
  key you hold; decode offline). Production hosts are usually
  `clerk.<app-domain>`; development instances use a Clerk-hosted
  `*.clerk.accounts.dev` host.
- Secret key: `sk_live_...` / `sk_test_...`. Grants the Backend API
  (`https://api.clerk.com/v1/...`): users, sessions, organizations. In a client
  bundle it is Critical. Do not use it.

### Stage A

- Decode the publishable key offline.
- The browser SDK loads the instance's public environment (sign-up mode,
  identifiers, enabled social providers) from the Frontend API at start-up.
  Read that same response from the browser's network panel while loading the
  app normally, rather than scripting it. Exact endpoint and field names were
  not confirmed for this skill (verify against the SDK version in the bundle).
- What you are looking for: sign-up open on an app the program describes as
  invite-only or restricted; social providers that allow unverified email.

### What the findings are

| Finding | Notes |
|---|---|
| Open sign-up on a restricted app | Same logic as Auth0. Prove what a fresh account can reach in Stage B. |
| Authorization from client-writable metadata | Clerk distinguishes metadata the user can write from the browser from metadata only the backend can set. An app that authorizes on the user-writable kind is the Clerk equivalent of `user_metadata.role` (verify field names in Clerk's user metadata docs). |
| Route protection only in middleware | CVE-2026-41248 below. |
| Leaked `sk_live_` | Critical exposure on its own. |

### SDK advisories (version-gate only)

| ID | Package | Issue | Fixed |
|---|---|---|---|
| CVE-2024-22206 / GHSA-q6w5-jg5q-47vg | `@clerk/nextjs` 4.7.0-4.29.2 | `auth()` / `getAuth()` logic flaw: unauthorized access or privilege escalation in API routes | 4.29.3 |
| CVE-2025-53548 / GHSA-9mp4-77wg-rwx9 | `@clerk/backend` | Webhook verification weakness | see advisory |
| CVE-2026-34076 / GHSA-gjxx-92w9-8v8f | `@clerk/backend` | SSRF in the opt-in Frontend API proxy may send secret keys to an unintended host | see advisory |
| CVE-2026-41248 / GHSA-vqx2-fgx2-5wq9 | `@clerk/nextjs`, `@clerk/nuxt`, `@clerk/astro`, `@clerk/shared` | `createRouteMatcher` middleware gating bypass with crafted requests; sessions not compromised, but downstream handlers that rely only on middleware are reachable | e.g. `@clerk/nextjs` 5.7.6 / 6.39.2 / 7.2.1 |
| CVE-2026-42349 / GHSA-w24r-5266-9c3c | Clerk SDKs | Authorization bypass when combining organization, billing or reverification checks | see advisory |

CVE-2026-41248 is testable from outside only by requesting a protected route
in the way the advisory describes and seeing whether the handler answers
without a session. The advisory withholds the crafted form; do not guess at
it on production. Version-gate and report.

## Sources (checked October 2026)

- Auth0 signup endpoint: <https://auth0.com/docs/api/authentication/signup/create-a-new-user>
- Auth0 change password: <https://auth0.com/docs/api/authentication/change-password/change-password>
- Auth0 metadata: <https://auth0.com/docs/manage-users/user-accounts/metadata>
- Auth0 cross-origin authentication: <https://auth0.com/docs/authenticate/login/cross-origin-authentication>
- Lock client config URL (community): <https://community.auth0.com/t/lock-sdk-fails-404-on-cdn-for-clientid-js-file/145410>
- GitHub advisories for the packages above: <https://github.com/advisories>

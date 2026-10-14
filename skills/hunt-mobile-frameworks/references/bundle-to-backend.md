# Bundle to backend: routing what the app ships to the skill that tests it

The framework references end with an inventory: hosts, route strings, GraphQL
operations, proto or service names, socket URLs, OAuth clients, BaaS configs,
bucket names, keys and feature flags. This file maps each artefact to the skill
that owns testing it, and covers the backend bugs that only show up because the
client is a mobile app.

Nothing here repeats those skills. Each row says which skill to load, which
step to start at, and where Stage B begins.

## 1. Normalise the inventory first

Collect everything into one file per app build before testing anything. Use one
row per artefact: `type, value, source file, app version, platform`. Tag every
row with the build it came from, because Section 4 depends on comparing builds.

| Framework | Where the inventory comes from | Reference |
|---|---|---|
| Flutter | Blutter `pp.txt` / `objs.txt`, `strings` on `libapp.so`, reFlutter `dump.dart` | `flutter.md` |
| React Native | `hbc-decompiler` output or the plain JS bundle, `strings.xml` / `Info.plist` keys | `react-native.md` |
| Xamarin / MAUI | decompiled assemblies (ILSpy), `appsettings*.json` in assets | `xamarin-maui.md` |
| Unity | `dump.cs` / `script.json` (Il2CppDumper) or Mono `Assembly-CSharp.dll`, `StreamingAssets/` | `unity.md` |
| Cordova / Capacitor / Ionic / TWA | `www/` or `public/` JS, `config.xml`, `capacitor.config.json`, `assetlinks.json` | `hybrid-webview.md` |
| KMP / Compose MP | jadx on Android; `strings` and symbols on the iOS framework | `kotlin-multiplatform.md` |

The generic secret catalog and regexes are in `apk-redteam-pipeline` Stage 3
and `offensive-osint/references/secret-patterns.md`. Run them over the
framework output, not only over `classes.dex`: in a Flutter, RN, Unity or
Xamarin app the interesting strings are almost never in the DEX.

A value being present is not a finding. Public client config (Firebase web
API key, Supabase anon or publishable key, Cognito client ID without a secret,
Auth0 domain, Maps key) is public by design. The finding is what the backend
lets that value do.

## 2. Decision table: artefact type to skill

| Artefact in the bundle | Load | Start at | Stage B begins at |
|---|---|---|---|
| REST base URLs, route strings, `/api/vN` prefixes, Retrofit / Dio / Refit / axios route constants | `hunt-spa-api` | Step 3 (find a gated control route), then Step 4 unauthenticated differential | any create, upload, signup or state change |
| Routes or hosts that the web app no longer calls; `v1` in the app, `v3` on the web | `hunt-shadow-api` | Stage 3 behavioural diff between versions | rate-limit bursts beyond the program's ceiling; any write |
| Request DTOs with privileged-looking fields (`role`, `isAdmin`, `tier`, `verified`, `price`) | `hunt-api-misconfig` | Mass assignment, read the DTO first | sending the extra field on any write endpoint, even on your own account |
| GraphQL endpoint, operation names, persisted-query hashes, Apollo / urql / Relay artefacts | `hunt-graphql` | Attack surface signals, then authz on queries | every mutation |
| `.proto`-derived class names, gRPC service paths (`/pkg.Service/Method`), grpc-web, Connect | `hunt-grpc` | Phase 5 (rebuild descriptors from what the app ships), then Phase 3 | any state-changing method |
| `wss://` URLs, socket.io namespaces, SignalR hubs, Phoenix channels, MQTT brokers | `hunt-websocket` | Phase 1 then Phase 3 (per-message auth) | publishing to a topic or room other users read |
| OAuth / OIDC client IDs, redirect URIs with custom schemes, AppAuth config, `client_secret` in the app | `hunt-oauth` | Mobile deep-link and token endpoint sections | completing a flow as anyone but your own test user |
| JWTs, JWKS URLs, HMAC signing secrets, request-signing keys | `hunt-jwt-crypto` | Recon, then offline secret checks | presenting a forged token to production |
| Firebase, Supabase, Amplify / Cognito, Auth0, Clerk, Appwrite, Parse, Hasura, PocketBase, Convex config | `hunt-cloud-backends` | Step 1 fingerprint, Step 3 count-only reads | Step 4: signup, write, reset, calling with a leaked secret |
| S3 / GCS / Azure Blob / R2 bucket or container names, CDN origins | `hunt-cloud-misconfig` | S3 / GCS / Azure Blob section, list and anonymous read checks | any write or ACL test |
| Cloud keys: AWS access key pairs, GCP service-account JSON, Azure SAS or connection strings, Cognito identity pool ID | `cloud-iam-deep` | Credential identification, then its Stage A: one identity call | reading contents, any write, any role assumption |
| Third-party SaaS keys (Stripe, Twilio, SendGrid, Algolia admin, Mapbox secret, Sentry auth, OpenAI) | `offensive-osint` secret validators (§23) | the read-only validator for that provider | any call that sends, charges or creates |
| In-app assistant, chat or support bot endpoints; LLM provider keys; RAG or tool-calling schemas | `hunt-llm-ai` | False-positive gate, then indirect injection and IDOR-via-AI | anything that makes the model act for another user |
| Payment SDK config, in-app purchase receipt endpoints | `hunt-payment-api`, `hunt-business-logic` | read-only receipt and entitlement checks | Stage B: any receipt replay or purchase-state change |

Two more artefacts route outside this table:

- **Hosts not seen in passive recon** (pinned-certificate SANs, staging hosts,
  internal names) go back to `recon-scope-triage` before any request. Mobile
  apps often embed third-party or vendor hosts that are not the program's.
- **OTA and live-update channels** (CodePush, EAS Update, Shorebird,
  Capacitor live updates) stay in this skill: SKILL.md Step 5. They are
  read-only here.

## 3. Mobile-specific backend bugs

These are backend bugs. The app only makes them visible. Proof is always done
with test accounts and test installs you control.

### 3a. Device ID used as authentication

Symptom: the API identifies the caller by an install ID, device ID,
advertising ID, push token or an app-generated UUID sent in a header or body
(`X-Device-Id`, `deviceId`, `installationId`), with no session token, or with a
session token the server never checks against it.

Read-only check with your own two installs:

1. Install the app on two test devices or two clean emulator profiles, each with
   its own test account. Record each install's identifier from the proxy.
2. Replay one read-only request from install A with install A's session removed.
   If the response is still A's data, the identifier alone authenticates.
3. Swap in install B's identifier on install A's request. B's data returning is
   the full proof. Both sides belong to you, so nothing reaches a real user.

Proving it against a real user's identifier is a different action: it reads
another person's data. It requires Stage B written sign-off naming the
endpoint and the single record, and many programs forbid it. The two-install
proof is enough to report. Grade it on what the identifier exposes and on how
guessable it is (sequential, timestamp-derived, or exposed elsewhere in the
API).

### 3b. Version-gated features visible in the bundle

Builds ship code for features that are not launched yet, gated by a remote
flag, a minimum app version, a country or an A/B bucket. The routes are in the
bundle even when the UI never shows them.

- Harvest flag names and gated routes. Typical sources are Remote Config
  defaults, LaunchDarkly, Statsig, Unleash or ConfigCat keys, `featureFlags`
  objects, and `if (version >= ...)` branches.
- For each gated route, send the read-only request the code would send. A
  response with data means the server does not enforce the gate. The client
  hides the feature and the server serves it anyway.
- Treat it as an authorization finding only if the feature exposes data or
  capability the account should not have yet: premium-only content, an
  unreleased admin view, another region's data. "I can see an unreleased
  screen" alone is informational.
- Calling a gated write route, or flipping your own account's flag
  server-side, is Stage B.

### 3c. Debug and staging endpoints

Mobile builds leak `debug`, `staging`, `qa`, `dev` and `mock` hosts, Swagger
paths, log-upload endpoints, test-login routes (`/auth/test`,
`/debug/impersonate`), and `BuildConfig.DEBUG` branches that the release build
still compiles in.

- Confirm ownership and scope first (`recon-scope-triage`). Staging is often
  out of scope, or hosted by an agency.
- Use read-only probes only: does the host answer, does it serve a spec, does a
  debug route answer unauthenticated. Hand the spec to `hunt-shadow-api`
  Stage 2.
- An impersonation or test-login route that works unauthenticated is critical.
  Stop at the response that shows it would work, such as a schema, an error
  naming the user field, or a 200 on your own test user. Using it as anyone else
  is Stage B, and usually not authorizable.
- Log-upload endpoints are writes. Do not upload to production to "see if it
  works".

### 3d. Unversioned or mobile-only APIs

Many backends run a separate mobile gateway (`m-api`, `mobile-api`,
`app-gateway`, `bff-mobile`) or accept a platform header (`X-Platform:
android`, `X-App-Version`, a mobile `User-Agent`) that routes requests to a
different stack from the web one.

- Diff the same operation through the web route and the mobile route
  (`hunt-shadow-api` Stage 3). Common deltas: no rate limit, no MFA step-up, no
  CAPTCHA, older validation, extra fields in responses.
- The minimum-version header is often the only thing keeping old app versions
  off the old API. Send an old `X-App-Version` value from a build you diffed
  (Section 4) and see whether the old behaviour is still served.
- A static "app key" or HMAC request-signing secret shipped in the bundle is not
  authentication. Anyone with the APK holds it. Report it only when the server
  treats it as authentication, and route the signing scheme to
  `hunt-jwt-crypto` for weaknesses.
- Rate-limit regressions get proved with the smallest burst that shows the
  difference, within the program's ceiling (`engine/throttle.py`). Chain to
  `hunt-brute-force` only with sign-off.

### 3e. Other recurring mobile backend patterns

| Pattern | Where it shows | Route |
|---|---|---|
| OTP, reset code or verification state returned in the API response to the app | proxy capture of your own flow | `hunt-mfa-bypass`, `hunt-forgot-password` |
| Integrity or attestation token (Play Integrity, App Attest) checked by the app only, or accepted when missing | server response with and without the header, on your own account | `hunt-auth-bypass` (the device-side resilience checks belong to `hunt-mobile-android` / `hunt-mobile-ios`) |
| Client-computed price, balance, score or entitlement accepted by the server | Unity and game backends, wallets, loyalty apps | `hunt-business-logic`; any submission is Stage B |
| Push or device registration endpoints keyed by user ID without ownership check | registration request in the proxy | `hunt-idor`; registering a device to another account is Stage B and usually not authorizable |
| Pinned certificate for a host absent from DNS recon | `*.cer` / `*.pem` / pin hashes in assets | `recon-scope-triage`, then this table |
| Third-party SDK keys with write scopes (analytics admin, crash-report auth tokens, search admin keys) | strings, config JSON | `offensive-osint` §23 validator, read-only |

## 4. Build-to-build diffing feeds the backend tests

`app-store-recon.md` Section 5 covers pulling older builds. For the backend,
the useful diffs are:

- **Endpoints removed from the app but still live.** Run the old build's route
  list through `hunt-shadow-api` Stage 1. A route the app stopped calling is
  the classic zombie.
- **Secrets rotated in a newer build.** The older build's key may still be
  valid. Validate it read-only, once, in the owning skill.
- **Pins and hosts that changed.** New hosts go to scope triage.
- **Flags that flipped.** A flag that defaulted to `true` in an old build and
  `false` now marks a feature the server may still serve.

## 5. Grading reminders

- Public client config with correct backend rules is not a finding.
- A secret is only a finding when it does something. Prove that with the
  owning skill's read-only validator.
- "Endpoint found in the APK" is recon, not a vulnerability. The report needs
  the backend behaviour: unauthenticated data, cross-account read on your two
  accounts, or a missing control relative to the web route.
- Pinning absent, debuggable flags and obfuscation absent are platform
  findings for `hunt-mobile-android` / `hunt-mobile-ios`, usually low or
  informational, and not this skill's output.

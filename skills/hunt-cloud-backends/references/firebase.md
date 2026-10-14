# Firebase: what to test, how to read the answer

Firebase hands the client a config (`apiKey`, `projectId`, `appId`,
`databaseURL`, `storageBucket`) and pushes authorization into **Security
Rules** for Realtime Database (RTDB), Cloud Firestore and Cloud Storage. The
config is public by design. Every finding is a rule that allows more than the
app needs, seen from outside. Rules are never readable anonymously, so the
report says "the rules allow X", inferred from the response.

Extraction of `google-services.json` and `GoogleService-Info.plist` belongs to
`apk-redteam-pipeline` and `ios-redteam-pipeline`. Raw `storage.googleapis.com`
listing of the same bucket belongs to `hunt-cloud-misconfig`.

## Config fields and where they point

| Field | Web key | Android (`google-services.json`) | iOS (`GoogleService-Info.plist`) | Used for |
|---|---|---|---|---|
| Project ID | `projectId` | `project_info.project_id` | `PROJECT_ID` | Firestore, Functions, Remote Config |
| RTDB URL | `databaseURL` | `project_info.firebase_url` | `DATABASE_URL` | RTDB REST |
| Bucket | `storageBucket` | `project_info.storage_bucket` | `STORAGE_BUCKET` | Storage REST |
| API key | `apiKey` | `client[].api_key[].current_key` | `API_KEY` | Identity Toolkit, Firestore `key=`, other Google APIs on the same project |
| App ID | `appId` | `client[].client_info.mobilesdk_app_id` | `GOOGLE_APP_ID` | Remote Config, Installations |

Also grep the code for the names the rules protect: `collection(db, '...')`,
`doc(db, '...')`, `ref(db, '...')`, `ref(storage, '...')`,
`httpsCallable(functions, '...')`. The client SDKs cannot list collections
(iosiro's Baserunner README states this for the JS SDK), so names come from the
code or nowhere.

## Realtime Database

URL forms: `https://<db>.firebaseio.com` and, for non-US instances,
`https://<db>.<region>.firebasedatabase.app`. The default instance is usually
`<project-id>-default-rtdb` on newer projects and `<project-id>` on older ones;
use the `databaseURL` from the config rather than guessing.

```bash
DB='https://<db-from-config>'
# Top-level keys only. Firebase docs: shallow "cannot be used with any of the filtering data query parameters".
curl -s "$DB/.json?shallow=true" | head -c 600
# One child of one node named in the app code (orderBy is required with limitToFirst).
curl -s "$DB/<node>.json?orderBy=%22%24key%22&limitToFirst=1" | head -c 1500
```

| Response | Reading |
|---|---|
| `{"error":"Permission denied"}` (401) | Rules deny anonymous read at that path. Try the specific node paths from the code; rules are per path. |
| `{"users":true,"orders":true}` from `shallow=true` | Anonymous read at the root. Critical if those nodes hold personal data; the key names are the evidence. |
| `null` | Readable but empty, or the path does not exist. |
| Redirect or error naming another host | Wrong region or instance. Use the config value. |

RTDB rules (`/.settings/rules.json`) need the database owner's credentials;
they are not an anonymous read (verify).

## Cloud Firestore

```bash
P='<PROJECT_ID>'; K='<API_KEY>'
# List (read): first document of a collection named in the code.
curl -s "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/<collection>?pageSize=1&key=$K" | head -c 1500
# runQuery (read, POST): same proof, also works for collection groups and filters the rules require.
curl -s -X POST "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents:runQuery?key=$K" \
  -H 'Content-Type: application/json' \
  -d '{"structuredQuery":{"from":[{"collectionId":"<collection>"}],"limit":1}}' | head -c 1500
```

- Denied: HTTP 403 with `PERMISSION_DENIED` ("Missing or insufficient
  permissions.", verify the wording per API version).
- A rule like `allow read: if request.auth != null` denies the anonymous call
  but allows every signed-in user. Combined with open signup, that is the
  common real-world bug (Chattr.ai, 2024). Proving it needs one test account:
  Stage B unless the program provides one.
- Rules that filter on a field (`resource.data.owner == request.auth.uid`)
  reject a list query that does not carry the same filter. A denied unfiltered
  list does not prove the collection is safe; a `runQuery` with the owner filter
  set to **your** UID is the matching test.
- Non-default databases use `databases/<database-id>` instead of `(default)`;
  look for `getFirestore(app, '<id>')` in the code.
- `:listCollectionIds` is evaluated with IAM, not Security Rules
  (`datastore.entities.list`), so an anonymous caller should not reach it
  (verify on the target, do not rely on it).

## Cloud Storage for Firebase

```bash
B='<bucket-from-config>'
# List (read): one object name.
curl -s "https://firebasestorage.googleapis.com/v0/b/$B/o?maxResults=1" | head -c 800
# Narrow to a prefix the app uses (e.g. users/, uploads/, kyc/).
curl -s "https://firebasestorage.googleapis.com/v0/b/$B/o?prefix=<prefix>%2F&maxResults=1" | head -c 800
```

- A JSON `items` array = anonymous list. The object names are the evidence.
  Do not download user files to prove read; if you must show content access,
  request one object's metadata (`/o/<url-encoded-path>` without `alt=media`,
  verify) or one file you uploaded yourself in Stage B.
- Bucket names: default buckets created on or after **30 Oct 2024** are
  `<project-id>.firebasestorage.app` and need the Blaze plan; older ones keep
  `<project-id>.appspot.com`, and Firebase announced that access to those also
  needs Blaze from **1 Oct 2025** (Firebase storage FAQ, Sept 2024). A bucket
  that now answers with a billing or project error is not a rules finding.
- Tea (July 2025): a legacy Firebase Storage bucket, embedded in the Android
  app, still held about 72,000 verification selfies, ID photos and message
  images after the company had migrated off it. Old buckets referenced by old
  app versions are worth checking.

## Firebase Authentication / Identity Toolkit

Read-only:

- **Email enumeration protection** is on by default for projects created on or
  after **15 Sept 2023** (Identity Platform docs). With it on, `createAuthUri`
  no longer returns sign-in methods and sign-in failures collapse into
  `INVALID_LOGIN_CREDENTIALS`. Sign-up with an existing address still returns
  `EMAIL_EXISTS`. A project that still returns `EMAIL_NOT_FOUND` has it off:
  Low, and only a single differential, never a list.
- Project config: `https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=<API_KEY>`
  has historically returned `authorizedDomains` and provider settings to
  anyone with the key (verify on the target). An authorized domain you can
  register or take over feeds `hunt-oauth` and `hunt-subdomain`.

Whether email/password or anonymous sign-up is enabled cannot be read
anonymously. The only probe is a `accounts:signUp` call, which is Stage B
(below).

## Cloud Functions

- 1st gen HTTP and callable functions: `https://<region>-<project-id>.cloudfunctions.net/<name>`.
  Callable functions take `POST` with `{"data": {...}}`. 2nd gen functions run
  on Cloud Run (`*.run.app`): `hunt-cloud-misconfig` owns that surface.
- A function is code, not a rule. Calling one with no auth is only a read if
  the source (bundle, source map, leaked repo) shows it is. Otherwise treat any
  call as Stage B. Missing `context.auth` checks in a callable that returns
  other users' data is the usual finding.

## Remote Config

The client fetch needs an installation ID and auth token from the Firebase
Installations API (Firebase SDK docs), and creating one is a registration,
which is a write. So:

- Stage A: read the defaults the app ships (`res/xml/remote_config_defaults.xml`,
  `setDefaultsAsync(...)`, `remoteConfig.defaultConfig = {...}` in JS) and any
  values cached in the decoded app. API keys, admin feature flags or internal
  URLs there are the finding.
- Stage B: a live fetch through `firebaseremoteconfig.googleapis.com/v1/projects/<project>/namespaces/firebase:fetch`
  (endpoint form seen in traffic analysis; verify against Google's reference)
  with a registered installation. Rarely worth the sign-off.

## Cloud Messaging (FCM) keys

- The legacy HTTP and XMPP send APIs were deprecated on **20 Jun 2023** and
  shutdown began **22 Jul 2024** (Firebase migration guide). Legacy server keys
  (long strings beginning `AAAA`) were long-lived send credentials for that API;
  HTTP v1 uses short-lived OAuth tokens from a service account.
- A leaked legacy key in 2026 is usually dead. Proving it is live means sending
  a push, which is Stage B and, to anyone but your own test device, never.
  Report the exposure as Low with the shutdown date unless the program asks
  for validation.
- A leaked FCM **service account JSON** is a GCP credential: `cloud-iam-deep`.

## Dynamic Links

Firebase Dynamic Links shut down on **25 Aug 2025**. Links on `page.link` and
on custom domains stop resolving (404), and the provisioned `page.link`
subdomains are not transferable (Firebase Dynamic Links FAQ). A dead link is
not a finding. A custom link domain whose DNS still points at Firebase Hosting
with no site behind it is a takeover candidate for `hunt-subdomain`.

## App Check

App Check makes Firebase reject requests that lack a valid attestation token
for enforced services. It raises the cost of scripted access; it is not
authorization. Do not try to bypass attestation (that is instrumenting the
app, owned by the mobile skills and usually out of scope). If a read succeeds
only because enforcement is off for that service, report the rule gap, and note
App Check status as context.

## Google API key reuse

The `apiKey` is a normal Google Cloud API key. If the project also enables the
Generative Language (Gemini) API and the key is unrestricted, the same key
reaches Gemini: see `google-api-keys.md`.

## Stage B on Firebase

Every request in this section needs the written sign-off block from SKILL.md
Step 4 naming the project, the action and the account.

### Lowest-risk sign-up probe

```bash
# Stage B: written sign-off required. One request, your own address, a password that cannot pass policy.
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>" \
  -H 'Content-Type: application/json' \
  -d '{"email":"tester+hcb@yourdomain.example","password":"1","returnSecureToken":true}'
```

`WEAK_PASSWORD` suggests the email/password provider and sign-up are enabled;
`OPERATION_NOT_ALLOWED` that the provider is off; `ADMIN_ONLY_OPERATION` that
Identity Platform's user-creation action is disabled. The order Google applies
these checks in is not documented (verify), so read it as a hint and note that
the request could not create an account because the password is below the
six-character minimum. Omitting `email` and `password` requests an
**anonymous** user, which does create an account.

### Write test on your own record

Only after a test account exists, only on a path or document the app creates
for that account, with a unique marker, then removed:

```bash
# Stage B: written sign-off required. Own record only; delete in the same window.
TOKEN='<ID_TOKEN_OF_TEST_ACCOUNT>'; MARK="hcb-$(openssl rand -hex 4)"
curl -s -X PATCH "https://<db-from-config>/users/<your-uid>.json?auth=$TOKEN" \
  -d "{\"hcb_marker\":\"$MARK\"}"
curl -s -X DELETE "https://<db-from-config>/users/<your-uid>/hcb_marker.json?auth=$TOKEN"
```

Never write to the root, to another user's node, or anonymously "to see if it
sticks". The ungated `PUT .../test.json` probe still shown in some older skills
in this repo writes to a production database root; do not copy it.

## Incidents and disclosures, 2022-2026

| Date | What | Source |
|---|---|---|
| Jan 2024 | Chattr.ai hiring platform: Firebase config on the site; after creating an account through Firebase Auth the researchers had read and write on the database (employee and applicant data for several fast-food chains). | <https://mrbruh.com/chattr/>, SecurityWeek |
| Mar 2024 | Scan of 5M+ domains found 916 sites with open Firebase rules: about 125M records, 19.8M plaintext passwords; 842 notifications sent. | <https://www.malwarebytes.com/blog/privacy/2024/03/19-million-plaintext-passwords-exposed-by-incorrectly-configured-firebase-instances> |
| Aug-Sep 2024 | Arc browser, CVE-2024-45489: Firestore rules let a user set another user's ID as a Boost's creator, installing JavaScript in the victim's browser. Fixed in a day; bounty paid. | <https://nvd.nist.gov/vuln/detail/CVE-2024-45489>, <https://arc.net/blog/CVE-2024-45489-incident-response> |
| Jul 2025 | Tea app: legacy Firebase Storage bucket from the Android app exposed about 72,000 images, including ID documents. | 404 Media via <https://securityaffairs.com/180539/data-breach/hackers-leak-images-and-comments-from-women-dating-safety-app-tea.html> |
| Aug 2025 | Intigriti researcher guide to Firestore and Storage access-control testing, including field-based ownership bypasses. | <https://www.intigriti.com/researchers/blog/hacking-tools/hacking-google-firebase-targets> |
| Feb 2026 | Truffle Security: 2,863 public `AIza` keys (Common Crawl, Nov 2025) reached Gemini after the API was enabled on their projects. | `google-api-keys.md` |

## Tools

- Baserunner (iosiro): browser tool that loads a Firebase config and runs
  Firestore, RTDB and Storage queries as anonymous or signed-in user.
  <https://github.com/iosiro/baserunner>. It can also write: keep to queries.
- firepwn: used in the Chattr.ai research; has write features, same caution.
- FireBaseScanner (shivsahni): RTDB-only, last pushed 2022; stale.
- Trail of Bits `firebase-apk-scanner` (a Claude Code skill): extracts config
  from an APK and tests RTDB, Firestore, Storage, Functions and Remote Config
  for unauthenticated access. Check what it sends before running it on a
  target; the rules here (no signup, no writes) still apply.

## Sources (checked October 2026)

- RTDB REST: <https://firebase.google.com/docs/database/rest/retrieve-data>
- Storage default bucket changes: <https://firebase.google.com/docs/storage/faqs-storage-changes-announced-sept-2024>
- Email enumeration protection: <https://docs.cloud.google.com/identity-platform/docs/admin/email-enumeration-protection>
- FCM legacy migration: <https://firebase.google.com/docs/cloud-messaging/migrate-v1>
- Dynamic Links FAQ: <https://firebase.google.com/support/dynamic-links-faq/>
- Firestore IAM permissions: <https://firebase.google.com/docs/firestore/security/iam>

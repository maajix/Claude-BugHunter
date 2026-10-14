# Authentication and session (MASVS-AUTH)

MASVS-AUTH is mostly a backend property: the server decides who you are. On
the device you test three things: whether a local gate (biometric, PIN,
"remember me") actually protects anything, where the app keeps the tokens
that prove identity, and whether the OAuth redirect can be captured on the
device. Server-side session lifecycle (logout, rotation, revocation) belongs to
`hunt-session`; OAuth server flaws to `hunt-oauth`.

All tests use **your own test account on your own device**.

## 1. Local authentication: BiometricPrompt and app PIN

**What to find.** Two implementations look identical on screen:

| Pattern | How it works | Bypassable with Frida? |
|---|---|---|
| Event-bound | `BiometricPrompt.authenticate(promptInfo)` with no `CryptoObject`; `onAuthenticationSucceeded` flips a boolean or navigates to the home screen | Yes. Invoke the success callback yourself |
| Crypto-bound | A Keystore key created with `setUserAuthenticationRequired(true)` (plus `setUserAuthenticationParameters(...)` on API 30+ (verify)), `authenticate(promptInfo, CryptoObject(cipher))`, and the unlocked `Cipher` from the result decrypts something the session needs (a refresh token, a local DB key) | No. Without a real biometric the key stays locked and the decrypt throws |

**Static check.**

```bash
SRC=decompiled/sources        # jadx output from apk-redteam-pipeline Stage 2
grep -rn -E 'BiometricPrompt|FingerprintManager|authenticate\(' "$SRC" | grep -v '/androidx/' | head -40
grep -rn -E 'CryptoObject|setUserAuthenticationRequired|setUserAuthenticationParameters|setInvalidatedByBiometricEnrollment|BIOMETRIC_STRONG|BIOMETRIC_WEAK|DEVICE_CREDENTIAL' "$SRC" | grep -v '/androidx/'
```

Red flags: `authenticate(` called with only the prompt info; `BIOMETRIC_WEAK`
(Class 2) allowed for a gate that protects payments or secrets;
`setInvalidatedByBiometricEnrollment(false)` on a key that guards a secret
(a newly enrolled fingerprint unlocks the old key); `CryptoObject` created but
the result's cipher never used.

**Dynamic check (your device, your install).** Hook the success path and see
whether the app unlocks. The maintained scripts are listed in `tooling.md`
§3; objection's `android hooking` commands are enough to locate the callback
class. WithSecure's `android-keystore-audit` repo ships the reference scripts
(`frida-scripts/fingerprint-bypass.js`, which calls the success callback with a
`CryptoObject(null)`, and `fingerprint-bypass-via-exception-handling.js`, which
swallows the `Cipher` exception). They only work when the key is **not**
crypto-bound: a key created with `setUserAuthenticationParameters` for
auth-per-use stays locked and `Cipher.doFinal` throws.

**Evidence.** Screen recording: biometric prompt shown, prompt cancelled or
no finger, app unlocked after the hook; plus the decompiled call site showing
`authenticate(promptInfo)` without a `CryptoObject`.

**Severity.** Bypassing a local gate needs the unlocked device in hand plus a
rooted or instrumented build. Most programs reject that ("Two-factor
authentication bypass that requires physical access to a logged-in device"
appears in public policies, and HackerOne's core list excludes attacks that
need physical access). Report it when:

- the biometric result is **sent to the server as a factor** (a request
  carrying `"biometricVerified": true` or similar that the backend trusts):
  that is server-side trust of a client assertion, Broken Authentication, and
  graded on what the factor protects;
- the program's scope explicitly lists local authentication or MASVS L2.

## 2. Client-side enforcement of server decisions

Grep the decompiled code and the sandbox (`storage.md` §1) for decisions the
server should own:

```bash
grep -rn -i -E '"(is_?premium|is_?admin|is_?verified|role|otp|pin_?code|kyc_?status)"' "$SRC" | head -40
```

Patterns that are real findings, because the server trusts the client:

- the OTP or PIN is returned in the API response and compared on the device;
- a "verified" or "premium" flag in SharedPreferences unlocks a feature and the
  backend serves the data without checking the account's entitlement;
- the app hides an admin screen but the API it calls has no role check.

Changing a local flag is Stage A (your device). Proving the server honours
it means calling the API: read-only calls with your own token are Stage A;
anything that buys, transfers or changes account state is Stage B with
written sign-off, run through `hunt-api-misconfig` / `hunt-business-logic`.

Severity: a client-trusted OTP/PIN comparison or a server that honours a
locally-flipped entitlement is VRT Broken Authentication > Authentication
Bypass (P1) when it yields access, or Broken Access Control when it unlocks
data/actions; a local flag the server re-checks is not a finding.

Severity: a client-trusted OTP/PIN comparison or a server that honours a
locally-flipped entitlement is VRT Broken Authentication > Authentication
Bypass (P1) when it yields access, or Broken Access Control when it unlocks
data/actions; a local flag the server re-checks is not a finding.

## 3. Token storage

Find every credential the app keeps: access and refresh tokens, session
cookies, API keys per user, device-binding secrets.

| Where | How to look |
|---|---|
| SharedPreferences / DataStore | `shared_prefs/*.xml`, `files/datastore/*.preferences_pb` (`storage.md` §2) |
| SQLite / Room / Realm | `databases/`, `*.realm` (`storage.md` §3) |
| WebView cookies | `app_webview/Default/Cookies` (Chromium SQLite cookie DB) |
| AccountManager | `adb shell dumpsys account` lists accounts by type; token values are not printed |
| Keystore-wrapped | Ciphertext in prefs plus a key alias in `AndroidKeyStore`; `objection` `android keystore list` |

A refresh token in plaintext inside the private sandbox is VRT Insecure Data
Storage > Sensitive Application Data Stored Unencrypted > On Internal Storage
(P5) and is ineligible on many programs because reading it needs root. It
becomes reportable when the same token also reaches shared storage, a backup,
logcat, a crash-reporting SDK upload, or an exported provider.

## 4. Session handling seen from the device

Stage A, own account, read-only:

1. Capture the session token in the proxy, log out in the app, then send **one
   read-only GET** with the old token. If it still works, hand the finding to
   `hunt-session` (VRT Failure to Invalidate Session > On Logout).
2. Check what logout clears on the device: re-list the sandbox and the
   WebView cookie store after logout. Tokens left behind locally are a weak
   finding alone; combined with a backup or shared-storage leak they matter.
3. Note token lifetime (`exp` in a JWT, decoded offline) and whether refresh
   tokens rotate. Long lifetimes alone are VRT P5.

Stage B (written sign-off): password change, "log out all devices", MFA
enrolment changes and any test that needs a second account. Follow
`hunt-session`.

## 5. OAuth and OIDC redirect capture on the device

**Identify the redirect.** In the manifest and code look for AppAuth's
`net.openid.appauth.RedirectUriReceiverActivity`, the `appAuthRedirectScheme`
manifest placeholder, custom schemes such as `com.client.app:/oauth2redirect`,
and `https` redirects on an App Link host. `hunt-oauth` §Mobile covers the
server side.

**Why it matters.** RFC 8252 (OAuth 2.0 for Native Apps) prefers claimed
`https` redirects (App Links) and requires PKCE for public clients, because any
app can register the same custom scheme. A custom-scheme redirect is only
exploitable when the authorization code can be redeemed without the
`code_verifier` the legitimate app holds.

**Stage A, own device.**

1. Record the authorization request in the proxy: `response_type`,
   `code_challenge`, `code_challenge_method`, `redirect_uri`.
2. If the redirect is `https`, check App Link verification
   (`ipc-and-platform.md` §7). An unverified host means the browser or a
   chooser handles the redirect, not necessarily the app.
3. Static: is there a client secret in the APK (VRT Sensitive Data Hardcoded >
   OAuth Secret, P5 alone)? Is the flow `response_type=token` (implicit, token
   in the redirect)?

**Stage B (written sign-off), own accounts only.** Proving capture needs a
second app on your test device that claims the same scheme, and a login with
your own test account so the redirect lands in that app. Proving impact needs
the token endpoint to accept the captured code without the verifier, which is
a write to the production identity provider. Run it once, with your accounts,
then hand to `hunt-oauth` for grading (VRT Server Security Misconfiguration >
OAuth Misconfiguration > Account Takeover, P2, only when the code is
redeemable).

**Embedded WebView login.** An app that renders a third-party identity
provider's login inside its own WebView can read what the user types. For the
app's own login page this is expected; for a third-party IdP it is a policy
issue for the IdP, usually not a bounty finding.

## 6. Password autofill and credential handling

- Login fields: `android:inputType="textPassword"` (keeps the value out of
  keyboard learning), `android:autofillHints` / `importantForAutofill` set so
  password managers fill the right field, and no password echoed into a
  normal `EditText` for "show password" without clearing it afterwards.
- Credential Manager / passkeys: confirm the relying-party ID and that the
  server validates the assertion, which is backend work for `hunt-ato`.
- WebView-hosted login pages and autofill: the "AutoSpill" research (Black Hat
  Europe 2023, Gangwal et al.) showed that when an app loads a login page
  inside its own WebView, the autofilled password-manager credentials can leak
  into the hosting app rather than staying with the web page. It is
  WebView-specific. An app that renders third-party logins in a WebView instead
  of a Custom Tab is the precondition; grep for `WebView` on login screens.

Severity: autofill weaknesses are rarely eligible on their own. Grade on what
a second, realistic bug lets an attacker do with the credential.

## Evidence for this file

- Decompiled call sites (file, class, method) for every claim about code.
- Proxy captures of the authorization request and token response, redacted
  per `evidence-hygiene`.
- Screen recordings for any local bypass, showing the device's Android
  version and the app version (`adb shell dumpsys package "$PKG" | grep versionName`).

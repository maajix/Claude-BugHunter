# Auth and session: MASVS-AUTH-1, -2, -3

Scope boundary: authorization-server behaviour (redirect_uri matching, `state`,
PKCE enforcement, token endpoint) is `hunt-oauth`; JWT signing is
`hunt-jwt-crypto`; MFA and account-linking logic is `hunt-mfa-bypass` and
`hunt-ato`. This file owns the **client half**: how the iOS app authenticates
locally, where it keeps tokens, how it runs OAuth, and the one question that
turns a local weakness into a finding, which is what the server trusts.

MASTG IDs from OWASP/mastg `master` (fetched 2026-10-14).

---

## 1. LocalAuthentication versus Keychain-bound biometrics (MASVS-AUTH-2)

Two designs look identical on screen:

| Design | How it works | What a hook does |
|---|---|---|
| **Event-bound** (`LAContext.evaluatePolicy` then `if success { unlock }`) | A boolean in the app's process decides | Flips the boolean; the app unlocks |
| **Keychain-bound** (`SecAccessControlCreateWithFlags` with a biometry or user-presence flag on the item holding the secret) | The Secure Enclave releases the secret only after a real match | Nothing; `SecItemCopyMatching` still fails without a match |

### Static (MASTG-TEST-0266, 0268, 0270)

```bash
grep -aE 'evaluatePolicy|canEvaluatePolicy|SecAccessControlCreateWithFlags|kSecAccessControl|deviceOwnerAuthentication|evaluatedPolicyDomainState|domainState' strings_target.txt | sort -u
ipsw macho search <AppBinary> --import 'SecAccessControlCreateWithFlags'
```

| Observation | MASTG | Meaning |
|---|---|---|
| `evaluatePolicy` used, no `SecAccessControlCreateWithFlags` with a user-presence flag on the sensitive item | 0266 | Event-bound only; fails |
| `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` on a high-value item | 0268 | Passcode fallback allowed; hardening note (MASTG says weakness, not critical) |
| No `kSecAccessControlBiometryCurrentSet` | 0270 | A newly enrolled face or finger (someone who knows the passcode adds one) unlocks the item |
| Uses `evaluatedPolicyDomainState` / `domainState` to detect enrollment changes | 0270, 0271 | Event-bound alternative; still bypassable in-process |

### Dynamic (MASTG-TEST-0267, 0269, 0271)

```bash
objection -n <bundle_id> start
#   ios ui biometrics_bypass       -> hooks the LAContext reply so a cancelled or failed Face ID reports success
```

Trigger the app's biometric prompt, cancel it, and observe:

- The protected screen opens and shows real data: event-bound. Record it.
- The screen opens but data does not load, or the app asks for the password:
  the secret was Keychain-bound or server-bound. Good.

### Grade

A local bypass needs the victim's unlocked phone running your instrumentation,
so it is `Lack of Binary Hardening > Runtime Instrumentation-Based` (P5) and
usually excluded. Two cases are real findings:

1. **Server trusts a client flag.** The step-up or "unlock" request carries a
   field such as `biometricVerified: true`, or a header the app sets after
   `evaluatePolicy`, and the server accepts the sensitive action on it. If the
   action writes (transfer, password change, device enrollment), the replay is
   Stage B and needs written sign-off; a read-only step-up check is Stage A.
   Prove it by replaying the request with the flag set but no biometric event,
   on your own account:

```
# Stage B: written sign-off required. One replay, own account, smallest action.
# Request: the step-up call captured in the proxy, biometric flag forced to true, no prompt shown
# Evidence: the request, the server's acceptance, the resulting state on your account
```

   Grade: `Broken Authentication and Session Management > Second Factor
   Authentication (2FA) Bypass` (P3), or `Authentication Bypass` (P1) if it
   yields a session without the password.

2. **Request signing not enforced.** The app signs sensitive requests with a
   Secure Enclave key (`kSecAttrTokenIDSecureEnclave`) created behind
   biometry. Drop or corrupt the signature header on a read-only request
   first (Stage A); only a write needs Stage B. If the server accepts unsigned
   requests, the biometric binding protects nothing. Grade as case 1.

Deprecated MASTG-TEST-0064 is the v1 biometric test.

---

## 2. Token storage (MASVS-AUTH-1, STORAGE-1)

Find every credential the app holds and where:

| Token | Should be | Common failure |
|---|---|---|
| Refresh token, long-lived API key | Keychain, `ThisDeviceOnly`, ideally behind access control for high-value apps | UserDefaults, plist, SQLite, `Cookies.binarycookies` with a long expiry |
| Access token | Memory or Keychain | Logged (`storage.md` section 9), in `Cache.db`, in a URL (then in server logs) |
| Password | Not stored at all (exchange for a token) | Keychain item holding the raw password for "remember me", or worse, UserDefaults |
| PIN for app unlock | Server-verified or a Keychain-bound secret | Hash of a 4-6 digit PIN in a plist (brute-forceable offline) |

The storage test and grade are in `storage.md` sections 3 and 4. Here, record
the token's **lifetime** and **binding**: does the refresh token rotate on
use, does it work from another device, does it carry a device identifier the
server checks? Decode JWTs offline; claims and algorithm issues go to
`hunt-jwt-crypto`.

Evidence: each token's location and protection class, its `exp`, and whether
refresh rotates (two refreshes compared), redacted to first and last four
characters.

---

## 3. Session handling (MASVS-AUTH-1)

Run each with your own account, using a **read-only** request (profile GET)
as the probe so replays are Stage A. Changing your own test account's password
or removing your own device through the app's own UI is Stage A; doing it to
any other account, or through a crafted request, is Stage B (written sign-off).

| Test | Steps | VRT if it fails |
|---|---|---|
| Logout revokes server-side | Capture a token, log out in the app, replay the GET | `Failure to Invalidate Session > On Logout (Server-Side Only)` (P5), or `On Logout (Client and Server-Side)` (P4) if the app also keeps the session locally |
| Password change revokes other sessions | Two devices or app plus web; change your test account's password through the app's own UI on one, replay the GET on the other | `Failure to Invalidate Session > On Password Reset and/or Change` (P4) |
| Remote device removal (if the product offers it) | Remove the test device from account settings, replay | argue as above |
| Excessive lifetime | Note `exp` and refresh rotation | `Excessive JSON Web Token (JWT) Lifetime` (P5) |
| Reinstall resumes session | Delete app, reinstall | `storage.md` section 4 |

All nodes above are under `Broken Authentication and Session Management`.

Evidence: token issue time, the logout or password-change time, and the
replayed GET with its 200 response after the event. Grade: the VRT column.

---

## 4. OAuth and OIDC in a native app (MASVS-AUTH-1)

Baseline: RFC 8252 (OAuth 2.0 for Native Apps) and RFC 9700 (OAuth 2.0
Security BCP, see `hunt-oauth`). A native app is a public client: PKCE is
required, and the app should use the system browser, not an embedded WebView.

### Identify the flow

```bash
grep -aE 'ASWebAuthenticationSession|SFSafariViewController|SFAuthenticationSession|callbackURLScheme|code_verifier|code_challenge|redirect_uri|prefersEphemeralWebBrowserSession' strings_target.txt | sort -u
```

| Pattern | Risk |
|---|---|
| `ASWebAuthenticationSession` with `callbackURLScheme` | The callback goes to the session that started the flow; Apple's position is that only the requesting app receives it (Developer Forums). Custom-scheme hijack does not apply to the callback itself |
| `ASWebAuthenticationSession` with an HTTPS callback (`Callback.https(host:path:)`, iOS 17.4+) | Callback bound to the app's associated domain (`webcredentials:`); strongest option |
| `SFSafariViewController` or Safari plus a custom-scheme redirect handled in `openURL` | The OS routes the redirect by scheme; a second app registering the same scheme can receive the code |
| Embedded `WKWebView` login | The app can read the credentials and cookies; RFC 8252 says native apps must not use embedded user-agents for authorization (verify exact wording). Also `platform.md` sections 5 and 6 |
| Deprecated `SFAuthenticationSession` | Old build; check the minimum iOS |

### Redirect capture test (own device, own account)

1. Build a PoC app with your own signing identity that registers the target's
   redirect scheme and logs any URL it receives. Install it on your test
   device only.
2. Start the target app's login on the same device and complete it with your
   test account.
3. If the PoC app receives `?code=` (or a token), the flow is capturable.
4. Check whether the code is usable without the verifier: try to exchange it
   at the token endpoint **without** `code_verifier`. This is your own code for
   your own account, so it is Stage A. Success means PKCE is not enforced
   server-side; hand that to `hunt-oauth`.
5. With PKCE enforced, the captured code alone is useless; record it as
   hardening and note the scheme collision.

Also check `state` (generated per flow, checked on return) and whether the
app accepts a callback it did not start (login CSRF; `platform.md` section 1).

### Universal Link redirect URIs

An HTTPS redirect handled as a Universal Link is safe only while the domain
is. If the redirect domain or its `applinks:` host can be taken over, codes
land on the attacker's page when the app is absent or the link falls back to
Safari. Route to `hunt-subdomain`; do not attempt a takeover from here.

### Secrets in the client

`client_secret` in the IPA: `Sensitive Data Exposure > Sensitive Data
Hardcoded > OAuth Secret` (P5) unless it unlocks a confidential-client grant
(client credentials with real scopes); then `hunt-oauth` grades it.

### Grade

| Proven | VRT node | Default |
|---|---|---|
| Code captured by a second app and exchangeable (no PKCE) | Server Security Misconfiguration > OAuth Misconfiguration > Account Takeover | P2 |
| Code captured, PKCE enforced | Server Security Misconfiguration > OAuth Misconfiguration > Insecure Redirect URI | VARIES, low |
| `state` missing or unchecked | Server Security Misconfiguration > OAuth Misconfiguration > Missing/Broken State Parameter | VARIES |
| Client secret shipped | Sensitive Data Exposure > Sensitive Data Hardcoded > OAuth Secret | P5 |

Evidence: the PoC app's source (never a distributable binary), a recording of
the login and of the PoC app logging the callback URL with the code redacted,
and the token-endpoint request and response for the PKCE check.

---

## 5. Passkeys (MASVS-AUTH-1)

The app side is thin: `ASAuthorizationPlatformPublicKeyCredentialProvider`
requests, a `webcredentials:` associated domain, and the AASA
`webcredentials.apps` list. iOS 26 added an account-creation API that issues a
passkey at signup, automatic passkey upgrades after password sign-in, and
credential import/export between managers (vendor and Apple WWDC25 material,
verify API names before citing). iCloud Keychain passkeys report a zeroed
AAGUID, so a server cannot attest which authenticator made them (verify).

Testing is mostly server-side. With your own account:

| Check | How | Owner |
|---|---|---|
| Challenge is single-use and short-lived | Replay a captured assertion | here, Stage A on own account (read-only login) |
| User verification flag required for sensitive actions | Inspect `authenticatorData` flags in an assertion | here |
| Registration binds the passkey to the authenticated account | Register on account A while presenting account B's identifier | `hunt-ato`, Stage B |
| Weaker fallbacks (SMS, email link, password) bypass the passkey policy | Use the fallback on your account | `hunt-mfa-bypass` |
| AASA `webcredentials` lists only the right app IDs | Read the file | here |

```
# Stage B: written sign-off required. Two tester-owned accounts only.
# Attempt to register a new passkey for account B from a session of account A.
```

Evidence: the AASA `webcredentials` block, the replayed assertion and the
server's response, and the sign-off reference for Stage B steps.

Grade: a replayable challenge or unenforced user verification is `Broken
Authentication and Session Management > Second Factor Authentication (2FA)
Bypass` (P3) when the passkey is the second factor, and `Broken Authentication
and Session Management > Authentication Bypass` (P1) when it alone yields a
session. Binding and fallback issues are graded by `hunt-ato` and
`hunt-mfa-bypass`.

---

## 6. Step-up and sensitive operations (MASVS-AUTH-3)

List the operations that should require re-authentication (payee add, limit
change, password or email change, device enrollment, export of data). For
each, record what the app asks for and what the request carries, then apply
section 1's "server trusts a client flag" test. Programs grade the outcome,
not the missing prompt (evidence: the request pair with and without the
step-up element): a missing re-auth with no bypass is
`Insufficient Security Configurability` territory (P5); a bypassable one is
the 2FA node (P3).

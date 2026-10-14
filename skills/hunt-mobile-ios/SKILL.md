---
name: hunt-mobile-ios
description: "MASVS v2 and MASTG aligned iOS app pentest for an authorized tester holding the IPA and a test device (jailbroken, developer-signed build on a stock device, or Corellium). Organised by control group. STORAGE: NSUserDefaults, plists, Core Data, SQLite, Realm, Keychain accessibility classes, NSFileProtection, backups, pasteboard, app-switcher snapshots, os_log, NSURLCache and WKWebView caches. PLATFORM: URL schemes, Universal Links and AASA, extensions, widgets, App Clips, WKWebView JavaScript bridges, custom keyboards, App Intents, Handoff, CloudKit. AUTH: LAContext bypass versus Keychain-bound biometrics, token storage, ASWebAuthenticationSession redirect capture, passkeys. NETWORK: ATS exceptions, pinning in URLSession, Alamofire and TrustKit, proxy-unaware apps. RESILIENCE: jailbreak, Frida and debugger detection and how programs grade them. Each control has a procedure, evidence and a Bugcrowd VRT grade. Use when an iOS app is in scope and ios-redteam-pipeline has produced a decrypted IPA."
metadata:
  sources: owasp_masvs, owasp_mastg, apple_developer_docs, bugcrowd_vrt, hackerone_docs, project_documentation, public_research
  report_count: 0
---

## When to use

Trigger when an iOS or iPadOS app is in scope and you hold the IPA plus a
device you control. This skill is the **methodology layer**: what to test per
MASVS control, how to prove it, and how a program will grade it. It starts
where `ios-redteam-pipeline` stops: that skill acquires and decrypts the IPA,
class-dumps it, greps Info.plist, entitlements and strings, dumps the ATS
dictionary, enumerates URL schemes and the AASA file, and carries the Frida,
objection and pinning-bypass templates. Run its Stages 0 to 3 first, then come
here. Do not repeat its commands; reuse its output.

The grounding is the OWASP MASVS v2 control list, the MASTG test catalogue
(IDs below were taken from the OWASP/mastg `master` branch on 2026-10-14; the
iOS test set matches the MASTG v2.0.0 release of 2026-06-30), Apple developer
documentation, Bugcrowd VRT v1.19.1 (released 2026-07-08) and HackerOne's core
ineligible list. It is not a counted corpus of disclosed reports, hence
`report_count: 0`.

### Where the chain ends

Stop at **weakness proven on your own device with your own test account,
impact described, evidence captured**:

- On-device data exposure: stop at "this file or Keychain item holds this
  canary, with this protection class". Never pull data from a device that is
  not yours, and never ask a real user for theirs.
- Platform IPC (URL schemes, Universal Links, extensions, WebView bridges):
  stop at the handler accepting attacker input and the effect on your own
  account. A proof-of-concept app is built with your own signing identity,
  installed only on your own test device, and never distributed through
  TestFlight, the App Store, an enterprise profile or a download link.
- Local authentication: stop at "the boolean gate falls to a hook" or "the
  server trusts a client-side flag". The second is the finding; the first
  rarely is.
- Network: stop at cleartext or accepted-forged-certificate traffic captured
  from your own device on a network you control.
- Backend: once traffic flows, API testing belongs to the web skills (below),
  under their own Stage A / Stage B rules.

Nothing here covers attacking another person's device, persistence, malware,
or getting code onto a device you do not own. `SECURITY.md` applies.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| App Store / TestFlight / OTA IPA acquisition, FairPlay decryption, class-dump, Info.plist and entitlements grep, ATS dump, URL-scheme and AASA enumeration, keychain-dumper, Frida and objection templates, pinning-bypass scripts, mitmproxy CA setup | `ios-redteam-pipeline` |
| Android, APKs, intents, Play Integrity | `apk-redteam-pipeline`, `hunt-mobile-android` |
| Flutter, React Native, Xamarin/.NET MAUI, Unity, Cordova/Capacitor internals (Dart snapshots, Hermes bundles, IL2CPP, JS bridges of those frameworks) | `hunt-mobile-frameworks` |
| Firebase, Supabase, Amplify/Cognito, Auth0 and other BaaS configs found in the IPA | `hunt-cloud-backends` |
| The app's REST/GraphQL API: missing auth, IDOR, mass assignment, older API versions | `hunt-spa-api`, `hunt-idor`, `hunt-api-misconfig`, `hunt-graphql`, `hunt-shadow-api` |
| Authorization-server bugs (redirect_uri matching, state, PKCE enforcement server-side) | `hunt-oauth` |
| JWT signing and claims | `hunt-jwt-crypto` |
| Server TLS configuration and certificates | `hunt-tls-network` |
| Secret regex catalogues | `hunt-source-leak`, `offensive-osint/references/secret-patterns.md` |
| Takeover of a domain listed in `applinks:` or used as a redirect URI | `hunt-subdomain` |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/storage.md` | Container pull, canary grep, UserDefaults, plists, Core Data, SQLite WAL, Realm, Keychain classes and access control, NSFileProtection, backups, pasteboard, snapshots, logs, keyboard cache, caches, crypto keys, iOS 17 to 27 notes | keychain dump, data protection, nsfileprotection, ios backup, pasteboard, app switcher screenshot, os_log, cache.db |
| `references/platform.md` | URL schemes, Universal Links and AASA, extensions, App Groups, widgets, App Clips, WKWebView and UIWebView, JS bridges, file loading, keyboards, App Intents, Handoff, iCloud and CloudKit | deep link, url scheme, universal link, aasa, wkwebview, messagehandlers, app extension, cloudkit |
| `references/auth-and-session.md` | LAContext versus kSecAccessControl, token storage, session revocation, ASWebAuthenticationSession, custom-scheme redirect capture, PKCE, passkeys, request signing | face id bypass, biometrics_bypass, lacontext, aswebauthenticationsession, redirect capture, passkey |
| `references/network.md` | Burp CA on iOS 17+, proxy-unaware apps, certificate-validation test, ATS exception grading, pinning detection in URLSession, Alamofire, TrustKit | burp ios, ats exception, certificate pinning, ssl kill switch, proxy unaware, quic |
| `references/resilience.md` | Jailbreak, Frida, debugger and virtual-device detection, anti-tamper, App Attest, symbols, obfuscation, exploit mitigations, program grading | jailbreak detection, frida detection, anti-debug, app attest, obfuscation, binary hardening |
| `references/tooling.md` | Versions checked 2026-10-14, Frida 16 vs 17, objection 1.12.5 syntax, ipsw, class-dump, jailbreak matrix, TrollStore, sideloading and signing limits, MobSF, Corellium, pymobiledevice3 | frida version, objection start, palera1n, dopamine, trollstore, sideloadly, corellium, mobsf |

---

## Step 0: Test bench and stage rules

Pick the bench from what the test needs, not from what you own. Details,
versions and jailbreak coverage are in `references/tooling.md`.

| Bench | Gives you | Breaks |
|---|---|---|
| Jailbroken physical device (palera1n on A8-A11; Dopamine per its matrix) | Whole filesystem, any app's container and Keychain, frida-server, App Store builds as shipped | Locked to old iOS; the app's minimum iOS may exclude it |
| Stock device + developer-signed build (client-supplied, or a decrypted IPA re-signed with Frida Gadget via `objection patchipa`) | Frida inside that one app, current iOS, no jailbreak artefacts | Re-signing changes the Team ID: associated domains, Keychain access groups, App Groups, iCloud and push stop matching. Universal Link, shared-Keychain and CloudKit tests are invalid on a re-signed build |
| Corellium virtual iPhone | Jailbroken current-ish iOS, snapshots, built-in traffic view | Cost; Apple services may be limited (verify); apps can detect virtualisation (MASTG-TEST-0367) |
| Xcode Simulator | Only for apps you build from source | Not for a third-party IPA |

Ask the client for a **developer-signed build signed with their own team**
when you have no jailbreak for the app's minimum iOS. It is the only way to
test entitlement-bound features on current iOS without a jailbreak.

### Stage A and Stage B

**Stage A is the default.** It covers static analysis of the IPA, everything
on your own test device, login, settings and profile edits on test accounts
you own through the app's own UI, and read-only requests with your own session
(a GET replayed after logout, a token-endpoint exchange for your own code).

**Stage B is blocked by default** and needs written sign-off naming the action,
account, request count and window. It covers any crafted, replayed or tampered
request that makes the production backend **write** (a deep link that moves
money, a CloudKit public-database write, a share-extension upload, a request
with the step-up flag flipped), flows that move money, message anyone other
than a tester account or publish content other users can see (unless the
client provides a sandbox environment), anything that touches another user's
account or data, anything that sends email, SMS or push to a person, and any
volume or rate test.

```
Stage B authorization
  App / build:      <bundle id, version, build>
  Action:           <e.g. one deep-link transfer of 0.01 between two tester-owned accounts>
  Accounts:         <tester accounts only>
  Blast radius:     <what the backend writes; who is notified>
  Reversibility:    <how it is undone, or that the client undoes it>
  Window:           <date/time>
  Authorized by:    <name/role>, in writing, <link>
```

Never: distribute a PoC app, test on a device that belongs to someone else,
install a profile, keyboard or VPN on anyone else's device, or keep any tool
running on a device after the engagement.

---

## Step 1: Build the app map

From the pipeline output, write down every trust boundary before testing.

```bash
APP=Payload/<App>.app
ls "$APP/PlugIns" "$APP/Extensions" 2>/dev/null     # .appex: share, keyboard, widget, intents, notification
ls "$APP/AppClips" 2>/dev/null                        # embedded App Clip (verify location)
ls "$APP/Frameworks"                                  # Flutter.framework, hermes, Xamarin, UnityFramework -> hunt-mobile-frameworks
for b in "$APP" "$APP"/PlugIns/*.appex; do
  exe=$(plutil -extract CFBundleExecutable raw -o - "$b/Info.plist")
  echo "== $b"; ipsw macho info "$b/$exe" --ent
done
```

Record per bundle:

| Item | Source | Feeds |
|---|---|---|
| `CFBundleURLTypes`, `LSApplicationQueriesSchemes` | Info.plist | Step 3, schemes |
| `com.apple.developer.associated-domains` (`applinks:`, `webcredentials:`, `appclips:`) | entitlements | Step 3, Step 4 passkeys |
| `keychain-access-groups`, `com.apple.security.application-groups` | entitlements | Step 2 |
| `com.apple.developer.icloud-container-identifiers`, `icloud-services` | entitlements | Step 3, CloudKit |
| `get-task-allow` true in a production build | entitlements | Step 6 (MASTG-TEST-0261) |
| `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace` | Info.plist | Step 2: `Documents/` is visible in Finder and Files |
| `NSUserActivityTypes`, App Intents metadata | Info.plist, bundle | Step 3 |
| `NSAppTransportSecurity`, `NSPinnedDomains` | Info.plist | Step 5 |
| `NSExtensionPointIdentifier`, `NSExtensionActivationRule`, `RequestsOpenAccess` | each appex Info.plist | Step 3 |

---

## Step 2: MASVS-STORAGE (and CRYPTO-2 key handling)

MASVS-STORAGE-1: the app securely stores sensitive data. MASVS-STORAGE-2: the
app prevents leakage of sensitive data. Full procedure, paths and grades:
`references/storage.md`.

Flows that move money, message anyone other than a tester account, or
publish content other users can see are Stage B (written sign-off) unless the
client provides a sandbox; everything else below is Stage A.

1. **Canaries first.** Use unique, greppable values for the test password,
   display name, address, card nickname, chat text and OTP-adjacent fields.
2. **Exercise every flow** on a fresh install: login, profile, payments,
   messaging, offline mode, document upload, logout.
3. **Pull the container** (jailbroken: the data container and every App Group
   container; stock device: an encrypted local backup, which also carries the
   app's backed-up files) and grep for the canaries and for tokens.
4. **Keychain:** dump and record each item's accessibility class and access
   control; flag secrets stored outside the Keychain.
5. **File protection:** record the `NSFileProtection` class of every file
   holding sensitive data.
6. **Leak channels:** pasteboard, app-switcher snapshot, unified log, keyboard
   cache, `NSURLCache`, cookies, WKWebView storage.
7. **Lifecycle:** what survives logout, what survives delete-and-reinstall
   (Keychain items do), what restores onto a second test device from backup.

| Check | Current MASTG tests | Typical grade |
|---|---|---|
| Plaintext secrets in sandbox files, UserDefaults, SQLite/Core Data/Realm | 0300, 0301, 0302 | P5 alone |
| Secrets in a shared App Group container | 0388, 0303 | P5; more if a third-party extension is a member |
| Weak file protection class on sensitive files | 0299 | P5 (physical access) |
| Sensitive files eligible for backup | 0215, 0298 | P5 |
| Secrets in logs | 0296, 0297 | P5 |
| Pasteboard exposure | 0276 to 0280 | P5 |
| Snapshot shows sensitive screen | 0290 | P5 |
| Keyboard caching of sensitive fields | 0313, 0314 | P5 |
| Hardcoded crypto keys protecting local data | 0213, 0214 | P5 unless the key also protects server data |

Storage findings need physical access or a compromised device, so HackerOne's
core ineligible list ("attacks requiring physical access to a device, unless
explicitly in scope") and most briefs exclude them alone. They earn more when a
**server credential** sits in the clear (a long-lived refresh token, an API
secret shared by all installs) or when the data is regulated (health, card).

---

## Step 3: MASVS-PLATFORM

MASVS-PLATFORM-1 (IPC), -2 (WebViews), -3 (user interface). Full procedure:
`references/platform.md`. Deep-link, extension, App Clip and intent tests that
make the backend act are Stage B (written sign-off); Stage A stops at the
request captured and dropped in the proxy. The reference marks each one.

| Surface | What to prove | MASTG | Typical grade |
|---|---|---|---|
| Custom URL scheme handler | A state-changing or data-revealing action from an untrusted link, no confirmation, no `sourceApplication` check | 0370, 0371 | VRT `Exposed Sensitive iOS URL Scheme` (VARIES) |
| Scheme parameter into a WKWebView | Attacker URL loaded in-app, bridge reachable | 0332, 0376 | XSS or open redirect nodes; ATO if a bridge leaks the token |
| Universal Link handler | Same input validation as schemes, on `webpageURL` | 0395 | as above |
| AASA scope | Paths that cover open redirects or user content; fallback-to-web leaks tokens in the URL | none current (0070 deprecated) | chain value |
| App extensions and App Groups | Extension accepts any input, shares secrets in the group | 0388 (0072 deprecated) | P5 to P3 by effect |
| Widgets, Live Activities | Sensitive data shown on the lock screen | none | P5 (physical) |
| App Clips | Invocation URL parameters trusted; shared data with the full app | none | as schemes |
| WKWebView file access | Broad `loadFileURL` read scope, relaxed file-origin flags | 0333, 0335, 0336 | P3 to P5 |
| JavaScript bridge | Native method callable from any loaded origin | 0376, 0377, 0379, 0380 | P2 to P3 when it yields a token |
| Custom keyboards | Sensitive fields not forced to the system keyboard | 0389, 0390, 0346, 0347 | P5 |
| App Intents / Siri / Shortcuts | Sensitive action or data available while locked | none | P5 to P4, argue |
| Handoff, NSUserActivity | Untrusted `userInfo` or `webpageURL` handled like a deep link | none | as schemes |
| iCloud / CloudKit | Public database exposes per-user records; Development container shipped | none | PII Leakage (VARIES) |

---

## Step 4: MASVS-AUTH

MASVS-AUTH-1 (secure auth protocols), -2 (local auth per platform practice),
-3 (step-up for sensitive operations). Full procedure:
`references/auth-and-session.md`.

- **LocalAuthentication versus Keychain-bound biometrics.** Static: find
  `evaluatePolicy` and `SecAccessControlCreateWithFlags`. Dynamic: run
  objection's `ios ui biometrics_bypass` and see whether the protected screen
  or secret opens. If it does, the gate is a boolean (MASTG-TEST-0266, 0267).
  If the secret is in the Keychain behind `kSecAccessControlBiometryCurrentSet`,
  the hook gets nothing.
- **The finding is server-side trust.** If a step-up request carries a
  client-asserted "biometric passed" field, or the server accepts the action
  without the signature the Secure Enclave key would make, that is a 2FA bypass
  (`Second Factor Authentication (2FA) Bypass`, P3) or worse. A pure local
  bypass is `Lack of Binary Hardening > Runtime Instrumentation-Based` (P5).
- **Tokens and sessions.** Where the refresh token lives, its lifetime, and
  whether logout, password change and device removal revoke it server-side
  (replay a read-only request after logout).
- **OAuth in native apps.** `ASWebAuthenticationSession` delivers the callback
  to the calling session; a custom-scheme redirect handled through `openURL`
  can be claimed by another app. Since iOS 17.4 the session also accepts an
  HTTPS callback bound to the app's associated domain. Check PKCE and `state`
  from the client side and hand server-side flaws to `hunt-oauth`.
- **Passkeys.** `webcredentials:` association, server-side challenge handling,
  user-verification enforcement and weaker fallbacks; account-binding tests go
  to `hunt-ato` and `hunt-mfa-bypass`.

---

## Step 5: MASVS-NETWORK

MASVS-NETWORK-1 (secure traffic), -2 (identity pinning). Full procedure:
`references/network.md`.

1. **Interception.** Burp or mitmproxy CA installed *and* enabled under
   Certificate Trust Settings. Proxy-unaware apps (Network.framework, QUIC,
   embedded TLS stacks) need a VPN-mode capture or a packet capture.
2. **Certificate validation, not pinning, is the real bug.** Untrust your CA
   and repeat. If the app still talks through the proxy with a forged
   certificate, it accepts any certificate (MASTG-TEST-0396, 0397). That is a
   network-attacker finding with no device compromise.
3. **ATS exceptions.** A config line alone is hardening. Capture an actual
   cleartext request carrying a session token or personal data before
   reporting (MASTG-TEST-0321, 0322, 0323, 0342).
4. **Pinning.** Present or absent, defeatable or not, it grades P5
   (`Mobile Security Misconfiguration > SSL Certificate Pinning`), and
   HackerOne lists "Lack of SSL Pinning" as core ineligible. Bypass it to reach
   the API, not to report it.

---

## Step 6: MASVS-RESILIENCE

MASVS-RESILIENCE-1 (platform integrity), -2 (anti-tampering), -3 (anti-static
analysis), -4 (anti-dynamic analysis). Full procedure and bypass notes:
`references/resilience.md`.

On bug-bounty programs these are almost never findings: every
`Lack of Binary Hardening` VRT node is P5, and HackerOne's core ineligible list
names "Lack of jailbreak detection in mobile apps". Report resilience as one
grouped hardening observation on a pentest that asked for MASVS-RESILIENCE,
and on a bounty only when a bypass is the step that unlocked a real
server-side bug (then it lives inside that report). Two exceptions are worth a
line on their own: a production build with `get-task-allow` (MASTG-TEST-0261),
and a server that advertises App Attest or DeviceCheck but accepts requests
without an assertion.

---

## Step 7: MASVS-CODE and MASVS-PRIVACY quick checks

These are short and mostly static.

| Check | How | MASTG |
|---|---|---|
| Minimum iOS version (`MinimumOSVersion`) still receives security fixes | Info.plist | CODE-1 |
| Forced update exists and is server-enforced (old build still served by the API?) | Run an old build; read-only calls | 0383, 0384 |
| Known-vulnerable embedded frameworks | `Frameworks/` versions, SBOM, `Podfile.lock`/`Package.resolved` if provided | 0273, 0275 |
| Unsafe deserialization (`NSKeyedUnarchiver` without secure coding) of untrusted data | Strings and xrefs | 0386 |
| Purpose strings match actual protected-resource use | Info.plist `NS*UsageDescription` vs runtime | 0360, 0361 |
| Entitlements without a feature behind them | Entitlements vs code | 0362, 0363 |
| Tracking domains not declared in the privacy manifest | `PrivacyInfo.xcprivacy` vs traffic | 0281 |

Outdated components grade `Using Components with Known Vulnerabilities >
Outdated Software Version` (P5) unless the vulnerable path is reachable and
demonstrated. Privacy findings are rarely in bounty scope; note them for
pentest reports.

---

## Step 8: Grade on what you proved

Node names and priorities checked against Bugcrowd VRT v1.19.1. VARIES means
no fixed default; argue it with `bugcrowd-reporting`.

| What you proved | VRT node | Default |
|---|---|---|
| Deep link performs a sensitive action or returns sensitive data with no user confirmation | Broken Access Control (BAC) > Exposed Sensitive iOS URL Scheme | VARIES |
| WebView bridge reachable from attacker-loaded content leaks the session token | Server Security Misconfiguration > OAuth Misconfiguration > Account Takeover, or XSS node by delivery | P2 / P3 |
| Script runs in an in-app WebView from a crafted link | Cross-Site Scripting (XSS) > Reflected > Non-Self | P3 |
| App opens an attacker URL from a crafted link, nothing else | Unvalidated Redirects and Forwards > Open Redirect > GET-Based | P4 |
| Malformed scheme crashes the app | Application-Level Denial-of-Service (DoS) > App Crash > Malformed iOS URL Schemes | P5 |
| Server trusts a client-side biometric or step-up flag | Broken Authentication and Session Management > Second Factor Authentication (2FA) Bypass | P3 |
| Local LAContext gate bypassed with a hook only | Lack of Binary Hardening > Runtime Instrumentation-Based | P5 |
| Custom-scheme OAuth redirect captured by a second app, code exchanged | Server Security Misconfiguration > OAuth Misconfiguration > Account Takeover | P2 |
| App accepts any TLS certificate, session token captured | Broken Authentication and Session Management > Cleartext Transmission of Session Token | P4 (request more) |
| Personal data sent over HTTP | Insecure Data Transport > Cleartext Transmission of Sensitive Data | VARIES |
| Session still valid server-side after logout | Broken Authentication and Session Management > Failure to Invalidate Session > On Logout (Server-Side Only) | P5 |
| Session still valid after password change | Broken Authentication and Session Management > Failure to Invalidate Session > On Password Reset and/or Change | P4 |
| Live backend secret in the IPA that works against a public asset | Sensitive Data Exposure > Disclosure of Secrets > For Publicly Accessible Asset | P1 |
| OAuth client secret in the IPA | Sensitive Data Exposure > Sensitive Data Hardcoded > OAuth Secret | P5 |
| CloudKit public database exposes other users' records | Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure | VARIES |
| Sensitive data unencrypted in the sandbox | Insecure Data Storage > Sensitive Application Data Stored Unencrypted > On Internal Storage | P5 |
| Sensitive screen in the app-switcher snapshot | Insecure Data Storage > Screen Caching Enabled | P5 |
| Secret written to the general pasteboard | Mobile Security Misconfiguration > Clipboard Enabled | P5 |
| Sensitive files included in backups | Mobile Security Misconfiguration > Auto Backup Allowed by Default (Android-named, nearest) | P5 |
| Sensitive field cached by the keyboard | External Behavior > Browser Feature > Autocorrect Enabled | P5 |
| Pinning absent or defeated | Mobile Security Misconfiguration > SSL Certificate Pinning > Absent / Defeatable | P5 |
| No jailbreak detection, no obfuscation, missing PIE or canaries | Lack of Binary Hardening > Lack of Jailbreak Detection / Lack of Obfuscation / Lack of Exploit Mitigations | P5 |

iOS has no external storage, so `On External Storage` (P4) does not apply
directly; data in an App Group shared with a third-party extension, or in a
`UIFileSharingEnabled` Documents folder, is the closest argument.

### What is not a finding

- Pinning absent or bypassed; jailbreak, Frida or debugger detection absent or
  bypassed; symbols present; no obfuscation. Each is P5 and core ineligible on
  HackerOne for pinning and jailbreak detection.
- Data readable only on a jailbroken device the attacker already controls,
  with no server credential in it.
- Firebase, Supabase-anon, Maps and analytics identifiers in the bundle
  (`hunt-cloud-backends` "not a finding" table).
- A URL scheme that opens a screen, with no action and no data.
- `NSAllowsArbitraryLoads` with no captured cleartext of sensitive data.
- An LAContext bypass that needs the victim's device to run your Frida hooks.
- Anything that only reproduces on an end-of-life iOS version the app no
  longer supports.
- "Runtime manipulation with Frida" as an attack class; many briefs exclude it
  by name. Read the brief.

---

## Step 9: Evidence

Follow `evidence-hygiene`. For every finding record: app version and build,
device model, iOS build, bench type (jailbroken, re-signed, Corellium),
timestamps, the exact command or hook used, the file path and protection class
or Keychain attributes, and a screenshot or screen recording of the effect on
your own account. Redact tokens to first and last four characters. For IPC
findings attach the PoC link or the PoC app's source, never a built binary
meant for others. Cite the Stage B sign-off for any backend write.

---

## Chain table

| Finding | Standalone | Where it goes next |
|---|---|---|
| Hardcoded API secret or backend key in the IPA | Varies | Validate per program rule; `hunt-cloud-backends`, `cloud-iam-deep` |
| Older API host or version in the IPA | Info | `hunt-shadow-api` diffing; `hunt-spa-api` unauth sweep |
| Deep link loads any URL in a WebView with a bridge | P3 to P2 | Token theft to ATO; `hunt-ato` |
| Custom-scheme OAuth redirect without PKCE | P2 | `hunt-oauth` for server-side redirect and PKCE enforcement |
| `applinks:` or redirect-URI domain dangling | Varies | `hunt-subdomain` takeover, then link capture |
| Step-up flag trusted server-side | P3 | `hunt-mfa-bypass`, `hunt-business-logic` |
| Any-certificate TLS acceptance | P4 | Report with captured token; `hunt-tls-network` is not needed |
| Plaintext refresh token on disk | P5 | Only grows if it is long-lived and not device-bound; `hunt-session` |
| CloudKit public records of other users | VARIES | `evidence-hygiene` for redaction; count, do not dump |

---

## Validation checklist

- [ ] Asset is the in-scope app and version; the bench is your own device or
      Corellium instance; the build used is recorded.
- [ ] `ios-redteam-pipeline` output reused; nothing re-derived here.
- [ ] Every claim reproduced on the current App Store build, not only on a
      re-signed build (or the difference stated).
- [ ] Storage claims show the canary, the path, and the protection class.
- [ ] IPC claims show the handler, the input, and the effect on your account.
- [ ] Network claims show captured traffic, with the CA untrusted for the
      certificate-validation test.
- [ ] Every backend write had a logged Stage B sign-off; no other user's
      account or device was touched; no PoC app left your device.
- [ ] Grade taken from Step 8 and the program brief, not from MASVS failure alone.
- [ ] Resilience items grouped as hardening, not filed one by one.
- [ ] Tokens redacted; test accounts and devices reset after the engagement.

---

## Sources

External sources (checked October 2026): OWASP MASVS <https://mas.owasp.org/MASVS/>,
MASTG tests <https://github.com/OWASP/mastg/tree/master/tests-beta/ios>,
Bugcrowd VRT <https://github.com/bugcrowd/vulnerability-rating-taxonomy>,
HackerOne core ineligible findings
<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>,
Apple associated domains
<https://developer.apple.com/documentation/xcode/supporting-associated-domains>,
App Intents authentication policy
<https://developer.apple.com/documentation/appintents/intentauthenticationpolicy>.

---

## Related Skills & Chains

- `ios-redteam-pipeline`: acquisition, decryption, static grep, Frida and
  pinning-bypass templates. Run first.
- `hunt-mobile-android` and `hunt-mobile-frameworks`: the Android
  methodology and cross-platform framework internals (Flutter, React Native,
  Xamarin, Unity, Cordova). Same MASVS layout.
- `apk-redteam-pipeline`: the Android acquisition counterpart.
- `hunt-cloud-backends`: BaaS configs found in `GoogleService-Info.plist` or
  the binary.
- `hunt-spa-api`, `hunt-idor`, `hunt-api-misconfig`, `hunt-shadow-api`: the
  backend once traffic is visible.
- `hunt-oauth`, `hunt-ato`, `hunt-mfa-bypass`, `hunt-session`,
  `hunt-jwt-crypto`: server-side halves of Step 4.
- `hunt-subdomain`: dangling `applinks:` or redirect-URI domains.
- `evidence-hygiene`, `triage-validation`, `report-writing`,
  `bugcrowd-reporting`: evidence, gates, write-up and VRT mapping.

---
name: hunt-mobile-android
description: "Android app pentest aligned to OWASP MASVS v2.1 and MASTG v2, for an authorized tester with the APK and a test device. STORAGE (SharedPreferences, SQLite, backups, logcat, Keystore), PLATFORM (exported components, intent redirection, PendingIntents, content providers, WebView bridges, deep links and App Links, tapjacking, task hijacking), AUTH (BiometricPrompt without CryptoObject, Frida bypass, token storage), NETWORK (Network Security Config, pinning and bypass), RESILIENCE. Use when an Android app is in scope; iOS and Flutter go to hunt-mobile-ios and hunt-mobile-frameworks."
metadata:
  sources: owasp_masvs, owasp_mastg, android_developers_docs, android_source_docs, bugcrowd_vrt, hackerone_docs, tool_documentation, public_research
  report_count: 0
---

## When to use

Trigger when an Android app is in scope and you have the APK (or the split
APKs) plus a test device or emulator you control. Typical signals: the program
lists a Play Store package ID or an APK as an asset, recon found an `*.apk` on
a client host, or `apk-redteam-pipeline` has already decompiled the build and
you now need to test the app itself rather than mine it for secrets.

This skill is the MASVS-aligned test plan for the app on the device: what it
stores, what it exposes to other apps, how it authenticates, how it talks to
its backend, and how it defends itself. It starts where
`apk-redteam-pipeline` Stage 5 ends (exported components listed, secrets
grepped, Firebase config found) and does not repeat acquisition, decompilation,
the secret-regex catalogue or the Frida pinning template.

`report_count` is 0: the skill is built from OWASP MASVS and MASTG, Android
developer and AOSP documentation, Bugcrowd VRT, platform policy pages and tool
documentation, not from a counted corpus of disclosed reports.

### Where the chain ends

Stop at **weakness proved on your own device with your own test account,
impact described, evidence captured**:

- Local data exposure: stop at one screenshot or file listing showing the
  sensitive value in your own test account's data. Never pull another user's
  data from a shared device, a backup you did not create, or a support dump.
- IPC weakness (exported component, intent redirection, provider traversal,
  WebView bridge): stop at a benign marker reached from `adb shell am` /
  `content` or from a throwaway PoC app installed only on your test device. A
  PoC app is never published, never distributed and never pointed at another
  person's device.
- Task hijacking and tapjacking: stop at "the mechanism works", shown with a
  plain marker screen. No look-alike login screen, no credential capture, no
  accessibility-service abuse.
- Network: stop at intercepted traffic of your own session. Replaying or
  modifying a request that changes server state is backend testing and is
  handed to the web skills under their Stage B rules.
- Resilience bypass: record it as the means that made testing possible. It is
  almost never the finding.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| APK acquisition, split/XAPK handling, jadx/apktool decompilation, secret and URL grep, pinned-cert extraction, exported-component grep, Frida pinning and OkHttp hook templates, mitmproxy setup | `apk-redteam-pipeline` Stages 0-8 |
| iOS apps (IPA, Keychain, ATS, URL schemes, Universal Links) | `hunt-mobile-ios`, `ios-redteam-pipeline` |
| Flutter, React Native, Xamarin/.NET MAUI, Unity, Cordova/Capacitor internals (Dart snapshots, Hermes bundles, IL2CPP, JS bridges) | `hunt-mobile-frameworks` |
| Firebase, Supabase, Amplify/Cognito, Auth0, Clerk and other BaaS config found in the APK | `hunt-cloud-backends` |
| The backend API once traffic is visible (IDOR, BAC, mass assignment, versions) | `hunt-spa-api`, `hunt-shadow-api`, `hunt-api-misconfig`, `hunt-idor` |
| OAuth/OIDC server-side flaws (redirect_uri, state, PKCE enforcement) | `hunt-oauth` |
| Server-side session lifecycle (logout, rotation, revocation) | `hunt-session` |
| gRPC and WebSocket backends | `hunt-grpc`, `hunt-websocket` |
| Web clickjacking (frames, X-Frame-Options) | `hunt-clickjacking` |
| Cloud keys found in the APK | `cloud-iam-deep` |
---

## References index

| File | Covers | Trigger phrases |
|---|---|---|
| `references/storage.md` | sandbox, SharedPreferences/DataStore, SQLite/Room/Realm, external storage, backups (allowBackup, adb backup, Auto Backup, bmgr), logcat, FLAG_SECURE, clipboard, Keystore and attestation, Android 15/16/17 storage changes | shared_prefs, allowBackup, dataExtractionRules, logcat, FLAG_SECURE, clipboard, keystore, key attestation |
| `references/ipc-and-platform.md` | exported components, intent redirection, PendingIntent, implicit intents, content provider traversal and SQLi, WebView bridges/file access/URL loading, deep links and App Links, tapjacking, task hijacking, drozer/am | exported activity, intent redirection, content provider, addJavascriptInterface, deep link, assetlinks, tapjacking, strandhogg |
| `references/auth-and-session.md` | BiometricPrompt and CryptoObject, local-auth bypass, token storage, session handling on device, OAuth redirect capture, autofill | biometricprompt, cryptoobject, fingerprint bypass, token storage, custom scheme, pkce, autofill |
| `references/network.md` | Network Security Config, cleartext, pinning and bypass, proxy-unaware apps, WebSocket/gRPC transport | network security config, cleartext, certificate pinning, objection sslpinning, apk-mitm, flutter proxy |
| `references/resilience.md` | root/Frida/debugger/emulator detection, anti-tamper, obfuscation, debuggable, Play Integrity | rootbeer, play integrity, frida detection, obfuscation, anti-tamper, debuggable |
| `references/tooling.md` | jadx, apktool, Frida 16/17, objection, MobSF, drozer, emulator images, Burp CA on Android 14+, rooting | jadx, apktool, frida 17, objection, mobsf, drozer, writable-system, conscrypt apex, magisk |

---

## Rate and safety posture

- **Stage A is the default and is read-only on your own test device**: static
  analysis, sandbox snapshots, reading settings, triggering the app's own
  components with benign markers, and intercepting your own session's traffic.
- **Stage B needs written sign-off** and covers anything that reaches the
  production backend in a way that writes or affects other users: replaying a
  state-changing request, proving a logout/session-revocation gap, capturing an
  OAuth redirect with a second account, writing through a content provider or a
  BaaS, or restoring a backup to prove a token survives. Every Stage B block in
  the references names "Stage B" / "sign-off" above it.
- **Never attack other users' devices.** Every IPC, tapjacking and task-
  hijacking PoC models a malicious app but runs only on your own device, with
  a throwaway PoC app you never distribute and a benign marker (toast, canary
  request, marker screen). No credential-phishing UI, no persistence, no boot
  receivers, no accessibility-service abuse.
- **Resilience bypasses enable testing; they are not the finding.** Bypass root
  / pinning / anti-debug on your own install to see the real behaviour, and
  report what you then find, not the missing control.

## MASVS control groups and where each is tested

Aligned to **MASVS v2.1.0** and **MASTG v2.0.0** (v2 tests are canonical;
legacy `MASTG-TEST-00xx` are deprecated). Each group's depth is in `references/`.

### MASVS-STORAGE and MASVS-PRIVACY (`references/storage.md`)

Local data, backups, logs, screenshots, clipboard, Keystore. Method: run the
app with known markers, then search every writable location for them.

| Control | Quick test | MASTG-TEST |
|---|---|---|
| Sensitive data in the sandbox | snapshot `/data/data/<pkg>`, grep markers | 0207, 0287, 0001(dep) |
| External / shared storage | grep `/sdcard/Android/data/<pkg>` and shared dirs | 0200-0202 |
| Backups | `allowBackup`/`dataExtractionRules`, `bmgr backupnow`, read it | 0216, 0262 |
| Logs | `adb logcat --pid`, grep markers and `HttpLoggingInterceptor` | 0203, 0231 |
| Screenshots / recents | `screencap` on sensitive screens; FLAG_SECURE | 0289, 0291 |
| Clipboard / keyboard | `setPrimaryClip` on secrets; input types | MASWE-0030 (no test) |
| Keystore / attestation | key provenance; server-side chain verification | KNOW-0043/44/47 |

### MASVS-CRYPTO (inline + `storage.md` §9)

Covered where keys are found. Red flags: hardcoded AES keys/IVs, keys derived
from `ANDROID_ID`, secrets stored next to their key, software-only keys for
high-value data. MASTG-TEST-0212 (hardcoded keys), 0208 (weak key sizes),
0307/0308 (key reuse). Grade by what the key protects.

### MASVS-AUTH (`references/auth-and-session.md`)

Local biometric/PIN gates, token storage, session handling seen from the
device, OAuth redirect capture, autofill. The server owns most of AUTH; this
file owns the device side and hands the rest to `hunt-oauth`, `hunt-session`,
`hunt-ato`. Biometric tests MASTG-TEST-0326-0330; the no-CryptoObject bypass
maps to MASWE-0020.

### MASVS-NETWORK (`references/network.md`)

Network Security Config, cleartext, pinning (and bypass to keep testing),
proxy-unaware apps, WebSocket/gRPC transport. MASTG-TEST-0235/0236 (cleartext),
0242/0244 (pinning), 0282/0283 (custom trust / hostname). Backend protocol
testing goes to `hunt-websocket`, `hunt-grpc`, `hunt-spa-api`.

### MASVS-PLATFORM (`references/ipc-and-platform.md`)

Exported activities/services/receivers/providers, intent redirection,
PendingIntent mutability, implicit intents, provider path traversal and SQLi,
WebView (`addJavascriptInterface`, file/content access, URL loading), deep
links and App Link verification, tapjacking, task hijacking. MASTG-TEST-0364-
0366, 0381, 0355-0357, 0339, 0250-0253/0334, 0393/0394, 0340.

### MASVS-CODE (inline)

- `android:debuggable="true"` in release (`resilience.md` §3; MASTG-TEST-0226).
- `minSdkVersion` too low, so platform mitigations above do not apply
  (CODE-1). State `targetSdk`/`minSdk` from `dumpsys package` on every finding
  whose severity depends on an Android version.
- Third-party libraries with known CVEs (MASTG-TEST-0272/0274): list them from
  the decompiled dependencies; a real finding needs a reachable vulnerable
  path, not just presence.
- Untrusted input: WebView URL loading (0398-0400), zip path traversal
  (blocked for apps targeting 14+), dynamic code loading (read-only for 14+).

### MASVS-RESILIENCE (`references/resilience.md`)

Root / Frida / debugger / emulator detection, anti-tamper and signature
checks, obfuscation. **Almost never a finding on its own** (see grading). This
group is mostly the cost of doing the other tests; `resilience.md` is how to
get past it and the narrow cases where it is the bug.

## Grading: VRT nodes and what programs reject

Node names and default priorities are from Bugcrowd VRT **v1.19.1**
(2026-07-08, `vulnerability-rating-taxonomy.json` on the `master` branch), the
same release `bugcrowd-reporting` §1.3 uses. Programs can remap defaults:
read what the form suggests for this program.

| Finding on Android | VRT node (default) |
|---|---|
| Token, password or PII in a world-readable or shared-storage file | Insecure Data Storage > Sensitive Application Data Stored Unencrypted > On External Storage (P4) |
| Same, in the app's private sandbox | ... > On Internal Storage (P5) |
| Backup includes sensitive data | Mobile Security Misconfiguration > Auto Backup Allowed by Default (P5) |
| Sensitive screen in the recents thumbnail | Insecure Data Storage > Screen Caching Enabled (P5) |
| Secret copied to the clipboard by the app | Mobile Security Misconfiguration > Clipboard Enabled (P5); shared links only: External Behavior > System Clipboard Leak > Shared Links (P5) |
| Exported component exposes data or a privileged action | Broken Access Control (BAC) > Exposed Sensitive Android Intent (VARIES) |
| Malformed intent crashes the app | Application-Level DoS > App Crash > Malformed Android Intents (P5) |
| Tapjacking | Mobile Security Misconfiguration > Tapjacking (P5) |
| Session token or credential over cleartext | Broken Authentication and Session Management > Cleartext Transmission of Session Token (P4); Insecure Data Transport > Cleartext Transmission of Sensitive Data (VARIES) |
| App downloads and runs code without an integrity check | Insecure Data Transport > Executable Download > No Secure Integrity Check (P4) |
| Pinning absent / defeatable | Mobile Security Misconfiguration > SSL Certificate Pinning > Absent (P5) / Defeatable (P5) |
| Root detection, obfuscation, anti-instrumentation missing | Lack of Binary Hardening > Lack of Jailbreak Detection / Lack of Obfuscation / Runtime Instrumentation-Based (all P5) |
| Hardcoded live secret with server impact | Sensitive Data Exposure > Disclosure of Secrets > For Publicly Accessible Asset (P1) / For Internal Asset (P3) / Pay-Per-Use Abuse (P4) |
| Hardcoded OAuth client secret | Sensitive Data Exposure > Sensitive Data Hardcoded > OAuth Secret (P5) |
| Deep link to account takeover via OAuth | Server Security Misconfiguration > OAuth Misconfiguration > Account Takeover (P2) |
| Auth screen skipped, session obtained | Broken Authentication and Session Management > Authentication Bypass (P1) |

There is no VRT node for "sensitive data in logcat". Use Insecure Data
Storage or Sensitive Data Exposure > Other and argue the data class
(`bugcrowd-reporting` §1.4).

### Not a finding on its own

Platform guidance and typical program policies agree on this list. HackerOne's
Core Ineligible Findings page names "Lack of SSL Pinning", "Lack of jailbreak
detection in mobile apps" and "Attacks requiring physical access to a device";
Google's Mobile VRP excludes attacks that need a rooted device, "Variants of
Strandhogg and Tapjacking", hardcoded API keys, and bugs that do not work on
the latest Android release. Public program policies commonly add:

| Usually ineligible alone | What makes it reportable |
|---|---|
| Certificate pinning absent or bypassable | Never by itself. Report what the traffic shows (IDOR, secret, cleartext) |
| Root, emulator, debugger or Frida detection absent or bypassable | Never by itself. It is a tool cost, not a vulnerability |
| No obfuscation, no binary protection, path strings in the binary | A live secret or logic flaw the binary reveals |
| Data readable only with root or physical access to an unlocked device | Same data reachable without root: shared storage, backup, exported provider, logs read by another app on older Android |
| Exported component with no sensitive data or action | A non-exported component, file, token or state change reached through it |
| Crash from a malformed intent | A crash that leaks data, or a persistent boot-loop / denial of the app; a bare crash is P5 at most |
| Clipboard of shared links, URI visibility to apps with that permission | The app placing a password, OTP or token on the clipboard |
| Task hijacking, tapjacking | Program explicitly lists them, and the affected Android versions are supported |
| Bugs needing a malicious app on the victim's device | Many programs reject this threat model; others accept it when the app needs zero permissions. Read the policy first |
| Bugs only on Android versions the program does not support | Reproduce on the minimum supported version the policy names |


## Sources

Checked October 2026. OWASP MASVS v2.1.0 (<https://mas.owasp.org/MASVS/>),
MASTG v2.0.0 and MASWE v1.0.0 (<https://mas.owasp.org/>). Android developer
behaviour-change and risk pages
(<https://developer.android.com/about/versions/>,
<https://developer.android.com/privacy-and-security/risks>), AOSP
(<https://source.android.com/>). Bugcrowd VRT v1.19.1
(<https://github.com/bugcrowd/vulnerability-rating-taxonomy>), HackerOne Core
Ineligible Findings
(<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>),
Google Mobile VRP
(<https://bughunters.google.com/about/rules/6618732618186752>). RFC 8252
(<https://www.rfc-editor.org/rfc/rfc8252>). Tool docs: Frida
(<https://frida.re/docs/>), objection, jadx, apktool, drozer, MobSF, HTTP
Toolkit Android-14 CA (<https://httptoolkit.com/blog/android-14-install-system-ca-certificate/>).
Research: WithSecure android-keystore-audit, AutoSpill (Black Hat EU 2023),
"Tabbed Out" Custom Tabs (IEEE S&P 2024), Oversecured content-provider writeups.

## Related skills and chains

- `apk-redteam-pipeline`: acquisition, jadx/apktool, the 60-pattern secret
  grep, pinned-cert extraction, exported-component grep, the Frida pinning and
  OkHttp hook templates, mitmproxy. This skill starts after its Stage 5.
- `hunt-mobile-ios`, `ios-redteam-pipeline`: the iOS counterpart.
- `hunt-mobile-frameworks`: Flutter, React Native, Xamarin/MAUI, Unity,
  Cordova/Capacitor internals and their traffic-interception quirks.
- `hunt-cloud-backends`: Firebase, Supabase, Amplify/Cognito, Auth0, Clerk and
  other BaaS config pulled from the APK.
- `hunt-spa-api`, `hunt-shadow-api`, `hunt-api-misconfig`, `hunt-idor`: the
  backend API once traffic is visible.
- `hunt-oauth`, `hunt-session`, `hunt-ato`: OAuth/OIDC, session lifecycle,
  account-takeover flows that a device-side primitive feeds.
- `hunt-websocket`, `hunt-grpc`: those backend protocols seen inside the app.
- `hunt-clickjacking`: web UI redressing (distinct from Android tapjacking).
- `cloud-iam-deep`: AWS/GCP/Azure keys recovered from the APK.
- `evidence-hygiene`, `triage-validation`, `report-writing`,
  `bugcrowd-reporting`: redaction, false-positive gates, write-up, VRT mapping.

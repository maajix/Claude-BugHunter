# IPC and platform interaction (MASVS-PLATFORM)

Every command here runs against the target app on **your own test device or
emulator**, signed in with **your own test account**. A throwaway PoC app, when
one is needed, is built for that device only, never published and never
installed anywhere else. If an IPC path ends in a server-side state change
(a transfer, a password change, a post, a deletion), stop at "the action
screen is reachable with attacker-chosen parameters" and treat any
confirmation click as backend testing under the web skills' Stage B rules.

```bash
PKG="com.client.app"            # from the program's scope
adb shell pm path "$PKG"        # confirm the build you decompiled is the one installed
adb shell dumpsys package "$PKG" > evidence/dumpsys_package.txt   # host-side redirect
```

`dumpsys package` gives the installed truth (resolved intent filters, granted
permissions, `targetSdk`, flags such as `DEBUGGABLE` and `ALLOW_BACKUP`), which
beats the decompiled manifest when a build uses manifest placeholders or
dynamic feature modules.

## 1. Enumerate the attack surface

Start from the installed app, not just the decompiled manifest:

```bash
adb shell dumpsys package "$PKG" | sed -n '/Activity Resolver Table/,/Service Resolver Table/p'
# drozer gives the exported set with permission context in one call:
#   run app.package.attacksurface com.client.app   # exported counts per type
#   run app.package.info          com.client.app   # permissions, data dirs (verify module name)
```

A component is reachable from another app when `android:exported="true"`, or
when it has an `<intent-filter>` and no explicit `exported` (implicitly true
only below API 31; since Android 12 the attribute is mandatory, so a build that
installs has it set one way or the other). Record, per component: exported
flag, the permission guarding it (if any), and whether its extras flow into a
sink (a WebView load, a file open, a nested intent, a SQL query).

MASTG: exported activities/services/receivers that expose sensitive
functionality are MASTG-TEST-0364/0365/0366.

## 2. Exported activities and services

Trigger each exported component from your own device and watch what it does.
If a component performs a server-side action on launch (the "delete account",
"confirm payment", "change setting" case), that `am start` is a production
write: this is **Stage B**, needs written sign-off, and uses your own test
account. Without sign-off, stop at "the confirmation screen is reachable with
attacker-chosen extras".

```bash
# Launch an exported activity, passing attacker-controlled extras
adb shell am start -n "$PKG/.SomeExportedActivity" --es url "https://canary.example/marker"
# Start/bind an exported service
adb shell am start-service -n "$PKG/.SomeExportedService" --es cmd probe
# objection equivalents: android intent launch_activity <Class>
```

Findings worth chasing: an exported activity that renders attacker-controlled
content in a WebView (§5), one that performs a privileged action (delete
account, change setting) without re-auth, one that returns data via
`setResult`, or one reachable **behind** the lock screen. A component that only
crashes on a malformed intent is at most VRT Application-Level DoS > App Crash
> Malformed Android Intents (P5); data or action exposure is BAC > Exposed
Sensitive Android Intent.

## 3. Intent redirection (the "confused deputy")

The classic bug: the app reads an `Intent` (or a URI) out of an incoming
intent's extras and then `startActivity`/`startService`s it, so your component
rides the victim app's identity and permissions into a non-exported component
or a `content://` it can read but you cannot.

- Static: grep the decompiled code for `getParcelableExtra(` returning an
  `Intent`, `Intent.parseUri(`, `getStringExtra("...url...")` feeding
  `startActivity`, and for `FLAG_GRANT_READ_URI_PERMISSION` being forwarded.
- The mitigations the risk page names: `IntentSanitizer`, an explicit
  `resolveActivity` allowlist, clearing the `FLAG_GRANT_*` flags.
- **Android 16 hardens intent redirection by default**; the opt-out is
  `Intent.removeLaunchSecurityProtection()`. An app that calls that, or targets
  below 16, is where redirection still lands. State the `targetSdk`.

PoC on your own device: a throwaway app (or `am` with `--esn`/`--es` carrying a
nested `intent:` URI) that sends the redirecting intent, and a benign marker
(a toast, a request to your canary host) proving the inner component ran. No
victim, no distribution.

Severity: VRT BAC > Exposed Sensitive Android Intent (VARIES), graded by what
the inner component or `content://` exposes. Google's Mobile VRP explicitly
lists "Intent redirections leading to launching non-exported application
components" as qualifying, so this threat model is accepted on at least some
programs.

## 4. PendingIntent and implicit intents

- **PendingIntent mutability.** A mutable `PendingIntent` wrapping an intent
  with no explicit component lets the receiver fill in the blanks and act as
  the app. Grep for `PendingIntent.getActivity/Service/Broadcast` without
  `FLAG_IMMUTABLE`. Apps targeting Android 12+ must specify mutability; a
  mutable PendingIntent with an implicit base intent throws on Android 14+.
  MASTG-TEST-0381.
- **Implicit intents carrying sensitive extras.** An implicit intent (action,
  no package/component) can be caught by any app with a matching filter. Grep
  for `setPackage` being absent on `startActivity`/`sendBroadcast` that carry
  tokens or PII. Android 14+ only delivers an implicit intent to exported
  components. MASTG-TEST-0372/0374; implicit-intent hijacking risk page
  mitigation is `setPackage()`.
- **Broadcasts.** Runtime receivers must declare `RECEIVER_EXPORTED` /
  `RECEIVER_NOT_EXPORTED` on Android 14+. A sticky or exported receiver that
  acts on attacker extras is the same confused-deputy shape.

Severity: VRT BAC > Exposed Sensitive Android Intent (VARIES). Google's Mobile
VRP lists "unsafe usage of pending intents" as qualifying with shown impact;
grade by the action the filled-in intent performs.

## 5. WebView

WebView is MASVS-PLATFORM-2. Check the settings in the decompiled code, then
confirm at runtime. Risk pages: `insecure-webview-native-bridges`,
`webview-unsafe-file-inclusion`, `unsafe-uri-loading`, `cross-app-scripting`.

| Setting | Secure value | Note |
|---|---|---|
| `setJavaScriptEnabled` | app's choice | default false; JS enabled is not a finding by itself (legacy MASTG-TEST-0031 deprecated with no replacement) |
| `setAllowFileAccess` | false | default false only when targeting API 30+; true below that. MASTG-TEST-0252/0253 |
| `setAllowContentAccess` | false if unused | default true; lets `content://` load. MASTG-TEST-0250/0251 |
| `setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs` | false | deprecated, "not secure"; true below API 16. A `file://` origin reading any file or any origin = universal XSS / local file theft |
| `addJavascriptInterface` | avoid, or `@JavascriptInterface` only | injected into every frame including iframes, no origin check. MASTG-TEST-0334 |
| `addWebMessageListener` | set `allowedOriginRules`, never `*` | rules match scheme/host/port, ignore path; wildcard only as leading subdomain |

The dangerous combinations:

- `addJavascriptInterface` + a WebView that loads attacker-influenced content
  (from an exported activity's `url` extra, a deep link, or a `http://`/mixed
  load) = JavaScript reaching native methods. Pre-API-17 this was any public
  method; since 17 only `@JavascriptInterface`-annotated ones. This is the
  `apk-redteam-pipeline` "exported Activity with WebView" lead, tested here.
- `setAllowUniversalAccessFromFileURLs(true)` + a `file://` load you control =
  read any file the app can and exfiltrate it (universal XSS). Serve local
  content through `WebViewAssetLoader`
  (`https://appassets.androidplatform.net/...`) instead of `file://`.
- `shouldOverrideUrlLoading` that validates the host with a loose `contains`
  or regex instead of parsing `Uri` scheme+host = open redirect into the
  WebView. MASTG-TEST-0398/0400.
- `setWebContentsDebuggingEnabled(true)` in release lets you attach
  `chrome://inspect` to the WebView (MASTG-TEST-0227); a weak finding alone but
  a free DOM into the app.

PoC: load your marker page in the target WebView via whatever reaches it
(exported activity extra, deep link), and show the bridge method firing or a
local file read, from your own device. Severity follows what the bridge or the
file read reaches; universal file read of the sandbox is the high case. VRT has
no clean node for in-app WebView XSS or universal file read, so map it via
`bugcrowd-reporting` §1.4 and argue impact (local file theft, bridge-reached
native action); a disclosed secret maps to Sensitive Data Exposure.

## 6. Content providers: path traversal and SQL injection

```bash
# Enumerate and probe exported providers (read-only)
#   run app.provider.finduri    com.client.app
#   run app.provider.query      com.client.app
#   run scanner.provider.finduris com.client.app
#   run scanner.provider.traversal com.client.app
#   run scanner.provider.injection com.client.app
adb shell content query --uri content://<authority>/<path>          # read
adb shell content read  --uri "content://<authority>/..%2F..%2Fdatabases%2Fapp.db"   # traversal probe
```

- **Path traversal via a file-backed provider.** `getLastPathSegment` /
  `getPathSegments` decode `%2F`, and an `openFile` that does not canonicalise
  serves files outside its intended root. `<root-path>` in a FileProvider
  exposes `/`. Probe with an encoded `../` sequence reading a file you own
  (the app's own DB), never a write. Fix guidance: `getCanonicalPath()` +
  `startsWith(expectedDir)`, no `<root-path>`. MASTG-TEST-0357; Google Play
  FAQ on `getLastPathSegment`.
- **SQL injection in a provider.** A provider that concatenates the `selection`
  (and, less commonly, `projection` or `sortOrder` (verify)) into its SQL is
  injectable. Prove it
  **read-only**: a `'` to force an error differential, or a `projection` such
  as `"* FROM sqlite_master--"` to read schema. Do not send UPDATE, DELETE or
  DROP through a provider; a read differential proves the bug. MASTG-TEST-0339;
  fix is `selectionArgs` + `SQLiteQueryBuilder.setStrict*`.
- **openFile mode confusion.** Some `openFile` implementations ignore the
  requested mode, so a provider meant for writes also reads. Note it; the read
  is the proof.

Exported providers are MASTG-TEST-0355/0356. A provider exposing another user's
or a non-exported DB's data is BAC; Google's Mobile VRP explicitly lists
"content providers... that can be manipulated to expose sensitive data".

## 7. Deep links and App Link verification

```bash
# What the app claims
adb shell pm get-app-links "$PKG"                 # per-host: verified / none / legacy_failure
adb shell dumpsys package "$PKG" | sed -n '/Schemes:/,/^$/p'
# Does the website back the claim?
curl -s https://client.example/.well-known/assetlinks.json | python3 -m json.tool
curl -s "https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://client.example&relation=delegate_permission/common.handle_all_urls"
# Fire a link at the app (your device)
adb shell am start -a android.intent.action.VIEW -d "https://client.example/path?next=https://canary.example"
adb shell am start -a android.intent.action.VIEW -d "clientapp://open?url=https://canary.example"
```

- **Custom schemes are claimable by any app.** A sensitive action behind
  `clientapp://` with no second check is reachable by a malicious app. The
  mitigation is an **App Link**: an `https` intent filter with
  `android:autoVerify="true"` plus a matching `assetlinks.json`
  (`/.well-known/assetlinks.json`, HTTPS, no redirect, `application/json`,
  correct `package_name` and `sha256_cert_fingerprints`).
- **Verification gaps.** `pm get-app-links` showing `none`/`legacy_failure`, a
  missing or wrong `assetlinks.json`, or a fingerprint that does not match the
  signing cert means the `https` links are not auto-verified: the user gets a
  chooser and another app can grab them. Android 12+ sends unverified web
  intents to the browser, not the app.
- **Parameter injection.** A deep link whose `url`/`next`/`redirect` param is
  loaded in a WebView (§5) or drives an OAuth redirect (`auth-and-session.md`
  §5) is the usual chain; `hunt-oauth` owns the OAuth side. Validate params
  against an allowlist (unsafe-deep-links risk page).
- **Dynamic App Links** (Android 15+ with Google services) add
  `dynamic_app_link_components` rules in `assetlinks.json`; they cannot widen
  the manifest's host scope and fall back to the manifest on malformed rules.

Severity: a deep link reaching account takeover through an OAuth redirect is
VRT Server Security Misconfiguration > OAuth Misconfiguration > Account
Takeover (P2); "Intent or URL Redirection leading to phishing" is explicitly
out of scope on some programs (Temu), so lead with the concrete account impact,
not the redirect. MASTG-TEST-0393 (unverified App Links), 0394 (custom-scheme
handler input validation); techniques MASTG-TECH-0172/0174.

## 8. Custom Tabs (vs embedded WebView for OAuth)

A Custom Tab (`CustomTabsIntent`) is a Chrome tab the app launches, not a
WebView it controls. The embedding app sees only low-entropy navigation
callbacks and engagement signals, and the loaded URL only after the user taps
an app-provided action; it has no access to cookies, DOM or script injection.
That is why RFC 8252 (App. B.2) and Google point OAuth at Custom Tabs (or App
Links), not embedded WebViews.

- **Where it is the finding.** An app that renders a login (especially a
  third-party identity provider's) inside its own **WebView** instead of a
  Custom Tab is the precondition for credential capture and AutoSpill
  (`auth-and-session.md` §5-6). Flag the WebView login; the Custom Tab itself
  is the safe pattern.
- **postMessage.** `CustomTabsSession.requestPostMessageChannel` needs a Digital
  Asset Links statement with relation `delegate_permission/common.use_as_origin`;
  that site becomes the message origin. The test is whether the app's handler
  validates `sourceOrigin` and how broadly the asset-links statement is scoped.
- **Research.** "Tabbed Out" (IEEE S&P 2024) found browser/platform side
  channels (cross-context state inference, SameSite bypass) and phishing via UI
  customization. These are mostly browser/OS issues, not an app bounty finding;
  cite them only when the app's own customization enables the phishing.

## 9. Tapjacking and task hijacking

Both are UI-redress classes. Prove the **mechanism** with a benign marker
overlay or a benign same-affinity activity on **your own device**. No
look-alike login, no credential capture, no accessibility-service abuse, no
boot receiver, no icon hiding. Web clickjacking (iframes, X-Frame-Options)
is a different thing: `hunt-clickjacking`.

- **Tapjacking.** An overlay (`TYPE_APPLICATION_OVERLAY`) over the target's
  sensitive buttons. Defences: `android:filterTouchesWhenObscured="true"` /
  `setFilterTouchesWhenObscured(true)`, checking `FLAG_WINDOW_IS_
  PARTIALLY_OBSCURED`, and `Window.setHideOverlayWindows(true)` (API 31+).
  Android 12 already blocks untrusted touches when overlay opacity exceeds 0.8.
  VRT Mobile Security Misconfiguration > Tapjacking (P5), risk page `tapjacking`,
  MASTG-TEST-0340.
- **Task hijacking / StrandHogg.** The original abuses `taskAffinity` +
  `allowTaskReparenting`; StrandHogg 2.0 is CVE-2020-0096 (patched 2020,
  Android 8-9 in the May 2020 bulletin). Google's page says devices on API 30+
  (Android 11) carry the OS patch and recommends `minSdkVersion="30"`. Android
  15 (targeting 35) prevents other apps launching arbitrary activities into
  your task; Android 17 adds Activity-Sandwich protection, turned on by setting
  `android:allowCrossUidActivitySwitchFromBelow="false"` (the guide ties this to
  apps targeting SDK 37; the heading says Android 15 (verify)). Confirm the
  Android version is one the program supports before filing.

**Grading reality:** Google's Mobile VRP lists "Variants of Strandhogg and
Tapjacking" as **non-qualifying**, and several programs (Decathlon, YesWeHack
boilerplate) exclude task hijacking outright. File these only when the program
explicitly accepts them and the affected Android versions are in support.

## 10. Evidence for this file

- `dumpsys package` excerpt showing the exported component and its guard.
- The exact `am`/`content`/drozer command and the benign marker that proved
  the sink fired, run on your own device (note the Android version and app
  version).
- For App Links, the `pm get-app-links` state plus the `assetlinks.json` (or
  its absence / mismatch).
- For providers, the read differential or schema row, never a write.

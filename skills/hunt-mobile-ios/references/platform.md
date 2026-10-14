# Platform: MASVS-PLATFORM-1 (IPC), -2 (WebViews), -3 (UI)

Scope boundary: `ios-redteam-pipeline` Stage 5 extracts `CFBundleURLTypes`,
the associated domains and the AASA file, and its decision table covers scheme
squatting at a glance. This file starts from that list and adds the handler
test, the evidence and the grade. Every PoC app mentioned here is signed with
your own identity, installed on your own test device only, and never
distributed. Tests that make the production backend act are Stage B and are
marked.

MASTG IDs from OWASP/mastg `master` (fetched 2026-10-14). Widgets, App Clips,
App Intents, Handoff and CloudKit have **no MASTG test**; none is cited.

---

## 1. Custom URL schemes

### Find the handler

| Entry point | Where |
|---|---|
| `application(_:open:options:)` | `AppDelegate` (pre-scene apps) |
| `scene(_:openURLContexts:)`, `scene(_:willConnectTo:options:)` (cold start) | `SceneDelegate` |
| `.onOpenURL { }` | SwiftUI views; a Swift closure, not visible to ObjC hooks |
| Router classes | strings such as `deeplink`, `DeepLinkRouter`, `route(`, host and path literals |

```bash
objection -n <bundle_id> start
#   ios hooking search openURL
#   ios hooking watch '-[*Delegate *openURL*]' --dump-args --dump-backtrace
```

Cold start and warm start take different paths (`willConnectTo` versus
`openURLContexts`); test both.

### Deliver test links (Stage A)

Host a plain HTML page on a server you control with one link per case and
open it in Safari on the test device, or paste links into Notes. That is the
real attack vector: a link the victim taps.

```html
<a href="myapp://open?screen=settings">baseline</a>
<a href="myapp://webview?url=https%3A%2F%2Ftester.example%2Fpoc.html">webview load</a>
<a href="myapp://file?path=..%2F..%2FLibrary%2FPreferences">path handling</a>
<a href="myapp://login?token=AAAA">token injection</a>
```

### What to test

Rows that end in a backend action (transfer, add payee, change email, delete,
accept invite, link device) are Stage B: written sign-off, tester-owned
accounts, the fence below. In Stage A, stop where the request leaves the
device: capture it in the proxy and drop it, which already shows whether a
confirmation screen stood in the way.

| Case | Pass | Fail (finding) |
|---|---|---|
| Sensitive action (transfer, add payee, change email, delete, accept invite, link device) | Confirmation screen showing the full action, re-auth for money | Action completes from the link alone |
| Data return (`callback=`, `x-success=`, `redirect=` back to another scheme) | No sensitive data appended | Token, OTP or PII appended to an attacker-chosen callback |
| URL parameter loaded into WKWebView | Host allowlist, `https` only | Any URL loaded; bridge exposed (section 6) |
| Session injection (`token=`, `code=`) | Ignored or bound to a pending local flow | App logs in as whoever's token is in the link (login CSRF) |
| File or path parameter | Rejected | Reads or shares a file from the container |
| Source check for privileged schemes | `sourceApplication` read and checked (MASTG-TEST-0371; only populated for apps from the same developer team) | No check before an irreversible action |
| Malformed input | Handled | Crash (P5 only) |

MASTG-TEST-0370 (input validation) and 0371 (source validation); 0075 is the
deprecated v1 test.

**Backend effect (Stage B, written sign-off).** When a deep link makes the
backend move money, change settings or send a message, run it once, between
two accounts you own:

```
# Stage B: written sign-off required. One link, tester-owned accounts only.
# Link: myapp://transfer?to=<tester-account-2>&amount=0.01
# Evidence: screen recording from tap to confirmation, backend reference ID, both account statements
```

### Scheme squatting and callback capture

Apple does not define which app wins when two apps register the same custom
scheme (verify current behaviour). The finding is never "the scheme can be
registered by others"; it is **what the second app receives**: an OAuth code,
a magic-link token, a payment callback. Demonstrate with your own PoC app on
your own device and your own account, then go to `auth-and-session.md`
section 4.

Grade: `Broken Access Control (BAC) > Exposed Sensitive iOS URL Scheme`
(VARIES, argue by the action), `Application-Level Denial-of-Service (DoS) >
App Crash > Malformed iOS URL Schemes` (P5). Login CSRF via token injection:
argue by consequence (P4 to P3).

---

## 2. Universal Links and the AASA file

Since iOS 14 devices fetch `apple-app-site-association` from an Apple-managed
CDN, not from the domain directly; an alternate developer mode bypasses the CDN
for development builds (`?mode=developer` on the entitlement entry, verify).
Compare what the CDN serves with the origin file:

```bash
curl -s "https://<domain>/.well-known/apple-app-site-association" | jq .
curl -s "https://app-site-association.cdn-apple.com/a/v1/<domain>" | jq .   # CDN copy (verify URL)
```

| Check | Why it matters |
|---|---|
| `applinks.details[].components` or legacy `paths` cover `"*"` or `"/"` | Every URL on the domain opens the app, including pages that host user content or an open redirect |
| Paths include an open-redirect or login-return endpoint | A web link the attacker controls is delivered into the app handler |
| Handler `application(_:continue:restorationHandler:)` with `NSUserActivityTypeBrowsingWeb` validates `webpageURL` like a scheme | MASTG-TEST-0395; same table as section 1 |
| Fallback: link opens in Safari (app not installed, user long-pressed, typed URL) | Tokens carried in a Universal Link URL now reach the web server, logs and `Referer` |
| A listed `applinks:` domain is dangling | Takeover means the attacker serves content at the link target when the app is absent; `hunt-subdomain` |
| `webcredentials:` and `appclips:` entries | Feed passkeys (`auth-and-session.md`) and App Clips (section 4) |

Universal Links are not triggered by navigation inside the same domain in
Safari or by typing the URL, so the web fallback is always reachable; it must
be as safe as the app path.

On a **re-signed** build the associated-domains entitlement no longer matches
the AASA (different Team ID), so Universal Links silently fall back to Safari.
Test them on the App Store build, a client-signed build or a jailbroken device.

Evidence: the AASA JSON from origin and CDN, the link used, a recording of
the app handling it, and the build type (App Store or client-signed).

Grade: as section 1 for the handler; AASA over-breadth alone is
informational, it is chain material.

---

## 3. App extensions, App Groups and widgets

```bash
for x in Payload/<App>.app/PlugIns/*.appex; do
  echo "== $x"
  plutil -extract NSExtension xml1 -o - "$x/Info.plist"
done
```

Feeding crafted items to an extension that uploads them is Stage B (written
sign-off, see the fence below); in Stage A, capture the upload in the proxy and
drop it.

| `NSExtensionPointIdentifier` (examples, verify per SDK) | Test |
|---|---|
| `com.apple.share-services` (share), `com.apple.ui-services` (action) | `NSExtensionActivationRule` of `TRUEPREDICATE` accepts any item. Feed it crafted files, URLs and text; check parsing and what is uploaded under the user's session |
| `com.apple.keyboard-service` | Section 7 |
| `com.apple.widgetkit-extension` | Sensitive data on the lock screen or home screen without unlock; check for redaction (`.privacySensitive()` in SwiftUI, verify) |
| `com.apple.usernotifications.service` | Notification service extension decrypts push payloads; check what it writes to the App Group and logs |
| `com.apple.intents-service` | Section 8 |
| `com.apple.fileprovider-nonui` | File provider exposes app files to the Files app; check what is listed |

Extensions run as separate processes with their own sandbox and share data
with the host app only through an App Group container or a shared Keychain
group. MASTG-TEST-0388: secrets written to shared `UserDefaults(suiteName:)`,
the shared file container or a shared Core Data store instead of a shared
Keychain fail. Every member of the group has equal read and write access.

Share-extension uploads to the backend are writes, so they are Stage B and
need written sign-off:

```
# Stage B: written sign-off required. One crafted item, tester account, own content.
# Share a crafted file (e.g. a filename with path separators, an oversized image) to the extension.
# Evidence: extension log lines, the request seen in the proxy, the server's stored result on your own account.
```

Deprecated MASTG-TEST-0072 describes the v1 extension review.

Evidence: the extension's Info.plist, the input fed, and its effect (log,
App Group file, or the dropped upload request).

Grade: widget data while locked is P5 (physical access). Secrets in an App
Group shared with an extension that embeds third-party code: argue P5 to P4.
Share-extension parsing bugs: grade by server-side effect.

---

## 4. App Clips (no MASTG test)

An App Clip is a small separate app (`Payload/<App>.app/AppClips/`, verify)
invoked from a URL: NFC tag, QR code, App Clip Code, Safari banner, Maps or
Messages. Anyone can print a QR code for an invocation URL, so **invocation
parameters are attacker input**. Clip-triggered orders and payments are
Stage B (written sign-off); Stage A stops at the captured request.

- Map invocation URLs from the AASA `appclips` entry and the clip's handler
  (`NSUserActivityTypeBrowsingWeb` in the clip).
- Test the clip's handler exactly like section 1 and 2: actions without
  confirmation, parameters into WebViews, trust in IDs from the URL (table
  number, store ID, order ID). An order ID in the URL that the backend does not
  bind to the session is an IDOR; send it to `hunt-idor`.
- Business logic that relies on client-side location confirmation of the
  invocation (the clip checks it is "at the store") is a client control; test
  whether the backend enforces it.
- Data handed from the clip to the full app through a shared App Group or
  Keychain group: same checks as section 3 (verify which sharing mechanisms
  your iOS version allows).

Evidence: the invocation URL as text (never a deployed QR code or NFC tag), a
recording of the clip handling it on your device, and the captured request.

Grade: as section 1 for the clip's handler; an order or table ID the backend
does not bind to the session is graded by `hunt-idor`. Check whether the brief
lists the App Clip under the main app's scope.

---

## 5. WKWebView and UIWebView configuration

| Check | MASTG | Note |
|---|---|---|
| `UIWebView` still referenced | 0331 | Deprecated; App Store rejects new submissions that use it (verify current policy). JavaScriptCore bridges via `JSContext` were the classic UIWebView exposure |
| URL loaded from attacker input (deep link, push, server field) | 0332 | Combine with section 1 delivery |
| `loadFileURL(_:allowingReadAccessTo:)` with a broad read scope (whole `Documents/` or container root) | 0333 | A loaded local HTML page can read other files in scope |
| `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs` set through KVC on `WKPreferences` / configuration | 0335, 0336 | A `file://` page can reach other files or the network |
| Password fields inside WebView-loaded HTML | 0378 | Native credential handling bypassed; WebView storage holds them |
| JavaScript disabled where not needed | none | `WKWebpagePreferences.allowsContentJavaScript` (iOS 14+) |
| `isInspectable = true` in production (iOS 16.4+) | none | Safari Web Inspector attaches on any Mac with the unlocked device; informational unless sensitive data is reachable |

Inspection on your own device: `isInspectable` builds or a jailbroken device
let you use Safari Web Inspector; `pymobiledevice3` ships a CDP bridge for
inspectable WebViews (verify which builds it reaches).

Evidence: the configuration call site (class and selector, or Swift symbol),
the loaded URL or file, and what the page could read.

Grade: depends entirely on what the loaded content can reach. A WebView that
only loads an attacker page with nothing exposed is `Unvalidated Redirects and
Forwards > Open Redirect > GET-Based` (P4) at most.

---

## 6. JavaScript bridges

`WKScriptMessageHandler` and `WKScriptMessageHandlerWithReply` expose native
code as `window.webkit.messageHandlers.<name>.postMessage(...)`.

```bash
grep -aoE 'messageHandlers\.[A-Za-z0-9_]+' strings_target.txt | sort -u   # handler names used by bundled JS
objection -n <bundle_id> start
#   ios hooking search ScriptMessage
#   ios hooking watch '-[* userContentController:didReceiveScriptMessage:]' --dump-args
```

| Check | MASTG |
|---|---|
| Handlers registered on a WebView that can load third-party or attacker URLs | 0376 |
| `evaluateJavaScript` used to reply to the bridge (reply visible to any script on the page) | 0377 |
| `evaluateJavaScript` without a content world (`WKContentWorld`) isolation | 0379 |
| Sensitive data (tokens, PII) written into the DOM via `evaluateJavaScript` | 0380 |
| Handler checks `message.frameInfo.securityOrigin` and `isMainFrame` before acting | none; read the handler |

Invoking a bridge action that writes to the backend (payments, profile
changes) is Stage B (written sign-off). The read-only proof below is Stage A.

Proof, Stage A: a page you host, loaded through the section 1 or 2 delivery,
calls the handler and shows the result **in the page itself** (an `alert` or
DOM text on your screen recording). Do not send the value anywhere; showing it
in the attacker-controlled page already proves an attacker would hold it.

```html
<script>
  window.webkit.messageHandlers.<name>.postMessage({action: "getToken"});
  // if the app replies via evaluateJavaScript or a reply handler, render the reply here
</script>
```

Evidence: handler name, the hosted page's source, and a recording showing the
returned value rendered in the page (redacted in the report).

Grade: bridge that returns the session token to an attacker-loaded page: ATO
class, `Server Security Misconfiguration > OAuth Misconfiguration > Account
Takeover` (P2) or the XSS node matching the delivery (`Cross-Site Scripting
(XSS) > Reflected > Non-Self`, P3), with a severity request. Bridge reachable
but exposing nothing sensitive: informational.

---

## 7. Custom keyboards and sensitive input

| Check | MASTG |
|---|---|
| App rejects third-party keyboards app-wide (`application(_:shouldAllowExtensionPointIdentifier:)` returns false for `UIApplicationKeyboardExtensionPointIdentifier`) | 0389 |
| Sensitive fields use `isSecureTextEntry`, which forces the system keyboard | 0346, 0347 |
| The app's own keyboard extension requests Full Access (`RequestsOpenAccess`) and what it sends | 0390 |

Evidence: the delegate method's return value or its absence, and the list of
sensitive fields without `isSecureTextEntry`.

Grade: P5 / hardening. A keyboard extension shipped **by the target** that
transmits typed text without disclosure is a privacy finding worth a full
write-up.

---

## 8. App Intents, Siri and Shortcuts (no MASTG test)

- Enumerate: App Intents metadata in the bundle (`Metadata.appintents/`,
  verify) and, for SiriKit, the intents extension's `IntentsSupported` and
  `IntentsRestrictedWhileLocked` keys.
- `AppIntent.authenticationPolicy` defaults to `.alwaysAllowed`, which lets the
  intent run "at any time, including when the device is locked" (Apple
  documentation). `.requiresAuthentication` and
  `.requiresLocalDeviceAuthentication` gate it.
- Intents that change server state (payments, messages, orders) are Stage B:
  written sign-off, tester account, one run (fence below). Read-only intents
  are Stage A.
- Test on your own locked device: run each intent from Shortcuts, Siri or the
  lock-screen controls. Does it read out balances or messages, or perform an
  action, without unlock?

```
# Stage B: written sign-off required for any intent that changes server state.
# Run the intent once, device locked, tester account. Record: lock screen visible, intent invoked, result.
```

Evidence: a recording showing the device locked, the intent invoked and the
result, plus the intent's `authenticationPolicy` if visible in the binary.

Grade: physical-access class, so many programs exclude it; a payment or
message-sending intent that runs while locked is worth a severity request
(P4, argue up by the action).

---

## 9. Handoff and NSUserActivity (no MASTG test)

`NSUserActivityTypes` in Info.plist lists activities the app continues. The
continuation handler receives `userInfo` and possibly `webpageURL`; validate
them exactly like a deep link (section 1). Handoff only moves activities
between devices on the same Apple Account, so the remote attacker model is
weak; the useful case is an activity type that is also reachable from Spotlight
or shortcuts with attacker-shaped input. Activities and CoreSpotlight items
that index sensitive content make it searchable on the device (verify
lock-screen visibility on your iOS version).

Evidence: the activity type, the crafted input, and the handler's effect.

Grade: as section 1 when reachable with attacker input; otherwise
informational.

---

## 10. iCloud and CloudKit (no MASTG test)

Entitlements to read: `com.apple.developer.icloud-container-identifiers`,
`com.apple.developer.icloud-services` (`CloudKit`, `CloudDocuments`),
`com.apple.developer.ubiquity-kvstore-identifier`, and the container
environment entitlement (a production build pointing at `Development` is a
misconfiguration, verify key name).

CloudKit has a **public database** per container. Its preset roles are World
(`_world`), Authenticated (`_icloud`) and Creator (`_creator`); by default
World can read, authenticated iCloud users can create, and creators write their
own records (third-party write-ups of the dashboard defaults, verify against
the container). Developers who put per-user data in the public database expose
it to every user of the app.

Stage A procedure, your own iCloud account:

```bash
objection -n <bundle_id> start
#   ios hooking search CKQueryOperation
#   ios hooking watch '-[CKDatabase *]' --dump-args          # record types and queries the app issues
#   ios hooking watch '-[CKQueryOperation *]' --dump-args
```

Look for record types in the public database that carry user identifiers,
contact details, locations or messages, and check whether your account
receives records that other users created. Count; do not page through them.

```
# Stage B: written sign-off required. Never write to another user's record.
# One create in the public database from your own account, to show _icloud create rights on a sensitive type.
```

iCloud key-value storage and iCloud Documents sync to the user's own devices;
secrets there are a storage finding (`storage.md`), not a cross-user one.

Grade: other users' personal data readable from the public database:
`Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure`
(VARIES; argue by data class and count). Redact with `evidence-hygiene`.

---

## Grade summary

| Proven | VRT node | Default |
|---|---|---|
| Deep link performs a sensitive action without confirmation | Broken Access Control (BAC) > Exposed Sensitive iOS URL Scheme | VARIES |
| Malformed scheme crash | Application-Level Denial-of-Service (DoS) > App Crash > Malformed iOS URL Schemes | P5 |
| WebView loads attacker URL, nothing else | Unvalidated Redirects and Forwards > Open Redirect > GET-Based | P4 |
| Script in WebView from a link | Cross-Site Scripting (XSS) > Reflected > Non-Self | P3 |
| Bridge returns session token to attacker page | Server Security Misconfiguration > OAuth Misconfiguration > Account Takeover | P2 |
| CloudKit public DB exposes other users | Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure | VARIES |
| Keyboard, widget, snapshot, intent-while-locked | see `storage.md`; physical-access class | P5 typical |

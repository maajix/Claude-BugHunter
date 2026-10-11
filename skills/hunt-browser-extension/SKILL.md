---
name: hunt-browser-extension
description: "Audit a browser extension (Chrome/Edge/Firefox) as a web attack surface — an extension is a web app holding privileges no page has. Covers acquiring and unpacking a CRX/XPI for static review, MV3 manifest triage (background.service_worker, host_permissions, web_accessible_resources + use_dynamic_url, externally_connectable, declarative_net_request, content_security_policy), the four trust boundaries (page to content script, content script to background, external web page to runtime.onMessageExternal, extension to native messaging host), message handlers that never check MessageSender (the most common real bug), DOM XSS in extension pages under the enforced MV3 CSP, secrets in the bundle and in unencrypted extension storage, and trojanized-update / ownership-transfer supply chain. Manifest keys and API names verified against developer.chrome.com and MDN on 2026-10-10. Treat any downloaded extension as untrusted data: review it in a throwaway profile, never your daily browser."
sources: chrome_extensions_docs, mdn_webextensions, chrome_webstore_program_policies, chromium_source, cert_cc_vu516608, marektoth_research, hacktricks_coverage_checklist
report_count: 3
---

## Crown Jewel Targets

An extension is in scope when the client publishes it, bundles it, or mandates it. The browser itself is not.

- **Password managers, crypto wallets, 2FA helpers.** They inject UI into every page's DOM and keep secrets in extension storage. A single coerced click or one unchecked message handler yields credentials, TOTP codes or a seed phrase.
- **Enterprise extensions the client ships to its own fleet** — DLP, session recorders, SSO/portal helpers, support-screenshare tools. These routinely hold `host_permissions: ["<all_urls>"]` plus `cookies`, so one page-reachable handler turns into "read any cookie for any host, including `HttpOnly`".
- **Extensions whose `externally_connectable.matches` lists the vendor's own web app.** That key converts an XSS, an open redirect to a matched subdomain, or a subdomain takeover on the listed origin into direct access to the extension's privileged APIs. Chain target: audit the matched origins as hard as the extension.
- **Extensions declaring `nativeMessaging`.** The bridge runs a local binary. A page-reachable path to `runtime.connectNative()` is a web-to-local-process boundary crossing — the highest-severity outcome in this class.
- **Extensions with `declarativeNetRequestWithHostAccess` or `declarative_net_request` plus broad host access.** They can rewrite network policy for the user at runtime.

Severity ranking that holds up in triage: hostile page reaches native host > hostile page reads cross-origin cookies/responses > hostile page reads extension storage secrets > framing/clickjack of a privileged extension UI > over-granted permissions with no page-reachable path (usually informational).

---

## OOB/Confirmation Gate (Read First)

**The finding is "a web page the user visits can do X". Proof must therefore come from page context, not from the extension's own context.**

A valid proof of concept is one HTML file served from an origin you control, opened in a **fresh throwaway profile** with only the target extension installed at a pinned version, which obtains something that origin cannot obtain on its own, tagged with a unique canary.

### What is NOT confirmation

| Non-proof | Why it fails triage |
|---|---|
| A permission in `manifest.json` | A declared permission is the extension's privilege, not the page's. It is a capability ceiling, not a vulnerability. |
| A message handler exists | Existence is not reachability. Show that the `externally_connectable` or `postMessage` relay path actually delivers your message. |
| Output from the **extension's** DevTools console (service worker / popup / options page) | That context already holds every extension privilege. Running `chrome.cookies.getAll({})` there proves nothing about an attacker. |
| Reading `chrome.storage` with the extension's own DevTools, or reading `Local Extension Settings` off disk | Both require local access you already had. Separate finding at most. |
| A `chrome-extension://` URL that loads for you after you typed it in the address bar | Typing it is not a web origin fetching it. Use `fetch()` / `<iframe>` from an attacker page. |

### What IS confirmation

- `fetch('chrome-extension://<ID>/<path>')` from `https://target.example` returns the resource body — proves the resource is web-accessible to that origin.
- `chrome.runtime.sendMessage('<ID>', {...})` executed from a page matching `externally_connectable.matches` returns privileged data (a cookie value, a cross-origin response body, a stored token) containing your canary.
- `window.postMessage` from the page is answered with privileged data, proving a content-script relay with no `event.source`/`event.origin` check.
- A unique canary string reaches the native messaging host's stdin (Stage B, see Step 9) or a request you control carries a header the extension injected.

### Record with every claim

Extension ID, version string from `manifest.json`, browser name and full version, `manifest_version`, the throwaway profile path, the PoC file, and the UTC timestamp. Extension findings rot fast: the store ships a silent update and the repro is gone.

---

## Attack Surface Signals

```bash
# Run from the package directory ($EXT in Step 2; the bundle unpacks to $EXT/src).
# Every path in this skill is relative to $EXT. Read-only, no network.
jq '{manifest_version, name, version, permissions, optional_permissions,
     host_permissions, optional_host_permissions, background, content_scripts,
     web_accessible_resources, externally_connectable, content_security_policy,
     sandbox, declarative_net_request, chrome_settings_overrides, key,
     oauth2, update_url, minimum_chrome_version}' src/manifest.json
```

High-signal manifest values:

- `"host_permissions": ["<all_urls>"]` or `["*://*/*"]`, `["http://*/*","https://*/*"]` — origin access to everything.
- `permissions` containing `cookies`, `webRequest`, `scripting`, `tabs`, `history`, `debugger`, `proxy`, `nativeMessaging`, `declarativeNetRequest`, `declarativeNetRequestWithHostAccess`. `cookies` + broad host access = reads `HttpOnly` auth cookies. `debugger` = full CDP over the user's tabs.
- `web_accessible_resources` with `"matches": ["<all_urls>"]` or `["*://*/*"]`, and without `"use_dynamic_url": true`.
- `externally_connectable` present at all, and especially `"ids": ["*"]`.
- `content_scripts[].world: "MAIN"`, `all_frames: true`, `match_about_blank: true`, `run_at: "document_start"`.
- `sandbox` pages (their CSP permits `unsafe-eval`).
- `chrome_settings_overrides.search_provider` with a `{searchTerms}` endpoint on infrastructure unrelated to the advertised feature — search-intent hijack with no API permission at all.
- `"manifest_version": 2` — see Gate 0; on Chrome this is a dead artifact, on Firefox it is live.

Code-level signals: `grep -rnE` for `onMessageExternal|onConnectExternal|connectNative|sendNativeMessage|executeScript|updateDynamicRules|permissions\.request|addHostAccessRequest|innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(|new Function|location\.href\s*=|chrome\.runtime\.getURL`.

---

## Step-by-Step Methodology

### Step 1 — Pin identity and scope

Get the 32-character extension ID and the exact version from the store listing URL, or from `chrome://extensions` with Developer mode on. Confirm in writing that this extension ID is in scope. Auditing a third party's extension against a third party's site needs the same authorization as any other live test.

### Step 2 — Acquire the package (treat it as untrusted data)

```bash
# One new EMPTY directory per package. Never unpack into a shared workspace.
EXT=/tmp/extaudit-$(date +%s)/<EXTENSION-ID>; mkdir -p "$EXT"; cd "$EXT"
# Chrome Web Store CRX (verified 302 -> clients2.googleusercontent.com/crx/blobs/... on 2026-10-10)
curl -sL -o ext.crx \
  "https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3&prodversion=140.0&x=id%3D<EXTENSION-ID>%26uc"
file ext.crx; sha256sum ext.crx    # record the hash in the report
```

- Firefox add-ons ship as `.xpi`, which is a ZIP — download from the listing and unzip directly.
- Edge Add-ons uses the update URL `https://edge.microsoft.com/extensionwebstorebase/v1/crx` (Microsoft Learn, Edge extensions FAQ). The query form above is a Chrome-store fact; confirm the 302 before scripting against Edge.
- Already installed locally? Read **Profile Path** from `chrome://version`, then
  `find "$PROFILE/Extensions" -maxdepth 3 -name manifest.json` (Chrome user-data dirs: `~/.config/google-chrome` on Linux, `~/Library/Application Support/Google/Chrome` on macOS, `%LOCALAPPDATA%\Google\Chrome\User Data` on Windows; each profile is a subdirectory such as `Default`). Do not assume the version subdirectory naming — let `find` report it.
- **Untrusted-data rules, non-negotiable:** never execute anything from the package, never `npm install`/`npm run` inside it, never load it unpacked into your daily browser profile, and keep any script you write in a different directory and pass the package path as an argument (an interpreter started inside the package can import a planted module). Run helper Python with `python3 -I`.

### Step 3 — Unpack

```bash
# CRX3 = "Cr24" magic (4B) + format version (4B) + header length N (4B, little-endian)
# + N bytes protobuf header + a ZIP archive. Strip the header, then extract with stdlib:
python3 -I -c 'import struct,sys;d=open(sys.argv[1],"rb").read();assert d[:4]==b"Cr24";n=struct.unpack("<I",d[8:12])[0];open(sys.argv[2],"wb").write(d[12+n:])' ext.crx ext.zip
python3 -I -c 'import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' ext.zip src
# `unzip -q -o ext.crx -d src` also works where unzip is installed (ZIP readers find the
# central directory from EOF), but do not depend on it — many agent hosts lack unzip.
```

If a bundle is minified onto one line, `grep -A`/`-B` context is meaningless. Split a **copy** (kept outside the package directory) before reading: `sed 's/;/;\n/g' src/js/<bundle>.js > /tmp/<bundle>.split.js`.

### Step 4 — Manifest triage

Run the `jq` block from Attack Surface Signals. Then write down the **privilege ceiling** in one sentence ("can read cookies and inject scripts on every origin") and the **page-reachable surface** separately. The gap between those two is the whole audit.

MV3-versus-MV2 differences that change what you look for:

| Aspect | MV2 | MV3 |
|---|---|---|
| Background | `background.scripts` / `background.page`, `persistent` defaults `true` | `background.service_worker` (+ `"type": "module"`); setting `persistent: true` is an error. Terminates when idle, so state lands in `chrome.storage` — go look there. |
| Origin access | Hosts listed inside `permissions` | Split into `host_permissions` / `optional_host_permissions`; runtime-grantable via `chrome.permissions.request()` and `permissions.addHostAccessRequest()` |
| Remote code | Allowed | Banned; `content_security_policy.extension_pages` cannot be relaxed past `script-src 'self' 'wasm-unsafe-eval'; object-src 'self';` (default without the key: `script-src 'self'; object-src 'self';`). `'unsafe-eval'` is an install-time error. |
| Network interception | Blocking `webRequest` | `declarative_net_request.rule_resources[{id,enabled,path}]` + dynamic/session rules |
| Status | Disabled for all Chrome users 2025-07-24; `ExtensionManifestV2Availability` policy removed in Chrome 139; remaining MV2 items removed from the Chrome Web Store 2026-08-31 | Current. Firefox still supports MV2 and has stated no deprecation plan, so MV2 findings stay live on Firefox. |

### Step 5 — Map the four trust boundaries before reading any handler

Draw them explicitly; every real bug in this class is a missing check on one of these edges.

1. **Hostile page to content script.** They share the page's DOM; JavaScript variables are isolated (`world` defaults to `ISOLATED`). The page cannot call the content script's functions — but it can `window.postMessage` to it, and it fully controls the DOM the content script reads.
2. **Content script to background.** The content script is the untrusted side: it runs in a page an attacker may control. Chrome's own guidance is to assume content-script messages were crafted by an attacker.
3. **External web page to extension**, via `externally_connectable` plus `runtime.onMessageExternal` / `runtime.onConnectExternal`.
4. **Extension to native messaging host** — a local process, reachable only from the service worker or an extension page, never from a content script.

### Step 6 — Boundary 1: the content-script relay

```bash
grep -rnE "addEventListener\(['\"]message['\"]|window\.onmessage" src/ --include=*.js
```

For each handler, check `event.origin` **and** `event.source === window` (or a known frame). A handler that forwards `event.data` into `chrome.runtime.sendMessage()` without both checks is the bug — and note that the background's own `sender.id === chrome.runtime.id` check passes here, because the message genuinely came from the extension's content script. The fix belongs at the relay, not at the background listener. Report it that way or the client patches the wrong file.

### Step 7 — Boundary 2: `sender` validation in the background

```bash
# List every handler site, then read each one. Do not try to judge validation with a
# second piped grep — context lines without `sender.` are normal and mean nothing.
grep -rn "onMessage\.addListener\|onConnect\.addListener" src/ --include=*.js
```

`MessageSender` fields the browser populates: `id`, `url`, `origin` (Chrome 80+), `tab`, `frameId`, `documentId`, `documentLifecycle`, `nativeApplication`, `tlsChannelId`. Audit rules:

- No `sender` reference anywhere in the handler = unvalidated. Then ask what the handler does: a cookie read, a `fetch` to a caller-supplied URL, a `scripting.executeScript`, a storage dump, or a native-host call are all reportable.
- `sender.url` is the URL of the frame that opened the connection; for an iframe it is the **iframe's** URL, not the top page's. A handler that reads `sender.url` while deciding whether "the user is on target.example" is wrong by construction.
- Substring matching on `sender.url` (`.includes('target.example')`) is bypassable from `https://target.example.attacker.test/` or `https://attacker.test/?x=target.example`. Compare `sender.origin` against an exact allowlist instead; `origin` can be opaque or differ from `url` (sandboxed iframes, `about:blank`), and an opaque origin must fail closed.
- `sender.tab === undefined` distinguishes extension-page senders from content-script senders. Handlers that assume `sender.tab` exists are fragile; handlers that grant privilege when it is missing are broken.

### Step 8 — Boundary 3: `externally_connectable` (Chromium)

Firefox does not support web-page-to-extension messaging: MDN states that for communication with web pages "neither API is supported" (Firefox bug 1319168). So this whole boundary is a Chromium-side surface; do not claim it on Firefox.

Default semantics, which decide whether this is even a finding:

- Key **absent**: any other extension may message it; **no** web page can.
- Key **present** with `matches` but no `ids`: no other extension can connect ("If left empty or unspecified, no extensions or apps can connect").
- Key present with `ids: ["*"]`: every installed extension can connect — including a low-privilege one an attacker gets the user to install.
- `matches` cannot use wildcard domains or public suffixes. Chrome rejects `<all_urls>`, `https://*/*`, `*://*.com/*`, `https://*.appspot.com/*`; it accepts `*://google.com/*` and `https://*.chromium.org/*`. So a listed `https://*.vendor.example/*` means **every** subdomain of that vendor — enumerate them and look for XSS, takeover candidates and user-content subdomains.

Stage A probe, from a page on a matching origin:

```js
// Attacker-controlled page served from an origin inside externally_connectable.matches
chrome.runtime.sendMessage('<EXTENSION-ID>', {type:'<HANDLER-TYPE>', canary:'<CANARY>'},
  r => console.log('reply', r));   // reply containing privileged data = confirmed
```

### Step 9 — Boundary 4: native messaging

Required permission: `nativeMessaging`. The host side is a separate manifest, not part of the extension package: fields `name`, `description`, `path`, `type` (must be `"stdio"`), `allowed_origins` (extension origins, **no wildcards**). Installed at `~/.config/google-chrome/NativeMessagingHosts/<name>.json` or `/etc/opt/chrome/native-messaging-hosts/<name>.json` on Linux, `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` or `/Library/Google/Chrome/NativeMessagingHosts/` on macOS, and a registry value under `SOFTWARE\Google\Chrome\NativeMessagingHosts\<name>` on Windows. Framing is UTF-8 JSON with a 32-bit native-byte-order length prefix (1 MB host-to-Chrome, 64 MiB Chrome-to-host).

Audit: does `allowed_origins` list more than the vendor's own extension IDs, and does any message that reaches `runtime.connectNative()` / `runtime.sendNativeMessage()` carry attacker-controllable data into a file path, a command argument or an update URL? Trace the chain `page -> content script -> service worker -> native host`. **Reaching the host with a canary argument is Stage B** (it starts a local process): detect statically, get written sign-off, then execute once.

### Step 10 — `web_accessible_resources` exposure

Nothing is web-accessible by default. Each rule needs `resources` plus `matches` or `extension_ids`; in Chrome, `matches` paths must be `/*`. `use_dynamic_url` defaults to `false`; when `true`, the resource is reachable only via a dynamic ID regenerated per session, on browser restart and on extension reload.

```js
// Stage A, from an attacker page: what can a hostile origin pull or frame?
fetch('chrome-extension://<ID>/<PATH>').then(r => r.text()).then(t => console.log(t.length));
document.body.append(Object.assign(document.createElement('iframe'),
  {src:'chrome-extension://<ID>/<PAGE>.html'}));   // loads = frameable privileged UI
```

Ask three questions per exposed path: does it leak data (config, bundled keys, a source map), does it leak the **existence** of the extension to any site (fingerprinting — a fixed `chrome-extension://<ID>/` URL is a stable probe; Firefox's `moz-extension://<UUID>` is randomised per browser instance, which is why this is a Chromium-side issue), and is it an HTML page whose UI performs a privileged action when clicked? Framing a privileged extension page is a real finding (PrivacyBadger's `skin/*`). `use_dynamic_url: true` kills static enumeration and pre-built framing — but it is defeated if the extension writes `chrome.runtime.getURL()` output into the page DOM, where a content script's own injection hands the live URL to the page.

### Step 11 — DOM XSS inside extension pages, under the real CSP

Sinks and sources are the generic taxonomy — use `hunt-dom` for that. What is extension-specific is where execution is actually possible:

- **Extension pages** (popup, options, side panel, a page in `web_accessible_resources`) run under the enforced `extension_pages` CSP. `innerHTML` with an `<img onerror>` payload there usually does **not** execute script. HTML injection without execution is still worth reporting only when it drives a privileged click or exfiltrates DOM content.
- **`sandbox` pages** get the lenient policy (`script-src 'self' 'unsafe-inline' 'unsafe-eval'`) and are the realistic execution target inside the package — but they hold no extension API access and cannot touch non-sandboxed pages directly, so chase what they message out.
- **Content-script injection executes in the host page**, under the host page's CSP. A content script building HTML from `document.title`, a URL parameter or remote JSON is XSS on **every** matched origin — frequently the highest-impact finding in the audit.
- **`world: "MAIN"`** drops the isolation entirely: the script shares the host page's execution environment, so the page can read and redefine everything it touches. Any secret or privileged callback a MAIN-world script holds is page-readable.
- **Firefox MV2** extensions still allow the looser MV2 CSP posture; do not apply Chromium MV3 assumptions to them.

### Step 12 — Secrets in the bundle and in storage

`hunt-source-leak` owns the generic hunt for secrets in shipped JavaScript; run it over `src/` and treat the extension bundle as a shipped SPA. Extension-specific notes:

- Extension storage is **not encrypted**: MDN states the storage area "is not encrypted and shouldn't be used for storing confidential user information". Tokens found in `chrome.storage.local` are a finding on their own merits only with a reachability story — but they become critical the moment Step 7 finds a handler that returns them.
- Access level matters: `storage.local`, `storage.sync` and `storage.managed` are exposed to content scripts by default; `storage.session` is **not**, unless the extension calls `setAccessLevel({accessLevel:'TRUSTED_AND_UNTRUSTED_CONTEXTS'})`. Grep for that call — it is a deliberate widening of the boundary.
- `storage.sync` leaves the machine via browser sync. Secrets there spread to every device on the account.
- Not secrets, do not report them: the `key` manifest field (a public key) and `oauth2.client_id` (a public client identifier).

### Step 13 — Runtime policy and late permission grants

The packaged manifest is an upper bound and a request, not a snapshot of live privilege. Two things hide from static review:

- `chrome.permissions.request()` (Chrome 96+, must be called inside a user gesture) and `permissions.addHostAccessRequest()` (Chrome 133+, MV3 only) acquire origins after install. Grep for both; a reputable extension that asks for `<all_urls>` later is the documented malware pattern. Note also that after `permissions.remove()`, a later `request()` "usually adds the permission back without prompting the user" (Chrome docs) — consent is sticky.
- `declarativeNetRequest` rules can be rewritten at runtime with `updateDynamicRules()` / `updateSessionRules()`, so the shipped `rule_resources` files may not be the live policy. In a throwaway profile, read the live set from the extension's service-worker DevTools with `getDynamicRules()`, `getSessionRules()` and `getEnabledRulesets()`. Note that `declarativeNetRequestWithHostAccess` produces **no** install-time warning and grants no origins by itself — assess it together with the effective host grants shown in `chrome://extensions/?id=<ID>`.

### Step 14 — Supply chain: the extension that changes hands

An extension is an auto-updating binary with a trusted install base. Two mechanisms matter and neither is detectable in the current package:

1. **Publisher compromise.** Phished Web Store developer accounts have been used to push trojanized updates that widen host access and exfiltrate cookies and session tokens, silently, to the existing install base.
2. **Ownership transfer.** The Chrome Web Store supports moving an item to another developer account (support request, confirmed by the original publisher) and adding publisher members (`developer.chrome.com/docs/webstore/share-ownership`). The extension ID, the install base and the granted permissions survive the handover; the trust assumption the user made does not.

Audit questions for the client's own extension: how many accounts can publish it, is 2FA enforced on all of them, is a Web Store API service-account key sitting in CI, and does release review diff `permissions`/`host_permissions` between versions? For a third-party extension in scope, diff manifests and bundle hashes across versions and flag any release that widens permissions without a changelog. Repo-level recon belongs to `supply-chain-attack-recon`.

### Step 15 — Dynamic confirmation in a disposable environment

**Stage A (detect).** Fresh profile, target extension only, your PoC page on an origin you control:

```bash
# Branded Chrome dropped --load-extension in Chrome 137; use Chromium or Chrome for Testing.
chromium --user-data-dir="$(mktemp -d)" --no-first-run \
  --load-extension="$EXT/src" "https://target.example/poc.html"
```

**Loading an extension is executing it** — the service worker runs with the extension's full privileges and network access, which is exactly what Step 2 forbade for the unpacked files. So this step happens in a container or throwaway VM where possible; the minimum is a brand-new `--user-data-dir`, no other extensions, no signed-in sessions, no profile you will ever reuse. Never your daily profile: it holds live sessions the extension can read and ship out. Serve the PoC from a host you own, one request at a time, no loops. A single successful request is the finding.

**Stage B (execute) — requires explicit written operator sign-off.** Anything that modifies the extension (repacking, patching the bundle, loading a modified build into a profile with real sessions), anything that actually triggers the native host or a state-changing privileged action, and anything published anywhere (an uploaded test extension, a store submission). `# Stage B — DO NOT execute without explicit scope OK.` Never bulk-download store packages: one package per in-scope ID, serial, `sleep 5` between downloads.

---

## Payload & Detection Patterns

```bash
# External handlers (the single highest-value grep in this skill) — read every hit
grep -rn "onMessageExternal\|onConnectExternal" src/ --include=*.js
# Privileged actions driven by message payloads
grep -rnE "cookies\.(get|getAll|set)|scripting\.(executeScript|insertCSS)|tabs\.executeScript|fetch\(\s*(msg|message|request|req|data)\b" src/ --include=*.js
# Relay with no origin/source check
grep -rnEB3 -A12 "addEventListener\(['\"]message['\"]" src/ --include=*.js
# Remote endpoints the extension talks to (then map them with hunt-spa-api)
grep -rhoE "https?://[a-zA-Z0-9._-]+" src/ --include=*.js | sort -u | head -50
```

Minimal shapes to recognise in review (write your own PoC; do not paste a vendor's code into a report):

```js
// BROKEN: external handler, no sender check, returns privileged data
chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {
  if (msg.type === 'getCookies') chrome.cookies.getAll({domain: msg.domain}, reply);
});
// FIXED: exact-origin allowlist, fail closed on opaque origin, no caller-supplied scope
const ALLOWED = new Set(['https://app.vendor.example']);
chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {
  if (!sender.origin || !ALLOWED.has(sender.origin)) return;   // opaque origin -> reject
  if (msg.type !== 'getSessionState') return;
  reply({loggedIn: true});                                     // no cookie passthrough
});
```

---

## Common Root Causes

- The developer treats "it came through my own content script" as "it came from my extension", forgetting the content script runs inside an attacker-controllable page.
- `sender` is never read, or is read as a substring of `sender.url` rather than an exact `sender.origin` comparison.
- A message handler is a generic proxy (`{action:'fetch', url}`, `{action:'getCookies', domain}`) instead of a narrow, named operation with server-side-style scope.
- `web_accessible_resources` is widened to a whole directory (`"resources": ["skin/*"]`) during a build refactor, with `matches: ["<all_urls>"]` because that made development work.
- `externally_connectable.matches` lists a whole wildcard subdomain space of the vendor, so every forgotten subdomain inherits extension access.
- `host_permissions` is written as a path (`https://target.example/account/*`) in the belief that it restricts access. For host permissions the path is "required but ignored" (Chrome match-pattern docs), so the grant covers the whole host.
- The service worker's non-persistence pushes state into `chrome.storage`, and a token lands in an unencrypted area that content scripts can read by default.
- Privilege creep across releases: each version adds one permission and nobody diffs the manifest.

---

## Bypass Techniques

- **Substring origin checks.** `sender.url.includes('vendor.example')` falls to `https://vendor.example.attacker.test/`, `https://attacker.test/#vendor.example`, or a subdomain the vendor no longer controls.
- **Iframe-sourced `sender.url`.** `sender.url` is the *frame's* URL, so a handler that reads it as "the page the user is on" can be fed an allowed-looking frame URL while the top-level page is yours.
- **First-message races.** A relay that trusts the first message can be beaten by flooding `postMessage` during frame load — mechanics in `hunt-dom`.
- **Extension-to-extension hop.** When `externally_connectable.ids` is `["*"]` (or the key is absent, which already allows extension senders), a low-privilege extension the user installs becomes the caller into the privileged one.
- **Dynamic URL leak.** `use_dynamic_url: true` still exposes the resource if the extension inserts `runtime.getURL()` output into a page the attacker controls.
- **Isolation removed by the extension itself.** With `world: "MAIN"` the page can monkey-patch the prototypes and functions the script relies on (`JSON.parse`, `fetch`) before it runs; inside a `sandbox` page, `unsafe-eval` plus a careless `postMessage` channel back to a privileged page converts injected script into privileged action.
- **DOM-based extension clickjacking.** Rather than framing a `chrome-extension://` page, hide or occlude the autofill UI the extension injects into your page (opacity, transparent ancestor, overlays with `pointer-events: none`) and harvest one coerced click. Works regardless of `web_accessible_resources`. Framing mechanics and click-coercion proof belong to `hunt-clickjacking`.

---

## Gate 0 Validation

Kill these before writing anything up:

1. **Is there a page-reachable path?** A broad permission with no handler, no WAR and no `externally_connectable` is informational at best. Say so plainly.
2. **Did the PoC run in page context?** Re-run it from a plain `https://` page in a profile where you never opened the extension's DevTools. If it only worked in the extension's console, it is not a finding.
3. **Fresh profile, no prior grants.** Optional permissions and per-site access persist, and a previously approved permission can often be re-granted without a prompt. Reproduce from a brand-new `--user-data-dir` so you are not measuring your own earlier consent.
4. **Version pinned and still published.** Install from the store, record the version, re-download the CRX and compare the hash. A silent update between your test and your report invalidates it.
5. **Is the manifest version live?** An MV2-only bug on Chrome is unexploitable (disabled for all users 2025-07-24, delisted 2026-08-31). Re-test it on Firefox, which still supports MV2, before scoring it.
6. **CSP reality check.** Claiming XSS in an extension page requires demonstrated script execution under the enforced `extension_pages` policy — otherwise it is HTML injection, or it belongs to the content-script-into-host-page case (Step 11).
7. **Not-a-secret list.** The manifest `key` field is a public key and `oauth2.client_id` is a public identifier. Neither is a finding.
8. **Browser attribution.** Name the browser and version in every claim. Chrome, Edge and Firefox differ on MV2 support, host-permission prompts, `use_dynamic_url` and the resource URL scheme (a fixed `chrome-extension://<ID>/` probe is Chromium-specific; Firefox's per-instance `moz-extension://<UUID>` is not probeable the same way).

---

## Real Impact Examples

- **Framing a privileged extension page.** Privacy Badger listed its whole `skin/` directory in `web_accessible_resources`, letting any site load the extension's UI in a near-invisible iframe and coerce a click on "disable for this site" — a security control turned off silently. Fixed by removing the directory from the key.
- **DOM-based extension clickjacking of password managers.** Injected autofill UI hidden with CSS/DOM tricks turned one click on a decoy (a cookie banner) into autofill of credentials, TOTP codes and card data into attacker-controlled inputs; CERT/CC tracked it as VU#516608 across multiple password-manager vendors.
- **Cookie-returning external handler.** The recurring pattern: `onMessageExternal` (or a page-fed relay) answers a `getCookies`-style request using the extension's `cookies` permission plus broad host access, handing a web page `HttpOnly` session cookies the same-origin policy exists to protect. Account takeover, one message.
- **Trojanized update after publisher compromise.** A phished Web Store publisher account shipped an update that widened host access and exfiltrated cookies and session tokens from the existing install base — no user action, no new install, the extension ID unchanged.

---

## Disclosed Report Citations

- Privacy Badger `web_accessible_resources` clickjacking — https://blog.lizzie.io/clickjacking-privacy-badger.html
- DOM-based Extension Clickjacking, Marek Tóth (2025-08-09, updated 2026-01-14) — https://marektoth.com/blog/dom-based-extension-clickjacking/
- CERT/CC VU#516608, Multiple Password Managers Vulnerable to Clickjacking Attacks (2025-10-17) — https://kb.cert.org/vuls/id/516608

Technique coverage was cross-checked against the HackTricks browser-extension pentesting pages, used as a checklist of what to cover, under `https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/pentesting-web/browser-extension-pentesting-methodology/`: `browext-permissions-and-host_permissions.md`, `browext-clickjacking.md`, `browext-xss-example.md`. Manifest keys, API names, CSP values, storage access levels, native-messaging fields and the MV2 dates above were read from developer.chrome.com, MDN or Chromium source on 2026-10-10. Two items came from search summaries rather than a full page read and are worth re-checking before you quote them in a report: the `externally_connectable` match-pattern restrictions and the `chrome_settings_overrides.search_provider` field list.

---

## Related Skills & Chains

| Skill | Why it chains here |
|---|---|
| `hunt-dom` | Generic DOM XSS source/sink taxonomy and `postMessage` handler abuse, including first-message races. Use it for the sink list; this skill owns the extension boundaries. |
| `hunt-source-leak` | Secrets, source maps and build artifacts in shipped JavaScript — run it over the unpacked bundle. |
| `supply-chain-attack-recon` | Publisher-side recon: org repos, CI configuration, service-account keys, release provenance. |
| `hunt-spa-api` | Map the extension's remote endpoints to backend routes, then test those routes for broken access control. |
| `hunt-clickjacking` | Click-coercion proof mechanics for both the framed-extension-page and injected-UI cases. |
| `hunt-xs-leaks` | Cross-origin state inference, when a web-accessible resource becomes an extension-presence or user-state oracle. |
| `hunt-oauth` | Where the extension runs an OAuth flow (`chrome.identity`, a hosted redirect page) — token handling and redirect validation live there. |
| `evidence-hygiene` | Pinning extension ID, version, browser build and package hash so the finding survives a silent store update. |

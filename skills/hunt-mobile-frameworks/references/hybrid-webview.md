# Hybrid WebView apps: Cordova, Capacitor, Ionic, TWA and PWA wrappers

In these apps the logic is the web app in `www/` or `public/`, running in a
platform WebView, with a **native bridge** that hands plugins (filesystem,
HTTP, camera, contacts, SQLite, in-app browser) to JavaScript. The two
questions that matter are: what can the web layer reach through the bridge,
and which origins can get into the web layer.

WebView settings at the platform level (`setJavaScriptEnabled`, file access,
`addJavascriptInterface` in native apps, iOS `WKWebView` preferences) belong
to `hunt-mobile-android` / `hunt-mobile-ios`. This file covers what the
hybrid framework configures.

## Detect

| Framework | Android | iOS |
|---|---|---|
| Cordova | `res/xml/config.xml` (compiled XML) + `assets/www/` | `config.xml` + `www/` in the `.app` |
| Capacitor (Ionic) | `assets/capacitor.config.json`, `assets/capacitor.plugins.json`, `assets/public/` | `capacitor.config.json`, `public/` at the bundle root |
| Ionic on Cordova | Cordova markers plus `cordova-plugin-ionic` keys `ionic_app_id`, `ionic_channel_name`, `ionic_update_api` in `strings.xml` | `IonAppId`, `IonChannelName`, `IonApi` in `Info.plist` |
| Median.co (formerly GoNative, rebrand per search snippet, verify) | `assets/appConfig.json` with `nativeBridgeUrls` (legacy marker); `median-js-bridge` in the JS | similar config (verify) |
| TWA | `com.google.androidbrowserhelper.trusted.LauncherActivity`, meta-data `android.support.customtabs.trusted.DEFAULT_URL`, `asset_statements`, `DelegationService` | n/a |
| PWABuilder iOS shell | WKWebView app with `WKAppBoundDomains`; user agent ends in `PWAShell` | |
| .NET MAUI Blazor Hybrid | `assets/wwwroot/` (see `xamarin-maui.md`) | `wwwroot/` |

`cordova.js`, `cordova_plugins.js` and `plugins/` are **not** a reliable
Cordova marker, because Capacitor writes them into `public/` too. Decide
using `config.xml` versus `capacitor.config.json`.

Default origins: Cordova Android serves from `https://localhost/` (since
cordova-android 10 via WebViewAssetLoader), Cordova iOS from
`app://localhost`, Capacitor Android from `https://localhost` (`androidScheme`
defaults to `https` since Capacitor 6), Capacitor iOS from
`capacitor://localhost`.

## Secrets and endpoints

The web bundle is plain JS. Read it like an SPA: `hunt-spa-api` Steps 1-2 on
the local files, `hunt-source-leak` for source maps shipped in `www/` (common
in hybrid builds), and the `apk-redteam-pipeline` Stage 3 catalog.

Config with security weight:

| Setting | Where | Why it matters |
|---|---|---|
| `<access origin>` | Cordova `config.xml` | which hosts XHR may reach; the default template has `*` |
| `<allow-navigation href>` | Cordova `config.xml` | **every allowed origin also gets the bridge on Android** (`shouldAllowBridgeAccess` returns `shouldAllowNavigation` in cordova-android 15.1.0); `href="*"` gives every http/https page `cordova.exec` |
| `<allow-intent href>` | Cordova `config.xml` | URLs handed to the OS (`tel:`, `sms:`, `geo:`, `market:`); route abuse to `hunt-mobile-android` |
| `server.url` | `capacitor.config.json` | loads a remote site as the app; documented as "not intended for use in production"; a dev or staging URL in a store build is a finding to report |
| `server.allowNavigation` | `capacitor.config.json` | extra origins allowed in the WebView, and on Android allowed to message the bridge |
| `server.cleartext`, `android.allowMixedContent` | `capacitor.config.json` | HTTP content in the app origin (defaults: false) |
| `android.webContentsDebuggingEnabled` | `capacitor.config.json` | defaults to the app's `debuggable` flag in code (the docs say false) |
| `ios.limitsNavigationsToAppBoundDomains` / `WKAppBoundDomains` | config / `Info.plist` | restricts which domains get script injection and message handlers |
| `loggingBehavior` | `capacitor.config.json` | documented as able to leak information if left on in release |
| CSP `<meta http-equiv="Content-Security-Policy">` | `index.html` | Cordova's docs recommend it on every page; its absence turns any injection in the web layer into full script execution |
| `plugins.CapacitorHttp.enabled` | `capacitor.config.json` | patches `fetch` / XHR to native HTTP (default false) |

Capacitor copies the whole external config into the packaged
`capacitor.config.json`. Live-update app IDs, channels and updater keys can
be read straight from the APK or IPA.

## Bridge reach (the core test)

| Framework | Bridge | Who can call it |
|---|---|---|
| Cordova Android | `_cordovaNative` JavascriptInterface plus a bridge secret | the secret is issued only to origins passing `shouldAllowBridgeAccess` = `<allow-navigation>` |
| Cordova iOS | `window.webkit.messageHandlers.cordova` | no frame or origin check seen in `didReceiveScriptMessage` (cordova-ios 8.1.1 source) |
| Capacitor Android | `androidBridge` via `addWebMessageListener` | app origin, `server.url`, each `allowNavigation` entry; main frame only; falls back to `addJavascriptInterface` (reachable from every frame) with `useLegacyBridge` or an old WebView |
| Capacitor iOS | `webkit.messageHandlers.bridge` | bridge JS injected for the main frame only |

Method, on **your own test device and build only**:

1. List the plugins (`cordova_plugins.js`, `capacitor.plugins.json`) and
   the native methods each exposes.
2. List every origin that can reach the bridge: the app origin, the
   allow-navigation and `server.url` origins, and anything loaded in the main
   frame (`location.href` sinks, OAuth return pages, in-app browser content).
3. For each origin you do not own, ask whether it can be controlled by
   anyone else: a third-party CDN, a user-content host, an open redirect on an
   allowed host (`hunt-open-redirect`), or a subdomain open to takeover
   (`hunt-subdomain`).
4. For script injection inside the app origin (DOM XSS in the bundle,
   server-rendered content shown in the WebView), work out which plugin calls
   become reachable. Prove it with a benign marker, such as calling a
   read-only plugin method on your own test install and showing the return
   value in the console.
5. Grade by what the reachable plugins do: file read, contacts, native HTTP
   (CapacitorHttp bypassing CORS is stated in its design proposal, verify),
   SQLite, or opening intents.

Never deliver a WebView payload to another person's device. Stored content
is the hard case. Writing any test content into production (a profile field,
a chat message, a product review) is Stage B behind written sign-off, on
your own two test accounts only, under `hunt-xss` rules. With that sign-off,
stop at proving the content is stored and rendered unescaped between your
own two accounts, using a benign marker. Planting it where real users load it
is not authorizable.

## Intercept

- **Proxy:** Android WebView uses the system-wide proxy by default. An app
  can override it with androidx `ProxyController.setProxyOverride`, so grep
  for it. iOS WKWebView follows the system proxy.
- **Trust:** apps targeting API 24+ trust only system CAs.
  `<debug-overrides>` applies only when `android:debuggable="true"`.
  Install your CA as a system CA (`apk-redteam-pipeline` Stage 8).
- **Inspect instead of proxying, on debuggable builds:**
  - Android: `chrome://inspect`. Since WebView 113.0.5656.0, debugging is on
    automatically for debuggable apps; otherwise the app must call
    `setWebContentsDebuggingEnabled(true)`.
  - iOS: Safari Web Inspector needs `isInspectable = true` (iOS 16.4+ SDK).
    Cordova sets `InspectableWebview` only under `DEBUG`. PWABuilder's iOS shell
    sets `isInspectable = true` outside `#if DEBUG`, so its release builds are
    inspectable.
  - Release builds of Cordova and Capacitor are normally not inspectable. An
    inspectable release build is a platform note.
- **Native HTTP plugins** (`cordova-plugin-advanced-http`, CapacitorHttp)
  bypass the WebView stack and use OkHttp / NSURLSession. They follow the
  platform proxy rules but can pin (below).
- **TWA:** traffic comes from Chrome, which trusts user-store CAs (Chromium
  `X509Util.getUserAddedRoots`; HTTP Toolkit). A user-installed CA plus the
  Wi-Fi proxy usually works without root. Certificate Transparency
  enforcement applies to system-store CAs.

## Pinning bypass

| Implementation | Detail | Bypass |
|---|---|---|
| `cordova-plugin-advanced-http` `setServerTrustMode('pinned')` | loads every DER `.cer` in `www/certificates/` | on your own re-signed test build, replace the `.cer` with your CA's, or use OkHttp / iOS TLS unpinning; modes are `default`, `legacy` (excludes user CAs on Android), `nocheck`, `pinned` |
| Capacitor community SSL-pinning plugins | plugin-specific (verify per plugin) | platform unpinning (`apk-redteam-pipeline` Stage 7, `ios-redteam-pipeline` Stage 4) |
| `network_security_config.xml` pin-set | platform | `apk-redteam-pipeline` Stage 7 |

WebView traffic itself is rarely pinned. The usual blocker is the system CA,
not a pin.

## What breaks Frida and objection

- Logic is JavaScript in the WebView. Java and ObjC hooks see only plugin
  entry points (`CordovaPlugin.execute`, the Capacitor `Plugin` classes).
  Hook those to log bridge traffic: plugin name, method and arguments.
- On a release build without inspection, a Frida hook on
  `WebView.evaluateJavascript` (Android) or the `WKWebView` equivalent can run
  JS in the page **of your own test install** for debugging.
- TWA content runs in Chrome's process, not the app's. Hooking the TWA app
  shows nothing, so test the site as a website.

## OTA and live updates (read-only)

| Channel | Config | Notes |
|---|---|---|
| Ionic Appflow Live Updates | `plugins.LiveUpdates` (`appId`, `channel`, `autoUpdateMethod`, `maxVersions`) in `capacitor.config.json`; legacy `cordova-plugin-ionic` keys above (default API `https://api.ionicjs.com`) | Ionic stopped new sales on 2025-02-11 and is winding down maintenance; Appflow access continues through 2027-12-31 |
| Capgo (`@capgo/capacitor-updater`) | `plugins.CapacitorUpdater`: `updateUrl` (default `https://plugin.capgo.app/updates`), `channelUrl`, `statsUrl`, `publicKey`, `defaultChannel`, `appId`; `allowSetDefaultChannel` defaults to true | encryption v2 uses `publicKey` |
| Remote content | Cordova pages from remote origins, Capacitor `server.url`, TWA start URL | the "update" is the website; its security is web security |

Record from the package and your own install's traffic: updater URL, app ID,
channel, and whether bundles are signed or encrypted (Capgo `publicKey`).
CVE-2026-56254 (NVD, status Deferred) describes Capgo's older end-to-end
encryption scheme distributing the private key to devices (advisory
GHSA-j2f4-4pfc-p8rx). A Capgo app without a v2 `publicKey` is worth noting.
The mapping of the fix to v2 is inferred (verify). Switching to another
channel, or fetching another channel's bundle, is Stage B with sign-off. Publishing anything is prohibited (SKILL.md Step 5).

## Version gates (verified advisories)

| Advisory | Affects | Fixed |
|---|---|---|
| CVE-2026-103922 / GHSA-rvm3-566m-v7fv (critical): remote content loaded at the app origin via Capacitor's internal HTTP proxy path, with plugin access | `@capacitor/android`, `@capacitor/ios`, `com.capacitorjs:core` 6.x < 6.2.2, 7.x < 7.6.9, 8.3.5-8.4.2, 8.5.0; GHSA lists 8.0.0-8.3.4 with no patch | 6.2.2, 7.6.9, 8.4.3, 8.5.1 |
| CVE-2026-47430 / GHSA-q42j-x8rq-pjg6 (critical): iOS InAppBrowser content can dispatch arbitrary Cordova callback IDs | `cordova-plugin-inappbrowser` < 6.0.1 | 6.0.1 |
| CVE-2023-2507 / GHSA-x2ph-qqwm-9cc6: CleverTap Cordova plugin XSS via crafted deep link | CleverTap Cordova plugin 2.6.2 | 2.7.0 |

Read the Capacitor version from `capacitor.plugins.json`, the native
`Capacitor` framework or library strings, or the bundled `@capacitor/core`
code. Report a version in range as a version gate. Do not build a
remote-content chain against the production app to "prove" it.

## TWA and PWA wrappers

- A TWA shows the site full screen after Digital Asset Links verification
  (`https://<site>/.well-known/assetlinks.json`, matched against the app's
  signing certificate). If verification fails, the site opens as a Custom
  Tab with browser UI. The `webview` fallback (`FALLBACK_STRATEGY`,
  Bubblewrap `fallbackType`) applies only when no TWA-capable browser is
  installed.
- The app is the website. Test it with the web skills, starting at the
  `DEFAULT_URL`. The mobile-specific parts: `assetlinks.json` content
  (fingerprints, and which packages may claim the site), the start URL and
  its query parameters (`utm_source=twa` style flags sometimes unlock
  app-only features, see `bundle-to-backend.md` §3b), and whether a WebView
  fallback weakens the cookie or storage model.
- iOS wrappers (PWABuilder shell) are WKWebView apps. `WKAppBoundDomains`
  (up to 10 domains) plus `limitsNavigationsToAppBoundDomains` strip script
  injection and message handlers from non-bound pages. A missing list widens
  what the wrapper's message handlers trust.

## Tools and versions (checked 2026-10-14)

| Item | Version | Source |
|---|---|---|
| cordova-android | 15.1.0 (2026-07-22) | npm |
| cordova-ios | 8.1.1 (2026-07-08) | npm |
| Capacitor | 8.5.3 (2026-10-07); 9.0.0 in alpha | npm, GitHub |
| @capacitor/live-updates | 0.5.0 | npm |
| @capgo/capacitor-updater | 8.52.1 | npm |
| cordova-plugin-advanced-http | 3.3.1 (2022), repo active | npm, GitHub |
| Bubblewrap CLI | 1.27.0 (2026-10-09) | <https://github.com/GoogleChromeLabs/bubblewrap> |

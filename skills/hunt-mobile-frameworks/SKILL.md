---
name: hunt-mobile-frameworks
description: "Test apps built with cross-platform mobile frameworks and route what the bundle ships to the backend skills: Flutter (Dart AOT, Blutter, reFlutter, BoringSSL pinning), React Native (Hermes bytecode, CodePush and EAS Update), Xamarin and .NET MAUI (assembly stores), Unity (IL2CPP, Il2CppDumper, client-trust bugs), Cordova, Capacitor and Ionic (www bundle, plugin bridges), Kotlin Multiplatform, PWA and TWA wrappers. Use when an APK or IPA shows libflutter.so, index.android.bundle, assemblies.blob, global-metadata.dat, www/ or capacitor.config.json."
metadata:
  sources: vendor_docs, project_source_code, tool_documentation, public_research, nvd, github_security_advisories
  report_count: 0
---

## When to use

Trigger when an in-scope app package turns out not to be plain Kotlin/Java or
Swift/Objective-C, so that the stock Android and iOS pipelines see little or
nothing:

- jadx shows a thin `MainActivity` and almost no app logic, while
  `lib/<abi>/` holds `libflutter.so`, `libhermes.so`, `libil2cpp.so`,
  `libmonosgen-2.0.so` or similar.
- `assets/` contains `flutter_assets/`, `index.android.bundle`, `www/`,
  `public/`, `bin/Data/` or an `assemblies*.blob`.
- The proxy shows nothing even though the app is clearly online. Flutter
  ignores the system proxy, and some .NET and Unity stacks do too.
- The program lists a mobile app in scope and the backend is the real target.

`report_count` is 0 because this skill is built from tool documentation,
vendor documentation and public research, not from a counted corpus of
disclosed reports.

### Where the chain ends

Stop at **backend behaviour proved with your own accounts and installs,
impact described, evidence captured**:

- Reverse engineering, interception and pinning bypass happen on your own
  test device or emulator, against your own install. They are means, not
  findings.
- Backend proof follows the owning skill's Stage A (`references/bundle-to-backend.md`).
  Stage B, behind written sign-off: any write, signup, purchase, score or
  receipt submission, message, or action that affects another user.
- OTA and live-update channels (Step 5) are read-only. Publishing,
  replaying or substituting an update for anyone but your own test install
  is prohibited, not Stage B.
- Cross-user proofs (device ID as auth, IDOR) use two test accounts or two
  test installs you control. Using a real user's identifier is Stage B and
  often not authorizable.
- Nothing here is delivered to other people's devices: no repackaged builds
  shared or published, no WebView payloads sent to other users, no
  enterprise MDM enrollment, no TestFlight invite-code guessing.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| APK and IPA acquisition, unzip, jadx, class-dump, generic secret grep, generic Frida and objection templates, Firebase quick probes | `apk-redteam-pipeline` (Stages 0-8), `ios-redteam-pipeline` (Stages 0-6) |
| Platform storage, IPC, exported components, deep links, keychain and keystore, biometrics, WebView settings at the platform level, root and jailbreak detection, tamper resistance (MASVS-STORAGE, PLATFORM, AUTH, RESILIENCE) | `hunt-mobile-android`, `hunt-mobile-ios` |
| Testing the backend APIs the app calls | the skills routed in `references/bundle-to-backend.md` |
| BaaS rules (Firebase, Supabase, Cognito, Auth0, Clerk) | `hunt-cloud-backends` |
| App ownership scoring before deep analysis | `offensive-osint` §21 |
| Game cheats, aimbots, memory editors and anti-cheat bypass | Nobody. Out of scope. Client-trust bugs on the server are in scope (Unity row). |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/flutter.md` | Detection, snapshot hash, Blutter, reFlutter, Dart obfuscation, proxy-unaware traffic, BoringSSL pinning, Shorebird | libflutter.so, libapp.so, flutter_assets, reflutter, blutter, dart snapshot, flutter ssl pinning |
| `references/react-native.md` | Hermes bytecode, hermes-dec, JSC bundles, CodePush and EAS Update config, RN pinning libraries, New Architecture | index.android.bundle, hermes bytecode, hbc, hermes-dec, codepush, expo-updates, react-native-ssl-pinning |
| `references/xamarin-maui.md` | Assembly stores, unpackers, ILSpy, dnSpyEx, AOT, HTTP handlers, Mono hooking | assemblies.blob, xamarin, maui, ilspy, dnspy, monodroid |
| `references/unity.md` | IL2CPP metadata, Il2CppDumper, Cpp2IL, frida-il2cpp-bridge, Mono builds, game-backend client trust | global-metadata.dat, libil2cpp.so, il2cppdumper, cpp2il, unity backend |
| `references/hybrid-webview.md` | Cordova, Capacitor, Ionic, live updates, plugin bridges, allow-navigation, CSP, TWA and PWA wrappers | cordova, capacitor, ionic, www bundle, allow-navigation, trusted web activity, bubblewrap |
| `references/kotlin-multiplatform.md` | KMP and Compose MP detection, Kotlin/Native on iOS, Ktor engines and pinning | kotlin multiplatform, compose multiplatform, ktor, kotlin native, skiko |
| `references/bundle-to-backend.md` | Artefact-to-skill decision table, device-ID auth, version-gated features, debug endpoints, mobile-only APIs | api from apk, endpoints in app, mobile backend, device id auth, feature flag |
| `references/app-store-recon.md` | Finding every app across stores, TestFlight, enterprise distribution, mirrors, version history and diffing, HarmonyOS NEXT | developer page, app store id, appgallery, galaxy store, testflight, apk mirror, harmonyos |

---

## Step 0: Find every app, confirm it is in scope, pull the right build

`references/app-store-recon.md` covers enumeration across Google Play, the
App Store, Huawei AppGallery, Samsung Galaxy Store, Amazon Appstore,
TestFlight public links, enterprise distribution and APK mirrors, plus version
history and HarmonyOS NEXT. Then:

1. Score ownership with `offensive-osint` §21 (>= 70 to analyse). White-label
   apps built by an agency often talk to the agency's backend, not the
   client's.
2. Acquire with `apk-redteam-pipeline` Stage 1 or `ios-redteam-pipeline`
   Stage 1. Prefer the official store build. For a mirror build, compare the
   signing certificate with the Play build before trusting anything in it:

   ```bash
   apksigner verify --print-certs mirror.apk | grep -E 'SHA-256 digest'
   apksigner verify --print-certs play.apk   | grep -E 'SHA-256 digest'
   ```

   A different signer means a different, untrusted build. Analyse it only in an
   isolated VM, never install it on your host, and do not report its contents
   as the vendor's.
3. Keep at least the current and one older build for each platform. Section 5
   of `app-store-recon.md` explains the diffing.

---

## Step 1: Fingerprint the framework

Work offline on the extracted package. Several frameworks can coexist: a
native shell with a Flutter module, a Capacitor app with a Unity view, or
React Native with WebViews.

| Framework | Android markers | iOS markers | Reference |
|---|---|---|---|
| Flutter | `lib/<abi>/libflutter.so`, `libapp.so`, `assets/flutter_assets/` | `Frameworks/Flutter.framework`, `Frameworks/App.framework` | `flutter.md` |
| React Native (Hermes) | `assets/index.android.bundle` that `file` reports as Hermes bytecode; `libhermes.so` (<= 0.81) or `libhermesvm.so` (>= 0.82); `libreactnative.so` (>= 0.76) | `main.jsbundle` (Hermes bytecode); `hermes.framework` or `hermesvm.framework` | `react-native.md` |
| React Native (JSC) | `index.android.bundle` as minified JS; `libjsc.so` / `libjscruntimefactory.so` | `main.jsbundle` as plain JS | `react-native.md` |
| Expo | RN markers plus `expo.modules.*` meta-data in the manifest | `Expo.plist` | `react-native.md` |
| Xamarin / .NET MAUI | `assemblies/assemblies.blob` (store v1), `lib/<abi>/libassemblies.<abi>.blob.so` (.NET 9-10) or `lib/<abi>/libassembly-store.so` (.NET 10 servicing); `libmonosgen-2.0.so`, `libmonodroid.so` | `*.dll` in the app bundle, `Microsoft.iOS` / `Xamarin.iOS` / `Microsoft.Maui*` names | `xamarin-maui.md` |
| Unity (IL2CPP) | `lib/<abi>/libil2cpp.so`, `libunity.so`, `assets/bin/Data/Managed/Metadata/global-metadata.dat` | `Frameworks/UnityFramework.framework`, `Data/Managed/Metadata/global-metadata.dat` | `unity.md` |
| Unity (Mono) | `assets/bin/Data/Managed/Assembly-CSharp.dll` | not expected: iOS builds use IL2CPP (verify) | `unity.md` |
| Cordova | `res/xml/config.xml` + `assets/www/` (`cordova.js` alone is not proof: Capacitor ships it too) | `config.xml` + `www/` | `hybrid-webview.md` |
| Capacitor / Ionic | `assets/public/`, `assets/capacitor.config.json`, `assets/capacitor.plugins.json` | `public/`, `capacitor.config.json` | `hybrid-webview.md` |
| TWA (PWA in a Play wrapper) | `com.google.androidbrowserhelper.trusted.LauncherActivity`, `asset_statements` string resource | n/a (iOS wrappers use WKWebView) | `hybrid-webview.md` |
| Kotlin / Compose Multiplatform | `io.ktor`, `kotlinx` classes in DEX; Compose MP adds `org.jetbrains.compose.resources` classes and `assets/composeResources/` (Android UI is plain Jetpack Compose) | a Kotlin/Native framework (often `shared` or `ComposeApp`) with `kfun:` symbols; `composeResources` inside the framework or `compose-resources` in the app | `kotlin-multiplatform.md` |

```bash
# Offline triage over an extracted APK directory ($D) or an unzipped IPA Payload.
D=extracted_app
ls "$D"/lib/*/ 2>/dev/null | sort -u | grep -E 'flutter|app\.so|hermes|reactnative|jsc|il2cpp|unity|mono|assembl'
find "$D" -maxdepth 4 \( -name 'flutter_assets' -o -name 'index.android.bundle' -o -name 'main.jsbundle' \
  -o -name 'global-metadata.dat' -o -name 'Assembly-CSharp.dll' -o -name 'assemblies*.blob' \
  -o -name 'config.xml' -o -name 'capacitor.config.json' -o -name 'Expo.plist' -o -name 'composeResources' \
  -o -name '*.framework' \) 2>/dev/null
file "$D"/assets/index.android.bundle 2>/dev/null     # "Hermes JavaScript bytecode, version NN" or text
```

Record framework, framework version where visible, and build mode (debug,
profile, release). A debug or profile build of a cross-platform app is a
platform finding for `hunt-mobile-android` / `hunt-mobile-ios`, and it makes
everything below easier.

---

## Step 2: Extract the inventory

Per framework, the reference file gives the tool, command and output. The goal
is always the same inventory: hosts, route strings, GraphQL operations, gRPC
services, socket URLs, OAuth clients, BaaS config, bucket names, keys, feature
flags and OTA config. Then run the `apk-redteam-pipeline` Stage 3 catalog over
the decompiled output, not only over `classes.dex`.

| Framework | Extract with | Where the strings end up |
|---|---|---|
| Flutter | `strings` on `libapp.so`; Blutter (Android arm64); reFlutter `-p` dump | `pp.txt`, `objs.txt`, `dump.dart` |
| React Native | `file` the bundle; `hbc-decompiler` (hermes-dec) for Hermes, a JS formatter for JSC | decompiled pseudo-JS |
| Xamarin / MAUI | assembly-store unpacker, then ILSpy (`ilspycmd`) | C# per assembly; `appsettings*.json` |
| Unity | Il2CppDumper or Cpp2IL on `libil2cpp.so` + `global-metadata.dat`; ILSpy for Mono | `dump.cs`, `stringliteral.json`, `script.json` |
| Cordova / Capacitor | read `www/` or `public/` directly; prettify the JS | JS, `config.xml`, `capacitor.config.json` |
| KMP / Compose MP | jadx (Android); `strings` and `nm` on the iOS framework | Kotlin classes; native strings |
| TWA | the website itself is the app | `hunt-spa-api` on the start URL |

Inventory format and routing: `references/bundle-to-backend.md` Section 1.

---

## Step 3: Get the traffic into your proxy

Decide first whether the HTTP stack is **proxy-aware** and **platform-trust
aware**. That single fact decides the method.

| Stack | System proxy | Platform trust store | First method |
|---|---|---|---|
| Flutter `dart:io` HttpClient (and `http`, `dio` on top of it) | ignored | Android: system store only, no user CAs; iOS: `SecTrust` | transparent or VPN redirect plus a Flutter TLS patch (`flutter.md`) |
| Flutter `cronet_http` / `cupertino_http` | respected | platform (pinning behaviour undocumented, verify) | standard proxy plus platform unpinning |
| React Native `fetch` / axios | respected (OkHttp, NSURLSession) | platform (Android 7+ needs a system CA or config) | standard proxy plus platform unpinning, then library pinning |
| Xamarin / MAUI `AndroidMessageHandler` (default), `NSUrlSessionHandler` (default) | respected | platform | standard proxy |
| Xamarin / MAUI explicit `SocketsHttpHandler` | Android: env vars only, Wi-Fi proxy ignored; iOS: respected | managed TLS | redirect on Android (`xamarin-maui.md`) |
| Unity `UnityWebRequest` | respected (Unity docs) | system root store; `CertificateHandler` for pinning | standard proxy with a system CA; plugins may differ (`unity.md`) |
| Cordova / Capacitor WebView | respected | platform plus app config | standard proxy; plugin HTTP stacks may pin |
| KMP Ktor: OkHttp, CIO on Android | respected (`ProxySelector`) | platform | standard proxy; OkHttp `CertificatePinner` |
| KMP Ktor: Darwin, CIO on iOS | Darwin: NSURLSession defaults (verify); CIO on iOS: ignored | platform | Darwin: standard proxy; CIO: redirect; Ktor Darwin `CertificatePinner` |
| TWA (Chrome) | respected | Chrome on Android trusts user-store CAs | standard proxy, usually no root needed |

Redirect options for stacks that ignore the proxy (all on your own test device):
the emulator's `-http-proxy` flag, ProxyDroid or iptables to a listener with
invisible proxying, VPN capture (HTTP Toolkit, `mitmproxy --mode wireguard`),
or HTTP Toolkit's `native-connect-hook.js`, which rewrites `connect()` in libc.

For the platform side (system CA on Android 14+, Play Integrity, iOS trust
settings) follow `apk-redteam-pipeline` Stages 7-8 and `ios-redteam-pipeline`
Stage 4. Each framework reference has its own **Pinning bypass** section.

---

## Step 4: Why stock Frida and objection scripts miss

| Framework | What the stock script hooks | Why it misses | What works instead |
|---|---|---|---|
| Flutter | OkHttp, `TrustManagerImpl`, NSURLSession, `SecTrust*` | Dart does TLS in the engine's BoringSSL: no Java trust path on Android; on iOS it calls `SecTrust` for the chain, but pins in Dart code run in AOT code | reFlutter, NVISO or HTTP Toolkit Flutter scripts; offset hooks from Blutter |
| React Native (Hermes) | Java and ObjC methods | Business logic is Hermes bytecode in a VM; only native modules are Java/ObjC | hook the network layer (OkHttp, NSURLSession) or the native module; read logic from `hbc-decompiler` |
| Xamarin / MAUI | Java and ObjC methods | Managed code runs in Mono; Java only appears at the `AndroidMessageHandler` boundary | Mono-aware Frida tooling, or patch and re-sign the assembly (`xamarin-maui.md`) |
| Unity IL2CPP | Java and ObjC methods | C# is compiled to native code in `libil2cpp.so` | `frida-il2cpp-bridge`, offsets from Il2CppDumper or Cpp2IL |
| Cordova / Capacitor | Java and ObjC methods | Logic is JS in the WebView | Chrome or Safari remote inspection of a debuggable build; hook the plugin's native side |
| KMP on iOS | ObjC classes (objection `ios hooking`) | Kotlin/Native logic lives in native functions; only exported types are real ObjC classes, others appear only as runtime adapter classes (`<prefix>_kobjcc<N>`) | native hooks on `kfun:` symbols; Ktor Darwin pins are checked in Kotlin after `SecTrust`, so hook the pinner, not just `SecTrust` |

Frida 17 dropped the bundled Java, ObjC and Swift bridges from GumJS (the
`frida` REPL still includes them). Custom agents need `frida-java-bridge` /
`frida-objc-bridge` (`apk-redteam-pipeline` Stage 7). Match `frida-server` to
`frida-tools` exactly.

---

## Step 5: OTA and live-update channels (read-only)

Several frameworks can replace app code without a store release. Record the
channel because it changes what "the build you reversed" means, and because
weak update signing is a reportable design issue. Never test it by pushing
anything.

| Channel | Framework | Where its config lives | Reference |
|---|---|---|---|
| Shorebird code push | Flutter | `flutter_assets/shorebird.yaml` (`app_id`) | `flutter.md` |
| CodePush (App Center retired; self-hosted server) | React Native | `CodePushDeploymentKey`, server URL in `strings.xml` / `Info.plist` | `react-native.md` |
| Expo EAS Update | React Native / Expo | `expo.modules.updates.*` manifest meta-data, `Expo.plist` | `react-native.md` |
| Capacitor live updates (Ionic Appflow, Capgo) | Capacitor | `capacitor.config.json` plugin block | `hybrid-webview.md` |
| Remote web content | Cordova, Capacitor `server.url`, TWA | config files | `hybrid-webview.md` |

Allowed (Stage A):

- Record the key, channel, server URL and runtime version from the package.
- Observe the update check and response for **your own** install through the
  proxy, and note whether the update is signed and whether the client verifies
  the signature (from config and decompiled code).
- Report exposure of a **management or publishing credential** (a CodePush
  access key, an EAS or Expo token, an Appflow or Capgo API key) on exposure
  alone. Make no call with it. A publishing key reaches every installed user,
  so even an identity check would need Stage B sign-off, and the exposure
  proves the finding without one.

Stage B, with written sign-off and only where the program allows it:
fetching a channel your install does not use (another deployment key, an
`expo-channel-name` value, a Capgo channel). That pulls content the vendor did
not ship to you, such as staging builds.

Prohibited, regardless of sign-off:

- Publishing, promoting, rolling back or replaying an update to any channel.
- Serving a modified update to any device that is not your own test install.
- Using a leaked publishing credential to list, change or publish anything.

---

## Step 6: Hand off to the backend skills

`references/bundle-to-backend.md` holds the decision table from artefact
type to skill, plus the mobile-specific backend bugs: device ID used as
authentication, version-gated features visible in the bundle, debug and
staging endpoints, and unversioned mobile-only APIs.

Rules that apply to every row:

- Stage A first, as defined by the owning skill: read-only, minimal, one
  process, inside the program's request ceiling (`engine/throttle.py`).
- Cross-account proof uses two test accounts or installs you control.
- Stage B is blocked by default. It needs written sign-off naming the
  endpoint, the account or record, the number of requests and a window. It
  covers any write, signup, purchase, receipt or score submission, push or
  device registration, message to a user, or use of a leaked secret beyond an
  identity call. "The app is in scope" is not sign-off.

---

## Step 7: Grade on backend impact

| What you proved | Grade |
|---|---|
| Admin or service credential in the bundle that works (one read-only identity call) | Critical |
| Device or install ID alone authenticates; your second install's data returned | High to Critical, by data class and how guessable the ID is |
| Mobile-only or old-version API serves data without auth that the web API protects | High |
| Gated or unreleased feature route served to an ineligible account, exposing data or capability | Medium to High |
| OTA publishing credential exposed in the bundle | High (reported on exposure; no call made) |
| OTA updates unsigned and fetched over a channel the app does not pin | Low to Medium design issue; needs a network position to matter |
| Debug or staging host from the bundle, in scope, with unauthenticated data | Medium to High |
| Server trusts client-computed price, balance or entitlement (Stage B proof on your own account) | Medium to High |

### What is not a finding

| Observation | Why |
|---|---|
| "Built with Flutter / RN / Unity" | Framework choice is not a vulnerability |
| Hermes bytecode, Dart AOT or IL2CPP decompiled | Reversing is expected; obfuscation is a resilience control (`hunt-mobile-*`) |
| Pinning bypassed on your own rooted or jailbroken device | Means, not a finding; pinning-absent is a low platform note |
| Public client config (Firebase web key, Supabase anon key, Cognito client ID) | Public by design; see `hunt-cloud-backends` "not a finding" |
| Endpoint list recovered from the app | Recon. The finding is what the endpoint does |
| CodePush or EAS deployment key, Shorebird `app_id` | Client identifiers by design |
| Game-balance or cheat findings with no server-side trust failure | Out of scope |

---

## Evidence

Follow `evidence-hygiene`. Record the app ID, version code or build number,
platform, store or mirror source and signing-cert SHA-256; the file and offset
or decompiled path where the artefact was found; the exact backend request,
timestamp and egress IP; the sign-off reference for any Stage B step; and every
test account or install you created. Redact keys to a prefix and suffix
before they leave your machine.

---

## Validation checklist

- [ ] App ownership scored (`offensive-osint` §21), build source recorded,
      mirror builds checked against the Play signer.
- [ ] Framework and build mode recorded; all co-existing frameworks found.
- [ ] Inventory extracted from the framework output, not only from DEX or the
      Mach-O strings.
- [ ] Interception and unpinning done on your own test device only; no
      repackaged build shared or published.
- [ ] Every backend test routed through `references/bundle-to-backend.md` and
      run at the owning skill's Stage A.
- [ ] Cross-user proofs used two accounts or installs you control.
- [ ] Every write, signup, submission or registration has a logged Stage B
      sign-off.
- [ ] OTA channels observed read-only; nothing published, replayed or served.
- [ ] Platform-level observations handed to `hunt-mobile-android` /
      `hunt-mobile-ios` rather than reported here.

---

## Related Skills & Chains

- `apk-redteam-pipeline`, `ios-redteam-pipeline`: acquisition, decompilation,
  secret catalog and generic Frida templates this skill builds on.
- `hunt-mobile-android`, `hunt-mobile-ios`: MASVS platform methodology:
  storage, IPC, deep links, WebView settings, biometrics, resilience.
- `hunt-spa-api`, `hunt-shadow-api`, `hunt-api-misconfig`, `hunt-graphql`,
  `hunt-grpc`, `hunt-websocket`, `hunt-oauth`, `hunt-jwt-crypto`: backend
  testing of what the bundle reveals.
- `hunt-cloud-backends`, `hunt-cloud-misconfig`, `cloud-iam-deep`: BaaS
  configs, buckets and cloud keys from the bundle.
- `hunt-llm-ai`: in-app assistants and chat.
- `offensive-osint`: app ownership scoring (§21), secret validators (§23).
- `recon-scope-triage`: new hosts from the bundle before any request.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence,
  false-positive gates, write-up.

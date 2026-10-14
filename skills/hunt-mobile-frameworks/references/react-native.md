# React Native and Expo

The app logic ships as one JavaScript bundle. In most current apps it is
compiled to **Hermes bytecode (HBC)**. Older or opted-out apps ship plain
minified JS executed by JavaScriptCore. Native modules (Java/Kotlin,
ObjC/Swift) sit underneath and do the networking.

Acquisition, unzip and the generic secret catalog are owned by
`apk-redteam-pipeline` Stages 1 and 3 and `ios-redteam-pipeline` Stages 1-3.

## Detect

| Platform | Marker | Notes |
|---|---|---|
| Android | `assets/index.android.bundle` | `file` says `Hermes JavaScript bytecode, version NN` or shows text |
| Android | `lib/<abi>/libhermes.so` (RN <= 0.81) or `libhermesvm.so` (RN >= 0.82) | glob `libhermes*.so` |
| Android | `libreactnative.so` (RN >= 0.76 merged most RN native libs into it, so `libreactnativejni.so` is absent); `libhermestooling.so` | older apps: `libreactnativejni.so` |
| Android | `libjscexecutor.so` / `libjsc.so` (<= 0.78), `libjscruntimefactory.so` (>= 0.79, community JSC package) | JSC engine instead of Hermes |
| iOS | `main.jsbundle` (default `$BUNDLE_NAME.jsbundle`) in the `.app` | Hermes-compiled unless `USE_HERMES=false` |
| iOS | `Frameworks/hermes.framework` (<= 0.81) or `hermesvm.framework` (>= 0.82) | |
| Expo | manifest meta-data `expo.modules.updates.*`; iOS `Expo.plist` | EAS Update config (see OTA) |

The HBC header is the magic `C6 1F BC 03 C1 03 19 1F` on disk, then a 32-bit
little-endian bytecode version at offset 8, then a 20-byte SHA1 source hash
(Hermes `BytecodeFileFormat.h`).

```bash
# Offline. Read the version from the file, never infer it from the RN version.
file assets/index.android.bundle
xxd -l 12 assets/index.android.bundle
od -An -tu4 -j8 -N4 assets/index.android.bundle      # bytecode version (from the header layout)
```

Bytecode version by Hermes line (Hermes repo branches, checked 2026-10-14):
85 (RN 0.69), 89 (0.70), 90 (0.71), 94 (0.72), 96 (0.73 to 0.84 legacy
Hermes), **98 for Hermes V1** (opt-in in RN 0.82, default from 0.84, only
engine listed in 0.87), **99** for the `260318099.x` line (RN 0.88). Read
the header anyway: from 0.82 to 0.86 the engine choice changes the version.

## Secrets and endpoints

- **Hermes:** decompile with hermes-dec, then grep the pseudo-JS:

  ```bash
  pipx install hermes-dec               # or: uv tool install hermes-dec
  hbc-file-parser  assets/index.android.bundle                   # header fields
  hbc-disassembler assets/index.android.bundle out/bundle.hasm
  hbc-decompiler   assets/index.android.bundle out/bundle.js     # pseudo-code, no rebuilt loops or ifs
  ```

  hermes-dec 0.1.7 ships opcode tables for HBC 51 to 99. Having a table does
  not prove full decompiler support for that version, so check the output.
  The string table alone (`hbc-disassembler` output, or `strings`) already
  gives hosts, paths and keys.
- **JSC (plain JS):** prettify with prettier or js-beautify. webcrack
  (<https://github.com/j4k0xb/webcrack>) unminifies and unpacks bundles. The
  old react-native-decompiler projects are stale.
- **Where config lives:** `react-native-config` / `.env` values are compiled
  into the bundle as constants. Native config sits in `res/values/strings.xml`
  and `Info.plist`. Look for `CodePush*`, `expo.modules.updates.*`, Sentry DSNs,
  Firebase, Branch, OneSignal and analytics keys there.
- **Source maps** are written to
  `build/generated/sourcemaps/react/<variant>/index.android.bundle.map`,
  outside `assets/`, so they normally do not ship (verify per app). An OTA
  update or a CDN may still expose one (`hunt-source-leak`).
- Release builds bundle with `--dev false`, so `__DEV__` branches are dead
  code. They still name debug endpoints, which is useful for
  `bundle-to-backend.md` §3c.

## Intercept

RN networking is native, so it usually behaves:

- **Android:** `fetch` and XHR go through `NetworkingModule`, which builds an
  OkHttp client with no explicit proxy. OkHttp then falls back to
  `ProxySelector.getDefault()`, so the Wi-Fi proxy normally applies. The RN
  template sets no network security config, and apps targeting API 24+ trust
  only system CAs, even in debug builds. Install your CA as a system CA
  (`apk-redteam-pipeline` Stage 8).
- **iOS:** `NSURLSession` with the default configuration. Apps can replace it
  via `RCTSetCustomNSURLSessionConfigurationProvider`, so check for that if
  traffic bypasses the proxy.
- **Exceptions:** WebSockets (`hunt-websocket`), native SDKs with their own
  stacks, and any library that builds its own OkHttp client.

## Pinning bypass

| Implementation | How it pins | Bypass |
|---|---|---|
| `react-native-ssl-pinning` (MaxToyberman, 1.6.0) | exports its **own** `fetch`; Android public-key mode uses OkHttp `CertificatePinner`, certificate mode a custom trust store with `.cer` files in `assets/`; iOS uses AFNetworking `AFSecurityPolicy` with `.cer` files in the bundle | the global `fetch` is not pinned; for its `fetch`, standard OkHttp / AFNetworking unpinning, or replace the bundled `.cer` with your CA on your own re-signed test build |
| `react-native-ssl-public-key-pinning` (frw, 1.2.6) | `initializeSslPinning`; OkHttp `CertificatePinner` via `NetworkingModule.setCustomClientBuilder` on Android, TrustKit on iOS; covers global `fetch` and XHR, so axios too | OkHttp unpinning on Android; TrustKit / `SecTrust` hooks on iOS (objection, HTTP Toolkit `native-tls-hook.js`) |
| App-level `OkHttpClientProvider.setOkHttpClientFactory` / `setCustomClientBuilder` | custom OkHttp client in `MainApplication` | standard OkHttp unpinning |
| `network_security_config.xml` `<pin-set>` | platform pinning | `apk-redteam-pipeline` Stage 7; `<debug-overrides>` only applies to debuggable builds |

Pinning in the JS layer (hash comparison in JS) is rare. Find it in the
decompiled bundle by searching for `sha256/` pins and certificate fields.

## What breaks Frida and objection

- Java and ObjC hooks see only native modules. The business logic (auth
  flows, signing, feature gates) is bytecode inside the Hermes VM. Read it
  from `hbc-decompiler` output instead of trying to hook it.
- Hook at the boundary instead: OkHttp or `NetworkingModule` on Android,
  `NSURLSession` on iOS for requests, and the native module a feature calls
  (`NativeModules.<Name>`), visible as a Java or ObjC class.
- **Injecting JS into Hermes.** Pilfer's 2024 write-up hooks
  `CatalystInstanceImpl.loadScriptFromAssets` and loads an extra script into
  the global context. `CatalystInstanceImpl` no longer exists in RN 0.87. The
  bridgeless equivalents are in `runtime/ReactInstance.kt`
  (`loadScriptFromAssets` / `loadScriptFromFile`, which call native
  `loadJSBundleFromAssets` / `loadJSBundleFromFile`). Whether the technique
  ports to them is unconfirmed (verify). Do this only on your own test
  install.
- **Patching the bundle.** Hermes rejects bytecode whose version differs
  from its build ("Wrong bytecode version"). A reassembled bundle must keep
  the exact version. Re-signing makes it a different app, and that app stays
  on your test device.
- Debug tooling is mostly gone. Flipper's native setup was removed from the
  template in 0.74, and Chrome remote JS debugging was removed in 0.79.

## OTA channels (read-only)

| Channel | Config in the package | Notes |
|---|---|---|
| CodePush | Android `strings.xml`: `CodePushDeploymentKey`, `CodePushServerUrl`, `CodePushPublicKey`; iOS `Info.plist`: `CodePushDeploymentKey`, `CodePushServerURL`, `CodePushPublicKey` | App Center, including hosted CodePush, retired on 2025-03-31. `microsoft/react-native-code-push` (last 9.0.1, deprecated on npm) and `microsoft/code-push-server` are archived, and the SDK does not support the New Architecture. A CodePush app today is old, self-hosted, or using a fork |
| CodePush forks | same keys; Revopush defaults to `api.revopush.org` | also AppZung; Stallion and hot-updater use their own SDKs |
| Expo EAS Update | iOS `Expo.plist`: `EXUpdatesURL`, `EXUpdatesRuntimeVersion`, `EXUpdatesRequestHeaders`, `EXUpdatesCodeSigningCertificate`, `EXUpdatesCodeSigningMetadata`; Android meta-data `expo.modules.updates.EXPO_UPDATE_URL`, `EXPO_RUNTIME_VERSION`, `UPDATES_CONFIGURATION_REQUEST_HEADERS_KEY`, `CODE_SIGNING_CERTIFICATE` | URL `https://u.expo.dev/<project-id>`, channel in the `expo-channel-name` request header; signed updates use `expo-expect-signature` / `expo-signature` (rsa-v1_5-sha256), and code signing is limited to certain EAS plans |

What to record, from the package and from your own install's traffic only:

- Server URL, deployment key or project ID, channel, runtime version.
- Whether a signing public key or certificate is configured. With CodePush,
  `CodePushPublicKey` absent most likely means the client does not check
  bundle signatures (inferred from the SDK's config, verify). With Expo, `EXUpdatesCodeSigningCertificate` absent means the
  client does not check update signatures (code signing is opt-in).
- Whether the update host is pinned, from the pinning sections above.

A deployment key or project ID is a client identifier, not a finding.
Changing the `expo-channel-name` header or the deployment key to fetch
another channel's update (for example staging) downloads content the vendor
did not ship to you. Treat it as Stage B with sign-off, and only where the
program allows it. A management credential in the bundle (a CodePush access
key, an Expo or EAS token, a Revopush or Stallion API key) is reported on
exposure. SKILL.md Step 5 lists what is prohibited.

## Tools and versions (checked 2026-10-14)

| Tool | Version / state | Source |
|---|---|---|
| React Native | 0.87.1 stable; 0.88.0-rc.5 | npm `react-native` |
| Expo SDK | 57 (`expo` 57.0.28); 58 tagged `next` | npm `expo` |
| Hermes compiler | npm `hermes-compiler` `latest` 250829098.0.19, `latest-v1` 260318099.0.4, `latest-v0` 0.17.0 | npm |
| hermes-dec | 0.1.7 (2026-08-11), HBC 51-99 tables | <https://github.com/P1sec/hermes-dec> |
| HBC-Tool (hbctool fork) | active (2026-08-31), README lists 83-99; `disasm` / `asm` | <https://github.com/Kirlif/HBC-Tool> |
| hbctool | last commit 2023-04; old versions only | <https://github.com/bongtrop/hbctool> |
| hermes_rs | disassembler/assembler, HBC 76, 89, 90, 93-96 | <https://github.com/Pilfer/hermes_rs> |
| r2hermes | radare2 plugin, active; `r2pm -ci r2hermes` | <https://github.com/radareorg/r2hermes> |
| hbcdump | ships with Hermes; reads only its own bytecode version | facebook/hermes `tools/hbcdump` |
| hasmer | archived 2024-10 | <https://github.com/lucasbaizer2/hasmer> |

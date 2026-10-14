# Flutter (Dart AOT)

Release builds compile Dart ahead of time into a snapshot inside `libapp.so`
(Android) or `App.framework/App` (iOS). There is no DEX and no JS to read. The
engine (`libflutter.so` / `Flutter.framework`) carries its own BoringSSL and
its own HTTP stack (`dart:io`). Most of what makes Flutter awkward for a
tester comes from that one design choice.

Acquisition, unzip and the generic secret catalog are owned by
`apk-redteam-pipeline` Stages 1 and 3 and `ios-redteam-pipeline` Stages 1 to 3.
This file covers only what is Flutter-specific.

## Detect

| Platform | Marker | Notes |
|---|---|---|
| Android | `lib/<abi>/libflutter.so` + `lib/<abi>/libapp.so` | AOT release or profile build |
| Android | `assets/flutter_assets/` (`AssetManifest*`, `FontManifest.json`, `NOTICES.Z`, `fonts/`, `packages/`) | present in all modes |
| Android | `flutter_assets/kernel_blob.bin`, `vm_snapshot_data`, `isolate_snapshot_data`, no `libapp.so` | debug (JIT) build; Dart source is far easier to recover; report the debug build itself to `hunt-mobile-android` |
| iOS | `Payload/Runner.app/Frameworks/App.framework/App` + `Frameworks/Flutter.framework/Flutter` | `Runner.app` is the default bundle name, not guaranteed; a debug build has only a placeholder `App.framework` |
| Both | `flutter_assets/shorebird.yaml` | Shorebird code push (OTA, see below); reFlutter also detects Shorebird by snapshot hash when the file is absent |

Two identifiers decide which tools work:

- The **snapshot hash** (32 hex characters) identifies the Dart VM build and
  keys reFlutter's `enginehash.csv`. Blutter's `extract_dart_info.py` reads it
  at symbol `_kDartVmSnapshotData` + 20 in `libapp.so`, followed by the VM
  flags string. reFlutter prints it as `SnapshotHash:`.
- The **engine commit** (40 hex characters) and a version string such as
  `3.47.5 (stable)` sit in `libflutter.so` `.rodata`. Blutter maps the commit
  to the matching Dart SDK.

```bash
# Offline, on files you already extracted.
strings -n 8 lib/arm64-v8a/libflutter.so | grep -E '^[0-9a-f]{40}$|\((stable|beta|dev)\)' | head
pip3 install reflutter && reflutter app.apk   # prints SnapshotHash, then prompts for a proxy IP (see Intercept)
```

## Secrets and endpoints

String literals live in the Dart object pool. Obfuscation (`flutter build
<target> --obfuscate --split-debug-info=<dir>`, release builds only) renames
classes and functions. Flutter's docs say it does not encrypt resources and
does not obfuscate enum names. The docs do not say what happens to string
literals. Blutter's `pp.txt` on obfuscated builds still shows URLs and keys
(inferred from tool output, verify on your build).

1. **Fast pass:** `strings -n 6 libapp.so` and run the
   `apk-redteam-pipeline` Stage 3 catalog over the output. Hosts, paths, API
   keys and Firebase options are usually visible here.
2. **Structured pass with Blutter** (Android arm64 only, recent Dart versions
   only, per its README). It compiles a matching Dart runtime and dumps the
   object pool with symbols:

   ```bash
   # Needs g++ >= 13 or clang >= 16; first run builds the Dart VM for that version.
   python3 blutter.py path/to/app/lib/arm64-v8a out_dir
   # out_dir/pp.txt    all Dart objects in the object pool (strings, URLs, keys)
   # out_dir/objs.txt  nested object dump
   # out_dir/asm/*     libapp assembly with symbols
   # out_dir/blutter_frida.js  Frida template for the app
   ```

   `--rebuild` forces a rebuild after `git pull`. Blutter has no tagged
   releases; track the default branch (last commit 2026-08-18 when checked).
3. **Function map with reFlutter dump mode** (`reflutter -p app.apk`, re-sign,
   run, then `adb pull /data/data/<package>/dump.dart`). You get one JSON line
   per function with library URL, class, method and offset. Library URLs such
   as `package:<app>/api/client.dart` show where the API layer lives.
4. Look in `flutter_assets/` for `.env` files (`flutter_dotenv`), JSON config,
   and `assets/` folders that ship environment files for every flavour.
5. On iOS, `App.framework/App` is FairPlay-encrypted in a Store build. Decrypt
   per `ios-redteam-pipeline` Stage 1 before any of the above.

## Intercept

Two separate problems:

- **Proxy.** Dart's `HttpClient` ignores the system proxy. Per the
  `findProxy` docs, "If this function is not set, direct connections will
  always be used." Setting a Wi-Fi proxy does nothing for `dart:io`, `http`
  or `dio` traffic.
- **Trust.** TLS runs in the engine's BoringSSL. On Android, Dart loads roots
  only from `/system/etc/security/cacerts` (dart-lang/sdk
  `security_context_linux.cc`), so a **user-installed CA is not trusted**. On
  Android 14+, the system store that Conscrypt uses moved to the APEX module,
  and whether Dart follows it is untested here (verify). On iOS, Dart
  validates through `SecTrust` against the platform roots. Older write-ups that
  say "Flutter has a compiled-in CA list" predate this source. App-level
  pinning sits on top of either path.

Ways to get the traffic to your proxy, from least to most invasive:

| Method | How | Notes |
|---|---|---|
| Emulator-level proxy | AVD `-http-proxy <host:port>` | Suggested in NVISO's README for Android Studio AVDs |
| Transparent redirect on a rooted test device | ProxyDroid, or iptables NAT to a Burp listener with *invisible proxying* enabled | Burp must handle non-proxy-aware clients |
| VPN-based capture | HTTP Toolkit's Android app, or mitmproxy WireGuard mode (`mitmproxy --mode wireguard`), or OpenVPN on iOS | No root needed for the redirect itself |
| Per-app proxy on iOS | Potatso or similar, per reFlutter's README | Device requirements not stated in the README (verify) |
| Socket-level Frida redirect | HTTP Toolkit `native-connect-hook.js` | Rewrites `connect()`; catches clients that ignore proxy settings |

Packages that use the platform stack, `cronet_http` on Android and
`cupertino_http` on iOS, document proxy and VPN support. Their trust and
pinning behaviour is not documented (verify). Check package names
(`package:cronet_http/...`) in `pp.txt` or `dump.dart` before choosing a
method.

## Pinning bypass

What you are bypassing:

- **Trust only.** Your CA is not in the store Dart reads (user CA on Android).
- **`SecurityContext`** built with `withTrustedRoots: false` and
  `setTrustedCertificatesBytes(<bundled cert>)`.
- **dio** `IOHttpClientAdapter.validateCertificate(cert, host, port)`, which
  checks the leaf after the chain is accepted, or `badCertificateCallback`.
- **`http_certificate_pinning`.** It opens its own native connection to
  compare SHA-1 or SHA-256 fingerprints (`HttpsURLConnection` on Android,
  Alamofire on iOS) before the Dart request. Platform unpinning hooks affect
  that check, not the Dart request, so you may need both.

| Option | What it does | Constraints |
|---|---|---|
| **reFlutter repack** (`reflutter app.apk` / `app.ipa`) | Swaps in a prebuilt engine whose BoringSSL chain verification always succeeds | Snapshot hash must be in `enginehash.csv` (on 2026-10-14 it covered 3.47.0-3.47.5; stable 3.47.7 had no row, verify); re-sign the output (`uber-apk-signer --allowResign -a release.RE.apk`); engines <= 3.24.x get a hardcoded proxy IP patched in (Burp listener on 8083, invisible proxying); from 3.27.x the README says to set the device proxy, and whether the patched engine honours it is unconfirmed, so keep a transparent redirect ready |
| **reFlutter `frida-ssl.js`** (no repack) | Patches verification inside the loaded `libflutter.so` | Needs an engine with a symbol table: Shorebird engines, debug and profile builds; stock release engines are stripped |
| **NVISO `disable-flutter-tls.js`** | Pattern-matches `ssl_verify_peer_cert` (one arm64 pattern: `ssl_crypto_x509_session_verify_cert_chain`) and forces success | `frida -U -f <package> -l disable-flutter-tls.js`; drop the README's `--no-pause`, which frida-tools 12+ removed; the script config covers Android arm64/arm/x64/x86 and iOS arm64 (the README line is stale); open issues from Aug-Sep 2026 report arm64 builds where no pattern matches, so check `libflutter_samples/` and `verify.py` |
| **HTTP Toolkit `android-disable-flutter-certificate-pinning.js`** | Hooks Dart's `SSLCertContext::CertificateCallback` by instruction pattern so your CA is trusted and custom validation is ignored | Android only; patterns cover Flutter 2.0.0 to 3.44.0 debug and release engines per its header; marked experimental; pair with `config.js` and `native-connect-hook.js` |
| **Blutter `blutter_frida.js` / reFlutter `frida.js`** | Hook the app's own pinning function by offset | For app-level pinning that survives the engine patch |

Pinning absent or bypassable is a platform observation for
`hunt-mobile-android` / `hunt-mobile-ios`, not a finding here. The bypass is
only the means to see the backend traffic.

## What breaks Frida and objection

- `Java.use('okhttp3...')`, `TrustManagerImpl` and objection's `android
  sslpinning disable` hook the Java stack. Dart traffic never touches it, so
  they report success and change nothing.
- On iOS, Dart validates the chain through `SecTrust` (dart-lang/sdk
  `security_context_macos.cc`), so objection's `ios sslpinning disable` may
  get a trust-only case through. Pins enforced in Dart (`SecurityContext`
  with bundled roots, dio `validateCertificate`) run in AOT code that ObjC
  hooks never see. Verify per app, and fall back to reFlutter or offset
  hooks.
- Dart functions have no exported symbols in a stripped release build. Hook
  by offset from Blutter or reFlutter dump output, relative to the Dart
  instructions image (`_kDartSnapshotText` on newer Dart,
  `_kDartIsolateSnapshotInstructions` on older), not the ELF base.
- Frida 17 removed the bundled Java and ObjC bridges from GumJS. The `frida`
  REPL still bundles them (see `apk-redteam-pipeline` Stage 7). Flutter
  scripts are native-only, so they are mostly unaffected. reFlutter notes that
  16.x frida-server cannot inject on Android 15+, so use 17.x.

## OTA: Shorebird code push

Shorebird ships a modified engine that checks for Dart patches at startup.
`flutter_assets/shorebird.yaml` carries the `app_id` (one per flavour).
Shorebird documents `api.shorebird.dev` for the in-app updater and
`cdn.shorebird.cloud` for patch delivery, and supports patch signing.

Stage A here is recording the `app_id`, whether patch signing is in use (verify
from the shipped config), and the patch your own install receives, as seen in
your proxy. Publishing, replaying or substituting a patch for any install
other than your own test build is prohibited (SKILL.md Step 5).

## Tools and versions (checked 2026-10-14)

| Tool | Version / state | Source |
|---|---|---|
| Flutter stable | 3.47.7 with Dart 3.13.5 (2026-10-08) | <https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json> |
| reFlutter | engine assets tagged `android-v3-<hash>` / `ios-v3-<hash>`, latest 2026-09-22; PyPI `reflutter` 0.9.8 | <https://github.com/Impact-I/reFlutter> |
| Blutter | no releases, default branch updated 2026-08-18; Android arm64 only | <https://github.com/worawit/blutter> |
| disable-flutter-tls-verification | no releases, updated 2026-06-17 | <https://github.com/NVISOsecurity/disable-flutter-tls-verification> |
| HTTP Toolkit Frida scripts | no releases, updated 2026-10-14; Flutter patterns stop at 3.44.0, behind current stable | <https://github.com/httptoolkit/frida-interception-and-unpinning> |
| unflutter | static Dart AOT snapshot parser, created 2026-02, very new | <https://github.com/zboralski/unflutter> |
| Doldrums | unmaintained since 2022-05, Dart 2.10 only; do not use on current apps | <https://github.com/rscloura/Doldrums> |
| Frida | 17.23.3 (2026-10-09) | <https://github.com/frida/frida/releases> |
| mitmproxy | 12.2.3 (2026-05-12) | <https://github.com/mitmproxy/mitmproxy/releases> |

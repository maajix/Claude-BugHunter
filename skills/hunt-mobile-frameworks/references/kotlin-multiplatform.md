# Kotlin Multiplatform and Compose Multiplatform

KMP shares Kotlin code between platforms. On Android the shared module is
ordinary Kotlin/JVM, so jadx and every Android tool work as usual. On iOS
the same code is compiled by Kotlin/Native into a native framework, and
that is where iOS tooling stops seeing it (kotlinlang.org,
"multiplatform-discover-project"). Compose Multiplatform adds a shared UI.
On Android that UI is Google's Jetpack Compose. On iOS it renders through
Skiko, which is Skia for Kotlin.

Android-side decompilation is `apk-redteam-pipeline` Stage 2. iOS
decryption and class-dump are `ios-redteam-pipeline` Stages 1-2. This file
covers the KMP-specific parts.

## Detect

| Platform | Marker | Meaning |
|---|---|---|
| Android | `io.ktor.*`, `kotlinx.serialization.*`, `kotlinx.coroutines.*` packages next to the app's own `shared` / `common` package | KMP likely (these are also common in plain Android apps; check the iOS build) |
| Android | `org.jetbrains.compose.resources.*` classes, `assets/composeResources/<pkg>.generated.resources/` | Compose Multiplatform resources |
| iOS | a framework under `Frameworks/` named `shared`, `Shared`, `ComposeApp` or `<Module>.framework` with Kotlin symbols | Kotlin/Native output |
| iOS | `kfun:` prefixed symbols in `nm` output (seen in Kotlin/Native debugging docs; release frameworks may be stripped, verify) | Kotlin/Native functions |
| iOS | `Frameworks/*.framework/composeResources` or `<App>.app/compose-resources` | Compose Multiplatform resources |

```bash
# Offline. Android: look for KMP namespaces in jadx output.
grep -rl --include=*.java -E 'io\.ktor\.client|org\.jetbrains\.compose\.resources' decompiled_app/sources | head
# iOS: framework symbols and strings.
nm -a Payload/*.app/Frameworks/ComposeApp.framework/ComposeApp 2>/dev/null | grep -c 'kfun:'
strings -n 8 Payload/*.app/Frameworks/*.framework/* 2>/dev/null | grep -E 'https?://' | sort -u | head
```

## Secrets and endpoints

- **Android:** the shared module decompiles like any Kotlin code. Ktor
  `defaultRequest { url(...) }` blocks, `HttpClient {}` configuration,
  `@Serializable` DTOs (field names give request shapes) and Koin or Kodein
  modules usually hold the base URLs and keys. Run the
  `apk-redteam-pipeline` Stage 3 catalog over the jadx output.
- **iOS:** the same constants appear as strings in the Kotlin/Native
  framework. Compare them with the Android build. If they differ, the
  platforms are configured separately, and the iOS build may point at
  another environment.
- **BuildKonfig / expect-actual config:** generated `BuildKonfig` or
  `AppConfig` objects carry per-flavour URLs and keys. Look for flavour
  names (`dev`, `staging`) in both builds.
- **Compose resources:** `composeResources/` can hold JSON config and string
  tables. Read them directly.

## Intercept

Interception depends on the Ktor engine, and each platform can use a
different one (ktor.io client engines doc, Ktor 3.6.0):

| Engine | Platforms | System proxy | Notes |
|---|---|---|---|
| OkHttp | JVM, Android | respected (`ProxySelector.getDefault()`) | standard Android interception (`apk-redteam-pipeline` Stage 8) |
| Android | JVM, Android | platform `HttpURLConnection` | standard Android interception |
| CIO | everywhere, HTTP/1.x only | JVM and Android: respected since 2025-07 (KTOR-5922); iOS/native: ignored | on iOS use a transparent or VPN redirect |
| Darwin | Apple, NSURLSession | NSURLSession defaults, likely respected (verify) | Ktor's docs say HTTPS through a Ktor-configured HTTP proxy is not supported on Darwin; this concerns Ktor's own proxy setting, not the device's |

## Pinning bypass

- **OkHttp engine:** an OkHttp `CertificatePinner` passed through the engine
  config. Standard Android unpinning works (`apk-redteam-pipeline` Stage 7,
  HTTP Toolkit `android-certificate-unpinning.js`).
- **Darwin engine:** `io.ktor.client.engine.darwin.certificates.CertificatePinner`
  installed with `handleChallenge(...)`. It calls `SecTrustEvaluateWithError`
  and then compares the pins **in Kotlin** (ktor source
  `CertificatePinner.kt`). Hooking `SecTrust` alone makes the chain pass but
  leaves the pin comparison failing. Find the pinner's Kotlin/Native
  function (`kfun:` symbol or by string reference to the `sha256/` pins) and
  hook its result, or use HTTP Toolkit's `native-tls-hook.js` together with
  an app-specific hook.
- **CIO on iOS:** uses Ktor's own TLS. Platform hooks do not apply. Look for
  a custom trust manager in the shared code.

## What breaks Frida and objection

- objection's `ios hooking list classes` and `ios hooking watch class` only see
  Objective-C classes. Exported Kotlin types become real ObjC classes,
  prefixed with the framework name. Non-exported Kotlin types get an ObjC
  class only when an instance crosses into Objective-C, created at runtime as
  `<prefix>_kobjcc<N>` with only adapter methods (JetBrains/kotlin
  `ObjCExport.mm`). Business logic stays in native Kotlin functions that ObjC
  hooking does not reach.
- Hook Kotlin/Native functions natively with `Interceptor.attach` on the
  symbol (`kfun:...`) when the framework keeps symbols. Otherwise resolve the
  function by cross-reference from a string in the disassembler.
- Kotlin subclasses of `NSObject`, such as `NSURLSessionDelegate`
  implementations for the Darwin engine, are real ObjC classes and can be
  hooked normally.
- On Android none of this applies. Java hooks work on the shared code.

## Tools and versions (checked 2026-10-14)

| Item | Version | Source |
|---|---|---|
| Kotlin | 2.4.21 (2026-10-08) | <https://github.com/JetBrains/kotlin/releases> |
| Compose Multiplatform | 1.12.1 (2026-09-22) | <https://github.com/JetBrains/compose-multiplatform/releases> |
| Ktor | 3.6.0 (2026-09-18) | <https://github.com/ktorio/ktor/releases> |
| jadx | 1.5.6 (2026-07-10) | <https://github.com/skylot/jadx/releases> |
| Ghidra / Hopper | for the iOS framework; demangle `kfun:` names by hand | n/a |

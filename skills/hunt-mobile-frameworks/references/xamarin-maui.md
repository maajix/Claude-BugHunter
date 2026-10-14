# Xamarin and .NET MAUI (.NET for Android and iOS)

The app's logic is managed .NET code in assemblies (`*.dll`). Up to and
including .NET 10, Android and iOS run it on Mono. Release builds add AOT
code but usually keep the IL, so a C# decompiler recovers near-source code.
That makes these apps easier to read than Flutter or IL2CPP, once you get
the assemblies out of their store format.

Xamarin and Xamarin.Forms support ended on 2024-05-01 (Microsoft migration
docs). Apps still on Xamarin are out of support, and that belongs in the
report as context, not as a finding.

## Detect

| Platform | Marker | Build era |
|---|---|---|
| Android | `assemblies/assemblies.blob` + `assemblies.manifest` (+ per-ABI `*_assemblies.<abi>.blob`) | Xamarin.Android 11+ and .NET 6-8, store v1 |
| Android | `lib/<abi>/libassemblies.<abi>.blob.so` (real ELF, `payload` section, header magic `XABA`) | .NET 9 (store v2) and .NET 10 GA (v3) |
| Android | `lib/<abi>/libassembly-store.so` | .NET 10 servicing from 36.1.12 (2026-01), v3 |
| Android | loose `assemblies/*.dll` | older Xamarin, or builds without the store |
| Android | `libmonosgen-2.0.so`, `libmonodroid.so`, `libxamarin-app.so`, `libaot-*.so` | Mono runtime, AOT code |
| Android | `assets/wwwroot/` | Blazor Hybrid (MAUI); path inferred from the asset provider code, verify |
| iOS | `*.dll` files in the `.app`, `Microsoft.iOS.dll` / `Xamarin.iOS.dll`, `Microsoft.Maui*.dll` | .NET for iOS / Xamarin.iOS |
| iOS | `<App>.app/wwwroot` | Blazor Hybrid |

Assemblies inside a store are often LZ4-compressed with an `XALZ` header
(magic `0x5A4C4158`), on by default since Xamarin.Android 11.0 (release-note
summary, verify). The `main`
branch for .NET 11 switches to Zstd (`XAZS`) and loads the store via
`dlopen` (dotnet/android `Documentation/project-docs/AssemblyStores.md`).

## Secrets and endpoints

1. **Unpack the store** with a tool that matches its version:

   | Store | Tool | Usage |
   |---|---|---|
   | v1 (`assemblies.blob`) | pyxamstore (last commit 2023-05; Python 3 support listed as a known limitation) | `apktool d app.apk` then `pyxamstore unpack -d app/unknown/assemblies/` |
   | v2 / v3 (`.blob.so`, `libassembly-store.so`) | XaBlob 1.2 (2026-08-28) | `xablob -l <elf>` list, `xablob -u <elf>` unpack |
   | v2 (.NET 9) | pymauistore | `python pymauistore.py libassemblies.arm64-v8a.blob.so out/` (v3 support not stated) |
   | v2 / v3 | maui-packer | `python3 maui_packer.py extract <blob.so> <out>` |
   | all, including XAZS | dotnet/android's own extractor (main branch) | from a dotnet/android checkout: `dotnet run --file .github/skills/extract-android-assemblies/scripts/extract-android-assemblies.cs -- --output <dir> <apk\|aab>` |

2. **Decompile** with ILSpy (`ilspycmd`) or dnSpyEx:

   ```bash
   dotnet tool install --global ilspycmd
   for d in out/*.dll; do ilspycmd -p -o "src/$(basename "$d" .dll)" "$d"; done
   grep -rhoE 'https?://[^"]+' src | sort -u
   ```

   Skip framework assemblies (`System.*`, `Microsoft.*`, `Xamarin.*`,
   `Mono.*`). The app is usually `<AppName>.dll` plus `<AppName>.Core.dll`
   or `.Shared.dll`.

3. **Look for** `appsettings*.json` as an embedded resource
   (`ilspycmd --list-resources`), `HttpClient` base addresses, Refit
   interfaces (`[Get("/...")]` attributes give the whole route map), MSAL /
   Entra `ClientId` and `Authority` values (`m365-entra-attack`),
   `Constants` classes, and Azure connection strings or SAS tokens
   (`cloud-iam-deep`).

4. **AOT and IL.** On Android, Release builds with Mono AOT use profiled AOT
   by default, and `AndroidStripILAfterAOT` defaults to false, so IL stays
   next to `libaot*.so`. On iOS, IL stripping (`EnableAssemblyILStripping`)
   turns on for Release device builds that use the Mono AOT compiler. Expect
   empty method bodies in a Store build. Strings, attributes and type
   metadata usually remain, and those carry the endpoints. Interpreter-enabled
   builds keep IL.

## Intercept

| Handler | Default? | Proxy | Trust |
|---|---|---|---|
| `AndroidMessageHandler` (Java `HttpURLConnection`) | yes on Android (`UseNativeHttpHandler=true`); `new HttpClientHandler()` wraps it | system proxy respected | Java / network security config |
| `NSUrlSessionHandler` | yes on iOS | system proxy | platform |
| `SocketsHttpHandler` (managed), only when set explicitly | no | Android: environment variables only, so the Wi-Fi proxy is **ignored**; iOS: system proxy | managed .NET TLS |

So most MAUI apps intercept like native apps (`apk-redteam-pipeline` Stage
8, `ios-redteam-pipeline` Stage 6). If traffic bypasses the proxy on Android,
look for `SocketsHttpHandler` or a third-party stack in the decompiled code,
and use a transparent or VPN redirect (SKILL.md Step 3).

## Pinning bypass

| Pin location | Bypass |
|---|---|
| `AndroidMessageHandler` with `TrustedCerts` or a `ServerCertificateCustomValidationCallback` | Java-level unpinning catches the platform path; the managed callback is .NET code, so patch it in the assembly or hook it via Mono |
| `HttpClientHandler.ServerCertificateCustomValidationCallback` | read the callback in ILSpy; patch it to return true in a copy of the assembly, repack, re-sign, run on your own device |
| `ServicePointManager.ServerCertificateValidationCallback` (older Mono) | GoSecure `frida-xamarin-unpin` targets this path (last push 2023-01; attach after launch: `frida -U -l dist/xamarin-unpin.js <pkg>`) |
| `network_security_config.xml` pin-set | `apk-redteam-pipeline` Stage 7 |
| iOS `NSUrlSessionHandler` trust callbacks | objection / `SecTrust` hooks, as for native apps |

Patch-and-repack (dnSpyEx edits the IL; XaBlob, maui-packer or pyxamstore
repack the store) gives a different app. It runs only on your test device.
maui-packer's workflow removes the AOT `.so` files so that the patched IL is
used.

## What breaks Frida and objection

- Java hooks see only the `AndroidMessageHandler` / Java boundary. Managed
  logic (token handling, request signing, feature gates) runs in Mono and
  is invisible to `Java.use`.
- Mono-aware Frida tooling is old or aimed at Unity Mono: fridax (last push
  2023-04, Frida 17 support not stated), GoSecure frida-xamarin-unpin (2023),
  and `frida-mono` 2.0 alpha (successor of frida-mono-api, 2026-10-13),
  whose CI covers Mono 4.8-6.12 and Unity, not the dotnet/runtime
  `libmonosgen-2.0` that .NET for Android uses (verify). In practice, reading
  the decompiled C# and patching the assembly is often faster.
- **.NET 11 moves Android and iOS to CoreCLR.** Microsoft's build-properties
  page shows `UseMonoRuntime` defaulting to false, with `true` rejected
  (NETSDK1242). A May 2026 devblog said Mono stays available through .NET 11
  servicing. .NET 11 is pre-release as of 2026-10-14, so verify against the
  build. Mono hooks do not apply to CoreCLR apps, and no CoreCLR or
  NativeAOT Frida tooling was found. On CoreCLR iOS, the default IL-stripping
  condition is not met, so IL likely stays (inferred from build logic,
  verify).

## Tools and versions (checked 2026-10-14)

| Tool | Version / state | Source |
|---|---|---|
| ILSpy / ilspycmd | v11.1 (2026-09-23) | <https://github.com/icsharpcode/ILSpy> |
| dnSpyEx | v6.6.0 (2026-06-20), active; original dnSpy archived (v6.1.8, 2020) | <https://github.com/dnSpyEx/dnSpy> |
| XaBlob | 1.2 (2026-08-28), store v2 and v3 | <https://github.com/Kirlif/XaBlob> |
| pyxamstore | store v1 only, last commit 2023-05 | <https://github.com/jakev/pyxamstore> |
| pymauistore | last push 2025-04, .NET 9 | <https://github.com/mwalkowski/pymauistore> |
| gomauistore | XALZ only | <https://github.com/kousha1999/gomauistore> |
| maui-packer | extract and repack | <https://github.com/svedm/maui-packer> |
| dotnet/android extractor | main branch, handles v1-v3, XALZ, XAZS | <https://github.com/dotnet/android> |
| frida-xamarin-unpin | last push 2023-01 | <https://github.com/GoSecure/frida-xamarin-unpin> |
| fridax | last push 2023-04 | <https://github.com/NorthwaveSecurity/fridax> |
| frida-mono (ex frida-mono-api) | 2.0 alpha (2026-10-13) | <https://github.com/freehuntx/frida-mono-api> |

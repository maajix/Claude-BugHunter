# Unity (IL2CPP and Mono)

Unity games and apps (retail, automotive configurators, AR, loyalty games)
compile C# either to .NET assemblies run by Mono, or through **IL2CPP** to
native code plus a metadata file. Either way the scripts name every backend
the client talks to.

**Scope:** cheats, memory editing, aimbots, speed hacks and anti-cheat bypass
are out of scope. In scope is the **server trusting the client**: scores,
currency, inventory, purchases, matchmaking and progression accepted
without server-side checks, and secrets that the client should never hold.

## Detect

| Platform | Marker | Backend |
|---|---|---|
| Android | `lib/<abi>/libil2cpp.so`, `libunity.so`, `libmain.so`, `assets/bin/Data/Managed/Metadata/global-metadata.dat`, `assets/bin/Data/globalgamemanagers` | IL2CPP |
| Android | `assets/bin/Data/Managed/Assembly-CSharp.dll` (+ other game DLLs) | Mono |
| iOS | `Frameworks/UnityFramework.framework/UnityFramework`, `<App>.app/Data/Managed/Metadata/global-metadata.dat` | IL2CPP (iOS requires AOT) |
| Both | `StreamingAssets/` (`assets/` on Android, `Data/Raw/` on iOS) | bundled config, Addressables catalogs (verify paths per version) |

Get the Unity version from `strings libunity.so` (or `UnityFramework`) or
from `globalgamemanagers`. It decides which dumper works, and whether the
build falls in the range of Unity's 2025 runtime advisory (below).

## Secrets and endpoints

**IL2CPP:** recover type and method names plus every C# string literal.

| Tool | Use | Limits |
|---|---|---|
| Il2CppDumper v6.7.46 (2024-07) | `Il2CppDumper.exe <libil2cpp.so> <global-metadata.dat> <out>` writes `dump.cs`, `script.json`, `stringliteral.json`, `il2cpp.h`, `DummyDll/` | metadata v16-31 only (README: Unity 5.3-2022.2); rejects newer Unity 6 metadata |
| Cpp2IL `2022.1.0-pre-release.21` (2026-02-22) | `Cpp2IL --game-path=<apk\|ipa\|dir> --output-as <fmt> --output-to <out>`; `--list-output-formats` lists formats | use the pre-release: the "latest" stable tag is from 2022; pre-release.21 adds metadata up to Unity 6000.5 alpha |
| Il2CppInspectorRedux 2026.2 (2026-06-07) | `-i <apk\|ipa\|binary> -m <global-metadata.dat>` | metadata up to v110 per README; the CLI section may describe the legacy build (verify) |
| frida-il2cpp-bridge v0.14.0 (2026-09-06) | runtime dump on your device: `npm exec frida-il2cpp-bridge -- -f <pkg> dump --out-dir dumps` | Frida 17 supported since v0.12.0; Unity 5.3.0-6000.3.x stated |

`stringliteral.json` (Il2CppDumper) or the Cpp2IL output is the inventory
source. Grep it for hosts, keys and service IDs, then route per
`bundle-to-backend.md`. If `global-metadata.dat` is encrypted or the header
is mangled (common in commercial games), dump at runtime with
frida-il2cpp-bridge on your own device rather than reversing the protection.

**Mono:** open `Assembly-CSharp.dll` (and the other non-Unity DLLs) in ILSpy
or dnSpyEx (`xamarin-maui.md` has versions). You get near-source C#.

**Unity-specific config:**

| Service | Client-side value | Public by design? | Secret that must not ship |
|---|---|---|---|
| PlayFab | Title ID | yes | **Developer Secret Key**: Microsoft says never include it in a client build; it allows Admin and Server API calls |
| Nakama (Heroic Labs) | `socket.server_key` (default `defaultkey`) | client key, used to create sessions | `runtime.http_key` (default `defaulthttpkey`), `session.encryption_key`; console defaults `admin` / `password` must be changed per Nakama's docs |
| Unity Gaming Services (Authentication, Cloud Save, Cloud Code, Economy) | project and environment IDs | yes (verify) | service-account keys |
| Photon | AppId | generally (verify) | |
| Firebase | `google-services.json` values | yes | see `hunt-cloud-backends` |

A PlayFab developer secret key, a non-default Nakama HTTP key, or a UGS
service-account key in the client is reportable on exposure. Validating any of
them is one read-only call at most, and only with Stage B sign-off. The
owning skill's rules apply (`offensive-osint` §23, `cloud-iam-deep` Stage A).
A Nakama server that still accepts **default** keys is a backend
misconfiguration. Trying the default HTTP key or console password counts as
using a credential: Stage B.

## Intercept

- `UnityWebRequest` applies the device's proxy settings and validates
  against the system root store (Unity 6 scripting reference). Whether user
  CAs count on Android is not documented (verify). Install your CA as a
  system CA (`apk-redteam-pipeline` Stage 8).
- Third-party HTTP plugins (Best HTTP and others) and custom socket code
  may use their own TLS and ignore the proxy (verify per plugin). Fall back to
  a transparent or VPN redirect (SKILL.md Step 3).
- Real-time game traffic (Photon, Nakama sockets, Netcode, custom UDP) is
  often not HTTP at all. Capture it to see message shapes; `hunt-websocket`
  covers WebSocket-based realtime.

## Pinning bypass

- **`CertificateHandler`** subclasses override `ValidateCertificate(byte[])`,
  which is called for the leaf certificate (Unity docs). On iOS this needs
  arbitrary loads enabled. Find the subclass in `dump.cs` and force it to
  return true. With IL2CPP, hook the method by address from the dump using
  frida-il2cpp-bridge on your test device. With Mono, patch the IL.
- **Platform or plugin pinning:** standard Android and iOS unpinning, or the
  plugin's own validation callback (`dump.cs` names it).

## What breaks Frida and objection

- IL2CPP game code is native code in `libil2cpp.so` / `UnityFramework`. Java
  and ObjC hooks see only the thin Unity player activity or app delegate.
- Use **frida-il2cpp-bridge**, which resolves classes and methods through the
  IL2CPP runtime API, or plain `Interceptor` on addresses from
  `script.json`.
- Mono builds need Mono-aware tooling (`frida-mono`, see
  `xamarin-maui.md`). Patching the DLL is usually simpler.

## Client-trust testing (the in-scope part)

Any submission (a score, a grant, a receipt, a progression update) is a
write. It is Stage B behind written sign-off: done on your own test account,
in a test or sandbox title or environment where the program offers one, and
kept off public leaderboards and economies that other players see. The
checks in the table below are static: they read the dump and the client
SDK calls, and send nothing.

Find in the dump what the client **tells** the server, and how the server
treats it:

| Client sends | Server should | Static check (dump and SDK calls) |
|---|---|---|
| final score, time, kills, distance | recompute or bound-check from game events | the client code sends the score with no session, replay or signature field |
| currency or item grants (`AddCurrency`, `GrantItem` called client-side) | grant only from server logic (Cloud Code, server API) | read the client SDK calls; client-callable grant APIs are the finding |
| IAP receipt (Google Play / App Store) | validate the receipt server-side with the store | is validation done in the client (Unity IAP local validation) with the server trusting the result? |
| progression, unlocks, entitlements | derive from server state | `bundle-to-backend.md` §3b (gated features) |
| matchmaking or lobby properties | validate server-side | `hunt-business-logic` |

Prefer the proof that reads: the client code that calls a grant API
directly. If the program wants a live demonstration, the Stage B sign-off
above names the endpoint, the test account and the single request.

## Unity runtime advisory (version gate only)

CVE-2025-59489 (NVD published 2025-10-03): Unity Runtime argument injection
that can load a library from an unintended location (CWE-88, CWE-426). It
affects Android, Windows, macOS and Linux builds from 2017.1.2p4. Fixes
shipped in 6000.3.0b4, 6000.2.6f2, 6000.0.58f2, 2022.3.67f2, 2021.3.56f2 and
backports down to 2019.1.15f1, or via Unity's binary patch tool. Unity
reports no exploitation (<https://unity.com/security/sept-2025-01>,
<https://nvd.nist.gov/vuln/detail/CVE-2025-59489>).

Record the Unity version and report "built with an affected Unity version,
not rebuilt or patched" as a version gate. The Android vector is an
exported-activity and intent issue, which is platform IPC owned by
`hunt-mobile-android`. Do not build or deliver anything that loads code into
another person's app.

## Tools and versions (checked 2026-10-14)

| Tool | Version / state | Source |
|---|---|---|
| Il2CppDumper | v6.7.46 (2024-07-06), last push 2024-08 | <https://github.com/Perfare/Il2CppDumper> |
| Cpp2IL | 2022.1.0-pre-release.21 (2026-02-22) | <https://github.com/SamboyCoding/Cpp2IL/releases> |
| Il2CppInspectorRedux | 2026.2 (2026-06-07) | <https://github.com/LukeFZ/Il2CppInspectorRedux> |
| frida-il2cpp-bridge | v0.14.0 (2026-09-06) | <https://github.com/vfsfitvnm/frida-il2cpp-bridge> |
| Frida | 17.23.3 (2026-10-09) | <https://github.com/frida/frida/releases> |

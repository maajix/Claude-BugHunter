# Tooling: versions, jailbreak matrix, signing limits

Versions below were read from each project's GitHub "latest release" on
2026-10-14 unless marked otherwise. Re-check before an engagement; Frida
alone shipped ten releases between 2026-09-25 and 2026-10-09. Install
commands for the core set are in `ios-redteam-pipeline` ("Tooling install").

---

## 1. Version table

| Tool | Latest | Date | Note |
|---|---|---|---|
| Frida (`frida`, `frida-tools`, `frida-server`) | 17.23.3 | 2026-10-09 | Host tools and on-device server must match |
| objection | 1.12.5 | 2026-06-02 | `objection -n <bundle> start`; `--gadget/-g` and `explore` deprecated |
| ipsw (blacktop) | v3.1.737 | 2026-10-12 | `macho info --ent`, `class-dump`, `swift-dump`, `macho search --import` |
| pymobiledevice3 | v11.29.1 | 2026-10-14 | syslog, crash, pcap, backup2, afc, profiles, iOS 17+ tunnels |
| libimobiledevice | 1.4.0 | 2025-10-10 | `idevicesyslog`, `ideviceinstaller`, `idevicebackup2` |
| ipatool | v2.7.0 | 2026-10-09 | App Store IPA download (pipeline Stage 1) |
| bagbak | v5.1.2 | 2026-04-14 | FairPlay decryption on a jailbroken device |
| frida-ios-dump | no releases | last push 2023-05 | Older decryption script; prefer bagbak |
| MobSF | v4.5.3 | 2026-09-21 | Static IPA analysis; iOS dynamic analysis uses Corellium (verify) |
| Ghidra | 12.1.4 | 2026-09-21 | Swift demangling quality varies by version (verify) |
| Hopper | not on GitHub | n/a | Commercial; check the vendor site for the current major version (verify) |
| Grapefruit | v1.1.2 | 2026-03-30 | Frida-based iOS runtime GUI |
| mitmproxy | v12.2.3 | 2026-05-12 | `--mode wireguard` for proxy-unaware apps |
| SSL Kill Switch 3 | v1.4 | 2023-11-10 | Rootful and rootless builds; unmaintained since, test per iOS |
| class-dump (nygard) | 3.4 | 2013-10-04 | Old; misses Swift and modern ObjC metadata. Use `ipsw class-dump` |
| dsdump | archived | 2024-02 | Do not plan around it; use `ipsw class-dump` / `swift-dump` |
| palera1n | v2.4 | 2026-07-27 | See section 3 |
| Dopamine | 3.0.11 | 2026-10-12 | See section 3 |
| TrollStore | 2.1.1 | 2026-04-01 | See section 4 |

---

## 2. Frida 16 versus 17, and iOS specifics

- **Frida 17 (May 2025)** removed the ObjC, Swift and Java bridges from GumJS.
  The `frida` REPL and `frida-trace` still bundle them; a custom agent built
  with `frida-compile` must install `frida-objc-bridge` / `frida-swift-bridge`
  (npm or `frida-pm install`). Frida 16 scripts that use `ObjC.classes` keep
  working in the REPL; compiled agents break until the bridge is imported.
- **objection** supports Frida 17 from 1.12.0; use 1.12.5.
- **Without a jailbreak** Frida instruments debuggable apps and injects Gadget
  automatically (since Frida 12.7.12). Needs the developer disk image mounted
  and the Gadget in Frida's cache directory (Frida iOS docs). "Debuggable"
  means `get-task-allow`, which in practice means a developer-signed build.
- **iOS 17+ developer services** run over CoreDevice/RemoteXPC tunnels. Recent
  Frida handles the tunnel itself (its 17.19.0 notes mention RSD discovery and
  a `force_transport=usbmux` option). pymobiledevice3 brings up a userspace
  tunnel automatically; on Linux and Windows, iOS 17.0 to 17.3.1 still needs
  `sudo python3 -m pymobiledevice3 remote tunneld`.
- **Dopamine on iOS 26+**: Dopamine 3.0.10 exposes a memory-hook API to Frida
  that avoids panics; it requires Frida 17.19.0 or newer.

Patch a decrypted IPA with Gadget for a stock device (flags from objection
1.12.5 source):

```bash
objection patchipa --source app-decrypted.ipa \
  --codesign-signature <signing-identity-SHA1> \
  --provision-file dev.mobileprovision \
  --bundle-id <bundle-id-allowed-by-the-profile>
# -V picks a Gadget version, -b names the binary, -C/-l embed a Gadget config or script
```

The result carries your Team ID, so entitlement-bound features break (see
SKILL.md Step 0).

---

## 3. Jailbreak status by iOS version

| Tool | Basis | Devices | iOS / iPadOS | Notes |
|---|---|---|---|---|
| palera1n v2.4 | checkm8 bootrom exploit (unpatchable in hardware) | A8 to A11, Apple T2 | 15.0 and later on those devices | iPhones in range top out at iOS 16 (iPhone 8/X); iPad 7th gen reaches iPadOS 18 (verify). A11: passcode must be disabled while jailbroken, and on iOS 16 the device must not have had a passcode set since restore (verify) |
| Dopamine 3.0.x | Kernel exploits plus PPL/SPTM bypasses | A8 to A13 | 15.0 to 18.7.1, and 26.0 to 26.0.1 (A12/A13) | Official site matrix. Use 3.0.7 or later (3.0 to 3.0.6 could corrupt a file during updates, per release notes) |
| Dopamine 3.0.x | same | A14 to A17, M1 to M2 | 15.0 to 17.3.1 | No SPTM bypass for 17.4+ on real hardware (3.0 release notes) |
| none public | n/a | A14 and later | 17.4 and later | Use a developer-signed build or Corellium (verify before buying devices) |
| none public | n/a | any | 26.0.2 and later, all of iOS 27 | iOS 27 released 2026-09-14 (verify). Dopamine 3.0 mentions SPTM support "up to 27.0 betas" only on Corellium |

Practical consequences:

- iOS 26 supports only newer iPhones (iPhone 11 / A13 and later, verify), so
  the only jailbreakable iOS 26 iPhones are A13 models on 26.0 to 26.0.1.
- Memory Integrity Enforcement on A19-class hardware (iPhone 17 family, iOS
  26) raises the cost of kernel exploits; expect no public jailbreak there
  (verify).
- Keep a pool of devices frozen on jailbreakable versions; never let them
  update. Match the pool to the target's `MinimumOSVersion`; an app requiring
  iOS 18 cannot be tested on an iOS 16 checkm8 device.

---

## 4. TrollStore and sideloading

**TrollStore 2.1.1** installs apps permanently signed with arbitrary
entitlements through CoreTrust bugs. Supported: iOS 14.0 beta 2 to 16.6.1,
16.7 RC (20H18) and 17.0. Its README states 16.7.x (except the RC) and 17.0.1+
will never be supported. Useful on a test device for installing a decrypted
IPA with `get-task-allow` (verify per build). Not a jailbreak; no tweak
injection by itself.

**Developer signing limits:**

| Account | Limits |
|---|---|
| Free Apple Account | Profiles valid 7 days; about 3 sideloaded apps active at once; about 10 App IDs per 7 days; 3 device UDIDs per 7 days (third-party sources, verify) |
| Paid Apple Developer Program | Profiles valid up to a year; device registration capped per device family per membership year (verify the current cap) |

- iOS 16 and later require **Developer Mode** (Settings, Privacy & Security,
  Developer Mode) to run developer-signed apps; `pymobiledevice3 amfi
  enable-developer-mode` toggles it from the host (verify per iOS version).
- Sideloadly and similar tools sign with your Apple Account; current support
  for iOS 26 and 27 is on the tool's site (verify).
- Re-signing with any non-client identity changes the Team ID; associated
  domains, Keychain groups, App Groups, iCloud and push stop matching.
- App Store IPAs must be FairPlay-decrypted first, which needs a jailbroken
  device at least once (pipeline "Decrypting").

---

## 5. Corellium

Virtual iPhones on Arm servers, jailbroken or not, with snapshots and built-in
network and file views. Corellium's own material states support for jailbroken
iOS 18 and announced iOS 26 and iPhone 17 support in November 2025; whether
iOS 26 or 27 images are offered jailbroken is not confirmed here (verify on the
account). Cellebrite acquired Corellium (reported December 2025, verify). Apps
can detect virtual devices (MASTG-TEST-0367), and some Apple services may be
limited on virtual devices (verify per feature you need: push, iCloud, Apple
Pay, Face ID simulation).

---

## 6. Device-side helpers (pymobiledevice3, verified in its CLI recipes)

```bash
pymobiledevice3 usbmux list
pymobiledevice3 apps list
pymobiledevice3 syslog live -m <ProcessName>
pymobiledevice3 crash pull ./crashes
pymobiledevice3 pcap --out capture.pcap
pymobiledevice3 backup2 encryption on '<password>'
pymobiledevice3 backup2 backup --full ./bk
pymobiledevice3 backup2 unback ./bk --password '<password>'
pymobiledevice3 profile list
pymobiledevice3 mounter auto-mount                 # developer disk image
pymobiledevice3 developer dvt screenshot ./screen.png
```

`profile install` exists too; use it only for your own CA on your own test
device, and remove it after the engagement.

---

## 7. Static analysis quick reference

```bash
ipsw macho info <AppBinary> --ent                 # entitlements
ipsw macho search <AppBinary> --import 'CCCrypt'  # imported symbol lookup
ipsw class-dump <AppBinary> --headers --output ./headers
ipsw swift-dump <AppBinary> --demangle
otool -l <AppBinary> | grep -A4 LC_ENCRYPTION_INFO   # cryptid 1 = still FairPlay-encrypted
otool -L <AppBinary>                              # linked frameworks
```

Ghidra and Hopper for code you need to read; MobSF for a quick automated pass
that you then verify by hand (its findings map loosely to MASVS; do not file
them unverified).

# Tooling: versions, flags and device setup

Versions checked October 2026 (GitHub releases / PyPI / Docker Hub). Acquisition
and decompilation themselves are owned by `apk-redteam-pipeline`; this file
records current versions, the flags that changed, and the device/CA setup that
Android 14-17 forces. Do all of it on your own test device or emulator.

## 1. Versions

| Tool | Version | Date | Note |
|---|---|---|---|
| jadx | 1.5.6 | 2026-07-10 | Java 11+ |
| apktool | 3.0.3 | 2026-07-20 | CLI reworked in 3.0.0 (below) |
| Frida | 17.23.3 | 2026-10-09 | no Frida 18 exists; bridges unbundled since 17.0 |
| frida-tools | 14.11.0 | 2026-10-03 | REPL and frida-trace still bundle the bridges |
| objection | 1.12.5 | 2026-06-02 | Frida 17 support since 1.12.0; use >=1.12.5 |
| MobSF | 4.5.3 | 2026-09-21 | `opensecurity/mobile-security-framework-mobsf:latest` |
| drozer / drozer-agent | 3.1.0 | 2024-08-01 | unmaintained since; still works |
| apk-mitm | 1.3.0 | 2024-04-21 | unmaintained; bundles apktool 2.9.3 |
| Magisk | 30.7 | 2026-02-23 | rooting |
| KernelSU / KernelSU-Next | 3.3.1 / 3.4.2 | 2026-10 | alternative root |
| APatch | 11224 | 2026-08-07 | alternative root |
| rootAVD | unversioned | last commit 2024-10-04 | emulator rooting; README defaults to API<=34, community-tested to API 35 (verify) |

## 2. Frida 16 to 17 (what breaks a copied script)

- **Bridges unbundled.** A standalone agent must `import Java from
  "frida-java-bridge"` and build with `frida-compile`, or install it with
  `frida-pm install frida-java-bridge` (frida-tools >=14.2). `frida -l x.js`
  and `frida-trace` still bundle the bridges, so a one-off script runs
  unchanged.
- **Static `Module` methods removed.** `Module.findExportByName(null, "open")`
  becomes `Module.getGlobalExportByName("open")` or
  `Process.getModuleByName("libc.so").getExportByName("open")`. The copy-paste
  pinning scripts that still call the old API fail on 17.
- **`Memory.readU32`/`writeU32` and the `onMatch`/`onComplete` enumeration
  callbacks are removed.** Use `ptr.readU32()` and the array-returning
  enumerators.
- **Android 15/16 stability.** 17.1.4 added Android 16 support; 17.6.0 stopped
  using ptrace on zygote. Open crash reports exist on some Pixel/Android 16 and
  OEM Android 15 builds (attach SIGSEGV, "Unable to locate Android dynamic
  linker") (verify against the installed version). If `frida-ps -U` crashes the
  app, try a different 17.x point release before blaming your script.

## 3. frida-server vs gadget; objection

```bash
# Rooted device / Google APIs emulator: match frida-server to the host frida-tools
adb root 2>/dev/null                       # userdebug/eng only; production needs su
adb push frida-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida-server
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U | head

# No root: inject the gadget by repackaging (objection wraps apktool + sign)
objection patchapk -s app.apk             # add -2 ONLY with apktool 2.x; 3.x removed --use-aapt2
```

objection 1.12.5 invocation changed: `objection -n <pkg> start`. The old
`objection -g <pkg> explore` still works as a hidden deprecated alias. Useful
REPL commands for this skill:

```
android sslpinning disable
android root disable            # or: android root simulate
android keystore list
android hooking list activities        # services / receivers / classes
android hooking watch class_method <Class>.<method> --dump-args --dump-return
android intent launch_activity <Class>
android clipboard monitor
android ui FLAG_SECURE
```

Note (verify, from reading the code, not tested): objection and apk-mitm still
call apktool with flags 3.x removed (`--use-aapt2`, `--only-main-classes`). On
an apktool 3.x host, pin apktool 2.9.x for patching or expect the aapt2 step to
fall back.

## 4. apktool 3.x and jadx flags

- apktool decode: `apktool d -f -o out app.apk` (`-r` no-res, `-s` no-src,
  `-a`/`--all-src` to decompile every dex). Build: `apktool b out -o new.apk`
  (`--debuggable`, `--net-sec-conf`). Removed in 3.0: `--only-main-classes`
  (now default), `-api/--api-level`, aapt1. Short flags like `-d` (now
  `--debuggable`) were dropped; `empty-framework-dir` is now `clean-frameworks`.
- jadx: `jadx -d out app.apk` with `--deobf`, `--show-bad-code`,
  `-e/--export-gradle`, `-r/--no-res`. `-f` is now `--fallback`.

## 5. Android emulator images and a writable system

| Image | Build | `adb root` | Play Store |
|---|---|---|---|
| Google Play | user / release-keys | no (root via rootAVD) | yes |
| Google APIs | userdebug | yes | no (Play services only) |
| AOSP | eng | yes | no |

Pick a **Google APIs** image for testing: it gives `adb root` without
repackaging, and most Play Integrity-gated apps will not run on it anyway. Use
a **Google Play** image (plus rootAVD) only when the app needs Play services and
you accept the extra rooting step.

```bash
emulator -avd Pixel_API_35 -writable-system      # must be set to write /system
adb root && adb remount
# API 29+: if remount refuses, disable verity first, then reboot and retry
adb shell avbctl disable-verification && adb reboot
```

On API 34+ a writable `/system` no longer changes trust: the CA store moved to
the Conscrypt APEX (§6).

## 6. Burp / mitmproxy CA on Android 14, 15, 16

The system trust store is `/apex/com.android.conscrypt/cacerts`, read-only with
private mount propagation, inherited from zygote. Dropping a cert in
`/system/etc/security/cacerts` is ignored. Two working routes:

1. **Magisk/KernelSU module** (easiest on a real device). Maintained options:
   `NVISOsecurity/AlwaysTrustUserCerts` (claims Android 7-16, updated 2025) and
   `pwnlogs/cert-fixer` (tested to Android 15). `nccgroup/ConscryptTrustUserCerts`
   is effectively unmaintained (2023). Install the Burp CA as a **user** cert
   first (Settings > Security > Encryption & credentials > Install a certificate
   > CA certificate), then the module copies user CAs into the APEX store.
2. **tmpfs + bind-mount into each namespace** (HTTP Toolkit's method, survives
   until reboot): mount a tmpfs over `/system/etc/security/cacerts`, populate it
   with the existing certs plus yours (correct `chown`/`chmod`/`chcon
   u:object_r:system_file:s0`), then bind-mount it into the mount namespace of
   `zygote`, `zygote64` and each running app PID with
   `nsenter --mount=/proc/<pid>/ns/mnt -- mount --bind ...`.

Prepare the cert file the store expects (name = subject hash, extension `.0`):

```bash
# Burp: Proxy settings > Import/export CA certificate > "Certificate in DER format"
openssl x509 -inform DER -subject_hash_old -in burp.der | head -1     # prints HASH
cp burp.der "$HASH.0" && chmod 644 "$HASH.0"
```

No source reports Android 16 breaking these methods (verify); retest the module
on the exact build. Installing a user CA and relying on a repackaged,
pinning-free debug build (`objection patchapk`, apk-mitm) avoids the system
store entirely for apps that trust user CAs via a debuggable Network Security
Config.

## 6b. Rooting a test device

- **Dedicated device only.** Unlocking the bootloader factory-resets the device,
  so never root one that holds real accounts or data. A rooted device also loses
  the Play Integrity DEVICE/STRONG verdict (`resilience.md` §5).
- **Magisk** (v30.7) is the mainstream path: extract `boot.img` (or `init_boot`
  on devices that launched with Android 13+ (verify)) from the factory image,
  patch it in the Magisk app, and `fastboot flash boot patched.img` /
  `fastboot flash init_boot patched.img`. Flash with fastboot, never `dd` to a
  block device.
- **KernelSU / KernelSU-Next** and **APatch** are kernel-based alternatives for
  devices with a compatible kernel source.
- **Emulators:** `rootAVD` patches an AVD's `ramdisk.img` with Magisk (stale,
  community-tested to API 35 (verify)); a Google APIs image already gives
  `adb root` without it (§5).
- For pinning or detection bypass you often do **not** need root: inject the
  Frida gadget by repackaging (`objection patchapk`, §3).

## 7. MASTG techniques and tools (OWASP references)

| Task | OWASP ID |
|---|---|
| Obtain / extract / repackage the app | MASTG-TECH-0003, -0004, -0039, -0145 (XAPK) |
| Interception proxy + installing a CA | MASTG-TECH-0011 (its "Installing a CA Certificate" section), generic -0120 |
| Bypass certificate pinning | MASTG-TECH-0012; tool MASTG-TOOL-0140 (frida-multiple-unpinning) |
| Frida on Android | MASTG-TOOL-0001; method hooking MASTG-TECH-0043; non-rooted MASTG-TECH-0026 |
| Analyse Network Security Config | MASTG-TECH-0151 |
| Bypass root detection | MASTG-TECH-0144 |
| Inspect / perform a backup | MASTG-TECH-0127, -0128 |
| List and verify deep/app links | MASTG-TECH-0172, -0174 |

## 8. MobSF and drozer quick start

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest  # login mobsf/mobsf
# drozer (agent app installed on the test device, listening on 31415):
adb forward tcp:31415 tcp:31415 && drozer console connect      # USB
# drozer console connect --server <device-ip>                   # network
```

drozer 3.1 changed the intent-extras syntax; check `help intents` in the
console rather than copying 2.x `--extra` examples.

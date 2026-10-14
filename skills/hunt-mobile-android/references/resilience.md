# Resilience against reverse engineering (MASVS-RESILIENCE)

Resilience controls raise the cost of analysis. On almost every bug-bounty
program their absence is **not a finding**: Bugcrowd VRT puts all four
Lack of Binary Hardening children at P5, HackerOne's Core Ineligible Findings
list names "Lack of jailbreak detection in mobile apps" and "Lack of SSL
Pinning", and Google's Mobile VRP excludes "Attacks that require a rooted
device". Treat this file as "how to get past the control so the real testing
can happen", plus the narrow cases where the control itself is the bug.

Bypass only on your own device, against your own install. Never ship a
patched APK to anyone, never upload it to a store or a file share, and delete
it when the engagement ends.

## 1. What each control is, and its MASTG test

| Control | What it does | MASTG-TEST (Android) |
|---|---|---|
| Root detection | refuses to run on a rooted device (RootBeer, Play Integrity verdict, su/Magisk path checks) | 0324 (refs), 0325 (runtime) |
| Anti-debugging | detects a debugger (`Debug.isDebuggerConnected`, `ptrace`, TracerPid) | 0352, 0353 |
| Hook/Frida detection | scans for frida-server port 27042, `frida-agent` in `/proc/self/maps`, `gum-js-loop` threads/pipes | 0341 |
| Emulator detection | checks `Build` props, QEMU artifacts, sensors | 0351 |
| Integrity / signature | verifies the APK signature / file hashes at runtime | 0338, 0224/0225 (signature scheme) |
| Obfuscation | R8/DexGuard name and control-flow obfuscation | 0368 (Java/Kotlin), 0369 (native) |
| Debuggable flag | `android:debuggable` must be false in release | 0226; native symbols 0288 |

## 2. How programs grade these (read before writing anything up)

All four Lack of Binary Hardening children are **P5 in Bugcrowd VRT** (Lack of
Jailbreak Detection, Lack of Obfuscation, Runtime Instrumentation-Based, Lack
of Exploit Mitigations). HackerOne's Core Ineligible Findings page lists "Lack
of jailbreak detection in mobile apps". Google's Mobile VRP excludes "Attacks
that require a rooted device". Public policies (Grab, Temu, YesWeHack,
Intigriti template) uniformly exclude missing pinning, root/jailbreak
detection, obfuscation and anti-debugging, and "exploits only possible in a
jailbroken/rooted environment".

So:

- **Missing or bypassable resilience is not a finding by itself.** Do not file
  "no root detection" or "no obfuscation".
- It is the **means** that let you test. Record "root detection bypassed with X
  to enable analysis" in the methodology, not as a vulnerability.
- The two narrow exceptions, both rare: the program's scope explicitly asks for
  a MASVS-RESILIENCE / L2 assessment, or the detection is the only thing
  protecting a feature the backend should protect (a client-side "device is
  safe" boolean the server trusts, which is really a server trust bug, graded
  there).

## 3. Debuggable is the one that is actually a finding

`android:debuggable="true"` in a release build is different: it lets anyone
`run-as` the sandbox, attach a debugger, and `adb backup` the app data without
root. MASTG-TEST-0226.

```bash
adb shell dumpsys package "$PKG" | grep -i 'flags=.*DEBUGGABLE'
# or statically:
grep -o 'android:debuggable="[^"]*"' decoded/AndroidManifest.xml
```

Severity: still modest alone (needs device access), but it widens every
storage and IPC test and some programs accept it as a misconfiguration. Pair it
with whatever sandbox data it exposes.

## 4. Getting past a control to continue the real test

Your own device, your own install, nothing distributed.

- Root/Frida/debugger detection: `objection -n "$PKG" start` then `android
  root disable`; hook or stub the detection method (`android hooking watch
  class_method`); or a Magisk DenyList / Shamiko / Play Integrity Fix module
  for a device that checks the integrity verdict (MASTG-TECH-0144).
- Emulator detection: use a real device, or a Google APIs image that carries
  fewer emulator tells, and stub the detector if it still fires.
- Anti-tamper/signature check: it fires after `objection patchapk` changed the
  signature. Hook the signature-check method, or run the gadget via Frida
  injection without repackaging (frida-server on a rooted device leaves the
  APK unmodified).

## 5. Play Integrity and SafetyNet (why a rooted test may not log in)

- **SafetyNet Attestation was fully turned down in January 2025**; calls now
  fail. Apps still on it are effectively unprotected on that axis, but that is
  not a finding you report.
- **Play Integrity** replaced it. On Android 13+, `MEETS_STRONG_INTEGRITY`
  needs hardware-backed signals and a recent security patch; a rooted phone or
  emulator gets at most `MEETS_BASIC_INTEGRITY`, and often nothing. An app that
  hard-gates login on the strong verdict will not run on your rooted test
  device.

Treat the integrity check as its own surface before blaming your hooks: a
real test device with a stock image is the reliable way through; a Play
Integrity Fix module on a rooted device can only reach `MEETS_BASIC_INTEGRITY`
(since May 2025 the DEVICE and STRONG verdicts need hardware-backed verified
boot, which a rooted or emulated device cannot provide). If the app trusts the
integrity verdict **client-side** to unlock a feature (rather than having the
server verify the token server-side), that client-side trust is the finding,
graded where the server should have checked.

## 6. Obfuscation grading

R8 (the default shrinker) renames; DexGuard/commercial tools add string
encryption and control-flow flattening. "Not obfuscated" is VRT Lack of
Obfuscation (P5) and ineligible on essentially every program. Obfuscation only
matters to you as an analysis cost: a live secret recovered from an obfuscated
build is still a finding; the obfuscation is not.

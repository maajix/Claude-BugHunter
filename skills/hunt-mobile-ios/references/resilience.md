# Resilience: MASVS-RESILIENCE-1 to -4

Scope boundary: the bypass scripts themselves (Frida templates, pinning
bypass) are in `ios-redteam-pipeline`. This file covers what each control
looks like, how to get past it so you can test the rest of the app, and, first,
how programs grade it.

MASTG IDs from OWASP/mastg `master` (fetched 2026-10-14). Everything here is
Stage A on your own device, except section 5's server checks where a request
writes.

---

## 0. Grade first

| Source | What it says |
|---|---|
| Bugcrowd VRT v1.19.1 | `Lack of Binary Hardening > Lack of Exploit Mitigations`, `> Lack of Jailbreak Detection`, `> Lack of Obfuscation`, `> Runtime Instrumentation-Based`: all P5 |
| HackerOne core ineligible findings | "Lack of jailbreak detection in mobile apps" and "Lack of SSL Pinning" under optional hardening; "Attacks requiring physical access to a device (unless explicitly in scope)" |
| Typical program briefs | Often exclude "runtime manipulation" or attacks needing a jailbroken or instrumented device by name. Read the brief |
| MASVS | RESILIENCE controls apply to apps whose threat model includes tampering and reverse engineering (banking, DRM, games with economies); for other apps a missing control is not a MASVS failure |

So: on a bounty, a resilience bypass is a **means**, mentioned inside the
report of the server-side bug it unlocked. On a pentest that scoped
MASVS-RESILIENCE, report one grouped hardening observation listing each
control, how long the bypass took and with what tool. Two items deserve a line
of their own: section 4's production `get-task-allow`, and section 5's
server that does not enforce App Attest.

---

## 1. Jailbreak detection (RESILIENCE-1; MASTG-TEST-0240, 0241)

| Technique | What it checks |
|---|---|
| File and directory probes | `/Applications/Cydia.app`, `/Applications/Sileo.app`, `/var/jb` (rootless prefix), `/var/lib/apt`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt` |
| Sandbox write test | Writing outside the container succeeds only when the sandbox is broken |
| `fork()` / `posix_spawn` availability | Sandboxed apps cannot fork |
| URL-scheme probes | `canOpenURL` for `cydia://`, `sileo://`, `zbra://` (needs `LSApplicationQueriesSchemes` entries, which is itself a tell) |
| Loaded images | `_dyld_image_count` / `_dyld_get_image_name` for substrate, libhooker, ellekit, frida, tweak dylibs |
| Environment | `DYLD_INSERT_LIBRARIES`, code-signing flags via `csops` |
| Direct syscalls (`svc 0x80`) | Evade libc hooks; harder to bypass |
| Third-party SDK verdict | RASP products report to their own backend |

```bash
grep -aE '/var/jb|Cydia|Sileo|zbra://|cydia://|MobileSubstrate|ellekit|frida|DYLD_INSERT' strings_target.txt | sort -u
objection -n <bundle_id> start
#   ios jailbreak disable       -> hooks common checks
#   ios jailbreak simulate      -> the opposite: make a stock device look jailbroken (tests the app's reaction)
```

Other routes: Dopamine has a per-app "Hide Jailbreak" option (its own release
notes say use at your own risk); per-app tweak-injection disablers exist for
rootless jailbreaks (verify current tools); a re-signed build with Frida Gadget
on a stock device avoids most jailbreak artefacts entirely; Corellium devices
can be run non-jailbroken.

Grade: `Lack of Binary Hardening > Lack of Jailbreak Detection` (P5) when
absent; a bypass is not a separate finding (section 0).

Evidence: which checks fired (hook the decision function and log it), how the
app reacts (exit, warning, reduced features, silent server report), bypass
method and time.

---

## 2. Frida and hook detection (RESILIENCE-4; MASTG-TEST-0354)

| Technique | Bypass direction |
|---|---|
| TCP connect to `27042` (default frida-server port) | Run frida-server on another port (`-l 0.0.0.0:<port>`, verify flag) and connect with `-H` |
| Process or file names (`frida-server`, `/usr/lib/frida`) | Renamed builds; Gadget instead of server |
| Thread names (`gum-js-loop`, `gmain`) | Hook the enumeration |
| Loaded-image names (`FridaGadget`, `frida-agent`) | Rename the Gadget dylib when patching (`objection patchipa` uses `FridaGadget.dylib`, rename manually, verify) |
| Inline-hook detection (prologue checksums on `open`, `stat`, `objc_msgSend`) | Hook later, or hook the checker; Stalker-based tracing instead of Interceptor |

Deprecated MASTG-TEST-0091 (reverse-engineering tool detection) is the v1 test.

Grade: `Lack of Binary Hardening > Runtime Instrumentation-Based` (P5).
Evidence: which checks fired and the bypass used, as in section 1.

---

## 3. Debugger detection (RESILIENCE-4; MASTG-TEST-0401, 0402)

| Technique | Notes |
|---|---|
| `ptrace(PT_DENY_ATTACH)` | Classic; hook `ptrace` or patch the call |
| `sysctl` with `KERN_PROC_PID`, test `P_TRACED` | Hook `sysctl` and clear the flag |
| `getppid() != 1`, `isatty`, exception ports | Hook individually |

Deprecated MASTG-TEST-0089 (anti-debugging detection) is the v1 test.

Grade: `Lack of Binary Hardening > Runtime Instrumentation-Based` (P5).
Evidence: which checks fired and the bypass used, as in section 1.

---

## 4. Debuggable entitlement and code signature (RESILIENCE-2; MASTG-TEST-0261, 0220)

```bash
ipsw macho info Payload/<App>.app/<AppBinary> --ent | grep -A1 get-task-allow
codesign -dvvv Payload/<App>.app 2>&1 | grep -E 'CodeDirectory v=|TeamIdentifier|Signature'
```

- `get-task-allow` true in an App Store or production enterprise build means
  any debugger (and Frida without a jailbreak, on a device with the developer
  image mounted) can attach to the shipped app. MASTG-TEST-0261. This is a
  real build misconfiguration; grade P5 on VRT but worth a line on its own.
- MASTG-TEST-0220 flags an outdated code-signature format.
- Evidence: the `--ent` output and the build's channel, version and build
  number (App Store, TestFlight or enterprise).
- Deprecated MASTG-TEST-0081 (proper signing) and 0082 (debuggable) are the
  v1 tests.

---

## 5. Anti-tampering and app integrity (RESILIENCE-2; MASTG-TEST-0387)

Client-side checks:

| Check | Tell |
|---|---|
| `embedded.mobileprovision` present (App Store builds have none) | File read at launch |
| Team ID or bundle ID compared with a constant | Strings of the team ID |
| Hash of the binary or resources | MASTG-TEST-0387 covers storage integrity APIs; deprecated 0090 covers file integrity |
| `LC_ENCRYPTION_INFO` `cryptid` checked (decrypted binary means tampering) | `otool -l` in the app's own logic |

Server-side attestation: **App Attest** (`DCAppAttestService`) and
**DeviceCheck**. Look for the `com.apple.developer.devicecheck.appattest-environment`
entitlement and `DCAppAttestService` in strings. The interesting question is
whether the server enforces it:

1. Capture a request that carries an assertion header or body field.
2. Replay a **read-only** request without the assertion (Stage A).
3. If it succeeds and the program's brief claims bot or fraud protection on
   that endpoint, test the write path once, as Stage B with written sign-off:

```
# Stage B: written sign-off required. One request, own account, the endpoint the brief says is protected.
# Replay the protected action (signup bonus, promo redemption, vote) with the assertion removed.
```

Evidence: the request with and without the assertion and both responses, and
the sign-off reference for the write.

Grade: by business impact (fraud, promotion abuse) via `hunt-business-logic`;
the missing enforcement alone is informational to P5.

---

## 6. Symbols and obfuscation (RESILIENCE-3; MASTG-TEST-0219, 0391)

What stripping cannot remove:

- Objective-C class, method and selector names in the `__objc_*` sections; the
  runtime needs them.
- Swift type metadata, field names (`__swift5_reflstr`) and type references
  (`__swift5_typeref`) unless reflection metadata is disabled at build time
  (verify the build-setting name for current Swift).

```bash
ipsw class-dump Payload/<App>.app/<AppBinary> --headers --output ./headers     # ObjC
ipsw swift-dump Payload/<App>.app/<AppBinary> --demangle                      # Swift (marked work-in-progress by ipsw)
nm -U Payload/<App>.app/<AppBinary> | wc -l                                    # local symbols left in = not stripped
```

Debug symbols present: MASTG-TEST-0219 (deprecated 0083). Weak obfuscation of
security-relevant native code: MASTG-TEST-0391 (deprecated 0093). Commercial
obfuscators add control-flow flattening and string encryption; open-source
Swift renamers exist but several are archived (verify before recommending one).

Evidence: symbol counts and an excerpt of security-relevant names from the
`ipsw` output.

Grade: `Lack of Binary Hardening > Lack of Obfuscation` (P5). Useful
instead as a lead: unstripped symbols name the security functions you will
hook in sections 1 to 3.

---

## 7. Exploit mitigations (CODE; MASTG-TEST-0228, 0229, 0230)

```bash
otool -hv Payload/<App>.app/<AppBinary> | grep -o PIE              # position-independent executable
otool -Iv Payload/<App>.app/<AppBinary> | grep -E '___stack_chk_(fail|guard)'   # stack canaries
otool -Iv Payload/<App>.app/<AppBinary> | grep -E '_objc_(release|retain|autorelease)'  # ARC
```

Modern Xcode toolchains enable all three by default, so a miss usually points
at an old embedded static library. Evidence: the `otool` lines. Grade: `Lack of Binary Hardening > Lack of
Exploit Mitigations` (P5).

---

## 8. Virtual-device and screen-lock checks (MASTG-TEST-0367, 0246, 0248)

- Virtual-device detection (0367) targets Corellium: model identifiers,
  missing hardware features, Corellium-specific files. If the app refuses to
  run, use a physical device or the Corellium-side mitigations their docs
  describe.
- Secure-screen-lock detection (0246, 0248): the app checks that a passcode is
  set (`LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`) and refuses
  to store secrets otherwise. Its absence is a hardening note.

Grade: informational. Evidence: what the app checks and how it reacts.

---

## 9. Reporting template for a scoped MASVS-RESILIENCE pentest

| Control | Present | Bypass | Time | Tool |
|---|---|---|---|---|
| Jailbreak detection | yes/no | yes/no | minutes | objection / Hide Jailbreak / custom hook |
| Frida detection | | | | |
| Debugger detection | | | | |
| Integrity / anti-tamper | | | | |
| App Attest enforcement (server) | | | | |
| Obfuscation / symbols | | n/a | | ipsw |

One finding, severity from the client's threat model, P5 if mapped to VRT.

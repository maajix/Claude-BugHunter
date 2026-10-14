# Storage: MASVS-STORAGE-1, MASVS-STORAGE-2 (and CRYPTO-2 key handling)

Scope boundary: `ios-redteam-pipeline` Stage 3 owns the generic secret grep of
the IPA, the `keychain-dumper` install and the backup-decrypt tooling install.
This file owns the **runtime** storage tests: what the app writes after you use
it, with which protection, and how that is graded. Everything here is Stage A:
it runs on your own test device with your own test account.

MASTG test IDs below come from OWASP/mastg `master` (fetched 2026-10-14). IDs
marked "deprecated" are the v1 tests kept for reference.

---

## 1. Canary discipline

Before you touch the app, write down canaries you will grep for later. Use one
prefix so a single grep finds all of them:

| Field | Example canary |
|---|---|
| Password | `CnryPw-1014-a7` |
| Display name | `CnryName-1014` |
| Address, card nickname, note, chat text | `CnryAddr-1014`, `CnryNote-1014` |
| Search query | `CnrySearch-1014` |

Also capture the session tokens the app receives (from the proxy, `network.md`)
so you can grep for their first 12 characters.

Payments, messages to anyone other than a tester account, and content other
users can see are Stage B (written sign-off) unless the client provides a
sandbox; capture and drop those requests in the proxy otherwise.

Exercise every flow on a fresh install: onboarding, login, "remember me",
profile edit, payments or orders, chat, document upload and preview, offline
mode, push opt-in, logout. Then background the app on each sensitive screen
(snapshots, section 7).

---

## 2. Pull the containers

### Jailbroken device or Corellium

```bash
# Find the app's data container and bundle path from inside the app
objection -n <bundle_id> start
#   env                      -> BundlePath, DocumentDirectory, LibraryDirectory, CachesDirectory
#   ls <DocumentDirectory>   -> includes an NSFileProtection column per file
# Copy the data container and any App Group container off the device (SSH over USB)
iproxy 2222 22 &
scp -P 2222 -r <user>@127.0.0.1:/var/mobile/Containers/Data/Application/<UUID> ./container
scp -P 2222 -r <user>@127.0.0.1:/private/var/mobile/Containers/Shared/AppGroup/<UUID> ./appgroup
```

The App Group path is the one MASTG-TEST-0299 uses. Map group UUIDs to group
identifiers from the `.com.apple.mobile_container_manager.metadata.plist` file
at the root of each container (verify on your iOS version).

### Stock device: encrypted local backup

A backup reaches the app's backed-up files on a non-jailbroken device. It
needs encryption on, or Keychain items and some health data are left out.

```bash
pymobiledevice3 backup2 encryption on '<backup-password>'   # once, on your test device
pymobiledevice3 backup2 backup --full ./bk
pymobiledevice3 backup2 unback ./bk --password '<backup-password>'
# unback rebuilds the domain tree; the app is under AppDomain-<bundle_id>/
```

What a backup does **not** contain: `Library/Caches`, `tmp`, and Keychain items
with a `ThisDeviceOnly` class (they are not restorable onto another device).
Keychain items in an encrypted backup are themselves encrypted; decoding them
needs a dedicated tool that supports your iOS version (verify which works).

`UIFileSharingEnabled` or `LSSupportsOpeningDocumentsInPlace` set to true
means `Documents/` is browsable from the Files app and from Finder on a trusted
computer. `pymobiledevice3 afc shell` reaches the shared Documents of such apps
(verify for your build). Anything sensitive in `Documents/` of such an app is
the strongest storage finding iOS offers, because no jailbreak is needed.

---

## 3. Grep for the canaries

```bash
grep -rla 'Cnry' ./container ./appgroup        # -a: also match inside binary files and SQLite pages
grep -rla '<first-12-chars-of-token>' ./container ./appgroup
# SQLite: the -wal file holds recent writes that are not yet in the main file
for f in $(find ./container ./appgroup -name '*.sqlite' -o -name '*.db' -o -name '*.sqlite-wal'); do
  strings -a "$f" | grep -q 'Cnry' && echo "HIT $f"
done
```

| Store | Location in the container | Read with | Notes |
|---|---|---|---|
| NSUserDefaults | `Library/Preferences/<bundle_id>.plist` | `plutil -p`, objection `ios nsuserdefaults get` | Not for tokens or PII. Shared defaults (`UserDefaults(suiteName:)`) sit in the App Group container |
| Plists, JSON, archives | `Documents/`, `Library/Application Support/` | `plutil -p`, `jq` | Also look for `NSKeyedArchiver` blobs |
| Core Data, SQLite | `*.sqlite`, `*.db` plus `-wal`, `-shm` | `sqlite3 file .dump` | Read `-wal` too; deleted rows survive in free pages |
| Realm | `*.realm` | Realm Studio | An encrypted Realm needs a 64-byte key; find where the key lives (Keychain is right, a constant in the binary is not) |
| URL cache | `Library/Caches/<bundle_id>/Cache.db` (verify) | `sqlite3`: `cfurl_cache_response`, `cfurl_cache_receiver_data` | API responses with PII or tokens; `Cache-Control: no-store` on sensitive endpoints prevents it |
| Cookies | `Library/Cookies/Cookies.binarycookies` | objection `ios cookies get` | Long-lived session cookies |
| WKWebView storage | `Library/WebKit/WebsiteData/` (LocalStorage, IndexedDB) (verify) | `sqlite3` | Tokens set by in-app web pages |
| Snapshots | `Library/SplashBoard/Snapshots/sceneID:<APP_NAME>-default/` | image viewer (format varies, verify) | Section 7 |
| Temporary files | `tmp/` | `ls -la` | Decrypted documents, previews, exports left behind |
| Credential storage | `NSURLCredentialStorage` | objection `ios nsurlcredentialstorage dump` | HTTP auth credentials persisted by the URL loading system |

Evidence per hit: path, file protection class (section 5), the matching line
with the canary, the app version and the flow that wrote it.

Grade: `Insecure Data Storage > Sensitive Application Data Stored Unencrypted >
On Internal Storage` (P5). Non-sensitive data: `Insecure Data Storage >
Non-Sensitive Application Data Stored Unencrypted` (P5). MASTG-TEST-0300, 0301,
0302 (sandbox), 0303 (shared storage), 0388 (App Group).

---

## 4. Keychain items and accessibility classes

```bash
objection -n <bundle_id> start
#   ios keychain dump                      -> columns: Created, Accessible, ACL, Type, Account, Service, Data
#   ios keychain dump --smart              -> also tries to decode binary values
#   ios keychain dump --json kc.json       -> writes the table to a local file for evidence
```

On a jailbroken device `keychain-dumper` (pipeline Stage 3) shows all apps'
items; objection shows only what the hooked app can read.

| Accessibility class | Readable when | Leaves the device via backup or iCloud Keychain |
|---|---|---|
| `kSecAttrAccessibleWhenUnlocked` (default for `SecItemAdd`) | Unlocked | Yes (encrypted backup) |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock until reboot | Yes |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Unlocked | No |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | After first unlock | No |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Unlocked, passcode set; deleted if passcode removed | No |
| `kSecAttrAccessibleAlways`, `...AlwaysThisDeviceOnly` | Any time | Deprecated since iOS 12; a finding in new code |

Also record `kSecAttrSynchronizable` (true means iCloud Keychain sync) and any
`kSecAttrAccessControl` (biometry or passcode binding, see
`auth-and-session.md`).

What to flag:

- Refresh tokens, private keys or long-lived credentials outside the Keychain
  (UserDefaults, plist, SQLite). This is the storage finding programs most
  often accept, because the token is a **server** credential.
- Those secrets in the Keychain with a non-`ThisDeviceOnly` class: the session
  moves to another device through a backup restore. Prove it by restoring an
  encrypted backup onto a second test device and opening the app.
- **Keychain survives uninstall.** Log in, delete the app, reinstall: if the
  app resumes the old session without asking, a second-hand or shared device
  inherits the account. Low; argue it for shared-device or kiosk apps.
- Shared `keychain-access-groups` with sibling apps (pipeline decision table):
  any app in the group reads the item.

Grade: P5 for class choices alone; the session-portability and
survives-uninstall proofs are worth a Low/P4 argument via `bugcrowd-reporting`
when the program cares about lost or shared devices. MASTG has no current
Keychain-class test; the deprecated 0052 covered it.

---

## 5. Data Protection classes (NSFileProtection)

| Class | Key available | Use |
|---|---|---|
| `NSFileProtectionComplete` | Only while unlocked | Sensitive files not needed in the background |
| `NSFileProtectionCompleteUnlessOpen` | Open handles keep working after lock; new files writable while locked | Background downloads |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | From first unlock until reboot | Default for app files |
| `NSFileProtectionNone` | Always | Never for sensitive data |

Read each file's class with objection `ls` (the `NSFileProtection` column) on
a jailbroken device. MASTG-TEST-0299 fails only on sensitive files with
`NSFileProtectionNone`; anything else is a hardening recommendation
(`Complete` for documents, health data, chat history).

Context for impact: since iOS 18.1 a device that stays locked for 72 hours
reboots into the Before First Unlock state, where the default class is
protected again (inactivity reboot; reported by researchers, verify current
timer). That narrows the window in which the default class matters on a lost
device.

Evidence: objection `ls` output with the protection column for the file,
next to the canary hit inside it.

Grade: P5. Physical-access only; HackerOne core ineligible unless the program
puts physical access in scope.

---

## 6. Backups and backup exclusion

Files in `Documents/` and `Library/` (except `Library/Caches`) are backed up to
iCloud and to Finder or iTunes. `isExcludedFromBackup` (`NSURLIsExcludedFromBackupKey`)
is advisory: Apple's documentation says it provides guidance to the system and
is not a guarantee (quoted by MASTG-TEST-0215).

Procedure: take the encrypted backup (section 2), `unback`, grep for canaries
and tokens under `AppDomain-<bundle_id>`, and list files the app marked as
excluded that still appear. MASTG-TEST-0298 hooks the file APIs at runtime to
list every file written to a backed-up location.

iCloud Backup is end-to-end encrypted only with Advanced Data Protection
enabled (iOS 16.2+, verify); without it, Apple holds the keys. That is the
argument for treating backed-up tokens as more exposed than on-device ones.

Evidence: backup encryption state, the `AppDomain-<bundle_id>` path and the
matching canary or token prefix; for session portability, a recording of the
restored second test device opening the account.

Grade: `Mobile Security Misconfiguration > Auto Backup Allowed by Default` (P5)
is the nearest VRT node (its name is Android's). Most briefs exclude it.

---

## 7. App-switcher snapshots

iOS captures the visible UI when the app moves to the background, for the App
Switcher. MASTG-TEST-0290: visit each sensitive screen, background the app,
then copy the snapshots from
`Library/SplashBoard/Snapshots/sceneID:<APP_NAME>-default/` (path varies by iOS
version). The test fails if a snapshot shows data that should be hidden
(balances, card numbers, messages, OTPs, documents).

Correct behaviour: the app covers sensitive views in
`sceneWillResignActive` / `applicationWillResignActive` (or the SwiftUI
`scenePhase` change) before the snapshot is taken.

iOS 18 added user-controlled app locking ("Require Face ID"); whether a locked
app's snapshot is hidden is user configuration, not the app's control, and
reports conflict on its behaviour (verify). It does not change the grade.

Evidence: the snapshot file with its path and timestamp, sensitive values
redacted, and the screen it came from.

Grade: `Insecure Data Storage > Screen Caching Enabled` (P5).

---

## 8. Pasteboard

| Concern | Check | MASTG |
|---|---|---|
| App writes secrets to `UIPasteboard.general` (copy-token, copy-OTP, copy-IBAN buttons, auto-copy) | Static references; runtime monitor | 0276, 0277 |
| Contents never cleared after use | Clear-on-background or `expirationDate` | 0278, 0279 |
| Contents sync to the user's other devices (Universal Clipboard) | `.localOnly` option missing | 0280 |

```bash
objection -n <bundle_id> start
#   ios pasteboard monitor     -> prints pasteboard changes while you use the app
```

Since iOS 16, a programmatic read of another app's pasteboard content prompts
the user ("Allow Paste") unless the user pastes through system UI (verify
exact rules per iOS version). That reduces silent cross-app reads and therefore
the impact of anything the target app puts on the pasteboard.

Evidence: `ios pasteboard monitor` output showing the value the app wrote,
and the code reference (MASTG-TEST-0276 output).

Grade: `Mobile Security Misconfiguration > Clipboard Enabled` (P5); a shared
link copied with a token in it: `External Behavior > System Clipboard Leak >
Shared Links` (P5).

---

## 9. Logs and crash reports

`os_log` and `Logger` redact dynamic strings and objects as `<private>` unless
the developer marks them `%{public}` / `privacy: .public`; scalar values are
public by default. `NSLog` and `print` output are not redacted. MASTG-TEST-0296
(logs at runtime), 0297 (logging APIs in the binary); 0358 and 0359 cover
implementation details in logs.

```bash
pymobiledevice3 syslog live -m <ProcessName>      # or: idevicesyslog -p <ProcessName>
pymobiledevice3 crash pull ./crashes                # crash logs can carry request bodies or tokens
```

Grep the stream for canaries and token prefixes while you replay the flows.
Also note third-party SDKs (analytics, crash reporting, session replay) that
**send** logs, screen captures or request bodies off the device: that is a
privacy finding (MASVS-PRIVACY) and sometimes a data-exposure one if the
vendor dashboard is shared.

Evidence: the log line with process name and timestamp, value redacted.

Grade: P5 on-device (reading the log needs the unlocked device and a trusted
computer). Off-device leakage of personal data to a third party: argue under
`Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure`
(VARIES).

---

## 10. Keyboard cache and text fields

The system keyboard learns typed words for autocorrection and predictive text.
Sensitive fields should set `isSecureTextEntry` (forces the system keyboard and
disables learning) or `autocorrectionType = .no` and `spellCheckingType = .no`.

- MASTG-TEST-0313 (references to the APIs) and 0314 (runtime check of which
  fields are eligible for caching).
- MASTG-TEST-0346, 0347: sensitive input not masked.
- The cache is system-owned, under `/private/var/mobile/Library/Keyboard/`
  (verify file names per iOS version); inspect it on a jailbroken device after
  typing canaries into non-secure fields, then reset the keyboard dictionary in
  Settings.

Evidence: the field (screen and accessibility identifier), its text-input
traits, and the cache hit.

Grade: `External Behavior > Browser Feature > Autocorrect Enabled` (P5).

---

## 11. Memory

Deprecated MASTG-TEST-0060 still describes the method: secrets kept in memory
longer than needed.

```bash
objection -n <bundle_id> start
#   memory search "CnryPw-1014" --string      -> offsets where the password still sits after login
```

Swift `String` and Objective-C `NSString` cannot be reliably zeroed, so this is
informational except for apps with explicit high-assurance requirements.
Evidence: the `memory search` output and when it was taken (after login,
after backgrounding, after logout).

Grade: `External Behavior > User Password Persisted in Memory` (P5).

---

## 12. Cryptography touchpoints (MASVS-CRYPTO)

Storage tests often end at "the file is encrypted". Then check the key.

| Check | MASTG |
|---|---|
| Key hardcoded in code or shipped in a file | 0213, 0214 |
| Broken algorithm or mode (DES, 3DES, RC4, ECB) | 0210, 0317 |
| Broken hash for integrity or passwords (MD5, SHA-1) | 0211 |
| Insufficient key size | 0209 |
| Insecure random for keys, IVs, tokens | 0311, 0349 |

`objection` `ios monitor crypto` logs CommonCrypto calls at runtime (keys, IVs,
plaintext) while you exercise the flow. A key derived from a constant plus the
bundle ID, or stored in UserDefaults next to the ciphertext, makes the
encryption decorative; report the storage finding with that context.

Evidence: the key's location (symbol or file), algorithm and mode from
`ios monitor crypto`, and which data it protects.

Grade: still P5 for local data. A hardcoded key that also signs or encrypts
**server** traffic (request signing, payload encryption the server trusts) is
a different finding: forge one request on your own account, Stage B if it
writes, and grade by what the server accepted.

---

## 13. What iOS 17 to 27 changed for these tests

| Release | Change | Effect on testing |
|---|---|---|
| iOS 16 | Paste permission prompt for programmatic reads of another app's content (verify) | Lowers pasteboard impact |
| iOS 16.2 | Advanced Data Protection: optional end-to-end encrypted iCloud Backup (verify) | Backup exposure depends on the user's setting |
| iOS 17.0 | Developer services move to CoreDevice/RemoteXPC tunnels | Use pymobiledevice3 or recent libimobiledevice; on Linux/Windows iOS 17.0 to 17.3.1 needs `pymobiledevice3 remote tunneld` (see `tooling.md`) |
| iOS 17.3 | Stolen Device Protection | Not app storage; affects passcode-only attacks on Settings |
| iOS 18 | User-controlled app lock and hide; Passwords app | No change to the app's own storage duties |
| iOS 18.1 | Inactivity reboot after 72 hours locked (researcher-confirmed; verify current timer) | Default file class returns to protected on idle lost devices |
| iOS 26 | No storage-API change found that alters these tests (verify). TLS changes are in `network.md`; Memory Integrity Enforcement on A19 hardware affects jailbreak availability (`tooling.md`) | Same procedure |
| iOS 27 | Released 2026-09-14 (verify); no confirmed storage-relevant developer change found | Re-check snapshot and keyboard-cache paths on first use |

---

## Grade summary

| Proven | VRT node | Default |
|---|---|---|
| Plaintext server credential (refresh token, API secret) in sandbox files | Insecure Data Storage > Sensitive Application Data Stored Unencrypted > On Internal Storage | P5; argue up when the token is long-lived and portable |
| Sensitive data in Finder-visible `Documents/` (`UIFileSharingEnabled`) | same node, argue the no-jailbreak path | P5, request more |
| Weak file protection on sensitive files | same node | P5 |
| Sensitive files in backups | Mobile Security Misconfiguration > Auto Backup Allowed by Default | P5 |
| Snapshot leak | Insecure Data Storage > Screen Caching Enabled | P5 |
| Secret on the pasteboard | Mobile Security Misconfiguration > Clipboard Enabled | P5 |
| Keyboard cache of sensitive field | External Behavior > Browser Feature > Autocorrect Enabled | P5 |
| Password persisted in memory | External Behavior > User Password Persisted in Memory | P5 |
| Personal data sent to a third-party SDK | Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure | VARIES |

# Data storage and privacy on the device (MASVS-STORAGE)

The method for every storage control is the same: **use the app with known
markers, then search everywhere the app can write for those markers.** Do it
on your own rooted test device (or a Google APIs emulator image, `tooling.md`
§4) with your own test account.

## 1. Marker run and sandbox snapshot

1. Pick markers you can grep for: the test account's email, a unique password
   (`Canary-Pw-7f3a`), a unique name and address, and the session token once
   you see it in the proxy.
2. Walk every flow that touches sensitive data: login, profile, payment
   screens (stop before paying), document upload, chat, logout.
3. Snapshot everything the app can write. Redirects stay on the host side.

```bash
PKG="com.client.app"
mkdir -p evidence/sandbox
# Private sandbox (rooted device or Google APIs emulator with adb root)
adb exec-out su -c "tar -C /data/data -cf - $PKG" > evidence/sandbox/data_data.tar
adb exec-out su -c "tar -C /data/user_de/0 -cf - $PKG" > evidence/sandbox/user_de.tar
# Debuggable build only (no root needed): run-as reads the sandbox as the app
adb exec-out run-as "$PKG" tar -cf - . > evidence/sandbox/run_as.tar
# App-specific external storage and the shared folders
adb exec-out tar -cf - "/sdcard/Android/data/$PKG" > evidence/sandbox/ext_app.tar
adb shell ls -laR /sdcard/Download /sdcard/Documents /sdcard/Pictures > evidence/sandbox/shared_ls.txt

mkdir -p evidence/sandbox/x && tar -C evidence/sandbox/x -xf evidence/sandbox/data_data.tar
grep -rIl -e 'Canary-Pw-7f3a' -e 'tester@canary.example' evidence/sandbox/x
# Binary stores (SQLite, protobuf DataStore, Realm) need strings, not grep -I
find evidence/sandbox/x -type f -exec sh -c 'strings -a "$1" | grep -q Canary-Pw-7f3a && echo "$1"' _ {} \;
```

On `adb exec-out su -c` some root solutions want `su 0 sh -c`; test once and
keep what works. The `/data/user_de/0/<pkg>` copy is device-encrypted storage
(readable before first unlock), so secrets there are exposed earlier than
credential-encrypted ones.

**Evidence.** Path, file, the matching line (token redacted to its first and
last four characters), file mode (`ls -la`), and whether it is in the private
sandbox, device-encrypted storage, or shared storage.

## 2. SharedPreferences and DataStore

- `shared_prefs/*.xml` is plaintext XML. Look for tokens, passwords, PINs,
  PII, feature flags that gate paid or privileged features (`auth-and-session.md` §2).
- Jetpack DataStore writes `files/datastore/*.preferences_pb` (protobuf; use
  `strings` or `protoc --decode_raw`).
- `EncryptedSharedPreferences` files have encrypted keys and values plus a
  `__androidx_security_crypto_encrypted_prefs_key_keyset__` entry. The
  `androidx.security:security-crypto` library is in maintenance / deprecated
  (verify); its presence is not a finding, and its absence for a refresh token
  is P5 at most.
- File mode: `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` throw a
  `SecurityException` for apps targeting API 24+ (verify the exact level). A
  world-readable file in the
  sandbox on a modern build means `chmod`/native code, worth one look.

## 3. SQLite, Room and Realm

```bash
cd evidence/sandbox/x/"$PKG"/databases
for db in *.db; do echo "== $db"; sqlite3 "$db" '.tables'; done
sqlite3 app.db '.schema'                   # column names tell you where secrets live
sqlite3 app.db 'SELECT * FROM tokens LIMIT 1;'   # read-only, your own data
head -c 16 app.db | xxd                    # "SQLite format 3" = plaintext; random bytes = SQLCipher or similar
```

- Room is SQLite underneath; the schema is in the decompiled `*_Impl` classes.
- SQLCipher: the key must come from somewhere. A hardcoded passphrase or one
  derived from `ANDROID_ID` is a finding when the DB holds sensitive data;
  hook `SQLiteDatabase.openOrCreateDatabase` (net.sqlcipher / net.zetetic) to
  record it.
- Realm: `files/*.realm`. Open with Realm Studio. Encrypted Realm files need
  the 64-byte key passed to `RealmConfiguration.Builder.encryptionKey(...)`;
  hook that to see where it comes from.
- WAL files (`*.db-wal`) keep rows that were "deleted"; grep them too.

Severity: a plaintext DB in the private sandbox is VRT Insecure Data Storage >
Sensitive Application Data Stored Unencrypted > On Internal Storage (P5) and
ineligible on many programs (needs root to read); the same DB on external or
shared storage is On External Storage (P4). A hardcoded SQLCipher key that
protects other users' data server-side is graded where that data lives.

## 4. Shared and external storage

- App-specific external storage (`/sdcard/Android/data/<pkg>/`,
  `getExternalFilesDir`) is private to the app on Android 11+ under scoped
  storage, but readable by apps holding broad storage access on older
  versions, and by anyone with the device on USB.
- Shared collections (`Download/`, `Documents/`, `Pictures/`, `DCIM/`, written
  via MediaStore or `Environment.getExternalStoragePublicDirectory`) are
  readable by other apps with media permissions.
- Exported files: statements, invoices, ID scans, chat attachments, logs and
  crash dumps are the usual hits.

Severity: sensitive data in shared storage is VRT Insecure Data Storage >
Sensitive Application Data Stored Unencrypted > On External Storage (P4), and
the one storage class most programs accept without a second bug. App-specific
external storage on Android 11+ is weaker; state the Android versions on which
another app can read it.

## 5. Backups: allowBackup, Auto Backup rules, adb backup

**Static.**

```bash
grep -o -E 'android:(allowBackup|fullBackupContent|dataExtractionRules|fullBackupOnly|backupAgent)="[^"]*"' decoded/AndroidManifest.xml
cat decoded/res/xml/*backup*.xml decoded/res/xml/*extraction*.xml 2>/dev/null
```

- `android:allowBackup` defaults to `true` when absent.
- `fullBackupContent` (Android 6 to 11) and `dataExtractionRules` (Android 12+,
  with separate `<cloud-backup>` and `<device-transfer>` sections) decide what
  is included. An app that sets `allowBackup="true"` with no rules, or rules
  that exclude only caches, ships its whole sandbox into the user's backup.
- `android:debuggable="true"` builds can be backed up and `run-as`ed at will.

**Trigger a backup you can read (own device, own test account).** On
Android 12+ `adb backup` excludes app data unless the app is `debuggable`,
so for a release build use the local Auto Backup transport instead:

```bash
adb shell bmgr enabled
adb shell bmgr list transports                       # pick the local transport
adb shell bmgr transport com.android.localtransport/.LocalTransport
adb shell bmgr backupnow "$PKG"                       # or: bmgr fullbackup "$PKG"
# Local transport writes under /data/backup; copy it out with root and grep the markers.
adb exec-out su -c "tar -C /data/backup -cf - ." > evidence/localbackup.tar
```

For a `debuggable` build, `adb backup -f backup.ab "$PKG"` still works; the
`.ab` is a (optionally AES-encrypted) header followed by a zlib stream. Unpack
it with `abe` (android-backup-extractor) rather than piping to a device; never
write the stream to a device path. Restore to a **second test device you own**
with `bmgr restore` to prove whether a session token survives the round trip.
The exact `bmgr`/local-transport commands vary by build; verify them against
`adb shell bmgr help` on your device (verify).

**Evidence.** The manifest attributes, the rules file, and the extracted
backup tree with the marker found in it.

**Severity.** VRT Mobile Security Misconfiguration > Auto Backup Allowed by
Default (P5). Many programs exclude backup inclusion unless it exposes session
tokens or critical PII that stays valid after restore. The backup and the local
restore are Stage A (your own devices, your own account). Confirming the
restored session still authenticates is **Stage B** and needs written
sign-off, because it is one authenticated request to the production backend:
restore to a second test device you own, open the app, and make a single
read-only call with the recovered session to show it survived without a login.

## 6. Logs

```bash
adb logcat -c
adb logcat --pid="$(adb shell pidof -s "$PKG")" -v threadtime | tee evidence/logcat_app.txt
# In a second terminal, walk the marker flows, then:
grep -n -e 'Canary-Pw-7f3a' -e 'tester@canary.example' -i -e 'bearer ' -e 'authorization' evidence/logcat_app.txt
```

- Also grep the decompiled code for `Log.d|Log.v|println|printStackTrace` near
  token handling and for HTTP logging interceptors left at `Level.BODY`
  (`HttpLoggingInterceptor`), which dump headers and bodies to logcat.
- Third-party apps cannot read other apps' logs on Android 4.1+ without the
  system-only `READ_LOGS` permission. A finding needs a reader: see severity below.

Severity: there is no VRT node for logcat. Public policies often reject log
findings "unless you can provide a proof with a malicious app stealing the
data from logs". Report it when the log reaches somewhere other parties read:
a crash-reporting or analytics SDK upload (visible in the proxy), a file in
shared storage, or `adb bugreport` output a support flow asks users to send.

## 7. Screenshots, recents thumbnail and screen capture

**Test.** Open each sensitive screen (card details, OTP, recovery codes,
statements), then:

```bash
adb shell screencap -p > evidence/screen_$(date +%s).png   # all-black PNG = FLAG_SECURE set
adb shell dumpsys window windows | grep -E 'mCurrentFocus|fl=|FLAG_SECURE' | head
```

Press the recents button and screenshot the switcher with a second device or
camera: the thumbnail must be blank or a placeholder.

- `WindowManager.LayoutParams.FLAG_SECURE` blocks screenshots, screen
  recording, non-secure displays and the recents thumbnail.
- `Activity.setRecentsScreenshotEnabled(false)` (API 33 (verify)) hides only
  the recents thumbnail.

- Android 14 added screenshot *detection* (`Activity.ScreenCaptureCallback`,
  `DETECT_SCREEN_CAPTURE`); it does not fire for `adb` screenshots, so test it
  with the hardware key combination. Detection is not prevention.
- Android 15 added screen *recording* detection
  (`WindowManager.addScreenRecordingCallback`) and screen-share protection
  that hides notifications, password input and OTP-posting apps' activities
  while sharing, and lets an app mark a view sensitive with
  `View.setContentSensitivity(CONTENT_SENSITIVITY_SENSITIVE)`. A developer
  option, "Disable screen share protections", turns this off on your test
  device for comparison.
- Android 17, for apps targeting it: `setContentCaptureEnabled(false)` no
  longer disables Content Capture; Google points to `FLAG_SECURE` instead.

**Severity.** VRT Insecure Data Storage > Screen Caching Enabled (P5). Grade
higher only with a remote path (a screenshot API exposed to another app,
screen sharing in a support flow capturing the card number).

## 8. Clipboard and keyboard

- Grep for `ClipboardManager.setPrimaryClip` near passwords, OTPs, recovery
  phrases, card numbers and tokens. A "copy" button for those is the finding.
- Since Android 10 only the focused app and the default input method can read
  the clipboard; Android 12 shows a toast when an app reads it; Android 13 lets
  apps mark a clip sensitive (`ClipDescription.EXTRA_IS_SENSITIVE`) so the
  preview hides it, and clears the clipboard after a period (these per-version
  behaviours and the clear interval: verify on the test build).
- Keyboard learning: sensitive fields should use `textPassword` /
  `textVisiblePassword` / `textNoSuggestions` input types.

Severity: VRT Mobile Security Misconfiguration > Clipboard Enabled (P5);
shared links on the clipboard are External Behavior > System Clipboard Leak >
Shared Links (P5) and listed as ineligible by many programs.

## 9. Keystore usage and key attestation (MASVS-STORAGE / MASVS-CRYPTO)

- Secrets should be wrapped by a key in `AndroidKeyStore`, not stored next to
  their key. Red flags: AES keys or IVs as string constants, keys derived from
  `ANDROID_ID`, `Build.SERIAL` or the package name, keys written to prefs.
- Inspect live keys on your device with objection (`android keystore list`,
  `tooling.md` §3) and the code that creates them: `KeyGenParameterSpec`
  purposes, `setUserAuthenticationRequired`, `setIsStrongBoxBacked(true)`,
  `setUnlockedDeviceRequired(true)`.
- `KeyInfo.getSecurityLevel()` (API 31 (verify)) or `isInsideSecureHardware()`
  tell you
  whether the key is TEE/StrongBox-backed or software-only (emulators are
  software-only, so record the security level from a physical device).
- **Key attestation** is a server-side control: the backend should verify the
  attestation certificate chain to a Google root, check the challenge, and
  read the key's properties. A backend that accepts any chain, or never sends
  a fresh challenge, is the finding; test with your own device's chain only.
  Google's key attestation page says a new root key began signing attestation
  chains on 1 February 2026 and that verifiers must trust both listed roots
  (root set at `https://android.googleapis.com/attestation/root`, revocation
  list at `https://android.googleapis.com/attestation/status`). A backend
  pinned to the old root alone rejects new devices; one that skips the
  revocation check accepts revoked keys. Both are server findings, graded on
  what attestation gates.

Severity: weak key storage is graded by what the key protects. A hardcoded
key that decrypts other users' data on the server side is high; a hardcoded
key that only decrypts the local cache of your own account is P5 at most.

## 10. What Android 15 and 16 changed for storage tests

Backup and WebView storage behaviour did not change in 15, 16 or 17 per the
behaviour-change pages. What did change, and how it affects a test:

| Version | Change | Scope | Effect on testing |
|---|---|---|---|
| 15 (API 35) | OTPs redacted from untrusted notification listeners; screen-share protection hides notifications, password fields and OTP apps | All apps | A notification-OTP leak to another app is mitigated on 15+; prove it on the minimum Android version the program supports |
| 15 | Private space keeps a separate copy of the app with its own sandbox | All | Test the app in the main profile; a private-space copy is a different user ID (`adb shell pm list users`) |
| 15 | Caller-identity checks for content URIs (`checkContentUriPermissionFull`, `requireContentUriPermissionFromCaller`) | Opt-in | Note whether the app uses them when you grade a provider or share-target finding (`ipc-and-platform.md` §6) |
| 16 (API 36) | Apps can grant other apps access to their Keystore keys (`KeyStoreManager.grantKeyAccess`) | Opt-in | Grep for `grantKeyAccess`; a grant to a package that is not the client's own is worth a look |
| 16 | Devices launching with 16 use Remote Key Provisioning only | Device | Attestation chains from new devices are RKP-issued; verifiers must handle them (§9) |
| 16 | Views marked `accessibilityDataSensitive` are hidden from accessibility services that are not real accessibility tools | Opt-in | A sensitive screen without the flag is readable by any enabled accessibility service; low severity alone |
| 17 (API 37, stable 2026) | SMS OTPs withheld from apps that are not the verified recipient for 3 hours | All apps (stricter for apps targeting 37) | SMS-reading as a leak path is closed on 17 |
| 17 | `setContentCaptureEnabled(false)` no longer opts out of Content Capture | Targeting 37 | Sensitive screens need `FLAG_SECURE` |
| 17 | Per-app Keystore key limit (50,000) | All | Not a security test; explains `ERROR_TOO_MANY_KEYS` crashes |

Older baselines that still decide severity: Android 11 scoped storage (other
apps cannot read your `Android/data/` directory), Android 12 `adb backup`
exclusion for apps targeting 31+, and the `dataExtractionRules` takeover from
`fullBackupContent` on 12+.

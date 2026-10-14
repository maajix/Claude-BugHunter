---
name: hunt-electron
description: "Hunt Electron and Chromium-wrapper desktop apps as a web attack surface - the app is web code, so an XSS inside it reaches the OS. Covers the per-version security model (nodeIntegration false since Electron 5, contextIsolation true since 12, remote module removed in 14, sandbox true since 20, new-window removed in 22), the escalation path from a DOM sink to require('child_process') or a preload-exposed bridge, over-broad contextBridge.exposeInMainWorld APIs, ipcMain handlers that never check event.senderFrame (CVE-2022-29247), navigation control (will-navigate, will-frame-navigate, setWindowOpenHandler), custom myapp:// deep links and Windows command-line argument injection (CVE-2018-1000006), shell.openExternal with attacker-controlled input, asar unpacking and why asar is not a security boundary, electron-updater signing bypass (CVE-2024-39698), and shipped secrets. Use when scope includes a downloadable desktop client, an Electron/NW.js/CEF wrapper, or an app whose UI is HTML."
sources: electron_docs, electron_breaking_changes, github_security_advisories, hackerone_public, doyensec_research, public_research, hacktricks_coverage_checklist
report_count: 6
---

## Crown Jewel Targets

An Electron renderer is a browser tab the vendor deliberately gave OS capabilities. One HTML injection in a chat message, link preview, markdown note or embed becomes code execution on an employee laptop, with the user's filesystem, SSH keys and session tokens in reach. Priority targets:

- **Team chat and collaboration clients.** Message bodies, embeds and OGP unfurls are attacker-controlled HTML reaching a privileged renderer.
- **Note, wiki and markdown apps.** Print and export paths often re-render stored content in a *second*, less hardened window.
- **Crypto wallets and finance clients.** RCE equals key theft; the keystore is in the same process tree.
- **Admin consoles, VPN and device-management clients.** Privileged credentials, usually on an old Electron.
- **Anything registering a custom URL scheme.** `myapp://` is reachable from any web page the user visits.
- **Self-updating apps.** The updater is a code-delivery channel; a weak one turns manifest or network compromise into persistent RCE.
- **Non-Electron Chromium wrappers** (NW.js, CEF shells, Tauri with a permissive allowlist). Same pattern: web content plus a native bridge.

Severity ranking: drive-by RCE from a visited web page (deep link or updater) > stored-content RCE inside the app > local file read or token exfiltration > bridge abuse limited to app-level actions.

---

## OOB/Confirmation Gate

**Read before you claim anything.** Static review of an unpacked app yields *configuration* findings. Configuration is not exploitation, and the inverse is also true: a dangerous flag with no reachable injection point is not RCE.

### What is NOT confirmation

- `nodeIntegration: true` in a `BrowserWindow` constructor with no demonstrated injection into *that* window. Many apps have one privileged window that only ever loads a local `file://` page.
- A dangerous-looking `exposeInMainWorld` reachable only from a trusted local origin.
- A calculator popping during manual testing. Without a canary you cannot prove *your* payload caused it rather than the app or an installer.
- `require` being defined in a DevTools console you opened yourself. DevTools has privileges the page does not.
- An `ipcMain.handle` channel merely existing. You need a renderer-reachable caller plus a handler that acts on unvalidated arguments.

### What IS confirmation

- **Code execution:** a per-attempt unique canary, written to a path only your payload knows or received on an OOB listener you control, diffed against a pre-trigger baseline of that same path or listener.
- **File read:** a file planted in the VM before the test, with a unique marker inside, returned through the app's own channel.
- **Bridge abuse:** the privileged action observed in app state or on disk, triggered from a renderer context you reached through an injection, not from a preload console.
- **Navigation takeover:** the app's own privileged window ends up on your origin, screenshotted, and it is not a system browser window.

### Default workflow

1. Acquire the installer, hash it, record the version. Keep the original artifact untouched.
2. Unpack and review statically (Stage A). Almost all findings come from here.
3. Only once static review names a concrete reachable chain, request Stage B sign-off and execute in a disposable VM.

---

## Attack Surface Signals

Signals that a target is in scope for this skill:

- A download page offering `.dmg`, `.exe`, `.AppImage`, `.deb`, `.snap` or a `.zip` with an `app` directory.
- A `resources/app.asar` file, a `resources/app/` directory, or a `*.pak` plus `v8_context_snapshot.bin` next to the main binary.
- A `Contents/Frameworks/Electron Framework.framework` directory in a macOS bundle.
- A `User-Agent` of the form `... Chrome/<version> Electron/<version> Safari/...` in server logs or in the client's own traffic.
- `nw.js`, `nw.pak` or a `package.json` with an `nw` key (NW.js), or `libcef.so` / `Chromium Embedded Framework.framework` (CEF).
- A web page in scope that links to a `myapp://` URL, or an OS registration for a custom scheme.
- A server-side feature whose output is rendered in both the web app and the desktop app. The desktop app usually has the weaker CSP.

Source-level signals to grep for once unpacked are in Step 4 below.

---

## Step-by-Step Methodology

> **Safety rule for this entire skill.** A desktop application under review is untrusted code. Never install or run it on your own machine. Use a disposable VM or container with a snapshot taken before first launch, no credentials, no mounted host directories, and network egress you can observe. Stage A (static) never executes the app. Do not run `npm install`, `npm start`, `node`, or any build tool inside the extracted tree: lifecycle scripts and planted modules in that directory will execute. Keep scripts you write outside the extracted directory and pass paths as arguments.

### 1. Acquire and record the artifact

```bash
# Detection only: download, hash, do not install.
mkdir -p ~/review/app-raw && cd ~/review/app-raw
curl -sSLO "https://vendor.example/download/App-1.2.3.dmg"
sha256sum App-1.2.3.dmg | tee SHA256SUMS
```

Record the version you reviewed. Every default in this skill is version-dependent, and a report against the wrong build is worthless.

### 2. Unpack into a fresh empty directory

```bash
# Linux AppImage: static extraction only. Do NOT run `--appimage-extract`,
# that executes the AppImage's own bundled runtime, which is untrusted code.
# The squashfs payload starts where the ELF ends: e_shoff + e_shentsize * e_shnum.
OFF=$(readelf -h App-1.2.3.AppImage | awk '
  /Start of section headers/  {s=$5}
  /Size of section headers/   {z=$5}
  /Number of section headers/ {n=$5}
  END {print s + z * n}')
unsquashfs -o "$OFF" -d ./squashfs-root App-1.2.3.AppImage   # confirm -o: unsquashfs -help

# Windows NSIS installer (static extraction, no execution)
7z x App-1.2.3.exe -o./app-ext
# macOS
hdiutil attach -nobrowse -readonly App-1.2.3.dmg   # then copy App.app out, detach

# ASAR archive: @electron/asar, requires Node 22.12.0 or later.
# Install the tool globally or in a tools directory, never inside the extracted tree.
npm install -g @electron/asar
asar list   ./resources/app.asar | head -50
asar extract ./resources/app.asar ./app-src
```

`asar` is a concatenation format with a JSON header. It is **not** a security boundary: it is not encrypted, not signed by itself, and `asar extract` reads it with no key. Integrity checking exists but is off unless the vendor enabled it (see Step 9).

### 3. Determine the bundled Electron major version

Every default below depends on it.

```bash
# Heuristic: the Chromium user-agent string is compiled into the main binary
strings -a ./app-ext/App.exe | grep -o 'Electron/[0-9][0-9.]*' | sort -u
# If app sources or a lockfile shipped, prefer them
grep -R '"electron"' ./app-src/package.json ./app-src/*.lock* 2>/dev/null
```

Stage B only, inside the VM: `process.versions.electron` read from the app's own DevTools is authoritative. If you cannot establish the version, assume **no** default and treat every preference as "unset, behaviour unknown", then say so in the report.

**Verified per-version defaults (Electron documentation):**

| Preference | Current default | Version boundary (from Electron breaking changes) |
|---|---|---|
| `nodeIntegration` | `false` | Default changed in **Electron 5**: deprecated default `true`, new default `false` |
| `webviewTag` | `false` | Default changed in **Electron 5**: previously `nodeIntegration` if set, else `true` |
| `contextIsolation` | `true` | Announced in the Electron 5 table; the flip landed in **Electron 12** ("In Electron 12, `contextIsolation` will be enabled by default") |
| `sandbox` | `true` | **Electron 20**: "renderers will be sandboxed by default, unless `nodeIntegration: true` or `sandbox: false` is specified" |
| `enableRemoteModule` | gone | **Electron 10**: "the remote module is now disabled by default". Deprecated in 12, **removed in 14** |
| `worldSafeExecuteJavaScript` | gone | Default `true` in **Electron 12**, removed in **Electron 14** |
| `webSecurity` | `true` | Setting it `false` also sets `allowRunningInsecureContent` to `true` if that was unset |
| `nodeIntegrationInWorker` | `false` | Only workers created by a frame that has Node access get it |
| `nodeIntegrationInSubFrames` | not documented with a default | Experimental. When enabled, every preload loads in every iframe. **Electron 44**: workers created by subframes follow this flag |
| `nativeWindowOpen` | gone | Enabled by default since **Electron 15**, option **removed in Electron 18** |
| `new-window` event | gone | **Removed in Electron 22** on both `WebContents` and `<webview>`; use `setWindowOpenHandler` |
| whole `ipcRenderer` over `contextBridge` | neutered | **Electron 29**: sending the entire module yields an empty object on the receiving side |

Sandbox detail that decides exploitability: in a sandboxed renderer the preload's `require` can load only the `electron` module, which gives `contextBridge`, `crashReporter`, `ipcRenderer`, `nativeImage`, `webFrame` and `webUtils`. No Node built-ins, no `Buffer`. The sandbox therefore removes `child_process` but **not** IPC. Electron's own docs note the preload environment is substantially more privileged than the sandboxed renderer, so privileged APIs still leak to page code unless `contextIsolation` is on.

### 4. Inventory every window and its effective preferences

```bash
cd ./app-src
grep -rn "new BrowserWindow\|new BrowserView\|new WebContentsView\|<webview" --include=*.js --include=*.ts --include=*.html .
grep -rn "webPreferences\|nodeIntegration\|contextIsolation\|sandbox:\|webSecurity\|allowRunningInsecureContent\|nodeIntegrationInSubFrames\|webviewTag\|allowpopups\|enableBlinkFeatures\|experimentalFeatures" --include=*.js --include=*.ts --include=*.html .
```

Build a table: window name, explicit preferences, **effective** preferences (explicit value, else the version default from Step 3), what it loads, and which preload it attaches. The window that loads remote or user-generated content with the weakest preferences is your target. Check secondary windows: print previews, OAuth popups, embedded help, crash reporters and `<webview>` tags are routinely created without the main window's hardening.

### 5. Follow `main` to the renderer entry points

```bash
python3 -I -c "import json;d=json.load(open('package.json'));print(d.get('main'),d.get('version'))"
grep -rn "loadURL\|loadFile\|\.src *=\|setWindowOpenHandler\|will-navigate\|will-frame-navigate" --include=*.js .
```

Map each window to its HTML entry, then to the bundled renderer JS. From there the sink taxonomy is ordinary DOM work: use `hunt-dom` for the sinks and `hunt-xss` for the injection. What is different here is where the sink leads.

### 6. Rate the escalation path for each injection point

Given an HTML or JS injection inside a renderer, the escalation depends only on the effective preferences:

1. `nodeIntegration: true` (or `sandbox: false` plus a preload that re-exports Node): page script calls `require('child_process').exec(...)` directly. One step to RCE.
2. `nodeIntegration: false`, `contextIsolation: false`: page script and preload share a JavaScript realm. Overriding intrinsics such as `RegExp.prototype.test`, `Array.prototype.join` or `Function.prototype.call` lets page code steer whatever the preload or Electron internals do next. This is the Discord 2020 chain.
3. `contextIsolation: true` with a preload bridge: realms are separate, so the only reachable privilege is exactly the API surface the preload exposed. Read it as if it were an unauthenticated HTTP API, because that is what it is.
4. Fully sandboxed with a narrow bridge: escalation needs a main-process handler bug, a Chromium bug, or a navigation or deep-link path that lands you in a more privileged window.

### 7. Read the bridge as an API

```bash
grep -rn "exposeInMainWorld\|exposeInIsolatedWorld" --include=*.js .
grep -rn "ipcRenderer.send\|ipcRenderer.invoke\|ipcRenderer.sendSync\|ipcRenderer.on" --include=*.js .
```

An over-broad `exposeInMainWorld` is the modern equivalent of `nodeIntegration: true`. Shapes to flag, worst first:

- A generic invoke passthrough: `{ invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) }`. The renderer now reaches every handler in the app.
- A module loader: `{ requireModule: (name) => require(name) }`, even with an allowlist, if any allowlisted module runs a subprocess or builds a command string.
- Anything that forwards to `shell.openExternal`, `shell.openPath`, `fs` writes, `spawn`/`exec`, `eval`, or a path argument used to read or write files.
- Anything exposing `webContents`, `BrowserWindow`, `app`, `clipboard`, or raw `ipcRenderer`. Electron's security checklist calls out the clipboard API specifically.
- A callback-registration API that passes the raw IPC `event` object into page code.

A safe bridge exposes one narrow verb per operation with no caller-supplied channel and no caller-supplied path.

### 8. Audit main-process IPC handlers for sender and argument validation

```bash
grep -rn "ipcMain.on\|ipcMain.handle\|ipcMain.handleOnce\|mainFrame.handle\|\.ipc\.handle" --include=*.js .
grep -rn "senderFrame\|event.sender\|validateSender" --include=*.js .
```

Two independent defects to look for:

- **No sender validation.** `IpcMainEvent.senderFrame` is a `WebFrameMain` or `null`. Electron's checklist validates the frame **origin**, not its URL, because `about:blank`, `blob:` and sandboxed documents have URLs that do not identify who controls them. A handler registered with `ipcMain.handle` receives messages from any frame, including child frames. Missing checks here are what made CVE-2022-29247 (GHSA-mq8j-3h7h-p8g7, "Compromised child renderer processes could obtain IPC access without `nodeIntegrationInSubFrames` being enabled", affected `< 15.5.5`, `>= 16.0.0 < 16.2.6`, `>= 17.0.0 < 17.2.0`, `>= 18.0.0-beta.1 <= 18.0.0-beta.5`) exploitable. The advisory's own workaround is "Ensure that all IPC message handlers appropriately validate `senderFrame`".
- **No argument validation.** A handler that concatenates an argument into a shell command, a path, a SQL string or a `require` call is the real bug. Treat these exactly like server-side handlers and apply `hunt-nodejs` for the sink classes (command injection, path traversal, prototype pollution, `require` injection). The difference is only that the "client" is a renderer rather than an HTTP request.

### 9. Navigation, new windows, protocol handlers and fuses

```bash
grep -rn "will-navigate\|will-frame-navigate\|setWindowOpenHandler\|did-create-window\|new-window\|openExternal\|openPath\|setAsDefaultProtocolClient\|open-url\|second-instance\|requestSingleInstanceLock\|registerSchemesAsPrivileged\|registerFileProtocol" --include=*.js .
```

- `will-navigate` fires **only for the main frame**, and not for programmatic navigation via `webContents.loadURL` or `webContents.back`. `will-frame-navigate` fires for the main frame or any subframe, so an app that guards only `will-navigate` never sees subframe navigations at all. Separately, in the versions covered by **CVE-2020-15174** (GHSA-2q4g-w47c-4674, "Unpreventable top-level navigation", affected `>= 8.0.0-beta.0 < 8.5.1`, `>= 9.0.0-beta.0 < 9.3.0`, `>= 10.0.0-beta.0 < 10.0.1`; patched 8.5.1, 9.3.0, 10.0.1) a sub-frame could perform a cross-site top-frame navigation that `will-navigate` did not fire for, which is how the Discord chain escaped its iframe. Pin the target's version before claiming that bypass.
- `setWindowOpenHandler` must return `{ action: 'deny' }` or `{ action: 'allow' }`; an unrecognised return value logs a console error and behaves as deny. Allow-by-default, or allowlisting by substring rather than parsed origin, is the finding.
- Host-only URL checks are the classic bypass: accepting any URL whose host matches the vendor domain inherits every open redirect on that domain. Chain `hunt-open-redirect`.
- `app.setAsDefaultProtocolClient(protocol[, path, args])` passes **the whole link, including the protocol, to the app as a parameter**. On Windows that lands on the app's own Chromium command line: CVE-2018-1000006, Windows-only, affecting any Electron app registered as a default protocol handler regardless of how it was registered, patched in 1.8.2-beta.5, 1.7.12 and 1.6.17. The documented mitigation appends `--` as the last argument so Chromium stops parsing switches. Check both the Electron version and whether `--` is present.
- Deep-link entry differs per OS: `open-url` is macOS only and needs the scheme in `Info.plist`; Windows and Linux get the link in `argv`, usually via `requestSingleInstanceLock` and `second-instance`. Review every path, since apps commonly validate one and not the others. Enumerate the OS-level registrations statically rather than trusting the code:

```bash
# macOS bundle: the schemes the app claims at install time
plutil -p ./App.app/Contents/Info.plist | grep -A6 "CFBundleURLTypes\|CFBundleURLSchemes"
# Linux deb/AppImage payload: scheme handlers are declared in .desktop files
grep -rn "x-scheme-handler/" --include=*.desktop . ; grep -rn "^Exec=" --include=*.desktop .
# Windows NSIS payload: the scheme name and the command line written to the registry
grep -rniE "setAsDefaultProtocolClient|HKCU\\\\Software\\\\Classes|shell\\\\open\\\\command" .
strings -a ./app-ext/App.exe | grep -iE "^[a-z][a-z0-9+.-]{2,20}://" | sort -u | head -20
```

Compare the `Exec=` line (Linux) and the registered command (Windows) against the `--` mitigation above: a registration that places `%u` or `%1` before an argument terminator is the argument-injection precondition.
- Record the **fuse** state. Defaults per Electron's fuses documentation: `runAsNode` **enabled**, `nodeOptions` **enabled**, `nodeCliInspect` **enabled**, `cookieEncryption` **disabled**, `embeddedAsarIntegrityValidation` **disabled**, `onlyLoadAppFromAsar` **disabled**, `loadBrowserProcessSpecificV8Snapshot` **disabled**. ASAR integrity is supported on macOS from `electron>=16.0.0` and Windows from `electron>=30.0.0`, requires an archive built by `@electron/asar` (support added in `asar@3.1.0`), and terminates the app on a header-hash mismatch. Enabled integrity fuses are version-gated too: **CVE-2025-55305** (GHSA-vmqv-hx8q-j7mg, "ASAR Integrity Bypass via resource modification", affected `< 35.7.5`, `>= 36.0.0-alpha.1 < 36.8.1`, `>= 37.0.0-alpha.1 < 37.3.1`, `>= 38.0.0-alpha.1 < 38.0.0-beta.6`; patched 35.7.5, 36.8.1, 37.3.1, 38.0.0-beta.6) impacts only apps with both `embeddedAsarIntegrityValidation` and `onlyLoadAppFromAsar` enabled. Trail of Bits' write-up shows the bypass goes through V8 heap snapshot files, which the integrity fuses did not cover, and the advisory lists no app-side workaround. On an affected Electron, record the fuses as on but not delivering integrity; the precondition is write access to the install location (CVSS `AV:L`), so it is a local finding. Report these as hardening gaps only. Local abuse of the Node-related fuses is local privilege escalation and persistence, out of scope for this bundle.

### 10. Secrets and local storage

```bash
grep -rniE "api[_-]?key|secret|token|password|bearer |private[_-]key|-----BEGIN" --include=*.js --include=*.json . | head -40
ls -la ./app-src   # look for .env, *.map, config.*.json, firebase config, sentry DSN
```

The whole bundle ships to every user, so anything in it is public. Source maps reconstruct the original source; use `hunt-source-leak` for the extraction mechanics. Also note where the app stores session tokens at rest (`Local Storage`, `leveldb`, a plaintext JSON config, an unencrypted cookie store when the `cookieEncryption` fuse is off). A renderer RCE or an over-broad file-read bridge turns that into account takeover without touching the server.

### 11. Updater review

```bash
grep -rn "autoUpdater\|electron-updater\|setFeedURL\|checkForUpdates\|feedURL" --include=*.js .
cat ./app-ext/resources/app-update.yml 2>/dev/null
```

Checklist:

- Feed URL and channel file (`latest.yml` / `latest-mac.yml`) served over HTTPS from a host the vendor controls.
- macOS build signed. electron-builder: "macOS application must be signed in order for auto updating to work."
- Windows target is the supported NSIS one (Squirrel.Windows is not supported).
- No `setFeedURL` call in app code, since electron-builder writes `app-update.yml` into `resources` ("Do not call `setFeedURL`").
- No `dev-app-update.yml` or `autoUpdater.forceDevUpdateConfig = true` in the release build.
- Version-check two known updater bugs: **CVE-2024-39698** (GHSA-9jxc-qjr9-vjxq, "electron-updater Code Signing Bypass on Windows", affected `<= 6.3.0-alpha.5`, patched `6.3.0-alpha.6`), where `cmd.exe` expands environment variables in the verification command line so the verifier can be "tricked into validating the certificate of a different file than the one that was just downloaded"; and Doyensec's 2020 finding, where the Windows check compared `publisherName` against the certificate Common Name via PowerShell `Get-AuthenticodeSignature` with the update file path unescaped, so a quote in the filename made verification fail open (resolved in electron-builder v22.3.5 per that write-up).

Both require a compromised manifest or a MITM position. Report the missing control; do not attack a live update channel.

---

## Payload & Detection Patterns

Stage A grep set, the one to run first on any unpacked app:

```bash
grep -rnE "nodeIntegration: *true|contextIsolation: *false|sandbox: *false|webSecurity: *false|allowRunningInsecureContent: *true|nodeIntegrationInSubFrames: *true|webviewTag: *true|allowpopups" --include=*.js --include=*.html .
grep -rnE "exposeInMainWorld|ipcRenderer\.(invoke|send)\(.*channel|require\(.*(name|mod|module)\)" --include=*.js .
grep -rnE "shell\.openExternal\(|shell\.openPath\(|child_process|execFile|exec\(|spawn\(|new Function|eval\(" --include=*.js .
grep -rnE "indexOf\(['\"]https?://|startsWith\(['\"]https?://|\.host ?===|includes\(['\"]\." --include=*.js .   # weak URL checks
```

Automated first pass (static, safe, reads files only):

```bash
npm install @doyensec/electronegativity -g
electronegativity -i ./app-src -o /tmp/eng.csv
electronegativity -i ./resources/app.asar -o /tmp/eng-asar.csv
electronegativity -i ./app-src -e 22.0.0        # force an assumed Electron version
electronegativity -i ./app-src -u 20..28        # upgrade-path checks between majors
```

The tool's README states it is no longer actively maintained and points to ElectroNG, Doyensec's improved SAST tool based on Electronegativity, as its successor (https://get-electrong.com). Treat electronegativity as a lead generator and confirm every hit by reading the code. Its `-e` flag "assume[s] the set Electron version, overriding the detected one": whenever the version is unknown to the tool or its detection could disagree with the version you pinned in Step 3, pass `-e` with the pinned version, or its version-dependent checks run against the wrong defaults.

Code-execution confirmation, Stage A baseline then Stage B, inside the VM only:

```bash
# Stage A: generate a per-attempt canary and capture the baseline. No execution yet.
CANARY="ELEC$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "$CANARY"
test ! -e "/tmp/$CANARY.txt" && echo "baseline: canary path absent"
ls -la /tmp > "/tmp/baseline_$CANARY.txt"   # keep for the body/behaviour diff
```

```js
// Stage B: execution (ONLY with explicit RCE-attempt sign-off, in a snapshotted VM).
// Substitute the $CANARY value from Stage A into both the filename and the content.

// Case 1: nodeIntegration true
require('child_process').execSync('printf CANARY-VALUE > /tmp/CANARY-VALUE.txt');

// Case 1b: preload re-export of require (window.nodeRequire pattern)
window.nodeRequire('child_process').execSync('printf CANARY-VALUE > /tmp/CANARY-VALUE.txt');

// Case 3: over-broad bridge. Enumerate the surface first, do not guess channel names.
Object.keys(window).filter(k => typeof window[k] === 'object' && window[k])
  .forEach(k => { try { console.log(k, Object.keys(window[k])) } catch (e) {} });
```

```bash
# Verification: the canary path must be absent from the Stage A baseline and present now,
# and its contents must equal the exact canary value.
grep -q "$CANARY" "/tmp/baseline_$CANARY.txt" && echo "INVALID: canary leaked into baseline"
cat "/tmp/$CANARY.txt"; diff <(ls -la /tmp) "/tmp/baseline_$CANARY.txt"
```

Confirmed RCE ONLY if `/tmp/$CANARY.txt` contains the exact `$CANARY` value, that path is absent from the Stage A baseline listing, and the file appeared in the post-trigger diff. A calculator window, an error dialog or a file whose name you did not generate this attempt is NOT confirmation. Restore the snapshot afterwards.

Deep-link probe. This launches the app, so it is Stage B, not detection:

```bash
# Stage B: launches the application. Requires sign-off. Serial, one link at a time, 2s apart.
xdg-open "myapp://canary-$CANARY"; sleep 2
# Windows (inside the VM): start "" "myapp://canary-%CANARY%"
# macOS  (inside the VM): open "myapp://canary-$CANARY"
```

Observe what the app does with the string: logged, parsed, passed to `loadURL`, or placed on a command line. Never loop a deep-link fuzzer at speed against a client; a crash loop is a denial of service on the host you were lent.

---

## Common Root Causes

- The app was written against an old Electron and carries old defaults forward in explicit code. `nodeIntegration: true` is often a copy-paste from a tutorial predating Electron 5.
- A hardened main window plus an unhardened secondary window. Print preview, OAuth popup, `<webview>`, and crash dialog are the usual offenders.
- `contextIsolation` left off because a feature needed shared intrinsics, then never revisited.
- The preload exposes a generic passthrough because "the renderer needs lots of things", so the bridge has no narrower contract than the whole IPC bus.
- Main-process handlers were written assuming only the app's own UI can call them, so they validate neither sender nor arguments.
- Allowlisting by host, substring or regex instead of parsing the URL and comparing origins, which imports every redirect on the vendor's domain.
- Deep-link handling validated on one OS path only.
- The desktop app reuses the web app's content pipeline but ships a weaker CSP, or none, because `file://` pages make CSP feel optional.
- The updater trusts a manifest without verifying a signature it actually computed over the artifact it just downloaded.

---

## Bypass Techniques

- **Click gating.** Code that only acts on a real click can be driven by `element.click()` or a synthetic `MouseEvent`, and by overriding the intrinsic the handler uses to validate (`RegExp.prototype.test`, `Array.prototype.join`, `String.prototype.startsWith`) when `contextIsolation` is off.
- **Iframe to top navigation.** If the injection sits in an iframe without Electron internals, navigate the top-level frame to your own page. In versions affected by CVE-2020-15174 (see Step 9 for the exact ranges) `will-navigate` did not fire for a cross-site top-frame navigation started from a sub-frame. On patched versions the event fires, so the bypass there is a weak check inside the handler, not a missing event.
- **Open redirect on the vendor's own host.** Defeats host-only allowlists in both `loadURL` guards and `setWindowOpenHandler`.
- **`window.open` and `target="_blank"`.** If `setWindowOpenHandler` allows by default, the child window may inherit preferences you could not reach directly. Check what the handler returns for every `disposition` value (`default`, `foreground-tab`, `background-tab`, `new-window`, `other`).
- **Subframe IPC.** Where `nodeIntegrationInSubFrames` is enabled, every preload loads in every iframe, so an injected iframe gets the bridge. Even without it, child renderers reached IPC in the versions covered by CVE-2022-29247.
- **Channel smuggling.** A bridge that takes a channel name lets you call handlers the UI never calls, including debug and internal channels left registered in release builds.
- **`shell.openExternal` scheme abuse.** The API opens the URL "in the desktop's default manner", so the reachable impact depends entirely on which schemes and handlers the victim OS has registered. Treat a reachable `openExternal` with attacker-controlled input as a finding on its own; enumerate what it can reach only inside the VM, and never point it at a path or scheme whose handler you have not identified.
- **Protocol argument injection.** On Windows, a crafted `myapp://` link can place switches on the app's own command line unless the registration appends `--` (CVE-2018-1000006).

---

## Gate 0 Validation

Before writing the report, all four must hold.

1. **Version pinned.** You state the exact app version and the Electron version, you say how you determined the Electron version, and every default you rely on is the default for *that* major. A claim such as "contextIsolation is off by default" is wrong from Electron 12 onward and will get the report closed.
2. **Reachability shown.** You name the injection point, the window it renders in, that window's effective preferences, and the preload attached to it. "Window X has `nodeIntegration: true`" plus "the app has an XSS somewhere" is two findings, not a chain, until you show the XSS renders in window X.
3. **Confirmation is canary-backed.** For RCE: a per-attempt unique canary observed in a location you checked was absent in the pre-trigger baseline, in a VM snapshot you can restore. For file read: a pre-planted marker file. A screenshot of a calculator is not evidence.
4. **Reproducible from a clean snapshot.** Restore the VM to the pre-install snapshot, install, and run the chain again. If it only works on a dirty VM, the chain depends on state you have not identified.

Also check the inverse before reporting a config-only finding: if the dangerous preference is only ever applied to a local `file://` page with no injection and no remote content, say so and downgrade it to a hardening recommendation.

---

## Real Impact Examples

**Scenario A: stored message content to RCE through an over-broad preload bridge.** A team-chat client rendered message embeds in its main window with `nodeIntegration: false` but `contextIsolation` left off, plus a preload exposing a module loader to page script. A DOM XSS in a third-party 3D-model embed gave JavaScript execution inside an iframe. Because realms were shared, overriding two array and regex intrinsics changed the command an allowlisted utility module built before spawning a subprocess. The iframe lacked Electron internals, so the chain navigated the top-level window to an attacker page, which re-ran the override with internals present. The fix had three parts: drop the embed source, sandbox the iframe, then enable `contextIsolation`.

**Scenario B: a visited web page to drive-by RCE through a custom scheme.** A collaboration client registered a custom scheme and, on launch, checked only that the launch URL's host equalled the vendor domain before calling `loadURL` on its main window. That window ran `nodeIntegration: true` with a preload assigning `require` to `window.nodeRequire`. An ordinary open redirect on the vendor's own site satisfied the host check, loaded an attacker page into the privileged window, and `nodeRequire('child_process')` did the rest. No user action beyond visiting a page and accepting the scheme prompt.

---

## Disclosed Report Citations

- **Slack desktop apps, RCE, critical** - "Remote Code Execution in Slack desktop apps + bonus", HackerOne report 783877: https://hackerone.com/reports/783877
- **Rocket.Chat, stored XSS to file leak and desktop RCE, high, CVE-2021-22886** - HackerOne report 1014459: https://hackerone.com/reports/1014459
- **Rocket.Chat desktop client <= 2.17.9, XSS to `shell.openExternal` RCE, critical** - the chain overwrote `Regex.test` and dispatched a synthetic click on an attacker-crafted link. HackerOne report 899964: https://hackerone.com/reports/899964
- **Simplenote 1.1.3 desktop, stored XSS executing on the print path, high** - HackerOne report 358049: https://hackerone.com/reports/358049
- **Discord desktop RCE** - Masato Kinugawa's write-up of the `contextIsolation: false` plus preload-module plus CVE-2020-15174 navigation-bypass chain: https://mksben.l0.cm/2020/10/discord-desktop-rce.html
- **Open redirect to RCE via custom scheme** - spaceraccoon's Electron code-review write-up of the host-only launch-URL check: https://spaceraccoon.dev/open-sesame-escalating-open-redirect-to-rce-with-electron-code-review/

Primary advisories referenced above: CVE-2018-1000006 (https://www.electronjs.org/blog/protocol-handler-fix), CVE-2020-15096 / GHSA-6vrv-94jv-crrg context-isolation bypass via Promise (affected `< 6.1.11`, `7.0.0 - < 7.2.4`, `8.0.0 - < 8.2.4`; patched 6.1.11, 7.2.4, 8.2.4), CVE-2022-29247 / GHSA-mq8j-3h7h-p8g7, CVE-2024-39698 / GHSA-9jxc-qjr9-vjxq, CVE-2025-55305 / GHSA-vmqv-hx8q-j7mg (https://github.com/electron/electron/security/advisories/GHSA-vmqv-hx8q-j7mg; mechanism: https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/). Electron's security checklist: https://www.electronjs.org/docs/latest/tutorial/security. Per-version defaults: https://www.electronjs.org/docs/latest/breaking-changes. Fuses: https://www.electronjs.org/docs/latest/tutorial/fuses. HackTricks' Electron pages were used only as a coverage checklist (commit-pinned): https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/network-services-pentesting/pentesting-web/electron-desktop-apps/README.md

---

## Related Skills & Chains

- **`hunt-xss`** - supplies the injection. Chain primitive: stored or reflected XSS in app-rendered content plus a privileged renderer equals OS code execution rather than session theft. Desktop builds routinely ship a weaker CSP than the web app, so an injection blocked on the web may fire in the client.
- **`hunt-dom`** - the generic sink taxonomy (`innerHTML`, `dangerouslySetInnerHTML`, postMessage, DOM clobbering). This skill adds where the sink leads once the page is an Electron renderer.
- **`hunt-nodejs`** - the server-side Node sink classes. Reuse them for main-process IPC handlers: command injection, path traversal, prototype pollution, `require` injection. The caller is a renderer instead of an HTTP client.
- **`hunt-open-redirect`** - a redirect on the vendor's own host defeats host-only allowlists in `loadURL` guards, `setWindowOpenHandler` and deep-link handlers.
- **`hunt-source-leak`** - source maps and bundle secrets. The whole desktop bundle is shipped to every user, so treat it as published source.
- **`hunt-rce`** - once a command sink is reachable, use its confirmation discipline and impact framing.
- **`supply-chain-attack-recon`** - signed Electron bundles are a known distribution vector; relevant when the updater or the build pipeline is in scope.
- **`apk-redteam-pipeline`, `ios-redteam-pipeline`** - the mobile equivalents. Same pipeline shape: acquire the binary, unpack, grep for secrets, enumerate exported entry points, then instrument in a disposable device or VM.
- **`evidence-hygiene`, `triage-validation`** - apply the canary-plus-baseline rule before any confirmed-RCE claim, and keep the VM snapshot and hashes with the evidence.
</content>
</invoke>

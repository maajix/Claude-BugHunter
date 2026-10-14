# XS-Leak Channel Catalog

Per-channel detail for `hunt-xs-leaks`. Each entry gives the oracle, the
inclusion method, the browser status **as verified on 2026-10-10**, the
mitigation that kills it, and the false-positive trap specific to that channel.

Every status line below maps to a source fetched during authoring. Where no
source could confirm a cell it says **unverified** — treat those as hypotheses to
test in the target's own browser build, not as facts to put in a report.

---

## 1. Error events (`onload` / `onerror`)

- **Oracle:** load a state-dependent URL as a subresource and watch which event
  fires. Success implies one response class, failure the other.
- **Inclusion:** `<script src>`, `<img>`, `<link rel=stylesheet>`, `<iframe>`.
  The cure53 HTTPLeaks list enumerates every element that emits a request.
- **Status:** alive in Chromium, Firefox and WebKit as a *mechanism*. Whether it
  leaks **user-specific** state depends entirely on whether the probe carries
  credentials — see `defences-and-headers.md` for the cookie matrix. A subresource
  probe is a cross-site non-navigation request, so a cookie without
  `SameSite=None; Secure` is not attached in Chrome: the Chromium Blog
  (2020-02, graduated rollout from 2020-02-17) states that from Chrome 80 a cookie
  with no declared `SameSite` is treated as Lax and only `SameSite=None; Secure`
  stays usable in third-party contexts.
- **Killed by:** a Resource Isolation Policy that rejects `Sec-Fetch-Site:
  cross-site` unless the request is a GET navigation; `Cross-Origin-Resource-Policy:
  same-origin`; returning one uniform status code for both states.
- **FP trap:** `onerror` also fires on DNS failure, TLS failure, CSP block and
  content-type mismatch. Baseline a URL you know 404s and a URL you know 200s in
  the same page load, in the same browser profile, before believing any result.

```html
<!-- Boolean status oracle. Replace with the target's own state-dependent path. -->
<script>
function probe(url) {
  return new Promise(res => {
    const s = document.createElement('script');
    s.src = url;
    s.onload  = () => res('loaded');
    s.onerror = () => res('error');
    document.head.appendChild(s);
  });
}
probe('https://target.example/api/item/4711').then(console.log);
</script>
```

## 2. CORB / ORB script-load oracle

- **Oracle:** request a state-dependent endpoint with `<script src>`. A response
  the browser refuses to hand to a `no-cors` script context (JSON, HTML with
  `X-Content-Type-Options: nosniff`) fires `onerror`; a response that parses as
  script fires `onload`. The *pair* (status class, content type) becomes the bit.
- **Status:** a 2022 blink-dev **intent to ship** sought approval for Opaque
  Response Blocking v0.1 in Chrome M103, and a 2023 v0.2 thread describes network
  errors replacing CORB's empty response behind the `OpaqueResponseBlockingV02`
  flag, with script-initiated fetches keeping CORB behaviour for compatibility.
  Whether ORB actually shipped and fully replaced CORB in current Chrome is
  **unverified** — the threads found this session stop in 2023. Firefox tracks the
  same work in Bugzilla 1532642. Treat the oracle's exact failure mode as
  something to measure in the target build, not to assume.
- **Killed by:** CORP `same-origin`; a Resource Isolation Policy; not returning
  different content types for the two states.
- **FP trap:** a JSON response that happens to be valid JavaScript (a bare array
  or a JSONP-style wrapper) loads cleanly and inverts your mapping.

## 3. Frame counting (`window.length`, `window.frames`)

- **Oracle:** the frame count of a cross-origin document is readable through a
  window reference. "Search returned results" pages often embed a different
  number of frames than "no results" pages.
- **Inclusion:** `<iframe>` (needs the target to permit framing) or
  `window.open` (needs a user gesture, survives framing protections).
- **Status:** the read itself is same-origin-policy-permitted in all current
  engines. The popup variant is the one that matters in 2026, because framing
  protections are common and because a popup is a **top-level navigation** —
  per MDN, a `SameSite=Lax` or attribute-less cookie *is* sent on a top-level
  cross-site navigation using a safe method. So a popup probe runs authenticated
  where an iframe probe does not.
- **Killed by:** `Cross-Origin-Opener-Policy: same-origin` severs the reference
  between opener and opened document (MDN; with `noopener-allow-popups` the
  handle even reports `closed === true`). For the iframe variant,
  `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.
  `SameSite=Strict` on the session cookie kills the popup variant's credentials.
- **FP trap:** frame count varies with ads, consent banners, A/B buckets and
  viewport. Capture the count for both known states, in both test accounts, and
  require a stable separation across at least 20 runs per state.

```html
<!-- Requires a click; popups without a gesture are blocked. -->
<button onclick="run()">start</button>
<script>
async function run() {
  const w = window.open('https://target.example/search?q=CANARY-9f3a1b', '_blank');
  await new Promise(r => setTimeout(r, 3000));   // single measurement, no loop
  console.log('frames:', w.length);              // COOP: same-origin breaks this
  w.close();
}
</script>
```

## 4. Navigation and redirect detection

- **`history.length`:** drive a window you own to the target, then back to a
  same-origin page, and read the entry count. A state that redirects adds an
  entry. Killed by COOP for the window variant, framing protections for the
  iframe variant.
- **Redirect-cap arithmetic:** the Fetch standard caps a redirect chain at **20**.
  Chain *n* of your own redirects in front of the target; the chain only completes
  when `n + target_redirects <= 20`. Binary-searching `n` yields the target's
  redirect count. Cookie restrictions do not help here, because the count is a
  browser limit rather than a credentialed read.
- **Client-side URL max length:** Chrome's URL limit is **2 MB** per the XS-Leaks
  Wiki (other engines' limits not stated there, so **unverified**). Pad a URL with
  a fragment to one character under the limit; if the target then issues a
  redirect that appends anything, the navigation fails and the window stays put.
- **`fetch(..., {redirect: 'manual'})`:** an opaque-redirect response is readable
  only as a type, not a location, which in principle yields "redirected or not"
  without following. **Unverified** — the wiki's navigations page does not cover
  this variant, and no source read this session confirms current behaviour. Test
  it on a lab origin before relying on it; the page's nearest covered equivalent
  is a CSP `connect-src` violation triggered by a cross-origin redirect.
- **Status of this family:** the redirect-cap and URL-length variants read
  *browser limits* rather than credentialed responses, so no cookie policy stops
  them; the wiki states the client-side URL-length variant survives `SameSite`,
  COOP and framing protections alike. Per-engine confirmation beyond Chrome's
  2 MB figure and Firefox's `form-action` behaviour is **unverified**.
- **Killed by:** Resource Isolation Policy and (for the server-side inflation
  variants) `SameSite=Strict`. COOP kills the window-reference variant of
  `history.length`; framing protections kill its iframe variant. The wiki lists
  **no** effective header defence for the client-side URL-length variant.
- **FP trap:** a network error is not a redirect. Distinguish `TypeError` from a
  resolved opaque response, and re-run after a cache reset.

## 5. Performance API (`performance.getEntries()`)

- **Oracle:** the presence, absence or count of `PerformanceResourceTiming`
  entries for a cross-origin load, rather than its contents. Cross-origin entries
  are coarse without `Timing-Allow-Origin`, but presence alone is a bit.
- **Known sub-channels:** a framed document carrying `X-Frame-Options` is absent
  from the performance buffer in **Chromium-based browsers only** (XS-Leaks Wiki
  states it "does seem to only work in Chromium based browsers"); empty responses
  and error responses behave differently from normal ones; redirects show up as a
  distinct entry shape.
- **Status:** the XFO sub-channel is Chromium-only per the wiki. Firefox reports
  network durations in milliseconds rather than finer units, which lowers the
  resolution of duration-based variants. Per-entry behaviour changes between
  releases — re-measure, never assume.
- **Killed by:** not varying header presence between states; CORP; a Resource
  Isolation Policy. `Timing-Allow-Origin` makes the leak *worse*, never better.
- **FP trap:** the buffer is capped and can be cleared by the page under test.
  Call `performance.clearResourceTimings()` before each measurement and read the
  buffer once, not in a poll loop.

## 6. Cache probing — **largely dead cross-site, alive same-site**

- **Oracle:** a resource that only loads in one state lands in the HTTP cache;
  a later timing measurement distinguishes hit from miss.
- **Status:** Chrome partitions the HTTP cache **since Chrome 86**, keyed by the
  resource URL plus a Network Isolation Key composed of the top-level site and the
  current-frame site, where a site is scheme + eTLD+1. Firefox partitions the HTTP
  cache, image cache, favicon cache, script cache, stylesheet cache, connection
  pooling, DNS, HTTP authentication, Alt-Svc, HSTS, OCSP, TLS session identifiers,
  the CORS-preflight cache and bfcache **since Firefox 85**, and MDN states this
  network partitioning is permanent and not relaxable by sites.
- **What survives:** the XS-Leaks Wiki notes partitioning is "ineffective for
  requests from subdomains" and for window navigations, so a same-site probe (your
  injected page on a target subdomain) and a top-level-navigation purge still
  work. Cache *invalidation* primitives still listed: `fetch(url, {cache:
  'reload'})` aborted via `AbortController.abort()` mid-flight, a `no-cors` POST,
  an `HTMLFormElement` POST (may purge under the top-level key), an overlong
  `Referer` combined with `cache: 'reload'`, or exceeding the cache size limit.
- **Boundary:** this is **not** `hunt-cache-poison`. Poisoning writes an
  attacker-controlled response into a *shared* cache so other users receive it.
  Probing only reads whether the *victim's own private, partitioned* cache holds
  an entry. Different defect, different owner, different severity.
- **FP trap:** a warm CDN edge looks exactly like a warm browser cache. Prove the
  browser cache is the variable by repeating the measurement with `cache:
  'no-store'`, which should erase the difference.

## 7. Connection-pool timing — **NOISY, gated**

- **Oracle:** occupy the socket pool, leave one slot, then time how long a probe
  request waits. The wait reflects how long the target's own request held a socket.
- **Verified limits** (Chromium `net/socket/client_socket_pool_manager.cc`,
  fetched this session):
  - `g_socket_soft_cap_per_pool` = **256** for normal sockets and **256** for
    WebSocket pools ("the soft limit for active sockets per pool for this network
    process").
  - `g_max_sockets_per_group` = **6** for normal sockets ("Default to allow up to
    6 connections per host"), **255** for WebSockets, with the source comment
    noting "Firefox uses a limit of 200" for WebSockets.
  - `g_max_sockets_per_proxy_chain` = **128**, with `CHECK_GE(socket_count, 6u)`
    and `CHECK_LE(socket_count, 256u)` on the setter.
- **Status:** in Chromium the socket-pool `GroupId` carries a
  `NetworkAnonymizationKey` when connection partitioning is enabled, which splits
  the **per-host group** by top-level site; whether that partitioning is on by
  default in the current stable build is **unverified** and must be checked per
  build. The per-pool soft cap is described in the source as per *network process*,
  so the global-exhaustion variant is not addressed by group keying. In Firefox,
  MDN lists connection pooling as permanently partitioned since Firefox 85, so the
  per-host variant is dead there. The wiki records Mozilla bug 1572544 (pool
  splitting) as under consideration, not shipped, and lists "Randomized Capacity"
  as the defence.

### Gate — cost to the target and bounds

| Item | Rule |
|---|---|
| Where the held sockets point | **Your own sink only.** Never hold sockets against the target. |
| Cost to the target | One probe request per measurement. Nothing else. |
| Cadence | Serial, one measurement every **2-5 s** with jitter. |
| Session cap | **200 measurements** per engagement session, then stop and report. |
| Cleanup | Abort every held request after each measurement; do not leave sockets open between runs. |
| Sign-off | Explicit written operator OK before Stage B, because sustained socket exhaustion inside the tester's browser is indistinguishable from a client-side DoS if mis-scoped. |

Stage A (always allowed): read the headers, confirm the state-dependent endpoint
exists, and confirm the browser build's partitioning behaviour on a lab origin
you own. Stage B (gated): run the timing oracle against the target.

## 8. Event-loop timing and busy event loop — **NOISY, local cost only**

- **Oracle:** JavaScript is single-threaded per renderer. Queue work, measure how
  late it runs, and infer how long another document's task held the loop. The
  busy-loop variant starts a long computation in the target document, then times
  an `onload` of a same-site page with `performance.now()`.
- **Status:** the XS-Leaks Wiki states the cross-document event-loop timing
  attack "is no longer possible in browsers with process isolation mechanisms in
  place", naming Chromium Site Isolation, with Firefox's Fission described as
  coming. The wiki says the busy-loop variant can circumvent Site Isolation, and
  marks `SameSite=Lax` and COOP as effective against it. The wiki page gives no
  millisecond thresholds. If you use `PerformanceLongTaskTiming` as the clock,
  MDN defines a long task as "any uninterrupted period where the main UI thread
  is busy for 50ms or longer" and marks the API experimental with limited
  availability — so it is not a cross-engine clock.
- **Cost:** the blocking happens in the **tester's own renderer**. The target
  receives only the probe requests. Say so in the report; do not let a reader
  mistake it for a server-side DoS.
- **Bound:** block for no longer than needed to take one sample, keep total
  wall-clock under a minute per state, and never ship an exploit page that blocks
  a real user's browser.
- **FP trap:** anything else on the test machine (a build, a video call) moves the
  timings. Run the two states interleaved, A/B/A/B, never as two separate blocks.

## 9. Cookie bomb + `onerror` — **NOISY, near-DoS, strictly gated**

- **Precondition:** you must already hold a cookie-write primitive for the target
  domain or one of its subdomains (an endpoint that reflects input into
  `Set-Cookie`, a subdomain you control, or a same-site injection). Without that
  there is no technique here.
- **Oracle:** inflate the `Cookie` header until the target's front end refuses the
  request. RFC 6585 §5 defines **431 Request Header Fields Too Large** for exactly
  this, and notes nginx answers the same condition with **400** instead. A URL
  that previously fired `onload` now fires `onerror`, which turns "is this
  path reachable for this user" into a Boolean you can read cross-site.
- **Status (derived, not a cited status line):** the bomb cookies are first-party
  on the target domain, but the *probe* from your origin is a cross-site
  non-navigation request. Combining the facts in `defences-and-headers.md` —
  Chrome treats attribute-less cookies as Lax from Chrome 80, Firefox partitions
  third-party state by top-level site from Firefox 103, Safari 13.1 blocks
  third-party cookies — the attacker-page subresource variant only carries the
  bombed cookies where they are `SameSite=None; Secure` (Chrome) or where the
  probe is **same-site**. Label this as derived reasoning in any report, and
  prove it in the target build before claiming it; a top-level navigation probe
  is the variant that still carries Lax cookies.
- **Size facts:** RFC 6265bis work *proposes* **4096 bytes** for cookie
  name + value and 1024 bytes per attribute value. The commonly cited per-domain
  ceiling of ~180 cookies in Chrome and Firefox appears only in secondary sources
  and is **unverified** — do not state a count in a report; state the observed
  request-header size at which the front end started rejecting.
- **Impact framing:** against a real user, a cookie bomb is a denial of service —
  it breaks the site for that user until the cookies expire. That is the *impact
  you describe*, never the action you take.

### Gate — mandatory

| Item | Rule |
|---|---|
| Target of the bomb | **Your own test browser profile only.** Never another account, never a shared or production user. |
| Scope of the cookies | Narrowest `Path` that reproduces the effect, and `Max-Age` of **60 s or less**. |
| Volume | Stop at the first rejection. Do not keep adding bytes to "see how far it goes". |
| Cleanup | Expire every cookie you set (`Max-Age=0` on each name) and verify a clean request succeeds before ending the session. |
| Sign-off | Explicit written operator OK, with the DoS cost named in the request. |
| Never | Do not deliver a cookie-bomb page to any user who is not the tester. |

## 10. CSS `:visited` history

- **Status:** Chrome shipped `:visited` link partitioning in **Chrome 136**
  (developer.chrome.com, published 2025-04-02). Visited styling now applies only
  when the link URL, the top-level site and the frame origin all match, with a
  "self-links" exception so a site may still style its own subpages as visited.
  That closes cross-site history sniffing in current Chrome.
- **Elsewhere:** the XS-Leaks Wiki states `getComputedStyle()` no longer
  distinguishes visited links and that the remaining vectors are interaction-based
  `mix-blend-mode` tricks and render-timing differences amplified across many
  links. It names only the user-side mitigations — disabling history, or setting
  `layout.css.visited_links_enabled` to `false` in Firefox `about:config` — plus
  Chrome's partitioning. Firefox and Safari partitioning status is **unverified**.
- **Reporting rule:** on a Chrome-136-or-later target this is not a finding. If
  you report it at all, name the engine and version you reproduced it in, and
  expect a program that excludes browser-rooted issues (Meta's XS-Leak guidelines
  explicitly refuse findings traced to an older browser version or a browser
  implementation mistake) to close it.

## 11. CSS as a cross-origin oracle (not same-origin exfil)

- **In scope here:** CSS features used to *condition or time* a cross-origin
  state — a `@media`/`:target`-driven request that only fires in one state, a
  CSS-ReDoS selector whose match cost is itself the timing signal, and lazy-image
  loading coupled to the event loop.
- **Status: unverified.** The wiki's CSS page read this session covers only
  `:visited`; no source read confirms current engine behaviour or a kill for the
  `@media`/`:target` request oracle, CSS ReDoS or the lazy-image timing variant.
  They came from the HackTricks checklist. Treat all three as hypotheses: prove
  them on a lab origin, name the engine and version, or leave them out of the
  report.
- **Out of scope here:** attribute-selector exfiltration of same-origin DOM values
  (`input[value^="a"]` → OOB per character). That is `hunt-dom`, which already
  carries the payload set, the CSP caveat and the OOB gate for it. Do not
  re-derive it; chain to it.

## 12. postMessage and header-presence oracles

- **postMessage broadcast:** a widget that posts to its parent only after a
  successful load turns message arrival into the bit; absence is the other state.
- **`X-Frame-Options: deny` oracle:** when the server answers a framed request
  with a deny policy for the wrong identifier, no message is emitted. Setting the
  frame `src` with a candidate ID and treating "no message before timeout" as
  failure brute-forces the identifier. This exact pattern was awarded by Meta —
  see the citation in `SKILL.md`.
- **Killed by:** `targetOrigin` on the sender's side plus a Resource Isolation
  Policy; emitting the same framing policy for every state.
- **Boundary:** `hunt-clickjacking` owns UI redress and framing *as an attack*.
  Here XFO presence is only a leak bit.

## 13. Historical / dead — do not report these as live

| Technique | Why it is dead or doubtful |
|---|---|
| XSS Auditor leak | Removed in **Chrome 78** (2019). Chrome's own deprecation note gives the reason: the auditor introduced cross-site information leaks and was widely bypassable. |
| `SharedArrayBuffer` high-resolution clock | SAB requires cross-origin isolation: Firefox 79 (July 2020) first, Chrome desktop from **Chrome 92** (Chrome Android 88). Isolation needs `COOP: same-origin` + `COEP: require-corp`, which in turn blocks embedding cross-origin resources that do not opt in via CORP or CORS — so the clock and the inclusion fight each other on one document. Treat any SAB-clock PoC as needing a fresh feasibility check. |
| XSinator results matrix | The paper and matrix are 2021 data. Useful as a technique index, useless as a current-status source. Never paste its cells into a report. |
| Style-reload error leak, request-merging error leak, WebSocket connection-limit leak, Payment Request API leak | Browser-bug-shaped channels from the 2021 XSinator set. Not re-verified this session — **unverified**, and programs that exclude browser-implementation issues will refuse them. |

## 14. PortSwigger Top 10 of 2025 additions

Both entries are from "Top 10 web hacking techniques of 2025"
(https://portswigger.net/research/top-10-web-hacking-techniques-of-2025, published
2026-02-05). Status lines below were read on 2026-10-13; treat anything not stated
in the primary source as **unverified**.

### 14a. Cross-Site ETag Length Leak (entry 6)

- **Source:** Takeshi Kaneko (arkark), 2025-12-26 —
  https://blog.arkark.dev/2025/12/26/etag-length-leak . Found as an unintended CTF
  solution.
- **Oracle:** an ETag format that encodes the response size (the write-up's example
  is `jshttp/etag`, which embeds the size in hex) grows by one character when the size
  crosses a boundary. The browser echoes the ETag back in `If-None-Match` on a repeat
  navigation; with request headers already close to the server's limit, that one byte
  turns the response into a `431`. In Chromium the failed repeat navigation replaces the
  history entry instead of adding one, so the difference shows up in `history.length`
  (channel 4).
- **Preconditions:** Chromium; a variable-length ETag on the state-dependent response; a
  way to put the two states on opposite sides of a size boundary; request headers near
  the server's limit. Other engines: **unverified**.
- **Killed by:** a fixed-length or opaque ETag, or no ETag on state-dependent
  responses. COOP removes the window reference the `history.length` read needs (derived
  from channel 4, not stated in the write-up).
- **Gate:** moving the response size needs writes to the account and inflating request
  headers. Same rules as channel 9: your own test accounts and browser profile only,
  Stage B with written sign-off, clean up the written data and headers afterwards.

### 14b. XSS-Leak: Leaking Cross-Origin Redirects (entry 8)

- **Source:** Salvatore Abello — https://blog.babelo.xyz/posts/cross-site-subdomain-leak/
  (the post returned HTTP 403 when this entry was written, so the mechanism below is the
  Top 10 summary only). Not an XSS technique despite the name.
- **Oracle:** uses Chrome's connection-pool prioritisation algorithm as an oracle to leak
  the hostname a cross-origin redirect points to.
- **Status:** Chrome per the summary; exact versions and other engines **unverified**.
  The summary notes the result stays useful even if Chrome changes the algorithm, which
  also means it may already have.
- **Gate:** a connection-pool technique, so channel 7's cost table and Stage B sign-off
  apply unchanged.

---

## Decision table — pick the channel from the observed defence set

| Target serves | Dead channels | Try instead |
|---|---|---|
| `COOP: same-origin` | popup `window.length`, `history.length` via window, popup navigation detection | iframe variants if framing is allowed; error events; redirect-cap arithmetic |
| `XFO: DENY` / `frame-ancestors 'none'` | all iframe variants | popup variants (and remember a popup is a top-level navigation, so Lax cookies ride along) |
| Fetch-Metadata resource isolation enforced | error events, CORB/ORB oracle, subresource timing | GET-navigation-based channels only: redirect cap, URL length, history length |
| `SameSite=Strict` session cookie | every credentialed channel, including popups | nothing user-specific; re-scope to unauthenticated state leaks |
| Chrome 86+ / Firefox 85+ (any modern build) | cross-site cache probing | same-site/subdomain cache probing; non-cache channels |
| Chrome 136+ | `:visited` history sniffing | other engines, or drop the vector |

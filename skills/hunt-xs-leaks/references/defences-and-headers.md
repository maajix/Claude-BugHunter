# XS-Leak Defences, Headers and the 2026 Browser Baseline

Reference for `hunt-xs-leaks`. Two uses: decide which channels are even worth
trying against a given target, and write the remediation half of the report.

All version numbers and header values below were checked against primary sources
on **2026-10-10**. Items marked **unverified** could not be confirmed from a
source read that day; do not assert them.

---

## 1. Why the browser baseline decides the finding

An XS-Leak is a three-way agreement between the target's headers, the victim's
browser and the attacker's page. Change any one and the finding evaporates. The
single most common invalid report in this class is a technique reproduced in an
old or specially configured browser and then written up as if it worked
everywhere. Meta's XS-Leak payout guidelines say outright that a finding whose
root cause traces to an older browser version or a browser implementation mistake
is not rewarded. Assume every serious program holds the same line.

So: **pin the browser.** Record engine and full version with every measurement,
and re-run the oracle in a second engine before claiming it generalises.

## 2. Credential matrix — does the probe even carry a session?

Most XS-Leaks only leak *user-specific* state if the probe request carries the
victim's session cookie. This is the first thing to establish, because it kills
or saves half the catalog.

| Browser | Third-party cookies on subresources | Top-level cross-site GET navigation (popup) |
|---|---|---|
| Chrome / Chromium | Still available **only for `SameSite=None; Secure` cookies**: the Chromium Blog (2020-02, graduated rollout from 2020-02-17) states that from **Chrome 80** a cookie with no declared `SameSite` is treated as Lax, and only `SameSite=None; Secure` remains usable in third-party contexts. Google announced on **2025-04-22** that it keeps this setup — no phase-out, no standalone prompt, user choice in Privacy and Security settings. Incognito blocks third-party cookies by default. | Cookie is sent when it is `SameSite=Lax` or has no attribute, because MDN defines Lax as sent on a top-level navigation using a safe method. |
| Firefox | Partitioned. Dynamic state partitioning (Total Cookie Protection) is **default for all users since Firefox 103**; strict-mode users got it in 86 and private browsing in 90. A third-party cookie is keyed to the embedding top-level site, so it is not the victim's first-party session. | Same Lax rule applies. Firefox release has **not** shipped `SameSite=Lax` as the default for attribute-less cookies — only forum reports and Mozilla's 2020 "no timeline to ship" statement were found, so the current default is **unverified**; read `network.cookie.sameSite.laxByDefault` on the test build. |
| Safari / WebKit | Blocked. Safari 13.1 made full third-party cookie blocking the default via ITP. | Same Lax rule applies in principle; WebKit's exact handling is **unverified**. |

**Operational consequence:** against a modern target, iframe and subresource
probes are usually *unauthenticated* and leak only public state. The popup
(`window.open`) family is the one that still runs with the victim's session,
because it is a top-level navigation. That is why `COOP` and `SameSite=Strict`
are the two headers that most often close a real finding.

## 3. Network-state partitioning — what it already killed

| Engine | What is partitioned | Since |
|---|---|---|
| Chrome | HTTP cache, keyed by resource URL + Network Isolation Key, where the NIK is composed of the top-level site and the current-frame site, and a site is scheme + eTLD+1 | **Chrome 86** |
| Chrome | Socket-pool groups carry a `NetworkAnonymizationKey` when connection partitioning is enabled (`net/socket/client_socket_pool_manager.cc`); the per-pool soft cap is described as per network process. Default-on status in the current stable build: **unverified** | flag-gated |
| Chrome | `:visited` link history, keyed by link URL + top-level site + frame origin, with a self-links exception | **Chrome 136** (2025-04-02) |
| Firefox | HTTP cache, image cache, favicon cache, script cache, stylesheet cache, **connection pooling**, DNS, HTTP authentication, Alt-Svc, speculative connections, fonts and font cache, HSTS, OCSP, intermediate CA cache, TLS client certificates, TLS session identifiers, prefetch, preconnect, CORS-preflight cache, WebRTC deviceID, bfcache. MDN states this partitioning is permanent and sites cannot relax it | **Firefox 85** |

Read that Firefox list before planning any timing work: connection pooling and
DNS are on it, so the whole per-host socket-timing family is already partitioned
there.

## 4. Opt-in headers, with exact values

### `Cross-Origin-Opener-Policy` (COOP)

| Value | Effect |
|---|---|
| `unsafe-none` | Default. May share a browsing context group with any document. |
| `same-origin-allow-popups` | Shares a BCG only with same-origin documents, except that `window.open()` may retain a reference to a cross-origin `unsafe-none` document. The value to use when an OAuth or payment popup must keep talking to its opener. |
| `same-origin` | Shares a BCG only with same-origin documents that also send `same-origin`. Enables cross-origin isolation. |
| `noopener-allow-popups` | Opened into a new BCG unless navigated from a same-origin document with the same value; isolates even from a same-origin opener. The returned `WindowProxy` reports `closed === true`. |

MDN states that when a document lands in a new browsing context group, "any
references between the new document and its opener are severed" and
`window.opener` is unavailable. MDN does not spell out `window.length` behaviour
for a severed reference — that specific read is a derived expectation, so verify
it in the test build rather than asserting it.

**Recommend:** `same-origin` on every authenticated HTML response;
`same-origin-allow-popups` only on the specific endpoints that need an opener
channel.

### `Cross-Origin-Resource-Policy` (CORP)

Values: `same-site`, `same-origin`, `cross-origin`. Tells the browser to block
`no-cors` cross-origin or cross-site loads of the resource. This is the header
that closes the error-event and CORB/ORB oracles for non-public resources.

**Recommend:** `same-origin` on every authenticated non-public resource
(JSON APIs, user-specific images, exports).

### `Cross-Origin-Embedder-Policy` (COEP)

`require-corp` plus `COOP: same-origin` is what gives a document cross-origin
isolation. Cross-origin subresources then need an explicit CORP or CORS opt-in.
This is also the gate on `SharedArrayBuffer`: Firefox 79 shipped the restriction
first, Chrome desktop from Chrome 92 (Chrome Android 88), with an origin trial
that preserved old behaviour until at least Chrome 113.

### `X-Frame-Options` / `frame-ancestors`

`X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`
removes every iframe-based inclusion method. It does nothing against popups —
that is COOP's job. Note the second-order effect: *varying* XFO between states is
itself a leak bit, readable in Chromium via the performance buffer.

## 5. Fetch Metadata and the Resource Isolation Policy

Request headers: `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`,
`Sec-Fetch-User`. `Sec-Fetch-Site` takes exactly four values: `cross-site`,
`same-origin`, `same-site`, `none` (`none` meaning a user-originated action such
as typing a URL or opening a bookmark). MDN marks the family as Baseline "widely
available", available across browsers since March 2023.

The Resource Isolation Policy from the XS-Leaks Wiki, verbatim in logic:

**Allow** the request if any of these hold:
1. There is no `Sec-Fetch-Site` header (the browser does not send Fetch Metadata).
2. `Sec-Fetch-Site` is `same-origin`, `same-site` or `none`.
3. `Sec-Fetch-Mode` is `navigate` **and** the method is `GET` — this covers
   top-level navigations, including embeds.
4. The path is on an explicit exemption list (a CORS endpoint, `/favicon.png`).

**Reject** everything else, i.e. cross-site requests that are not simple GET
navigations.

Two things an agent must get right about this policy:

- It deliberately still allows cross-site GET navigations, so it does **not**
  close the navigation, redirect-cap, URL-length or popup-frame-count channels.
  Those need COOP and `SameSite`.
- If any of these responses are cacheable, the cache key must include the
  metadata: `Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest`. Without it a
  shared cache can serve the cross-site variant to a same-origin request or the
  reverse — which is a cache-key defect, owned by `hunt-cache-poison`.

## 6. Application-level mitigations that actually move the needle

Headers alone never close XS-Search. These do:

1. **Make the two states indistinguishable at the response level.** Same status
   code, same content type, same body length class, same header set, same frame
   count. If "no results" and "results" differ by one embedded frame, no header
   saves you.
2. **Require an unguessable token on state-dependent GETs.** A search endpoint
   that needs a per-session token in the query string cannot be probed
   cross-site at all, because the attacker cannot construct the URL.
3. **Do not vary redirects by state.** Redirect-count arithmetic reads a browser
   limit, not a credentialed response, so it survives every cookie policy.
4. **Separate eTLD+1 for user content.** Puts partitioning to work for you and is
   the only real answer to same-site cache probing.
5. **`Cache-Control: no-store` on state-dependent responses**, plus random tokens
   in user-specific resource URLs, as the cache-probing page recommends.
6. **Rate-limit per session, not per IP.** XS-Search needs hundreds to thousands
   of probe requests from the victim's browser; a per-session budget on the
   state-dependent endpoint turns a working extraction into a stalled one and
   produces a detection signal.

## 7. Remediation text for the report

Order the recommendations by what the finding actually used:

| Channel you proved | First recommendation | Second |
|---|---|---|
| Popup frame count / history length | `Cross-Origin-Opener-Policy: same-origin` | `SameSite=Strict` on the session cookie |
| Error events / CORB-ORB oracle | `Cross-Origin-Resource-Policy: same-origin` | Fetch-Metadata resource isolation + `Vary` |
| Performance-API header detection | Stop varying header presence by state | CORP |
| Redirect or URL-length detection | Make redirect behaviour state-independent | Per-session token on the endpoint |
| Same-site cache probing | `Cache-Control: no-store` + random token in the URL | Move user content to a separate eTLD+1 |
| Search-content extraction | Per-session token on the search endpoint | Per-session rate limit + alerting |

## 8. Sources read on 2026-10-10

- XS-Leaks Wiki: frame counting, error events, cache probing, connection pool,
  performance API, execution timing, navigations, CSS tricks, COOP defence,
  Fetch Metadata defence, resource isolation policy (`xsleaks.dev`).
- Chrome for Developers: "Making :visited more private" (Chrome 136, 2025-04-02);
  HTTP cache partitioning (Chrome 86); SharedArrayBuffer cross-origin isolation.
- MDN: State Partitioning; `Sec-Fetch-Site`; `Cross-Origin-Opener-Policy`;
  `Cross-Origin-Resource-Policy`; `Set-Cookie` (SameSite semantics).
- Chromium source: `net/socket/client_socket_pool_manager.cc` socket limits.
- Google Privacy Sandbox blog, 2025-04-22: third-party cookies retained.
- Chromium Blog, 2020-02: `SameSite=Lax` as the default from Chrome 80.
- MDN `PerformanceLongTaskTiming`: 50 ms long-task threshold, experimental.
- Chrome 78 deprecations and removals: XSS Auditor removed.
- RFC 6585 §5: `431 Request Header Fields Too Large`.
- Meta Bug Bounty XS-Leak payout guidelines (scope, exclusions, tiers).
- HackTricks XS-Search/XS-Leaks page (technique checklist only, CC BY-NC —
  coverage index, not copy source).

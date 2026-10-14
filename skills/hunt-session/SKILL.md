---
name: hunt-session
description: "Hunt Session Management vulnerabilities — session fixation (no regeneration on login), insufficient invalidation on logout / password-change / email-change, predictable or low-entropy session IDs, JWT-as-session with no exp/revocation, refresh-token rotation/reuse-detection gaps, OAuth/SSO session linkage, device-bound-session (DBSC) downgrade, and cookie attribute issues (Secure/HttpOnly/SameSite/__Host-). Also cookie integrity: cookie tossing from a controlled subdomain (fixation + CSRF-token overwrite delivery), cookie-prefix forgery through edge-vs-origin name-parsing differentials, the cookie sandwich HttpOnly bypass, and cookie jar overflow / cookie bomb handled as precondition-only DoS exposures. Validate with TWO real sessions (attacker A + victim B), body-diff every 200, and OOB confirmation for theft chains. Medium to Critical (fixation→admin hijack, no-invalidation→persistent ATO)."
sources: hackerone_public, portswigger_research, owasp_wstg, rfc6265bis, mdn_web_docs, mdn_browser_compat_data, chromium_source, gecko_source, ankursundara_research, hacktricks_coverage_checklist
report_count: 19
---

## Autonomous Testing Priority

**Missing HttpOnly on cookies is auto-detected — focus your active testing on lifecycle invalidation (higher impact).**

**Pattern 1 — Session survives logout (most common high-value finding):**
1. Login and note the session token/cookie value
2. Call the logout endpoint (`/logout`, `POST /api/logout`, etc.)
3. Try to use the OLD session token to access a protected resource (`/api/me`, `/dashboard`, `/account`)
4. If 200 with user data → session not invalidated on logout = ATO persistence

**Pattern 2 — Session not regenerated on login (session fixation):**
1. GET any page to receive a pre-authentication session token/cookie
2. POST valid credentials to the login endpoint
3. Compare the session token BEFORE and AFTER login
4. If the token is unchanged → session fixation vulnerability

**Pattern 3 — Session survives password change:**
1. Login → record session A value
2. Change the password via the account settings endpoint
3. Replay session A on a protected endpoint
4. If 200 → token not rotated on credential change = persistent ATO (critical chain when combined with XSS/cookie theft)

**Content-type:** Login and session endpoints vary — use `application/json` for REST APIs, `application/x-www-form-urlencoded` for traditional web forms. Try both if the first returns an unexpected response.

**Proof:** A protected-resource 200 response (with user data) using a session token that should have been invalidated confirms the finding.

---

# HUNT-SESSION — Session Management

## Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session surviving a password change = High-to-Critical (persistent ATO from a stolen cookie that the victim believes they revoked by resetting their password).

**Highest-value chains:**
- **Session fixation** — server accepts a session ID set by the client and does NOT regenerate it on login → attacker pre-plants an ID, victim authenticates, attacker rides the now-authenticated session → persistent ATO.
- **No invalidation on logout** — old token still works after `/logout` → theft window never closes.
- **No invalidation on password / email change** — a stolen session survives the victim's "I think I was hacked, let me reset" → persistent ATO. This is the single highest-paid session bug class.
- **Refresh-token reuse without rotation-detection** — a leaked refresh token mints fresh access tokens forever; no reuse-detection means the legitimate user's later refresh does NOT revoke the attacker's branch.
- **Predictable / low-entropy session ID** — sequential, timestamp- or userId-derived IDs → brute-force or compute other users' sessions.
- **JWT-as-session with no `exp` / no revocation list** — stolen JWT = permanent access; logout is cosmetic.

---

## Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — binds a session to a TPM/device key; specified in the W3C WebAppSec WG ([w3c.github.io/webappsec-dbsc](https://w3c.github.io/webappsec-dbsc/)). No longer just a draft in practice: [public availability on Chrome 146 for Windows](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/) (Apr 2026, macOS announced as upcoming) and [GA, on by default for Google Workspace](https://workspaceupdates.googleblog.com/2026/05/prevent-account-takeovers-with-DBSC-now-generally-available-in-the-Chrome-browser-for-Windows.html) (rollout from May 25 2026). Third-party RPs still opt in, so most targets accept plain cookies. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped, or from a non-Windows / non-Chrome client?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `hunt-xss`/`hunt-dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.
- **Cookie integrity (tossing, prefixes, parser differentials, jar limits)** — RFC 6265bis sections 4.1.3 (prefixes), 4.2.2 (serialization order is not a guarantee), 5.6 (no percent-decoding, WSP trimming) and 5.7 (Secure-cookie protection, nameless-prefix rule); the per-domain eviction constants read from Chromium `cookie_monster.cc` and Firefox `CookieStorage.cpp`; PortSwigger's cookie-sandwich research for the quoted-value HttpOnly bypass. Phases 9-11 below; depth in `references/cookie-integrity.md`.

Cross-refs: ATO chaining → `hunt-ato`; JWT alg/kid/key-confusion tampering → `hunt-jwt-crypto`; OAuth code/state flaws → `hunt-oauth`; CSRF mechanics → `hunt-csrf`; cookie-theft sinks → `hunt-xss` / `hunt-dom`.

---

## Attack Surface Signals

```
Set-Cookie: session=...            # name varies: sid, JSESSIONID, connect.sid,
                                   # PHPSESSID, ASP.NET_SessionId, laravel_session, _csrf
/login /logout /api/login /oauth/token
/auth/refresh /api/token/refresh   # refresh-token rotation surface
/account/change-password /settings/email
?sid= ?session= in URL             # session-in-URL → leaks via Referer/logs (finding)
```
```
# Header signals worth flagging immediately:
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure = rejected by modern browsers, but flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
Set-Cookie: csrf=abc; Domain=.target.example    # Domain-scoped → tossable from any subdomain (Phase 9)
Set-Cookie: sess=abc; Path=/app                 # Path-scoped → a more specific Path takes position 1
Cookie: sess=A; sess=B                          # duplicate name reaching the origin → parser differential (Phase 10)
```

---

## Step-by-Step Hunting Methodology

> **Two-session rule.** Every invalidation/fixation claim is proven with TWO concrete sessions captured by a real flow — attacker **A** and victim **B** — never with hardcoded placeholder strings. Helpers below capture real cookies from `curl`'s Netscape jar.

```bash
TARGET=target.example
JAR_A=$(mktemp); JAR_B=$(mktemp)

# Robust session-cookie extractor: handles #HttpOnly_ prefix lines and any
# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/...). Prints name=value.
get_cookie () {  # $1=jar  $2=name-regex (default: common session names)
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|laravel_session}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }   # strip jar HttpOnly marker
    /^#/ { next }                              # skip remaining comments
    NF>=7 && $6 ~ re { print $6"="$7 }         # field6=name field7=value
  ' "$jar" | tail -1
}
```

### Phase 1 — Session Fixation (regeneration-on-login)
```bash
# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"

# Step 1b (stronger): can we FORCE an arbitrary ID? attacker-chosen value.
FIX="session=AAAAdeadbeefAAAA"

# Step 2: authenticate while CARRYING the pre-auth/forced cookie (reuse same jar).
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"

# DECISION:
#  - If $POST == $PRE (value unchanged across the auth boundary) AND that value
#    now returns authenticated data → FIXATION. The server reused the anon ID.
#  - If the forced $FIX value is accepted and authenticates → CRITICAL fixation
#    (attacker controls the ID; no email/XSS needed to plant it).
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side session keyed by a second cookie. Diff the FULL `Set-Cookie` set and confirm the *old* value is genuinely dead (Phase 2). Also confirm `/api/me` returns *your* identity, not a generic 200/landing page.

### Phase 2 — Invalidation on Logout
```bash
# A logs in for real (fresh jar), capture A's live session.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"

# Baseline: what does an authenticated /api/me look like for A? (capture body, not just code)
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")

# Logout A.
curl -s -L -b "$JAR_A" -X POST "https://$TARGET/api/logout" -o /dev/null

# Replay A's OLD cookie value explicitly (do NOT reuse the jar — logout may have
# overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER: $AFTER"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or a generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — the finding is only real if `AFTER` still contains A's *unique identity marker* (email, user-id, CSRF token, account name).
- Confirm with a **negative control**: a random/garbage cookie value must NOT return the same authenticated body. If garbage also yields 200 with user data, the endpoint isn't session-gated and there's no finding here.
- Re-test after a **short delay** and from a **different IP** — some servers lazily expire on next access or pin sessions to IP.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)
```bash
# This is the real two-session flow. A = attacker holding a stolen/old session.
# B = the victim who changes their password believing it revokes access.
# (In a real engagement A is a session you legitimately captured for a TEST account
#  that you also control as B — never use a real third party.)

# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `hunt-ato` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `hunt-mfa-bypass`), A can pivot from read-only to full takeover → escalate.

### Phase 4 — Cookie Attribute Analysis
```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`hunt-xss`/`hunt-dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `hunt-tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `hunt-csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.

### Phase 5 — Session-ID Entropy
```bash
# Collect a LARGE sample (200+) of freshly-issued IDs. -L is required: a 302
# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic (re-use)
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c   # length distribution
```
Then analyse, don't eyeball:
- **Sequential / monotonic** — `sort -n` the decoded values; a steady +1/+N delta = predictable.
- **Decodable structure** — `base64 -d` / hex-decode each ID and look for embedded `userId`, unix timestamps, or PIDs.
- **Bit entropy** — feed the raw bytes to `ent` or `dieharder`; NIST SP 800-63B wants ≥64 bits. 10 samples is far too few to claim anything — gather hundreds.
- **FP guard:** a long random-*looking* token is not proof of strength; only structural decode + a large-sample entropy estimate is. Conversely a short token with high per-char entropy may still be fine — measure, don't count characters.

### Phase 6 — JWT-as-Session
```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie
# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `hunt-jwt-crypto`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.

### Phase 7 — Refresh-Token Rotation & Reuse-Detection
```bash
# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')

# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"

# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"

# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates
#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `hunt-ssrf`/`hunt-source-leak`, not by guessing.

### Phase 8 — OAuth/SSO Session Linkage & DBSC Downgrade
```bash
# SSO linkage: after IdP callback, is the app session bound to the IdP session?
#  - Log out at the IdP only; replay the app session cookie. Still 200 with user
#    data → app session outlives the IdP session (single-logout gap).
# DBSC downgrade: if responses carry Sec-Session-Registration / Sec-Session-Id,
#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,
#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `hunt-oauth`; this phase only covers the *session-layer* binding.

### Phase 9 — Cookie Tossing (a subdomain writes a cookie that shadows the parent's)

**Authorization first.** Tossing requires the ability to set a cookie on a host
inside the target's registrable domain: a subdomain you took over, a
user-content subdomain, or a subdomain with its own XSS. That control is a scope
question, not a technicality. Confirm the subdomain is in scope before you test,
and get the takeover itself proven and reported through `hunt-subdomain` (which
owns the takeover precondition and already notes cookie-domain bleed as impact).
If the user-content host sits on a *separate* registrable domain or a public
suffix, tossing is impossible and there is nothing to test.

The mechanics, and the two spec rules that decide feasibility:
- A response may set `Domain` to its own host or a **parent** domain, never a
  sibling and never a public suffix. So `evil.$TARGET` can write a cookie scoped
  to `$TARGET`, which the victim's browser then sends to the parent app.
  Leading dots (`.example.com`) are ignored, they are not a scoping trick.
- The parent's own cookie is **not replaced**: both are sent. RFC 6265 ordered
  matching cookies by descending `Path` length, which is why the attacker sets a
  **more specific `Path`** to take position one. RFC 6265bis 4.2.2 says servers
  "SHOULD NOT rely upon the serialization order", so which value wins is a
  property of the target's parser, measured in Phase 10, not assumed.
- A subdomain reachable only over plain HTTP cannot toss over a `Secure` cookie:
  6265bis 5.7 step 16 rejects that write. The tossing host needs HTTPS.

**The escalations are the point** (ordered by what they pay):
1. **Session fixation.** Toss a session cookie the attacker knows, wait for the
   victim to authenticate on it, then ride it. Prove it with the Phase 1 boundary
   check: the tossed value must survive the auth boundary and return the victim's
   identity. Severity follows Phase 1.
2. **CSRF-token overwrite.** Where the token is carried in a cookie
   (double-submit, or a framework that seeds it from one), a tossed cookie makes
   the attacker's token the one the server validates. **Tossing is only the
   delivery mechanism here.** `hunt-csrf` owns the token mechanics, the forgery
   proof and the severity, and already covers `Domain=`-scoped BFF session
   cookies. Hand it over with the tossing precondition attached.
3. **Session donation.** The victim keeps using the site inside the attacker's
   session and types data (searches, addresses, payment details) into an account
   the attacker can read. Narrow `Path` scoping makes this partial and quiet:
   the victim is themselves everywhere except the one path you scoped.

**Never capture the victim's own cookie value.** Proof is that the
*attacker-controlled* cookie reaches the server and changes its behaviour,
demonstrated between two accounts the tester owns: account A writes the cookie,
account B's requests act on it.

**Fix, and where it does not apply.** `__Host-` is the real fix: it forces
`Secure`, `Path=/` and **no `Domain`**, making the cookie host-only, so no
subdomain can create it for the parent (Chrome 49, Firefox 50, Safari 13).
`__Secure-` does not help, it constrains transport only. A cookie that is
*deliberately* `Domain`-scoped so several hosts can read it cannot be defended
this way at all: `Domain=$TARGET` is by definition writable by every subdomain
and is incompatible with `__Host-`. For that design the remediation to recommend
is server-side: bind the session to a server-side record, reject requests
carrying duplicate names for a security cookie, or issue per-host cookies and
exchange a token between them. Say this explicitly in the report, because
"add `__Host-`" is wrong advice for a shared-login architecture.

### Phase 10 — Cookie Prefix Integrity & Parser Differentials (edge vs origin)

`__Host-` only holds if the server reads the cookie name **byte-exact**. The
browser hands over raw octets: 6265bis 5.6 strips only leading and trailing WSP
and states a UA "MUST NOT decode" percent-escapes. Any trimming, decoding or
legacy parsing the origin adds on top is a differential it owns, and a
differential between the **edge/WAF and the origin** is where the real bugs are:
one side validates a name, the other acts on a different one.

```bash
# A FRESH cache-buster per request: a shared one lets an edge keyed on URL alone
# replay probe 1's body as probe 2's answer, which fakes the precedence result.
cb(){ echo "cb=$RANDOM$RANDOM$(date +%s%N)"; }
# Duplicate precedence: which of two tester-owned sessions does the origin act on?
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: sess=$A; sess=$B" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: sess=$B; sess=$A" | head -c 200
# Prefix forgery: percent-encoded name, leading NBSP (U+00A0), legacy $Version mode
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: %5F%5FHost-sess=$B; __Host-sess=$A" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H $'Cookie:  __Host-sess='"$B; __Host-sess=$A" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: \$Version=1; __Host-sess=$B; __Host-sess=$A" | head -c 200
```
- **Prefix family (state these exactly).** `__Secure-` needs `Secure`;
  `__Host-` needs `Secure` + `Path=/` + no `Domain`; `__Http-` needs `Secure` +
  `HttpOnly`, so it cannot be set from script at all; `__Host-Http-` combines
  both. `__Http-`/`__Host-Http-` are Chrome 140 and Firefox 143 (Firefox 142
  shipped the name `__HostHttp-`), **not supported in Safari**, and they are not
  in the 6265bis draft, which defines only the first two.
- **Nameless forgery is closed in-spec**: 6265bis 5.7 step 22 drops a cookie
  whose name is empty and whose value starts with `__Secure-`/`__Host-`. Test it
  anyway against the *server*, which may still concatenate it into a usable pair.
- **Cookie sandwich** (`$Version=1`, an unterminated quoted value, then a closing
  one) traps the victim's cookie inside an attacker-named value on legacy or
  quoted-string parsers. Where the application reflects that value, it is an
  **HttpOnly bypass**, worth a report even when tossing is not available. Full
  walkthrough, the named stacks and the local parser evidence are in
  `references/cookie-integrity.md`. **Own session only:** demonstrate it in your
  own browser with your own test account, where the proof is *your* HttpOnly
  value appearing in the reflected response. Never deliver the payload to another
  user and never add an exfiltration step to it.
- **Report it as a differential, not as a framework fact.** Versions move. Run
  each probe against the edge hostname and, where scope allows, the origin
  directly, and show the two answers side by side.

### Phase 11 — Cookie Jar Overflow and Cookie Bomb (precondition-first, DoS-gated)

Both of these techniques can take a real person's access away. A cookie bomb
makes the victim's own requests too large for the server to accept, which locks
that user out of the site until the cookies expire. A jar overflow evicts
cookies from a browser profile, which can destroy a live session or a security
flag belonging to whoever owns that profile. Neither one is ever run against a
third party, a shared domain, or any account that is not the tester's own. The
default engagement, and usually the whole engagement, is to prove the
**precondition** and report that: a cookie-write primitive such as unbounded
reflection into `Set-Cookie`, a subdomain you can write parent-scoped cookies
on, a security cookie that lacks the prefix that would protect it, or the
request-size threshold the origin already advertises. A precondition plus a
described impact is a complete, payable report. Any step that actually evicts or
oversizes cookies is **Stage B**: the tester's own browser profile, the tester's
own account, explicit written sign-off, a named window, and a cleanup step that
clears the jar and confirms normal service returned. The Stage B runbooks,
including the mandatory cleanup, are in `references/cookie-integrity.md`
section 5.

**Stage A (always allowed) — recognise and report the exposure:**
```bash
# 1) Is there a cookie-write primitive at all? Short canary, no oversizing.
curl -sI "https://$TARGET/?lang=AAAAAcanary123" | grep -i '^set-cookie'
# 2) Which security cookies are unprotected against eviction/re-creation?
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie' | grep -iv '__Host-Http-\|__Http-'
```
- **Eviction facts, stated with the browser** (full table and the in-source
  eviction order in `references/cookie-integrity.md` section 1). Chromium:
  `kDomainMaxCookies = 180` per domain key, purged back to 150
  (`kDomainPurgeCookies = 30`), 3300/300 for the whole store, and domain
  collection runs least-recently-accessed first in six rounds that protect
  secure cookies before non-secure ones. Firefox:
  `network.cookie.maxPerHost = 180` evicting down to
  `network.cookie.quotaPerHost = 150`, expired cookies first, then
  least-recently-accessed. Safari's limits are **unverified here, do not quote a
  number for it.**
- **Gate 0 consequences.** In both engines a non-`Secure` flood cannot evict a
  `Secure` cookie, so overflow against a `Secure` session needs an HTTPS writer
  setting `Secure` junk. In Chromium `Priority=High` pushes the target into the
  last purge round. `__Host-` does **not** stop re-creation after eviction,
  because same-host HTTPS script may legitimately set
  `__Host-x=1; Secure; Path=/`; only `__Http-`/`__Host-Http-` do, since script
  cannot set `HttpOnly`. Overflow also needs script in the target origin, which
  normally means an XSS that is already the bigger report.
- **Size facts.** 6265bis ignores a cookie whose name plus value exceeds 4096
  octets and an attribute value over 1024 octets, and notes 8192 octets as a
  common header-size default. "A limit exists" is therefore not a finding; the
  fillable jar is.
- **Loop bounds for Stage B, split by technique** (the two need opposite shapes;
  the bomb's small-request budget would never reach a 180-cookie jar).
  *Overflow:* one synchronous JS loop in your own profile, no sleep, hard cap of
  200 writes (engine limit plus margin), `Max-Age` 60 seconds or less, stop at
  the plateau, then **one** server request to read the effect, then clean up.
  *Bomb:* a handful of cookies near the 4096-octet ceiling, bisected serially
  with `sleep 1` and a hard cap of 6 requests, stopping at the first rejection.
  Both use the narrowest `Path` that reproduces the effect.
- **Ownership, so nobody runs this twice.** `hunt-xs-leaks` owns the cookie bomb
  as a *cross-site oracle* and already gates it in
  `references/leak-channel-catalog.md` section 9; do not duplicate that work.
  `hunt-session` owns it only as a *single-user DoS exposure* reported from its
  precondition. A cached 400/431 that denies every user of a path is
  cache-poisoned DoS and belongs to `hunt-cache-poison`. Publicly disclosed
  example of the class: [HackerOne 57356, "DOM based cookie bomb"](https://hackerone.com/reports/57356).

---

## Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `hunt-xss`/`hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |
| Controlled subdomain + `Domain`-scoped session cookie | Toss a known session ID, victim authenticates on it | Session fixation → ATO (`hunt-subdomain` for the takeover) |
| Controlled subdomain + cookie-borne CSRF token | Toss the token, then forge a state change | CSRF; `hunt-csrf` owns the token mechanics and severity |
| Origin trims/decodes cookie names, edge does not | Forge a `__Host-`/`__Secure-` name the origin accepts | Prefix protection defeated → tossing works despite the prefix |
| Reflected cookie + quoted-value parser | Cookie sandwich traps the session value in a reflected cookie | HttpOnly bypass → session theft |
| Cookie-write primitive, no `__Http-`/`__Host-Http-` | Evict then re-create a security cookie from script | Weaker server path; Stage B only, own profile |
| Cookie-write primitive + origin header-size limit | Oversized `Cookie` rejected for that user | Single-user DoS exposure (report precondition; `hunt-cache-poison` if cacheable) |

---

## Validation (house FP discipline)

Before claiming ANY session finding:
- **Two real sessions, not placeholders** — every fixation/invalidation claim uses A and B captured by the `curl` flows above.
- **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker present in the body, diffed against the authenticated baseline.
- **Negative control** — a garbage/random cookie must FAIL where your "surviving" cookie succeeds; otherwise the endpoint isn't session-gated and it's a non-finding.
- **Cache/edge check** — re-request with a cache-buster and from a second IP; rule out an edge-cached or IP-pinned 200.
- **OOB for theft chains** — when the impact depends on exfiltrating a cookie/token (XSS, SSRF, log leak), confirm receipt out-of-band (Collaborator) rather than asserting it.
- **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, network-MITM, CSRF). Standalone attribute gaps are Low/Informational.
- **Tossing needs a named writer** — "a subdomain could set this cookie" is not a finding. Name the host you control, how you got it (in-scope takeover or user-content origin), and show the parent app acting on the cookie you wrote. A tossed cookie is same-site, so `SameSite` offers no protection and must not be cited as one.
- **Never the victim's value** — prove the attacker-controlled cookie reaches the server and changes its behaviour, between two accounts you own. A report that quotes someone else's session value is out of scope, not stronger.
- **Parser claims are per-target** — state which stack you observed and the probe that showed it, never a framework's reputation. Re-run through the edge and the origin; the differential between them is the finding.
- **DoS primitives are precondition-only by default** — for cookie bomb and jar overflow, the deliverable is the write primitive plus the described impact unless Stage B sign-off exists. If Stage B ran, the report must contain the cleanup confirmation that normal service returned.

**Severity:**
- Session fixation → admin/SSO takeover: **Critical**
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up also absent)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained
- Cookie tossing proven into fixation or a cookie-borne CSRF token: **High → Critical** (severity follows the primitive it delivers, so route the CSRF half to `hunt-csrf`)
- Prefix forgery via a server-side name differential (`__Host-` defeated): **High** (it removes the control the app relies on)
- Cookie sandwich reflecting a session cookie: **High** (HttpOnly bypass → theft)
- Cookie-bomb / jar-overflow precondition, impact described but not executed: **Low → Medium** (single-user DoS; raise only with a sign-off-backed demonstration)

---

## Reference Files

| File | Coverage | Trigger phrases |
|---|---|---|
| `cookie-integrity.md` | Verified per-domain cookie limits and in-source eviction order for Chromium and Firefox; the four-prefix table with Chrome/Firefox/Safari support versions; the RFC 6265bis rules that decide tossing feasibility (Secure-cookie protection, nameless-prefix rule, WSP/percent-decoding, ordering, size limits); parser-differential matrix of named stacks with the exact header to send; cookie-sandwich walkthrough plus locally verified stdlib parser evidence; Stage B runbooks with mandatory cleanup for jar overflow and cookie-bomb exposure; dated source list | cookie tossing, cookie jar overflow, cookie bomb, cookie sandwich, `__Host-`, `__Secure-`, `__Http-`, `__Host-Http-`, prefix bypass, prefix forgery, cookie parser differential, duplicate cookie name, `$Version=1`, RFC 2109, quoted cookie value, cookie eviction, maxPerHost, quotaPerHost, kDomainMaxCookies, CHIPS partition limit, HttpOnly bypass via cookie |

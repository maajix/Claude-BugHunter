# Cookie Integrity Reference — tossing, prefixes, parser differentials, jar limits

Depth behind `SKILL.md` Phases 9-11. Every number below was read from a primary
source on 2026-10-11; the fetch target is named so it can be re-checked when it
moves. Browser limits are **version-specific**: never quote a bare number,
always quote browser plus number plus the file it came from.

---

## 1. Per-domain cookie limits and eviction order (verified)

| Engine | Limit | Value | Source read 2026-10-11 |
|---|---|---|---|
| Chromium | `kDomainMaxCookies` | 180 per domain key | `net/cookies/cookie_monster.cc`, `refs/heads/main` |
| Chromium | `kDomainPurgeCookies` | 30 (so a domain over 180 is purged back to 150) | same file |
| Chromium | `kMaxCookies` / `kPurgeCookies` | 3300 / 300 for the whole store | same file |
| Chromium | `kPerPartitionDomainMaxCookies` / `...MaxCookieBytes` | 180 / 10240 bytes per CHIPS partition | same file |
| Chromium | `kDomainCookiesQuotaLow` / `Medium` / `High` | 30 / 50 / 70 (high = 180 - 30 - 30 - 50) | same file |
| Chromium | `kSafeFromGlobalPurgeDays` | 30 days, and the header comment states it protects against **global** GC only, "This does not affect domain garbage collection" | `net/cookies/cookie_monster.h` |
| Firefox | `network.cookie.maxPerHost` | 180 | `modules/libpref/init/all.js`, searchfox `firefox-main` |
| Firefox | `network.cookie.quotaPerHost` (`kCookieQuotaPerHost`) | 150, the level eviction drops back to | `netwerk/cookie/CookieCommons.h` + `CookieService.cpp` |
| Firefox | `network.cookie.maxNumber` | 3000 for the whole store | `modules/libpref/init/all.js` |
| Safari / WebKit | per-domain count | **unverified** - not read this session, do not state a number | n/a |

### Chromium domain eviction order

`CookieMonster::GarbageCollect` expires cookies first, then sorts the survivors
least-recently-accessed first (`LRACookieSorter`) and purges in six rounds,
quoting the in-source comment order:

1. Low-priority non-secure
2. Low-priority secure
3. Medium-priority non-secure
4. High-priority non-secure
5. Medium-priority secure
6. High-priority secure

Two consequences for testing. A **non-Secure flood cannot reach a Secure
cookie** until every non-secure candidate above it is gone, because rounds 1, 3
and 4 run with `protect_secure_cookies = true`. And `Priority=High` on the
target session cookie moves it into the final round, so a hardened app is
materially harder to overflow.

### Firefox domain eviction order

`CookieStorage::AddCookie` calls `FindStaleCookies` with `aSecure = false`
first, so only non-secure cookies are eviction candidates. If none are found the
code comments state the two outcomes exactly: `It's valid to evict a secure
cookie for another secure cookie` (so the retry happens only when the *incoming*
cookie is itself Secure), otherwise `Too many cookies for this domain and the
new cookie is not a secure cookie` and the **new** cookie is dropped instead.
Candidate ordering is expired cookies first, then `CompareCookiesByAge`, which
compares `LastAccessed` and tiebreaks on `CreationTime`.

**Net rule for both engines:** overflowing a Secure session cookie requires an
HTTPS writer that sets Secure junk cookies. Junk set over plain HTTP, or without
`Secure`, will not evict it.

---

## 2. Cookie name prefixes (exact requirements and support)

Requirements per MDN `Set-Cookie`; support versions per `mdn/browser-compat-data`
(`http/headers/Set-Cookie.json`, `main`), both read 2026-10-11.

| Prefix | Requirements | Chrome | Firefox | Safari |
|---|---|---|---|---|
| `__Secure-` | set from HTTPS with `Secure` | 49 | 50 | 13 |
| `__Host-` | `Secure`, from HTTPS, **no `Domain`**, `Path=/` | 49 | 50 | 13 |
| `__Http-` | `Secure` **and `HttpOnly`**, so only settable via `Set-Cookie` | 140 | 143 | not supported |
| `__Host-Http-` | the `__Http-` rules plus the `__Host-` rules | 140 | 143 (142 shipped it as `__HostHttp-`, renamed in 143, bugzil.la/1982555) | not supported |

RFC 6265bis (`draft-ietf-httpbis-rfc6265bis-latest`, 7 October 2026) defines
**only** `__Secure-` (4.1.3.1) and `__Host-` (4.1.3.2). The `__Http-` family is
browser-documented, not in that draft. Prefix matching is case-insensitive:
section 5.4 states "UAs MUST match the prefix string case-insensitively".

MDN's own caveat matters for reporting: "You cannot count on these additional
assurances on browsers that don't support cookie prefixes; in such cases,
prefixed cookies will always be accepted."

### Which prefix stops which attack

- **Tossing from a subdomain:** `__Host-` stops it, because the cookie must be
  host-only and no sibling or child host can create a host-only cookie for the
  parent. `__Secure-` does **not** stop it: it constrains the transport only.
- **Script re-creation after eviction:** `__Host-` does **not** stop it. Script
  on an HTTPS page of the same host can legitimately set
  `__Host-x=...; Secure; Path=/`. Only `__Http-` and `__Host-Http-` stop it,
  because the required `HttpOnly` attribute cannot be set from `document.cookie`
  or the Cookie Store API.

---

## 3. Spec rules that decide whether tossing is even possible

All from RFC 6265bis, read 2026-10-11:

- **Who may set a `Domain` cookie** (MDN wording, same rule): the value "must be
  the domain of the server that sends the `Set-Cookie` response header, or a
  parent domain of that server's domain. It cannot be a public suffix". So
  `api.example.com` may set `Domain=example.com`, but not
  `Domain=other.example.com`.
- Leading dots are not a scoping trick: MDN states "Contrary to earlier
  specifications, leading dots in domain names (`.example.com`) are ignored".
- **Non-secure origin against a Secure cookie:** section 5.7 step 16 rejects the
  write when a stored matching cookie has `secure-only-flag` true, and Appendix A
  summarises it as "Prohibits non-secure origins from setting cookies with a
  `Secure` flag or overwriting cookies with this flag". A taken-over subdomain
  that only serves HTTP therefore cannot toss over a Secure session cookie.
- **Nameless prefix forgery is closed in the spec:** section 5.7 step 22 ignores
  a cookie entirely when the name is empty and the value begins with a
  case-insensitive `__Secure-` or `__Host-`.
- **Whitespace and encoding:** section 5.6 step 4 removes leading and trailing
  WSP from name and value, and the same section states a user agent "MUST NOT
  decode" percent-encoded sequences. The browser therefore hands the origin raw
  octets; any trimming or decoding the origin adds is a differential it owns.
- **Ordering is not a guarantee:** section 4.2.2 says servers "SHOULD NOT rely
  upon the serialization order". RFC 6265 ordered matching cookies by descending
  path length then ascending creation time, which is why a more specific `Path`
  is the attacker's positioning lever.
- **Sizes:** ignore a cookie whose name plus value exceeds 4096 octets (5.7 step
  4); ignore an attribute value longer than 1024 octets (5.6 step 6); section
  4.2.1 notes implementations commonly default to an 8192-octet header limit.
- The per-domain count is **not** a spec requirement. Section 5.7 only says a UA
  MAY evict above an implementation-defined bound, "such as 50 cookies", with
  "such as 3000 cookies" for the whole store. The real numbers are in section 1.

---

## 4. Parser differential matrix

Server-side quirks documented by Ankur Sundara's cookie-bugs research and
PortSwigger's cookie-sandwich research (both read 2026-10-11). Treat the stack
column as **where to look**, never as a finding: confirm against the target
build, because versions move.

| Quirk | Named stacks | What to send |
|---|---|---|
| Quoted value swallows following cookies | Jetty (CVE-2023-26049), Tomcat, Undertow, Zope, Python stdlib `SimpleCookie`/`BaseCookie` and its users (cherrypy, web.py, aiohttp, bottle, webob) | `RENDER_TEXT="hello world; JSESSIONID=13371337; ASDF=end"` |
| New cookie starts after a closing quote, no `;` needed | Undertow | `LANGUAGE="en-us" CSRF_TOKEN="SPOOFED_VALUE"` |
| Comma treated as a cookie delimiter | Zope | `LANGUAGE=en-us,CSRF_TOKEN=SPOOFED_VALUE` |
| Space treated as a cookie delimiter | Python stdlib cookie classes | `LANGUAGE=en-us CSRF_TOKEN=SPOOFED_VALUE` |
| Duplicate name resolved last-wins | Python stdlib cookie classes, Django (`parse_cookie()` assigns into a dict, so the last chunk wins) | two cookies that normalise to one name |
| Legacy RFC 2109 mode switched on by a leading `$Version` | Tomcat (PortSwigger names 8.5.x, 9.0.x and 10.0.x as supporting RFC 2109 by default); the same research notes Python frameworks need no `$Version` | `$Version=1` as the first pair |
| Leading Unicode whitespace trimmed server-side, forging a prefix | any stack that trims names; Django's `parse_cookie()` calls `key.strip()` | name prefixed with U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F or U+3000 |

Verified by reading the code and running it, 2026-10-11, Python 3.12.3:

```
# stdlib http.cookies.SimpleCookie (not a framework)
load('a=first; a=second')                            -> {'a': 'second'}      # last wins
load('$Version=1; p="start; sess=SECRET; q=end"')    -> {'p': 'start; sess=SECRET; q=end'}

# str.isspace() is true for every code point in the trim list above, so a
# leading one of them is removed by str.strip():
[hex(c) for c in range(0x110000) if chr(c).isspace()]
  -> ... 0x85, 0xa0, 0x1680, 0x2000..0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000

# django/http/cookie.py (main branch): splits on ';', then
#   key, val = key.strip(), val.strip()
#   cookiedict[key] = cookies._unquote(val)
# so Django both trims the name and resolves duplicates last-wins.
```

Safari's handling of multibyte whitespace in cookie names is **unverified**:
cross-test rather than assuming a browser will refuse to set the name.

The second line is the cookie sandwich: the victim's cookie has been absorbed
into an attacker-named value that the application may reflect.

### Cookie sandwich, as published

PortSwigger's technique sets three cookies so that a legacy or quoted-string
parser treats the span between them as one value:

```javascript
document.cookie = `$Version=1;`;
document.cookie = `param1="start`;
document.cookie = `param2=end";`;
```

On the wire that becomes
`Cookie: $Version=1; param1="start; sess=<victim>; param2=end"`. Preconditions
are a cookie-write primitive on the origin, a cookie whose value the application
reflects back, and control of ordering, which the research achieved by giving
`$Version` a longer `Path`. Because the victim's value lands inside a reflected
parameter, **this is an HttpOnly bypass**, which is the reason the technique is
worth a report even where tossing is not.

**Own session only.** Run the sandwich in your own browser against your own test
account, and let the proof be *your* HttpOnly value appearing in the reflected
response. Never deliver the payload to another user, and never bolt an
exfiltration step onto it: the reflection itself is the finding.

### Measurement without a subdomain

Two sessions of **tester-owned accounts**, no victim involved, cache-buster on
every request. These probes assert nothing about the framework; they read the
target's own precedence:

```bash
# One fresh cache-buster PER REQUEST. A single shared value leaves two probes on
# the same URL, so an edge keyed on URL alone replays the first body for the
# second probe and the precedence you read is the cache's, not the origin's.
cb(){ echo "cb=$RANDOM$RANDOM$(date +%s%N)"; }
# Precedence: which duplicate does the origin act on?
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: sess=$A; sess=$B" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: sess=$B; sess=$A" | head -c 200
# Prefix integrity: does the origin decode, trim, or legacy-parse the name?
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: %5F%5FHost-sess=$B; __Host-sess=$A" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H $'Cookie:  __Host-sess='"$B; __Host-sess=$A" | head -c 200
curl -s "https://$TARGET/api/me?$(cb)" -H "Cookie: \$Version=1; __Host-sess=$B; __Host-sess=$A" | head -c 200
```

Read the **identity in the body**, not the status code. The finding is a
differential: the edge or WAF validates one view of the name and the origin acts
on another. Run each probe against the edge hostname and, where scope allows it,
against the origin directly, and compare.

---

## 5. Stage B runbooks (own browser, own account, written sign-off)

Both procedures below can deny service. They run only on the tester's own
browser profile and the tester's own account, inside a named window the operator
signed off on in writing, and each ends with its cleanup verified. If sign-off is
absent, the deliverable is the Stage A precondition and nothing else.

### 5a. Jar overflow against your own session

Preconditions to record before touching anything: the target cookie's exact
`name`, `Path`, `Domain` or host-only status, `Secure`, `Priority`, `Partitioned`
and prefix, captured from the real `Set-Cookie`. Overflow needs script execution
in the target origin, so the primitive is normally an XSS that is itself the
report.

1. Count the baseline in the profile first. `document.cookie` shows non-HttpOnly
   cookies only, so a plateau there is a lower bound, not the jar size.
2. Set junk in **one synchronous loop with no sleep**, hard-capped at 200 writes
   (the 180-per-domain engine limit plus margin). Writes to `document.cookie` are
   local, so nothing is sent to the server while the loop runs and the loop
   finishes in milliseconds. Mirror the target's `Secure` flag, because
   non-secure junk cannot evict a Secure cookie in either engine. Keep `Max-Age`
   at 60 seconds or less so the profile self-heals even if cleanup is
   interrupted. Do not reuse the cookie-bomb budget here: a 40-write,
   one-per-second loop cannot reach a 180-cookie jar.
3. Stop at the first signal: the target cookie absent from the next request, or
   the visible count failing to grow. Do not keep going "to see how far it goes".
4. Prove the consequence, not the eviction: the server now behaves differently
   for a request that no longer carries the cookie, or a re-created same-named
   cookie is accepted. A re-created cookie is only possible where the prefix
   allows it, see section 2.
5. Cleanup, mandatory: re-set every junk name with `Max-Age=0` on the same
   `Path`, confirm the count is back to baseline, reload and confirm a normal
   authenticated request succeeds. Record that confirmation in the report.

### 5b. Cookie bomb: exposure, not execution

The reportable artifact is the **cookie-write primitive plus the rejection
threshold the origin already advertises**, not a bombed user. Section 4.2.1 of
the draft notes 8192 octets as a common default, so "a limit exists" is not a
finding on its own; the finding is that an attacker can fill the victim's jar for
this origin at all.

- Stage A, always allowed: show unbounded or long reflection into `Set-Cookie`
  (about 100 characters is enough to prove it), or show a subdomain you control
  that can write a parent-scoped cookie. Report that.
- If the threshold itself must be measured, it is measured against the tester's
  own request on an **uncacheable** path with a unique cache-buster, and
  `Age`, `X-Cache` and `CF-Cache-Status` are read on the response. A cached
  400/431 denies every user of that path, which is cache-poisoned DoS and belongs
  to `hunt-cache-poison`, not here. Use a few cookies near the 4096-octet
  name-plus-value ceiling rather than many small ones, bisect serially with
  `sleep 1`, cap it at **6 requests**, and stop at the first rejection.
- Never deliver a bomb page or link to anyone but the tester. There is no
  engagement in which bombing a third party is the proof.
- `hunt-xs-leaks` owns the same primitive as a cross-site oracle, with its own
  gate in `references/leak-channel-catalog.md` section 9. Do not re-run that
  work here.

---

## 6. Sources read for this reference (2026-10-11)

- RFC 6265bis, `draft-ietf-httpbis-rfc6265bis-latest`, 7 October 2026:
  https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html
- MDN `Set-Cookie`:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie
- MDN browser-compat-data, `http/headers/Set-Cookie.json` (`main`):
  https://github.com/mdn/browser-compat-data
- Chromium `net/cookies/cookie_monster.cc` and `.h` (`refs/heads/main`):
  https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/cookies/cookie_monster.cc
- Firefox `modules/libpref/init/all.js`, `netwerk/cookie/CookieStorage.cpp`,
  `netwerk/cookie/CookieCommons.h` (searchfox `firefox-main`):
  https://searchfox.org/firefox-main/source/netwerk/cookie/CookieStorage.cpp
- PortSwigger, stealing HttpOnly cookies with the cookie sandwich technique:
  https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique
- Ankur Sundara, cookie bugs (server parsing quirks, Jetty CVE-2023-26049):
  https://blog.ankursundara.com/cookie-bugs/
- HackerOne 57356, "DOM based cookie bomb", disclosed 2017-04-11:
  https://hackerone.com/reports/57356
- Python 3.12.3 stdlib `http.cookies` and `django/http/cookie.py` (`main`), both
  read and executed locally for the parser rows in section 4:
  https://github.com/django/django/blob/main/django/http/cookie.py
- HackTricks (CC BY-NC 4.0, commit `722fec5c`) was used as a coverage checklist
  only, re-authored here; pages consulted:
  https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/pentesting-web/hacking-with-cookies/README.md ,
  https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/pentesting-web/hacking-with-cookies/cookie-tossing.md ,
  https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/pentesting-web/hacking-with-cookies/cookie-jar-overflow.md ,
  https://github.com/HackTricks-wiki/hacktricks/blob/722fec5c0e9148ffc53346f8d61ed71abbf4c240/src/pentesting-web/hacking-with-cookies/cookie-bomb.md

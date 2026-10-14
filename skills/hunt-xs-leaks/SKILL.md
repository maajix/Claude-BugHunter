---
name: hunt-xs-leaks
description: "Hunt cross-site leaks (XS-Leaks) and XS-Search — inferring a victim's cross-origin state through side channels the same-origin policy does not close. Channels: error events (onload/onerror), CORB/ORB script-load oracles, frame counting (window.length) by popup or iframe, navigation/redirect detection (history.length, 20-redirect cap, URL max length), performance.getEntries() detection, same-site cache probing, connection-pool and event-loop timing, cookie-bomb onerror oracles, CSS :visited history. Every channel carries a browser status verified on 2026-10-10 and the header that kills it (COOP, COEP, CORP, X-Frame-Options, Fetch Metadata resource isolation, SameSite, cache and network-state partitioning). Confirmation needs two accounts in known states plus a blinded 20-run trial per state with the exact browser version recorded — a missing header is never the finding. Noisy channels (connection-pool exhaustion, cookie bombs) are Stage-B gated on written operator sign-off."
sources: xsleaks_dev_wiki, chrome_developers, mdn_web_docs, chromium_source, privacy_sandbox_blog, rfc_6585, meta_bugbounty_guidelines, ysamm_research, hacktricks_xs_search
report_count: 1
---

# HUNT-XS-LEAKS — Cross-Site Leaks & XS-Search

An XS-Leak reads a *bit* of cross-origin state that the same-origin policy was
never designed to hide: did this search return results, is this user logged in,
is this user ID the active one, does this document exist for this account. Chain
enough bits and you extract content (XS-Search) or deanonymise the visitor.

Three things make this class different from everything else in this bundle:

1. **The browser is part of the vulnerability.** The same technique can be live
   in one engine and dead in the next release of another. Every status claim in
   this skill is dated; re-verify before you report.
2. **The proof is statistical, not a single response.** One lucky measurement is
   noise. The gate below is a blinded trial, not a screenshot.
3. **Several channels are noisy or near-DoS.** Those are Stage-B gated. Never run
   one against a real user's browser.

Technique index drawn from the HackTricks XS-Search page
(`https://hacktricks.wiki/en/pentesting-web/xs-search/index.html`, CC BY-NC —
used as a coverage checklist only); current status from the XS-Leaks Wiki
(`https://xsleaks.dev`) and vendor documentation read on 2026-10-10.

---

## Crown Jewel Targets

XS-Leaks pay where a single bit is already sensitive, or where a search box
indexes private content:

- **Search over private data** — webmail, chat, support tickets, CRM notes,
  document stores, code search. "Does my query match anything in your mailbox"
  is the canonical XS-Search and the highest-paid tier in the one public rate
  card for this class (Meta: up to $5k for the search bar).
- **Identity oracles** — endpoints that behave differently when a supplied user,
  tenant or page ID matches the active session. Reading the current user's ID
  outright beats checking a guess; a scalable check against a list beats a point
  check.
- **Membership and role state** — employee, group member, page administrator.
  Employee-only subdomains are a recurring soft spot.
- **Object existence** — `/doc/<id>` differing in status, frame count or redirect
  for an authorised versus unauthorised viewer leaks the object graph by
  enumeration.
- **Deanonymisation** — anything that turns "random visitor" into "this named
  account". That is the impact that lifts an XS-Leak out of informational.

Deprioritise pure login-state detection on a consumer site: usually known, often
accepted, rarely paid alone.

---

## OOB/Confirmation Gate

There is no Collaborator callback here — the leak happens inside the victim's
browser. The equivalent of OOB proof is a **blinded, reproducible oracle**.

**A finding requires all five:**

1. **Two accounts in known, opposite states.** Account A has the state (a
   matching search hit, the matching ID, the private document); account B does
   not. You, not the target, decide the states.
2. **A unique canary in every probe.** Put a per-probe random token in the query
   (`?q=CANARY-9f3a1b`) so a cached response, a WAF block page or a stale
   measurement cannot masquerade as a hit.
3. **A blinded trial of at least 20 runs per state**, interleaved A/B/A/B, with
   the predicted label recorded *before* the true label is revealed. Report the
   accuracy. Below roughly 95% you have a hypothesis, not a finding.
4. **The exact browser build.** Engine and full version string, captured with the
   run (`google-chrome --version`, `firefox --version`). A result without a
   version is unreportable in this class.
5. **A state flip.** Change account A's state (delete the matching item), re-run,
   and show the oracle flips with it. This is the step that separates a real
   oracle from a per-account quirk.

**What is NOT confirmation:**

- A missing `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` or
  Fetch-Metadata check. Absent hardening is a hardening recommendation.
- A response diff you observed with `curl`. `curl` is not a browser; it proves
  the server distinguishes the states, which is the *precondition*, not the leak.
- A timing difference measured once, or measured with the two states in separate
  blocks rather than interleaved.
- A technique reproduced in an old or flag-modified browser. Meta's XS-Leak
  guidelines refuse findings rooted in an older browser version or a browser
  implementation mistake; assume every mature program does the same.

---

## Attack Surface Signals

Signals that a target is worth a session of this work:

- **A state-dependent GET with a constructible URL** — no per-session token in
  the query. `?q=`, `/doc/<id>`, `?user=`, `?tenant=` are the shapes.
- **No `Cross-Origin-Opener-Policy`** on authenticated HTML: keeps the popup
  family (frame counting, history length, navigation detection) alive.
- **No `Cross-Origin-Resource-Policy`** on authenticated JSON or user-specific
  images: keeps the error-event and CORB/ORB oracles alive.
- **The server ignores `Sec-Fetch-Site`** — a cross-site-labelled request gets
  the same body as a same-origin one, so no resource isolation policy is enforced.
- **Framing policy that varies by state** — `X-Frame-Options: deny` for a wrong
  identifier and nothing for the right one is itself the oracle, readable via the
  Chromium performance buffer or postMessage arrival.
- **Session cookies without `SameSite=Strict`** — Lax or attribute-less cookies
  ride along on a top-level cross-site navigation, which is what a popup is.
- **Redirect behaviour that varies by state** — redirect-count arithmetic reads a
  browser limit, so it survives every cookie policy.
- **User content on the main eTLD+1**, or an injectable subdomain: cache probing
  is dead cross-site, alive same-site.

---

## Step-by-Step Methodology

Rate posture for every loop below: **serial, one request every 2-5 s with
jitter**, never parallel fan-out. These probes come from a browser in a real
session; bursts look like an attack on the account, not a test.

**1 — Pin the environment.** Record both engines before measuring anything.

```bash
google-chrome --version; firefox --version
```

**2 — Baseline the headers of the candidate endpoint.**

```bash
curl -sSI "https://target.example/app/search?q=test" \
  | grep -iE 'cross-origin-(opener|embedder|resource)-policy|x-frame-options|content-security-policy|timing-allow-origin|vary|set-cookie'
```

Read `defences-and-headers.md` and cross off the channels those headers kill
before writing a line of PoC.

**3 — Test whether the server enforces resource isolation.** Server-side check
only; it tells you whether a Fetch-Metadata policy exists.

```bash
d=$(mktemp -d)   # fresh dir per run: a failed curl does NOT truncate an old file
for site in same-origin cross-site; do
  curl -sS -b "session=<SESSION-COOKIE>" \
    -H "Sec-Fetch-Site: $site" -H "Sec-Fetch-Mode: no-cors" -H "Sec-Fetch-Dest: image" \
    -o "$d/$site.body" -w "$site http=%{http_code} bytes=%{size_download}\n" \
    "https://target.example/app/search?q=CANARY-9f3a1b"
  sleep 3
done
# http=000 means the request never completed — discard the run, do not diff it.
[ -s "$d/same-origin.body" ] && [ -s "$d/cross-site.body" ] \
  && diff "$d/same-origin.body" "$d/cross-site.body" | head -20 \
  || echo "incomplete run — re-measure"
```

Identical bodies and status codes mean no isolation policy — the subresource
channels stay on the table. A diff you did not watch both writes land for is not
evidence; re-run it.

**4 — Prove the server distinguishes the two states.** Same request, two
sessions, diff the bodies. This is the precondition, not the finding.

```bash
d=$(mktemp -d)
for acct in A B; do
  curl -sS -b "session=<SESSION-COOKIE-$acct>" \
    -o "$d/state-$acct.body" -w "$acct http=%{http_code} bytes=%{size_download}\n" \
    "https://target.example/app/search?q=CANARY-9f3a1b"
  sleep 3
done
[ -s "$d/state-A.body" ] && [ -s "$d/state-B.body" ] \
  && diff "$d/state-A.body" "$d/state-B.body" | head -20 \
  || echo "incomplete run — re-measure"
```

Record which observable differs: status code, byte length, content type, header
presence, redirect count, or embedded frame count.

**5 — Map the observable to a channel.** Use the decision table at the end of
`leak-channel-catalog.md`. Status-code difference goes to error events; frame
count to `window.length`; header presence to the performance buffer; redirect
difference to redirect-cap arithmetic; nothing-but-latency to timing — and timing
is the last resort, not the first.

**6 — Build the minimal browser PoC.** One channel, one bit, served from an
origin you control. Keep it to a single measurement per page load.

```html
<!-- Error-event oracle. One probe, no loop. -->
<script>
const probe = url => new Promise(res => {
  const s = document.createElement('script');
  s.src = url; s.onload = () => res(1); s.onerror = () => res(0);
  document.head.appendChild(s);
});
probe('https://target.example/app/search?q=CANARY-9f3a1b').then(b => console.log('bit', b));
</script>
```

**7 — Run the blinded trial.** 20 runs per state, interleaved, labels predicted
before they are checked, 2-5 s between runs. Report accuracy and both browser
versions. Anything under ~95% is not a finding yet.

**8 — Only then escalate to extraction.** Binary-search a search endpoint
character by character, with a hard budget: **no more than 500 probe requests
per engagement session**, serial, with jitter, and stop at the first evidence
that enumeration is being rate-limited or alerted on. Extract a short proof
string, not the victim's whole mailbox — a single recovered private token or
subject line carries the severity.

**9 — Noisy channels: Stage A then Stage B.** Connection-pool timing, cookie
bombs and event-loop blocking each carry their own cost table and gate in
`leak-channel-catalog.md`.

```
# Stage A (detection only) — header reads and lab-origin feasibility checks: no sign-off needed.
# Stage B — DO NOT execute the pool/cookie-bomb/event-loop oracle against the target
#           without explicit scope OK naming the cost. Tester's own profile only.
```

A cookie bomb is only ever set in the tester's own profile, with a short
`Max-Age` and an explicit cleanup step. Against a real user it is a denial of
service: that is the impact you describe, never an action you take.

**10 — Document for a browser-literate triager.** State the channel, the engine
and version, the trial accuracy, the state flip, and the one header that fixes
it. See `report-writing` and `evidence-hygiene`.

---

## Payload & Detection Patterns

| Observable difference | Channel to use | Reads as |
|---|---|---|
| Status code 200 vs 404/403 | error events on `<script>` / `<img>` | `onload` vs `onerror` |
| Content type HTML vs JSON | CORB/ORB script-load oracle | `onload` vs `onerror` |
| Embedded frame count | `window.length` via popup (or iframe if framing allowed) | integer |
| Extra redirect in one state | redirect-cap arithmetic against the Fetch spec limit of **20** | chain completes or fails |
| `history.length` after a driven navigation | navigation detection via window reference | integer |
| Header present in one state only | `performance.getEntries()` entry presence (XFO variant is Chromium-only) | entry count |
| Response cacheable and state-dependent | same-site cache probing | hit vs miss latency |
| Only latency differs | connection-pool or event-loop timing (gated) | delay distribution |
| Load succeeds vs rejected oversized request | cookie bomb → `431` (RFC 6585), or `400` on nginx (gated) | `onload` vs `onerror` |
| postMessage arrives vs timeout | widget broadcast / XFO-deny oracle | message or no message |
| Link styled visited | CSS `:visited` — dead in Chrome 136+ | render difference |
| Response size crosses an ETag-length boundary | Cross-Site ETag Length Leak (Chromium, gated) — catalog §14a | `431` on repeat navigation, read via `history.length` |
| Cross-origin redirect target hostname | XSS-Leak via connection-pool prioritisation (Chrome, gated) — catalog §14b | pool ordering |

Detection discipline: always probe a **known-200** and a **known-404** control URL
in the same page load. If the controls do not separate cleanly, the channel is
not working and your target result means nothing.

---

## Common Root Causes

1. **A state-dependent GET with a guessable URL.** No per-session token in the
   query string, so the attacker's page can construct the exact request.
2. **Response shape leaks the answer.** Different status code, content type, body
   length class, redirect count or frame count for "found" versus "not found".
3. **No opt-in isolation.** Authenticated HTML without COOP, authenticated
   resources without CORP, no Fetch-Metadata resource isolation policy.
4. **Cookies usable in a cross-site top-level navigation.** `SameSite=Lax` or no
   attribute at all, so a popup probe runs as the victim.
5. **Framing policy as a state signal.** Varying `X-Frame-Options` per request
   turns a defence into an oracle.
6. **User content on the organisation's main eTLD+1**, which forfeits the
   browser's partitioning and keeps same-site cache probing alive.
7. **No per-session budget on the expensive state-dependent endpoint**, so
   thousands of oracle probes look like ordinary traffic.

---

## Bypass Techniques

- **Framing blocked → popup.** `window.open` needs a user gesture but ignores
  `X-Frame-Options`, and as a top-level navigation it carries Lax cookies. COOP
  is the header that closes it.
- **COOP present → channels needing no window reference.** Redirect-cap
  arithmetic, client-side URL max length and error events read nothing from the
  target's window.
- **Resource isolation enforced → GET navigations.** The published policy
  deliberately allows `Sec-Fetch-Mode: navigate` GETs, so that family survives it.
- **Cache partitioned → go same-site.** Partitioning keys on the top-level site;
  the wiki notes it is ineffective for subdomain requests and window navigations,
  so a foothold on any target subdomain restores cache probing.
- **Cache warm → invalidate deliberately.** `fetch(url, {cache: 'reload'})`
  aborted mid-flight with `AbortController`, a `no-cors` POST, or a form POST.
  One invalidation per measurement, never a loop.
- **Status codes uniform → second-order differences.** Frame count, header
  presence, redirect count and `postMessage` arrival all survive normalised
  status codes.
- **Timing too noisy → amplify legitimately.** Interleave A/B/A/B, take medians,
  and widen the gap with a heavier state-dependent query rather than by hammering
  the endpoint.

---

## Gate 0 Validation

Kill these false positives before writing anything up:

- **Header absence is not a finding.** No COOP, no CORP, no Fetch-Metadata check:
  that is a hardening item, filed as such.
- **`curl` is not a browser.** A server-side diff proves only the precondition.
- **One measurement is noise.** 20 runs per state, interleaved, accuracy stated.
- **No version, no report.** Engine and full version with every measurement, and
  a second engine checked — if it only works in one, say which, and expect the
  severity to drop.
- **Controls must separate.** Known-200 and known-404 controls in the same page
  load, or the channel is not live.
- **The state flip is mandatory.** If the oracle does not follow the state when
  you change it, you measured an account quirk.
- **Check the published status before claiming a channel.** `:visited` sniffing
  is closed in Chrome 136+; cross-site cache probing is closed by Chrome 86 and
  Firefox 85 partitioning; the XSS Auditor leak died with Chrome 78. Reporting
  one of these as live burns credibility for the whole submission.
- **Do not reuse the XSinator matrix as status.** It is 2021 data.
- **Read the program policy.** Many programs exclude browser-rooted issues
  outright, and some price login-state detection at zero. A technically valid
  leak can still be out of scope.
- **Noisy channels: confirm sign-off is on file** before Stage B, and confirm
  cleanup afterwards (cookies expired, sockets released).

---

## Real Impact Examples

- **Identity disclosure on a major social platform (2024-12 → 2025-05).** Four
  leaks let a third-party site identify the visiting user: response differences in
  OAuth-style callback endpoints brute-forced the logged-in user ID via
  `__cid`/`__user`; a social plugin in an iframe emitted a `postMessage` only when
  the supplied `__user` matched, because a wrong ID drew `X-Frame-Options: deny`
  and no message arrived; a pixel-bootstrap script exposed the user ID directly;
  and employee-only subdomains plus that script served as login-state and
  staff-membership oracles. Bounties awarded 2025-02-12: **$2,400, $2,400 and
  $3,600**; one report informative. Fixed 2025-05-22.
- **Published rate card.** Meta's XS-Leak guidelines: search bar up to **$5k**;
  identification up to **$3k** (current user's ID $3k, checking a supplied ID $2k
  and only when scalable against a list); location up to $1.5k; age up to $1k;
  page role up to $1.25k; less impactful leaks $500-750. Deductions when the
  attack needs a new browser tab or the value cannot be binary-searched. Findings
  rooted in an old browser version or a browser bug are not rewarded.
- **Severity shape.** Login-state only: informational to low. Identity or role
  disclosure: medium. XS-Search extraction of private content: high — the bit
  count is unbounded and the victim only has to visit a page.

---

## Disclosed Report Citations

- `https://ysamm.com/uncategorized/2026/01/16/cross-site-leaks.html` — multiple
  cross-site leaks disclosing platform users to third-party sites; endpoints,
  parameters, bounty amounts ($2,400 / $2,400 / $3,600) and the 2024-12 → 2025-05
  timeline. Read on 2026-10-10.

Program policy (not a disclosed report, listed for scoping):
`https://bugbounty.meta.com/payout-guidelines/xsleak/`.

---

## Related Skills & Chains

| Skill | Boundary |
|---|---|
| `hunt-dom` | Owns same-origin CSS exfiltration (attribute selectors leaking DOM values char-by-char) and postMessage hijacking as a vulnerability. This skill uses CSS only as a *cross-origin state oracle* (`:visited`, CSS-ReDoS timing) and postMessage only as a presence/absence bit. |
| `hunt-cors` | Owns credentialed cross-origin **reads** through misconfigured `Access-Control-*`. Here a CORS failure is only an oracle: the error tells you something about the response without reading it. If you can read the body, it is a CORS finding and worth more. |
| `hunt-cache-poison` | Owns writing an attacker-controlled response into a **shared** cache so other users receive it. This skill only **reads** whether the victim's own partitioned, private cache holds an entry. Different defect, different owner. |
| `hunt-clickjacking` | Owns framing as UI redress. Here `X-Frame-Options` presence is a leak bit, not a click target. |
| `hunt-session` | Owns cookie attributes and session lifecycle as findings. This skill consumes `SameSite` as the precondition that decides whether a probe is authenticated. |
| `hunt-csrf` | Chain target: an XS-Leak that recovers a token or confirms a state often supplies the missing precondition for a CSRF. |
| `triage-validation` | Run before submitting; the blinded-trial numbers belong in its output. |
| `evidence-hygiene`, `report-writing` | Capture the browser versions, the trial table and the single-header fix. |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `leak-channel-catalog.md` | Per-channel detail for 12 live channel families with probe code, verified browser status, the mitigation that kills each, and per-channel false-positive traps; mandatory cost/rate gates for connection-pool timing, cookie bombs and event-loop blocking; the dead/historical list (XSS Auditor, SharedArrayBuffer clock, XSinator-era browser bugs); channel decision table keyed on the target's observed defences; the two PortSwigger Top 10 of 2025 entries (Cross-Site ETag Length Leak, XSS-Leak connection-pool redirect leak) | ETag length leak, If-None-Match, XSS-Leak, redirect hostname leak, connection pool exhaustion, socket limit, cookie bomb, 431 header too large, frame counting, window.length, event loop blocking, busy event loop, cache probing, error events, onerror oracle, CORB, ORB, performance.getEntries, resource timing, redirect detection, history.length, URL max length, CSS :visited, postMessage oracle, dead technique |
| `defences-and-headers.md` | Exact values and semantics for COOP, COEP, CORP, XFO and `frame-ancestors`; the Fetch Metadata resource isolation rule with its allow/reject logic and `Vary` requirement; the 2026 credential matrix (Chrome/Firefox/Safari third-party-cookie and SameSite posture); the cache and network-state partitioning timeline per engine; application-level mitigations and a per-channel remediation table; the dated source list | COOP, COEP, CORP, Cross-Origin-Opener-Policy, Fetch Metadata, Sec-Fetch-Site, SameSite default, third-party cookies, cache partitioning, state partitioning, network partitioning, remediation, how to fix XS-Leak, browser baseline |

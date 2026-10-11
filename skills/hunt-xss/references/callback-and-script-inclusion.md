# Callback abuse (SOME) and cross-site script inclusion (XSSI)

Two classes that live next to XSS and are routinely thrown away as "useless
reflection": a callback parameter that only accepts `[\w.]`, and an authenticated
endpoint that answers with JavaScript. Each entry carries **Status** (what is
verified, against which source, on which date), **Killed by** and **Proof bar**.
No Status line means not verified; do not report it as live.

Ownership boundaries, so nothing is claimed twice:

| Class | Owner | Why |
|---|---|---|
| Reading another account's data by including its response as a script | `hunt-xss` (this file) | The attacker reads the body. It is a data-disclosure finding. |
| Load-vs-error bit from a script include (CORB/ORB oracle) | `hunt-xs-leaks` | Nothing is read; one bit of cross-origin state is inferred. |
| Credentialed cross-origin read through `Access-Control-Allow-*` | `hunt-cors` | The read is granted by headers, not by the script tag. |
| Cookie attributes and `SameSite` posture as a finding | `hunt-session` | Here `SameSite` is only the precondition that decides whether a probe is authenticated. |

---

## 1. SOME: Same Origin Method Execution

**Status** (verified 2026-10-11 against Ben Hayak's Black Hat Europe 2014 white
paper "Same Origin Method Execution (SOME): Exploiting a Callback for Same Origin
Policy Bypass", the HITB 2017 follow-up "Everybody Wants SOME", and the author's
`someattack.com` playground, which still publishes the generator and the
vulnerable example): the primitive is structural, not a browser bug. No browser
ever "fixed" it, because nothing is broken. What changed is the isolation
primitives listed under *Killed by*.

**The escalation.** You found a `?callback=` parameter that the server drops into
script position, and the value is restricted to word characters and dots, so you
cannot write arbitrary JavaScript. That is not a dead end: a method path is enough.
The playground's shape is literally `<script>opener.{callback}</script>`, so the
payload is only the path of a method to invoke on the opener's document. The
callback endpoint itself is usually a bare page with no interesting DOM, and SOME
is how you borrow a document that has one:

1. Victim loads the attacker's page A. One click is needed, because popups require
   a user gesture.
2. A calls `window.open()` to create popup P. P's `window.opener` references A's
   browsing context. The attacker controls this call, so the implicit
   `rel="noopener"` that browsers apply to `target="_blank"` anchors (MDN) is not
   a defence here.
3. A navigates **itself** to the target page that holds the interesting DOM, which
   is same-origin with the callback endpoint.
4. P navigates to the vulnerable callback endpoint with
   `callback=<method path on the opener document>`.
5. P's script dereferences `opener` and calls the method. A window handle survives
   navigation of the referenced context, and the same-origin check is evaluated
   against the documents' **current** origins, so after step 3 the dereference is
   legal.

Hunting signals: `?callback=`, `?cb=`, `?jsonp=`, `?handler=`, OAuth and payment
dialogs that redirect to a JSONP-style endpoint, and any endpoint whose response
is `text/javascript` built from a parameter. Probe with a canary identifier such
as `callback=cpmark987abc` and confirm the token lands unquoted in script position.
If the parameter is **not** character-restricted, stop: that is ordinary reflected
XSS and worth more.

**Killed by:** validating the callback against a fixed allowlist of function names
(the real fix); not prefixing the emitted call with `opener.`;
`Cross-Origin-Opener-Policy`. On the COOP point, what is verified from MDN
(2026-10-11) is the browsing-context-group rule: a navigation keeps the same group
only if the policies match, meaning both `unsafe-none` or the same policy with
same-origin documents, and a document opened into a new browsing context group has
its references to and from its opener severed. The attacker's page is
`unsafe-none`, so
a target page sending `COOP: same-origin` moves into a new group at step 3 and the
popup's handle no longer reaches it. **Mechanism-derived, not a cited result:** no
source read this session states "COOP kills SOME", so re-test against the actual
target rather than asserting it. `COOP: same-origin-allow-popups` on the target
does not help you as a tester to assume either way; measure it.

**Proof bar:** invoke a **non-state-changing** method in the tester's own session,
for example a UI toggle, a tab switch, or a method whose only effect is visible
rendering, and screenshot it next to the callback URL that caused it. Never click a
state-changing control in another account's session, even a tester-owned one, when
a read-only method proves the same reachability. If the only reachable method
changes state, write it up as Stage A (reachability proven, method named) and get
written operator sign-off before any Stage B execution.

---

## 2. XSSI: cross-site script inclusion

**Status** (verified 2026-10-11): the class is structural. The same-origin policy
never restricted `<script src>`, so an attacker page can include a victim's
authenticated response and read whatever that response defines. The foundational
measurement is Lekies, Stock, Wentzel and Johns, "The Unexpected Dangers of
Dynamic JavaScript", USENIX Security 2015, which found more than 80% of the 150
top-ranked domains studied served includable dynamic JavaScript. Two gates decide
whether it is still live on a given target today:

- **Credentials.** The include must carry the victim's cookies. Read the 2026
  credential matrix in `hunt-xs-leaks/references/defences-and-headers.md`
  (`SameSite` defaults, third-party-cookie and partitioning posture, verified
  2026-10-10) rather than re-deriving it here. A `SameSite=Lax` session cookie is
  not sent on a cross-site subresource request, which kills the classic drive-by
  include; same-site contexts, including a sibling subdomain, are unaffected.
- **Chrome's Cross-Origin Read Blocking.** Verified 2026-10-11 from the Chromium
  CORB explainer: for script destinations, CORB blocks cross-origin responses
  labelled HTML, XML (except `image/svg+xml`), JSON or `text/plain` when
  `X-Content-Type-Options: nosniff` is present; without `nosniff` it sniffs and
  blocks only when the sniff confirms the label; and it blocks any response other
  than `text/css` that begins with a JSON security prefix such as `)]}'`,
  `{} &&` or `for(;;);`. It does **not** block JavaScript MIME types, including
  JSONP, and does not block responses with no `Content-Type` header. Whether ORB
  has fully replaced CORB in current Chrome is an open question, recorded the same
  way in `hunt-xs-leaks/references/leak-channel-catalog.md`: treat as unverified.

**Live shapes.**

- **Dynamic JavaScript with per-user data.** An authenticated endpoint that
  answers `application/javascript` and assigns to globals, for example
  `var csrfToken = "<TOKEN>"` or `window.currentUser = { ... }`. Include it and
  read the globals. CORB does not touch it, because the MIME type is JavaScript.
- **JSONP.** `?callback=x` wraps the data in a call you define. The same endpoint
  is simultaneously a CSP allowlist bypass; see `csp-bypass-depth.md`.
- **MIME confusion without `nosniff`.** A response that is not labelled
  JavaScript but sniffs as script executes anyway. The CTF-demonstrated extreme
  (UIUCTF 2022 "modernism" and "precisionism", via a UTF-16 byte-order-mark prefix
  and via an ICO width field read from a cross-origin image) shows a `text/plain`
  secret recovered byte by byte. **Unverified in current browsers:** those two
  results are from 2022 and were not re-tested this session. The practical,
  verified takeaway is the header check: missing `X-Content-Type-Options: nosniff`
  on a data endpoint is worth probing.

**Dead shapes, do not report them as live.** The pre-ES5 tricks that leaked plain
JSON arrays and objects, overriding the `Array` constructor or installing
`Object.prototype` setters with `__defineSetter__`, depended on engine semantics
that ES5 changed; array literals no longer call the `Array` constructor. They do
not work in any current browser. A bare JSON response included as a script is now
a syntax error, which is why the live shapes above all involve JavaScript-typed or
sniffable responses.

**Probe (two tester-owned accounts, local file or your own host):**

```html
<!-- Account B is logged in in this browser profile. Reads only the canary value
     the tester stored in account B. No cookies, no page content, no third-party data. -->
<script>window.currentUser = undefined;</script>
<script src="https://target.example/api/me.js"></script>
<script>
  // Expect the canary string the tester wrote into account B's profile.
  console.log('XSSI canary:', window.currentUser && window.currentUser.displayName);
</script>
```

Keep the include serial and single-shot. There is no loop here to rate-limit, and
there is no reason to iterate over user IDs: iterating is enumeration of real
accounts, which this skill does not authorise.

**Killed by:** requiring a custom header or a token the attacker page cannot set
(so the request becomes a CORS preflight case and `hunt-cors` rules apply);
serving data as JSON with `X-Content-Type-Options: nosniff` and a JSON security
prefix; `SameSite=Lax` or stricter on the session cookie; removing JSONP.

**Proof bar:** a canary value that the tester planted in a **second
tester-owned account** appears in the attacker page's console while that second
account's session is the one loaded in the browser. Real third-party data must
never be read, logged, or pasted into a report. A reflected global with no
per-account data in it is not a finding.

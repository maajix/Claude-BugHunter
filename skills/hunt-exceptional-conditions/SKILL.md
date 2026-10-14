---
name: hunt-exceptional-conditions
description: "Hunt mishandling of exceptional conditions — feed an endpoint malformed/unexpected input (wrong type, broken JSON, oversized field, null byte) and make it fail OPEN or leak internals: a verbose stack-trace / framework error page that discloses ORM internals, server file paths, library versions, or a language traceback. Use on any input-accepting endpoint (JSON APIs, forms, query params). Medium-High when the leak exposes internal structure that arms a deeper attack."
report_count: 0
sources: hackerone_public
---

# HUNT-EXCEPTIONAL-CONDITIONS — Verbose Errors / Fail-Open (A10:2025)

## What actually pays

Well-built apps catch errors and return a clean, generic message. A broken app,
when handed input it didn't expect, throws an unhandled exception and renders a
**developer error page** straight to the client — leaking the stack trace, the
ORM/query internals, server-side file paths, and framework/library versions.
That disclosure is the finding (and it arms SQLi/RCE/path attacks next).

## Recon

Any endpoint that parses input is a candidate; the richest are:

```
JSON APIs that expect typed fields:  POST /api/* with {numbers, ids, enums}
Endpoints with numeric/id path or query params:  /item/{id}, ?page=, ?quantity=
Search / filter / sort params
File or content-type sensitive uploads
```

## Attack — send what the code didn't anticipate

Take a known-good request and break ONE assumption at a time:

- **Wrong type:** a field the app expects to be a number/string is sent as an
  array or object — `{"rating":"x","comment":[1,2,3]}`, `{"quantity":{}}`.
- **Malformed body:** truncated/invalid JSON, an unterminated string, a stray
  brace, a wrong/missing Content-Type.
- **Boundary/oversized:** a very long string, a huge/negative/overflow number.
- **Null byte / control chars** embedded in a value.

```
POST /api/Feedbacks   {"rating":"notanumber","comment":[1,2,3]}
GET  /item/' OR /item/%00   (also exercises the error path)
```

Watch the RESPONSE BODY, not just the status: a 500 (or even a 200/400) whose
body contains a stack trace or framework error page is the signal.

## What counts as a leak (the success signal)

A finding is confirmed when the response body contains a cross-framework error-disclosure signature:

- **Node/Express + Sequelize:** `SequelizeDatabaseError`, `node_modules/sequelize`,
  a JS stack with internal paths.
- **PHP:** `<b>Warning</b> ... /var/www/.../file.php on line N`.
- **Python:** `Traceback (most recent call last)`, `werkzeug.exceptions`.
- **Java:** `at com.app.Foo(Foo.java:42)` stack frames.
- **.NET:** `Server Error in '/' Application`, a `[System.XxxException: ...]` YSOD.

A clean JSON error (`{"error":"Invalid input"}`) with no internals is NOT a
finding — that's correct handling. Disclosure of internal structure is.

## Fail-open on exception (auth decided inside a try block)

The higher-paying variant: the exception happens **inside** an authentication or
authorization check, and the handler's default is "allow". Typical shapes: a
`try/except` around token parsing that falls through to the handler, an external
authz / policy service that times out and is treated as approved, a permission
lookup that throws on an unexpected type and skips the deny branch.

```
Baseline 1: protected endpoint, no credentials          → expect 401/403
Baseline 2: protected endpoint, valid low-priv session  → expect 403 on admin routes
Probe:      same request, auth input made malformed     → truncated token, wrong type
            in a role/permission parameter, invalid encoding in the auth header,
            oversized cookie, duplicate auth headers
```

A finding is a probe that gets **more** access than Baseline 1 or 2 (a 200 with
protected data, or an admin action that completes). Body-diff against both
baselines; a 500 alone is the verbose-error finding above, not fail-open.
Signature/claim forgery is a different bug class: route it to `hunt-jwt-crypto`.

## Chain targets the error path opens

- **Error-based blind SSTI.** When template output is never reflected, an error
  page that changes with the injected expression becomes an oracle. That was the
  #1 entry in PortSwigger's [Top 10 web hacking techniques of 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
  ("Successful Errors", Vladislav Korchagin). If a template-looking input produces
  an engine-specific error here, stop and hand the field to `hunt-ssti`; do not
  escalate from this skill.
- **SQL error text** → `hunt-sqli`; **absolute paths** → `hunt-lfi`.

## Validation discipline

- Capture the exact leaked artifact (path, ORM class, version, stack frame) —
  that's the evidence. "It returned 500" alone is not disclosure.
- Note what the leak enables next (e.g. a disclosed SQL error → hunt-sqli; a
  disclosed absolute path → hunt-lfi).

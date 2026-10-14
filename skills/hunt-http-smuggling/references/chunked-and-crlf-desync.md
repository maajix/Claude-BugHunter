# Chunked-parsing differentials and CRLF-powered desync

Depth for `hunt-http-smuggling`. Read the Engagement Safety Contract in that skill's `SKILL.md` first: the Stage A / Stage B split and the serial / 5-second-delay / 20-attempt-cap / stop-on-first-signal bounds apply to every probe below without exception.

Both families matter because they survive front-ends that already reject a request carrying both `Content-Length` and `Transfer-Encoding`. Neither needs a duplicate length header: the ambiguity lives inside the chunked body or inside a decoded path.

## Funky Chunks — chunk-line terminators, chunk extensions and spills

Source: Jeppe Bonde Weikop, "Funky Chunks", 18 Jun 2025 — https://w4ke.info/2025/06/18/funky-chunks.html . Vendor and CVE tracking: https://github.com/JLLeitschuh/unCVEed/issues/1 .

RFC 9112 §7.1 ends every chunk-size line with CRLF and §7.1.1 lets a chunk extension (`;name=value`) sit before it. Hops disagree in two places:

- **Line terminators inside the chunk-size line or extension.** A bare LF, a bare CR, or `\rX` is the end of the line to one parser and ordinary extension bytes to the other.
- **Spills.** Chunk data longer than its declared size. One parser accepts the extra bytes; the other reads a line terminator inside them.

The paper names the four resulting classes by which hop sees what:

| Class | Front-end (proxy) sees | Back-end (server) sees | Trigger shape from the paper |
|---|---|---|---|
| TERM.EXT | line terminator | extension bytes | `2;\n` in the chunk-size line |
| EXT.TERM | extension bytes | line terminator | `45;\n` in the chunk-size line |
| TERM.SPILL / SPILL.TERM | terminator vs. accepted spill (either way round) | the opposite | a 5-byte chunk followed by `AAAAAXXX\r\n` |

**Detection follows the timing-probe logic in `SKILL.md`, with the length ambiguity moved into the chunk-size line.** A probe whose only effect is that the back-end waits for bytes that never arrive, on a request that carries no prefix, is Stage A. Anything that appends a second request after the ambiguous chunk is a smuggled prefix and is **Stage B**, exactly like the CL.0 two-request probe.

CVEs confirmed for this family (NVD wording paraphrased):

| CVE | Component | Class | What was wrong |
|---|---|---|---|
| CVE-2025-22871 | Go `net/http` | TERM.EXT, server | accepted a bare LF as the line terminator of a chunk-size line |
| CVE-2025-4600 | Google Cloud Classic Application Load Balancer | SPILL.TERM, proxy | mishandled chunked requests; fixed by disallowing stray data after a chunk, not vulnerable after 2025-04-26 |
| CVE-2025-43859 | h11 < 0.16.0 (uvicorn, hypercorn) | SPILL.TERM, server | leniency in parsing line terminators in chunked bodies; needs a buggy proxy in front |
| CVE-2024-53868 | Apache Traffic Server | TERM.EXT, proxy | listed in the paper and the tracking issue |
| CVE-2024-52304 | AIOHTTP | TERM.EXT, server | listed in the paper and the tracking issue |
| CVE-2025-29904 | Ktor | SPILL.TERM, server | listed in the paper and the tracking issue |

Later CVEs in the same family, not part of the paper:

| CVE | Component | What was wrong |
|---|---|---|
| CVE-2025-55315 | ASP.NET Core (Kestrel) | the chunk-extension parser accepted a lone `\r` or `\n` and kept reading; the patch rejects it ("Bad chunk extension") and adds an `InsecureChunkedParsing` switch that restores the old behaviour. Microsoft scored it CVSS 9.9. Analysis: https://community.f5.com/kb/security-insights/http-request-smuggling-using-chunk-extensions-cve-2025-55315/344118 |
| CVE-2025-66373 | Akamai Ghost (CDN edge) before 2025-11-17 | when a chunk's declared size differs from its actual data, the edge could forward the invalid request plus the superfluous bytes to the origin, where a smuggled request can hide; exploitability depends on the origin's parsing (NVD CVSS 4.8) |

Status per the paper at publication (June 2025), re-check before relying on it: nginx as a back-end was EXT.TERM and the maintainers declined to change it; Gunicorn was TERM.EXT with a fix pending. A version-confirmed lenient back-end behind a lenient front-end is the pairing to look for; one lenient hop alone is not a desync.

## CRLF-powered desync

Source: Tom Stacey (PortSwigger) with Tobia Righi (TurtleSec), "CRLF-Powered Desync Attacks", 5 Aug 2026 — https://portswigger.net/research/crlf-powered-desync-attacks .

The root configuration is an nginx `proxy_pass` that builds the upstream URL from `$uri`:

```
location / {
  proxy_pass http://backend$uri;
}
```

`$uri` is the normalised, URL-decoded path, so a `%0d%0a` in the request path becomes a real CRLF in the upstream request. The attacker then controls the upstream request's structure: inject headers, end the request line early, or split it into a second request. The response-side twin is `return 302 https://example.com$uri;`, which is response splitting.

Where else to look:

- OpenResty and Tengine, which inherit nginx's behaviour; check their configs for the same pattern.
- Custom upstream headers built from decoded input (for example an `X-Original-Url` the proxy sets from the path).
- Non-path inputs that end up in the upstream path, such as a cookie value.
- Regex captures used in `proxy_pass` or `return` that do not exclude whitespace and CR/LF.

**It is browser-deliverable.** The trigger is a plain URL path, so a `fetch()` or an ordinary navigation fires it. That makes it a client-side desync primitive and, combined with an XSS gadget, the basis for the "desync worm" the article describes. A PoC hosted anywhere another person could load it is **Stage B**.

**Detection.** The article uses injected syntax that a back-end rejects with a predictable status code, compared against a baseline: an invalid HTTP version injected through the path (`505`), an injected `Transfer-Encoding: x` (`501`), or `Expect: asdf` (`417`). One shape for the first, with a per-probe canary and a cachebuster:

```
GET /404-a7f3c1%20HTTP/9.9%0d%0aX:%20y?cb=a7f3c1 HTTP/1.1
Host: target.example
```

If the upstream request line becomes `GET /404-a7f3c1 HTTP/9.9`, a back-end that validates the version answers `505` where the baseline answered `404`.

- **Stage A:** single-request status-code probes like the one above, sent serially from your own client, read back on your own connection, with no injected body-length header and no second request.
- **Stage B:** anything that injects `Content-Length`, a second request line, or a body. The article does not call any of its probes safe and warns that testing can affect other users; treat it with the same caution as the TE.CL probe.

Tooling: `t0xodile/crlf-powered-desync-scanner` (linked from the article; the author used a Burp extension throughout the research) and the nuclei templates in `turtlesec-software/crlf-desyncs` (Tobia Righi). Run either serially against one host, never as a scope-wide sweep.

**Whitebox check (no traffic):** if you hold the config, `grep -rnE 'proxy_pass[^;]*\$uri|return[^;]*\$uri' /etc/nginx/` finds the pattern directly. The fix to recommend is `proxy_pass http://backend;` with no variable (nginx then forwards the original, still-encoded URI) or `$request_uri`, which is not decoded.

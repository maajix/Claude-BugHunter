# Adobe Experience Manager (AEM)

AEM is not a PHP CMS. It is a Java content repository (JCR) fronted by the
Apache Sling request-to-resource resolver, usually with the AEM Dispatcher as a
caching reverse proxy in front. That architecture produces a failure mode none
of the other products in this skill share: the proxy's idea of a path and the
repository servlet's idea of a path can differ, and every security control on a
production AEM site lives in the proxy.

Two practical consequences. First, almost all unauthenticated findings here are
"an endpoint that was supposed to be denied answered anyway". Second, the
severity is unusually high when it works, because the repository servlets return
structured content, including user nodes.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter. Caps per host:
15 fingerprint requests, 40 endpoint probes, 25 bypass-variant probes.

```bash
# Define this before any loop below. Never tighten it to finish a list faster.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }
```

## 1. Fingerprint corroboration

| Artifact | Request | What it proves |
|---|---|---|
| Client library path | `/etc.clientlibs/` references in the baseline HTML, returning CSS or JS | AEM's asset pipeline |
| Dispatcher header | `X-Dispatcher` in the response headers | The AEM Dispatcher is in front |
| Author login page | `GET /libs/granite/core/content/login.html` | Granite, which is AEM |
| Asset path | `/content/dam/` references for images | AEM's digital asset manager |
| HTML comment | A trailing `CQ` comment block at the end of the document | Legacy CQ or AEM markup |
| Sling selectors | A page URL accepting a `.html` selector chain such as `page.1.json` behaving differently from `page.html` | Sling resource resolution |

Two artifacts minimum. `/etc.clientlibs/` on its own is strong but can be
proxied by an unrelated edge.

## 2. Version and service-pack pinning

AEM has no public version-check API, and the deployed service pack is what
decides exposure. Candidate artifacts:

- The author login page and the Granite UI reveal a major line (6.5 versus a
  Cloud Service deployment versus an LTS build).
- Client library paths frequently carry a build hash that correlates with a
  service pack, which is useful for change detection across a retest but is not
  a version on its own.
- The OSGi console, when reachable, names the exact product and bundle versions.
  It is normally denied; see section 5.

Because precise fingerprinting is often impossible from outside, the practical
workflow is the reverse of the other products: establish which quarter's Adobe
bulletin the client's service pack corresponds to by asking them, then probe
only for the specific misconfigurations below. Read the `APSB` bulletin matching
that quarter at `https://helpx.adobe.com/security/products/experience-manager/`
and record the date you read it.

Verified anchor, read this session: bulletin APSB25-115 was published on
9 December 2025 with a priority rating of 3, listing AEM 6.5 LTS 6.5.23 and
earlier as affected and 6.5.24 among the fixed releases. Note that the three
CVEs most commonly quoted alongside that bulletin (CVE-2025-64537, CVE-2025-64538
and CVE-2025-64539) are stated by Adobe as **not** impacting AEM 6.5 and LTS
versions, so do not attach them to a 6.5 target. Read the bulletin's own table.

## 3. AEM Forms on JEE: the two verified unauthenticated CVEs

These are separate from AEM Sites and require the Forms on JEE add-on. Both were
published on 5 August 2025 and both are unauthenticated.

| CVE | What it is | Affected | Score |
|---|---|---|---|
| CVE-2025-54253 | A misconfiguration that results in arbitrary code execution. An attacker can bypass security mechanisms and execute code, with no user interaction and a changed scope. Publicly described as a Struts development-mode OGNL expression evaluator left reachable. | AEM 6.5.23 and earlier | CVSS 3.1 **10.0 Critical** |
| CVE-2025-54254 | Improper restriction of XML external entity references, leading to arbitrary file-system read with a changed scope and no user interaction. | AEM 6.5.23 and earlier | CVSS 3.1 8.6 High |

Sources: <https://nvd.nist.gov/vuln/detail/CVE-2025-54253>,
<https://nvd.nist.gov/vuln/detail/CVE-2025-54254>. Technical background:
<https://slcyber.io/assetnote-security-research-center/struts-devmode-in-2025-critical-pre-auth-vulnerabilities-in-adobe-experience-manager-forms>.

Adobe shipped these as emergency fixes outside the normal service-pack cadence,
and the Forms on JEE add-on carries its own hotfix stream, so a Sites
installation that is current does not imply the Forms add-on is.

**Stage A detection for CVE-2025-54253.** The published proof evaluates an OGNL
expression that spawns a process. Executing a command on a client system is
Stage B at minimum and is unnecessary for confirmation. Detect reachability
instead:

```bash
T="https://target.example"
# Does the development-mode debug endpoint exist and respond as an evaluator?
curl -s -o /tmp/aem-debug.out -w '%{http_code} %{size_download} %{content_type}\n' \
  -m 20 -k "$T/adminui/debug"
head -c 400 /tmp/aem-debug.out
```

A 404 or a redirect to a login page is the healthy answer. A 200 from a debug
evaluator, or an error page that names the expression parameter, is the finding:
report reachability plus the CVE's own impact statement. Do not escalate to
expression evaluation without written sign-off, and never run a process-spawning
expression on a production node.

For the XXE (CVE-2025-54254), the confirmation pattern is an out-of-band entity
resolving to infrastructure you own with a per-request canary. Follow
`hunt-xxe`; this file only says which product and version range to point it at.

## 4. Unauthenticated endpoints worth probing

Each of these should be denied by the Dispatcher on a correctly configured
production deployment. The finding is that it answers.

| Path | What it returns when exposed | Severity shape |
|---|---|---|
| `/.json`, `/<page>.1.json`, `/<page>.infinity.json` | Repository nodes serialised by the default GET servlet, including properties the page template never renders | High when it returns content outside the published site |
| `/bin/querybuilder.json?path=/&p.limit=10` | The QueryBuilder API, which can walk the repository tree and return page structure, internal paths and user nodes | High to Critical depending on what the query reaches |
| `/libs/cq/AuditlogSearchServlet.json` | Audit log entries, naming authors, times and content paths | Information disclosure |
| `/libs/cq/ui/content/dumplibs.html` | A client-library dump, historically a reflected-XSS vector | Medium, chainable |
| `/system/console/bundles`, `/system/console/status-*` | The OSGi and Felix console: exact product and bundle versions. With credentials it also allows bundle upload, which is code execution | Critical if reachable with credentials, High for the disclosure alone |
| `/crx/packmgr/index.jsp`, `/crx/de/` | Package Manager and CRXDE. With credentials, a content package can carry a JSP, which is code execution | Critical if authenticated access is reachable |
| `/etc/groovyconsole`, `/bin/groovyconsole/post.json` | The AEM Groovy Console. If reachable it evaluates arbitrary Groovy and Java | Critical |
| `/adminui/debug` | AEM Forms on JEE development-mode evaluator. See section 3 | Critical |

The highest-impact read is the QueryBuilder one, because with default anonymous
read ACLs on user home nodes it can return user profile nodes and, on
misconfigured installs, their stored credential properties. That is the
difference between "a JSON endpoint is exposed" and a Critical.

```bash
# Stage A. Read-only. Keep p.limit small; this is a repository query.
curl -s -o /tmp/aem-qb.json -w '%{http_code} %{size_download}\n' -m 20 -k \
  "$T/bin/querybuilder.json?path=/content&p.limit=5&p.hits=selective&p.properties=jcr:path"
python3 -I -c 'import json;d=json.load(open("/tmp/aem-qb.json"));print(d.get("success"),d.get("total"));print([h.get("jcr:path") for h in d.get("hits",[])][:5])'
```

If the response carries credential or hash properties, stop, do not page through
more results, and hand evidence handling to `evidence-hygiene`. The first page
is the proof.

## 5. Dispatcher path-normalisation bypasses

Production AEM denies paths at the Dispatcher by prefix and by extension. Where
the Dispatcher and Sling disagree about separators and extension parsing, a
denied path answers anyway. Two documented shapes:

```text
# Append an allowed static extension after a separator the proxy does not
# treat as part of the path, but the application does.
GET /bin/querybuilder.json;%0aa.css?path=/content&p.limit=1 HTTP/1.1

# Percent-encode the path separators so a prefix-based deny rule does not match.
GET /%2fbin%2fquerybuilder.json?path=/content&p.limit=1 HTTP/1.1
```

Rules for using these:

- **Confirm the bypass changed the application's answer, not the proxy's.**
  A 200 carrying a CSS content type is the proxy answering from cache or a
  rewrite. The evidence is a JSON body whose structure matches the servlet,
  diffed against the denied request's body.
- Probe variants serially and cap them. Twenty-five variants is plenty; a
  hundred is a scan.
- Record both the denied and the bypassing request verbatim. The report's whole
  value is the pair.
- A bypass that reaches a read-only servlet is Stage A. A bypass that reaches a
  POST servlet is not: see section 6.

## 6. Write paths: Stage B, and mostly "describe and stop"

Three documented AEM write paths reach code execution. All of them change the
content repository, which on an author instance is the client's production
content store.

- **Anonymous POST to the default servlet.** A POST with an import operation can
  plant new repository nodes, which is how a JSP payload gets written to a
  servable path. Blocking POST to the serialisation extensions at the
  Dispatcher is the documented fix.
- **Package Manager.** An authenticated user who can upload a content package
  can include a JSP, which executes on request.
- **OSGi console bundle upload.** With console credentials, a malicious bundle
  is direct code execution.

For all three: **write the probe that proves reachability and stop there.**
The Stage A proof is that the endpoint accepts an authenticated or anonymous
session and reports the capability, for example a Package Manager index page
that renders for your session, or a POST that is rejected for a reason other
than authorisation. Do not plant a node, do not upload a package, do not upload
a bundle. The CVSS impact comes from the advisory, not from your demonstration.

Default credentials (`admin:admin` and the other shipped pairs) are worth a
**single** detection-only attempt each against an administrative endpoint,
logged, with no retry and no spraying, and only if the engagement permits
credential testing at all. One attempt per pair, serial, with the `pace` delay.
Anything beyond that is `hunt-brute-force`'s problem and needs its own sign-off.

## 7. Other misconfigurations with a Stage A tell

- **World-readable user profiles.** Default ACLs on user home profile nodes can
  grant read to everyone. The tell is a profile node returned by a
  serialisation endpoint or by QueryBuilder.
- **Development or debug filters left enabled.** A debug selector on a page
  request producing a layout or component dump is a reflected-XSS and
  information-disclosure surface. The tell is that a debug parameter changes the
  rendered output.
- **A server-side request forgery surface on integration endpoints.** Historic
  AEM versions exposed integration callback URLs that fetch an attacker-supplied
  address. Treat these as `hunt-ssrf` work: canary callback, one parameter
  attributed, no onward requests to third parties.

## 8. False-positive killers specific to AEM

- **The Dispatcher answers for paths that do not exist.** A 200 with a static
  content type is the cache, not the application. Require a body whose structure
  matches the servlet you think you reached.
- **A publish instance is not an author instance.** Many "exposed" endpoints on
  a publish instance return nothing useful by design. Say which instance you
  reached and why you believe it.
- **A 403 from the Dispatcher is not evidence that the servlet is disabled.**
  It is evidence that one path shape is denied. That distinction is the entire
  point of section 5, and it also means a 403 is not proof of a fix: retest a
  patched target with the bypass shapes, not only the plain path.
- **Do not attach a CVE to the wrong product line.** AEM Sites, AEM Forms on
  JEE, AEM Forms on OSGi, Cloud Service and LTS have separate advisories and
  separate affected ranges. APSB25-115's three commonly quoted CVEs explicitly
  do not affect 6.5 and LTS.
- **Version inference from a client-library hash is not a version.** Treat it as
  a change detector between scans, not as a service-pack claim.
- **Third-party enumeration frameworks are loud.** The widely used AEM
  enumeration script sends hundreds of requests including default-credential
  attempts. If you use one, cap it, and never point its own callback listener at
  infrastructure you do not control.

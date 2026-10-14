---
name: nuclei-template-forge
description: "Forge and validate custom Nuclei templates so a finding you confirmed once by hand becomes a repeatable, estate-wide check. Covers the current Nuclei template schema (top-level id/info/http keys, the seven matcher types, the five extractor types, the six severity values), matcher discipline that kills false positives, syntax validation with `nuclei -validate`, the mandatory known-bad / known-good host pair before any fleet run, rate-limit posture for production targets, and the Stage A / Stage B split that keeps a template read-only unless an active payload is signed off in writing. Use when turning a CVE advisory, a disclosed report, or your own manual finding into a scan across the operator's own estate; when building a private CVE-monitor corpus to re-run on a schedule; or when someone says 'write a nuclei template', 'validate this template', or 'scan our estate for this CVE'. NOT for spraying the default community template set at a target, and NOT a discovery tool for unknown bugs."
metadata:
  sources: projectdiscovery-nuclei-docs, nuclei-engine-v3.11.1, community-fork-draft
---

> Authorized testing only: run this against assets you own or that a signed scope or a program's in-scope list names. It is a find-and-report methodology, not a weapon.

## When to use

Trigger when you already know the signature and want it repeated:

- A **CVE advisory plus a public PoC or patch diff** describes an exact
  request/response pair, and the operator has more than one host that might run
  the affected product.
- **Your own confirmed manual finding** on one host, and the same stack is
  deployed on N other hosts in the operator's estate. This is the highest-value
  source: you already know the true-positive behaviour first hand.
- A **fingerprint sweep** — header, favicon hash, or path signature — to map what
  is running where. Severity `info`, an inventory input, not a finding.
- Building a **private corpus to re-run on a schedule**, so new assets and newly
  published CVEs get checked instead of being assumed covered by a one-off scan.

Do NOT use for:

- Spraying the full default community set at a mature target. That produces
  duplicates and noise, not findings.
- Inventing a template for a bug nobody has characterised yet. A template encodes
  a **known** signature; discovery stays manual.
- Recalling a recent CVE's request and response from memory. Feed the real
  advisory text. If you cannot read the advisory, you cannot write the template.

> **The gate, stated once:** no template joins the corpus, and no template is run
> across more than one host, until it has **fired on an instance you know is
> vulnerable AND stayed silent on an instance you know is patched**. Drafting the
> YAML is the small part of this job. Proving the false-positive and
> false-negative rate is the rest of it, and that number does not exist until you
> measure it on both hosts.

---

## Step 1 — Pull the real signature from a primary source

Read the advisory, the public PoC, and where one exists the patch diff. The diff
is the most useful of the three because it shows the exact behavioural difference
between the vulnerable and the patched build, which is precisely what the matcher
has to detect.

Write down four things before opening an editor:

| What | Why it matters |
|---|---|
| Trigger request: method, path, query, headers, body | Becomes the `http` request block |
| Response feature that proves **vulnerable** | Becomes the matcher |
| Response feature of a **patched** host | Tells you what must NOT match |
| Affected version range | Goes in `info.description`, and bounds the sweep |

`scripts/refresh-cve-index.py` in this repo surfaces which in-scope CVEs are not
yet covered; that output is a reasonable forge queue. `docs/disclosed-reports/`
holds distilled public disclosures, many of which describe a repeatable
request-to-response signature worth encoding.

---

## Step 2 — Confirm the schema against the installed engine, not from memory

The template schema is versioned and has changed across major Nuclei releases.
Check what you actually have before writing YAML:

```bash
nuclei -version
```

Everything below was confirmed against **Nuclei Engine v3.11.1** (current release,
2026-08-08: `nuclei -h`, the matcher/extractor type sources, and a live `-validate`
of the Step 3 template) and `docs.projectdiscovery.io`. If your engine reports a
different version, re-confirm before trusting these names.

**Version notes that change behaviour:**
- Since **v3.11.0**, custom templates that use the `javascript:` protocol must be
  signed. Unsigned ones are skipped during template loading and when referenced from
  workflows (code-protocol templates already required a signature). Sign with
  `nuclei -sign -t <template>` (private key from `NUCLEI_SIGNATURE_PRIVATE_KEY`).
  A skipped JS template looks like a Step 5 false negative. The only sign is a load-time
  `[WRN] Found N unsigned or tampered javascript template` line (plus `no templates
  provided for scan` if it was the only one), so check for it before blaming the
  matcher. Official nuclei-templates are pre-signed.
- `-fuzz` is deprecated in favour of `-dast` (`nuclei -h` on v3.11.1). DAST templates
  inject payloads by design, so a `-dast` run is Stage B (Step 6).

**Severity values** (from `nuclei -h`, the `-s, -severity` flag):
`info`, `low`, `medium`, `high`, `critical`, `unknown`. Nothing else is accepted —
`-validate` rejects an invalid value outright, see Step 4.

**Matcher types, seven of them:**
`status`, `size`, `word`, `regex`, `binary`, `dsl`, `xpath`.

**Extractor types, five of them:**
`regex`, `kval`, `json`, `xpath`, `dsl`. Supporting fields include `group` (regex),
`name` and `internal: true` (dynamic extractors), `part`, and `attribute` (xpath).

**Matcher control fields:** `part` (defaults to `body`), `condition: and|or`
(defaults to `or`), `matchers-condition: and|or` (defaults to `or`), and
`negative: true` to invert a matcher.

Both defaults being `or` is the single most important schema fact in this skill.
A template that omits them is wider than its author intended.

---

## Step 3 — Draft the template read-only by default

**Every template is read-only unless Step 6 applies.** Read-only means the request
reads state and the matcher keys on something the response already reveals:
a status code, a response header, or a body string. It does not write, it does not
delete, it does not reboot, and it does not inject a payload that changes
behaviour on the target.

```yaml
id: example-widget-config-disclosure

info:
  name: Example Widget < 2.3 - unauthenticated config disclosure
  author: operator
  severity: high
  description: /api/config returns the admin token pre-auth on Example Widget < 2.3.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-0000
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
    cve-id: CVE-2024-0000
    cwe-id: CWE-200
  metadata:
    verified: true
  tags: cve,cve2024,exposure,example

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/config"
    stop-at-first-match: true
    matchers-condition: and        # explicit: the default is `or`
    matchers:
      - type: word
        part: body
        words:
          - '"admin_token"'
          - '"example_widget"'     # second, product-specific anchor
        condition: and             # explicit: the default is `or`
      - type: word
        part: header
        words:
          - application/json
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Request Rejected"
          - "Access Denied"
        negative: true             # a WAF block page is not a finding
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - '"admin_token"\s*:\s*"([a-f0-9]{32})"'
```

That exact template passes `-validate` on v3.11.1. Matcher rules that earn their
place:

- **Set `matchers-condition: and` and `condition: and` explicitly.** The defaults
  are `or`. Relying on the default is how a template fires on an unrelated 200.
- **Two independent anchors, minimum.** A status code alone, or one generic word
  such as `error` or `token`, matches half the internet. Pair the vulnerability
  marker with a product marker.
- **Match the effect, not the endpoint existing.** A 200 proves the path resolves.
  Match the leaked value, or the version string below the patched floor.
- **Add a `negative: true` matcher for the WAF and error-page bodies** the target
  actually returns. A block page containing your keyword is a false positive, and
  this is the cheapest way to exclude it.
- **Prefer an `extractor` that pulls the proof** over a bare `word` match. The
  extracted value doubles as the evidence line in the report. Redact it before the
  report leaves your machine — see `evidence-hygiene`.
- **For a blind or out-of-band case**, use the engine's interactsh placeholders
  rather than a guessed response string. `{{interactsh-url}}` in the request, then
  match on `part: interactsh_protocol` or `part: interactsh_request`. Other
  placeholders available: `{{BaseURL}}`, `{{Hostname}}`, `{{randstr}}`. Run with
  `-ni` to disable interactsh and skip OAST templates when the engagement forbids
  callbacks to third-party infrastructure.

---

## Step 4 — Validate the syntax

Free, offline, sends nothing to any target. Run it on every draft:

```bash
nuclei -validate -t ./forge/example-widget-config-disclosure.yaml -duc
```

A clean draft prints `All templates validated successfully`. A broken one names
the cause and exits non-zero — this is the real output for a template whose
`severity` was set to `severe`:

```
[ERR] Error occurred loading template ./forge/bad.yaml: cause="Could not load
      template ./forge/bad.yaml: Invalid severity: severe"
[FTL] Could not validate templates: errors occurred during template validation
```

`-validate` checks that the template loads and its fields are legal. It says
nothing about whether the matcher is correct. That is Step 5, and `-validate`
passing is not a substitute for it.

---

## Step 5 — Prove it on a known-bad and a known-good host

Two hosts, both of them yours, both under your control:

- **Known-bad:** an instance you have confirmed is vulnerable — the unpatched
  build, stood up locally.
- **Known-good:** the same product at the patched version, or a hardened
  configuration of it.

Stand both on loopback or on an isolated host in the operator's own lab. Never use
a production asset as either half of this pair, and never use a third party's
system as the known-bad.

```bash
# a) TRUE POSITIVE - must fire on the vulnerable instance
nuclei -validate -t ./forge/t.yaml -duc            # syntax first
nuclei -t ./forge/t.yaml -u http://127.0.0.1:8080/ -duc -v
# Expect a hit. Silent means the matcher is too strict - a false negative.

# b) TRUE NEGATIVE - must stay silent on the patched instance
nuclei -t ./forge/t.yaml -u http://127.0.0.1:8081/ -duc -v
# Expect nothing. A hit means the matcher is too loose - a false positive.
```

| | Vulnerable instance | Patched instance |
|---|---|---|
| **Fires** | true positive — keep | **false positive** — add an anchor, re-test |
| **Silent** | **false negative** — fix the trigger, re-test | true negative — keep |

Both columns pass, or the template does not leave the draft directory. If no
vulnerable instance is available to you, what you have is an **unvalidated draft**.
Mark it `# UNVALIDATED - not for estate-wide use` in the file and keep it out of
the corpus. Confidence from reading an advisory is not a measurement.

---

## Step 6 — Stage B: a template with an active payload

A read-only template that is wrong wastes triage time. A template with an active
payload that is wrong changes state on every host it touches, and a corpus run
multiplies that by the size of the estate. So:

**Stage A — detect (default).** Reachability and version evidence only. Status
code, response header, body string, version banner. No payload, nothing written.
This is what you run across the estate.

**Stage B — active payload. Requires explicit written sign-off from the operator
naming the asset and the payload, obtained before the run.** A template is Stage B
if it does any of the following:

- injects a payload intended to execute, inject, deserialise, or template-render;
- writes, modifies, or deletes any resource on the target;
- triggers an outbound connection from the target to infrastructure you control;
- loops over a candidate list against an authentication endpoint, or does anything
  else that can lock an account or exhaust a resource.

Running the engine with `-dast` (formerly `-fuzz`) is Stage B by definition: DAST
templates inject payloads into the request parts their fuzzing rules target, whatever
the corpus holds.

Stage B templates live in a separate directory from the Stage A corpus, so a
`-t <corpus-dir>` run can never pick one up by accident. Mark the file:

```yaml
# STAGE B - ACTIVE PAYLOAD. Do NOT run without written sign-off naming this asset.
```

When a Stage B template is signed off, run it against **one named host at a time**,
never with `-l`, and require a unique canary echoed back plus a body diff against a
saved Stage A baseline before calling the result confirmed. A keyword appearing in
a response that could be a WAF page is not confirmation.

Never write a template that denies service, mass-scans outside the agreed scope,
or destroys data. For anything that writes, deletes, or reboots, write the
Stage A probe that proves reachability and stop there.

---

## Step 7 — Rate-limit posture before any estate-wide run

The engine's defaults are tuned for throughput, not for a production target. From
`nuclei -h` on v3.11.1:

| Flag | Default | What it does |
|---|---|---|
| `-rl`, `-rate-limit` | **150** requests per second | Global request rate |
| `-rld`, `-rate-limit-duration` | `1s` | The window `-rl` is counted over |
| `-c`, `-concurrency` | **25** | Templates executed in parallel |
| `-timeout` | `10` seconds | Per-request timeout |

**150 requests per second is far too aggressive for a production target.** It is
enough to trip rate limiting, fill the target's logs, and in front of a fragile
appliance to degrade it. Set both flags explicitly on every run against anything
live:

```bash
# Production estate, business hours - conservative
nuclei -l ./hosts.txt -t ./forge-corpus/ -rl 5 -c 5 -duc -o ./forge-hits.txt

# Production estate, agreed maintenance window - still bounded
nuclei -l ./hosts.txt -t ./forge-corpus/ -rl 20 -c 10 -duc -o ./forge-hits.txt

# Your own lab, no third party affected
nuclei -t ./forge/t.yaml -u http://127.0.0.1:8080/ -duc -v
```

Note that `-rlm`, `-rate-limit-minute` is marked DEPRECATED on v3.11.1; use `-rl`
with `-rld` if you need a per-minute window. Take the concrete ceiling from the
engagement's own scope document when it names one; where it does not, 5 requests
per second with `-c 5` is the default posture for a production asset, and anything
above it is a decision the operator makes, not the agent.

---

## Step 8 — Curate the corpus and re-run it over time

- Keep the forged corpus in a directory **separate from the community template
  set**, so `-t` can select one without pulling in the other. One subdirectory per
  engagement where scopes differ, and a separate subdirectory for Stage B.
- Record provenance in `info.reference` — the advisory URL, the report URL, or the
  internal reference for your own finding — plus which known-bad and known-good
  pair it was validated against, and when.
- Dedup against the community set before adding. If an upstream template already
  covers the signature correctly, use that one and spend the effort elsewhere.
- **Re-run on a schedule.** The corpus earns its value over time, because new
  assets appear and new CVEs are published after any one-off scan. A scheduled
  sweep at the Step 7 rate limit is the monitoring play; a single pass is not.
- Template count is not progress. Ten validated templates beat a hundred plausible
  ones, because the hundred cost more in triage than they return in findings.

---

## Chains and related skills

| Skill | Direction | What it hands over |
|---|---|---|
| `web2-recon` | into forge | Live-host and technology-fingerprint lists; the `-l` input for a corpus sweep |
| `recon-scope-triage` | into forge | The authorised asset list and the rate ceiling for Step 7 |
| `triage-validation` | out of forge | A template hit is a lead, not a finding. Run the hit through its gate before reporting |
| `evidence-hygiene` | out of forge | Extractor output may contain a live secret. Redact before the hit reaches a report or a ticket |
| `hunt-exposed-panels` | alongside | Panel and appliance fingerprints that make good `info`-severity inventory templates |
| `hunt-exposed-services` | alongside | External service exposure worth encoding as a recurring check |
| `report-writing` | out of forge | Turning a validated corpus hit into a finding with version evidence |

---

## Validation checklist

Before a template joins the corpus:

- [ ] Signature came from a primary source read this session — advisory, PoC, or
      patch diff — not from memory.
- [ ] `nuclei -version` checked, and the field and matcher names used are the ones
      that engine accepts.
- [ ] `severity` is one of `info`, `low`, `medium`, `high`, `critical`, `unknown`.
- [ ] `matchers-condition` and `condition` are set **explicitly**, because both
      default to `or`.
- [ ] At least two independent anchors, one of them product-specific.
- [ ] A `negative: true` matcher covers the target's WAF or error-page body.
- [ ] The matcher keys on the vulnerable **effect**, not on the endpoint existing.
- [ ] `nuclei -validate -t <file>` prints `All templates validated successfully`.
- [ ] Fired on the known-bad instance. Recorded which instance and when.
- [ ] Stayed silent on the known-good instance. Recorded which instance and when.
- [ ] Read-only, or marked Stage B and filed in the Stage B directory with written
      sign-off naming the asset.
- [ ] `info.reference` records provenance and the validation pair.

Before an estate-wide run:

- [ ] Every target in the `-l` file is in scope and authorised in writing.
- [ ] Corpus directory contains no Stage B template.
- [ ] `-rl` and `-c` set explicitly, at or below the scope's ceiling — never the
      150 requests-per-second default against a production target.
- [ ] Output path set with `-o`, so the run is reviewable instead of scrolling past.

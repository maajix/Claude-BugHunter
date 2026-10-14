---
name: hunt-healthcare-fhir
description: "Hunt authorization flaws in HL7 FHIR R4 healthcare APIs where a token scoped to one patient reaches another patient's records: CapabilityStatement and smart-configuration recon, the Patient compartment as the access boundary, cross-compartment reads via $everything, search chaining and _has, _include and _revinclude as compartment escapes, SMART on FHIR v1 and v2 scope semantics, Bulk Data $export gaps. Read-only; writes and $export kick-off are Stage B. Use on an EHR, patient portal, HIE, telehealth API or any /fhir/, /baseR4/ or SMART endpoint, on sandbox or synthetic data."
metadata:
  sources: hl7-fhir-r4-spec, hl7-patient-compartment-r4, hl7-smart-app-launch-v1, hl7-smart-app-launch-v2, hl7-bulk-data-access-ig, smart-health-it-sandbox, hapi-public-test-server, community-fork-draft
  report_count: 0
---

**Read this before the first request.** Healthcare records are special-category
personal data. The bug class in this skill is, by its nature, one that returns
another person's medical record when it succeeds, so the discipline has to be set
before testing rather than after.

Never retrieve, store, screenshot, or paste real patient data. When a
cross-patient read succeeds, the proof is that **an identifier you are not
entitled to was returned**, or a **status-code differential** between a resource
you own and one you do not, with the response body reduced to a count and a list
of resource types. You do not need the clinical content to prove the finding, and
once you have copied it you are holding data you have no basis to hold.

Testing belongs on a sandbox or a synthetic dataset wherever one exists, and for
FHIR one almost always does. The public FHIR test servers and the vendor developer
sandboxes are the correct venue for this work, and synthetic patient data is
freely generatable. A production FHIR endpoint requires explicit written
authorization that names the data involved — not a generic web-application scope
that happens to include the hostname. If you cannot point at that authorization,
stop and ask for it.

This skill is read-only. No step here writes, updates, or deletes a resource. The
operations that do — creating a `Subscription`, posting a `DocumentReference`,
kicking off an `$export` — are Stage B and need the same written sign-off.

---

## Crown Jewel Targets

FHIR pays off where one authorization mistake exposes a whole record rather than
one field, because the spec's access unit is the patient compartment:

- **Patient portals and patient-facing apps.** A token issued to one patient is
  the cleanest possible test credential: you know exactly which compartment you
  are entitled to, so anything outside it is unambiguous.
- **Health information exchanges and aggregators.** They hold many organisations'
  data behind one API, so a compartment bug crosses organisational boundaries as
  well as patient ones.
- **Third-party SMART on FHIR apps.** Registered against the EHR's authorization
  server, and frequently where launch context is mishandled because the app
  re-reads the patient id from its own URL.
- **Bulk Data endpoints.** `$export` exists specifically to move
  record-set-scale data out of the server. Highest-severity surface by design.
- **Research and analytics FHIR facades** in front of a clinical warehouse, built
  for throughput, inheriting authorization as an afterthought.

Measured baseline for scale: the public HAPI test server at
`https://hapi.fhir.org/baseR4` reports `fhirVersion` `4.0.1` and advertises **146
resource types** in its CapabilityStatement. That is the breadth one compartment
bug exposes.

---

## OOB/Confirmation Gate

### What is NOT confirmation

- A `200` whose contents you cannot attribute to another patient. Many servers
  return an empty `searchset` Bundle with `200`; an empty Bundle is not a leak.
- `Bundle.total` above zero with no entry you can tie to a subject outside your
  compartment.
- A resource id merely resolving. Learning that `Patient/1002` exists is weaker
  than reading anything belonging to it.
- Your own data returned under a different query shape. `patient=`, `subject=` and
  `subject:Patient=` can all resolve to you — resolve the subject reference before
  claiming anything.
- A `403` you did not compare against the `403` the same server gives for a
  resource that does not exist. Without that, you cannot tell refusal from absence.

### What IS confirmation

- **An identifier you are not entitled to, returned to a token you hold.** A
  subject reference such as `Patient/<other-id>`, an `identifier` entry, or a
  `Bundle.entry.fullUrl` pointing outside your compartment. Record the identifier
  and nothing else from the body.
- **A three-case differential.** The same request for (a) a resource inside your
  compartment, (b) one outside it, (c) one that does not exist. Three distinct
  responses is the leak; two identical ones are not.
- **A count differential.** R4 treats `_count=0` the same as `_summary=count`:
  `Bundle.total` with no entries. A total that rises when the query widens past
  your compartment proves the boundary is unenforced **without pulling a single
  record.** Prefer this probe over anything that returns bodies.

### Default workflow

1. Establish your own compartment: read the token response's `patient` context and
   confirm you can read your own records.
2. Run the identical request against an identifier outside your compartment.
3. Run it against an identifier that does not exist.
4. Compare the three. Keep status, headers, `Bundle.total`, and the list of
   `resourceType` values. Discard the bodies.
5. Redact before anything is written down — see `evidence-hygiene`. A FHIR
   response must be redacted before it reaches a report, a ticket, a commit
   message, or a chat message.

---

## Attack Surface Signals

```
/fhir/        /fhir/R4/      /baseR4/      /R4/      /fhir/DSTU2/
/fhir/metadata                       (CapabilityStatement)
/.well-known/smart-configuration     (authorization server + capabilities)
```

Do **not** guess a vendor's base path. Vendor base URLs vary and several have
changed. Take the base URL from the app's registered FHIR endpoint, from
`.well-known/smart-configuration`, or from the client bundle (see
`hunt-source-leak`) rather than from a remembered path.

Schema tells in JSON responses or client code: `Patient`, `Observation`,
`Encounter`, `MedicationRequest`, `DiagnosticReport`, `DocumentReference`,
`Consent`, `Subscription`, `Bundle`, `CapabilityStatement`.

**First recon step. The CapabilityStatement is the FHIR equivalent of a GraphQL
introspection dump**, and it is a plain read:

```bash
BASE="https://target.example/fhir"
curl -s "$BASE/metadata" \
  | jq '.fhirVersion, (.rest[0].resource[] | {type, interaction: [.interaction[].code], searchParam: [.searchParam[].name]})'
```

That enumerates every resource type, every supported interaction, and every search
parameter the server accepts — the input list for every test below. Note which
types advertise `create`, `update`, `patch` or `delete`: that is the Stage B
surface, and knowing it exists is itself a read-only result.

```bash
curl -s "$BASE/.well-known/smart-configuration" | jq .
```

A server advertising the `permission-v1` capability still processes SMART v1
scopes — see `smart-scopes.md`.

---

## Step-by-Step Methodology

1. **Pick the venue.** The public HAPI test server (`https://hapi.fhir.org/baseR4`),
   the SMART App Launcher (`https://launch.smarthealthit.org`) with its R4 sandbox
   at `https://r4.smarthealthit.org`, a vendor developer sandbox, or synthetic data
   you generated — the `synthetichealth/synthea` synthetic patient population
   simulator exists precisely so nobody has to test on real records. A production
   endpoint needs the written authorization described at the top of this file.

2. **Pull the CapabilityStatement and `.well-known/smart-configuration`.** Record
   `fhirVersion`, the resource list, the interactions, the search parameters, and
   `scopes_supported`. Everything after this is scoped to what the server accepts.

3. **Establish your own compartment.** Complete the SMART launch and read the
   token response. The granted `scope` is what you were actually given, which is
   not necessarily what you asked for. Context parameters and their meanings:
   `smart-scopes.md` §5.

4. **Map the compartment you are entitled to.** The linking parameter differs per
   resource type **and changed between FHIR versions**, so read the compartment
   definition for the `fhirVersion` the server reported in step 2 rather than
   carrying a table over. R4 table and the version deltas:
   `search-and-compartment.md` §1.

5. **Probe the boundary with counts first.** For a resource type in your
   compartment, run the identical search for an identifier outside it with
   `_summary=count` and compare `Bundle.total`. No bodies move.
   `search-and-compartment.md` §3.

6. **Test `$everything`.** Both the instance-level and type-level forms. The R4
   spec is explicit that authorization is not the operation's job — "It is assumed
   that the server has identified and secured the context appropriately" — and
   that the type-level form returns "all patients that the user associated with
   the request has access to". So the type-level call asks the server directly what
   it thinks your token can reach. `search-and-compartment.md` §2.

7. **Test search chaining and reverse chaining.** Chains are the
   compartment-escape vector: the server builds a sub-query at each hop and must
   re-apply the filter at every one. `_has` is the highest-value probe because it
   asks the question from the opposite direction and often routes through a
   different query builder. `search-and-compartment.md` §4-5.

8. **Test `_include` and `_revinclude`, including `:iterate`.** The question is
   whether included resources inherit the base query's compartment filter, or are
   fetched by following a reference — a different code path that may never consult
   the compartment. `search-and-compartment.md` §6.

9. **Test SMART scope enforcement and launch-context binding.** Compare what the
   granted scope permits against what the server serves, for both the resource
   type and the permission letter, then replay a request with a different patient
   id to see whether the server trusts the client-supplied parameter over the
   token's bound context. `smart-scopes.md` §3-5.

10. **Enumerate the bulk surface read-only.** The CapabilityStatement and
    `scopes_supported` tell you whether bulk operations and system-tier scopes
    exist without kicking anything off. A kick-off is Stage B.
    `bulk-and-subscription.md` §1. The `system/` tokens behind bulk come from
    SMART Backend Services (asymmetric JWT client authentication, no user), which
    moved from the Bulk Data IG into the SMART App Launch IG at v2.0.0; read it in
    the current SMART App Launch 2.2.0 (STU 2.2), not in older Bulk Data copies
    (<https://hl7.org/fhir/smart-app-launch/backend-services.html>).

11. **Inventory the Subscription surface read-only.** Whether `Subscription`
    advertises `create`, and whether existing ones are readable — their
    `channel.endpoint` and `criteria` values frequently disclose internal hosts or
    other patients' identifiers. Both are GETs. Creating one is Stage B.
    `bulk-and-subscription.md` §2.

12. **Diff versions and undocumented bases.** A server exposing both `/fhir/R4/`
    and an older `/fhir/DSTU2/` base frequently enforces authorization on only one.
    Hand the enumeration to `hunt-shadow-api`.

**Rate posture throughout.** These are database queries against a clinical
system. Serial, one request at a time, at least 1 second between them, and no loop
over identifiers without the operator's agreement on the rate. The `_include=*`
wildcard is expensive by the spec's own warning — run it once, never in a loop.

---

## Payload & Detection Patterns

Every probe in this skill is a **GET**. The exact syntax, with the spec's own
examples, lives in the reference files below; the three that matter most:

```bash
# 1. Count-only compartment probe - run this before anything that returns bodies
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Observation?patient=$OTHER_PATIENT_ID&_summary=count" | jq '.total'

# 2. Reverse chain - asks the question from the other direction
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Patient?_has:Observation:patient:code=1234-5&_summary=count" | jq '.total'

# 3. Launch-context trust - same token, substituted patient id
curl -s -H "Authorization: Bearer $TOKEN_BOUND_TO_PATIENT_A" \
  "$BASE/MedicationRequest?patient=$PATIENT_B_ID&_summary=count" | jq '.total'
```

If entries do come back, keep the shape and discard the content:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Patient/$OTHER_PATIENT_ID/\$everything?_type=Observation&_count=5" \
  | jq '[.entry[].resource.resourceType] | group_by(.) | map({(.[0]): length}) | add'
```

### References index

| File | Coverage | Trigger phrases |
|---|---|---|
| `smart-scopes.md` | `.well-known/smart-configuration` keys and capabilities; SMART v1 clinical-scope grammar and the `patient/` vs `user/` tier; v2 granular `.cruds` letters; scope search-parameter restriction; the v1-to-v2 mapping and the `.write` to `.cud` check; launch context scopes; token response context parameters; the launch-context trust probe; identity and refresh scopes | SMART on FHIR scopes, patient/*.read, user/*.*, cruds scopes, granular scopes, launch context, launch/patient, fhirUser, offline_access, permission-v1, scope escalation |
| `search-and-compartment.md` | R4 Patient compartment table and the cross-version deltas; `$everything` both forms and parameters; `_summary=count` and `_count=0` probes; chained search and the `:Patient` type modifier; `_has` reverse chaining including nesting; `_include`/`_revinclude` and `:iterate`; the R4 modifier list; the bypass order when a direct read is refused | patient compartment, $everything, chained search, _has, reverse chaining, _include, _revinclude, iterate, search modifiers, :identifier, compartment bypass, cross-patient search |
| `bulk-and-subscription.md` | `$export` Stage A enumeration; the three kick-off URL forms; `Prefer: respond-async`; the async flow with `Content-Location`, `X-Progress`, `Retry-After`, `X-Export-Status`; manifest fields and the `requiresAccessToken` check; R4 `Subscription` element reference; Stage A subscription read; Stage B rules and cleanup; evidence handling for both | bulk data export, $export, NDJSON, bulk manifest, requiresAccessToken, Content-Location polling, FHIR Subscription, rest-hook, channel.endpoint, subscription SSRF |

Load only the file you need. Each is self-contained.

---

## Common Root Causes

1. **Access control checked at the resource-type level instead of the compartment
   level.** The server correctly answers "may this token read `Observation`" and
   never asks "does this `Observation` belong to a patient this token is scoped
   to". The most common shape by far, and why `$everything` and a type-level search
   often behave differently on the same server.
2. **Launch context read from the request instead of the token.** The token
   exchange binds the token to one patient; the resource endpoint then re-reads
   `patient=` from the query string because that is what the client sends. The
   authorization decision gets made from attacker-controlled input.
3. **Chained and reverse-chained sub-queries built by a generic query builder.**
   The base query is compartment-scoped; the sub-query at each `_has` or chain hop
   is assembled without re-applying the filter. The R4 note that chains are
   evaluated independently is the design that makes this easy to get wrong.
4. **`_include` resolved by reference rather than by authorization.** The base
   search is filtered, then included resources are fetched by following
   references — and following a reference is not the same code path as answering a
   search, so the second path never consults the compartment.
5. **Bulk output URLs treated as sufficiently obscure.** A long random presigned
   URL feels unguessable, so no token check is added and the IG's
   `requiresAccessToken=true` requirement goes unmet. The URL then leaks through
   logs, a referrer header or browser history and becomes a standing export link.
6. **`Subscription.channel.endpoint` with no allowlist.** The server checks that
   the caller may create a subscription, never that the destination is a host the
   operator controls.
7. **Scope strings parsed loosely.** A malformed or out-of-order v2 scope, or a v1
   `.write` mapped to `.cruds` instead of `.cud`, grants more than was requested.
8. **An older FHIR base left mounted beside the current one**, with authorization
   wired to only one of them.

---

## Bypass Techniques

When the direct cross-compartment read is refused, the filter is usually applied
on one code path and not another. **Vary the path, not the payload.** Full
sequence with exact syntax in `search-and-compartment.md` §8; the order:

1. Change the lookup key — `:identifier` searches by business identifier rather
   than resource id, a different lookup and possibly a different check.
2. Change the reference form — `subject:Patient=23` has the same effect as
   `subject=Patient/23` per the spec, but is a different parameter parse.
3. Move the identifier between path and query. Instance reads and type-level
   searches are frequently enforced separately.
4. Reverse the direction — `_has` instead of a forward filter.
5. Add a hop — `_include:iterate=` extends an include past its first hop.
6. Change the resource type. Enforcement is often not uniform; walk the
   CapabilityStatement's resource list rather than assuming it is.
7. Try an older base path, then hand the enumeration to `hunt-shadow-api`.
8. Check the compartment table against the server's own reported `fhirVersion`.

Not a bypass, and out of scope for this skill: anything that writes. If the only
way past a control is to create or modify a resource, that is Stage B and needs
written sign-off naming the asset and the data.

---

## Gate 0 Validation

1. **Is the identifier actually outside your compartment?** Resolve the subject
   reference and confirm it is not your own patient id in a different form. This is
   the most common false positive in FHIR testing.
2. **Did you run the non-existent-identifier control?** If the response for
   "another patient's" matches "does not exist", you have found nothing.
3. **Was the response actually non-empty?** A `200` with an empty `searchset`
   Bundle is the correct, secure answer. Check `total` and `entry`, not the status.
4. **Is it reproducible with a token you legitimately hold**, rather than
   contingent on an identifier you were handed out of band? Show the exact
   request, the exact status, and the counts.
5. **Did you avoid retrieving clinical content?** If the finding needed a diagnosis
   or a medication to prove, redo it with `_summary=count` and prove it from the
   differential instead.
6. **For a bulk-export finding: does the file URL work without the bearer token,
   and does the manifest say `requiresAccessToken: true`?** Both halves are needed
   — the manifest claim is what makes it a spec violation rather than a design.
7. **For a Subscription finding: did a callback you control actually receive
   something?** An accepted subscription with no confirmed delivery is weaker.
   `hunt-ssrf` owns that gate.
8. **Did you clean up?** Any Stage B artifact must be removed and the removal
   recorded.

---

## Real Impact Examples

**Scenario A — compartment unenforced on a type-level search.** A patient-portal
token carries `patient/*.read` and a bound `patient` context. Instance reads are
enforced, so `Patient/<other>` returns `403`. But
`Observation?patient=<other>&_summary=count` returns a non-zero `total`, and a
five-entry sample returns `subject` references to another patient. Impact is every
observation for every patient on the server, provable from the count differential
alone without reading one clinical value.

**Scenario B — launch context taken from the request.** A SMART app's token is
bound to patient A; the resource server re-reads `patient=` from the query string,
so `MedicationRequest?patient=B` answers for B. Because the app is a legitimately
registered third-party client, every one of its users becomes an authenticated
reader of the whole patient population.

**Scenario C — bulk manifest asserts a control it does not apply.** An `$export`
manifest sets `requiresAccessToken: true`, and the `output[].url` NDJSON files
serve to an unauthenticated request from a different address. The URLs are long and
random, so the team considered them protected. Each is a standing
record-set-scale PHI export link that will outlive the engagement unless expired.
Highest-severity finding available on a FHIR target, and the manifest's own
`requiresAccessToken` value is what proves the server intended the control.

---

## Related Skills & Chains

- **`hunt-oauth`** — owns the SMART on FHIR flow. SMART is OAuth 2.0:
  redirect_uri validation, PKCE, code interception, token handling and storage all
  belong there, unchanged. **The boundary:** `hunt-oauth` owns the flow, this
  skill owns the scope semantics — what `patient/` versus `user/` versus `system/`
  means, what the `cruds` letters grant, the v1-to-v2 mapping, and launch-context
  binding. Chain: authorize endpoint found via `.well-known/smart-configuration` →
  `hunt-oauth` for the flow → back here for whether the granted scope is enforced
  on the resource endpoints.
- **`hunt-idor`** — cross-patient access is IDOR-shaped and that skill owns the
  general class: identifier enumeration, predictable ids, the cross-account
  comparison method. **The boundary:** `hunt-idor` owns one object reached by a
  changed identifier. This skill owns the case where the access unit is a
  **compartment** rather than an object, so one bypass returns a whole record set,
  and where the escape vector is a FHIR search mechanism — chaining, `_has`,
  `_include`, `$everything` — rather than a changed id in a path. "I changed an id
  in a URL" is IDOR; "the compartment filter is not applied to the sub-query" is
  this skill.
- **`hunt-api-misconfig`** — owns generic REST exploitation once you hold an
  endpoint: mass assignment, verb tampering, missing function-level authorization.
  Use it for FHIR `PATCH`/`PUT` on client-writable fields, which is Stage B here
  because it writes.
- **`hunt-shadow-api`** — owns version-surface enumeration. Hand it the
  multiple-FHIR-base case and the behavioural diff between versions.
- **`hunt-ssrf`** — owns the SSRF payload set and the callback confirmation gate
  for `Subscription.channel.endpoint`. Note that R4 `ValueSet/$expand` requires the
  server to **already know** the value set rather than fetching the `url`
  parameter, so do not treat terminology expansion as an SSRF entry point without
  evidence from the specific implementation.
- **`hunt-graphql`** — the CapabilityStatement plays the role introspection plays
  there, so the "dump the schema, then test authorization per field" instinct
  transfers; the mechanics do not.
- **`hunt-source-leak`** — patient-portal web and mobile clients routinely embed
  the FHIR base URL, the SMART client id, and the scopes they request. That is how
  you learn the base path instead of guessing it.
- **`evidence-hygiene`** — **mandatory here, not optional.** PHI is a stricter
  redaction category than generic PII. A FHIR response must be redacted before it
  reaches a report, a ticket, a screenshot or a chat message: reduce the body to a
  count and a list of resource types, keep at most one identifier as proof, retain
  nothing else. Apply its black-bar protocol to any patient name, MRN, date of
  birth, diagnosis or medication, and its post-submission hygiene to delete local
  copies when the report is filed.
- **`triage-validation`** — run the Gate 0 list above through its gate before
  drafting. "The compartment filter can probably be bypassed" without a documented
  three-case differential is exactly the claim that gate exists to reject.
- **`report-writing`** — a FHIR finding needs its blast radius framed as record
  sets and patient counts, stated without reproducing any record.

# FHIR R4 search mechanics and the Patient compartment

Exact R4 syntax for every search mechanism this skill tests, plus the compartment
model that defines what "another patient's data" means. All syntax below was
confirmed against the HL7 FHIR R4 specification (`hl7.org/fhir/R4`).

Every request in this file is a **GET**. Nothing here writes.

Rate posture: these are database queries against a clinical system. One request at
a time, at least 1 second between them, and no loop over identifiers without the
operator's agreement on the rate.

---

## 1. The Patient compartment

R4 defines the membership rule as: "A resource is in this compartment if the
nominated search parameter (or chain) refers to the patient resource." There is
one compartment instance per `Patient` resource.

**The compartment, not the resource, is the access unit on most FHIR servers.**
That is why one enforcement gap returns a whole record set rather than one field.

The linking parameter differs per resource type. R4 v4.0.1, first rows of the
Patient compartment definition:

| Resource | R4 inclusion parameter |
|---|---|
| Account | subject |
| AdverseEvent | subject |
| AllergyIntolerance | patient or recorder or asserter |
| Appointment | actor |
| AppointmentResponse | actor |
| AuditEvent | patient |
| Basic | patient or author |
| BodyStructure | patient |
| CarePlan | patient or performer |
| CareTeam | patient or participant |
| ChargeItem | subject |
| Claim | patient or payee |
| ClaimResponse | patient |
| ClinicalImpression | subject |
| Communication | subject or sender or recipient |
| CommunicationRequest | subject or sender or recipient or requester |
| Composition | subject or author or attester |
| Condition | patient or asserter |
| Consent | patient |
| Coverage | policy-holder or subscriber or beneficiary or payor |
| CoverageEligibilityRequest | patient |
| CoverageEligibilityResponse | patient |
| DetectedIssue | patient |
| DeviceRequest | subject or performer |
| DeviceUseStatement | subject |

Resource types that are **never** in the Patient compartment include `Device`,
`Location`, `Organization` and `Practitioner`.

### Why the version matters

The table above is **R4**. The current FHIR build differs on several rows, for
example:

| Resource | R4 | Current build |
|---|---|---|
| Consent | patient | subject |
| AllergyIntolerance | patient or recorder or asserter | patient or participant |
| Condition | patient or asserter | patient or participant-actor |
| CommunicationRequest | subject or sender or recipient or requester | subject or information-provider or recipient or requester |

A server implementing one version's compartment table while serving another
version's resources has a genuine enforcement gap: a resource reachable by a
parameter the server's table does not list is a resource the compartment filter
will not catch. **Read the compartment definition for the `fhirVersion` the
server reported in its CapabilityStatement.** Do not carry the table over from
another version.

### Linked patients

R4 handles linked patients separately. Records of a linked `Patient` are not
returned in a compartment search for another patient; they appear only in a
search using the linked patient's own id. A server that merges them is widening
the compartment.

---

## 2. `$everything`

Two URL forms:

```
[base]/Patient/$everything          # type level, no patient nominated
[base]/Patient/[id]/$everything     # instance level
```

Parameters: `start`, `end` (both filter by care dates, not record update dates),
`_since` (instant — resources updated after this time), `_type` (code, repeatable,
comma-delimited resource types), `_count` (paging).

The spec is explicit that authorization is **not** the operation's job:

> "It is assumed that the server has identified and secured the context
> appropriately."

For the type-level form with no patient nominated, the returned scope is "all
patients that the user associated with the request has access to". So the
type-level call is the direct question of what the server believes your token can
reach — and a count-only form of it costs one request:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/Patient/\$everything?_count=0" | jq '.total'
```

The server SHOULD return at least all resources it has that are in the patient
compartment, and may return an error rather than all records for an overly broad
request. The operation is idempotent; GET is the form the spec shows.

Instance-level, outside your compartment, status only:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" \
  "$BASE/Patient/$OTHER_PATIENT_ID/\$everything"
```

If entries do come back, keep the shape and discard the content:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Patient/$OTHER_PATIENT_ID/\$everything?_type=Observation&_count=5" \
  | jq '[.entry[].resource.resourceType] | group_by(.) | map({(.[0]): length}) | add'
```

---

## 3. Count-only probes — use these first

R4 treats `_count=0` the same as `_summary=count`: it returns `Bundle.total` with
no entries. **This is the probe that proves a compartment bug without moving a
single record.** Prefer it over anything that returns bodies.

```bash
# Baseline inside your compartment
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Observation?patient=$MY_PATIENT_ID&_summary=count" | jq '.total'

# Outside your compartment - a non-zero total is the finding
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Observation?patient=$OTHER_PATIENT_ID&_summary=count" | jq '.total'

# Control: an id that does not exist
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Observation?patient=no-such-id-$RANDOM&_summary=count" | jq '.total'
```

`_total` accepts `none`, `estimate` or `accurate`, is trial-use in R4, and servers
may ignore it. A server that answers `estimate` when refused and `accurate` when
permitted has handed you a differential.

Paging: `_count` instructs the server how many resources to return per page.
Servers SHALL NOT return more than requested but may return fewer, and should
repeat the original `_count` in their page links.

---

## 4. Chained search

The compartment-escape mechanism, because the server builds a sub-query at each
hop and must re-apply the compartment filter at every one of them.

```bash
# Basic chain
curl -s "$BASE/DiagnosticReport?subject.name=peter&_summary=count"

# Type-restricted chain. The :Patient modifier is required when the reference
# parameter can point at more than one resource type.
curl -s "$BASE/DiagnosticReport?subject:Patient.name=peter&_summary=count"

# Reference type modifier. The spec says subject:Patient=23 "has the same effect"
# as subject=Patient/23 - same effect, different parameter parse, so test both.
curl -s "$BASE/Observation?subject:Patient=$OTHER_PATIENT_ID&_summary=count"
```

The R4 spec notes that multiple chains are evaluated **independently**: in
`Patient?general-practitioner.name=Joe&general-practitioner.address-state=MN`,
"no one practitioner need satisfy both conditions." That independence is the
design that makes dropping the filter on one hop easy.

---

## 5. Reverse chaining with `_has`

Pattern: `_has:<SourceType>:<referenceParam>:<param>=<value>`

```bash
# Which patients have an Observation with this code? If a patient-scoped token
# gets an answer spanning the server, the filter is not applied to the sub-query.
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Patient?_has:Observation:patient:code=1234-5&_summary=count" | jq '.total'

# OR values on one _has
curl -s "$BASE/Patient?_has:Observation:patient:code=123,456&_summary=count"

# Nested _has - two hops, two chances to drop the filter
curl -s "$BASE/Patient?_has:Observation:patient:_has:AuditEvent:entity:user=MyUserId&_summary=count"
```

Multiple `_has` parameters are allowed and each is processed independently.

`_has` is the highest-value probe in this file, because it asks the question from
the opposite direction: instead of "give me this patient's observations", it asks
"give me the patients matching an observation criterion", which some
implementations route through an entirely different query builder.

---

## 6. `_include` and `_revinclude`

Format: source resource name, the reference search parameter, and an optional
target type, colon-separated. Repeat the parameter for each include — values are
**not** comma-combined.

```bash
curl -s "$BASE/MedicationRequest?_include=MedicationRequest:patient&_count=0"
curl -s "$BASE/MedicationRequest?_revinclude=Provenance:target&_count=0"
```

`:iterate` goes on the **parameter name** and is **not** the default:

```bash
curl -s "$BASE/MedicationDispense?_include=MedicationDispense:prescription&_include:iterate=MedicationRequest:performer&_count=0"
```

The wildcard `*` is permitted for the search parameter name. The spec warns it
can be expensive, so run it once, serially, never in a loop:

```bash
curl -s "$BASE/Patient?_id=$MY_PATIENT_ID&_include=*&_count=0"
```

The question for both parameters is whether the included resources inherit the
compartment filter applied to the base query, or are fetched by following a
reference — because following a reference is a different code path from answering
a search, and the second path may never consult the compartment.

---

## 7. Modifiers

Exact R4 modifier names, with the spec's own examples:

| Modifier | Example |
|---|---|
| `:missing` | `gender:missing=true` |
| `:exact` | `given:exact=Eve` |
| `:contains` | `given:contains=eve` |
| `:not` | `gender:not=male` |
| `:above` | `encounter:above=21` (reference), `url:above=http://acme.org/fhir/ValueSet/123/_history/5` (uri) |
| `:below` | `code:below=126851005` (token), `location:below=42` (reference) |
| `:in` | `code:in=http://acme.org/fhir/ValueSet/cardiac-conditions` |
| `:not-in` | Defined as testing that a coding is not in a value set. The spec gives no example |
| `:identifier` | `subject:identifier=http://acme.org/fhir/identifier/mrn|123456` |
| `:text` | `code:text=headache` |

`:of-type` appears in the R4 modifier table with the format `system|code|value`,
while the page's own example uses `identifier:otype=...`. The spec does not
reconcile the two names, so **confirm which one the target server accepts before
asserting either** — if a test depends on it, test both and report what answered.

`:identifier` is the most useful of these for authorization testing: it searches
by **business identifier** rather than resource id, which is a different lookup
path and may miss a compartment check wired only to the id path.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/Observation?subject:identifier=http://target.example/fhir/identifier/mrn|123456&_summary=count"
```

---

## 8. Bypass order when the direct read is refused

When `Observation?patient=<other>` is refused, the filter is usually applied on
one code path and not another. Vary the path, not the payload:

1. **Change the lookup key** — `:identifier` instead of the resource id.
2. **Change the reference form** — `subject:Patient=23` instead of
   `subject=Patient/23`.
3. **Move the identifier between path and query** — instance reads and
   type-level searches are frequently enforced separately.
4. **Reverse the direction** — `_has` instead of a forward filter.
5. **Add a hop** — `_include:iterate=` extends an include past its first hop.
6. **Change the resource type** — enforcement is often not uniform. Walk the
   CapabilityStatement's resource list rather than assuming it is.
7. **Try an older base path** — `/fhir/DSTU2/` beside `/fhir/R4/`. Hand the
   enumeration to `hunt-shadow-api`.
8. **Check the compartment table against the server's own `fhirVersion`** — see
   section 1.

Not a bypass, and out of scope: anything that writes. If the only way past a
control is to create or modify a resource, that is Stage B and needs written
sign-off.

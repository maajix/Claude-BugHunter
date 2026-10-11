# SMART on FHIR scope and launch-context semantics

`hunt-oauth` owns the OAuth flow itself — redirect_uri validation, PKCE, code
interception, token storage. This file owns what the scope strings **mean** and
how to test whether the server enforces them. All field names and grammar below
were confirmed against the HL7 SMART App Launch specification.

---

## 1. Discovery: `.well-known/smart-configuration`

```bash
curl -s "https://target.example/fhir/.well-known/smart-configuration" | jq .
```

Measured against a live SMART sandbox, the document returns these keys:

`authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, `issuer`,
`jwks_uri`, `capabilities`, `scopes_supported`, `grant_types_supported`,
`response_types_supported`, `code_challenge_methods_supported`,
`token_endpoint_auth_methods_supported`.

The `capabilities` array names what the server supports. Values observed on that
sandbox: `launch-ehr`, `launch-standalone`, `client-public`,
`client-confidential-symmetric`, `client-confidential-asymmetric`,
`sso-openid-connect`, `context-passthrough-banner`, `context-passthrough-style`.

A server advertising **`permission-v1`** is declaring that it still processes
SMART v1 scopes. That is the trigger to test the v1-to-v2 mapping in section 4.

Read `scopes_supported` before requesting anything: it tells you which tiers
(`patient/`, `user/`, `system/`) the server will even consider.

---

## 2. SMART v1 clinical scopes

The v1 guide gives this grammar:

```
clinical-scope ::= ( 'patient' | 'user' ) '/' ( fhir-resource | '*' ) '.' ( 'read' | 'write' | '*' )
```

| Scope | Grants |
|---|---|
| `patient/Observation.read` | Read observations for the **current patient** only |
| `patient/Patient.read` | Read the current patient's demographics. Note `patient` is the tier and `Patient` is the resource |
| `patient/*.read` | Read all available data for the current patient, including resource types added to the server later |
| `patient/Observation.write` | Add observations for the current patient. Write does **not** imply read |
| `user/Observation.read` | Read observations **the user can access, across patients** |
| `user/*.*` | Read and write everything the current user can access |

Two things to take from the table:

- **The tier prefix is the whole game.** `user/*.read` granted to a
  patient-facing app is over-broad by construction, independent of any server
  bug — the app is asking for everything its signed-in user can reach rather than
  everything one patient's record contains.
- **A `*` in the resource position covers resource types that do not exist yet.**
  The spec says it requests all data for all available resources "both now and in
  the future", so a `patient/*.read` grant silently widens as the server adds
  resource types.

Servers may grant a scope different from the one requested, and the spec expects
clients to check what they were actually granted. A client that assumes it got
what it asked for is its own finding.

---

## 3. SMART v2 granular scopes

Pattern: `{patient|user|system}/{ResourceType|*}.{letters}` where the letters are
an **in-order subset of the string `cruds`**.

| Letter | Grants |
|---|---|
| `c` | create — type-level create |
| `r` | read — instance read, vread, history |
| `u` | update — instance update and patch. On some servers an update may create an instance |
| `d` | delete — instance delete |
| `s` | search — type- and system-level search and history |

- `patient/Observation.rs` — read plus search.
- `patient/Observation.cu` — create plus update, with **no read**.
- Scopes are space-separated and combine as a union: `Observation.rs` is
  equivalent to `Observation.r Observation.s`.
- **Write access does not imply read access.**
- Letters out of order or undefined, such as `.dus`, may be ignored, replaced, or
  rejected. A server that silently accepts a malformed scope string and grants
  something is worth examining: what did it grant?

### Search-parameter restriction on a v2 scope

A v2 scope may carry a query restriction, appended with `?` and `&`-joined pairs:

```
patient/Observation.rs?category=http://terminology.hl7.org/CodeSystem/observation-category|laboratory
```

That is intended to restrict read and search to laboratory observations only.

**How to test it, read-only:** request a different `category` value, then request
with no `category` at all, and compare `Bundle.total` using `_summary=count`
each time. A restriction that is recorded in the token but not applied at query
time shows up as an unchanged total.

The spec marks modifiers, chaining (for example `patient.birthdate=1990`), and
`_filter` inside a scope restriction as **experimental** — which is precisely
where enforcement is thinnest, so that is where to look first.

---

## 4. The v1-to-v2 mapping, and the one to check

Servers that advertise `permission-v1` should process v1 scopes with this
mapping:

| v1 | becomes v2 |
|---|---|
| `.read` | `.rs` |
| `.write` | **`.cud`** |
| `.*` | `.cruds` |

**`.write` is the mapping to verify.** `.write` must become `.cud` — create,
update, delete — and must **not** include `r` or `s`. A server that maps
`.write` to `.cruds` has silently converted a write-only grant into a read grant
over the same resource type. Test it by requesting a `.write`-only v1 scope and
then attempting a plain read of that resource type; a successful read is the
finding, and the count probe is enough to prove it.

---

## 5. Launch context

Launch context scopes: `launch`, `launch/patient`, `launch/encounter`. With
`launch`, the app also passes through the EHR's `launch` URL parameter with the
same value. Other resource types may be requested in lowercase (for example
`launch/diagnosticreport`), optionally with `?role=`; those forms are marked
experimental.

Token response context parameters:

| Parameter | Type | Notes |
|---|---|---|
| `patient` | string | Patient id. **Patient-tier scopes are scoped to this patient** — this value is the authorization boundary |
| `encounter` | string | Encounter id |
| `need_patient_banner` | boolean | `false` means the app may not need to display a patient banner |
| `smart_style_url` | URL | Points at a SMART Style JSON object. Experimental |
| `fhirContext` | array | For resource types other than Patient or Encounter. Each object carries at least one of `reference`, `canonical`, `identifier`, and may carry `type` and `role`. Experimental |
| `intent` | string | Launch purpose. Values are not standardised by SMART |
| `tenant` | string | Tenant identifier |

### The launch-context trust probe

The token is bound to one patient by the launch. The question is whether the
**resource** endpoint honours that binding or re-reads the patient from the
request. Read-only, count only:

```bash
# Baseline: your own compartment
curl -s -H "Authorization: Bearer $TOKEN_BOUND_TO_PATIENT_A" \
  "$BASE/MedicationRequest?patient=$PATIENT_A_ID&_summary=count" | jq '.total'

# Same token, substituted id. A non-zero total here is the finding.
curl -s -H "Authorization: Bearer $TOKEN_BOUND_TO_PATIENT_A" \
  "$BASE/MedicationRequest?patient=$PATIENT_B_ID&_summary=count" | jq '.total'

# Control: an id that does not exist, so you can tell refusal from absence
curl -s -H "Authorization: Bearer $TOKEN_BOUND_TO_PATIENT_A" \
  "$BASE/MedicationRequest?patient=does-not-exist-$RANDOM&_summary=count" | jq '.total'
```

Three distinct responses across those three requests is the leak. Two identical
ones are not.

---

## 6. Identity and refresh scopes

| Scope | Effect |
|---|---|
| `openid` | Authenticates the user. The app receives an `id_token` alongside the access token and must validate it per OIDC |
| `fhirUser` | Requires `openid`. The `fhirUser` claim is a URL to a FHIR resource for the current user, of type `Patient`, `Practitioner`, `PractitionerRole`, `RelatedPerson` or `Person` |
| `online_access` | Requests a refresh token usable as long as the end user stays online |
| `offline_access` | Requests a refresh token usable regardless of whether the end user is online, for as long as the authorization server and end user allow |

`fhirUser` is useful recon on its own: the claim tells you which resource type the
server considers the signed-in principal, which tells you whether you are inside
a patient compartment or acting as a practitioner with a much wider reach.

`offline_access` on a patient-facing third-party app is worth flagging on its own
merits — a long-lived refresh token held by a third party against a healthcare
record is a standing exposure even when every control works as designed.

# Bulk Data `$export` and `Subscription` — Stage A / Stage B

These are the two FHIR surfaces that move data at record-set scale by design, so
they carry the highest severity and the strictest handling rules in this skill.

**Both have a read-only Stage A that is a real deliverable on its own.** Do Stage
A first. Stage B needs explicit written sign-off from the operator naming the
asset and the data involved, obtained before the request is sent.

Field names, header names and spec quotations below come from the HL7 Bulk Data
Access (Flat FHIR) implementation guide and the FHIR R4 `Subscription` resource
definition.

---

## 1. Bulk Data `$export`

### Stage A — read-only enumeration

Both of these are plain GETs and neither starts a job:

```bash
# Does the server advertise the operation, and on which resources?
curl -s "$BASE/metadata" | jq '.rest[0].operation, .rest[0].resource[].operation' 2>/dev/null

# Does the authorization server offer system-tier scopes at all?
curl -s "$BASE/.well-known/smart-configuration" | jq '.scopes_supported'
```

If `scopes_supported` advertises `system/*.read` or similar system-tier scopes,
the bulk surface exists and is reachable in principle. That fact, plus the
operation advertisement, is reportable without ever kicking off an export.

### Stage B — the kick-off

```
# STAGE B - needs written sign-off naming the asset and the data.
POST [fhir base]/$export                  # system level - every patient
POST [fhir base]/Patient/$export          # all patients
POST [fhir base]/Group/[id]/$export       # one group
```

Required header: `Prefer: respond-async`. A consumer SHOULD include it to
indicate asynchronous processing; if omitted, the provider MAY return an error or
MAY process the request as if `respond-async` had been supplied.

A consumer MAY also send `Prefer: respond-async,separate-export-status`. When
that value is supplied and supported, the provider SHALL return a
`Preference-Applied` header carrying both values.

### The async flow

| Phase | Response |
|---|---|
| Kick-off accepted | HTTP `202 Accepted` plus a **`Content-Location`** header holding the absolute URL of the status endpoint |
| In progress | `202 Accepted`, optional **`X-Progress`** header (free-text status under 100 characters, e.g. `"50% complete"`), plus **`Retry-After`** (seconds, e.g. `120`, or an HTTP-date) |
| Complete | `200 OK` with `Content-Type: application/json` and the manifest as the body |
| Error | `500 Internal Server Error` with `Content-Type: application/fhir+json` and an `OperationOutcome` body |

With `separate-export-status` in effect, the HTTP status becomes `200 OK` and the
export status moves into an **`X-Export-Status`** header instead.

If the provider wants to prevent a new export while one is in progress, it SHOULD
answer `429 Too Many Requests` with a `Retry-After` header.

**Poll with the server's own `Retry-After` value.** The IG tells consumers to use
exponential backoff, and warns that a provider SHOULD answer excessively frequent
status queries with `429 Too Many Requests` and MAY terminate the session. Polling
in a tight loop is a self-inflicted denial of service against a clinical system.

### The manifest, and the check that matters

Confirmed manifest fields from the IG's own minimal example:

```json
{
  "manifestType": "http://hl7.org/fhir/uv/bulkdata/StructureDefinition/BulkDataManifest",
  "transactionTime": "2021-01-01T00:00:00Z",
  "requiresAccessToken": true,
  "output": [{
      "type": "Patient",
      "url": "https://example.org/output/patient_file_1.ndjson"
    }]
}
```

The authorization requirement, quoted from the IG:

> When SMART Backend Services Authorization is used, Bulk Data Status Requests and
> Bulk Data Output File Requests with `requiresAccessToken=true` SHALL be
> protected the same way as the Bulk Data Kick-off Request, including an access
> token with scopes that cover all resources being exported.

The IG also notes that a provider MAY restrict status and output-file requests to
the consumer that originated the export, and MAY use authorization schemes other
than OAuth 2.0 such as mutual TLS or signed URLs.

**So the highest-severity check on this surface is a two-part comparison:**

1. Does the manifest set `requiresAccessToken: true`?
2. Does an `output[].url` serve content to a request with **no** `Authorization`
   header, from a different address and session?

Both true is a direct violation of the IG requirement, and the manifest's own
`requiresAccessToken` value is what proves the server intended the control. A long
random presigned URL is not the control; the token check is.

```bash
# Status-only. Do not download the NDJSON body.
curl -s -o /dev/null -w "%{http_code}\n" "$NDJSON_URL_FROM_MANIFEST"
```

Check the status code and nothing else. **Do not download the file.** An NDJSON
export file is bulk PHI; a `200` with a non-zero `Content-Length` is the finding
and you do not need its contents:

```bash
curl -s -o /dev/null -D - "$NDJSON_URL_FROM_MANIFEST" | head -20
```

If sign-off for the kick-off is not forthcoming, say so and stop. Stage A is
still a real deliverable, and the note "this server exposes a system-tier bulk
export surface, unverified" is honest where a fabricated manifest check would not
be.

---

## 2. `Subscription`

### R4 element reference

| Element | Card. | Allowed values and notes |
|---|---|---|
| `status` | 1..1 | `requested`, `active`, `error`, `off` |
| `criteria` | 1..1 | A search string, interpreted as if appended to the base URL. Applied to the **new** value of a resource, so deletes and updates that stop matching do not notify |
| `channel.type` | 1..1 | `rest-hook`, `websocket`, `email`, `sms`, `message` |
| `channel.endpoint` | 0..1 | An HTTP URL for rest-hook, a `mailto:` address for email, a `tel:` number for sms, a `$process-message` URL for message. The websocket URL is advertised in the CapabilityStatement |
| `channel.payload` | 0..1 | MIME type: `application/fhir+json` or `application/fhir+xml`. `text/plain` may be used for email and SMS. **Omit for no payload** |
| `channel.header` | 0..* | Channel-dependent; e.g. an `Authorization` header for rest-hook, or an email subject line |
| `reason` | 1..1 | Why the subscription was created |
| `end` | 0..1 | instant — when the server automatically deletes the subscription |

### Stage A — read-only, and often a finding on its own

Can your token **read** existing `Subscription` resources? That is a plain GET:

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/Subscription?_summary=count" | jq '.total'

curl -s -H "Authorization: Bearer $TOKEN" "$BASE/Subscription?_count=20" \
  | jq '[.entry[].resource | {status, channelType: .channel.type, endpoint: .channel.endpoint, criteria}]'
```

Two things to look for in that output, both reportable without writing anything:

- **`channel.endpoint` values disclosing internal hostnames** or third-party
  integration endpoints. That is an information-disclosure finding and an internal
  network map in one.
- **`criteria` strings containing other patients' identifiers.** The criteria is a
  search string; if it names a patient, reading it is a cross-patient identifier
  disclosure through a surface nobody thinks of as patient data.

Also check whether the CapabilityStatement advertises `create` on `Subscription`.
Knowing the write surface exists is a read.

### Stage B — creating a Subscription

Creating one is a write, and it configures the server to push data outbound on a
schedule you do not control. The R4 spec notes:

> the subscription remains active after the client access tokens expire

So a test subscription can outlive the engagement and keep delivering after your
access is revoked. If Stage B is signed off:

- The endpoint must be infrastructure **you** control.
- **Omit `channel.payload`** so no resource content is pushed. Without a payload,
  data remains available only through the REST API, which the spec notes "helps
  consolidate authorization and authentication logic."
- Set `end` to a near-term instant so the server expires it even if cleanup fails.
- Delete the subscription at the end of the test and **record the deletion**.
- `hunt-ssrf` owns the payload set and the callback confirmation gate. An accepted
  subscription with no confirmed delivery is a weaker finding than one with a
  captured request on a listener you control.

### What the spec itself says about the risk

These quotations are the basis for treating a missing endpoint allowlist as a
finding rather than a design choice:

- "Note that sending the entire resource creates security concerns that must be
  managed by the server."
- "Servers are responsible for ensuring appropriate security is employed for each
  channel."
- The `Subscription` resource "does not address these concerns directly", and a
  server "might maintain a whitelist of acceptable servers" for rest-create and
  rest-update methods.
- For rest-hook with full payloads: "In order to execute this channel, the server
  must know how to authenticate appropriately with the destination server."
- For message channels: "Most servers will require that the end-point is
  white-listed prior to allowing these kinds of subscriptions."

A server that accepts an arbitrary `channel.endpoint` with a full
`channel.payload` and no allowlist is measurably off the spec's own guidance, and
that is the framing to use in the report.

---

## 3. Evidence handling for both surfaces

Both of these surfaces return bulk PHI when they fail. The redaction rule from
`evidence-hygiene` applies before anything is written down, and here it is
specific:

- For `$export`: record the **manifest** — `transactionTime`,
  `requiresAccessToken`, the `output[].type` values and the **count** of output
  URLs. Record one `output[].url` with its host and path structure intact and its
  random component redacted. Never record the NDJSON contents, and never retain a
  downloaded export file.
- For `Subscription`: record `status`, `channel.type`, the `channel.endpoint`
  **host** and the fact that `criteria` referenced an identifier outside your
  compartment. Redact the identifier itself to its form, for example
  `Patient/<redacted-id>`.
- Delete local copies when the report is filed, per that skill's post-submission
  hygiene.

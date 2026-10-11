# SaaS platform exposure and reverse-proxy path misconfiguration

Two findings that do not fit the "open port on a host you can scan" shape but
turn up constantly on the same engagements:

1. **ServiceNow** — a vendor-hosted platform where the exposure is a
   configuration state inside the tenant, not an open port.
2. **The nginx `alias` off-by-slash** — a generic reverse-proxy
   misconfiguration that leaks the filesystem of whatever panel sits behind it.

Rate posture: serial, 2 s base delay plus 0-3 s jitter. ServiceNow needs more
than that; see below.

---

## ServiceNow public data exposure

### Why this is different from everything else in this skill

ServiceNow instances are **vendor-hosted SaaS**. You are not probing the
client's network, you are probing a tenant on ServiceNow's infrastructure. Three
consequences, all of which precede the first request:

- The signed scope must **name the tenant** (the instance hostname). "The
  client's ServiceNow" is not a scope statement.
- The client's contract with ServiceNow, and ServiceNow's own testing policy,
  govern what is permitted. If the scope document does not address third-party
  hosted platforms, raise it with the operator before testing rather than after.
- Rate limiting is ServiceNow's, not the client's, and tripping it is visible to
  the vendor. Keep the probe count small and the delay generous.

### The finding class

The exposure is not a CVE. It is a misconfigured Service Portal: widgets and
tables that a public, unauthenticated session can read. The route, per Bishop
Fox's published research on testing ServiceNow for public data exposure
([Bishop Fox, snowpick](https://bishopfox.com/blog/introducing-snowpick-testing-servicenow-for-public-data-exposure)):

- A public session token and cookies are obtained from the instance's public
  login page, then reused on subsequent requests.
- Widgets are reachable at `/api/now/sp/widget/{widget_id}` and accept `POST`
  requests with a JSON payload.
- Tables are reachable through the REST Table API at
  `/api/now/table/{table_name}`.
- Those two routes have **separate authorisation paths**, so a table that the
  Table API refuses may still be readable through a widget, and vice versa.
  Check both before concluding "not exposed".

Widget IDs named by that research as the productive ones:
`ticket-attachments` (sys ID `ff26f2b1db12220099f93691f0b8f5ce`), which
dominated its 166-instance study, plus `kb-article-page`, `kb-search`,
`kb-category-list`, `sc-category`, `simple-list` and `widget-simple-list`.
Tables named include `sys_user`, `incident`, `kb_knowledge` and `oauth_entity`.

### Three outcomes, and why the middle one matters

That research distinguishes result states which map directly onto report
severity, and the distinction is the single most useful thing in this section:

| State | Meaning | Report as |
|---|---|---|
| `exposed` | Records and field values were returned. | Finding, graded on the data class. |
| `count_oracle` | The platform confirmed that matching records exist but returned no rows. | A separate, lower finding: a record-count oracle, **not** row access. |
| `not_exposed` | No accessible data. Missing widgets, token errors and request errors each have their own state. | Not a finding. |

Do not collapse `count_oracle` into `exposed`. A report that claims record
access on the strength of a count is withdrawn on first retest, and it is the
most likely way to get this finding rejected.

### Evidence discipline

ServiceNow tables hold personal data by definition: `sys_user` is a staff
directory, `incident` carries free-text descriptions, attachments carry
documents. The evidence rule is harder here than anywhere else in this skill:

- Record the **total count** where the platform provides it, the **sample
  count**, and a **bounded** set of sample records with values redacted to the
  field names and data types.
- Never retrieve `sys_user` rows wholesale to demonstrate scale. The count
  demonstrates scale.
- Attachment exposure through `ticket-attachments` is proven by the attachment
  metadata — file name, size, parent record — not by downloading the file.
- Apply `evidence-hygiene` for storage, and state in the report that no
  personal-data records were retained.

### Verified CVEs worth a version note

| CVE | What NVD records |
|---|---|
| CVE-2024-4879 | An input-validation vulnerability in the Vancouver and Washington DC Now Platform releases that "could enable an unauthenticated user to remotely execute code within the context of the Now Platform". ServiceNow patched hosted instances and released updates to partners and self-hosted customers. |
| CVE-2024-5217 | An input-validation vulnerability in the Washington DC, Vancouver and earlier releases, likewise enabling an unauthenticated user to remotely execute code in the Now Platform context. Addressed in the June 2024 patching cycle. |

Both are pre-auth RCE on a managed platform, which is exactly the situation
where you do **not** fire an exploit: the instance is ServiceNow's
infrastructure and shares a control plane with other tenants. Determine the
release family from the login page or an `/api/now` response, state the exposure
against the advisory, and leave exploitation alone unless the operator has
written sign-off **and** the platform vendor's testing policy permits it. This
is the one place in this skill where "the client said critical findings are in
scope" is definitively not enough.

---

## The nginx `alias` off-by-slash path traversal

### The misconfiguration

A `location` prefix without a trailing slash, pointing at an `alias` that has
one, lets a request escape the alias target. From Gixy's `alias_traversal`
check documentation, which is the canonical write-up of the pattern
([Gixy, alias-traversal](https://github.com/dvershinin/gixy/blob/master/docs/en/checks/alias-traversal.md)):

```nginx
# Vulnerable: the location prefix has no trailing slash.
location /i {
    alias /data/w3/images/;
}
```

The request `/i../app/config.py` resolves to `/data/w3/app/config.py`, which is
outside the intended `/data/w3/images/` directory. The fix is to make the
location end with a directory separator so it matches the alias target —
`location /i/ { alias /data/w3/images/; }` — or, for a single file, to use an
exact-match location with `=`.

Note the mechanism precisely, because it is what makes this findable without the
configuration: there is no `../` in the request path that a normaliser would
collapse. The traversal happens in the **concatenation** of the request path onto
the alias value, so `/i../` is a legitimate, already-normalised path as far as
any proxy, WAF or HTTP client is concerned.

### Why it belongs in a panel-hunting skill

The products in this skill are almost always reverse-proxied, and the proxy
configuration is where someone writes `location /grafana { ... }` instead of
`location /grafana/ { ... }`. The off-by-slash then reads the filesystem of the
host running the panel, which is where that panel's configuration file and its
credentials live.

### Detection (Stage A)

Build the candidate list from the path prefixes you already observed while
fingerprinting panels — `/grafana`, `/zabbix`, `/kibana`, `/static`, `/assets`,
`/img`, `/media`, `/files`, `/docs`. For each prefix `P` that serves content,
request `P../` variants and compare.

```bash
TARGET="target.example"
PREFIX="/static"

# Stage A — read-only. Save a baseline for the legitimate prefix first.
curl -s -m 15 --path-as-is -o /tmp/alias_base.txt -w 'base %{http_code}\n' \
  "https://${TARGET}${PREFIX}/"

# Then the off-by-slash variant, aimed at a file whose content is predictable.
curl -s -m 15 --path-as-is -o /tmp/alias_hit.txt -w 'hit  %{http_code}\n' \
  "https://${TARGET}${PREFIX}../../../../../../etc/passwd"

# Confirmed ONLY by content, never by status code:
grep -qE '^root:[^:]*:0:0:' /tmp/alias_hit.txt && echo "ALIAS TRAVERSAL CONFIRMED"
diff <(head -c 400 /tmp/alias_base.txt) <(head -c 400 /tmp/alias_hit.txt) >/dev/null \
  || echo "body differs from baseline"
```

`--path-as-is` is mandatory. Without it curl normalises the path and you will
report a false negative on a vulnerable host.

### The false positives this produces, and the gate

Status codes are hints and nothing more. A `403` on `alias../`, a `404` on
`alias.../`, a `400` on a long traversal chain — these differences only tell you
that the server treats the variants differently. They are a reason to keep
probing, never a finding.

Confirmation requires **both**:

1. A file whose content you can predict, returned verbatim. `/etc/passwd` with
   a line matching `^root:[^:]*:0:0:` is the standard choice precisely because
   it is unmistakable and contains no secrets.
2. A body diff against the saved baseline for the legitimate prefix, so an error
   page or a WAF block page that happens to contain the word "root" cannot be
   mistaken for a read.

Once confirmed, name the impact rather than harvesting it: the panel's
configuration file is readable, and that file holds the database credential or
the signing key. Read one predictable, non-sensitive file to prove the primitive
and stop. Pulling the credential store converts a clean finding into data you
now have to protect.

### `merge_slashes off` — adjacent, and not the same finding

nginx compresses repeated slashes by default (`merge_slashes on`). Turning it
off can expose backend traversal behaviour that the default happened to mask, so
`merge_slashes off` in a configuration is worth a hardening note. But do not
report it as a vulnerability on its own, and do not treat `merge_slashes off` as
a fix for anything: the actual guidance is to align canonicalisation between
proxy and backend, reject ambiguous paths, and enforce authorisation on the
canonical route. The original research is Danny Robinson and Rotem Bar's
write-up on nginx inadvertently protecting applications from traversal.

---

## Cross-references

- `hunt-lfi` — traversal payload construction, encoding variants and what to
  read once the primitive is confirmed. This file only covers the
  product-specific route to it.
- `hunt-idor` — the authorisation model behind the ServiceNow widget-versus-
  Table-API split, which is a broken-object-level-authorisation problem.
- `hunt-source-leak` — configuration files and source recovered through either
  finding.
- `hunt-cloud-misconfig` — the same "internal tool reachable from the internet"
  root cause when the service is cloud-managed rather than proxied.
- `evidence-hygiene` — mandatory for the ServiceNow personal-data handling
  above.
- `triage-validation` — the count-versus-rows distinction, before filing.

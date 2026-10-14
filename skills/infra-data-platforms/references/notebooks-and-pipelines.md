# Notebooks, pipeline engines and their consoles

Apache Zeppelin, Apache Livy, Hue, Apache Storm, Apache NiFi, plus the Flink and
Airflow facts that `hunt-exposed-panels` does not carry. Every product here
executes user-supplied code or commands as its main feature. Exposure without
authentication is the whole finding; using the feature to prove it is never
needed.

**Ownership.** Flink JobManager fingerprinting (`/config`, `/jobmanager/config`),
CVE-2020-17518 and CVE-2020-17519, Airflow fingerprinting (`/api/v2/version`,
`/api/v1/`), `expose_config` and the secret-key check, and Jupyter all live in
`hunt-exposed-panels` (`references/data-and-notebook-tools.md`). Run those from
there. This file adds the KEV status they lack and the later CVEs.

Rate posture: serial, 2 s base delay plus 0-3 s jitter.

---

## Apache NiFi (8443 HTTPS since 1.14.0; 8080 HTTP before; NiFi Registry 18080)

```bash
TARGET="192.0.2.80"
# Version; requires authentication on a secured NiFi, so 401/403 is the healthy answer.
curl -sk -m 10 "https://$TARGET:8443/nifi-api/flow/about"
curl -s  -m 10 "http://$TARGET:8080/nifi-api/flow/about"      # pre-1.14 layout
curl -s  -m 10 "http://$TARGET:18080/nifi-registry-api/about" # Registry: registryAboutVersion
```

- **Before 1.14.0** the default was HTTP on 8080, and the admin guide says it
  plainly: "NiFi does not perform user authentication over HTTP. Using HTTP, all
  users will be granted all roles." 1.12.1 and earlier bound all interfaces;
  1.13.2 shipped `nifi.web.http.host=127.0.0.1`.
- **1.14.0 and later** start HTTPS-only on 8443 with a self-signed certificate
  and a generated single-user credential (UUID user name, 32-character password)
  written to `logs/nifi-app.log`. An exposed 8443 with that login page is the
  expected posture; an exposed HTTP 8080 that answers `flow/about` is the finding.
- Whether a secured Registry still answers `/nifi-registry-api/about`
  anonymously is unconfirmed (verify).

Stage B: adding or starting any processor (ExecuteProcess and
ExecuteStreamCommand run OS commands), creating controller services (the JDBC
and JNDI CVEs below), parameter-context changes, and template or flow imports.

## Apache Flink (8081): the delta

- **CVE-2020-17519 is in CISA KEV** (added 2024-05-23); `hunt-exposed-panels`
  has the read-only confirmation. CVE-2020-17518 (file write) is not in KEV.
- `GET /config` returns `features.web-submit`: whether JAR upload is enabled.
  That flag is the difference between an information leak and code execution by
  design. Flink's security page: "SSL/TLS, REST API authentication, and SQL
  Gateway authentication are all disabled by default ... A default Flink
  deployment is unauthenticated."
- Stage B: JAR upload and run (`/jars/upload`, `/jars/<id>/run`), job cancel or
  savepoint triggers, and anything through the SQL Gateway.

## Apache Airflow (8080): the delta

- **Two Airflow CVEs are in CISA KEV**, both added 2022-01-18:
  - **CVE-2020-13927**: "The previous default setting for Airflow's
    Experimental API was to allow all API requests without authentication."
    Affected before 1.10.11; the fix changed the default for **new** installs
    only, so an upgraded 1.10.x can still be open. Read-only check: on 1.10.x,
    `GET /api/experimental/test` answering `200` without credentials means the
    condition holds.
  - **CVE-2020-11978**: command injection in an example DAG shipped with
    Airflow, through 1.10.10, fixed in 1.10.11; not exploitable when
    `load_examples=False`. With the open experimental API it becomes
    unauthenticated code execution (derived chain, not stated in one record).
    Report the version, the open API and whether example DAGs are listed;
    never trigger one.
- On 1.10.x, `GET /api/experimental/dags/<id>/paused/<true|false>` changes state
  despite the verb. Do not send it.
- `/api/v1/version` (2.x) and `/api/v2/version` (3.x) are public by design; they
  version-gate without proving anything about authentication.
- Roughly a hundred 2023-2026 Airflow advisories are authenticated RBAC,
  information-leak or DAG-author issues. Several carry a PR:N vector that
  contradicts their own description. Do not cite them as pre-auth.

---

## Version matrix

KEV from the CISA feed, catalog 2026.10.13.

| Product | CVE | Class | Affected | Fixed | Pre-auth | KEV |
|---|---|---|---|---|---|---|
| Airflow | CVE-2020-13927 | Experimental API allows all requests by default | < 1.10.11 | 1.10.11 (new installs only) | Yes | **Yes, 2022-01-18** |
| Airflow | CVE-2020-11978 | Example-DAG command injection | <= 1.10.10 | 1.10.11 | PR:L; none with 13927 | **Yes, 2022-01-18** |
| Flink | CVE-2020-17519 | JobManager REST arbitrary file read | 1.11.0-<1.11.3 | 1.11.3, 1.12.0 | Yes | **Yes, 2024-05-23** (probe in `hunt-exposed-panels`) |
| Airflow | CVE-2021-38540 | Variable import endpoint missing authentication | 2.0.0-<2.1.3 | 2.1.3 | Yes | No |
| Airflow | CVE-2021-35936 | Worker log server unauthenticated (not port 8080) | < 2.1.2 | 2.1.2 | Yes | No |
| Airflow | CVE-2020-17526 | Session reuse via the default `secret_key` | < 1.10.14 | 1.10.14 | PR:L | No |
| Airflow | CVE-2022-24288, CVE-2022-40127 | Example-DAG code execution | < 2.2.4; < 2.4.0 | 2.2.4; 2.4.0 | PR:L | No |
| Flink | CVE-2026-35194 | SQL to TaskManager code injection | 1.15.0-1.20.x, 2.0-2.x | 1.20.4, 2.0.2, 2.1.2, 2.2.1 | PR:L; nobody on a default deployment | No |
| NiFi | CVE-2020-9487 | Unauthenticated download-token request DoS | 1.0.0-1.11.4 | 1.12.0 | Yes, **DoS-class** | No |
| NiFi | CVE-2023-34468, CVE-2023-36542 | H2 JDBC URL / remote driver URL to code execution | 0.0.2-1.21.0; 0.0.2-1.22.0 | 1.22.0; 1.23.0 | PR:L; nobody over pre-1.14 HTTP | No |
| NiFi | CVE-2023-34212, CVE-2023-40037 | JNDI/JMS deserialization; JDBC/JNDI validation bypass | 1.8.0-1.21.0; 1.21.0-1.23.0 | 1.22.0; 1.23.1 | PR:L | No |
| NiFi | CVE-2026-54665 | `X-ProxyHost` / `X-Forwarded-Host` not validated | 0.0.1-2.9.0 | 2.10.0 | Yes | No |
| NiFi | CVE-2026-68981, CVE-2026-70469 | Gzip decompression DoS and its Content-Encoding bypass | 1.5.0-2.10.0; 2.11.0 | 2.11.0; 2.12.0 | Yes, **DoS-class** | No |
| NiFi | CVE-2026-68979 | Parameter Context authorization gap, can reach code execution | 1.10.0-2.10.0 | 2.11.0 | NVD says PR:N; CNA PR:H and the record says authenticated. Cite both | No |

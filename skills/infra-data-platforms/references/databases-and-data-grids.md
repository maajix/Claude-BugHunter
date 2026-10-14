# Databases and data grids with no other owner

Neo4j, IBM Db2, Firebird, SAP ASE, SAP HANA, CockroachDB, ArangoDB, RethinkDB,
Vertica, Hazelcast and Apache Ignite. Redis, MongoDB, Elasticsearch, CouchDB,
InfluxDB, Cassandra, PostgreSQL, MySQL, Oracle TNS and HSQLDB belong to
`hunt-exposed-services` (`references/databases.md`); MSSQL to
`infra-windows-perimeter`. Do not repeat their probes here.

Every probe in this file is **Stage A** under SKILL.md Step 4: one request,
no credential, no claimed identity, metadata only. Rate posture: serial, 2 s
base delay plus 0-3 s jitter (`probe_delay` in SKILL.md Step 1).

KEV column in the matrix at the end: none of these products has an entry in the
CISA KEV catalog (feed 2026.10.13). Ranges come from the CVE Program record
(`cveawg.mitre.org/api/cve/<ID>`) or the vendor's GitHub advisory.

---

## Neo4j (HTTP 7474, HTTPS 7473, Bolt 7687)

Connector `listen_address` settings default to `localhost:<port>`; Bolt and HTTP
are enabled, HTTPS is off (`server.https.enabled=false`). A Neo4j answering on a
public address was rebound on purpose.

```bash
TARGET="192.0.2.40"
# Discovery API: documented as un-authenticated. Fields neo4j_version,
# neo4j_edition, bolt_routing, bolt_direct and auth_config (OIDC providers).
curl -s -m 10 -H 'Accept: application/json' "http://$TARGET:7474/" | head -c 800
```

- Default account `neo4j` / `neo4j`, and that password "must be changed at first
  login"; minimum length 8. A session opened with the default can only change the
  password, so a successful default login is still Critical: whoever sets the
  new password owns the database.
- Auth-posture check (Stage A by the metadata-statement rule in SKILL.md Step 4):
  one `RETURN 1` with **no** credential to the transaction endpoint. `401` means
  authentication is on; `200` with a result means `dbms.security.auth_enabled`
  was set to `false`, which is the finding.

```bash
# Stage A metadata statement (SKILL.md Step 4): constant expression, no credential.
curl -s -m 10 -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' \
  -d '{"statements":[{"statement":"RETURN 1"}]}' "http://$TARGET:7474/db/neo4j/tx/commit"
```

Stage B: the single `neo4j`/`neo4j` attempt (it starts the forced-change flow;
never complete it), any `MATCH` over user data, `CALL db.*` listing beyond
labels, and every APOC procedure or `LOAD CSV` (file and URL access from the
server). The Neo4j 3.x shell server (port 1337, RMI) is CVE-2021-34371: detect
the port, never talk RMI to it.

## IBM Db2 LUW (DRDA 50000, commonly 50001 for TLS; DAS 523/udp)

```bash
# drda-info: categories safe, discovery, version. Sends one DRDA EXCSAT and
# prints the server release level (SRVRLSLV, e.g. SQL11058) and server class.
nmap -Pn -sT -p 50000 --script drda-info "$TARGET"
# Legacy Db2 Administration Server: db2-das-info (safe, discovery, version).
nmap -Pn -sU -p 523 --script db2-das-info "$TARGET"
```

- Default `AUTHENTICATION` is `SERVER` (operating-system users). There is no
  product default password; `db2inst1`, `db2fenc1` and `dasusr1` are naming
  conventions, and guessing them is `hunt-brute-force`.
- The configuration to look for is `AUTHENTICATION CLIENT` with
  `TRUST_ALLCLNTS YES`, where the server trusts a client to have authenticated
  its own user (verify against the Db2 release in front of you). Confirming it
  means connecting as a claimed user: Stage B.
- **Port 50000 collision:** SAP NetWeaver AS Java uses 5NN00 (50000 for
  instance 00) for HTTP. An HTTP reply is NetWeaver, not Db2, and NetWeaver has
  no owner in this bundle.
- IBM scores many query-triggered crashes PR:N (for example CVE-2023-26021,
  CVE-2023-30449). Sending SQL requires a connected session, and every one of
  them is DoS-class: banner-gate them, never test.

## Firebird (3050)

```bash
# nmap's firebird probe is an op_connect naming "service_mgr" with user "scanner";
# it negotiates a protocol and sends no password.
nmap -Pn -sT -sV --version-light -p 3050 "$TARGET"
```

- `-sV` yields "Firebird RDBMS" and a wire-protocol version, not the server
  release. The release needs an attachment: Stage B.
- Defaults: legacy authentication ships `SYSDBA` with `masterkey` (stored as
  `masterke`). Firebird 3+ uses SRP, and the standard installers create `SYSDBA`
  with a random or operator-chosen password. An installer that skipped the step
  leaves "Install incomplete. To complete security database initialization
  please CREATE USER." (Windows report; verify on Linux).
- Stage B: one `SYSDBA`/`masterkey` attempt, once, on a host whose banner says
  legacy auth. Every 2026 CVE below is a crash: version-gate only.

## SAP ASE / Sybase ASE (data server 5000, backup server often 5001, Cockpit 4282/4283)

`-sV` matches `Sybase Adaptive Server` (and `Sybase Backup Server`,
`Sybase Monitor Server`) from the TDS reply, usually without a version: the
release is reported after login. Port 5000 is also a generic HTTP port
(Flask, Docker registry, UPnP): check for a TDS reply before naming ASE.

- Default credential posture: older releases allowed an `sa` login with a NULL
  password (verify per release). One `sa` attempt is Stage B.
- Every 2020 SAP ASE CVE below needs authentication. On an exposed ASE the
  finding is the exposure plus whatever credential policy the client confirms.

## SAP HANA (SQL 3NN13 system DB, 3NN15 single-container, tenants 3NN40-3NN99; XS 80NN/43NN)

`NN` is the instance number. Multi-tenant systems put the system database on
3NN13 and give each tenant three ports from 3NN40 upward (SQL, HTTP, internal);
3NN15 is the single-container SQL port. A client can also reach a tenant through
3NN13 by naming the database, which is why some client docs list 3NN13 for
tenants.

- No default password: `SYSTEM` is set at installation. No pre-auth version
  oracle on the SQL port was confirmed (verify); the XS classic login page on
  80NN/43NN identifies the product.
- SAP Host Agent (1128/1129) and `sapstartsrv` (5NN13/5NN14) on the same hosts
  are SAP management planes with no owner in the bundle: report the exposure
  generically.
- CVE-2019-0350 (malformed connection request crashes the indexserver) is the
  pre-auth CVE on the SQL port, and it is DoS-class: never test.

## CockroachDB (SQL 26257, DB Console 8080)

`--listen-addr` defaults to all addresses on 26257 and the DB Console follows on
8080. `--insecure` is documented as "non-production testing only": "any user,
even `root`, can log in without providing a password" and "can read or write any
data in your cluster."

```bash
curl -s -m 10 "http://$TARGET:8080/health"                      # liveness, no login
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8080/"   # DB Console
```

- An insecure node is identified by the console loading with no login form and by
  plain-HTTP (no TLS) on both ports. The SQL proof (`psql` as `root` with no
  password, `SELECT version()`) is Stage A by the `hunt-exposed-services`
  PostgreSQL precedent; stop at `version()` and `SHOW DATABASES`.
- `/_status/vars` (Prometheus metrics) is commonly scrapeable without a session
  (verify per version); it leaks node count and build tags.
- Technical Advisory 42567 (2020-01-22, no CVE): through v2.1.9, v19.1.5 and
  v19.2.1, privileged HTTP endpoints including `/_admin/v1/events` answered
  without authentication with root privileges. Fixed in v2.1.10, v19.1.6, v19.2.2.
- Technical Advisory 58932: the GoGo Protobuf bug CVE-2021-3121 crashes a node
  through a crafted HTTP request "even without an authenticated session".
  Affected through v19.2.11, v20.1.10, v20.2.3; fixed v19.2.12, v20.1.11, v20.2.4.
  DoS-class: never test.

## ArangoDB (8529)

```bash
# Documented as a public API that does not require authentication.
curl -s -m 10 -i "http://$TARGET:8529/_admin/server/availability" | head -12
# 401 here means authentication is on; a version JSON means it is off.
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8529/_api/version"
```

- Authentication is on by default; an open `/_api/version` means
  `--server.authentication false`. The official container image refuses to start
  without one of a root password, a random root password, or an explicit
  no-auth flag (verify the variable names for the image tag in use).
- 2026 advisories without CVE IDs (GitHub Security Advisories on
  `arangodb/arangodb`) are the reason an exposed 3.12 matters: one is an
  unauthenticated URL-decoding differential on system routes that reaches
  superuser actions on a **default** install. Version-gate it; never send the
  encoded-route request, because the public example deletes documents.
- Stage B: Foxx service install, `/_api/tasks`, `/_api/transaction`, any AQL
  beyond listing database and collection names with counts.

## RethinkDB (driver 28015, web UI 8080, cluster 29015)

The project's security page: the `admin` account "by default ... has no
password", and "the authentication system affects client drivers, not the web
interface". An exposed web UI is unauthenticated administration, including the
Data Explorer that runs ReQL as admin.

```bash
curl -s -m 10 "http://$TARGET:8080/" | grep -i -o '<title>[^<]*' | head -1
# Driver port: any non-handshake bytes produce a self-identifying error
# ("This port is for RethinkDB queries"), which is how nmap -sV names it.
nmap -Pn -sT -sV --version-light -p 28015,29015 "$TARGET"
```

Stage B: anything typed into the Data Explorer, `r.js()` (server-side
JavaScript) and `r.http()` (server-side fetch). The cluster port 29015 answers
with a `RethinkDB <version> cluster` banner; record it, never join it.

## Vertica (client 5433, Management Console 5450)

`-sV` recognises Vertica from the `ErrorMsg` it returns to an invalid startup
packet, which also leaks a build path (`.../vbuild/vertica/Session/ClientSession.cpp`).
The database superuser `dbadmin` gets its password at database creation (verify
whether the release in front of you allows an empty one). Stage A stops at the
banner; the Management Console login page is `hunt-exposed-panels` territory in
spirit but has no profile there, so record its version string and stop.

## Hazelcast (members 5701-5703, Management Center 8080/8443)

Authentication and authorisation "are the features of Hazelcast Enterprise
Edition". A Community Edition member that a client can reach **is** an
unauthenticated data grid; "PR:L" in a CVE vector means "anyone who can connect"
on such a cluster.

```bash
# The member port multiplexes protocols. The REST service is disabled by default;
# when enabled, CLUSTER_READ and HEALTH_CHECK groups are on by default.
curl -s -m 10 "http://$TARGET:5701/hazelcast/health/ready"
curl -s -m 10 "http://$TARGET:5701/hazelcast/rest/cluster"     # member list, if REST on
```

`nmap -sV` sends the same `/hazelcast/rest/cluster` GET. An empty reply with the
port open means REST is off, not that Hazelcast is absent; the binary client
protocol still answers.

- Management Center: a first-run page that offers to create the administrator or
  pick **Dev Mode** means nobody configured security. That page is the finding;
  choosing a provider on it is Stage B and claims the console.
- Stage B: connecting a Hazelcast client (it joins the data plane), any `DATA`
  or `CLUSTER_WRITE` REST group call, Jet job submission.

## Apache Ignite (thin client/JDBC/ODBC 10800, REST 8080, discovery 47500, communication 47100)

Authentication is off unless configured. The REST connector exists only when
`ignite-rest-http` and `ignite-json` are moved from the optional libs into
`libs`; it then listens on 8080 with no authentication by default.

```bash
curl -s -m 10 "http://$TARGET:8080/ignite?cmd=version"
curl -s -m 10 "http://$TARGET:8080/ignite?cmd=top" | head -c 800   # topology, node IDs, addresses
```

Stage B: `cmd=exe` ("Executes a given task in the cluster"), `put`, `rmv`,
`qryexe` and any SQL, plus `cmd=log` (the CVE-2025-48977 file-read path).
Discovery (47500) and communication (47100) ports speak Java serialization:
record them, send nothing.

---

## Version matrix

"Pre-auth" reads PR from the CNA vector, then NVD. "Gate" says whether a remote
banner can decide the version.

| Product | ID | Class | Affected | Fixed | Pre-auth | KEV | Gate |
|---|---|---|---|---|---|---|---|
| Neo4j | CVE-2021-34371 | RMI deserialization RCE via the shell server | through 3.4.18 with the shell server on | upgrade off 3.4 (verify) | Yes (NVD 9.8) | No | Port 1337 open + 3.4 discovery doc |
| Neo4j APOC | CVE-2021-42767 | Directory traversal read (and sometimes write) | before 3.5.17, 4.2.10, 4.3.0.4, 4.4.0.1 | those | NVD PR:N, but needs Cypher access | No | No (plugin version) |
| Neo4j APOC | CVE-2022-37423 | Traversal to sibling dirs via `apoc.log.stream` | < 4.3.0.7, 4.4 < 4.4.0.8 | 4.3.0.7, 4.4.0.8 | NVD PR:N, needs Cypher | No | No |
| Neo4j APOC | CVE-2023-23926 | XXE in `apoc.import.graphml` | < 4.4.0.14, 5.x < 5.5.0 | 4.4.0.14, 5.5.0 | No (PR:L) | No | No |
| Neo4j | CVE-2025-11602 | One byte of a previous connection leaks in the Bolt handshake | 5.26.0-<5.26.15, 2025.1-<2025.10.1 | 5.26.15, 2025.10.1 | Yes | No | Discovery doc |
| Neo4j | CVE-2026-14587 | Bolt handshake decoder holds the channel open; pre-auth DoS | 5.0-<5.26.29, 2025.01-<2026.07 | 5.26.29, 2026.07 | Yes, **DoS-class** | No | Discovery doc |
| Neo4j Enterprise | CVE-2026-1524 | Authentication-only OIDC provider also grants authorisation | 4.4.0-<5.26.22, 2025.01-<2026.02 | 5.26.22, 2026.02 | CNA PR:H; NVD 9.8 PR:N. Cite both | No | Discovery doc + `auth_config` |
| Db2 | CVE-2023-26021, CVE-2023-30449 (examples) | Server crash on a crafted query | 11.1, 11.5 (per IBM) | IBM fix pack per bulletin | IBM says PR:N; needs a session | No | `drda-info` SRVRLSLV |
| Firebird | CVE-2026-28212, CVE-2026-35215 | Pre-auth crash via `op_slice` packet | < 3.0.14, 4.0.0-<4.0.7, 5.0.0-<5.0.4 | 3.0.14, 4.0.7, 5.0.4 (6.0 for 28212) | Yes, **DoS-class** | No | No (release needs attach) |
| Firebird | CVE-2026-33337 | Pre-auth buffer overflow parsing a slice packet | 3.0.0-<3.0.14, 4.0.0-<4.0.7, 5.0.0-<5.0.4 | 3.0.14, 4.0.7, 5.0.4 | Yes | No | No |
| Firebird | CVE-2026-40342 | External-engine path traversal loads any library (RCE) | < 3.0.14, 4.0-<4.0.7, 5.0-<5.0.4 | 3.0.14, 4.0.7, 5.0.4 | No (needs CREATE FUNCTION) | No | No |
| Firebird | CVE-2025-54989 | XDR parsing NULL dereference | < 3.0.13, 4.0.6, 5.0.3 | 3.0.13, 4.0.6, 5.0.3 | Yes, **DoS-class** | No | No |
| SAP ASE | CVE-2020-6248 | Backup Server DUMP/LOAD code injection | 16.0 | SAP Note per Patch Day (verify) | No (PR:H) | No | No |
| SAP ASE | CVE-2020-6241, CVE-2020-6253 | Authenticated SQL injection to privilege escalation | 16.0; 15.7/16.0 (Web Services) | SAP Note (verify) | No (PR:L/H) | No | No |
| SAP ASE | CVE-2020-6252, CVE-2020-6250 | Cockpit / misconfigured endpoint credential disclosure | 16.0 | SAP Note (verify) | No (AV:A) | No | No |
| SAP HANA | CVE-2019-0350 | Malformed connection request crashes the indexserver | 1.0, 2.0 | SAP Note (verify) | Yes, **DoS-class** | No | No |
| SAP HANA | CVE-2021-21484 | LDAP authentication bypass when the LDAP server allows unauthenticated bind | 2.0 | SAP Note (verify) | Yes (AC:H) | No | No; configuration-dependent |
| SAP HANA | CVE-2019-0261 | XS advanced authentication checks not performed | XS advanced before 1.0.97-1.0.99 | 1.0.97-1.0.99 | Yes | No | XS version |
| SAP HANA | CVE-2025-42885 | Missing authentication on an hdbrss remote function; information view | HDB 2.00 | SAP Note (verify) | Yes (5.8) | No | No |
| SAP HANA | CVE-2026-44753 | User and e-mail enumeration in XS classic user self-service | HDB 2.00 | SAP Note (verify) | Yes (3.7) | No | No |
| SAP HANA | CVE-2026-0492 | Any valid user can switch to another user | HDB 2.00 | SAP Note (verify) | No (PR:L) | No | No |
| CockroachDB | TA 42567 (no CVE) | Unauthenticated privileged HTTP endpoints | through v2.1.9, v19.1.5, v19.2.1 | v2.1.10, v19.1.6, v19.2.2 | Yes | No | Console version |
| CockroachDB | CVE-2021-3121 (TA 58932) | GoGo Protobuf crash over the HTTP port | through v19.2.11, v20.1.10, v20.2.3 | v19.2.12, v20.1.11, v20.2.4 | Yes, **DoS-class** | No | Console version |
| ArangoDB | GHSA-rrgq-978q-36mq (no CVE) | URL-decoding differential: unauthenticated superuser actions | <= 3.12.10.1 | 3.12.11 | Yes | No | Only with credentials (`/_api/version` needs auth) |
| ArangoDB | GHSA-8v35-895w-232p (no CVE) | JWT HS256/ES256 confusion in folder mode | 3.12.8-3.12.10.1 | 3.12.11 | Yes, config-dependent | No | As above |
| ArangoDB | GHSA-rvhw-4hpw-9vrx (no CVE) | `POST /_api/tasks` `isSystem` flag: host file read/write as `arangod` | <= 3.12.10.1 | 3.12.11 | No (RW on any DB) | No | As above |
| ArangoDB | GHSA-4xhx-8cv5-wh62 (no CVE) | `/_admin/aardvark/` prefix escalates any user to superuser | 3.12.0-3.12.9.4 | 3.12.10 | No (any user) | No | As above |
| RethinkDB | CVE-2025-14310 | Buffer overflow (record gives no attack path) | < 2.4.4 | 2.4.4 | CNA PR:N (verify reachability) | No | Cluster banner |
| RethinkDB | CVE-2026-24810 | Buffer overflow in vendored cJSON (record gives no attack path) | through 2.4.4 | none stated | CNA PR:N (verify reachability) | No | Cluster banner |
| Vertica | CVE-2025-12455 | Management Console login response discrepancy enables password brute forcing | 10.x-12.x | per OpenText advisory (verify) | Yes (oracle only) | No | MC version |
| Hazelcast | CVE-2016-10750 (pre-2019) | Join-request Java deserialization RCE | before 3.11 | 3.11 | Yes | No | No |
| Hazelcast | CVE-2022-36437 | Unauthenticated connection reuses another connection's identity | through 4.0.6, 4.1.9, 4.2.5, 5.0.3, 5.1.2 (Jet 4.5.3) | next patch release per line | Yes (9.1) | No | No |
| Hazelcast | CVE-2023-45860 | CSV File Source SQL mapping reads member files | 5.3.0-5.3.4 | 5.3.5 | PR:L (no auth on Community) | No | No |
| Hazelcast | CVE-2026-107726 | Any connecting client reads member heap/off-heap memory; crash | < 5.4.5, 5.5.0-<5.5.10, 5.6.0 | 5.4.5, 5.5.10, 5.6.1, 5.7.0 | Yes (CNA 9.3) | No | No |
| Hazelcast | CVE-2026-107725 | IMap Predicates API: limited client executes code | < 5.4.5, 5.5.0-<5.5.10, 5.6.0 | 5.4.5, 5.5.10, 5.6.1, 5.7.0 | PR:L (no auth on Community) | No | No |
| Hazelcast | GHSA-6hfv-j8jg-ggpx (no CVE) | Malicious client reads any member file via Jet | before 5.5.10, 5.6.2, 5.7.1 | 5.5.10, 5.6.2, 5.7.1 | Client access | No | No |
| Ignite | CVE-2018-1295, CVE-2018-8018 (pre-2019) | Java deserialization RCE on discovery, memcached and GridClient endpoints | <= 2.3; < 2.4.8, 2.5.x < 2.5.3 | 2.4.8, 2.5.3 | Yes | No | `cmd=version` |
| Ignite | CVE-2020-1963 | H2 SQL functions reach the filesystem | up to 2.8 | 2.8.1 (verify) | NVD PR:N | No | `cmd=version` |
| Ignite | CVE-2024-52577 | Configured class serialization filters ignored on some endpoints: RCE | 2.6.0-<2.17.0 | 2.17.0 | Yes (CNA 9.5) | No | `cmd=version` |
| Ignite | CVE-2025-48977 | REST `cmd=log` path traversal reads any file | 2.0.0-2.17.0 | 2.18.0 | PR:L; nobody is "authenticated" when auth is off | No | `cmd=version` |

Two reading rules for this table:

- **"PR:L" on a product that ships without authentication is effectively
  pre-auth.** Hazelcast Community, Ignite with authentication disabled and an
  insecure CockroachDB grant every connecting client the "low privilege" the
  vector assumes. Say so in the report instead of downgrading.
- **NVD PR:N on APOC traversal rows overstates reachability.** They need the
  ability to run a Cypher query: an open Neo4j (auth disabled) or a Cypher
  injection in an application (`hunt-sqli`-style testing on the app).

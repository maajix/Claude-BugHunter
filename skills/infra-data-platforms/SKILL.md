---
name: infra-data-platforms
description: "Triage internet-exposed big-data, streaming, search and database services: Hadoop HDFS and YARN, Spark, Hive, HBase, Solr, ClickHouse, Kafka and Schema Registry, ZooKeeper, Pulsar, ActiveMQ (CVE-2023-46604), Neo4j, Db2, Firebird, SAP ASE and HANA, CockroachDB, ArangoDB, RethinkDB, Vertica, Hazelcast, Ignite. The finding is unauthenticated metadata access, a client-supplied identity the server trusts, or a version in a known-exploited range. Stage A reads versions, names and counts only. Use when a scan shows one of these ports, banners or consoles on an in-scope host."
metadata:
  sources: cisa_kev, cve_program_records, nvd, vendor_advisories, apache_security_pages, github_security_advisories, project_documentation, project_source, nmap_nse_source
  report_count: 0
---

## When to use

Trigger when external recon has produced an open port, banner or console for one
of the products in the description on a host you are authorized to test, and you
need to decide whether it is a finding. These are data platforms: the finding is
**the exposure plus what it leaks or grants**, and most of them grant code
execution or full data access by design once reached, so a single read usually
proves the whole thing.

Use when any of these is true:

- A scan or Shodan/Censys record shows a port from the Step 3 table answering on
  a public address.
- A banner, page title, TLS certificate or reverse-DNS name names one of these
  products (`spark://`, `Zookeeper version:`, `ActiveMQ`, `X-ClickHouse-`,
  `neo4j_version`, `serverSparkVersion`).
- A web console turns out to be a data-platform UI rather than the client's app.
- The client's inventory says "internal analytics cluster" and you can reach it.

**This skill is not for discovery.** Host, port and ASN discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation to `recon-scope-triage`.
It starts from "a port is open and in scope".

### Where the chain ends

Stop at **unauthenticated access or a trusted forged identity demonstrated by a
read, impact described from names and counts, evidence captured**. Nothing here
submits a job, runs a notebook paragraph, creates a connector, topic, table,
queue or subscription, reads message bodies or table rows, or uses a cluster as
a pivot. A cluster that accepts anonymous job submission is already a Critical:
report it from the read that shows the submission endpoint is open, and stop.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| Redis, MongoDB, Elasticsearch/Kibana, CouchDB, InfluxDB, memcached, Cassandra, PostgreSQL, MySQL, Oracle TNS, HSQLDB, splunkd | `hunt-exposed-services` `references/databases.md` |
| Baseline Hadoop 3 probes: NameNode JMX 9870, WebHDFS `LISTSTATUS /`, YARN `cluster/info` 8088 | Same file. This skill adds the delta (`references/hadoop-and-spark.md`) |
| AMQP, RabbitMQ, MQTT (Mosquitto), NATS, IBM MQ, EPMD | `hunt-exposed-services` `references/message-brokers.md`. ActiveMQ on 5672/1883 stays here |
| Spark application UI 4040 and history 18080 (CVE-2022-33891), Flink JobManager (CVE-2020-17518/17519), Airflow fingerprint and `expose_config`, Jupyter, phpMyAdmin | `hunt-exposed-panels` `references/data-and-notebook-tools.md` |
| MSSQL | `infra-windows-perimeter` |
| Kubernetes, Docker, etcd under these workloads | `hunt-k8s` |
| Managed services (MSK, Confluent Cloud, Databricks, BigQuery, Snowflake, Atlas) | `hunt-cloud-misconfig` |
| Injection into these engines through the client's application | `hunt-sqli`, `hunt-nosqli`; reached via a URL fetcher, `hunt-ssrf` |
| Log4Shell (CVE-2021-44228, KEV) out-of-band testing on any of these JVMs | `hunt-rce` under its own rules; here it is a version gate only |
| Credential guessing of any kind | `hunt-brute-force` |
| SAP NetWeaver, SAP Host Agent, `sapstartsrv`, Apache Superset, Kylin, RocketMQ, HugeGraph | No owner in the bundle. Report the exposure generically; do not improvise probes |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/hadoop-and-spark.md` | HDFS 50070/50075/8020/9864, NodeManager 8042, JobHistory 19888, simple-auth identity trap, `dr.who`, open YARN submission, Spark standalone 7077/6066/8080/8081, Hive, HBase, Oozie, Hadoop and Spark CVE matrix | exposed hadoop, yarn rce, webhdfs user.name, spark master 7077, spark rest 6066, hiveserver2 exposed, hbase master ui, oozie exposed |
| `references/notebooks-and-pipelines.md` | Zeppelin, Livy 8998, Hue, Storm, NiFi 8080/8443, Flink and Airflow KEV deltas | exposed zeppelin, livy sessions open, hue first login, storm ui exposed, nifi no auth, airflow experimental api, flink web submit |
| `references/query-search-olap.md` | Trino/Presto 8080, Druid 8081/8888, Solr 8983, ClickHouse 8123/9000/9004 | trino no auth, presto exposed, druid allowall, druid rce version, solr admin exposed, solr velocity, clickhouse default user no password |
| `references/streaming-and-brokers.md` | Kafka 9092, Connect 8083, Schema Registry 8081, ZooKeeper 2181 and AdminServer, Pulsar 6650/8080, ActiveMQ Classic 61616/8161, Artemis | exposed kafka, kafka connect rce, zookeeper four letter words, zookeeper srvr, pulsar admin exposed, activemq openwire cve-2023-46604, activemq jolokia, artemis console |
| `references/databases-and-data-grids.md` | Neo4j, Db2, Firebird, SAP ASE, SAP HANA, CockroachDB, ArangoDB, RethinkDB, Vertica, Hazelcast, Ignite | neo4j exposed, neo4j default password, db2 50000, firebird masterkey, sybase ase exposed, sap hana port 30015, cockroachdb insecure, arangodb exposed, rethinkdb web ui, hazelcast 5701, ignite rest |

---

## Step 1: Inherit the host and port, never generate them

Take hosts from the signed scope and ports from recon. Confirm IP ownership
(ASN, WHOIS/RDAP, reverse DNS) before the first packet. These clusters often sit
on cloud provider ranges and behind load balancers that answer for several
tenants; a shared address is not the client's cluster.

### Rate posture

These services are shared production clusters, and several of them are
single-threaded control planes (ZooKeeper, a Spark master, a YARN
ResourceManager, an Airflow scheduler). The default, for every step:

```bash
# 2s base delay + 0-3s jitter, one host at a time, serial.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

- Serial, one host and one product at a time. Never point two tools at one
  cluster in parallel.
- One request per endpoint. A timeout is a result: retry once, not in a loop.
- Never request large listings without a limit: pipe to `head -c` and stop.
  A full topic, table or znode walk on a big cluster is load you created.

---

## Step 2: Prove the exposure is real, external and the client's

The `hunt-exposed-services` Step 2 table applies unchanged: external vantage,
IP ownership, honeypot, filtering versus service. Two additions for this family:

| Check | Why it matters here |
|---|---|
| **Advertised versus reached address.** Kafka metadata, Spark `/json/`, Pulsar, Hazelcast and ZooKeeper replies name internal hostnames and RFC 1918 addresses. Record them; never connect to them. | They are recon output, not new scope. A broker that advertises `10.x` addresses is still only the one public address you reached. |
| **Product versus port.** The ports below collide constantly (8080 has a dozen owners). Identify the product from its own reply (Step 3) before quoting any default or CVE. | A "Trino" finding against a ZooKeeper AdminServer is the classic withdrawn report in this family. |

Record the raw first response of every probe before anything else.

---

## Step 3: Identify the product, then load one reference file

### Port collisions and the read that settles each

| Port | Candidates | One discriminating read (Stage A) |
|---|---|---|
| 8080 | Trino/Presto, Spark master UI, ZooKeeper AdminServer, Pulsar admin, Zeppelin, Storm UI, NiFi before 1.14, Airflow, CockroachDB console, RethinkDB UI, Hazelcast Management Center, Ignite REST, HBase REST | `GET /v1/info` (Trino `nodeVersion`), `GET /json/` (Spark `spark://` URL), `GET /commands` (ZooKeeper), `GET /admin/v2/brokers/version` (Pulsar), `GET /api/version` (Zeppelin), `GET /api/v1/cluster/summary` (Storm), `GET /nifi-api/flow/about`, `GET /api/v1/version` (Airflow 2), `GET /health` (CockroachDB), `GET /ignite?cmd=version`. The page title settles the rest |
| 8081 | Flink, Druid coordinator/overlord, Schema Registry, Spark worker UI | `GET /config` (`flink-version`), `GET /status` (Druid `version`), `GET /` with `application/vnd.schemaregistry.v1+json`, Spark version span |
| 8083 | Kafka Connect, Druid historical | `GET /` (`version`, `commit`, `kafka_cluster_id`) versus `GET /status` |
| 8888 | Druid router, Hue, Jupyter (`hunt-exposed-panels`) | `GET /status/health`, Hue login page, `GET /api/` (Jupyter) |
| 9000 | ClickHouse native, FastCGI (`hunt-exposed-services`), HDFS IPC in single-node setups, many HTTP products | HTTP `GET /` answering "Port 9000 is for clickhouse-client program"; Hadoop IPC answering "It looks like you are making an HTTP request to a Hadoop IPC port"; an FCGI record per `hes` |
| 10000 | HiveServer2 Thrift, NDMP, Webmin | Webmin is HTTP; NDMP per `hes`; HiveServer2 is Thrift with no HTTP reply (web UI on 10002) |
| 50000 | Db2 DRDA, SAP NetWeaver AS Java HTTP | `nmap --script drda-info` versus an HTTP reply |
| 5000 | SAP ASE, Flask, Docker registry, UPnP | TDS reply (`-sV`: Sybase Adaptive Server) versus HTTP |
| 61616 | ActiveMQ Classic, Artemis | Classic sends `WireFormatInfo` unprompted; Artemis waits and answers a STOMP 1.2 `CONNECT` with `server:ActiveMQ-Artemis/...` |
| 5672, 1883, 61613 | ActiveMQ, RabbitMQ, Mosquitto | STOMP or OpenWire banner says ActiveMQ: here. Otherwise `hunt-exposed-services` |
| 9090 | HBase Thrift, Prometheus | Prometheus is HTTP (`hunt-exposed-panels`); HBase Thrift UI is on 9095 |
| 9092, 9093 | Kafka client, Kafka KRaft controller (or TLS) | `kcat -L` metadata |

### Route to the reference file

| Product family | Load |
|---|---|
| HDFS legacy and IPC ports, DataNode, NodeManager 8042, JobHistory 19888, Spark standalone 7077/6066/8080, Hive, HBase, Oozie | `references/hadoop-and-spark.md` |
| Zeppelin, Livy 8998, Hue, Storm, NiFi, Flink and Airflow deltas | `references/notebooks-and-pipelines.md` |
| Trino/Presto, Druid, Solr 8983, ClickHouse 8123/9000/9004 | `references/query-search-olap.md` |
| Kafka 9092, Connect 8083, Schema Registry 8081, ZooKeeper 2181, Pulsar 6650/8080, ActiveMQ Classic and Artemis | `references/streaming-and-brokers.md` |
| Neo4j 7474/7687, Db2 50000, Firebird 3050, SAP ASE 5000, SAP HANA 3NN13/3NN15, CockroachDB 26257, ArangoDB 8529, RethinkDB 28015, Vertica 5433, Hazelcast 5701, Ignite 10800 | `references/databases-and-data-grids.md` |

---

## Step 4: Stage A rules for this family

A Stage A probe reads, sends one request, sends **no credential and no claimed
identity**, leaves no server-side state, and fails as an error rather than a
restart. Within that, five traps specific to data platforms:

1. **The server trusts the identity you send.** Hadoop simple auth (`user.name=`,
   `doas=`), Trino's `X-Trino-User`, PrestoDB's `X-Presto-User` on HTTP, Livy's
   `proxyUser` and Db2 `AUTHENTICATION CLIENT` all believe the caller. Stage A
   sends no identity at all, so the server falls back to its anonymous identity
   (`dr.who` on Hadoop). Naming `hdfs`, `admin` or any real user is
   impersonation: Stage B.
2. **Reads that create state.** A Kafka metadata request naming a topic can
   auto-create it; a Kafka consumer with a group id rebalances live consumers and
   commits offsets; any Pulsar or Artemis producer or consumer can auto-create a
   topic or queue, and a Pulsar subscription is a durable cursor. Use `kcat -L`
   without `-t` or `-G`, and nothing more.
3. **GETs that write.** Hadoop `/logLevel?log=...&level=...`, Airflow 1.10
   `.../paused/<bool>`, WebHDFS `GETDELEGATIONTOKEN`, the ActiveMQ REST message
   API (a `GET` consumes the message) and ZooKeeper `crst`/`srst`/`stmk`. The
   verb is not the test; the effect is.
4. **Metadata statements.** Where the protocol only accepts a statement, one
   constant or metadata statement (`RETURN 1`, `SELECT version()`, `SHOW
   DATABASES`) sent with no credential counts as Stage A, following
   `hunt-exposed-services`' `SELECT version()` precedent. Statements that read
   rows, call procedures or functions that reach files or URLs, or run under a
   claimed user are Stage B. **Trino and PrestoDB are the exception:** every
   statement needs a claimed user and is recorded as a cluster query, so even
   `SHOW CATALOGS` is Stage B there.
5. **Responses that carry secrets.** Hadoop `/conf` and `/jmx`, Druid
   `/status/properties`, Kafka Connect connector configs, Flink
   `/jobmanager/config`, Spark environment tabs. Record that the endpoint
   answers and which property names matter; do not keep values, and do not
   fetch Connect connector configs at all.

### Default credentials follow the `infra-ssh` model

One vendor-documented default pair, once, per host, **under Stage B**:
ActiveMQ `admin`/`admin`, Artemis container `artemis`/`artemis`, Neo4j
`neo4j`/`neo4j`, Firebird legacy `SYSDBA`/`masterkey`, SAP ASE `sa` with an
empty password where the release allowed it. This is stricter than
`hunt-exposed-services` (which allows one attempt in Stage A) because the
`infra-*` family treats any credential use as Stage B. Products whose
unconfigured state lets the first visitor create the administrator (the Hazelcast
Management Center first-run page) are reported from the page; claiming it is
Stage B.

### NSE scripts

Check categories with `nmap --script-help <name>` before running anything. In
nmap 7.991: `drda-info` and `db2-das-info` are `safe`, `discovery`, `version`.
`hadoop-*-info` and `hbase-*-info` are `default`, `discovery`, `safe` but scrape
Hadoop 1.x JSP pages on the legacy ports: empty output on Hadoop 3 is "old
script", not "not Hadoop". `drda-brute` is credential guessing. `-sV` sends
`stats\r\n` to ZooKeeper, which reads it as `stat` and, on older servers,
answers with every client's address. No `-sC`, no `-A`.

---

## Step 5: Version gates and the KEV shortlist

A version inside a range is **unconfirmed** until the client confirms the build
or a Stage B check is signed off. The full matrices sit at the end of each
reference file. These are the rows from this family in the CISA KEV catalog
(feed 2026.10.13), all checked against the local feed:

| Product | CVE | Affected (fixed) | Remote gate | KEV added |
|---|---|---|---|---|
| ActiveMQ Classic | CVE-2023-46604 (OpenWire class instantiation, RCE) | < 5.15.16, 5.16.7, 5.17.6, 5.18.3 | OpenWire `ProviderVersion` (5.14.0+) or STOMP `server:` header, passively | 2023-11-02, known ransomware use |
| ActiveMQ Classic | CVE-2026-34197 (Jolokia connector operations, RCE) | < 5.19.4, 6.0.0-<6.2.3; bypasses through 5.19.7 / 6.2.6 | Same banner; Jolokia reachability decides exposure | 2026-04-16 |
| ActiveMQ Classic | CVE-2016-3088 (fileserver PUT/MOVE; pre-2019, still KEV) | 5.x < 5.14.0 | Banner | 2022-02-10 |
| Apache Solr | CVE-2019-17558 (VelocityResponseWriter RCE) | see `query-search-olap.md` | `/solr/admin/info/system` | 2021-11-03 |
| Apache Solr | CVE-2019-0193 (DataImportHandler code injection) | see `query-search-olap.md` | Same, plus DIH configured | 2021-12-10 |
| Apache Airflow | CVE-2020-13927 (experimental API open by default) | < 1.10.11 | `/api/experimental/test` answers without credentials | 2022-01-18 |
| Apache Airflow | CVE-2020-11978 (example-DAG command injection) | <= 1.10.10 | Version plus example DAGs listed | 2022-01-18 |
| Apache Flink | CVE-2020-17519 (file read) | 1.11.0-<1.11.3 | `hunt-exposed-panels` | 2024-05-23 |
| Apache Spark | CVE-2022-33891 (UI ACL shell injection) | <= 3.2.1 lines | `hunt-exposed-panels` | 2023-03-07 |

Nothing else in this family is in KEV: no Hadoop, Hive, HBase, Kafka, ZooKeeper,
Pulsar, Artemis, Druid, Trino, NiFi, ClickHouse or listed database row. Do not
write "actively exploited" for any of them. CVE-2021-44228 (Log4Shell) is in KEV
and affects many of these JVMs by version; gate it here, test it in `hunt-rce`.

Two grading rules that recur in every matrix:

- **"PR:L" on a product that ships without authentication is pre-auth in
  practice.** Druid under `allowAll`, Kafka Connect, Pulsar Functions with auth
  off, Hazelcast Community, Ignite with auth off, an insecure CockroachDB: every
  connecting client holds the "low privilege" the vector assumes. Say so and
  name the configuration.
- **"PR:N" that contradicts the record's own description is not pre-auth.**
  Several Airflow, NiFi and Kafka records do this. Quote the description.

---

## Step 6: Stage B, anything that writes, submits, executes or claims an identity

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the host, the identity used and a time window. Record before
the first packet:

```
Stage B authorization
  Host/port:        192.0.2.60:8161
  Action:           one admin/admin attempt on the ActiveMQ web console
  Identity:         admin (vendor default), no other pair
  Blast radius:     one failed or successful login in the broker's Jetty log;
                    no destination, message or MBean touched after login
  Reversibility:    nothing to reverse; client rotates the credential
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| Job submission: YARN application, Spark driver (6066/7077), Flink JAR, Druid task or sampler, Livy session or statement, Oozie workflow, Storm topology | Runs code on production nodes as the service account; consumes cluster capacity; may move data or spend money |
| Notebook execution: Zeppelin paragraph, Hue editor query, Livy statement | Code as the interpreter's OS user, on a shared host |
| A Trino or Presto statement, even `SHOW CATALOGS` | A query logged under the identity you claim |
| Kafka produce, topic creation, consume with or without a group | Third-party data read, or state left on the broker |
| Kafka Connect connector create, validate, update, delete | Plugin code runs with your configuration |
| Pulsar, Artemis or ActiveMQ producer, consumer, subscription, destination create | Auto-created topics and durable cursors that grow until removed |
| ActiveMQ or Artemis Jolokia `exec` | MBean operations, including the CVE-2026-34197 code path |
| ZooKeeper `create`, `set`, `delete`, `setAcl`, or `get` on a data znode | Coordination state of every system using the ensemble |
| Any request naming a real identity (`user.name=`, `X-Trino-User`, `proxyUser`) | Impersonation of that account in its audit trail |
| One documented default credential | A login, possibly a lockout counter; on Neo4j a forced-change session you must not complete |
| Reading rows, documents, messages or znode data to "show impact" | Personal data you then hold. Counts and names already prove it |

**Forbidden outright, sign-off or not:** every DoS-class CVE flagged in the
matrices (Kafka CVE-2022-34917, the Firebird 2026 slice-packet crashes, the
Neo4j Bolt handshake hang, ActiveMQ pre-auth OOM rows, CockroachDB
CVE-2021-3121, SAP HANA CVE-2019-0350, Db2 query crashes, NiFi decompression
DoS); ZooKeeper AdminServer `snapshot`/`restore` and any znode deletion; any
public exploit for a KEV row (report from the version gate); JNDI or LDAP
login-module payloads, template-injection payloads and deserialization gadgets
of any kind; using a cluster to reach addresses it advertises.

---

## Step 7: Grade by what you proved

| What you proved (Stage A unless stated) | Grade |
|---|---|
| Job submission or code execution reachable by design with no authentication (YARN on simple auth, Spark master or REST, Kafka Connect, Livy, anonymous Zeppelin, NiFi over HTTP, Flink with `web-submit`, Druid `allowAll`, Ignite REST, Hazelcast Community, RethinkDB web UI) | Critical, reported from the read; nothing executed |
| Unauthenticated read of production data names and counts (topics, datasources, collections, databases, HDFS paths, keyspaces) | High to Critical by data class |
| Default credential accepted (Stage B) | Critical |
| Version inside a KEV-listed range with the vulnerable surface reachable | High to Critical, labelled unconfirmed, same-day notice to the client |
| Version inside a non-KEV pre-auth range | Medium, labelled unconfirmed, with the backport caveat |
| Secrets-bearing endpoint reachable (`/conf`, `/status/properties`, connector configs) with names visible | High; values never captured |
| Internal hostnames, cluster IDs, broker lists only, authentication enforced | Low |
| Exposed, authentication enforced, current version | Informational hardening item |

### What is not a finding

- **Public-by-design endpoints.** Trino `/v1/info`, Druid `/status/health`,
  Airflow `/api/v*/version`, ArangoDB `/_admin/server/availability`, Pulsar
  `/metrics`, the Neo4j discovery document, Kafka `ApiVersions`. They gate
  versions; they prove nothing about access.
- **Banner or version disclosure alone.** HackerOne lists "Software version
  disclosure / Banner identification issues" as ineligible; Bugcrowd's VRT rates
  banner disclosure P5.
- **A login page or a 401** on a product that ships authenticated (NiFi 1.14+,
  Artemis, secured Druid). That is the control working.
- **DoS-class CVEs** in a banner: a patch item, Low to Medium, never "critical".
- **Client-library CVEs** (Kafka producer, NMS .NET clients, libhdfs, Avro):
  an exposed server is not evidence of them.

---

## Step 8: Evidence

Follow `evidence-hygiene`. Minimum per finding: the raw first response with
timestamps and egress IP, the exact command, the version field as returned, and
the names-and-counts listing that establishes impact (topic, datasource, core,
collection or database names; document or message counts). Redact internal
hostnames and client IP addresses that appear in replies (ZooKeeper `stat`,
Kafka metadata, Spark `/json/`) in anything that leaves the engagement. Never
capture message bodies, rows, connector configs or configuration values. For
Stage B, add the sign-off record and the single line that proves the result.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| ZooKeeper `ls /` names `brokers`, `hbase`, `hadoop-ha` | The ensemble maps the rest of the estate | Recon multiplier | Scope check each named service, then this skill |
| Kafka metadata or Spark `/json/` advertises internal hosts | Internal topology disclosed | Low alone | `offensive-osint` for naming; never connect to them |
| Open Kafka Connect with JDBC or S3 connector plugins | Connector configs hold database or cloud credentials | Critical (do not read them) | Report; `hunt-cloud-misconfig` only if a key leaks elsewhere |
| Hadoop `/conf`, Druid `/status/properties` naming object-store properties | Cloud storage credentials on the cluster | High | `hunt-cloud-misconfig`, `cloud-iam-deep` if a key surfaces |
| ActiveMQ banner in the CVE-2023-46604 range | KEV-listed pre-auth RCE | Critical-class, unconfirmed | Same-day notice. No exploit |
| Airflow 1.10.x with the experimental API open | CVE-2020-13927 plus example DAGs (CVE-2020-11978) | Critical-class | `hunt-exposed-panels` for the console |
| Neo4j discovery document lists OIDC providers | Identity integration details | Low | `hunt-oauth` |
| Open Druid, Trino or ClickHouse | Every catalog it federates is reachable | Critical | Report the catalog and datasource names |
| Any JVM in this family with a 2021-era version | Log4Shell by version | Unconfirmed | `hunt-rce` |

---

## Validation checklist

- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Every IP confirmed client-owned and in the signed scope; advertised internal
      addresses were recorded, not contacted.
- [ ] Product identified from its own reply, not the port number (Step 3).
- [ ] No request carried `user.name=`, `doas=`, a Trino/Presto user, a Livy
      `proxyUser` or any credential outside a signed Stage B action.
- [ ] Kafka: `-L` only, no `-t`, no `-G`, no consume. Pulsar/Artemis: no producer
      or consumer connection.
- [ ] ZooKeeper: `srvr` plus at most one other read-only word; no `crst`,
      `srst`, `stmk`, `wchc`, `wchp`, `dump`, `cons`; AdminServer limited to
      `/commands` and `srvr`.
- [ ] No job, statement (Trino/Presto), notebook paragraph, connector, topic,
      table, queue or subscription created.
- [ ] Secrets-bearing endpoints recorded by name only; no values kept; no
      Connect connector config fetched.
- [ ] Every default-credential attempt was Stage B, one pair, once.
- [ ] KEV claims match the CISA feed; every other row says "not in KEV".
- [ ] Version-gated findings labelled unconfirmed; no DoS-class CVE tested.
- [ ] Impact evidenced by names and counts. No rows, documents or messages kept.
- [ ] The report ends at access proven plus impact.

---

## Sources

Primary sources (fetched 2026-10-13): CISA KEV feed, catalog 2026.10.13
(<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>); CVE Program
records (<https://cveawg.mitre.org/api/cve/>); NVD
(<https://services.nvd.nist.gov/rest/json/cves/2.0>); Apache security pages
(<https://hadoop.apache.org/cve_list.html>, <https://spark.apache.org/security.html>,
<https://kafka.apache.org/cve-list>, <https://zookeeper.apache.org/security.html>,
<https://solr.apache.org/security.html>, <https://pulsar.apache.org/security/>,
<https://activemq.apache.org/security-advisories>, <https://security.apache.org/projects/>);
GitHub Security Advisories for Hazelcast, ArangoDB, Firebird and ClickHouse;
project documentation for each product (Hadoop, Spark, Trino, Druid, NiFi,
Flink, Neo4j, CockroachDB, RethinkDB, Ignite, Hazelcast, ArangoDB); nmap 7.991
NSE scripts and `nmap-service-probes`; HackerOne core ineligible findings
(<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>);
Bugcrowd VRT (<https://github.com/bugcrowd/vulnerability-rating-taxonomy>).

---

## Related Skills & Chains

- `hunt-exposed-services`: the generic non-HTTP triage this skill specialises;
  owns the baseline Hadoop probes and the generic broker rules this skill reuses.
- `hunt-exposed-panels`: Spark application UI, Flink, Airflow and Jupyter
  consoles, with their read-only CVE confirmations.
- `infra-external-methodology`: the master port-to-skill routing table.
- `infra-ssh`: the Stage B default-credential model this skill copies.
- `hunt-cloud-misconfig`, `cloud-iam-deep`: managed equivalents, and object-store
  credentials named in cluster configuration.
- `hunt-rce`: Log4Shell and other out-of-band confirmation, under its rules.
- `hunt-sqli`, `hunt-nosqli`, `hunt-ssrf`: the same engines reached through the
  client's application.
- `hunt-brute-force`: any credential guessing.
- `hunt-k8s`: the clusters these workloads run on.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence handling,
  false-positive gates and write-up.

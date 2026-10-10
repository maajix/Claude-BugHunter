# Exposed datastores and analytics services

Scope: the datastore answers directly from a public address. Injection into a
datastore the application already reaches is `hunt-nosqli`. The same services
reached through a web application's URL fetcher are `hunt-ssrf`. Managed cloud
equivalents (RDS, DocumentDB, OpenSearch, ElastiCache, Cosmos) are
`hunt-cloud-misconfig`.

Every probe below is **Stage A**: it reads server metadata and nothing else. The
state-changing commands each protocol offers are listed under "Never" so you can
recognise them in someone else's write-up and not run them.

## Port map and default posture

| Port | Service | Default posture that produces the finding |
|---|---|---|
| 6379, 16379 | Redis | Since 3.2.0 Redis enters *protected mode* when bound to all interfaces with no password, and answers non-loopback clients with an explanatory error instead of data. A reachable Redis that serves commands therefore means an administrator disabled protected mode or set an explicit `bind`. |
| 27017, 27018, 27019 | MongoDB (standalone/replica member, shard member, config server) | `net.bindIp` defaults to localhost and `mongod`'s `--noauth` is documented as the current default, so a publicly reachable MongoDB that answers commands is two deliberate configuration changes away from the shipped defaults. |
| 9200, 9300 | Elasticsearch | In 7.x, `xpack.security.enabled` defaults to `false` under a basic or trial licence. Elasticsearch 8.0 and later enable security and TLS by default on first start, but the auto-configuration is skipped when the data directory is non-empty, when `xpack.security.*` is already set, or when discovery settings are pre-configured. So an open 8.x cluster means either security was switched off or the node was started into a pre-existing configuration. |
| 5601 | Kibana | Inherits the cluster's auth. Unauthenticated Kibana is a full read UI over the indices. |
| 5984, 6984 | CouchDB | Before 3.0 an instance with no admin configured ran in "admin party": every anonymous request had admin rights. 3.0+ refuses to start without an admin, so the modern finding is a weak or default admin. |
| 8086 | InfluxDB | 1.x ships with HTTP auth disabled (`auth-enabled = false`). Also a very common plain HTTP alt port, so fingerprint before you claim it. |
| 11211 | memcached | No authentication in the protocol at all. SASL exists but is rarely enabled. UDP has been off by default since **1.5.6** (February 2018, in direct response to the amplification attacks); it only comes back if someone passed `-U 11211`, and `-U 0` is the explicit off switch to recommend in remediation. |
| 9042, 7199 | Cassandra (CQL, JMX) | Default authenticator allows all connections; default credentials `cassandra` / `cassandra` once authentication is enabled. |
| 5432 | PostgreSQL | `listen_addresses` defaults to localhost. Exposure plus a `trust` or `md5`-with-weak-password entry in `pg_hba.conf` is the finding. |
| 3306, 33060 | MySQL / MariaDB | The server sends a version and capability banner before any authentication, so the version leak is free. |
| 1521, 1522-1529 | Oracle TNS listener | Older listeners answer version and status queries with no credential. |
| 9001 | HSQLDB | Ships with user `sa` and an empty password. |
| 8089 | splunkd management | Historically default `admin` / `changeme`. |
| 9870, 9864, 8088 | Hadoop NameNode HTTP, DataNode HTTP, YARN ResourceManager | Hadoop 3 defaults: `dfs.namenode.http-address` 9870, `dfs.datanode.http.address` 9864. Hadoop 2 used 50070 and 50075, which you will still meet on legacy clusters. Without Kerberos, WebHDFS and YARN application submission are open. |

## Stage A probes

### Redis (6379)

```bash
TARGET="192.0.2.10"
# PING and INFO both fail with NOAUTH on a password-protected instance and with a
# protected-mode error on a default install, so a real reply proves unauthenticated access.
redis-cli -h "$TARGET" -p 6379 PING
redis-cli -h "$TARGET" -p 6379 INFO server | head -20
redis-cli -h "$TARGET" -p 6379 INFO keyspace     # key counts per DB = impact, without reading keys
redis-cli -h "$TARGET" -p 6379 ACL WHOAMI        # which identity you are acting as
# nmap equivalent: --script redis-info (discovery, safe).
# Do not send AUTH speculatively: on an instance with no requirepass it errors
# with "AUTH <password> called without any password configured for the default
# user", which is noise in the target's log and tells you nothing new.
```

Impact evidence: the `db0:keys=N` line from `INFO keyspace` plus the version from
`INFO server`. That is enough.

**Never:** `CONFIG SET dir` / `dbfilename`, `SAVE`, `BGSAVE`, `MODULE LOAD`,
`SLAVEOF` / `REPLICAOF`, `FLUSHALL`, `FLUSHDB`, `DEBUG`, `SHUTDOWN`, or any
`EVAL` script. `REPLICAOF` against a master you control replaces the entire
dataset. The RDB-write trick that lands an SSH key or a cron entry is persistence
and is out of scope for this bundle.

### MongoDB (27017)

```bash
mongosh --host "$TARGET" --port 27017 --quiet \
  --eval 'db.version()'
mongosh --host "$TARGET" --port 27017 --quiet \
  --eval 'db.adminCommand({listDatabases:1, nameOnly:true})'
# Per-collection counts prove impact without reading documents:
mongosh --host "$TARGET" --port 27017 --quiet \
  --eval 'db.getSiblingDB("<dbname>").getCollectionNames()'
```

A `listDatabases` reply with no credential is the finding. Take counts and
collection names; do not dump documents. **Never** `insert`, `drop`,
`createUser`, or `eval`.

### Elasticsearch (9200) and Kibana (5601)

```bash
curl -s "http://$TARGET:9200/" | head -40                 # version + cluster name
curl -s "http://$TARGET:9200/_cluster/health?pretty"
curl -s "http://$TARGET:9200/_cat/indices?v&h=index,docs.count,store.size"
curl -s "http://$TARGET:9200/_cat/nodes?v"
curl -s "http://$TARGET:5601/api/status" | head -c 600      # Kibana version + plugin state
```

`_cat/indices` gives index names, document counts and sizes: a complete impact
statement in one read-only request. Index names routinely identify the data class
on their own. **Never** `PUT`/`POST`/`DELETE` any index, and never use
`_search` with a large `size` to pull records.

### CouchDB (5984)

```bash
curl -s "http://$TARGET:5984/"             # version banner
curl -s "http://$TARGET:5984/_up"
curl -s "http://$TARGET:5984/_all_dbs"     # anonymous DB listing = admin party or open read
curl -s "http://$TARGET:5984/<db>"         # doc_count, update_seq, disk_size
```

An anonymous `_all_dbs` is the proof. **Never** touch `_config` (changing
configuration over HTTP is how CouchDB's historical config-to-RCE path works),
and never read `_users` documents.

### InfluxDB (8086)

```bash
curl -s -i "http://$TARGET:8086/ping" | head -5            # version in X-Influxdb-Version
curl -s "http://$TARGET:8086/health"
# 1.x, read-only query:
curl -sG "http://$TARGET:8086/query" --data-urlencode 'q=SHOW DATABASES'
```

Fingerprint before claiming it: 8086 is also a generic HTTP alt port. The
`X-Influxdb-Version` response header is the discriminator. **Never** issue
`DROP`, `CREATE`, or write-line-protocol POSTs to `/write`.

### memcached (11211)

```bash
# TCP text protocol, read-only stats commands only
printf 'version\r\nstats\r\nquit\r\n' | timeout 10 nc "$TARGET" 11211 | head -40
printf 'stats items\r\nquit\r\n'      | timeout 10 nc "$TARGET" 11211 | head -40
printf 'stats slabs\r\nquit\r\n'      | timeout 10 nc "$TARGET" 11211 | head -40
```

`stats` returns `curr_items`, `bytes` and `cmd_get`, which is the impact
statement. The `stats cachedump` walk that recovers key names is a debug command
the project has long discouraged, returns a non-deterministic subset, and is
unnecessary once you have the counts.

UDP: at most **one** unspoofed packet, purely to record that the UDP listener
exists. memcached UDP is an amplification reflector. Never loop it, never spoof
a source address, and never send one from an address that is not yours. The
reportable finding is "this host can be used to reflect traffic at third
parties", which is a different and lesser finding than data exposure.

**Never** `set`, `add`, `delete`, or `flush_all`.

### Cassandra (9042), PostgreSQL (5432), MySQL (3306)

```bash
# Cassandra: CQL banner + version, no keyspace reads
cqlsh "$TARGET" 9042 -e "SELECT release_version FROM system.local;"

# PostgreSQL: does it accept a connection at all, and as whom
psql "host=$TARGET port=5432 user=postgres dbname=postgres connect_timeout=10" \
  -c "SELECT version(), current_user;"
psql "host=$TARGET port=5432 user=postgres dbname=postgres connect_timeout=10" \
  -c "\l"      # database list only

# MySQL: the pre-auth handshake already carries the version
timeout 10 nc "$TARGET" 3306 < /dev/null | head -c 120 | strings
```

A successful `psql` connection with no password is the finding. Stop at
`version()`, `current_user` and the database list. `COPY ... FROM PROGRAM` is
post-authentication, needs a privileged role, and is command execution: do not
run it. Do not try alternate usernames; that is credential guessing.

### Oracle TNS listener (1521), HSQLDB (9001), splunkd (8089), Hadoop

```bash
# Oracle: version and status from the listener, no SID guessing
tnscmd10g version -h "$TARGET" -p 1521
tnscmd10g status  -h "$TARGET" -p 1521

# HSQLDB: default sa / empty password is the whole finding
# (connect read-only, read the version, stop)
# Hadoop 3 NameNode / YARN, unauthenticated REST:
curl -s "http://$TARGET:9870/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo" | head -c 800
curl -s "http://$TARGET:9870/webhdfs/v1/?op=LISTSTATUS" | head -c 800
curl -s "http://$TARGET:8088/ws/v1/cluster/info"
```

SID enumeration against a TNS listener is credential-style brute force: out of
scope here, see `hunt-brute-force`. HSQLDB's Java language routines and
`SCRIPT`-to-file primitives are command execution and file write: Stage B, and
almost never needed, because `sa` with an empty password is already Critical.
On Hadoop, an anonymous `LISTSTATUS` or an anonymous YARN `cluster/info` is the
finding. **Never** submit a YARN application; that is unauthenticated remote
code execution by design and it runs real work on the cluster.

## Pre-auth CVE watchlist

Treat a version inside a range as *unconfirmed*. Report it as a version finding,
not as an exploited vulnerability, unless the operator signed off on exploitation.

| CVE | Product and affected range | Class | Reachable pre-auth from the network? |
|---|---|---|---|
| CVE-2025-49844 | Redis < 6.2.20, 7.0 to < 7.2.11, 7.4.0 to < 7.4.6, 8.0.0 to < 8.0.4, 8.2.0 to < 8.2.2; Valkey < 7.2.11, 8.0.0 to < 8.0.6, 8.1.0 to < 8.1.4 | Lua garbage-collector use-after-free reached by a crafted script, leading to remote code execution ("RediShell") | PARTIAL. Rated PR:L, so it needs the ability to run `EVAL`. An exposed passwordless instance supplies exactly that. |
| CVE-2025-46817 | Redis, same ranges, fixed 8.2.2 | Integer overflow in Lua scripting leading to code execution | PARTIAL, same `EVAL` precondition. Note that NVD scores it AV:N while the project advisory scores it AV:L/AC:H; cite the disagreement rather than picking one. |
| CVE-2025-46818 | Redis, same ranges, fixed 8.2.2 | Lua script runs code in another user's context | NO. The NVD vector is AV:L with UI:R, so it is not a network path. Do not cite it as one. |
| CVE-2026-23631 | Redis < 8.6.3 per NVD; the project advisory says 7.0.0 and later with the patch version still open | Use-after-free in the replication/Lua path on a replica, leading to remote code execution | PARTIAL. Needs `EVAL` plus a replica with `replica-read-only` disabled. |
| CVE-2022-0543 | Redis **as packaged by Debian and Ubuntu only**. Debian fixes 5:5.0.14-1+deb10u2 (buster) and 5:6.0.16-1+deb11u2 (bullseye). NVD states no upstream range. | Lua sandbox escape specific to the distribution's packaging, leading to code execution | PARTIAL. Scored PR:N, but still needs `EVAL` to be reachable, i.e. no `requirepass`. |
| CVE-2025-14847 | MongoDB Server; fixed in 4.4.30, 5.0.32, 6.0.27, 7.0.28, 8.0.17, 8.2.3. 3.6, 4.0 and 4.2 are affected and unfixed. | Zlib header length confusion leading to an uninitialised heap read | YES. The CNA record states an unauthenticated client can trigger it. |
| CVE-2017-12635 | Apache CouchDB 1.2.0 to 1.6.1 and 2.0.0 to 2.1.0 (NVD CPE: < 1.7.0 and 2.0.0) | Two JSON parsers disagree on duplicate keys, letting any user create an admin account | YES. PR:N, CVSS 9.8. Chains into CVE-2017-12636 for execution. |
| CVE-2017-12636 | Apache CouchDB, same ranges | Admin-only configuration change reaches OS command execution | PARTIAL. PR:H, so admin is required. CVE-2017-12635 supplies it. |
| CVE-2018-8007 | Apache CouchDB < 1.7.2 and 2.0.0 to 2.1.1 (fixed 1.7.2 and 2.1.2) | Configuration change reaches code execution, bypassing the CVE-2017-12636 fix | PARTIAL. PR:H, admin required. |
| CVE-2022-24706 | Apache CouchDB <= 3.2.1, fixed 3.2.2 | The installer's default Erlang distribution cookie `monster` grants remote access to the Erlang VM | YES, PR:N, CVSS 9.8. **The entry point is `epmd` plus the random Erlang distribution port, not 5984.** CouchDB's own advisory page describes `epmd` advertising a random distribution port on all interfaces, and 3.2.2 both refuses the default cookie and binds `epmd` and the distribution port to loopback. |
| CVE-2019-20933 | InfluxDB < 1.7.6 | A JWT is accepted when the shared secret is empty, giving an authentication bypass | YES. PR:N, CVSS 9.8. |
| CVE-2019-7609 | Kibana < 5.6.15 and 6.0.0 to < 6.6.1 | Timelion arbitrary code execution | YES. PR:N, CVSS 10.0, provided the Timelion app is reachable. |
| CVE-2018-17246 | Kibana 5.0.0 to < 5.6.13 and 6.0.0 to < 6.4.3 | Console plugin local file inclusion leading to JavaScript execution | YES. PR:N, CVSS 9.8, provided the Console API is reachable. |
| CVE-2015-1427 | Elasticsearch < 1.3.8 and 1.4.0 to < 1.4.3 | Groovy scripting sandbox bypass to shell command execution | YES on an open cluster. CVSS 9.8. |
| CVE-2022-41853 | HSQLDB < 2.7.1 | Untrusted SQL can call any static Java method | PARTIAL. Rated PR:L with UI:R; it needs a SQL path. On an `sa`-with-empty-password instance the exposure itself already carries the finding. |

Deliberately listed as **not** network pre-auth paths, because they get
miscited constantly:

- **CVE-2019-9193 (PostgreSQL `COPY ... FROM PROGRAM`).** PostgreSQL publicly
  disputes it and states it is not a security vulnerability. It needs
  authentication plus either superuser or the `pg_execute_server_program` role.
  Do not file it. The finding on an exposed PostgreSQL is the exposure and the
  `pg_hba.conf` policy, not this CVE.
- **CVE-2023-26031 (Apache Hadoop 3.3.1 to 3.3.4).** Local privilege escalation
  via a relative RPATH in `container-executor`. Not a remote network path.
- **CVE-2024-30896 (InfluxDB OSS 2.x through 2.7.11).** The supplier describes
  it as intended behaviour; rated PR:H. Not a pre-auth finding.
- **CVE-2023-21971** is in MySQL **Connector/J**, and **CVE-2024-12744** is in
  the **Amazon Redshift JDBC driver**. Both are client libraries. Neither is
  reachable by connecting to an exposed server port.

The Redis Lua issues above all need the ability to send a script. On a correctly
authenticated Redis they are a patch-cycle item for the client. On an exposed,
passwordless Redis they are reachable by anyone, which is exactly why the
exposure itself is the Critical finding and the CVE is a severity multiplier
rather than the headline.

Version ranges here come from NVD and the CVE Program records; where the NVD
analysis was unavailable the range is as stated by the CNA, which is sometimes
broader than the vendor's own advisory. Re-check the vendor advisory before
putting a range in a client report.

## Checklist

- [ ] Service identified from its own protocol reply, not from the port number.
- [ ] Unauthenticated access proven by a command that an authenticated instance
      refuses (`NOAUTH`, 401, `authentication required`).
- [ ] Impact evidenced by counts and names only. No records copied.
- [ ] No write, drop, flush, config change or script execution sent.
- [ ] No alternate usernames or passwords tried beyond one documented default.
- [ ] memcached UDP touched at most once, unspoofed, from an address you own.
- [ ] Version-in-range CVEs labelled unconfirmed.

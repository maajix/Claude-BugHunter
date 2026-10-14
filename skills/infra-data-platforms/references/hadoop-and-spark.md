# Hadoop core and Spark standalone

HDFS NameNode and DataNode, YARN ResourceManager and NodeManager, MapReduce
JobHistory, and the Spark standalone cluster manager (master RPC 7077, REST
submission 6066, master UI 8080, worker UI 8081).

**Ownership.** The baseline Hadoop 3 probes already live in
`hunt-exposed-services` `references/databases.md`: NameNode `NameNodeInfo` JMX
on 9870, an anonymous WebHDFS `LISTSTATUS` of `/`, and YARN `cluster/info` on
8088. Run those from there. This file adds the legacy 2.x ports, the IPC ports,
DataNode, NodeManager, JobHistory, the default-identity trap, Spark standalone
and the version matrix. The Spark **application** UI (4040) and history server
(18080), including CVE-2022-33891, belong to `hunt-exposed-panels`
(`references/data-and-notebook-tools.md`).

Rate posture: serial, 2 s base delay plus 0-3 s jitter.

---

## The trap that makes "read-only" probes unsafe here

Hadoop's defaults (`core-default.xml`): `hadoop.security.authentication=simple`
("no authentication"), `hadoop.http.authentication.simple.anonymous.allowed=true`,
`hadoop.security.authorization=false`, and anonymous web requests run as the
static user `dr.who`. Under simple authentication **the caller names its own
identity**: WebHDFS documents that "the authenticated user is the username
specified in the `user.name` query parameter".

Consequences for Stage A:

- Never add `user.name=` (or `doas=`) to any request. Naming `hdfs`, `yarn` or
  any real account is impersonation of that account, and under simple auth the
  HDFS superuser is simply the NameNode process owner. Stage B, every time.
- With no `user.name`, requests run as `dr.who`. That is the identity the
  finding is about: "anyone on the internet acts as `dr.who`".
- `hadoop.security.authorization=false` also makes `HttpServer2` treat every
  caller as an administrator, so `/logLevel` and `/logs` are open. A `GET` to
  `/logLevel` **with** `log=` and `level=` parameters changes a log level: it
  is a write despite the verb. Do not send it.
- WebHDFS `op=GETDELEGATIONTOKEN` is a `GET` that mints a credential, and
  `op=OPEN` reads file contents. Neither is Stage A.
- `/conf`, `/jmx`, `/stacks` and `/logs` are read-only but routinely carry
  secrets, internal hostnames and paths. Record that they answer and the
  property **names** that matter; do not harvest values.

## Ports and one discriminating read each

| Port | Service | Stage A read | Product and version field |
|---|---|---|---|
| 9870 (2.x 50070), TLS 9871 (2.x 50470) | NameNode HTTP | `hes` `databases.md` probe, or `GET /jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo` | `SoftwareVersion`, `Version` |
| 8020 (also 9000 in single-node examples) | NameNode IPC | `GET / HTTP/1.1` | IPC answers `404` "It looks like you are making an HTTP request to a Hadoop IPC port." No version. Same reply from DataNode IPC 9867, RM 8032, JobHistory 10020 |
| 9864 (2.x 50075), TLS 9865 | DataNode HTTP | `GET /jmx?qry=Hadoop:service=DataNode,name=DataNodeInfo` | `Version`, `SoftwareVersion` |
| 9866 (2.x 50010) | DataNode data transfer | none documented; record the open port | n/a |
| 8088, TLS 8090 | YARN ResourceManager | `hes` probe, `GET /ws/v1/cluster/info` | `resourceManagerVersion`, `hadoopVersion`, `haState` |
| 8042 | YARN NodeManager | `GET /ws/v1/node/info` | `nodeManagerVersion`, `hadoopVersion` |
| 19888, TLS 19890 | MapReduce JobHistory | `GET /ws/v1/history/info` | `hadoopVersion`, `hadoopBuildVersion` |
| 8080 | Spark master UI | `GET /` (version), `GET /json/` (product) | Version in the HTML `class="version"` span; `/json/` carries `url` (`spark://host:7077`), worker and app counts, `status`, but no version |
| 8081 | Spark worker UI | `GET /` | Same version span. Collides with Flink, Druid and Schema Registry (SKILL.md Step 3) |
| 6066 | Spark REST submission server | `GET /` | JSON `"action":"ErrorResponse"`, "Missing protocol version.", `serverSparkVersion` |
| 7077 | Spark master RPC | none; never register an application | n/a |

```bash
TARGET="192.0.2.50"
curl -s -m 10 "http://$TARGET:9864/jmx?qry=Hadoop:service=DataNode,name=DataNodeInfo" | head -c 600
probe_delay
curl -s -m 10 "http://$TARGET:8042/ws/v1/node/info"
probe_delay
curl -s -m 10 "http://$TARGET:19888/ws/v1/history/info"
probe_delay
curl -s -m 10 "http://$TARGET:8080/json/" | head -c 600       # Spark master: product, counts
probe_delay
curl -s -m 10 "http://$TARGET:6066/"                           # Spark REST: serverSparkVersion
```

NSE trap: `hadoop-namenode-info`, `hadoop-datanode-info`, `hadoop-jobtracker-info`,
`hbase-master-info` and `hbase-region-info` are `default`, `discovery`, `safe`,
but they scrape Hadoop 1.x JSP pages (`/dfshealth.jsp`, `/dfsnodelist.jsp`) on
the legacy ports. Empty output on Hadoop 3 means "old script", not "not Hadoop".

## Default posture worth reporting

- **YARN application submission is open on simple auth.** The documentation says
  write endpoints need an authentication filter; in the code the static-user
  filter sets the caller to `dr.who`, the writable-endpoint check rejects the
  static user only when Kerberos is on, and the admin ACL check runs only when
  `yarn.acl.enable` is true (default false, with `yarn.admin.acl=*`). So an
  anonymous `cluster/info` on an unsecured cluster implies anonymous job
  submission, which is code execution on the cluster by design. Report it from
  the `cluster/info` read and the security mode; never demonstrate it.
- **Spark standalone has no authentication of its own.** `spark.authenticate`
  defaults to `false`; the master's only RPC protection is the shared secret
  `spark.authenticate.secret`, and the UIs have none unless `spark.ui.filters`
  is set. `spark.ui.killEnabled` defaults to `true`.
- **The Spark REST server on 6066 never checks the shared secret.**
  `spark.master.rest.enabled` was `true` in 1.3-2.3, `false` from 2.4.0 through
  4.0.x, and **`true` again from 4.1.0** (SPARK-51165). Since 3.0 the master
  refuses to start with both REST and the secret configured; from 4.0.0 the only
  REST authentication is `spark.master.rest.filters=org.apache.spark.ui.JWSFilter`.
  So a 6066 that answers on Spark 4.1+ is the new default, and on 2.4-4.0 it was
  switched on deliberately.

## Stage B, named so you recognise it

Everything below changes cluster state or runs code. Each needs written sign-off
naming host, action and blast radius, and the realistic answer is "report from
the Stage A read instead":

| Action | Blast radius |
|---|---|
| YARN `new-application`, application submission, app kill or move, scheduler-conf change, node resource change, container signal, delegation-token calls, the UI kill button | Allocates or runs real work on production nodes; kills someone's job; changes queues for every tenant |
| NodeManager auxiliary-service changes | Requires admin plus a non-default manifest setting; restarts services |
| WebHDFS `CREATE`, `MKDIRS`, `RENAME`, `DELETE`, `SETPERMISSION`, `SETOWNER`, `CREATESYMLINK`, and any `OPEN` of a real file | Writes to or reads from production storage |
| Any request carrying `user.name=` or `doas=` | Impersonation |
| Spark REST create, kill, killall, clear; master UI app/driver kill; worker decommission | Starts a driver (code execution) or stops production jobs |
| Registering any application on 7077 | Code execution on executors |

`GET /v1/submissions/status/<id>` and (4.x) `/v1/submissions/readyz` on 6066 are
read-only, but a submission ID you did not create is someone else's job: do not
enumerate them.

## Version matrix

KEV: none of the Hadoop rows is in the CISA KEV catalog (feed 2026.10.13).
CVE-2022-33891 (Spark UI) **is** in KEV, added 2023-03-07, and is owned by
`hunt-exposed-panels`. Ranges are from the CVE Program records and the vendor
pages `hadoop.apache.org/cve_list.html` and `spark.apache.org/security.html`.

| Product | CVE | Class | Affected | Fixed | Pre-auth | KEV |
|---|---|---|---|---|---|---|
| Spark standalone master | CVE-2018-17190 (pre-2019) | The record that documents "no authentication by default": an unauthenticated master runs user code | all versions | none; enable authentication or firewall | Yes | No |
| Spark REST 6066 | CVE-2018-11770 (pre-2019) | REST server ignores the shared secret | 1.3.0-<2.4.0 | 2.4.0 (REST off by default; on again in 4.1.0) | NVD PR:L | No |
| Spark standalone master | CVE-2020-9480 | Authentication bypass with `spark.authenticate` on; leads to command execution | <= 2.4.5 | 2.4.6, 3.0.0 | Yes (9.8) | No |
| Spark RPC | CVE-2021-38296 | Key recovery in the custom auth/encryption protocol | <= 3.1.2 | 3.1.3 | Yes (7.5) | No |
| Spark RPC | CVE-2025-55039 | Unauthenticated AES-CTR mode allows bit-flipping, only with `network.crypto.enabled` | < 3.4.4, 3.5.0-<3.5.2 | 3.4.4, 3.5.2, 4.0.0 | Yes (ADP 6.5) | No |
| Spark UI | CVE-2022-33891 | ACL impersonation into shell command | <= 3.0.3, 3.1.1-3.1.2, 3.2.0-3.2.1 | 3.2.2, 3.3.0 | PR:L per NVD | **Yes, 2023-03-07** |
| Spark UI | CVE-2023-32007 | Re-scopes CVE-2022-33891 to include 3.1.3 | 3.1.1-<3.2.2 | supported release | PR:L | No |
| Spark submit | CVE-2023-22946 | Proxy-user privilege escalation via a config class | < 3.4.0 | 3.4.0 | No | No |
| Hadoop web | CVE-2018-11765 (pre-2019 ID, announced 2020) | With Kerberos on but SPNEGO off, some servlets answer unauthenticated | 2.8.0-2.8.5, 2.9.0-2.9.2, 3.0.0-alpha2-3.0.0 | 2.10.0, 3.0.1 | Yes (7.5) | No |
| Hadoop web | CVE-2018-11764 (pre-2019 ID, announced 2020) | Broken web auth check: authenticated user impersonates anyone | 3.0.0-alpha4, -beta1, 3.0.0 | 3.0.1 | No | No |
| Hadoop FileUtil | CVE-2022-25168 | Command injection through a file name during untar | 2.0.0-2.10.1, 3.0.0-alpha-3.2.3, 3.3.0-3.3.2 | 2.10.2, 3.2.4, 3.3.3 | NVD PR:N; reached via job localization | No |
| Hadoop FileUtil | CVE-2022-26612 | Arbitrary file write via symlink in a tar (Windows only) | < 3.2.3, 3.3.1-3.3.2 | 3.2.3, 3.3.3 | NVD PR:N | No |
| YARN | CVE-2021-33036 | `yarn` user to root (local) | 2.2.0-2.10.1, 3.0.0-alpha1-3.1.4, 3.2.0-3.2.2, 3.3.0-3.3.1 | 2.10.2, 3.2.3, 3.3.2 | No | No |
| YARN | CVE-2021-25642 | Deserialization of data read from ZooKeeper (needs ZK write) | 2.9.0-2.10.1, 3.0.0-alpha1-3.1.4, 3.2.0-3.2.3, 3.3.0-3.3.3 | 2.10.2, 3.2.4, 3.3.4 | No | No |
| YARN | CVE-2023-26031 | Relative RPATH in `container-executor` to root | 3.3.1-3.3.4 | 3.3.5 | NVD AV:N/PR:L: reached by a job submitter, which on simple auth is anyone | No |
| YARN | CVE-2018-8029 (pre-2019 ID) | `yarn` user to root | 2.2.0-2.8.4, 2.9.0-2.9.1, 3.0.0-alpha1-3.1.0 | 2.8.5, 2.9.2, 3.1.1 | No | No |
| WebHDFS client | CVE-2020-9492 | Client sends SPNEGO to an unverified URL (client side) | 2.0.0-alpha-2.10.0, 3.0.0-alpha1-3.1.3, 3.2.0-3.2.1 | 2.10.1, 3.1.4, 3.2.2 | No | No |
| libhdfs, HDFS native client | CVE-2021-37404, CVE-2025-27821 | Client-library memory corruption | see vendor page | 2.10.2/3.2.3/3.3.2; 3.4.2 | Client side, not a daemon | No |

`hunt-exposed-services` lists CVE-2023-26031 as a local escalation; the NVD vector
is network/low-privilege because a job submitter reaches it. Both readings agree
that it is Stage B to exercise and that the open submission endpoint is the
finding. No 2019-2026 Hadoop CVE is a pre-auth RCE in a daemon; the exposure is
the default configuration. The Hadoop project states no ASF Hadoop release was
vulnerable to Log4Shell (CVE-2021-44228).

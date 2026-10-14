# Streaming platforms and Java message brokers

Apache Kafka brokers, Kafka Connect, Confluent Schema Registry, Apache
ZooKeeper, Apache Pulsar, ActiveMQ Classic and ActiveMQ Artemis (renamed
**Apache Artemis** from 2.50.0). Generic AMQP 0-9-1, RabbitMQ, MQTT, NATS, IBM MQ
and EPMD stay with `hunt-exposed-services` (`references/message-brokers.md`).
ActiveMQ also listens on AMQP 5672 and MQTT 1883: when the fingerprint says
ActiveMQ, this file owns the host; when it says RabbitMQ or Mosquitto, that one
does.

The broker rules from `message-brokers.md` apply unchanged and are not repeated
at length: **never publish**, never hold a subscription open, names and counts
are the impact, message bodies are not retained.

Rate posture: serial, 2 s base delay plus 0-3 s jitter.

---

## Kafka brokers (9092; 9093 is the KRaft CONTROLLER listener in the shipped 4.x config)

```bash
TARGET="192.0.2.60"
# Cluster metadata: brokers (id, advertised host:port, rack), cluster ID,
# controller, topic names, partitions, leaders, ISR. No -t: see the trap below.
kcat -b "$TARGET:9092" -L -m 15 | head -60
```

- No authentication and no authorisation by default: `authorizer.class.name`
  is empty, so every client may do everything, including `AlterConfigs`.
- `ApiVersions` is answered before any SASL exchange; it "may leak information
  about the broker version". There is no version string: the release is inferred
  from the max-version table. A SASL listener answers a bogus mechanism with the
  list of supported mechanisms, which tells you whether OAUTHBEARER is enabled
  (CVE-2026-33557).
- Advertised listeners usually carry internal hostnames or RFC 1918 addresses.
  That is an information leak in its own right, and the reason follow-up tools
  "time out" after a successful metadata call.

Traps that turn a read into a write:

- **Topic auto-creation.** `auto.create.topics.enable` defaults to `true`, and a
  Metadata request that names a topic may create it. `kcat -L` with `-t` uses a
  producer handle with auto-creation allowed. Never pass `-t`; never request
  metadata for a topic you guessed.
- **Consumer groups.** Any consumer with a real `group.id` joins that group,
  triggers a rebalance that takes partitions away from live consumers, and leaves
  committed offsets. Never pass `-G`, never reuse a group name you saw.
- **Reading messages at all** is Stage B: it is third-party data in transit.
  Topic names establish the data class, as MQTT topic names do.

## Kafka Connect REST (8083)

```bash
curl -s -m 10 "http://$TARGET:8083/"                    # {"version","commit","kafka_cluster_id"}
curl -s -m 10 "http://$TARGET:8083/connectors"          # connector names
curl -s -m 10 "http://$TARGET:8083/connectors?expand=status" | head -c 800   # states, no config
curl -s -m 10 "http://$TARGET:8083/connector-plugins" | head -c 800          # installed plugin classes
```

- No authentication by default; authentication exists only through a REST
  extension (`rest.extension.classes`, default empty). Admin endpoints share the
  main listener unless `admin.listeners` is set.
- `connector.client.config.override.policy` was `None` in 2.8.0 and **`All`
  from 3.0.0**, still `All` in 4.x. The JAAS login-module deny-list property
  `org.apache.kafka.disallowed.login.modules` does not exist before 3.4.0,
  blocks `JndiLoginModule` from 3.4.0, and adds `LdapLoginModule` from 3.9.1
  and 4.0.0. Those three facts decide whether the Connect CVEs below apply.
- Do **not** fetch `/connectors/<name>/config`: it returns connector
  configuration including plaintext credentials. Its reachability is proven by
  the names listing.
- An open Connect REST API is code execution by design (creating a connector
  runs plugin code with attacker-chosen configuration). Report it from the
  `GET /` and names reads.

Stage B: creating, updating, pausing, restarting or deleting a connector; changing
`/admin/loggers`; and `PUT /connector-plugins/<type>/config/validate`, which looks
like a dry run but instantiates the connector and calls its `validate()`.

## Confluent Schema Registry (8081)

```bash
curl -s -m 10 -i "http://$TARGET:8081/" | head -12       # {} + application/vnd.schemaregistry.v1+json
curl -s -m 10 "http://$TARGET:8081/v1/metadata/version"  # {"version","commitId"} on CP 7.2.0+
curl -s -m 10 "http://$TARGET:8081/subjects" | head -c 600
curl -s -m 10 "http://$TARGET:8081/config"               # global compatibility level
```

`authentication.method` defaults to `NONE`. Subject names map topic names and
data classes. Stage B: registering a schema, changing `/config` (a compatibility
change can break every producer), `/mode`, and any `DELETE`. No Schema Registry
CVE ID was confirmed; Confluent advisories CONFSA-2026-11 and CONFSA-2026-15
(request-body and schema-reference DoS) are reported fixed in 8.2.2 and 8.2.3
(verify: the advisory pages were not readable).

## ZooKeeper (2181; AdminServer 8080)

```bash
# srvr: always enabled on 3.5.3+. Returns "Zookeeper version: x.y.z-<sha>, built on ...",
# latency, mode (leader/follower/standalone) and node count.
echo srvr | timeout 10 nc -w 5 "$TARGET" 2181
# AdminServer (3.5.0+, on by default on 0.0.0.0:8080): command list and srvr as JSON.
curl -s -m 10 "http://$TARGET:8080/commands" | head -c 600
curl -s -m 10 "http://$TARGET:8080/commands/srvr"
```

Four-letter-word defaults, from source:

| Version | Enabled when `4lw.commands.whitelist` is unset |
|---|---|
| before 3.4.10 | every word |
| 3.4.10-3.4.14 | every word except `wchc` and `wchp` (the 3.4.14 admin guide says "srvr only"; the code disagrees) |
| 3.5.3 and later | `srvr` only (plus `isro` in read-only mode) |

- A disabled word answers "... is not executed because it is not in the
  whitelist". One extra read-only word (`conf`) is enough to show the whitelist
  was widened; do not walk the list.
- `nmap -sV` sends `stats\r\n`, which ZooKeeper reads as `stat` and, where
  enabled, answers with every connected client's address. Expect that line in
  `-sV` output on older servers and redact client IPs from evidence.
- Never send `crst`, `srst` or `stmk` (they reset or change state) or the
  expensive `wchc`, `wchp`, `dump`, `cons`.
- The AdminServer does not consult the 4lw whitelist (verify per release), so
  `/commands/<word>` can expose what 2181 refuses. Read `/commands` and `srvr`
  only; `snapshot` and `restore` (3.9, enabled by default, `Perms.ALL` on `/`)
  stream or replace the whole tree and are forbidden.
- The root znode's ACL is `world:anyone` with all permissions unless changed,
  and ACLs are not recursive. One `ls /` (names only) shows which systems keep
  state here (`brokers`, `hbase`, `hadoop-ha`, `yarn-leader-election`). Never
  `get` a znode, and never create, set, delete or change an ACL.

## Apache Pulsar (binary 6650/6651, admin HTTP 8080/8443)

```bash
curl -s -m 10 "http://$TARGET:8080/admin/v2/brokers/version"   # plain-text version; 401 if auth on
curl -s -m 10 "http://$TARGET:8080/admin/v2/clusters"
curl -s -m 10 "http://$TARGET:8080/admin/v2/tenants"
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8080/metrics"
```

- `broker.conf` and `standalone.conf` ship `authenticationEnabled=false`,
  `authorizationEnabled=false`, `bindAddress=0.0.0.0`, `allowAutoTopicCreation=true`;
  standalone mode also starts the Functions worker. The docs: "By default,
  Pulsar configures no encryption, authentication, or authorization."
- `/metrics` stays open even with authentication on
  (`authenticateMetricsEndpoint=false`), so a `200` there proves only the product.
  The admin endpoints decide.
- Pulsar Manager (9527 UI, 7750 backend) is unmaintained and ships a hardcoded
  `jwt.secret` in `application.properties` (verify what it signs). Report its
  exposure; never create its superuser.

Stage B: any tenant, namespace or topic creation; **any producer or consumer
connection** (with auto-creation on it creates the topic; a new subscription is
a durable cursor that accumulates backlog until deleted); Functions, sources and
sinks (`/admin/v3/...`), which are code execution by design. If message content
is ever signed off, `examinemessage` on an existing topic reads without creating
a subscription.

## ActiveMQ Classic (OpenWire 61616, console 8161, STOMP 61613, AMQP 5672, MQTT 1883, WS 61614)

```bash
# OpenWire: the broker speaks first. Connect, read, close. The WireFormatInfo
# carries ProviderName=ActiveMQ and ProviderVersion (5.14.0 and later).
timeout 8 nc -w 5 "$TARGET" 61616 < /dev/null | head -c 600 | strings
# STOMP CONNECT with no credential: CONNECTED carries server:ActiveMQ/<version>;
# an ERROR frame means authentication is on. The empty line plus NUL ends the frame.
printf 'CONNECT\naccept-version:1.2\nhost:probe\n\n\0' | timeout 8 nc -w 5 "$TARGET" 61613 | head -5
# Console: 401 with realm="ActiveMQRealm" is the expected posture.
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8161/admin/"
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8161/api/jolokia/version"
```

Posture by version:

- Transports have **no authentication** unless a JAAS or simple authentication
  plugin is configured; the shipped `activemq.xml` has none.
- Console credentials ship as `admin`/`admin` (5.x `jetty-realm.properties`,
  6.x `users.properties`). The console binds `0.0.0.0` through 5.15.x and
  `127.0.0.1` from 5.16.0 through 6.2.x; 6.3.x moved Jetty config and allows
  only loopback through an access handler, so an external `403` is plausible
  (verify). Docker images commonly override all of this.
- `/api` (Jolokia and the REST message API) was **unauthenticated by default in
  6.0.0-6.1.1** (CVE-2024-32114). A `200` from `/api/jolokia/version` with no
  credential is that finding, read-only. Note that `/api/jolokia/version`
  returns the Jolokia agent version; the broker version is the `BrokerVersion`
  attribute, which needs a Jolokia `read`.
- 6.3.0 and later enable only the OpenWire connector; closed STOMP, AMQP, MQTT
  and WS ports are normal there.

Stage B: the single `admin`/`admin` console attempt; every Jolokia `exec`
(connector, queue and network-connector operations are the code paths behind
CVE-2026-34197 and its bypasses); the REST message API, where `GET` **consumes**
a message; sending to or creating any destination. A JMS QueueBrowser or the
console's browse view does not remove messages, but on unpatched brokers browsing
can render stored script in your own session (CVE-2026-41043).

## ActiveMQ Artemis / Apache Artemis (61616 multi-protocol, 61613, 8161, 5445)

```bash
# Artemis waits for the client on 61616 (Classic speaks first): silence after
# connect is itself a hint (verify). STOMP 1.1/1.2 CONNECT returns
# server:ActiveMQ-Artemis/<version> unless disableStompServerHeader is set.
printf 'CONNECT\naccept-version:1.1,1.2\nhost:probe\n\n\0' | timeout 8 nc -w 5 "$TARGET" 61616 | head -5
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:8161/console/"
```

- `artemis create` prompts for the user and for `--allow-anonymous` or
  `--require-login`; the console binds `localhost` by default and Jolokia
  enforces an `Origin` check unless `--relax-jolokia` was used.
- The project Dockerfile (2.57.0) sets `artemis`/`artemis`,
  `--http-host 0.0.0.0` and `--relax-jolokia`. An exposed console on a container
  host is usually that image. One `artemis`/`artemis` attempt is Stage B.
- Addresses and queues are auto-created by default: any producer or consumer
  connection is Stage B, as on Pulsar.

---

## Version matrix

KEV from the CISA feed, catalog 2026.10.13. Ranges from the CVE Program records
and the Kafka, ZooKeeper, Pulsar and ActiveMQ advisory pages. Rows marked
**DoS-class** are banner-gated only and never tested.

### KEV-listed

| Product | CVE | Class | Affected | Fixed | Pre-auth | KEV |
|---|---|---|---|---|---|---|
| ActiveMQ Classic | CVE-2023-46604 | OpenWire class instantiation leads to RCE | < 5.15.16, 5.16.0-<5.16.7, 5.17.0-<5.17.6, 5.18.0-<5.18.3 (client and legacy OpenWire module from 5.8.0) | 5.15.16, 5.16.7, 5.17.6, 5.18.3 | Yes (CNA 10.0) | **Yes, 2023-11-02; known ransomware use** |
| ActiveMQ Classic | CVE-2026-34197 | Jolokia connector operations load remote broker configuration: RCE | < 5.19.4, 6.0.0-<6.2.3 | 5.19.4, 6.2.3 (bypasses fixed through 5.19.7 / 6.2.6) | PR:L; on 6.0.0-6.1.1 `/api` had no auth (CVE-2024-32114), so possibly none (verify) | **Yes, 2026-04-16** |
| ActiveMQ Classic | CVE-2016-3088 (pre-2019) | Fileserver web app PUT then MOVE: file write to RCE | 5.x < 5.14.0 | 5.14.0 | Yes | **Yes, 2022-02-10** |

The OpenWire `ProviderVersion` (5.14.0+) or the STOMP `server:` header decides
CVE-2023-46604 from a passive read. Artemis is **not** listed as affected by
CVE-2023-46604.

### Others

| Product | CVE | Class | Affected | Fixed | Pre-auth | KEV |
|---|---|---|---|---|---|---|
| Kafka broker | CVE-2026-33557 | Default OAUTHBEARER JWT validator accepts any token | 4.1.0-4.1.1 | 4.1.2, 4.2.0 | Yes (9.1) | No |
| Kafka broker | CVE-2022-34917 | Unauthenticated memory allocation, OOM before SASL | 2.8.0-2.8.1, 3.0.0-3.0.1, 3.1.0-3.1.1, 3.2.0-3.2.1 | 2.8.2, 3.0.2, 3.1.2, 3.2.3 | Yes, **DoS-class** | No |
| Kafka (snappy-java) | CVE-2023-34455 | Compressed produce request exhausts memory | Kafka 0.8.0-3.5.0 | 3.5.1 | Yes, **DoS-class** | No |
| Kafka broker | CVE-2025-27819 | JNDI login module via `AlterConfigs`: RCE or DoS | 2.0.0-3.3.2 | 3.4.0 blocks by default; 3.9.1, 4.0.0 | Needs `AlterConfigs`, which every client has with no authorizer | No |
| Kafka broker / Connect | CVE-2025-27818 | LDAP login module in JAAS config: deserialization RCE | 2.3.0-3.9.0 | 3.9.1, 4.0.0 | PR:L; nobody needs to log in to a default Connect REST | No |
| Kafka Connect | CVE-2023-25194 | JNDI login module via client override config: RCE | 2.3.0-3.3.2 | 3.4.0 | PR:L; open by default on 3.0-3.3 | No |
| Kafka clients / Connect | CVE-2025-27817 | `sasl.oauthbearer.*.url` reads files or fetches URLs (SSRF) | 3.1.0-3.9.0 | 3.9.1, 4.0.0 plus `allowed.urls` | Yes via an open Connect REST | No |
| Kafka clients / Connect | CVE-2024-31141 | Config providers read files and environment variables | 2.3.0-3.5.2, 3.6.0-3.6.2, 3.7.0 | 3.8.0 plus `automatic.config.providers=none` | PR:L; open on default Connect | No |
| Kafka Connect | CVE-2019-12399 | Tasks endpoint shows externalized secrets in plaintext | 2.0.0-2.3.0 | 2.2.2, 2.3.1 | Open by default | No |
| Kafka broker | CVE-2024-56128 | SCRAM nonce not checked (replay), only SCRAM without TLS | 0.10.2.0-3.7.1, 3.8.0 | 3.7.2, 3.8.1, 3.9.0 | Yes (5.3) | No |
| ZooKeeper | CVE-2026-79993 | Unauthenticated client can delete empty persistent, container or TTL znodes | 3.8.0-3.8.6, 3.9.0-3.9.5 | 3.8.7, 3.9.6 | Yes (7.5). Never test | No |
| ZooKeeper | CVE-2026-59739 | Watch replay leaks ACL-restricted paths | 3.8.0-3.8.6, 3.9.0-3.9.5 | 3.8.7, 3.9.6 | Yes | No |
| ZooKeeper | CVE-2024-51504 | AdminServer IP auth trusts `X-Forwarded-For`, opening snapshot/restore | 3.9.0-<3.9.3 | 3.9.3 | Yes (9.1) | No |
| ZooKeeper | CVE-2025-58457 | AdminServer snapshot/restore permission check too weak | 3.9.0-<3.9.4 | 3.9.4 | PR:L | No |
| ZooKeeper | CVE-2024-23944 | Persistent watcher leaks child znode paths | 3.6.0-3.7.2, 3.8.0-3.8.3, 3.9.0-3.9.1 | 3.8.4, 3.9.2 | Network reachable despite the AV:L score | No |
| ZooKeeper | CVE-2023-44981 | SASL quorum authorization bypass (2888/3888), only with `quorum.auth.enableSasl=true` | < 3.7.2, 3.8.0-3.8.2, 3.9.0 | 3.7.2, 3.8.3, 3.9.1 | Yes (9.1) | No |
| ZooKeeper | CVE-2019-0201 | Unauthenticated `getACL` discloses digest password hashes | 1.0.0-3.4.13, 3.5.0-alpha-3.5.4-beta | 3.4.14, 3.5.5 | Yes (NVD 5.9) | No |
| Pulsar proxy | CVE-2022-34321 | `/proxy-stats` unauthenticated | 2.6.0-<2.10.6, 2.11.0-<2.11.3, 3.0.0-<3.0.2, 3.1.0-<3.1.1 | 2.10.6, 2.11.3, 3.0.2, 3.1.1 | Yes (8.2) | No |
| Pulsar | CVE-2023-51437 | SASL role-token forgery via timing | <= 2.10.5, 2.11.0-2.11.2, 3.0.0-3.0.1, 3.1.0 | 2.11.3, 3.0.2, 3.1.1 | Yes (AC:H) | No |
| Pulsar WebSocket proxy | CVE-2023-37544 | Unauthenticated `/pingpong` DoS | 2.8.x-2.9.x, 2.10.0-2.10.4, 2.11.0-2.11.1, 3.0.0 | 2.10.5, 2.11.2, 3.0.1 | Yes, **DoS-class** | No |
| Pulsar | CVE-2021-22160 | JWT `alg:none` accepted | < 2.7.1 | 2.7.1 | Yes | No |
| Pulsar Functions | CVE-2024-27135, CVE-2024-27317, CVE-2024-27894 | Worker: code outside the sandbox, zip-slip on upload, `file://` read and SSRF | 2.4.0-<2.10.6, 2.11.0-<2.11.4, 3.0.0-<3.0.3, 3.1.0-<3.1.3, 3.2.0 | 2.10.6, 2.11.4, 3.0.3, 3.1.3, 3.2.1 | PR:L; nobody when auth is off | No |
| ActiveMQ Classic | CVE-2024-32114 | `/api` (Jolokia, REST) unauthenticated by default | 6.0.0-6.1.1 | 6.1.2 | Yes | No |
| ActiveMQ Classic | CVE-2022-41678 | Jolokia JFR MBean to RCE (authenticated) | < 5.16.6, 5.17.0-<5.17.4 | 5.16.6, 5.17.4, 5.18.0, 6.0.0 | No | No |
| ActiveMQ Classic | CVE-2021-26117 | LDAP login module: anonymous bind accepted, password not checked (also Artemis < 2.16.0) | < 5.16.1 (5.15.14 fixed) | 5.15.14, 5.16.1 | Yes, config-dependent | No |
| ActiveMQ Classic | CVE-2026-49270 | Pre-auth BrokerInfo returns durable subscriptions (needs a `syncDurableSubs` network connector) | 5.14.0-<5.19.7, 6.0.0-<6.2.6 | 5.19.7, 6.2.6 | Yes (AC:H) | No |
| ActiveMQ Classic | CVE-2026-39304, CVE-2026-50734, CVE-2026-49432, CVE-2026-53916, CVE-2026-50750, CVE-2026-59878 | Pre-auth memory exhaustion (TLS KeyUpdate, WireFormatInfo size, STOMP headers, BrokerInfo flood, AMQP frame size) | up to 5.19.8 / 6.2.7 depending on the ID | 5.19.4-5.19.9 / 6.2.4-6.2.8 (current floor 5.19.11, 6.3.2) | Yes, **DoS-class** | No |
| Artemis | CVE-2026-27446 | Core protocol forces outbound federation to a rogue broker | ActiveMQ Artemis 2.11.0-2.44.0, Apache Artemis 2.50.0-2.51.0 | Apache Artemis 2.52.0 | Yes (CNA 9.3) | No |
| Artemis | CVE-2026-57967, CVE-2026-67593, CVE-2026-49362, CVE-2026-49363, CVE-2026-49364 | Pre-auth Core session hijack, queue deletion and creation, topology and cluster-credential disclosure | all ActiveMQ Artemis through 2.44.0 and Apache Artemis 2.50.0-2.56.0 | **Apache Artemis 2.57.0 only**; no fix on the ActiveMQ Artemis line | Yes | No |
| Artemis | CVE-2023-50780 | Jolokia Log4j2 MBean file write to RCE | < 2.29.0 | 2.29.0 | PR:L | No |

Three reading rules:

- **An ActiveMQ Artemis banner (any 2.x up to 2.44.0) is unpatchable in place**
  for the 2026 Core-protocol CVEs: the fix exists only after the rename. Say so.
- **"PR:L" on Connect and Pulsar Functions is pre-auth in the default
  deployment**, because neither ships authentication on. Grade on what the
  deployment requires, and name the configuration that makes it so.
- ZooKeeper's 2025-2026 records list only the 3.8 and 3.9 lines; end-of-life
  3.7 and older were not assessed. Treat them as unknown, not clean.

Fetched but not server exposure, so not reported from a banner: CVE-2025-29953
and CVE-2025-54539 (NMS .NET clients), CVE-2024-47561 (Apache Avro, picked up by
Pulsar 3.0.7 and 3.3.2), CVE-2022-33681 to CVE-2022-33684 (Pulsar client TLS),
CVE-2026-35554 (Java producer race), and the log4j 1.x entries on Kafka's list.

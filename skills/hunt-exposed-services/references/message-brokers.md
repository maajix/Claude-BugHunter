# Exposed message brokers and queues

A broker is a worse exposure than it first looks. It is not one application's
data: it is the live traffic between every application that uses it. An
anonymous subscribe on a wildcard topic can yield session tokens, order events,
PII, telemetry and device commands from systems you were never scoped to see.

That cuts the other way too. **Never publish.** On an IoT or building broker a
published message is a command, and a command moves something physical. On a
business broker a published message is a transaction that downstream consumers
will process as real.

| Port | Service | Default posture |
|---|---|---|
| 5672, 5671 (TLS) | AMQP 0-9-1 / 1.0 | Credentials required, but the broker announces its mechanisms and version before authentication. |
| 15672, 15671 (TLS) | RabbitMQ management plugin (HTTP API and UI) | The `guest`/`guest` account exists by default. Since RabbitMQ **3.3.0** it can only connect over loopback, so `guest` working from the internet means an administrator set `loopback_users` to allow it. That is a finding in itself. |
| 1883 | MQTT, cleartext | The protocol has optional username/password and no transport security. Mosquitto 2.0 changed the shipped defaults: with no configuration file it binds only to `127.0.0.1` and `::1`, and `allow_anonymous` now defaults to `false`. A `listener 1883` set in a configuration file still binds to `0.0.0.0` by default, so a publicly reachable *anonymous* broker means someone added `allow_anonymous true` on top of that listener. |
| 8883 | MQTT over TLS | Same authentication posture, encrypted transport. Credentials may still be anonymous. |
| 4222 | NATS, client port | The server sends an `INFO` JSON document to every client immediately on connect, before any authentication, including whether authentication is required. |
| 8222 | NATS monitoring HTTP | Read-only JSON endpoints listing every connection, account and subject in use. The monitoring port is **off until someone turns it on** (`http_port: 8222` in the config, or `-m 8222`), and 8222 is only the conventional choice, so a reachable monitoring port is always a deliberate act. |
| 6222 | NATS cluster routes | Cluster-internal; exposure means the cluster mesh is reachable. |
| 1414 | IBM MQ | Channel-based. The queue manager and channel names are the enumeration target; many deployments still run a channel with no security exit. |
| 4369 | Erlang port mapper daemon (`epmd`) | `epmd` itself requires no authentication and advertises the Erlang distribution ports of every node registered on the host. Access to the distribution port plus the node's cookie is full control of the Erlang VM, which is why `epmd` exposure matters for RabbitMQ, CouchDB, Riak and Elixir applications alike. |

## Stage A probes

### AMQP and RabbitMQ

```bash
TARGET="192.0.2.30"

# AMQP: the protocol header exchange returns the broker's version and the
# SASL mechanisms it offers, with no credential.
printf 'AMQP\x00\x00\x09\x01' | timeout 10 nc -w 5 "$TARGET" 5672 | head -c 512 | strings

# RabbitMQ management API: these are the two requests that settle it.
curl -s -m 10 -o /dev/null -w '%{http_code}\n' "http://$TARGET:15672/api/overview"
curl -s -m 10 -u guest:guest "http://$TARGET:15672/api/whoami"
curl -s -m 10 -u guest:guest "http://$TARGET:15672/api/overview" \
  | head -c 600                      # version, erlang version, cluster name
```

- `401` on `/api/overview` without credentials is the correct, non-finding
  behaviour. Record it and move on.
- A `200` with no credentials, or `guest:guest` succeeding from an external
  address, is the finding. Follow it with `/api/vhosts` and `/api/queues` to
  record vhost names, queue names and message counts. **Stop there.** Do not
  read messages: the HTTP API's message-get is a destructive read by default
  because it can acknowledge and remove the message from the queue.
- Testing `guest:guest` is one documented default credential, which this skill
  permits once per service. Anything beyond it is `hunt-brute-force`.

### MQTT

```bash
# Subscribe read-only, with BOTH a message cap and a time cap, so the probe
# cannot sit on the broker indefinitely or accumulate third-party data.
timeout 20 mosquitto_sub -h "$TARGET" -p 1883 -t '$SYS/#' -C 20 -W 15 -v

# If $SYS is unavailable, the wildcard proves anonymous subscribe just as well.
timeout 20 mosquitto_sub -h "$TARGET" -p 1883 -t '#' -C 10 -W 15 -v
```

The `$SYS/#` tree is the right first choice: on Mosquitto it returns broker
version, uptime, client counts and message counters, which is a complete impact
statement without touching anyone's application data.

Both caps are documented and you want both. `-C` disconnects and exits "after
the given count of messages have been received". `-W` provides "a timeout as an
integer number of seconds", after which the client stops processing messages and
disconnects, timed from just after connect. `-C` alone hangs on a quiet broker;
`-W` alone keeps reading a busy one.

Two flags to stay away from: `-c` / `--disable-clean-session` (clean session is
**on** by default in `mosquitto_sub`, and turning it off leaves your
subscriptions registered on the broker), and `--remove-retained`, which sends
messages to the broker to clear retained messages and is destructive.

**Do not use nmap's `mqtt-subscribe` as a Stage A probe.** It is tagged `safe`,
but its CONNECT never sets clean-session, so the broker retains the session and
your `$SYS/#` and `#` subscriptions after you disconnect. That is persistent
state left on a client's production broker. Its one redeeming detail is that it
randomises the client ID, so it will not collide with a device.

On the `#` wildcard, read the **topic names** and stop. Topic hierarchies are
usually self-describing (`building/floor3/hvac/setpoint`,
`fleet/<vehicle>/location`), and the names alone establish the data class and
whether the broker carries control traffic. If messages arrive containing
personal data, note the fact, retain nothing, and say so in the evidence.

**Never** `mosquitto_pub`. Never subscribe without both caps. Never hold a
subscription open across the engagement to "see what comes in": that is bulk
collection of a third party's data.

Two broker-specific hazards worth knowing because they are easy to trigger by
accident:

- MQTT identifies clients by `ClientId`, and the specification *requires* the
  broker to evict the incumbent: `[MQTT-3.1.4-3]` says that if the ClientID
  represents a client already connected, the server sends that client a
  DISCONNECT with reason code `0x8E` ("Session taken over") and must close its
  network connection. So guessing a device-like client ID does not risk a
  collision, it causes one. Use a unique random `ClientId` for every probe and
  never pass `-i` with a plausible device name.
- A subscription with clean-session false creates persistent state on the
  broker. Always use a clean session, which is `mosquitto_sub`'s default.

### NATS

```bash
# The server volunteers INFO before anything else; auth_required tells you the
# answer immediately.
timeout 10 nc -w 5 "$TARGET" 4222 < /dev/null | head -c 1024

# Monitoring port: read-only JSON, no authentication by default when exposed.
curl -s -m 10 "http://$TARGET:8222/varz"     | head -c 800
curl -s -m 10 "http://$TARGET:8222/connz"    | head -c 800
curl -s -m 10 "http://$TARGET:8222/subsz"    | head -c 800
```

`"auth_required": false` in the `INFO` document, from an external address, is
the finding on its own: no further connection needed. `/varz` gives the version
and configuration, `/connz` the active clients, `/subsz` the subject space.
Subject names establish the data class the same way MQTT topics do.

**Never** publish, and never create a JetStream consumer: a consumer is
persistent server-side state and, depending on its configuration, consuming
removes messages other systems were waiting for. The KB's credential-capture
and JetStream-looting techniques are post-access activity and are out of scope
for this bundle.

### IBM MQ and `epmd`

```bash
# IBM MQ: identify the listener. Channel and queue-manager enumeration beyond
# the listener response is credential-adjacent; treat it as Stage B.
timeout 10 nc -w 5 "$TARGET" 1414 < /dev/null | head -c 256 | strings

# epmd: the NAMES request returns every registered Erlang node and its
# distribution port. The `epmd` CLI has NO remote-host flag at all: `-names`
# lists names on the *currently running* local epmd, and `-port` only chooses
# which port to contact. The protocol does accept name listing from remote
# nodes, so use the safe NSE script (`default`, `discovery`, `safe`) or
# erl_epmd:names(Host) from OTP 21.0 onwards.
nmap -Pn -p 4369 --script epmd-info --scan-delay 1s "$TARGET"
# Never run `epmd -kill` or `epmd -stop <Name>`: both are destructive.
```

An `epmd` NAMES reply listing node names and distribution ports is a High
finding, and Critical if the application is one that historically shipped a
default cookie. Record the node names and ports.

While you are looking at an Erlang host, check whether it also runs Erlang's own
SSH daemon rather than OpenSSH: **CVE-2025-32433** is an unauthenticated
remote-code-execution flaw in Erlang/OTP's SSH server, CVSS 10.0, affecting OTP
below 25.3.2.20, 26.0 up to below 26.2.5.11, and 27.0 up to below 27.3.3, and it
also shipped inside a long list of network products. Detect by version. It is a
separate finding from the `epmd` exposure, not an escalation of it. **Do not** connect to a
distribution port or attempt a cookie: a successful Erlang distribution
handshake is remote code execution in the VM, which is Stage B and almost never
necessary once you have proved the port answers.

## Pre-auth CVE notes

| CVE | Product and range | Class | Reachable pre-auth? |
|---|---|---|---|
| CVE-2022-24706 | Apache CouchDB <= 3.2.1 | Default Erlang cookie `monster` grants access to the Erlang VM via `epmd` and the distribution port | YES, PR:N, CVSS 9.8. The clearest illustration of why an exposed `epmd` matters. Full detail in `databases.md`. |
| CVE-2024-51988 | RabbitMQ server OSS >= 3.12.7 and < 3.12.11; Tanzu >= 2.0.0 and < 3.13.0, and < 1.5.2. Fixed in 3.12.11, 1.5.2, 3.13.0 and 4.0.0. | HTTP API queue deletion skips the configure permission check | NO. Rated PR:L: valid credentials and HTTP API access required. Not an exposure finding. |
| CVE-2025-50200 | RabbitMQ server <= 3.13.7, patched in 4.0.8 | Basic-Auth header written to the log in base64 plaintext | NO. Vector AV:L with PR:H: it needs access to the logs. |

Neither RabbitMQ CVE is a pre-auth network path. On an exposed broker the
finding is the exposure, the `guest` account reachable from a non-loopback
address, or a real credential that works. Do not pad a report with the two CVEs
above.

## Checklist

- [ ] Broker identified from its own protocol reply (AMQP header exchange, MQTT
      CONNACK, NATS `INFO`), not from the port number.
- [ ] Unauthenticated access proven by a reply that an authenticating broker
      refuses (`401`, `auth_required: true`, CONNACK with a refusal code).
- [ ] At most one documented default credential tried, once.
- [ ] Every subscription had both a message cap and a time cap, a unique random
      `ClientId`, and a clean session.
- [ ] Nothing published, to any broker, on any topic or subject.
- [ ] No queue read that acknowledges or removes a message; no JetStream
      consumer created; no queue or exchange created or deleted.
- [ ] Impact evidenced by topic, subject, queue and vhost **names** plus counts.
      No message bodies retained.
- [ ] No connection made to an Erlang distribution port and no cookie attempted.
- [ ] Third-party personal data seen in transit was not retained, and the
      non-retention is documented.

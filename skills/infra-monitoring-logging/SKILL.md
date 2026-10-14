---
name: infra-monitoring-logging
description: "Triage internet-exposed monitoring, metrics, logging and tracing services and their agent and ingest protocols: Zabbix agent/agent 2 (10050) and trapper (10051), NRPE 5666, NSClient++ 8443/12489, Icinga 2 API 5665, Checkmk agent 6556, Prometheus exporters (node 9100, blackbox, snmp), Alertmanager 9093, Pushgateway 9091, Graphite 2003/2004, StatsD 8125/8126, Loki 3100, Jaeger 16686, OpenTelemetry Collector 4317/4318, Graylog 9000 and GELF 12201, Logstash 5044/9600, Fluentd 24224/24220, Fluent Bit 2020, Elastic APM 8200, Sentry self-hosted, Netdata API 19999, syslog and SNMP trap receivers, plus NMS consoles (PRTG, SolarWinds Orion and Web Help Desk, Nagios XI, Cacti, LibreNMS, Observium) with a KEV-tagged CVE matrix. The finding is what unauthenticated access leaks (internal hostnames and IPs, credentials in labels and configs, an agent that answers anyone) or a KEV version gate. Stage A only reads; writing metrics or logs, triggering checks and remote commands need Stage B sign-off."
sources: nvd, cisa_kev, cve_org, vendor_advisories, github_security_advisories, project_documentation, project_source_code, bugcrowd_vrt
report_count: 0
---

## When to use

Trigger when external recon has produced a monitoring, metrics, logging or
tracing service on a host you are authorized to test, and you need to decide
whether it is a finding. Monitoring systems are built to see everything and to be
trusted by every host, so an exposed one is a map of the estate and sometimes a
command channel into it. The finding here is **the exposure plus what it leaks
or grants**, not an exploit you wrote.

Use when any of these is true:

- A port from the routing table in Step 3 answers on a public address
  (10050/10051, 5666, 5665, 6556, 9100, 9093, 9091, 2003, 8126, 3100, 16686,
  4317/4318, 12201, 9600, 24224/24220, 2020, 8200, 19999, 514, 6514, 162).
- An HTTP service fingerprints as an NMS console (PRTG, SolarWinds Orion or Web
  Help Desk, Nagios XI, Cacti, LibreNMS, Observium, Icinga Web 2, Checkmk).
- A config, compose file or Helm chart in a leak (`hunt-source-leak`) names an
  agent, exporter or ingest endpoint with a public address.
- The client says "monitoring is internal only" and you can reach it anyway.

**Do not use this skill for discovery.** Host and port discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation to `recon-scope-triage`.
This skill starts from "a monitoring port answers and is in scope".

### Where the chain ends

This skill stops at **unauthenticated read proven, impact described, evidence
captured**. Nothing here writes into the client's monitoring, silences an alert,
runs a check, executes a command through an agent, or pivots through an exporter
toward internal addresses. If an agent answers you, the finding is complete.
Write it up and stop. Stage B (Step 6) allows one signed-off proof per finding.

### Not covered here, on purpose

- Zabbix frontend and API, Grafana UI, Prometheus server 9090 (status, config,
  targets, admin API) and the Netdata dashboard root: `hunt-exposed-panels`
  (`references/monitoring-and-dashboards.md`). This skill adds the agents,
  trappers, exporters and the KEV rows panels does not carry.
- Elasticsearch, Kibana, InfluxDB and splunkd 8089 with their CVEs:
  `hunt-exposed-services` (`references/databases.md`). SNMP get/walk on 161 and
  raw printing on 9100: `hunt-exposed-services`.
- SolarWinds Serv-U: `infra-ftp`. Kubernetes-internal Prometheus, kubelet and
  cAdvisor: `hunt-k8s`. TLS posture on any port: `hunt-tls-network`.
- Credential guessing of any kind: `hunt-brute-force`. This skill tries **one**
  shipped default, once, under Stage B.
- Exploiting SSRF found through blackbox or snmp exporters beyond one canary:
  `hunt-ssrf`. Sentry integration SSRF: `hunt-misc`. syslog-ng config injection:
  `hunt-rce`.

---

## Step 1: Inherit the host and port, never generate them

Take the host from the signed scope document and the port from recon. Confirm IP
ownership (ASN, WHOIS/RDAP, reverse DNS) before the first packet. Never sweep
ranges for agent ports; Shodan and Censys already index 10050, 9100 and 9093,
and looking there costs the target nothing (`offensive-osint`).

### Rate posture

You are probing the system that watches the client. Every request lands in the
logs, metrics and alert rules of the monitoring stack itself, and many stacks
alert on unknown sources hitting an agent or on scrape errors.

- Serial, one host at a time, 5-10 s between requests to the same host.
- Stage A budget: **15 requests per host per engagement day**, counting each
  TCP connection to an agent port as one.
- Bounded reads only: `head -c` on every HTTP body, `limit=` on every query API,
  no recursive tree walks, no wildcard renders, no profiling endpoints.
- One passive Zabbix key causes one real agent poll; a Checkmk connection runs
  the whole agent and is Stage B. Never loop either.
- A refusal or reset after earlier successes means an allow-list or IDS reacted.
  Stop; do not retry in a loop.

```bash
# 5s base delay + 0-5s jitter between requests to the same host.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 5+rand()*5}')"; }
```

---

## Step 2: Prove the exposure is real, external, the client's, and not a honeypot

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN, tunnel and office range; record the egress IP. | An agent reached over the client's VPN is not an exposure; agents are supposed to answer the monitoring network. |
| IP ownership | ASN + WHOIS/RDAP + reverse DNS, cross-checked with scope. | Cloud pools and managed monitoring vendors (hosted Grafana, Datadog, Sentry SaaS) answer for addresses that are not the client's. |
| Self-hosted vs SaaS | A vendor's multi-tenant ingest (sentry.io, Grafana Cloud, Elastic Cloud) is the vendor's surface, not the client's. | Report only what the client operates. |
| Data is the client's | Hostnames, labels and service names in the response must match the client's domains or naming. | Lab boxes, honeypots and demo stacks return `localhost`, `example`, default job names. |
| Honeypot tells | Identical body across many unrelated IPs, synthetic values (uptime of seconds on every visit, zero ARP entries, a `nodename` that does not resolve), a banner that disagrees with the host's other services. | A "Zabbix agent answers anyone" report against a honeypot is withdrawn. |
| Port collisions | 9000 (Graylog, Sentry, PHP-FPM, others), 9100 (node_exporter vs PJL printing), 8088 (Splunk HEC vs YARN), 514/tcp (syslog vs rsh), 3000/8080 generic. | Route by response, not by port number. |

Record raw output for every probe before Stage B, so later evidence has a baseline.

---

## Step 3: Route by port

| Port(s) | Product | Reference |
|---|---|---|
| 10050, 10051 | Zabbix agent / agent 2, server or proxy trapper | `agent-protocols.md` |
| 5666, 12489, 8443 | NRPE, NSClient++ (check_nt, web/REST) | `agent-protocols.md` |
| 5665 | Icinga 2 API and cluster | `agent-protocols.md` |
| 6556, 8000, 6555 | Checkmk agent, agent receiver, mknotifyd (verify port) | `agent-protocols.md` |
| 162/udp | SNMP trap receiver | `agent-protocols.md` |
| 9100, 9115, 9116 | node, blackbox, snmp exporters | `metrics-and-tracing.md` |
| 9093/9094, 9091 | Alertmanager, Pushgateway | `metrics-and-tracing.md` |
| 2003/2004/7002, 2013/2014, 8080 | Carbon receivers and cache, relay, graphite-web | `metrics-and-tracing.md` |
| 8125/udp, 8126 | StatsD, StatsD admin | `metrics-and-tracing.md` |
| 3100 | Loki | `metrics-and-tracing.md` |
| 16686, 14268, 14250, 9411, 5778 | Jaeger query/UI, collector, Zipkin, sampling | `metrics-and-tracing.md` |
| 4317, 4318, 55681, 13133, 55679, 8888, 1777 | OTLP receivers, Collector health, zpages, self-metrics, pprof | `metrics-and-tracing.md` |
| 19999 | Netdata API (dashboard root: panels) | `metrics-and-tracing.md` |
| 9000, 12201 | Graylog web/API, GELF inputs | `log-ingest.md` |
| 5044, 9600 | Logstash Beats input, monitoring API | `log-ingest.md` |
| 24224, 24220, 24230, 24444, 9880 | Fluentd forward, monitor agent, debug agent, RPC, http | `log-ingest.md` |
| 2020 | Fluent Bit HTTP server | `log-ingest.md` |
| 8200 | Elastic APM Server | `log-ingest.md` |
| 9000 / 443 | Sentry self-hosted | `log-ingest.md` |
| 8088, 9997 | Splunk HEC, S2S (fingerprint rows; CVEs in `hunt-exposed-services`) | `log-ingest.md` |
| 514, 601, 6514 | syslog receivers (fingerprint rows only) | `log-ingest.md` |
| 80/443 | PRTG, Orion, Web Help Desk, Nagios, Cacti, LibreNMS, Observium, Icinga Web 2, Checkmk | `cve-matrix.md` |

---

## Step 4: Stage A: read-only fingerprint

Stage A means: the request only reads, one request at a time, the failure mode is
a timeout or an error, and nothing changes state on the target. No `-sC`, no
`-A`; any NSE script is named and checked first with `nmap --script-help`.
Per-product command sets live in the references; the core probes are:

```bash
# A1. Zabbix agent (10050): agent.* keys only. A version string means the agent
# accepts passive checks from your address.
zabbix_get -s 192.0.2.10 -p 10050 -t 5 -k agent.version
zabbix_get -s 192.0.2.10 -p 10050 -t 5 -k agent.hostname

# A2. NRPE (5666): no -c, so the daemon returns its version and runs no plugin.
check_nrpe -H 192.0.2.10 -p 5666 -t 10

# A3. Icinga 2 (5665): expect 401; read the Server header and the certificate CN.
curl -sk -m 10 -D - -o /dev/null https://192.0.2.10:5665/v1

# A4. Checkmk agent (6556): no live probe in Stage A. Any connection, even a
# port check, makes a pull-mode agent run all its sections and plugins. Use
# existing scan data from offensive-osint; the header read is Stage B.

# A5. Exporters and gateways: bounded reads.
curl -s -m 10 http://192.0.2.10:9100/metrics | head -c 2000000 | grep -E '^node_(uname|os|dmi|network)_info' | head -20
curl -s -m 10 http://192.0.2.10:9093/api/v2/status | head -c 200000
curl -s -m 10 http://192.0.2.10:9091/api/v1/status | head -c 50000

# A6. Logs and traces: metadata, never content.
curl -s -m 10 http://192.0.2.10:3100/loki/api/v1/status/buildinfo
curl -s -m 10 -D - http://192.0.2.10:3100/loki/api/v1/labels | head -c 5000
curl -s -m 10 http://192.0.2.10:16686/api/services | head -c 50000

# A7. Ingest listeners: prove the listener without writing.
curl -s -m 10 -D - http://192.0.2.10:4318/v1/traces | head -c 2000   # 405 supported: [POST]
curl -s -m 10 http://192.0.2.10:9000/api/ | head -c 2000              # Graylog tagline + version
curl -s -m 10 http://192.0.2.10:9600/ | head -c 5000                  # Logstash host + version
curl -s -m 10 http://192.0.2.10:24220/api/plugins.json | head -c 300000 # Fluentd plugins (configs pre-1.19.3)
curl -s -m 10 http://192.0.2.10:2020/ | head -c 2000                  # Fluent Bit version
curl -s -m 10 -D - http://192.0.2.10:8200/ | head -c 2000             # APM: version body = no token required
curl -s -m 10 http://192.0.2.10:19999/api/v1/info | head -c 100000   # Netdata: mirrored_hosts, labels
```

### Tools that look like Stage A and are not

| Tool or request | What it actually does |
|---|---|
| `nmap --script nrpe-enum` | Categories discovery, intrusive: executes the stock NRPE command list on the target. |
| `check_nrpe -c <command>` | Runs a plugin on the target. Stage B, one stock command, no arguments. |
| Any connection to Checkmk 6556 (including `nc -vz`) | A pull-mode or socket-activated agent runs every section, local check and MRPE plugin for each connection. Stage B. |
| `zabbix_get -k system.run[...]` or `vfs.file.contents[...]` | Command execution or a file read through the agent. Stage B. |
| Zabbix `active checks` request to 10051 | May autoregister a host on every refresh and fire the client's registration actions. Stage B. |
| `zabbix_sender` | Writes a trapper value (or fails loudly). Stage B. |
| `check_nt -v CLIENTVERSION` | Sends the (often empty) NSClient++ password: a credential attempt. Stage B. |
| blackbox `/probe?target=`, snmp_exporter `/snmp?target=` | SSRF by design: the exporter connects where you say. Stage B, tester-owned external canary only. |
| Loki or Jaeger queries for log lines or traces | Data access; span tags and log lines carry tokens and PII. Stage B, `limit=1`. |
| Loki request with a guessed `X-Scope-OrgID` | Tenant impersonation. Stage B. |
| StatsD admin `health up`/`down`, `del*`, `quit` | Changes state or deletes metrics. Forbidden. |
| `GET` to Fluentd RPC (24444) | Every documented RPC path acts on GET (flush, kill workers, reload). Forbidden. |
| dRuby client to Fluentd debug agent (24230) | Exposes the engine object: code execution. Forbidden. |
| Collector pprof (1777), Netdata wide chart queries, graphite `/render` with wildcards | Load on production. Forbidden or tightly bounded. |
| `nmap -sU` on 514/162 | "open or filtered" proves nothing; not a finding either way. |

---

## Step 5: Read the results

### 5a. What leaks, and where

| Data | Typical source | Why it matters |
|---|---|---|
| Internal hostnames and FQDNs | `agent.hostname`, Checkmk `Hostname:`, Icinga certificate CN, `node_uname_info`, Netdata `mirrored_hosts`, Logstash `host`, Loki `join_members` | Naming scheme and internal domain for the rest of the engagement. |
| Internal IPs and topology | Alertmanager cluster peers, alert `instance` labels, blackbox recent-probe targets, OTel `pipelinez` exporters, Prometheus targets (panels) | Where the internal services are, without touching them. |
| Credentials | Alertmanager webhook URLs with tokens (older releases), Fluentd monitor-agent configs (`include_config`, before 1.19.3), Loki `/config` storage keys, Prometheus Azure AD `client_secret` (CVE-2026-42151), exporter textfile and Pushgateway labels | Grade by what the credential grants, not by where it was found. |
| Software inventory | Checkmk agent output (packages, processes), Logstash `/_node/plugins`, Fluent Bit `/api/v1/metrics`, Jaeger service and operation names | Version-gates other services without probing them. |
| Command channel | Zabbix agent answering you, NRPE answering you, Icinga API with a working credential | The agent can run what its config allows; that is the critical path. |
| Open ingest | APM version body without a token, Fluentd forward with no `HELO`, Graylog HTTP input on 6.1.x (CVE-2025-30373) | Log and alert injection, SIEM poisoning, cost. Proven without writing only where noted. |

### 5b. Version gates

Take the version from the product itself (`agent.version`, `NRPE vX`, Icinga
`Server` header, Checkmk `Version:`, `/api/v1/status`, buildinfo, `/api/`,
Logstash `version`, Fluent Bit `/`, APM `/`, Netdata `/api/v1/info`), then look
it up in the reference table for that product. Report version-only matches as
**unconfirmed**, with KEV status and PR from the CVE record. Distro packages
(Debian, RHEL, EPEL) backport fixes for Zabbix, Icinga and Nagios; a distro
release suffix can move a version out of range. Checkmk's `Version:` comes only
from a Stage B header read or third-party scan data.

### 5c. KEV in scope (catalog 2026.10.13)

SolarWinds Web Help Desk (CVE-2024-28986, CVE-2024-28987, CVE-2025-40551,
CVE-2025-40536, CVE-2025-26399), SolarWinds Orion (CVE-2020-10148), PRTG
(CVE-2018-19410, CVE-2018-9276), Nagios XI (CVE-2019-15949, CVE-2021-25296,
CVE-2021-25297, CVE-2021-25298), Cacti (CVE-2022-46169), Zabbix frontend
(CVE-2022-23131, CVE-2022-23134), Grafana (CVE-2021-43798, CVE-2021-39226).
Several need authentication (PR:L or PR:H); see `references/cve-matrix.md`.

---

## Step 6: Stage B: anything that writes, triggers, executes or authenticates

Stage B is **blocked by default**. It requires explicit written operator sign-off
naming the action, the host, the exact payload and a time window. A chat
thumbs-up or "critical findings are in scope" is not sign-off. Record before the
first packet:

```
Stage B authorization
  Host/port:        192.0.2.10:10050
  Action:           one passive check of system.run[id] (AllowKey permits system.run)
  Payload:          the key above, nothing else
  Blast radius:     one command as the zabbix user; one line in the agent log
  Reversibility:    nothing persists on the host
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| Zabbix `system.run[id]` or one `vfs.file.contents` read of a named benign file | Command execution or file read as the agent user. Proves the critical path; never more than one. |
| `check_nrpe -c <stock command>` (no arguments) | Runs one plugin on the target; appears in NRPE logs. |
| One connection to Checkmk 6556, header read, close | One full agent poll including local checks and MRPE plugins; one entry in the agent log. |
| One documented default credential on a console (PRTG and Cacti shipped defaults, see `cve-matrix.md` (verify)) or NSClient++ empty password | A failed login can count toward lockout; a success is an admin session. Log out at once. |
| Zabbix `active checks` or `sender data` | Possible host autoregistration and its actions (notifications, template links); a trapper value. |
| One canary datum into an ingest path (Graphite line, StatsD packet, GELF message, Loki push, OTLP export, Fluentd forward, APM event, Sentry event, syslog line, SNMP trap, HEC event) | **Cannot be deleted by you**, lands in the client's SIEM or TSDB permanently, may match an alert rule and page on-call. Tell the client the exact canary string in advance. |
| One Pushgateway canary group | Visible to every scraper until deleted; a `DELETE` of your own group is the only write cleanup in this skill. |
| blackbox or snmp_exporter `target=` pointed at a tester-owned external canary | The client's exporter connects out to you. Never an internal, RFC 1918 or metadata address. |
| One log line or one trace (`limit=1`) from Loki or Jaeger | Real customer or employee data. Redact in evidence. |
| One guessed Loki `X-Scope-OrgID` | Reads another tenant's data. |

**Forbidden outright, sign-off or not:** creating Alertmanager silences or
posting alerts (blinds or pages the client's on-call), Pushgateway admin wipe and
`/-/quit`, Prometheus TSDB admin endpoints (panels' territory, never run), Loki
`/ingester/shutdown`, `/flush`, `POST /log_level` and the delete API, Fluent Bit
`/api/v2/reload` and `/api/v1/traces`, Fluentd RPC and debug agent, StatsD admin
state changes, Icinga `/v1/console`, `/v1/actions/*` and config stages, Netdata
`PUT /api/v3/settings`, Graylog `cluster_config` writes, NRPE argument passing and
metacharacter tests, trap or log payloads aimed at a parser (CVE-2024-42332,
CVE-2026-59787, CVE-2026-44024), every DoS-class CVE (decompression bombs,
ReDoS, snappy, Beats input), and sending any KEV exploit request to confirm a
version gate.

---

## Step 7: Grade by what you proved

| What you proved | Grade |
|---|---|
| Command execution through an agent (Zabbix `system.run`, NRPE) under sign-off, or an agent that would run it for you | Critical |
| Working credential leaked unauthenticated (webhook token, storage key, Fluentd shared key, cloud secret) | High to Critical, by what it grants |
| KEV-listed pre-auth CVE in range on an NMS console (WHD, Orion, PRTG CVE-2018-19410, Cacti) | High, labelled unconfirmed; escalate the same day |
| Checkmk agent in plaintext pull mode, or Zabbix agent answering anyone | Medium to High (host inventory; command channel if keys allow) |
| Unauthenticated log or trace read (Loki `auth_enabled: false`, Jaeger query) | Medium to High, by data class seen under Stage B |
| Open ingest proven (APM version body, Fluentd forward without `HELO`, or a signed-off canary accepted) | Low to Medium: log injection, alert spoofing, cost |
| Internal topology from metrics, alerts, exporters or zpages | Low to Medium; higher when it feeds a chain |
| Non-KEV version gate (Icinga CVE-2024-49369, Checkmk chain, Fluent Bit CVE-2024-4323) | Medium to High, unconfirmed, by PR and impact |
| Listener reachable, auth enforced, current version | Informational or not a finding |

### What is not a finding

- **Version or banner disclosure alone** (`NRPE v4.1.0`, Icinga `Server` header,
  Logstash `version`). HackerOne's core ineligible findings list "Software version
  disclosure / Banner identification issues"; the Bugcrowd VRT rates
  "Fingerprinting/Banner Disclosure" P5.
- **`/metrics` with only Go runtime and process stats**, health endpoints
  (`/ready`, `/-/healthy`, `/_health/`, `/api/v1/health`).
- **A Sentry DSN in front-end JavaScript.** It is public by design.
- **UDP 514 or 162 "open or filtered".** Nothing was proven.
- **An OTLP 405 or a Splunk HEC health reply alone.** They prove a listener, not
  open ingest.
- **DoS-only CVEs in range.** Report as patch hygiene at most; never test.
- **"Outdated version" with no reachable issue.** VRT "Outdated Software Version"
  is P5; distro backports make many of these false.

---

## Step 8: Evidence

Follow `evidence-hygiene`. Minimum per finding: the request and the first lines
of the raw response with timestamps and the egress IP; for leaks, field names
and counts plus redacted values (first 4 characters of any secret); for agents,
the exact key or command sent and its reply; for Stage B, the sign-off record and
the canary string. Never paste log lines, trace spans, full agent output or
customer data beyond what proves the class. Tell the client to rotate any
leaked credential the same day.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| Zabbix agent answers `agent.version` | `AllowKey` permits `system.run` (B) | Critical | Report; no shell, no persistence. |
| Alertmanager config leaks a webhook URL with a token | Token posts to the client's chat or paging | High | Validate per `hunt-source-leak`; never post a message. |
| Fluentd monitor agent returns `aws_key_id`/`aws_sec_key` | Cloud credential | High to Critical | `cloud-iam-deep` for privilege analysis. |
| Logstash or Loki config names Elasticsearch, S3 or Kafka with credentials | Data-store access | High | `hunt-exposed-services` for the store. |
| blackbox or snmp exporter reachable | SSRF by design | Medium to High | `hunt-ssrf`; external canary only. |
| Netdata `mirrored_hosts`, Prometheus targets, OTel `pipelinez`, alert `instance` labels | Internal host and port map | Recon multiplier | Scope check per name; `web2-recon`. |
| Checkmk agent plaintext output | Installed packages and versions | Recon multiplier | Version-gate other exposed services. |
| Icinga 2 in range of CVE-2024-49369 | API user or node impersonation | High, unconfirmed | Same-day notice. |
| NMS console with KEV-listed CVE | Pre-auth RCE on the host that holds every monitored credential | Critical-class, unconfirmed | Same-day notice; no PoC. |
| Grafana, Zabbix frontend, Prometheus 9090 on the same host | UI and API checks | per panels | `hunt-exposed-panels`. |

---

## Validation checklist

- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Every IP confirmed client-owned and in scope; not a SaaS vendor's ingest.
- [ ] Response data matches the client's naming; honeypot and demo stacks ruled out.
- [ ] Port collisions resolved by response (9000, 9100, 8088, 514/tcp).
- [ ] Stage A stayed inside 15 requests per host, serial, bounded with `head -c`
      and `limit=`.
- [ ] Zabbix: only `agent.*` keys and `zabbix.stats` in Stage A; no `active checks`.
- [ ] NRPE: no `-c`, no `nrpe-enum`; NSClient++: no `check_nt` without sign-off.
- [ ] Checkmk agent: no live connection in Stage A; the one header read had
      sign-off, body discarded.
- [ ] Loki and Jaeger: labels and service names only, unless Stage B was signed.
- [ ] No request sent to Fluentd RPC or debug agent, Fluent Bit reload or traces,
      Alertmanager silences or alerts, StatsD state commands.
- [ ] Every write, check, command or credential has a logged written sign-off and
      happened exactly once; canary strings recorded and given to the client.
- [ ] Version-gated findings labelled unconfirmed, with KEV status, PR level and
      the distro backport caveat.
- [ ] No DoS-class CVE tested; no KEV exploit request sent.
- [ ] Secrets redacted; no log lines, spans or agent output beyond the proof.
- [ ] Not reporting banner disclosure, health endpoints or public DSNs alone.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/agent-protocols.md` | Zabbix ZBXD framing, passive and active checks, trapper, `zabbix.stats`, AllowKey/DenyKey and autoregistration; NRPE `_NRPE_CHECK`; NSClient++ defaults; Icinga 2 API and certificates; Checkmk agent 6556, agent receiver, mknotifyd; SNMP trap receivers; agent-side CVE rows | zabbix agent 10050 exposed, zabbix trapper 10051, zabbix_get agent.version, system.run allowkey, nrpe 5666 open, check_nrpe version, nsclient 8443, icinga 5665 api, checkmk 6556 agent output, cve-2024-49369 |
| `references/metrics-and-tracing.md` | node, blackbox and snmp exporters; Alertmanager; Pushgateway; Graphite/Carbon; StatsD admin; Loki; Jaeger; OpenTelemetry Collector (OTLP, zpages, health); Netdata API; CVE rows | node_exporter 9100 exposed, blackbox probe ssrf, alertmanager api v2 status, pushgateway exposed, graphite 2003, statsd 8126 admin, loki 3100 no auth, x-scope-orgid, jaeger 16686 services, otlp 4318 exposed, zpages, netdata api info |
| `references/log-ingest.md` | Graylog API and GELF; Logstash 5044/9600; Fluentd forward, monitor agent, debug agent, RPC; Fluent Bit HTTP server; Elastic APM 8200; Sentry self-hosted; Splunk HEC fingerprint; syslog fingerprint rows; CVE rows | graylog 9000 api, gelf 12201, logstash 9600 api, fluentd 24220 monitor agent, fluentd 24224 forward, fluent bit 2020, cve-2024-4323, apm server 8200 secret token, sentry self-hosted version, syslog 514 exposed, splunk hec 8088 |
| `references/cve-matrix.md` | All in-scope KEV rows; NMS console fingerprints and shipped credentials; CVE tables for SolarWinds Orion and Web Help Desk, PRTG, Nagios XI/Core, Cacti, LibreNMS, Observium, Icinga Web 2; Grafana and Prometheus rows panels lacks; products with no CVE found | solarwinds web help desk cve, orion cve-2020-10148, prtg cve-2018-19410, nagios xi kev, cacti cve-2022-46169, librenms auth bypass, observium cve, icinga web 2 file read, grafana cve-2021-39226 kev |

Primary sources (fetched 2026-10-13):

- Zabbix documentation (protocol header, passive/active checks, trapper items,
  remote stats, restricting agent checks, autoregistration, zabbix_sender):
  <https://www.zabbix.com/documentation/current/en/manual>
- NRPE source and `nrpe.cfg`: <https://github.com/NagiosEnterprises/nrpe>
- NSClient++ WEBServer docs: <https://nsclient.org/docs/reference/client/WEBServer/>
- Icinga 2 REST API docs and source: <https://icinga.com/docs/icinga-2/latest/doc/12-icinga2-api/>
- Checkmk Linux agent docs: <https://docs.checkmk.com/latest/en/agent_linux.html>
- Prometheus node_exporter, blackbox_exporter, snmp_exporter, Alertmanager,
  Pushgateway READMEs and source: <https://github.com/prometheus>
- Graphite `carbon.conf.example`: <https://github.com/graphite-project/carbon>
- StatsD admin interface: <https://github.com/statsd/statsd/blob/master/docs/admin_interface.md>
- Loki HTTP API: <https://grafana.com/docs/loki/latest/reference/loki-http-api/>
- Jaeger v2 docs: <https://www.jaegertracing.io/docs/latest/>
- OpenTelemetry Collector security best practices and source:
  <https://github.com/open-telemetry/opentelemetry-collector>
- Fluent Bit monitoring docs: <https://docs.fluentbit.io/manual/administration/monitoring>
- Fluentd `in_forward`, `in_monitor_agent`, debug agent and RPC docs: <https://docs.fluentd.org/>
- Graylog server source (`HelloWorldResource`): <https://github.com/Graylog2/graylog2-server>
- Logstash settings and Docker config: <https://github.com/elastic/logstash>
- APM Server root handler source: <https://github.com/elastic/apm-server>
- Sentry self-hosted `.env`: <https://github.com/getsentry/self-hosted>
- CISA KEV feed (catalog 2026.10.13): <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CVE records: <https://cveawg.mitre.org/api/cve/>; NVD <https://services.nvd.nist.gov/rest/json/cves/2.0>;
  CIRCL vulnerability-lookup <https://vulnerability.circl.lu/>
- HackerOne core ineligible findings: <https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>
- Bugcrowd VRT: <https://github.com/bugcrowd/vulnerability-rating-taxonomy>

No lab verification was run for this skill; commands follow the cited
documentation and source. Response formats marked "(verify)" in the references
should be confirmed on first real use.

---

## Related Skills & Chains

- `hunt-exposed-panels`: Zabbix, Grafana, Prometheus 9090 and Netdata dashboard
  probes; this skill owns the agents, exporters, ingest and KEV rows around them.
- `hunt-exposed-services`: Elasticsearch, Kibana, InfluxDB, Splunk, SNMP 161,
  printing on 9100; its Stage A/B model is the template here.
- `infra-ssh`, `infra-mail`, `infra-ftp`: sibling infra skills (Serv-U lives in
  `infra-ftp`).
- `hunt-ssrf`: exporter `target=` SSRF beyond the canary.
- `hunt-source-leak`, `cloud-iam-deep`: validating and scoping credentials found
  in configs and labels.
- `hunt-k8s`: Prometheus, exporters and collectors inside a cluster.
- `hunt-brute-force`: any credential attempt beyond one shipped default.
- `offensive-osint`, `web2-recon`, `recon-scope-triage`: discovery and scope.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence, false
  positive gates and write-up.

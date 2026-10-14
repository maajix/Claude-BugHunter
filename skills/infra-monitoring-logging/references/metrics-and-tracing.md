# Metrics and tracing: exporters, Alertmanager, Pushgateway, Graphite, StatsD, Loki, Jaeger, OpenTelemetry, Netdata API

The Prometheus server (9090: `/api/v1/status/config`, `/targets`, flags, admin
API), the Grafana UI (3000) and the Netdata dashboard root (19999) are probed in
`hunt-exposed-panels` (`references/monitoring-and-dashboards.md`). This file owns
everything around them: exporters, alert and push gateways, metric line
protocols, log and trace query APIs, and the collector pipeline.

Rule for every HTTP read here: one request, bounded output (`head -c`), no
wide time ranges, no profiling endpoints. Metadata (labels, service names,
target lists) is Stage A; reading log lines or trace spans is data access and
needs Stage B sign-off. "(verify)" marks facts not confirmed against a primary
source on 2026-10-13. KEV status: CISA catalog 2026.10.13.

---

## Port map

| Port | Product | Read path | Write / action path (never Stage A) |
|---|---|---|---|
| 9100 | node_exporter | `GET /metrics` | none |
| 9115 | blackbox_exporter | `GET /`, `GET /metrics`, `GET /config` | `GET /probe?target=` (SSRF by design), `POST /-/reload` |
| 9116 | snmp_exporter | `GET /`, `GET /metrics` | `GET /snmp?target=` (SSRF by design, sends SNMP) |
| 9093 / 9094 | Alertmanager / cluster gossip | `GET /api/v2/status`, `/api/v2/alerts`, `/api/v2/silences`, `/api/v2/receivers` | `POST /api/v2/silences`, `POST /api/v2/alerts`, `DELETE /api/v2/silence/<id>` |
| 9091 | Pushgateway | `GET /api/v1/status`, `/api/v1/metrics`, `/metrics` | `PUT`/`POST`/`DELETE /metrics/job/...`, admin wipe, `/-/quit` |
| 2003 / 2004 / 7002 | Carbon line / pickle / cache query | none (TCP connect only) | any line on 2003 or pickle frame on 2004 is a datapoint |
| 2013 / 2014 | Carbon relay line / pickle | none | same |
| 80 / 8080 | graphite-web | `GET /metrics/find?query=*` | `/composer/send_email` (CVE-2017-18638) |
| 8125/udp, 8126 | StatsD / StatsD admin | admin `stats` command | any packet on 8125; admin `health <arg>`, `del*`, `quit` |
| 3100 | Loki | `/ready`, `/loki/api/v1/status/buildinfo`, `/config`, `/services`, `/loki/api/v1/labels` | `/loki/api/v1/push`, `/otlp/v1/logs`, `/api/prom/push`, `/flush`, `/ingester/shutdown`, `/ingester/prepare_shutdown`, delete API, `POST /log_level` |
| 16686 | Jaeger query / UI | `/api/services`, `/api/v3/services`, `/api/services/<svc>/operations` | none on 16686 |
| 14268 / 14250 / 9411 / 5778 | Jaeger collector HTTP / gRPC, Zipkin, sampling | `GET /sampling?service=` on 5778 (read, verify) | `POST /api/traces`, `POST /api/v2/spans` |
| 4317 / 4318 | OTLP gRPC / HTTP (Collector, Jaeger v2, Tempo, vendors) | `GET /v1/traces` returns 405 | `POST /v1/traces`, `/v1/metrics`, `/v1/logs`, `/v1/profiles` |
| 55681 | legacy OTLP/HTTP port (older collectors) | same as 4318 (verify) | same |
| 13133 / 55679 / 8888 / 1777 | Collector health_check / zpages / self-metrics / pprof | `GET /`, `/debug/servicez`, `/debug/pipelinez`, `/metrics` | pprof profiles (forbidden) |
| 19999 | Netdata agent API | `GET /api/v1/info` | `PUT /api/v3/settings` (CVE-2026-83602) |

Port collisions: 9100 is also raw printing (PJL/JetDirect, owned by
`hunt-exposed-services`); a printer answers HTTP with nothing or garbage. 9090 is
also Cockpit and others. 8080 and 3100 are generic.

---

## Prometheus exporters

### node_exporter (9100)

Default-enabled collectors include `uname`, `os`, `dmi`, `netclass`, `netdev`,
`filesystem`, `arp` and `textfile` (needs a directory). `network_route`,
`processes` and `systemd` are off by default.

```bash
curl -s -m 10 http://192.0.2.10:9100/metrics | head -c 2000000 \
  | grep -E '^node_(uname_info|os_info|dmi_info|network_info|exporter_build_info)|^node_filesystem_size_bytes\{|^node_arp_entries' | head -60
# Custom textfile metrics: anything the client's scripts wrote, sometimes secrets in labels.
curl -s -m 10 http://192.0.2.10:9100/metrics | head -c 2000000 | grep -vE '^(#|node_|go_|process_|promhttp_)' | head -40
```

What leaks: `node_uname_info{nodename=...,release=...}` (hostname, kernel),
`node_os_info` (distro and version), `node_dmi_info` (hardware vendor, sometimes
serial numbers), `node_network_info` (interface names, MAC addresses, operstate),
filesystem mountpoints, ARP entry counts per interface (internal network shape).
No CVE found for node_exporter 2018-2026 (checked 2026-10-13) apart from the
shared exporter-toolkit row below.

### blackbox_exporter (9115) and snmp_exporter (9116)

```bash
# Status page: blackbox lists recent probes with their targets and modules,
# which are the client's internal and external monitored endpoints.
curl -s -m 10 http://192.0.2.10:9115/ | head -c 200000 | grep -oE 'target=[^&"<]+' | sort -u | head -50
curl -s -m 10 http://192.0.2.10:9115/config | head -c 100000   # modules; secrets render masked (verify)
curl -s -m 10 http://192.0.2.10:9116/ | head -c 20000
```

`/probe?target=` and `/snmp?target=` make the exporter connect wherever you say:
SSRF by design. The snmp_exporter README states that "community strings in SNMP
are not considered secrets". Stage B only, toward a tester-controlled external
canary, never toward an internal or cloud metadata address. TLS and basic auth,
when configured through `--web.config.file`, cover `/metrics`, `/probe` and the
web UI.

| CVE | Product | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|---|
| CVE-2020-16248 | blackbox_exporter | up to 0.17.0 | disputed | N | No | `/probe` SSRF; the vendor disputes it as intended behaviour. Report the exposure, not the CVE. |
| CVE-2022-46146 | exporter-toolkit (all exporters using `web.yml`) | before 0.7.2, 0.8.0-0.8.1 | 0.7.2 / 0.8.2 | AV:L in record | No | Basic-auth bypass when an attacker knows the bcrypt hash. Needs the hash first. |

No CVE found 2018-2026 for snmp_exporter (checked 2026-10-13).

---

## Alertmanager (9093, cluster 9094)

The README's Docker example binds `127.0.0.1:9093`. APIv1 was removed in 0.27.0.

```bash
curl -s -m 10 http://192.0.2.10:9093/api/v2/status | head -c 200000 | python3 -m json.tool | head -120
curl -s -m 10 'http://192.0.2.10:9093/api/v2/alerts?active=true' | head -c 200000 | python3 -c 'import json,sys; [print(a["labels"].get("alertname"), a["labels"].get("instance"), a["labels"].get("job")) for a in json.load(sys.stdin)[:40]]'
curl -s -m 10 http://192.0.2.10:9093/api/v2/silences | head -c 100000 | python3 -c 'import json,sys; [print(s["createdBy"], s["status"]["state"]) for s in json.load(sys.stdin)[:20]]'
```

What leaks: `config.original` (routing tree, receiver names, email addresses,
SMTP smarthost, webhook endpoints), `versionInfo`, cluster peers (internal IPs),
alert labels (`instance` = internal host:port, `job`, annotations with runbook
and dashboard URLs) and silence authors. Current releases render Slack,
Mattermost and webhook URLs as secrets; older releases may print webhook URLs with
embedded tokens (verify per version). A webhook URL with a token is a credential:
grade it by what it posts to, validate it under `hunt-source-leak` rules.

Creating a silence or posting an alert is forbidden outright: a silence blinds
the client's on-call, a fake alert pages them.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2023-40577 | up to 0.25.0 | 0.25.1 | N | No | Stored XSS through `POST /api/v1/alerts` rendered in the UI. Version gate only; posting the alert is a write. |

---

## Pushgateway (9091)

```bash
curl -s -m 10 http://192.0.2.10:9091/api/v1/status | head -c 50000     # build info and flags
curl -s -m 10 http://192.0.2.10:9091/api/v1/metrics | head -c 500000 \
  | python3 -c 'import json,sys; [print(g["labels"]) for g in json.load(sys.stdin)["data"][:50]]'
```

What leaks: pushed groups (`job`, `instance` and custom labels: batch job names,
internal hosts, sometimes tokens or connection strings in labels), and whether
`--web.enable-admin-api` (wipe) or `--web.enable-lifecycle` (`/-/quit`) are on.
Writes (`PUT`/`POST`/`DELETE /metrics/job/...`), the admin wipe and `/-/quit` are
never run; a single canary group is Stage B (see SKILL.md Step 6). No CVE found
2018-2026 (checked 2026-10-13).

---

## Graphite (Carbon 2003/2004/7002, relay 2013/2014, graphite-web)

Shipped `carbon.conf`: line receiver `0.0.0.0:2003`, UDP listener off, pickle
receiver `0.0.0.0:2004` (safe unpickler by default), cache query `0.0.0.0:7002`,
relay 2013/2014. Carbon sends no banner and has no read command on 2003/2004.

```bash
nc -vz -w 5 192.0.2.10 2003; nc -vz -w 5 192.0.2.10 2004   # TCP connect only
# graphite-web: one level of the metric tree. Top-level nodes are often host or
# environment names.
curl -s -m 10 'http://192.0.2.10:8080/metrics/find?query=*' | head -c 50000
```

Do not walk the tree recursively and do not call `/render` with wildcards; both
can be expensive for the client's storage. Writing a datapoint is Stage B.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2017-18638 | graphite-web up to 1.1.5 (published 2019) | 1.1.6 (verify) | N | No | SSRF through `send_email`. Never send; it mails on the client's behalf. |
| CVE-2022-4728, CVE-2022-4729, CVE-2022-4730 | graphite-web, unspecified (records cite patch commits) | (verify) | L, UI:R | No | XSS. Version gate only. |

---

## StatsD (8125/udp, admin 8126/tcp)

Etsy StatsD admin commands: `health` (read without argument, `health up|down`
changes state), `config`, `stats`, `counters`, `gauges`, `timers`,
`delcounters`, `delgauges`, `deltimers`, `quit`.

```bash
# One read-only admin command. Never send health with an argument, del*, or quit.
printf 'stats\n' | nc -w 5 192.0.2.10 8126 | head -c 4000
```

`stats` returns uptime, `messages.last_msg_seen` and backend status. `counters`
and `gauges` dump every metric name (service and host inventory); read one of
them only if `stats` succeeded and keep the output bounded. 8125/udp has no read
path; a packet is a write (Stage B). No CVE found 2018-2026 (checked 2026-10-13).

---

## Grafana Loki (3100)

Loki "does not come with any included authentication layer". With
`auth_enabled: true` (the default) every request needs `X-Scope-OrgID`; without
it Loki answers 401 `no org id`. With `auth_enabled: false` everything runs as
tenant `fake`.

```bash
curl -s -m 10 http://192.0.2.10:3100/ready
curl -s -m 10 http://192.0.2.10:3100/loki/api/v1/status/buildinfo
curl -s -m 10 http://192.0.2.10:3100/services | head -c 5000
curl -s -m 10 http://192.0.2.10:3100/config | head -c 300000 \
  | grep -nE 'bucket|endpoint|access_key|secret|password|join_members|alertmanager_url|tenant' | head -40
# No header: 401 "no org id" = auth_enabled true and no gateway in front.
curl -s -m 10 -D - http://192.0.2.10:3100/loki/api/v1/labels | head -c 5000
```

Read the result:

- `/config` returns the runtime config: object storage buckets and endpoints,
  memberlist `join_members` (internal hostnames), ruler and Alertmanager URLs.
  Masking of secret fields is version-dependent (verify); report any secret seen.
- Labels returned without a header: `auth_enabled: false`, all logs readable.
  Stop at `/loki/api/v1/labels` and one `label/<name>/values` call.
- 401 `no org id`: multi-tenant mode reachable without its auth proxy. Any guessed
  `X-Scope-OrgID` value is impersonating a tenant: Stage B.

Reading log lines (`query_range`, `tail`) is Stage B: one query, `limit=1`,
15-minute window, redacted in evidence. `POST /log_level`, `/flush`,
`/ingester/shutdown`, push and delete endpoints are forbidden.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2021-36156 | Loki up to 2.2.1 | 2.3.0 (verify) | N | No | Path traversal through `X-Scope-OrgID` to rules files. Version gate only. |
| CVE-2022-28660 | Grafana Enterprise Logs 1.1.x-1.3.x | 1.4.0 | N | No | Querier required no authentication beyond `X-Scope-OrgID`. |

---

## Jaeger (16686 UI and query API)

Jaeger v2 all-in-one exposes 16686 (UI, `/api/v3/*` stable and `/api/*`
internal), 4317/4318 (OTLP), 5778 (sampling), 9411 (Zipkin). v1 collectors used
14250 (gRPC) and 14268 (`POST /api/traces`).

```bash
curl -s -m 10 http://192.0.2.10:16686/api/services | head -c 50000
curl -s -m 10 http://192.0.2.10:16686/api/v3/services | head -c 50000
curl -s -m 10 'http://192.0.2.10:16686/api/services/<service-from-above>/operations' | head -c 50000
```

Service and operation names are an inventory of internal applications and their
HTTP routes and SQL operations. Fetching traces (`/api/traces?service=...`) is
Stage B: span tags routinely carry user IDs, tokens, SQL with parameters and
internal URLs. One trace, `limit=1`, `lookback=1h`, redacted. Version is rarely
visible on 16686; the admin or metrics port may expose build info (verify).
Only CVE-2020-10750 found 2018-2026 (credentials in logs, local); nothing
external.

---

## OpenTelemetry Collector (4317/4318, 55681, 13133, 55679, 8888, 1777)

Since v0.110.0 receivers and extensions default to `localhost`; earlier
versions bound `0.0.0.0` unless the `component.UseLocalHostAsDefaultHost` gate
was set. An internet-reachable OTLP port is therefore an explicit choice or an
old build. Paths: `/v1/traces`, `/v1/metrics`, `/v1/logs`, `/v1/profiles`.

```bash
# OTLP/HTTP: a GET returns "405 method not allowed, supported: [POST]".
curl -s -m 10 -D - http://192.0.2.10:4318/v1/traces | head -c 2000
# OTLP/gRPC: TLS or h2c? Try TLS with ALPN h2 first.
openssl s_client -connect 192.0.2.10:4317 -alpn h2 </dev/null 2>/dev/null | grep -E "ALPN|subject=|issuer="
curl -s -m 10 http://192.0.2.10:13133/ | head -c 2000                 # health_check extension
curl -s -m 10 http://192.0.2.10:55679/debug/servicez | head -c 100000 # zpages: build info, version
curl -s -m 10 http://192.0.2.10:55679/debug/pipelinez | head -c 100000 # receivers -> processors -> exporters
curl -s -m 10 http://192.0.2.10:8888/metrics | grep -m5 -E 'otelcol_process_uptime|service_version' # (verify label)
```

A 405 proves an OTLP receiver, not that it is unauthenticated: an `auth`
extension may reject the POST that you are not sending (verify ordering per
version). `pipelinez` names exporters and their backends (internal Tempo, Loki,
Elasticsearch, vendor endpoints). pprof on 1777 is forbidden (CPU profiling on
production).

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2024-36129 | opentelemetry-collector before 0.102.1 | 0.102.1 | N | No | Decompression bomb over HTTP or gRPC. DoS class: never test. |
| CVE-2026-42602 | collector-contrib 0.124.0-0.150.0 | 0.151.0 (verify) | L | No | `azureauthextension` did not validate bearer tokens. Matters only when that extension guards the receiver. |

---

## Netdata agent API (19999)

The dashboard root on 19999 is in `hunt-exposed-panels`. The API leaks more than
the dashboard banner:

```bash
curl -s -m 10 http://192.0.2.10:19999/api/v1/info | head -c 100000 \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(k, d.get(k)) for k in ("version","uid","mirrored_hosts","mirrored_hosts_status","host_labels","collectors")]'
```

`mirrored_hosts` lists every child streaming to this parent (internal
hostnames); `host_labels` carry cloud, container and custom labels. The API is
unauthenticated by design unless the client restricts it.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2023-22496 | before 1.37 (nightly 1.36.0-409) | 1.37.0 | N, AC:H | No | Command injection via streaming. Needs a streaming key. |
| CVE-2023-22497 | before 1.37 | 1.37.0 | N, AC:H | No | Machine GUID accepted as a streaming API key. |
| CVE-2026-83602 | 2.0.0 before 2.11.0 | 2.11.0 | N | No | Unauthenticated `PUT /api/v3/settings` bypassed IP allow-lists. A write: version gate only. |
| CVE-2026-83599 | before 2.11.0 | 2.11.0 | N | No | WebSocket decompression bomb. DoS class: never test. |
| CVE-2024-32019 | 1.44.0-60 before 1.45.3 | 1.45.3 | local | No | `ndsudo` local privilege escalation. Not external. |

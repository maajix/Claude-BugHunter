# Log ingest: Graylog, Logstash, Fluentd, Fluent Bit, Elastic APM, Sentry self-hosted, syslog, Splunk HEC

Ingest ports accept data and give nothing back. The rule for this file: prove the
listener with a request that writes nothing (TCP connect, TLS handshake, a GET
that the endpoint refuses, a monitoring API on a different port), and treat one
named canary record as Stage B, because the client cannot delete what you wrote
and it may page their on-call.

Elasticsearch, Kibana, InfluxDB and splunkd 8089 (including Splunk CVEs) are in
`hunt-exposed-services` (`references/databases.md`). "(verify)" marks facts not
confirmed against a primary source on 2026-10-13. KEV status: CISA catalog
2026.10.13.

---

## Port map

| Port | Product | No-write fingerprint | Write path (Stage B) |
|---|---|---|---|
| 9000 | Graylog web/API (also Sentry self-hosted, PHP-FPM, Portainer, MinIO and others) | `GET /api/` | REST writes, inputs |
| 12201/udp, 12201/tcp, 12201 HTTP | Graylog GELF inputs | TCP connect; UDP proves nothing | one GELF message |
| 5044 | Logstash Beats input | TCP connect, TLS handshake | one Beats event |
| 9600 | Logstash monitoring API | `GET /`, `/_node/pipelines`, `/_node/plugins` | none on 9600 |
| 24224 tcp+udp | Fluentd / Fluent Bit forward input | TCP connect, read for `HELO` | one forward event |
| 24220 | Fluentd monitor agent | `GET /api/plugins.json`, `/api/config.json` | none |
| 24230 | Fluentd debug agent (dRuby) | TCP connect only | dRuby exposes `Fluent::Engine`: forbidden |
| 24444 | Fluentd RPC (`rpc_endpoint`) | TCP connect only | every documented path is an action, even as GET: forbidden |
| 9880 | Fluentd `in_http` | TCP connect only | any request with a tag path |
| 2020 | Fluent Bit HTTP server | `GET /`, `/api/v1/health`, `/api/v1/uptime`, `/api/v1/metrics` | `/api/v2/reload`, `/api/v1/traces` |
| 8200 | Elastic APM Server | `GET /` | `/intake/v2/events`, `/intake/v2/rum/events` |
| 9000 / 443 | Sentry self-hosted (`SENTRY_BIND=9000`) | `GET /_health/`, login page | `/api/<project>/envelope/`, `/api/<project>/store/` |
| 8088 | Splunk HEC (collides with Hadoop YARN, owned by `hunt-exposed-services`) | `GET /services/collector/health` | `/services/collector/event`, `/raw` |
| 9997 | Splunk forwarder-to-indexer (S2S) | TCP connect only | any S2S frame |
| 514/udp | syslog | nothing (no reply) | one syslog line |
| 514/tcp, 601/tcp | syslog over TCP (514/tcp is also legacy rsh) | TCP connect | one syslog line |
| 6514/tcp | syslog over TLS | TLS handshake, certificate | one syslog line |

---

## Graylog (9000 web/API, GELF 12201)

`GET /api/` is served by an unauthenticated resource and returns `cluster_id`,
`node_id`, `version` and the tagline "Manage your logs in the dark and have lasers
going and make it look like you're from space!". That tagline is the fingerprint
that separates Graylog from everything else on 9000.

```bash
curl -s -m 10 http://192.0.2.10:9000/api/ | head -c 2000
nc -vz -w 5 192.0.2.10 12201          # GELF TCP input: connect only
```

GELF UDP never replies; GELF TCP accepts null-byte-delimited JSON with no
greeting; a GELF HTTP input answers on `/gelf` (non-POST behaviour (verify)).
None of them can be shown to accept data without sending data. Graylog's admin
password is set by the operator (`root_password_sha2`); whether any shipped
default exists to try is (verify), and Docker quick-start examples differ.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2024-24824 | 2.0.0 before 5.1.11, 5.2.0 before 5.2.4 | 5.1.11 / 5.2.4 | L | No | Arbitrary class instantiation through `PUT /api/system/cluster_config`. Authenticated. |
| CVE-2025-30373 | 6.1.0 before 6.1.9 | 6.1.9 | N | No | HTTP inputs with header auth returned 401 but still ingested the message. A 401 from an HTTP input on 6.1.x is not proof that auth works. Testing it means sending a message: Stage B. |
| CVE-2025-53106 | 6.2.0 before 6.2.4, 6.3.0 pre-releases | 6.2.4 / 6.3.0-rc.2 | L | No | Privilege escalation through API tokens. |
| CVE-2021-37759 | before 4.1.2 | 4.1.2 | n/a | No | Session IDs written to the DEBUG log. |

---

## Logstash (Beats 5044, monitoring API 9600)

Shipped `config/logstash.yml`: `api.http.host: 127.0.0.1`, port range 9600-9700,
`api.auth.type: none`. The official Docker image's `logstash-full.yml` sets
`api.http.host: "0.0.0.0"`, which is how most exposed 9600s happen.

```bash
curl -s -m 10 http://192.0.2.10:9600/ | head -c 5000                  # host, version, http_address, id, name, pipeline settings
curl -s -m 10 http://192.0.2.10:9600/_node/plugins | head -c 50000    # installed plugin versions
curl -s -m 10 http://192.0.2.10:9600/_node/pipelines | head -c 50000  # pipeline ids and settings
openssl s_client -connect 192.0.2.10:5044 </dev/null 2>/dev/null | grep -E "subject=|issuer=|no peer certificate"
```

The `host` field is the internal hostname; plugin lists show which inputs and
outputs exist (Elasticsearch, Kafka, S3, JDBC). Whether pipeline graph output
includes plugin settings such as output passwords depends on version and flags
(verify); report any credential seen and stop. Skip `/_node/hot_threads` (load).

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2019-7620 | before 6.8.4 and 7.4.1 | 6.8.4 / 7.4.1 | N | No | Beats input DoS. Never test. |
| CVE-2026-33466 | 8.0.0 up to 8.19.13 (9.x branches per Elastic advisory (verify)) | 8.19.14 (verify) | N, AC:H | No | Archive extraction path traversal to arbitrary file write. Needs an attacker-controlled or compromised update endpoint serving the archive; not reachable from an exposed port alone. |

---

## Fluentd (forward 24224, monitor 24220, debug 24230, RPC 24444, http 9880)

`in_forward` binds `0.0.0.0:24224` (TCP plus UDP heartbeat). With a `<security>`
section (`shared_key`, optional `user_auth`) the server opens with a `HELO`
message carrying a nonce and auth salt; without it there is no handshake and any
client can send events.

`in_monitor_agent` binds `0.0.0.0` by default and "does not provide an
authentication mechanism". Its `include_config` option defaulted to true until
v1.19.3 changed the default to false; with it on, plugin configs (passwords,
shared keys, cloud credentials) are returned.

```bash
# Forward: connect, read for 3 s, send nothing. A msgpack array starting with
# "HELO" means shared_key auth is on; silence means no handshake.
timeout 5 nc -w 3 192.0.2.10 24224 </dev/null | head -c 512 | xxd | head -5
# Monitor agent: plugin list (and configs on older versions).
curl -s -m 10 http://192.0.2.10:24220/api/plugins.json | head -c 300000 \
  | python3 -c 'import json,sys; [print(p.get("plugin_category"), p.get("type"), sorted((p.get("config") or {}).keys())) for p in json.load(sys.stdin)["plugins"]]'
curl -s -m 10 http://192.0.2.10:24220/api/config.json | head -c 5000
```

Print config keys first, as above; look at values only for the keys that matter
(`password`, `shared_key`, `aws_key_id`, `aws_sec_key`, `token`) and redact them
in evidence.

Never: connect a dRuby client to 24230 (the debug agent exposes the engine
object; that is code execution), send any HTTP request to the RPC port 24444
(`/api/processes.interruptWorkers`, `killWorkers`, `zeroDowntimeRestart`,
`flushBuffersAndKillWorkers`, `/api/plugins.flushBuffers`, `/api/config.reload`,
`gracefulReload` act on GET), or post to `in_http`.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2026-44024 | before 1.19.3 | 1.19.3 | N | No | Arbitrary file write leading to RCE through the `${tag}` placeholder when an attacker controls the tag (open forward or http input feeding a file-path output). Version plus open input plus config evidence; never send a crafted tag. |
| CVE-2026-44025 | before 1.19.3 | 1.19.3 | N | No | Sensitive information exposure through the monitor agent API. Confirmed by the 24220 read above. |
| CVE-2026-44160 | before 1.19.3 | 1.19.3 | N | No | Gzip decompression bomb in `in_http` and `in_forward`. DoS class: never test. |
| CVE-2026-44161 | before 1.19.3 | 1.19.3 | N | No | SSRF: `out_http` endpoints with placeholders such as `${tag}` let an attacker who controls the tag choose the destination host. |
| CVE-2022-39379 | 1.13.2 before 1.15.3 | 1.15.3 | L, AC:H | No | Deserialization RCE, only with non-default `FLUENT_OJ_OPTION_MODE`. |
| CVE-2021-41186 | before 1.14.2 | 1.14.2 | N | No | ReDoS in `parser_apache2`. Never test. |

---

## Fluent Bit (HTTP server 2020, forward 24224)

The built-in HTTP server is off until `http_server on`; documented examples use
`http_listen 0.0.0.0` and `http_port 2020`.

```bash
curl -s -m 10 http://192.0.2.10:2020/ | head -c 2000          # {"fluent-bit":{"version":...,"edition":...,"flags":[...]}}
curl -s -m 10 http://192.0.2.10:2020/api/v1/health | head -c 200
curl -s -m 10 http://192.0.2.10:2020/api/v1/metrics | head -c 50000   # input/output plugin names and record counts
```

`/api/v1/metrics` names every input and output instance (for example `tail.0`,
`es.0`, `s3.1`), which maps the pipeline. `/api/v2/reload` (POST/PUT hot reload)
and the trace endpoint `/api/v1/traces` (CVE-2024-4323) are forbidden.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2024-4323 | 2.0.7 up to 3.0.3 | 3.0.4 | N | No | Memory corruption in the HTTP server trace endpoint ("Linguistic Lumberjack"). Version gate plus `http_server` reachable. Never send the request. |
| CVE-2025-12969 | before 4.0.13 | 4.0.13 | N | No | `in_forward` `security.users` authentication bypass: an "authenticated" forward input accepts anyone. |
| CVE-2025-12972 | before 4.0.12 | 4.0.12 | N | No | Path traversal through tag values in `out_file`. |
| CVE-2025-12977 | before 4.0.12 | 4.0.12 | N | No | `in_http`, `in_splunk` and `in_elasticsearch` do not sanitize `tag_key` values. |
| CVE-2025-12970 | before 4.0.12 (verify) | 4.0.12 (verify) | L | No | `in_docker` copies container names into a fixed-size stack buffer. Not external. |
| CVE-2024-23722, CVE-2024-50608, CVE-2024-50609, CVE-2021-36088 | per record | per record | N | No | DoS class. Never test. |

---

## Elastic APM Server (8200)

`GET /` (or `HEAD /`) returns `build_date`, `build_sha`, `version` (and
`publish_ready`) only when the request counts as authorized; with no secret token
or API key configured every request is authorized. `POST /` answers "this is the
server information endpoint; did you mean to send data to another endpoint
instead?".

```bash
curl -s -m 10 -D - http://192.0.2.10:8200/ | head -c 2000
```

A version body without credentials means the server does not require a secret
token or API key, so the intake endpoints accept events from anyone (verify
against the version's auth model before grading). An empty body means auth is on
or anonymous access is restricted.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2023-31416 | Elastic Cloud on Kubernetes before 2.8 with APM Server 8.0+ | ECK 2.8 | N | No | The configured secret token was never applied: anonymous ingest accepted. Same signal as above. |

Other APM Server CVEs found (CVE-2024-23448, CVE-2024-37286) are local or
adjacent-network; not external. F5 BIG-IP APM is a different product.

---

## Sentry self-hosted (9000 behind nginx, or 443)

```bash
curl -s -m 10 http://192.0.2.10:9000/_health/ | head -c 200
curl -s -m 10 http://192.0.2.10:9000/auth/login/ | head -c 200000 | grep -oiE 'sentry[^"<]{0,60}' | sort -u | head
```

The version is not reliably exposed unauthenticated (verify). Project DSNs in
front-end JavaScript are public by design: a DSN alone is not a finding. Sending
an event through `/api/<project>/envelope/` is Stage B. Ivanti Sentry is a
different product (its KEV rows CVE-2023-38035 and CVE-2026-10520 do not apply).

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2025-22146 | 21.12.0 before 25.1.0 | 25.1.0 | N | No | SAML SSO user impersonation; needs multi-organization mode (`SENTRY_SINGLE_ORGANIZATION` false) and SAML. |
| CVE-2026-27197 | 21.12.0 before 26.2.0 | 26.2.0 | N | No | SAML identity linking. |
| CVE-2026-42354 | 21.12.0 before 26.4.1 | 26.4.1 | N | No | SAML identity linking. |
| CVE-2023-39349 | 22.1.0 before 23.7.2 | 23.7.2 | L | No | Privilege escalation via ApiTokensEndpoint. |
| CVE-2023-36826 | 8.21.0 before 23.5.2 | 23.5.2 | L | No | Improper authorization on debug and artifact file downloads. |
| CVE-2026-52794 | 24.4.0 before 26.5.2 | 26.5.2 | N | No | ReDoS. Never test. |

---

## Splunk HEC (8088) and S2S (9997)

`GET /services/collector/health` answers `{"text":"HEC is healthy","code":17}`
(verify) without a token. That fingerprints HEC; it does not mean ingest is open,
because every event needs a token. 9997: TCP connect only. All Splunk CVEs,
including the KEV-listed CVE-2026-20253, are in `hunt-exposed-services`
(`references/databases.md`).

---

## syslog (514/udp, 514/tcp, 601/tcp, 6514/tcp TLS): fingerprint rows only

| Port | What you can prove without writing | Note |
|---|---|---|
| 514/udp | Nothing. An nmap "open or filtered" UDP state is not a finding. | Classic rsyslog/syslog-ng/SIEM collector port. |
| 514/tcp | A TCP listener. | IANA assigns 514/tcp to rsh (`shell`); do not assume syslog. |
| 601/tcp | A TCP listener. | RFC 3195 reliable syslog. |
| 6514/tcp | TLS handshake and certificate (collector hostname, internal CA). | `openssl s_client -connect host:6514 </dev/null` |

Sending a test message (`logger -n`, netcat) is Stage B: it lands in the client's
SIEM, can trigger correlation rules and cannot be removed by you. Injection
payloads aimed at log parsers are forbidden here; syslog-ng config injection lives
in `hunt-rce`.

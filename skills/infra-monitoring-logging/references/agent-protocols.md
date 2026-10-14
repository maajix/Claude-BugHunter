# Agent protocols: Zabbix, NRPE, NSClient++, Icinga 2, Checkmk

Monitoring agents are built to answer one trusted poller. Exposed to the internet,
they answer you instead. This file owns the agent and trapper ports; the web
frontends of Zabbix belong to `hunt-exposed-panels`, SNMP get/walk on 161 to
`hunt-exposed-services` (`references/management-interfaces.md`).

Anything marked "(verify)" was not confirmed against a primary source on
2026-10-13; check it before quoting it in a report. KEV status is from the CISA
catalog version 2026.10.13.

---

## Zabbix agent / agent 2 (10050) and server/proxy trapper (10051)

### Wire format

Every Zabbix TCP message starts with a header: `ZBXD`, one flags byte (`0x01`
Zabbix protocol, `0x02` compressed, `0x04` large packet), a 4-byte little-endian
data length, and 4 reserved bytes (the uncompressed length when `0x02` is set,
else 0). Payloads are capped at 1 GB (16 GB with `0x04`).

Passive checks: the server connects to the agent on 10050 and asks for one item
key. Since Zabbix 7.0 the server sends JSON
(`{"request":"passive checks","data":[{"key":"agent.ping","timeout":3}]}`) and falls
back to the plaintext key for agents older than 7.2. Whether 7.x agents still
accept the bare plaintext key is (verify); try the plaintext form first because it
works on every older agent.

Active checks and trapper: agents and `zabbix_sender` connect to the server or
proxy on 10051. Request types include `active checks`, `agent data`, `sender data`,
`proxy config` and `zabbix.stats`.

### Default auth posture

| Control | Default | What it means externally |
|---|---|---|
| Agent `Server=` (passive allow-list) | Set to the server IP in the shipped config | An agent that answers you has `Server=` widened (often `0.0.0.0/0`) or a NAT rule maps your traffic to an allowed source. When your IP is not allowed the agent accepts the TCP connection, logs a rejection and closes without data (verify). |
| `AllowKey` / `DenyKey` | "All `system.run` items are disabled by default (even when DenyKey is empty)" | Remote commands need an explicit `AllowKey=system.run[*]`. Older agents used `EnableRemoteCommands` instead (verify the cut-over release). |
| `vfs.file.contents` | Not denied by default; the docs warn about path traversal | An agent that answers you can usually read any file the `zabbix` user can read. That read is Stage B. |
| TLS / PSK | Unencrypted unless `TLSConnect`/`TLSAccept` are set | A passive answer over plaintext means no PSK or certificate requirement. |
| Trapper item "Allowed hosts" | Empty | "If specified, incoming connections will be accepted only from the hosts listed here"; empty accepts any source. |
| `StatsAllowedIP` (server/proxy) | Unset | "If this parameter is not set no stats requests will be accepted." |
| Autoregistration | Configured per action | "Autoregistration can happen when a previously unknown active agent asks for checks." An `active checks` request from you can create a host. |

### Stage A

```bash
# Z1. Passive agent: agent.* keys only. One connection per key, 10 s apart.
zabbix_get -s 192.0.2.10 -p 10050 -t 5 -k agent.version
zabbix_get -s 192.0.2.10 -p 10050 -t 5 -k agent.hostname

# Same probe without zabbix_get (plaintext key form, framed with the ZBXD header).
python3 - 192.0.2.10 agent.version <<'PY'
import socket, struct, sys
host, key = sys.argv[1], sys.argv[2].encode()
s = socket.create_connection((host, 10050), timeout=5)
s.sendall(b"ZBXD\x01" + struct.pack("<II", len(key), 0) + key)
print(s.recv(4096)); s.close()
PY

# Z2. Server/proxy trapper: one internal-stats request. A ZBXD-framed reply of
# any kind proves a Zabbix server or proxy; a stats body proves StatsAllowedIP
# admits your address. The denial text is (verify).
python3 - 192.0.2.10 <<'PY'
import socket, struct, sys
data = b'{"request":"zabbix.stats"}'
s = socket.create_connection((sys.argv[1], 10051), timeout=5)
s.sendall(b"ZBXD\x01" + struct.pack("<II", len(data), 0) + data)
print(s.recv(65536)[:2048]); s.close()
PY
```

Read the result:

- `agent.version` returns a version string: the agent accepts passive checks from
  the internet. `agent.hostname` returns the Zabbix host name, which is usually an
  internal FQDN.
- `ZBX_NOTSUPPORTED` on `agent.*` keys is unusual and points to a proxy or an
  `AllowKey`/`DenyKey` policy; record it, do not escalate keys.
- Connection accepted, no data, closed: the allow-list works. Not a finding.
- `zabbix.stats` body: server version, queue sizes, internal process counts and
  cache usage. Low on its own; it proves StatsAllowedIP is open to the world.

### Needs Stage B sign-off

| Action | Why it is not Stage A |
|---|---|
| Any data key beyond `agent.*` (`system.uname`, `vfs.file.contents[...]`, `net.if.discovery`) | Reads host data or files through the agent. `vfs.file.contents` is a file read on the target. |
| `system.run[...]` | Remote command execution, even with a benign marker. Only when `AllowKey` permits it, one command, written sign-off. |
| `active checks` request to 10051 | Can trigger autoregistration on every refresh, creating a host and firing the client's registration actions. |
| `sender data` / `zabbix_sender` | Writes a value into a trapper item, or fails loudly in the server log. |
| SNMP traps toward a Zabbix trap receiver | See CVE-2024-42332 and CVE-2026-59787 below; trap content is parsed into Zabbix. Injection payloads are forbidden. |

### Zabbix CVE rows owned here (agent, agent 2, trapper, trap receiver)

Frontend and API CVEs (CVE-2022-23131, CVE-2024-42327, CVE-2024-22120) are
probed in `hunt-exposed-panels`; KEV status for those and for CVE-2022-23134
(setup.php, not in panels' list) is in `cve-matrix.md`.

| CVE | Component | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|---|
| CVE-2020-11800 | Server trapper (active proxy) | 2.2.x, 3.0.x before 3.0.31, 3.2 | 3.0.31 for the 3.0 branch (verify for 2.2 and 3.2) | N, AC:H | No | Pre-auth RCE against old servers via the trapper. Version gate only. |
| CVE-2026-59786 | Server/proxy trapper, active agent heartbeat | 7.0.0-7.0.28, 7.4.0-7.4.12 | next release (verify) | N | No | Heartbeats are accepted regardless of the configured PSK or certificate: anyone reaching 10051 can mark an active-agent host as available. Integrity only. |
| CVE-2026-59787 | `zabbix_trap_receiver.pl` | 6.0.0-6.0.47, 7.0.0-7.0.28, 7.4.0-7.4.12 | next release (verify) | L | No | ZBXTRAP record-delimiter injection: a crafted trap injects a record for another host. |
| CVE-2024-42332 | SNMP trap log parsing | 6.0.0 before 6.0.34, 6.4.0 before 6.4.19, 7.0.0 before 7.0.4 | 6.0.34 / 6.4.19 / 7.0.4 | N, AC:H | No | Forged lines shown in the UI; needs SNMP auth off or a known community, and a text SNMP item. |
| CVE-2025-27233 | Agent 2 smartctl plugin | 6.0.0-6.0.39, 7.0.0-7.0.10, 7.2.0-7.2.4 | next release (verify) | H, AV:A | No | `smart.disk.get` argument injection; can leak the NTLMv2 hash on Windows. |
| CVE-2025-27234 | Agent 2 smartctl (5.0) | 5.0.0-5.0.46 | (verify) | H, AV:A | No | Same injection; remote code execution on 5.0. |
| CVE-2026-23924 | Agent 2 Docker plugin | 6.0.0-6.0.43, 7.0.0-7.0.22, 7.4.0-7.4.6 | next release (verify) | H | No | `docker.container_info` injection: read files from running containers. |
| CVE-2026-23927 | Agent 2 Oracle plugin | 6.0.0-6.0.44, 7.0.0-7.0.23, 7.4.0-7.4.7 | next release (verify) | H | No | TNS connect-string injection; can leak saved Oracle credentials to an attacker server. |
| CVE-2022-43516 | Windows MSI packages built 2022-10-29 to 2022-12-02 | packages from 2022-12-03 | N, AC:H | No | Installer created an allow-all firewall rule for the agent: a cause of exposure, cite it when a Windows agent answers you. |
| CVE-2024-36462, CVE-2024-45700 | 7.0.0alpha1-rc2; server up to 6.0.38, 7.0.9, 7.2.3 | per record | N | No | DoS class (45700 is decompression, AV:A in record). Never test; version gate only. |

The Agent 2 rows carry PR:H in their records: the attacker must be able to choose
the item key, which externally means the agent already answers you (Z1) and the
plugin is loaded. Report them as impact of an open agent, not as separate bugs.

---

## NRPE (5666)

NRPE runs Nagios plugins on request from `check_nrpe`. Shipped `nrpe.cfg`
defaults: `allowed_hosts=127.0.0.1,::1`, `dont_blame_nrpe=0` (no client
arguments), `ssl_use_adh` commented out. When `allowed_hosts` rejects you the
daemon drops the connection and `check_nrpe` reports an SSL handshake error (exact
text varies by version (verify)).

```bash
# N1. Version only. Without -c, check_nrpe sends the internal _NRPE_CHECK
# command, which returns the daemon version and runs no plugin.
check_nrpe -H 192.0.2.10 -p 5666 -t 10
# Legacy listener without TLS:
check_nrpe -H 192.0.2.10 -p 5666 -t 10 -n
# TLS certificate (many installs use a self-signed cert naming the host):
openssl s_client -connect 192.0.2.10:5666 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

`NRPE v4.x.y` in reply: the daemon accepts you, so `allowed_hosts` is open or
missing. The finding is "anyone can ask this host to run its configured checks";
the commands themselves are not visible without running them.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2020-6581 | NRPE 3.2.1 | 4.0.x (verify) | N, needs `dont_blame_nrpe=1` | No | `\n` missing from nasty metacharacters: command injection through arguments. The 4.1.0 changelog notes a nasty_metachars default fix. |
| CVE-2020-6582 | NRPE 3.2.1 | 4.0.x (verify) | N | No | Heap overflow. Never test. |

Stage B: `check_nrpe -c <command>` runs a plugin on the target. One stock command
named in the sign-off (for example `check_users`), no arguments. Argument passing
and `nmap --script nrpe-enum` (categories discovery, intrusive: it executes the
stock command list) are forbidden.

---

## NSClient++ (8443 web/REST, 12489 check_nt, 5666 NRPE)

Defaults from the WEBServer documentation: port 8443, `allowed hosts` 127.0.0.1,
`bind to` blank (all interfaces), `password` empty, admin user enabled, anonymous
access false. Legacy installs with `allowed hosts` blank accepted anyone (forum
reports; (verify) per version).

```bash
# S1. Web/REST listener: headers, title, certificate. One request.
curl -sk -m 10 -D - -o /dev/null https://192.0.2.10:8443/
openssl s_client -connect 192.0.2.10:8443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
# S2. check_nt / NRPE ports: TCP connect only in Stage A.
nc -vz -w 5 192.0.2.10 12489
```

A `check_nt -v CLIENTVERSION` query sends the (often empty) password field, so it
is a credential attempt: Stage B, one try. The REST API login and anything under
ExternalScripts are Stage B or forbidden.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2025-34079 | 0.5.2.35 | (verify) | H | No | With the web interface and ExternalScripts enabled, the admin password allows command injection via `/settings/query.json`, run through `/query/<name>` as SYSTEM. Reportable from version plus exposure; never reproduce. |
| CVE-2025-34078 | 0.5.2.35 | (verify) | local | No | Local privilege escalation; plaintext password in `nsclient.ini`. Not external. |

---

## Icinga 2 API and cluster (5665)

The REST API and the cluster JSON-RPC share 5665 (`icinga2 api setup`). API users
authenticate with basic auth or a client certificate (`client_cn`); cluster
endpoints with certificates signed by the Icinga CA.

```bash
# I1. One unauthenticated request: expect 401 and the Server header. The source
# sets "Icinga/" + the application version (format such as r2.14.3 (verify)).
curl -sk -m 10 -D - -o /dev/null https://192.0.2.10:5665/v1
# I2. Certificate: subject CN is the node name (usually an internal FQDN),
# issuer is the Icinga CA. Acceptable client CA names leak in the handshake.
openssl s_client -connect 192.0.2.10:5665 </dev/null 2>/dev/null | grep -E "subject=|issuer=|Acceptable client certificate CA names" -A2
```

Report an exposed 5665 as exposure plus version (Low, or High-unconfirmed when the
version is inside CVE-2024-49369). Endpoints `/v1/console` (execute-script),
`/v1/actions/*`, `/v1/config/stages` and object writes are never touched; a
credential that works is Stage B and the finding stops at `/v1/status` or an
equivalent read.

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2024-49369 | 2.4.0 up to before 2.11.12, 2.12.11, 2.13.10, 2.14.3 | 2.11.12 / 2.12.11 / 2.13.10 / 2.14.3 | N | No | TLS certificate validation bypass for JSON-RPC and HTTP API: impersonate nodes or API users. The headline external Icinga issue. |
| CVE-2025-48057 | before 2.12.12, 2.13.0-2.13.11, 2.14.0-2.14.5 | 2.12.12 / 2.13.12 / 2.14.6 | N | No | Certificate renewal may renew an invalid certificate. |
| CVE-2020-29663 | 2.8.0-2.11.7, 2.12.0-2.12.2 | 2.11.8 / 2.12.3 | N | No | Revoked certificates due for renewal were renewed automatically. |
| CVE-2021-32743 | before 2.11.10, 2.12.0-2.12.4 | 2.11.10 / 2.12.5 | L | No | Passwords for external services exposed through the API to API users. |
| CVE-2025-61907 | 2.4.0 before 2.13.13, 2.14.0 before 2.14.7, 2.15.0 | 2.13.13 / 2.14.7 / 2.15.1 | L | No | API filter expressions read objects and globals the user may not see. |
| CVE-2025-61908 | 2.10.0 before 2.13.13, 2.14.0 before 2.14.7, 2.15.0 | 2.13.13 / 2.14.7 / 2.15.1 | L | No | Filter expression crashes the daemon. DoS class: never test. |
| CVE-2018-6532 | up to 2.8.1 | 2.8.2 (verify) | N | No | Memory exhaustion. DoS class: never test. |

Icinga Web 2 (the PHP frontend, usually `/icingaweb2/`) rows are in `cve-matrix.md`.

---

## Checkmk agent (6556), agent receiver (8000), mknotifyd

Default Linux agent packages open 6556 and, until the agent is registered for TLS,
"output unencrypted agent data via this port to anyone requesting it". A registered
agent controller answers `16` and waits for TLS instead.

Stage A for 6556 is existing third-party scan data only (Shodan, Censys via
`offensive-osint`). Any live connection, including a bare port check, makes a
pull-mode agent (xinetd, systemd socket or agent controller in legacy mode) run
every section, local check and MRPE plugin, exactly like a real poll.

```bash
# C1. Stage B only, with written sign-off. Blast radius: one full agent poll,
# including local checks and MRPE plugins, and one entry in the agent's log.
# One connection, read the header, close. Never loop it.
nc -w 5 192.0.2.10 6556 </dev/null | head -c 4096
```

Read the result:

| Reply | Meaning |
|---|---|
| `16` | TLS-registered agent controller. Not a finding by itself. |
| `<<<check_mk>>>` then `Version:`, `AgentOS:`, `Hostname:`, `AgentDirectory:`, `PluginsDirectory:`, `AgentController:` | Legacy pull mode, plaintext. Stop reading after the header; the full output that follows contains process lists, mounts, packages and local check output. Medium to High by content. |
| Connection reset or closed | `only_from` or a firewall restricts the agent. |

The agent receiver (registration API) listens on 8000 for the first site (8001
for a second). Its TLS certificate names the site CA (verify). The notification
spooler `mknotifyd` port is 6555 by default (verify).

| CVE | Affected | Fixed | PR | KEV | Note |
|---|---|---|---|---|---|
| CVE-2022-48321, CVE-2022-47909, CVE-2022-46836 | 2.1.0 up to 2.1.0p11; 2.0.0 up to 2.0.0p28; 1.6.0 up to 1.6.0p30 (per-CVE ranges differ) | 2.1.0p12 / 2.0.0p29 (verify) | records say AV:L or PR:L | No | Agent-receiver SSRF, Livestatus LQL injection through HTTP headers and PHP code injection in watolib. Published together as a chain to pre-auth RCE (SonarSource 2022 (verify)). Version gate only. |
| CVE-2024-6163 | 2.3.0 before p10, 2.2.0 before p31, 2.1.0 before p46, 2.0.0 up to p39 | 2.3.0p10 / 2.2.0p31 / 2.1.0p46 | N | No | Local-IP restriction of internal HTTP endpoints bypassable. |
| CVE-2025-3506 | 2.4.0 before b6, 2.3.0, 2.2.0, 2.1.0 up to p50 | 2.4.0b6 and per-branch patches (verify) | N | No | Sensitive agent-deploy path exposed through an unauthenticated route. |
| CVE-2026-2859 | 2.4.0 before p23, 2.3.0 before p43, 2.2.0 | 2.4.0p23 / 2.3.0p43 | N | No | Unauthenticated host enumeration through response differences on the deploy-agent endpoint. Probing it is enumeration: Stage B. |
| CVE-2024-6747 | 2.3.0 before p18, 2.2.0 before p36, 2.1.0 before p49, 2.0.0 up to p39 | 2.3.0p18 / 2.2.0p36 / 2.1.0p49 | N | No | Information leak in mknotifyd. |
| CVE-2024-6542 | 2.3.0 before p11, 2.2.0 before p32, 2.1.0 before p47, 2.0.0 up to p39 | 2.3.0p11 / 2.2.0p32 / 2.1.0p47 | N | No | Livestatus injection in mknotifyd. |
| CVE-2023-1768 | up to 2.1.0p25, 2.0.0p34, 2.2.0b3, all 1.6.0 | 2.1.0p26 / 2.0.0p35 / 2.2.0b4 (verify) | N, AC:H | No | Symmetric agent encryption failed silently and sent plaintext. Cite when C1 shows plaintext despite the client claiming encryption. |

---

## SNMP trap receivers (162/udp)

A trap receiver (snmptrapd, Zabbix trap receiver, NMS collectors) never answers.
`nmap -sU` reports `open|filtered`, which proves nothing. There is no read path;
the only test is sending a trap, which is Stage B (a canary trap lands in the
client's NMS and may alert on-call), and trap content aimed at a parser
(CVE-2024-42332, CVE-2026-59787) is forbidden. SNMP get/walk on 161 belongs to
`hunt-exposed-services`.

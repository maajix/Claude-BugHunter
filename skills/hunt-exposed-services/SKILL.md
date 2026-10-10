---
name: hunt-exposed-services
description: "Triage internet-exposed non-HTTP services and management interfaces: a port answering from the public internet that belonged behind a firewall or VPN. Covers Redis 6379, MongoDB 27017, Elasticsearch 9200, Kibana 5601, CouchDB 5984, InfluxDB 8086, memcached 11211, PostgreSQL 5432, MySQL 3306, Oracle TNS 1521, HSQLDB 9001, RabbitMQ 15672, AMQP 5672, MQTT 1883/8883, NATS 4222, IBM MQ 1414, EPMD 4369, Java RMI 1099, JDWP, AJP 8009, FastCGI 9000, ADB 5555, distcc 3632, X11 6000, VNC 5900, SNMP 161/udp, IPMI BMC 623/udp, WinRM and OMI 5985/5986, LDAP 389/636, Telnet 23, rlogin/rsh 512-514, TFTP 69/udp, rsync 873, NFS 2049, iSCSI 3260, GlusterFS 24007, IPP 631, PJL 9100, RTSP 554/8554, Modbus 502, BACnet 47808/udp, EtherNet/IP 44818, OPC UA 4840, Cisco Smart Install 4786, SAProuter 3299, NDMP 10000. Stage A read-only detection by default, state-changing probes gated on written sign-off. Use when a port scan shows a non-HTTP port open on an in-scope external host."
sources: hacktricks_coverage_checklist, nvd, vendor_advisories, cisa_kev, project_documentation, rfc, authorized-engagement
report_count: 0
---

## When to use

Trigger when external recon has already produced an open non-HTTP port on a host
you are authorized to test, and you need to decide whether that open port is a
finding. The finding here is **the exposure itself plus what it leaks or grants**,
not a memory-corruption bug you wrote yourself.

Use when any of these is true:

- A port scan or Shodan/Censys record shows a service port from the triage table
  in Step 3 answering on a public address.
- A TLS certificate, reverse-DNS name or banner names a database, broker, BMC,
  printer, camera or PLC.
- The client's asset inventory says "internal only" and you can reach it anyway.
- A firewall or VPN migration is suspected to have left a management plane open.

**Do not use this skill for discovery.** Host, port and ASN discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation belongs to
`recon-scope-triage`. This skill starts from "a port is open and in scope".

### Where the chain ends

This skill stops at **unauthenticated access confirmed, impact described,
evidence captured**. It deliberately contains nothing about what you do once you
are inside: no OS privilege escalation, no lateral movement or pivoting, no
Active Directory, no credential dumping, no persistence, no C2, no evasion. If a
service hands you a shell, you have the finding already. Write it up and stop.

Two concrete cuts that follow from this, because the usual public write-ups walk
straight past them:

- Redis: stop at an unauthenticated `INFO`. Writing `authorized_keys` or a cron
  entry through `CONFIG SET` is persistence, and `REPLICAOF` against a rogue
  master destroys the dataset.
- SAProuter: stop at the route-table or info response. Routing a connection
  through it to an internal host is pivoting.

### Not covered here, on purpose

SMB/NetBIOS (139/445), MSRPC (135), MSSQL (1433), FTP (21), RDP (3389) and
Kerberos (88) are treated as internal-network services by this bundle and are
excluded by `SECURITY.md`. Appliance management planes already have owners:
SSL VPN and remote-access gateways in `enterprise-vpn-attack`, vCenter and
Workspace ONE in `vmware-vcenter-attack`, Kubernetes API/kubelet/etcd and
Docker in `hunt-k8s`, cloud-managed service exposure in `hunt-cloud-misconfig`.

---

## Step 1 — Inherit the port list, never generate it

Take the host list from the signed scope document and the port list from the
recon phase. Two rules, both non-negotiable:

- **Never scan address space the client does not own.** Confirm ownership per IP
  before you send a packet to it: ASN and WHOIS/RDAP lookup, plus reverse DNS.
  Shared hosting, CDN edge ranges and cloud provider pools routinely answer for
  addresses that are not in scope.
- **Never mass-scan.** This skill has no step that sweeps a /16. If the operator
  wants broad discovery, that is a Shodan/Censys query against data someone else
  already collected, which is `offensive-osint`'s job.

### Rate posture for every looping step in this skill

Serial, one host at a time, with jitter. The default:

```bash
# 2s base delay + 0-3s jitter between probes, one host at a time.
# Industrial and camera targets: raise the base delay to 10s (see Step 5).
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }

for host in $(cat scope-hosts.txt); do
  # ... one Stage A probe ...
  probe_delay
done
```

A probe that times out is a result. Do not retry it more than once, and never
tighten the delay to "get through the list faster". Many of the services below
are single-threaded or embedded; a retry storm is a denial of service with extra
steps.

---

## Step 2 — Prove the exposure is real, external, and the client's

Four false-positive classes kill more of these findings than anything else.
Clear all four before you write a word of the report.

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from a host outside any client VPN, tunnel or office range. Note the egress IP in evidence. | "Exposed" means exposed. A port reached over the client's own VPN is not a finding. |
| IP ownership | ASN + WHOIS/RDAP + reverse DNS per address; cross-check the scope document. | Testing a neighbour's host on shared infrastructure is unauthorized access. |
| Honeypot | Many "services" on one host with identical uptime, implausible banner combinations, a PLC that answers every function code instantly, Conpot/Dionaea fingerprints. | Industrial honeypots are common. A Conpot finding is a reputational problem, not a report. |
| Filtering vs service | Compare against a closed port on the same host and a known-good host. A middlebox that completes the TCP handshake for everything makes every port look open. | Handshake-completing load balancers and scrubbing services fake open ports wholesale. |

Record the baseline raw response for every probe before any Stage B work, so a
later diff has something to diff against.

---

## Step 3 — Triage the open port to one reference file

Load **only** the reference file the port maps to. Do not read all seven.

| Port(s) | Service | Load |
|---|---|---|
| 6379, 27017, 9200, 5601, 5984, 8086, 11211, 9042, 5432, 3306, 1521, 9001, 8089, 9870, 8088 | Redis, MongoDB, Elasticsearch, Kibana, CouchDB, InfluxDB, memcached, Cassandra, PostgreSQL, MySQL, Oracle TNS, HSQLDB, splunkd, Hadoop | `references/databases.md` |
| 5672, 15672, 1883, 8883, 4222, 8222, 1414, 4369 | AMQP, RabbitMQ management, MQTT, NATS, IBM MQ, Erlang EPMD | `references/message-brokers.md` |
| 1099, 8009, 9000, 6000-6005, 3632, 5555, any JDWP port, gdbserver | Java RMI, AJP, FastCGI, X11, distcc, ADB, JDWP, gdbserver | `references/remote-debug.md` |
| 623/udp, 161/udp, 5985, 5986, 5900-5906, 389, 636, 3268, 264, 4786, 12346/udp, 3299, 9401, 10000 | IPMI/BMC, SNMP, WinRM/OMI, VNC, LDAP, Check Point FW-1, Cisco Smart Install, Cisco SD-WAN, SAProuter, Veeam B&R, NDMP | `references/management-interfaces.md` |
| 502, 47808/udp, 44818, 4840, 554, 8554, 32100/udp, 20000 | Modbus, BACnet/IP, EtherNet/IP, OPC UA, RTSP cameras, PPPP/CS2 cameras, DNP3 | `references/industrial-and-iot.md` |
| 631, 9100, 515, 69/udp, 873, 2049, 111, 3260, 24007, 3690, 548 | IPP/CUPS, raw PJL printing, LPD, TFTP, rsync, NFS, rpcbind, iSCSI, GlusterFS, SVN, AFP | `references/printers-and-storage.md` |
| 23, 512, 513, 514, 79, 113, 1026, 7, 123/udp, 1080, 3128, 5060, 5353/udp, 3702/udp | Telnet, rexec/rlogin/rsh, finger, ident, rusersd, echo, NTP, SOCKS, Squid, SIP, mDNS, WS-Discovery | `references/legacy-and-infoleak.md` |

If the port is not in the table, fingerprint it as an unknown service and
describe the exposure generically. Do not invent protocol specifics.

---

## Step 4 — Stage A: read-only fingerprint and unauthenticated-access test

**Stage A is the default and covers almost every finding in this skill.** A
Stage A probe must satisfy all of:

1. It only reads. No write, delete, publish, reboot, config change, mount or
   command execution.
2. It is a single request per service, not a loop over credentials or object IDs.
3. Its failure mode is a timeout or an error reply, never a service restart.
4. It leaves the service's state, queue depth, print spool and physical outputs
   untouched.

The generic shape, before any protocol-specific work:

```bash
TARGET="192.0.2.10"; PORT="6379"

# TCP banner, bounded, no payload sent beyond what the protocol needs
timeout 10 nc -v -w 5 "$TARGET" "$PORT" < /dev/null | head -c 2048 \
  | tee "evidence/${TARGET}_${PORT}_banner.raw"

# TLS-wrapped variant (many brokers and DBs answer only under TLS)
timeout 10 openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" \
  </dev/null 2>/dev/null | head -60
```

For version detection, keep nmap deliberately slow and keep its scripts inside
the `safe` category. **Verify before you run any NSE script you have not used
before:** `nmap --script-help <name>` prints the script's declared categories.
If the categories include `intrusive`, `exploit`, `brute`, `dos` or `vuln`, it is
not a Stage A probe. Verified traps in the standard distribution:

| Script | Declared categories | Why it is not detection |
|---|---|---|
| `distcc-cve2004-2687` | `exploit`, `intrusive`, `vuln` | Executes a command on the target. |
| `realvnc-auth-bypass` | `auth`, `safe`, `vuln` | Despite `safe`, it performs the CVE-2006-2369 bypass: it offers security type None even when the server did not. |
| `ipmi-cipher-zero` | `vuln`, `safe` | Despite `safe`, it sends an RMCP+ Open Session Request with cipher zero, crossing the authentication boundary. Use `ipmi-version` instead. |
| `iscsi-info` | `default`, `safe`, `discovery` | Despite `safe` **and** `default`, it calls `login()` on every discovered target. It creates sessions on a live storage target. |
| `mqtt-subscribe` | `safe`, `discovery`, `version` | Despite `safe`, it never sets clean-session, so the broker **keeps the session and its subscriptions after disconnect**. That is persistent state you left behind. |
| `socks-open-proxy`, `http-open-proxy` | `default`, `discovery`, `external`, `safe` | The `external` category is the tell: they relay through the target to real third-party sites. That is traffic you are not authorized to send. |
| `tftp-enum` | `discovery`, `intrusive` | Requests a filename wordlist plus 256 generated config names and reads file data. |
| `nfs-ls` | `discovery`, `safe` | Despite `safe`, it mounts every export and touches the server's mount table. Use `nfs-showmount`. |
| `pjl-ready-message` | `intrusive` | Reads status with no arguments, but **writes the printer's physical panel** once `pjl_ready_message` is set. |
| `modbus-discover` | `discovery`, `intrusive` | Loops unit IDs against a PLC. |
| `ntp-monlist` | `discovery`, `intrusive` | Sends the amplification request pair. |
| `rtsp-url-brute` | `brute`, `intrusive` | Stream-path wordlist against an embedded camera. |
| `bacnet-info`, `enip-info` | `discovery`, `version` (no `safe`) | Not declared safe; see the ICS reference. |
| any `*-brute` | `brute` | Credential guessing; belongs to `hunt-brute-force`. |

**Therefore `-sC` and `-A` are not Stage A.** Both pull the whole `default`
category, which includes `iscsi-info` (logs in to storage targets) and
`socks-open-proxy` and `http-open-proxy` (relay to third parties). Name the
scripts you want explicitly, every time.

Two further limits worth knowing: a `safe` category is the author's claim, not a
guarantee, so prefer a hand-issued protocol request when the stakes are
physical; and nmap's `Exclude` directive only suppresses **version detection**,
so a `--script` aimed at an excluded port still runs.

Per-family Stage A hard limits, before you open the reference file:

- **Raw print (9100, 515):** any byte sequence that is not a recognised PJL or
  PostScript query becomes a print job on real paper. Query subcommands only.
  Nmap ships `Exclude T:9100-9107` in `nmap-service-probes` precisely so that
  `-sV` does not do this; never override it with `--allports` against a printer.
- **VNC (5900+):** connect shared and view-only. An exclusive connection can
  disconnect the person currently using the console.
- **MQTT / NATS (1883, 8883, 4222):** subscribe with both a message cap and a
  time cap, and never publish. A publish on an IoT broker can move an actuator.
- **memcached (11211):** TCP `stats` only. At most one unspoofed UDP packet, and
  only to confirm the UDP listener exists; memcached UDP is an amplification
  reflector and a looping UDP probe is a DDoS rehearsal.
- **Industrial (502, 47808, 44818, 4840) and cameras (554, 32100):** passive
  Shodan/Censys lookup first, then detection only. See Step 5.
- **iSCSI (3260):** `sendtargets` discovery only. Logging in is Stage B and
  mounting is forbidden outright, read-only flag or not, because a mount can
  replay a filesystem journal and write to the LUN.

---

## Step 5 — Stage B: anything that changes state

Stage B is **blocked by default**. It requires explicit written operator
sign-off naming the specific action, the specific host, and a maintenance
window. Verbal approval, a Slack thumbs-up, or "the scope says critical findings
are in scope" is not sign-off.

Record this block in the engagement log before the first Stage B packet:

```
Stage B authorization
  Host/port:        192.0.2.10:5555
  Action:           single `adb shell id` on an exposed ADB daemon
  Blast radius:     command runs as the adbd user on a live device; the device
                    may be production hardware; the action is logged on-device
  Reversibility:    none (command execution cannot be un-run)
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

Actions that are always Stage B, with the blast radius you must state:

| Action | Blast radius to name in the sign-off |
|---|---|
| JDWP command execution | Code runs inside a live JVM. A wrong invocation hangs or kills the application. |
| `adb shell` on exposed ADB | Command execution on a live device, possibly production hardware or a kiosk. |
| Cisco Smart Install config fetch or change | Switch configuration and switch availability. Cisco's own advisory for CVE-2018-0171 names three possible impacts of the overflow: a device reload, arbitrary code execution, and an indefinite loop that triggers a watchdog crash. Two of those take the network segment with them. |
| NDMP operations beyond the version handshake | Backup and restore plane. A misdirected NDMP job can overwrite a backup set. |
| A crafted datagram to a `cups-browsed` UDP listener (CVE-2024-47176) | Plants an attacker-controlled print queue in the host's configuration and arms code execution as the `cups`/`lp` user the next time anyone prints to it. Sign-off must include verified removal of the planted queue. |
| distcc command execution | Arbitrary command on a build host as the distcc user. |
| iSCSI login / LUN access | A block device that other hosts may have mounted. Journal replay corrupts filesystems. |
| Any ICS or BACnet write function code | **Physical.** Valve positions, setpoints, breakers, building HVAC. |
| Camera stream capture beyond a `DESCRIBE` | Personal data of identifiable people, with the attendant legal exposure. |
| IPMI/BMC user or password change via cipher-0 | Out-of-band control of the server's power and console. |
| Cracking a captured IPMI RAKP hash | The hash is already the finding. Cracking it produces a live credential to a power-control plane. |
| Credential guessing of any kind | Account lockout, log flooding, and in `hunt-brute-force`'s territory, not this skill's. |

### Industrial control systems and cameras: a harder default

For anything in `references/industrial-and-iot.md` the default is **detection
only, with no active exploitation at all**, even with generic "critical findings
in scope" language in the contract.

An availability impact on a PLC, RTU, building controller or BMS is not a page of
downtime. It is a physical event: a pump that stops, a breaker that opens, a
chiller that trips, a door that unlocks. Many of these devices have no concept of
a malformed packet and fall over on a port scan alone. Treat every industrial
finding as reportable at the exposure level and escalate the decision to the
operator and the asset owner together, in writing, before anything beyond a
single read.

Rate bound for industrial targets: one request per device, at least 10 seconds
apart, serially, with no concurrent probing of the same site.

---

## Step 6 — Grade the finding by what the exposure actually grants

Grade on what you proved, not on what the protocol could theoretically allow.

| What you proved | Grade |
|---|---|
| Unauthenticated read of production data (records, documents, backups, credentials, PII) | Critical |
| Unauthenticated command execution or an administrative session on a production host | Critical |
| Unauthenticated access to a management plane that controls power, console, backups or network configuration | Critical |
| Default credentials accepted on a production service | Critical or High, by what the account can reach |
| Unauthenticated read of an industrial or safety-related control plane | Critical, and escalate immediately |
| Unauthenticated access to a non-production instance holding real data | High |
| Service exposed and fingerprinted, authentication present and enforced, version in CVE range | Medium, and say plainly that you did not exploit it |
| Information disclosure only: version, hostname, internal addressing, user list | Low to Medium, by what the leak enables |
| Service exposed, authenticated, no known reachable pre-auth issue | Informational, as a hardening item |

Two grading rules the triage side will hold you to: a version banner inside a
CVE range is **not** a confirmed vulnerability, and an amplification-capable
service (memcached UDP, NTP, SSDP) is a finding about the client being a
reflector for others, not about the client being compromised.

---

## Step 7 — Capture evidence once, immutably

Follow `evidence-hygiene` for storage and handling. Minimum set per finding:

- Raw protocol transcript with timestamps, saved at probe time, not reconstructed.
- The exact command run, including the source IP you ran it from.
- Service version and banner exactly as returned.
- A redacted sample proving the data class without exfiltrating the data: record
  counts, index or database names, field names, one redacted row. **Never pull
  the dataset.** Counting 4.1 million customer records proves impact; copying
  them creates a breach you are responsible for.
- For a camera or any system handling personal data, a written note that no
  stream or image was retained.

---

## Chain table

| Exposure confirmed | Realistic standalone severity | Where it goes next |
|---|---|---|
| Unauthenticated Redis, MongoDB, Elasticsearch or CouchDB with production data | Critical | Report. Do not write to it, do not use it as an RCE primitive. |
| Exposed JDWP, ADB, distcc or gdbserver | Critical (pre-auth code execution by design) | Report the exposure. Execution proof is Stage B and usually unnecessary. |
| Exposed IPMI/BMC with cipher-0 accepted or a RAKP hash returned | Critical | Report. Hash cracking and BMC login are Stage B. |
| Default credentials on RabbitMQ management, a printer, a camera or a BMC | Critical to High | Report with the account's visible privilege, nothing further. |
| Unauthenticated SNMP with a working community string | High | Config and interface leak. Full device enumeration via `offensive-osint`. |
| Anonymous LDAP bind returning rootDSE and naming contexts | Medium | Stop there. Directory enumeration against AD is out of scope. |
| Exposed WinRM/OMI | Medium to Critical by version | NTLM metadata leak belongs to `hunt-ntlm-info`. No shell. |
| Exposed Modbus, BACnet, EtherNet/IP or OPC UA | Critical as an exposure, regardless of reachable CVE | Escalate to operator plus asset owner. Detection only. |
| Exposed RTSP or PPPP camera, unauthenticated | High to Critical | Privacy impact. `DESCRIBE` only. |
| memcached, NTP or SSDP usable as an amplification reflector | Medium | Reflector finding, not a compromise. One probe, no loop. |
| TLS weakness on any of the above | Per `hunt-tls-network` | Separate finding, separate skill. |

---

## Validation checklist

Clear every line before filing. Each one has produced a withdrawn report.

- [ ] Probed from outside every client VPN, tunnel and office range, and the
      egress IP is in the evidence.
- [ ] Every target IP confirmed client-owned by ASN plus WHOIS/RDAP, and present
      in the signed scope document.
- [ ] Honeypot ruled out: banner combination is plausible, uptime and response
      timing are consistent, no Conpot/Dionaea fingerprint.
- [ ] Open-vs-filtered confirmed against a closed port on the same host, so a
      handshake-completing middlebox is excluded.
- [ ] The service was identified from its own protocol response, not from the
      port number alone. Port 10000 is NDMP in IANA's registry and Webmin in
      practice; 8086 is InfluxDB and also a common HTTP alt port.
- [ ] Unauthenticated access was proven by a protocol response that only an
      authenticated-or-open service returns, not by a bare TCP connect.
- [ ] Every probe run was Stage A, or has a logged written sign-off naming the
      host, the action and the blast radius.
- [ ] No `-sC`, no `-A`, and no `--script` category selection. Every NSE script
      was named individually and checked with `--script-help` first.
- [ ] No write, publish, mount, reboot, config change or credential guess was
      sent to any host.
- [ ] No dataset copied. Impact is evidenced by counts and names.
- [ ] Version-in-CVE-range findings are labelled unconfirmed, not exploited.
- [ ] Industrial and camera findings were escalated to the operator before
      anything beyond a single read, and no stream was retained.
- [ ] The report ends at exposure plus impact. No internal follow-up written.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `databases.md` | Redis 6379, MongoDB 27017, Elasticsearch 9200, Kibana 5601, CouchDB 5984, InfluxDB 8086, memcached 11211, Cassandra 9042, PostgreSQL 5432, MySQL 3306, Oracle TNS 1521, HSQLDB 9001, splunkd 8089, Hadoop 9870 and 8088 | exposed redis, open mongodb, elasticsearch no auth, couchdb admin party, influxdb auth bypass, memcached dump, oracle tns listener, exposed postgres, hadoop yarn exposed |
| `message-brokers.md` | AMQP 5672, RabbitMQ management 15672, MQTT 1883/8883, NATS 4222/8222, IBM MQ 1414, Erlang EPMD 4369 | exposed mqtt broker, mosquitto anonymous, rabbitmq guest guest, nats no auth, amqp exposed, ibm mq channel, epmd erlang cookie |
| `remote-debug.md` | Java RMI 1099, JDWP, AJP 8009 Ghostcat, FastCGI 9000, X11 6000-6005, distcc 3632, ADB 5555, gdbserver | exposed jdwp, java debug wire protocol, android debug bridge internet, adb 5555, ghostcat ajp, java rmi registry, distcc exposed, x11 no access control, fastcgi exposed |
| `management-interfaces.md` | IPMI/BMC 623/udp, SNMP 161/162, WinRM and OMI 5985/5986, VNC 5900-5906, LDAP 389/636/3268, Check Point FW-1 264, Cisco Smart Install 4786, Cisco SD-WAN 12346/udp, SAProuter 3299, Veeam B&R 9401, NDMP 10000 | exposed ipmi, bmc internet facing, cipher zero, rakp hash, snmp public community, exposed winrm, omigod, vnc no password, anonymous ldap bind, cisco smart install, saprouter exposed, veeam backup exposed, ndmp 10000 |
| `industrial-and-iot.md` | Modbus 502, BACnet/IP 47808/udp, EtherNet/IP 44818, OPC UA 4840, DNP3 20000, RTSP 554/8554, PPPP/CS2 cameras 32100/udp | exposed plc, modbus internet, bacnet exposed, ethernet ip 44818, opc ua anonymous, scada exposed, ics exposure, exposed rtsp camera, ip camera internet, pppp p2p camera |
| `printers-and-storage.md` | IPP/CUPS 631, raw PJL 9100, LPD 515, TFTP 69/udp, rsync 873, NFS 2049, rpcbind 111, iSCSI 3260, GlusterFS 24007, SVN 3690, AFP 548 | exposed printer, cups exposed, jetdirect 9100, open tftp, rsync module anonymous, nfs export world readable, iscsi target exposed, glusterfs exposed, svnserve exposed |
| `legacy-and-infoleak.md` | Telnet 23, rexec/rlogin/rsh 512-514, finger 79, ident 113, rusersd 1026, echo 7, NTP 123/udp, SOCKS 1080, Squid 3128, SIP 5060, mDNS 5353/udp, WS-Discovery 3702/udp | exposed telnet, rsh rlogin exposed, finger service, ntp monlist amplification, open proxy, open socks proxy, squid open proxy, exposed sip, mdns leak, ws-discovery exposed |

Attribution: the service and port coverage list was checked against the
HackTricks network-services-pentesting section
(<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0) used as a
checklist only. All prose, tables, staging and safety guidance here are
original; protocol facts, ports, flags and CVE identifiers were verified against
NVD, vendor advisories and project documentation.

---

## Related Skills & Chains

- `offensive-osint`, `web2-recon`, `recon-scope-triage` — host, port and ASN
  discovery, Shodan/Censys workflow, scope confirmation. They produce the input
  to Step 1; this skill does not re-teach any of it.
- `hunt-ssrf` — covers Redis and memcached reached **through** an SSRF in a web
  application, where the attacker has no direct route to the port and smuggles a
  protocol over `gopher://` or an HTTP fetcher. This skill is the opposite case:
  the port answers the attacker directly from the internet, so the finding is the
  firewall gap rather than the web application's URL handling. Same services,
  different root cause, different fix, different report.
- `hunt-nosqli` — injection into a datastore the application already reaches.
  This skill is about reaching the datastore yourself.
- `hunt-k8s` — Kubernetes API, kubelet, etcd, Docker socket.
- `hunt-tls-network` — TLS and certificate findings on any exposed port.
- `enterprise-vpn-attack`, `vmware-vcenter-attack` — SSL VPN gateways and
  vCenter/Workspace ONE appliances.
- `hunt-cloud-misconfig` — the same classes of datastore when they are a managed
  cloud service rather than a host you can port-scan.
- `hunt-ntlm-info` — NTLM metadata leaked by an exposed Windows management
  endpoint.
- `hunt-brute-force` — all credential guessing. This skill tests documented
  default credentials once, and nothing else.
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence handling,
  false-positive gates and write-up.

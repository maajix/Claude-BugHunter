---
name: infra-external-methodology
description: "Orchestrate an external infrastructure penetration test at the port and service layer: confirm scope and per-IP ownership, plan discovery (nmap top ports then the full range, targeted UDP, IPv6, when masscan, naabu or rustscan are acceptable and at what rate), exclude cloud and CDN ranges, fingerprint read-only, then route each open port to its owning skill through the master port-to-skill table (infra-* and hunt-exposed-* skills). Use for an external infra pentest, a perimeter assessment, reading nmap output, or asking which skill handles port N."
metadata:
  sources: nist_800_115, ptes, osstmm, nmap_docs, project_documentation, cloud_provider_policies, authorized-engagement
  report_count: 0
---

## When to use

Use this skill to start an external infrastructure test, when the question is
"what does this client expose to the internet below the web layer, and is any of
it a finding". It owns the shape of the engagement. That means scope and
ownership, the discovery plan and its rate, read-only fingerprinting, routing,
the grading of exposure as such, and the coverage statement in the report.

Use when any of these is true:

- The scope document lists IP addresses, CIDR ranges or hostnames to be tested
  at the network layer, not only web applications.
- Someone asks for a port scan, an nmap run, service enumeration or a
  perimeter assessment, or holds scan output and asks which skill handles port N.
- A web engagement turned up a host with non-HTTP ports.

**This skill routes. It does not test services.** Per-service depth lives in the
owner skills of Step 6. Once a port routes away, load that skill and stop
reading this one for that port.

### Where the chain ends

The boundary is `SECURITY.md`'s: external attack surface only. The chain ends at
"service exposed, unauthenticated behaviour proven, evidence captured". There is
nothing here about pivoting through a perimeter host, internal Active Directory,
lateral movement, credential dumping, persistence, C2 or evasion.

Two cuts that matter at this layer:

- **Windows perimeter services** (SMB, RPC, RDP, Kerberos, MSSQL, CLDAP) go to
  `infra-windows-perimeter` for exposure and unauthenticated enumeration only,
  for example SMB signing state, NTLM metadata and the RDP security layer.
  Kerberoasting, AS-REP roasting, relaying, and anything that needs a domain
  credential stay out of scope, even when port 88 answers from the internet.
- **IPv6.** The client's global addresses are in scope like their IPv4 ones.
  Link-local and L2 work is internal-network attack and is excluded: SLAAC abuse,
  mitm6, router advertisements, and nmap's `broadcast`-category multicast
  scripts.

### Not covered here, on purpose

- Asset discovery from names, ASNs, certificate transparency, Shodan and Censys
  belongs to `offensive-osint` and `web2-recon`. Triage of ASM output for
  namespace collisions belongs to `recon-scope-triage`. This skill starts from a
  candidate list of addresses.
- Web application testing on 80/443 goes to `web2-recon`, then `hunt-dispatch`.
- Every per-service probe beyond fingerprinting goes to the owner skill.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/port-routing-table.md` | Every port and protocol with its owner skill and reference file: TCP, UDP, alternate ports, collisions, ports with no owner | which skill for port, what is port N, route open ports, port to skill map |
| `references/discovery-commands.md` | nmap TCP, UDP and IPv6 passes; masscan, naabu and rustscan with verified flags; the shared-range classifier; RDAP and ASN lookups; IPv6 address sources | nmap command, full port scan, udp scan, masscan rate, naabu, rustscan, ipv6 scan, cloud ip ranges, cdn ranges, exclude file |

---

## Step 1: Rules of engagement in writing, before the first packet

NIST SP 800-115 §5.2.1 sets this in the planning phase, where "no actual testing
occurs". PTES calls it pre-engagement interactions. The scan needs every field
below, written in the engagement log:

| Field | Why the scan needs it |
|---|---|
| In-scope addresses and ranges, IPv4 and IPv6 listed separately | Default deny. A hostname in scope does not put its IPs in scope (Step 2). |
| Exclusions | Fragile hosts, third-party-hosted systems, anything the client wants left alone. |
| Window and time zone | A scan outside the window is unauthorized traffic. |
| Source IPs you scan from | The client's SOC or MSSP watches or allow-lists them. They also prove the external vantage in evidence. |
| Agreed scan rate in packets per second, and whether high-rate scanners are allowed | Step 4. If the RoE is silent, use this skill's default posture and no high-rate scanner. |
| Emergency stop contact | For the moment a host stops answering. |
| Hosting, colo or cloud authorization where the client does not own the range | Step 2. |

Two facts about this repo's tooling that change how the scan runs:

- `/scope` (`engine/scope.py`) matches IPv4 CIDRs only. An IPv6 literal checked
  against an in-scope `2001:db8::/32` comes back out of scope (verified). It fails
  closed, but **IPv6 scope has to be checked by hand** against the signed
  document.
- `engine/throttle.py` lists nmap, masscan, naabu and rustscan as **ungoverned**.
  While the engagement JSON sets a `rate_limit`, `hooks/throttle-guard.py`
  refuses them, and that refusal is correct. The throttle counts HTTP requests,
  and a scanner sends packets. Do not unset the engagement variables to get past
  it, because the guard refuses that too. The operator decides in writing whether
  the scan phase runs outside the agent, or under a configuration where the
  scanner's own flag (`--max-rate`, `--rate`, `-rate`) carries the RoE figure.

---

## Step 2: Prove each address is the client's, and not shared

Run these per address, before any packet goes to it. All of them are lookups
against third parties, not the target:

| Check | How | What it rules out |
|---|---|---|
| Registry owner | RDAP (`curl -s https://rdap.org/ip/<ip>` redirects to the right RIR) or `whois` | A range belonging to someone else |
| Origin ASN | `whois -h whois.cymru.com " -v <ip>"` | A hoster or cloud ASN where the client was assumed to own the space |
| Reverse and forward DNS | PTR with `dig -x`, then forward-confirm the name it returns | Stale PTR records and shared hosting |
| Shared-range membership | Published cloud and CDN range files (`references/discovery-commands.md`) | Edge addresses that answer for every tenant |

The result puts each address into one of four ownership shapes:

| Shape | How it shows | Port-scan it? |
|---|---|---|
| Client-registered range | RDAP organisation is the client, or a PA assignment to them | Yes, within scope |
| Dedicated server or VPS at a hoster | RDAP names the hoster; the client attests the address | Yes, with the client's attestation, inside the hoster's own testing terms (check per hoster) |
| Cloud customer pool (AWS EC2 or EIP, GCP `cloud.json`, Azure, OCI) | Provider in RDAP; address in the provider's published list | Only addresses the client attests are assigned to their account **now**, timestamped at test time. AWS allows testing your own assets and prohibits port and protocol flooding. Azure allows your own tenant only. GCP allows your own projects only. |
| CDN edge or shared front end (Cloudflare, Fastly, CloudFront, Azure Front Door, Akamai (verify), shared web hosting) | Address in a CDN list, or many unrelated names resolve to it | **No.** Every port belongs to the provider. Test the client's hostname at the HTTP layer only. Origin discovery belongs to `offensive-osint`. |

Three traps:

- **Reassigned cloud addresses.** A DNS record in scope that points at a
  released EIP or public IP now points at another customer. The record does not
  make the host the client's. Confirm the address against the client's current
  inventory. The dangling record is its own finding, for `hunt-subdomain`.
- **ASN or netblock expansion.** Never widen scope from an ASN or a WHOIS
  netblock. nmap's `targets-asn` (`discovery external safe`) adds every prefix an
  ASN announces as targets. That is scope expansion in one flag, so it is never
  used here.
- **Vantage-dependent DNS.** Geo-DNS and round-robin names return different
  addresses from different places. Resolve from the scan host and check every
  address that comes back.

Step 2 produces two files that every scanner reads: `scope-ips.txt` (verified)
and `exclude.txt` (shared, CDN and excluded). nmap and masscan take
`--excludefile`, naabu takes `-ef` and rustscan takes `-x`. Pass the exclude
file even when the target list is already clean. It is a second guard against a
copy-paste error.

---

## Step 3: Passive data first

Before sending packets, pull Shodan, Censys or InternetDB records for the
verified list. That workflow is owned by `offensive-osint`. naabu's `-passive`
reads the Shodan InternetDB API (verified, naabu 2.6.1). Passive data serves two
purposes:

- It is a prior: historical ports, banners and certificates, and hosts that
  were open last month and closed now.
- It is the **only** acceptable first look at ICS, OT, building-automation and
  camera estates (`hunt-exposed-services` Step 5).

Passive data is never a finding. It is stale and was collected from someone
else's vantage. Every port you report has to be observed again from your own
scan host.

---

## Step 4: Active discovery, in order, at the agreed rate

**Precondition for every command in this step:** each target is in
`scope-ips.txt` from Step 2 and is not in `exclude.txt`. The rate is the RoE
figure, or the default posture below. Full commands are in
`references/discovery-commands.md`.

| Pass | What | Why |
|---|---|---|
| 1 | TCP top 1000 (nmap's default) on every verified address, with `-Pn` | A quick picture. On the internet ICMP is often filtered, and dropping a host because ping failed loses real exposure. |
| 2 | Full TCP 1-65535 on **every** verified address, not only those that answered pass 1 | Top-1000 misses what matters most (nmap-services ranks below). |
| 3 | UDP top 100 plus a targeted list | UDP is slow by design and top-ports never reaches several high-value services. |
| 4 | IPv6 addresses, as a separate pass | Dual-stack hosts often run a different firewall policy on v6. |
| 5 | Confirm deltas | Ports that appeared or disappeared between passes are scanned again from a second source IP or at a different time. |

Why the full TCP pass is not optional. These ranks come from the nmap-services
file shipped with the installed nmap (`nmap --version` printed 7.991; rank by frequency, top 1000 = default
scan):

| Port | Service | Rank |
|---|---|---|
| 6379 | Redis | 1683 |
| 27017 | MongoDB | 2841 |
| 6443 | Kubernetes API | 4868 |
| 4786 | Cisco Smart Install | 5441 |
| 2379 | etcd | 7382 |
| 10250 | kubelet | not in the file at all |

On UDP, nmap's man page says a Linux-style limit of one ICMP unreachable per
second "makes a 65,536-port scan take more than 18 hours". A full UDP sweep is
rarely worth it. Top 100 misses these (same file): 389/udp CLDAP (rank 161),
3702/udp WS-Discovery (343), 1194/udp OpenVPN (15246), 51820/udp WireGuard
(12250), 3478/udp STUN (17277), 11211/udp memcached (18973). Add them by name;
the targeted list is in the reference file. BACnet 47808/udp (515) is missed
too, but it is probed only under the industrial rules. A UDP port that stays
`open|filtered` is not open, so do not report it as open.

### Rate posture

These defaults belong to this skill. Only the RoE figure overrides them. Each
tool default was verified against the installed binary:

| Tool | Default posture here | Tool's own default |
|---|---|---|
| nmap TCP | `-sS -T3 --max-rate 100 --max-retries 2` | `-T3`, no rate cap, adaptive |
| nmap UDP | `-sU --max-rate 50 --max-retries 1` | Slows itself to the target's ICMP rate limit |
| masscan 1.3.2 | `--rate 100`, ownership-verified list only | 100 packets/s, stateless, retries sent regardless of replies |
| naabu 2.6.1 | `-rate 100 -c 10 -iv 4` (add `6` only for verified v6) | `-rate 1000`, `-c 25`, `-top-ports 100`, `-iv 4,6` |
| rustscan 2.3.0 | `-g -b 200 -t 2000` | Batch 4500 concurrent connects, 1500 ms timeout, then runs nmap with `-Pn -vvv -p` |

Two of those defaults bite:

- naabu scans a hostname's AAAA records **by default**. If v6 ownership is not
  verified, that is a scan of an unchecked address. Pin `-iv 4` until it is.
- rustscan's own help text says: "Do not use this program against sensitive
  infrastructure since the specified server may not be able to handle this many
  socket connections at once." Run it with `-g` (no automatic nmap) and a small
  batch, then run nmap yourself.

### When a masscan-class scanner is acceptable

Use masscan, or naabu or rustscan above the default posture, only when **all**
of these hold:

1. The RoE explicitly allows high-rate scanning and states a packets-per-second
   figure.
2. The target list is `scope-ips.txt`. It is never a range with unknown tenants,
   a cloud pool or a CDN. AWS policy prohibits port flooding even against your
   own assets.
3. nmap at the default posture cannot finish in the window. Full TCP at 100
   packets/s takes 65,535 x hosts / 100 seconds before retries: 30 hosts is
   about 5.5 hours, a /24 about 47 hours. Use that figure to negotiate the rate.
4. The list contains no ICS, OT, medical or fragile embedded estate.
5. The output is treated as a candidate list. Every open port is confirmed and
   fingerprinted again with nmap. masscan is stateless, and its built-in stack's
   RSTs break `--banners` unless you firewall a source port, so do not use it to
   identify anything.

Because it changes the blast radius, high-rate scanning needs the Step 7
sign-off block as well as the RoE clause.

### Fragile estates

ICS, OT, building management, medical and camera networks get no full-range
scan at all. Use passive data, then single named ports, then stop. nmap's own
man page says: "Omitting version detection is far more effective than playing
with timing values at reducing these problems." So `-sV` is not run against
these hosts. Route to `hunt-exposed-services` and its industrial reference.

### Noticing that you have been blocked

An IPS that shuns your source makes every later port look `filtered`, and a
clean result then means nothing. During long scans, probe a port you know is
open on an already-confirmed host at intervals. If it goes filtered in the
middle of the scan, stop, note the time, and raise it with the client contact.
`mid-engagement-ir-detection` turns that observation into a deliverable.

---

## Step 5: Fingerprint the service, read-only (Stage A)

The port number is a hint. The service is identified by its own protocol
response. Run `-sV` at its default intensity against open ports only. For each
port, record the banner, the `-sV` match, and the TLS certificate where one is
presented. A certificate SAN or CN is the strongest identity and ownership
signal a port gives you.

NSE rules come from `hunt-exposed-services` Step 4 and apply to every scan this
skill runs:

- **No `-sC`, no `-A`, no `--script` category selection.** That includes
  rustscan's `-- -A` passthrough. The `default` category contains scripts that
  log in to storage targets and relay through open proxies.
- Name every script. Read its declared categories with `nmap --script-help
  <name>` before the first run.

At the orchestration layer, only these scripts are used (categories verified):

| Script | Categories | Use |
|---|---|---|
| `banner` | `discovery safe` | Raw banner of an unidentified port |
| `ssl-cert` | `default safe discovery` | Certificate identity on any TLS port |

Scripts that are **not** Stage A here, despite how they sound:

| Script | Categories | Why not |
|---|---|---|
| `dns-ip6-arpa-scan` | `intrusive discovery` | Walks the client's reverse zone with many queries. This is Stage B. |
| `targets-asn` | `discovery external safe` | Adds every announced prefix of an ASN as targets |
| `asn-query`, `whois-ip` | `discovery external safe` | Fine as lookups, but they send target addresses to third parties. Use the Step 2 lookups instead, so you know what left your host. |

Further fingerprinting rules:

- nmap's `nmap-service-probes` carries `Exclude T:9100-9107` so that `-sV` does
  not print on raw-print ports. Never override it with `--allports`.
- UDP `-sV` resolves `open|filtered` only for protocols nmap has a payload for.
  The rest stay unresolved and go in the coverage statement, not the findings.
- If a service is unknown, record the banner, describe the exposure
  generically and invent nothing.

Stage A for this skill means port-state scanning at the agreed rate, `-sV` on
open ports, the named scripts above, and passive lookups. Anything else is
either the owner skill's work or Stage B.

---

## Step 6: Route each open port to its owner

Load **only** the owner for the port in front of you. The full map, with every
port, the UDP and alternate ports and the ownership notes, is in
`references/port-routing-table.md`.

| Port(s) | Service | Owner |
|---|---|---|
| 21, 990 | FTP, FTPS (SFTP is SSH) | `infra-ftp` |
| 22, or an SSH banner on any port | SSH, SFTP | `infra-ssh` |
| 25, 465, 587, 110, 995, 143, 993 | SMTP, POP3, IMAP | `infra-mail`. SPF, DKIM and DMARC go to `hunt-tls-network` |
| 53 tcp/udp | DNS server exposure | `infra-dns`. AXFR goes to `hunt-tls-network` |
| 88, 135 and dynamic RPC, 137-139, 445, 3389, 1433, 1434/udp, 389/udp | Kerberos, MSRPC, NetBIOS, SMB, RDP, MSSQL, CLDAP | `infra-windows-perimeter` (exposure and unauthenticated enumeration only) |
| 500/udp, 4500/udp, 1701/udp, 1723, 1194, 51820/udp, 9993, SSTP or OpenVPN on 443 | IKE/IPsec, L2TP, PPTP, OpenVPN, WireGuard, ZeroTier, SoftEther, SSTP | `infra-vpn-ike` |
| 5060, 5061, 1720, RTP media ports | SIP, H.323, RTP | `infra-voip-sip` |
| 8291, 8728/8729, 2000 (btest hello), 10001/udp, 7547, 7557/7567, 541, 4343, 8211/udp, 1812/1813 and 1645/1646 udp, 49, 179, 520/udp, 514/udp, 2055/udp, 6343/udp, 1900/udp, vendor admin HTTPS | MikroTik, Ubiquiti, TR-069/CWMP and ACS, FGFM, Aruba, RADIUS, TACACS+, BGP, RIP, syslog, NetFlow/sFlow, SSDP, router/firewall/WLC management planes | `infra-network-devices` (SSL VPN portals stay in `enterprise-vpn-attack`; 514/tcp is rsh, `hunt-exposed-services`) |
| ScreenConnect, SimpleHelp, BeyondTrust, N-central, Kaseya, ManageEngine on their HTTPS ports; 1494, 2598, 4000, SPICE on 5900+ | RMM and remote-support servers, Citrix ICA/CGP, NoMachine, SPICE | `infra-rmm-remote-support` (VNC and RDP keep their owners) |
| 9392, 9393, 9401, 8400, 1556, 13724, 9101-9103, 9000/9001 MinIO, 5000/5001 DSM, 8080/443 QNAP, 8384, Nextcloud on 443 | Backup servers, NAS, object storage, file sync | `infra-backup-nas` (NFS, rsync, iSCSI, SMB shares stay in `hunt-exposed-services`) |
| 32NN, 33NN, 36NN, 80NN, 443NN, 5NN00, 7001/7002, 9060, 9080, 8880, 9990, 4447, 4848, 8500 (ColdFusion), 8090, 7990, 8085 | SAP NetWeaver, WebLogic, WebSphere, JBoss/WildFly, GlassFish, ColdFusion, Atlassian DC | `infra-enterprise-appservers` (AJP, RMI, SAProuter, TNS keep their owners) |
| 9870, 8020, 8088, 7077, 6066, 10000 (HiveServer2), 16010, 8998, 8081 (Flink), 9092/9093, 2181, 61616, 8161, 61613, 8983, 8123, 9000 (ClickHouse), 7474/7687, 50000 (DB2), 3050, 5000 (ASE), 3NN15, 26257, 8529, 28015, 5433, 5701 | Hadoop, Spark, Hive, HBase, Livy, Flink, Kafka, ZooKeeper, ActiveMQ, Solr, ClickHouse, databases without another owner | `infra-data-platforms` |
| 11434, 8265, 10001, 8000-8002 (Triton), 8080-8082 (TorchServe), 5000 (MLflow), 7860, 8188, 3001, 5678, 4200, 1234, 50052, `/mcp` or `/sse` paths | LLM inference servers, Ray, TorchServe, Triton, MLOps, AI web UIs, agent builders, MCP servers | `infra-ai-ml-services` |
| 8200, 8500/8600 (Consul), 4646, 8761, 50000 (Jenkins agent), 8111, 29418, 9418, 8081 (Nexus/Artifactory), 5000 (registry), 4873, 9000 (SonarQube/Portainer), 9443, 4440 | Vault, Consul, Nomad, Eureka, Jenkins, TeamCity, Gerrit, git daemon, registries, SonarQube, Portainer, Rundeck | `infra-devops-platforms` |
| 10050/10051, 5666, 5665, 6556, 8443/12489 (NSClient++), 9090, 9100 (HTTP), 9093, 9091, 2003/2004, 8125/udp, 3100, 16686, 4317/4318, 12201, 5044, 9600, 24224, 2020, 8200 (APM), 19999, 162/udp | Monitoring servers and agents, metrics, logging and tracing ingest | `infra-monitoring-logging` |
| SSL VPN portal on 443, 4443, 8443, 10443 | Cisco, Fortinet, Citrix, Palo Alto, Ivanti, SonicWall, F5 | `enterprise-vpn-attack` |
| vCenter, Workspace ONE or Aria on 443; ESXi OpenSLP 427 | VMware | `vmware-vcenter-attack` |
| 6443, 10250, 10255, 2379, 2380, 2375, 2376 | Kubernetes API, kubelet, etcd, Docker | `hunt-k8s` |
| Datastores, brokers, debug ports, BMC, SNMP, WinRM, VNC, LDAP, printers, NFS, rsync, iSCSI, telnet, r-services, NTP, proxies, mDNS, ICS | See the reference table | `hunt-exposed-services`, one reference file per family |
| HTTP or HTTPS on any port | Web server or admin console | Fingerprint, then `hunt-exposed-panels` for consoles, `web2-recon` and `hunt-dispatch` for applications |
| TLS on any port | Certificate, protocol, ciphers | `hunt-tls-network`, as a separate finding |
| A managed cloud endpoint (bucket, blob, function URL) | Cloud service | `hunt-cloud-misconfig` |
| Anything else | Unknown | Check the reference first: JDWP and gdbserver answer on any port (`hunt-exposed-services`). Otherwise no owner; describe generically. |

The protocol decides collisions, never the port number:

- **9100** is raw PJL printing (`hunt-exposed-services`), or HTTP `/metrics`
  from a Prometheus node exporter (`infra-monitoring-logging`). Decide from
  passive data and the host's other ports first. Never send an HTTP request to find out: a
  raw-print port prints whatever is not a PJL or PostScript query.
- **10000** is NDMP or Webmin, and is also inside a common RTP media range.
- **8086** is InfluxDB or an alternate HTTP port. **5555** is ADB
  (`hunt-exposed-services`) or SoftEther (`infra-vpn-ike`).
- **389/tcp, 636, 3268 and 3269** (LDAP rootDSE) belong to
  `hunt-exposed-services`. **389/udp** (CLDAP) belongs to
  `infra-windows-perimeter`.
- **5985/5986** (WinRM, OMI) stays with `hunt-exposed-services`.
- **5060** goes to `infra-voip-sip`. `hunt-exposed-services`'
  legacy-and-infoleak reference also carries a single SIP `OPTIONS` probe, so do
  not run both.
- **443** can be a web app, an SSL VPN, vCenter, SSTP or a panel. Route on the
  fingerprint.
- **8500** is Consul (`infra-devops-platforms`) or ColdFusion
  (`infra-enterprise-appservers`). **9443** is Portainer or WebSphere.
  **8000** is SAP ICM, JDWP or an AI serving endpoint. **5000** is MinIO,
  Synology DSM, MLflow, a Docker registry or SAP ASE. **8081** is Nexus,
  Artifactory, Flink or TorchServe management. **6379** beside an 8265 is Ray,
  not Redis. **2000** is the MikroTik bandwidth-test server when the 4-byte
  hello `\x01\0\0\0` appears, otherwise Cisco SCCP (`infra-voip-sip`). **3000**
  is GenieACS, Grafana, Dagster, Flowise or BentoML. The banner and the first
  read-only probe decide.

If an owner skill is not installed, the `hunt-exposed-services` rule for unknown
ports applies: fingerprint, describe the exposure, and invent nothing.

---

## Step 7: Stage B at the orchestration layer

Stage B is **blocked by default**. It needs explicit written sign-off that names
the action, the target file and the window. The format is the one in
`hunt-exposed-services` Step 5. At this layer these actions are Stage B:

| Action | Blast radius to state in the sign-off |
|---|---|
| High-rate scanning (masscan, naabu or rustscan above the default posture) | Packet rate against production edges, IPS and firewall state tables, upstream abuse complaints |
| Any NSE script outside `safe` (such as `dns-ip6-arpa-scan`), or a `safe`-tagged trap from `hunt-exposed-services` Step 4 | Whatever the script actually does. Read its categories and source first. |
| Anything beyond passive data and single-port reachability against ICS, OT, medical or camera estates | Physical process and personal data |
| Any credential attempt, including documented defaults beyond the owner skill's one-shot rule | Account lockout. This is `hunt-brute-force` territory. |
| Any state-changing action on a service | Governed by the owner skill's own Stage B |

```
Stage B authorization
  Targets:          scope-ips.txt (sha256 <hash>), <n> addresses; exclude.txt applied
  Action:           masscan full TCP 1-65535 at <pps> packets/s
  Blast radius:     sustained SYN rate against production edges and their
                    state tables; possible IPS shun of the source IP
  Window:           <date/time, time zone>
  Source IPs:       <scan host egress addresses>
  Authorized by:    <name/role>, in writing, <link to the message>
```

These are forbidden outright, and no sign-off makes them acceptable:

- Scanning addresses that are not in `scope-ips.txt`.
- Port-scanning CDN or shared edge addresses.
- Expanding scope from an ASN or netblock.
- Spoofed sources (`-S`), decoys (`-D`) and idle scans (`-sI`). Each of them
  puts a third party's address into the client's logs, or uses a third party's
  host as the scanner.

---

## Step 8: Grade the exposure, and only the exposure

The owner skill grades service findings. Grade only what this layer proves:

| What you proved | Grade |
|---|---|
| The owner skill proved unauthenticated access, data or execution | The owner's grade. This skill adds nothing. |
| A service is filtered on IPv4 but reachable on IPv6 for the same host | The grade of the exposure it creates, reported as a firewall-policy defect with both transcripts |
| A management or data plane (SSH, RDP, WinRM, database, BMC, hypervisor, Kubernetes API, VPN admin) is reachable from any internet source, with authentication enforced | Informational to Medium by what the plane controls, with BMC, hypervisor and Kubernetes API at the top. The owner skill's grade wins. |
| A host or port the client's declared inventory says is internal or absent | Low, with the routing that follows. The value is in the next skill. |
| An expected public service with authentication enforced (443 web, 25 on the MX, 53 on an authoritative server) | Not a finding |

Two rules that triage will enforce:

- A version banner inside a CVE range is "unconfirmed" until the owner skill
  confirms it.
- A port count is not a finding. "Large attack surface" is a narrative for the
  executive summary, not a line item.

What not to write up:

- An open port on its own.
- UDP `open|filtered`.
- Anything on a CDN or shared edge address.
- ICMP echo or timestamp replies, TCP timestamps, OS guesses.
- Filtered ports.
- Passive-data ports you did not observe yourself.

---

## Step 9: Evidence and report handoff

- Keep the `-oA` output of every run (the XML imports into reporting tools).
  Record with it the exact command line, source IP, start and end time, and rate.
- Write the **coverage statement**. Without one, a clean result reads as
  "nothing exposed" when it means "nothing tested". It contains:
  - Addresses in scope and addresses scanned.
  - Full or partial TCP coverage per address.
  - The UDP port list.
  - IPv6 covered or not, and why.
  - Excluded addresses and the reason for each (CDN, shared, client request).
  - Windows, source IPs, rate, and any host that went silent mid-scan.
- Per finding, follow the owner skill's evidence rules and `evidence-hygiene`,
  run `triage-validation`, then write up with `redteam-report-template`
  (engagement) or `report-writing` (bounty platform).

---

## Chain table

| Discovery signal | Where it goes |
|---|---|
| Port open on IPv6 and filtered on IPv4, same host | Owner skill for the service. Report the policy gap here. |
| Self-signed certificate naming an internal hostname on a perimeter port | `hunt-tls-network`, and the hostname feeds `offensive-osint` |
| `WWW-Authenticate: NTLM` on any HTTP port, or NTLM metadata from RDP or SMB | `hunt-ntlm-info` for HTTP, `infra-windows-perimeter` for RDP and SMB. Metadata only. |
| SSH, VPN or mail banner naming an appliance vendor | `enterprise-vpn-attack` for SSL VPN appliances, otherwise the protocol owner |
| A DNS record in scope pointing at an address now owned by someone else | `hunt-subdomain` as a dangling record. Do not scan the address. |
| Admin console on a high port | `hunt-exposed-panels` |
| Datastore, broker, BMC or ICS port | `hunt-exposed-services`, with one reference file |
| Credential surfaced anywhere | Stop. Report it. `cloud-iam-deep` only for cloud keys, and only within scope. |

---

## Validation checklist

- [ ] The RoE names IPv4 and IPv6 scope, exclusions, window, source IPs, rate
      and emergency contact, and it is in the engagement log.
- [ ] Every scanned address passed Step 2, and IPv6 was checked by hand.
- [ ] No CDN, shared edge or unattested cloud address was port-scanned, and
      `exclude.txt` was passed to every scanner.
- [ ] No scope was expanded from an ASN, netblock or `targets-asn`.
- [ ] The rate came from the RoE or this skill's default, and was set in the
      scanner's own flag. High-rate scanning has a logged sign-off.
- [ ] Full TCP coverage on every verified address, or the gap is in the
      coverage statement.
- [ ] UDP covers top 100 plus the targeted list. `open|filtered` was not
      reported as open.
- [ ] The scan box had working IPv6 egress for the IPv6 pass. Without it, every
      v6 port looks closed.
- [ ] Every reported port was observed from your own vantage, outside any client
      VPN, and identified by its protocol response.
- [ ] No `-sC`, `-A` or category selection. Every NSE script was named and
      checked with `--script-help`.
- [ ] No spoofed, decoy or idle scan.
- [ ] Fragile estates got passive data and single-port checks only.
- [ ] The scan was checked for an IPS shun, and silent hosts are in the coverage
      statement.
- [ ] Each open port went to exactly one owner, and its finding is graded there.
- [ ] The report ends at exposure plus proven impact. No internal follow-up is
      written.

---

## Sources

Grounding: NIST SP 800-115 §4.2 and §5.2.1 (planning, discovery, attack,
reporting); PTES's seven sections (checked against a mirror, official site
unreachable); OSSTMM 3 porosity (verify the section). Scanner behaviour checked
against the installed binaries; cloud rules from the AWS, Microsoft and Google
Cloud penetration-testing policies.

---

## Related Skills & Chains

- `recon-scope-triage`, `offensive-osint`, `web2-recon`: they produce the
  candidate address list and the passive prior. This skill takes over from them.
- `hunt-exposed-services`: the default owner of non-HTTP service exposure, and
  the source of the NSE and Stage B rules this skill inherits.
- `infra-ssh`, `infra-ftp`, `infra-mail`, `infra-dns`,
  `infra-windows-perimeter`, `infra-voip-sip`, `infra-vpn-ike`,
  `infra-network-devices`, `infra-rmm-remote-support`, `infra-backup-nas`,
  `infra-enterprise-appservers`, `infra-data-platforms`,
  `infra-ai-ml-services`, `infra-devops-platforms`,
  `infra-monitoring-logging`: per-protocol
  owners.
- `hunt-k8s`, `hunt-exposed-panels`, `hunt-tls-network`,
  `enterprise-vpn-attack`, `vmware-vcenter-attack`, `hunt-cloud-misconfig`,
  `hunt-ntlm-info`, `hunt-subdomain`: owners for the remaining families.
- `hunt-brute-force`: all credential guessing.
- `mid-engagement-ir-detection`: when the client's defenses react during the
  scan.
- `evidence-hygiene`, `triage-validation`, `redteam-report-template`,
  `report-writing`: evidence, false-positive gates and the deliverable.

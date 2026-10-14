---
name: infra-network-devices
description: "Triage internet-exposed management and control planes of network devices. Families: MikroTik RouterOS (Winbox 8291, API 8728/8729, WebFig/REST, btest 2000); Ubiquiti (discovery 10001/udp, UniFi Network 8443, UniFi OS, EdgeOS, airOS); TR-069/CWMP 7547 CPEs and ACS servers (GenieACS NBI 7557); Cisco IOS XE web UI, ASA and FMC; Juniper J-Web; Fortinet FGFM 541 and FortiGate admin; PAN-OS management; SOHO/CPE admin UIs (Zyxel, DrayTek, TP-Link, D-Link KEV rows; Netgear, Linksys, Tenda); Aruba, Ruckus and Cisco wireless controllers; fingerprint rows for TACACS+ 49, RADIUS 1812, BGP 179, RIP 520/udp, syslog 514/udp, NetFlow/sFlow and SSDP 1900/udp. Read-only fingerprinting, version gates against a KEV-checked CVE matrix, one-datagram amplification checks, grading. Stage A read-only; logins, enumeration and CVE triggers are Stage B with written sign-off; DoS checks are declined. Use when a scan, banner or title shows one of these devices or ports on an in-scope host."
sources: nvd, cisa_kev, cisa_ics_advisories, vendor_advisories, project_documentation, tool_source_code, public_research
report_count: 0
---

## When to use

Trigger when external recon has found a network device's management or
control plane answering on a host you are authorized to test. The finding is
**a management plane the internet can reach, with its version and its
unauthenticated behaviour proven**, not a device you took over.

- A scan or passive data shows a port from Step 3, or a banner, title or
  certificate names RouterOS, UniFi, EdgeOS, airOS, RomPager, IOS XE, J-Web,
  FortiGate, FortiManager, PAN-OS, ArubaOS, Ruckus, a Cisco WLC or a SOHO model.
- The client is an ISP, WISP or MSP with a CPE fleet, or runs an ACS.
- A scanner flagged a device CVE that needs confirming or killing. Not for
  discovery: that is `infra-external-methodology` and `offensive-osint`.

### Where the chain ends

At **exposure, version and unauthenticated behaviour proven, evidence
captured**. A router or firewall is the edge of the client's internal network.
Nothing here logs in, reads configuration, pushes a task to a CPE, joins a
routing session, or uses the device as a hop (proxy, SOCKS, tunnel, port
forward, "intermediary" request into the LAN). That is internal-network
attack, outside `SECURITY.md`.

### Not covered here, on purpose

- **A device's other protocols** stay with their owner: SSH and the
  factory-credential table (`infra-ssh`), FTP (`infra-ftp`), telnet, SNMP,
  Smart Install, open proxies and BMCs (`hunt-exposed-services`), SMB
  (`infra-windows-perimeter`), DNS (`infra-dns`), IKE and VPN tunnels
  (`infra-vpn-ike`), TLS (`hunt-tls-network`). Map in
  `references/fingerprints-and-ports.md`.
- **SSL VPN portals and the rows `enterprise-vpn-attack` already carries**:
  FortiGate `/remote/` SSL VPN, GlobalProtect, AnyConnect, and the PAN-OS and
  FortiOS admin auth-bypass rows listed in the matrix as owned there.
- **Consoles that are applications, not devices**: UniFi Protect, Access,
  Talk, Connect, UISP, Expedition, ACS front-ends and Grafana go to
  `hunt-exposed-panels`; NAS models to `infra-backup-nas`.
- **Every credential attempt**: `hunt-brute-force`, and Stage B here.

---

## Step 1: Inherit the target list, then set the posture

Take `scope-ips.txt` and `exclude.txt` from `infra-external-methodology` Step 2.

- **Subscriber CPE is not the client's network.** 7547, 8291 or 10001 in an
  ISP's ASN is usually a customer's router: in scope only when the RoE names
  subscriber CPE, as a written sample, never a sweep. A crashed CPE is a
  customer offline.
- **The client's own line may carry the ISP's CPE.** 7547 on the client's DSL
  or fibre address is usually ISP-managed: report it as third-party managed;
  anything past Stage A needs the ISP's authorization.

### Rate posture and helpers

Embedded stacks fall over: one TCP byte sent Grandstream's TR-069 service into
an infinite loop (CVE-2020-5761). One host at a time, one attempt per probe,
jitter between probes, no `--version-all`, no retry loops.

```bash
T="192.0.2.10"; mkdir -p evidence
# 2s base + 0-3s jitter, as in hunt-exposed-services.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
# One datagram read from stdin to <host> <port>: sizes, ratio, raw reply. No retries.
udp1() {
  python3 -I -c '
import socket, sys
req = sys.stdin.buffer.read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(req, (sys.argv[1], int(sys.argv[2])))
try:
    data, src = s.recvfrom(65535)
except socket.timeout:
    sys.exit("no reply: filtered, closed or another service. Do not resend in a loop.")
print(f"from={src[0]} sent={len(req)}B recv={len(data)}B ratio={len(data)/len(req):.1f}x")
print("raw", data.hex())' "$1" "$2"
}
```

### nmap traps for these ports

As in `hunt-exposed-services`: no `-sC`, no `-A`, no category selection. Read
every script with `nmap --script-help <name>` first (categories below from
nmap 7.991). A probe registered on the target port "is tried regardless of
intensity level" (man page); `-sU` sends them as payloads (verify with
`--packet-trace`).

| Script or probe | What it sends | Stage |
|---|---|---|
| `mikrotik-routeros-version` (`default version discovery safe`) | Two legacy pre-login file-list requests, as the Winbox client makes; works "until 6.49.17" | A |
| `mikrotik-routeros-username-brute`, `mikrotik-routeros-brute` | Winbox username enumeration; API password guessing | B |
| `ubiquiti-discovery` (`default ... safe`) | Up to two discovery datagrams; `-sC` fires it | Use `udp1` |
| `http-vuln-misfortune-cookie` (`vuln intrusive`) | "Detects" by exploiting the memory corruption | Decline |
| `upnp-info` (`default discovery safe`) | M-SEARCH, then fetches the device's LOCATION URL | Decline; Step 10 |
| `http-dlink-backdoor`, `http-tplink-dir-traversal` (`exploit vuln`) | Exploit requests | Decline |
| `-sV`/`-sU` on 1812/udp | `RADIUS_ACCESS`: an empty Access-Request | Use `--data-length 0` |
| `-sV` on 1900/udp | M-SEARCH `ST: ssdp:all`: one reply per service | Use `udp1` |

## Step 2: Prove the exposure is real, external and the client's

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client range and VPN; record the egress IP. | Reached from inside, a management port proves nothing. MikroTik's default configuration, for one, blocks these ports from the internet. |
| Ownership | `infra-external-methodology` Step 2, plus the CPE rules in Step 1. | A subscriber's router is not the client's asset. |
| Protocol reply | Only a protocol, HTTP or TLS reply proves a listener, never a bare handshake. | Scrubbing services complete handshakes on every port. |
| Honeypot | Signs in `references/fingerprints-and-ports.md` section 5. | A sensor is not a client misconfiguration. |

A discovery hostname `HACKED-ROUTER-HELP-SOS` is no honeypot: Rapid7 found
17,000 such compromised devices in 2019. Notify the client the same day.

## Step 3: Route the port or banner

| Seen | Family | Step |
|---|---|---|
| 8291, 8728/8729, WebFig/REST on 80/443, 2000 with the btest hello | MikroTik RouterOS | 4 |
| 10001/udp, UniFi 8443, `UniFi OS` title, EdgeOS, airOS | Ubiquiti | 5 |
| 7547 on a CPE; 7557/7567/3000 on an ACS | TR-069/CWMP | 6 |
| IOS XE web UI, ASDM, FMC, J-Web, FGFM 541, FortiGate admin, PAN-OS management | Enterprise management planes | 7 |
| Zyxel, DrayTek, Netgear, TP-Link, D-Link, Linksys, Tenda admin UI | SOHO and CPE | 8 |
| Aruba WebUI 4343 or PAPI 8211/udp, Ruckus, Cisco WLC | Wireless controllers | 9 |
| 49, 1812/1813/udp, 179, 520/udp, 514/udp, 2055/6343/udp, 1900/udp | AAA and control plane | 10 |

Collisions (2000 is also SCCP, 3000 also Grafana, 8443 also SSL VPN portals,
541 is `uucp-rlogin` to nmap) are in `references/fingerprints-and-ports.md`.

---

## Step 4: MikroTik RouterOS

```bash
nmap -Pn -sT -sV -p 8291,8728,8729,2000 "$T" -oA "evidence/${T}_ros_sv"
probe_delay
nmap -Pn -sT -p 8291 --script mikrotik-routeros-version "$T" -oA "evidence/${T}_winbox_ver"
probe_delay
curl -sk -m 10 -D - -o "evidence/${T}_webfig_root.html" "http://$T/" | tee "evidence/${T}_webfig_root.hdr"
probe_delay
# No credentials: a 401 proves REST is on without logging in.
curl -sk -m 10 -D - -o /dev/null "https://$T/rest/system/resource" | tee "evidence/${T}_rest_noauth.hdr"
```

- **Winbox (8291):** `-sV` says `MikroTik RouterOS >=6.43` or `legacy
  protocol, <6.43`. Legacy covers the CVE-2018-14847 range (through 6.42) plus
  a few fixed builds: a lead until the build is known. The version script
  prints the build from the plugin list (`roteros.dll 6.49.7`); on RouterOS 7
  it returns nothing, so take the build from the FTP banner (`infra-ftp`),
  passive data or the client. **Any other Winbox request is declined**: an
  unauthenticated file request is CVE-2018-14847 itself, aimed at `user.dat`.
- **API (8728) and API-SSL (8729):** `!fatal not logged in` to nmap's
  `NotesRPC` probe is the API refusing an anonymous client. **Never send
  `/login`**: since 6.43 "the client sends a username and password in the first
  message", in plain text on 8728. CVE-2026-16347 (CISA ICSA-26-209-05): the
  API "lacks effective safeguards against excessive login attempts", all
  versions, no fix. Exposure alone is the finding.
- **WebFig and REST (80, 443):** the root page identifies WebFig (whether it
  prints the build varies by release, verify on the page). REST is HTTP Basic
  against the device's own users; a `401` is the whole check. WebFig on plain
  HTTP exposes admin logins on path (CVE-2025-61481). Request nothing beyond
  the login page as served: CVE-2026-67281 (7.20 and later) and CVE-2026-84411
  (pre-auth root RCE before 7.24, CVSS 9.8) both sit on this service.
- **Bandwidth test (2000):** the NULL probe reads the server's 4-byte hello
  `\x01\0\0\0`. Anything else on 2000 (SCCP) goes to `infra-voip-sip`. The
  hello does not say whether `authenticate=yes` (the default) is still set.
  **Never start a test**: it "uses all available bandwidth (by default)", and
  CVE-2026-67277 (KEV) starts one without authentication and can restart the kernel.
- **SSH (`SSH-2.0-ROSSSH`)** goes to `infra-ssh` but carries this family's
  worst 2026 rows: CVE-2026-67279, which MikroTik calls "the issue that was
  seen being exploited in the wild", chained with CVE-2026-86060 (both KEV),
  pre-auth command execution before 6.49.21, 7.23.4 and 7.24.2.

---

## Step 5: Ubiquiti

### 5.1 Discovery (10001/udp): one datagram, measured

```bash
probe_delay
# The 4 bytes of nmap's UbiquitiDiscoveryv1 probe.
printf '\x01\x00\x00\x00' | udp1 "$T" 10001 | tee "evidence/${T}_ubnt_discovery.txt"
```

- **Any reply is a finding.** Rapid7 (2019): a 4-byte request draws a reply
  "30-35x the size of the request", about 490,000 devices exposed then. An
  amplification reflector and an information leak in one.
- Decode the saved `raw` line offline with `ubnt_decode` from
  `references/fingerprints-and-ports.md` section 6: `firmware` gives platform
  and build for Step 11, `mac+ip` lists internal addresses (record, never
  scan), `essid` is client data. Send nothing else: a malformed discovery
  packet disrupts management on UniFi gear (CVE-2024-22054).

### 5.2 UniFi Network Application (8443) and UniFi OS (443)

```bash
probe_delay
curl -sk -m 10 "https://$T:8443/status" | tee "evidence/${T}_unifi_status.json"
probe_delay
curl -sk -m 10 "https://$T/" | grep -o '<title>[^<]*</title>' | tee "evidence/${T}_title.txt"
```

- `meta.server_version` in `/status` is the controller build (Metasploit's
  Log4Shell check reads the same field). Without it, the login page's
  `angular/g<hash>` asset path maps to a build (Censys).
- 8080 is the device inform port, required by a hosted controller: not a
  finding alone. 8880/8843, 6789 and 3478/udp beside 8443 confirm the controller.
- A `UniFi OS` title is the whole of Stage A. **UniFi OS does not disclose its
  version unauthenticated** (Censys); the build comes from the client. Two
  2026 pre-auth sets sit there: CVE-2026-34908/34909/34910 (KEV, exploited in
  the wild) and CVE-2026-77550. Request nothing beyond the root page.

### 5.3 EdgeOS and airOS

Title and certificate only; the version comes from the 5.1 reply. The joint
FBI advisory of 2024-02-27 describes APT28 operating EdgeRouters first
compromised through default credentials (Moobot). Trying the default
(`infra-ssh`'s `appliance-ssh.md`) is Stage B, one attempt.

---

## Step 6: TR-069/CWMP

### 6.1 The CPE side (7547)

The ACS sends a Connection Request as an HTTP GET to the CPE's
`ConnectionRequestURL`, authenticated with `ConnectionRequestUsername` and
`Password`; a valid one makes the CPE open a session to its ACS. One
unauthenticated GET, no path guessing:

```bash
probe_delay
curl -s -m 10 -D - -o /dev/null "http://$T:7547/" | tee "evidence/${T}_cwmp_get.hdr"
```

| Reply | Meaning |
|---|---|
| `401` with `WWW-Authenticate` | Listener enforcing authentication. The realm often names vendor or model (nmap knows `Thomson_cwmp_<model>`). On an ISP-managed CPE this is the design. |
| `200` or `204`, empty body | The CPE accepted a Connection Request **without credentials** and has just called its ACS. That is the finding. Do not repeat it. |
| `404` | The path is randomized. Stop: guessing it is enumeration. |
| `Server: RomPager/<ver>` | Misfortune Cookie range (CVE-2014-9222). Unconfirmed lead; its nmap check is declined. |
| UPnP or SOAP service description, or TR-064 in passive data | TR-064, a LAN configuration protocol, on the WAN (the CVE-2016-10372 class). Every SOAP action is Stage B. |

### 6.2 The ACS side

An ACS controls every CPE it manages: firmware, parameters, reboots. GenieACS
listens by default on 7547 (CWMP), 7557 (NBI), 7567 (FS) and 3000 (UI), all on
`::`; its documentation describes no NBI authentication (CVE-2025-56015 records
unauthenticated NBI access on 1.2.13). A read-only differential that reads no
record:

```bash
probe_delay
curl -s -m 10 -D - "http://$T:7557/devices/?query=%7B%22_id%22%3A%22cbh-probe-nonexistent%22%7D" \
  | tee "evidence/${T}_nbi_probe.txt"
```

- `200` with `[]`: the NBI answers unauthenticated queries, so it would accept
  tasks for the whole fleet. Stop and report. Never list devices, presets,
  provisions or files, never POST a task. `401`, `403` or a proxy login:
  fronted, not a finding.
- 7547 on an ACS is by design; 7567 is not enumerated; 3000 is the GenieACS UI
  or Grafana (title decides). Other ACS consoles: `hunt-exposed-panels`.

---

## Step 7: Enterprise management planes

The exposure is the finding. The build almost never shows unauthenticated,
so the client supplies it (`show version` or equivalent) for the matrix.

```bash
probe_delay   # use the admin port in both URLs if it is not 443
curl -sk -m 10 -D - -o "evidence/${T}_mgmt_root.html" "https://$T/" | tee "evidence/${T}_mgmt_root.hdr"
grep -o '<title>[^<]*</title>' "evidence/${T}_mgmt_root.html"
probe_delay
openssl s_client -connect "$T:443" -servername "$T" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates | tee "evidence/${T}_mgmt_cert.txt"
```

| Device | Read-only identifier | Gate rows (matrix) |
|---|---|---|
| Cisco IOS XE web UI | `Cisco IOS http config` / `httpd` label, login page | CVE-2023-20198 (KEV, CVSS 10, pre-auth admin creation) and 20273. Compromise checks are the client's, from Cisco's and Talos's guidance. |
| Cisco ASA ASDM, Firewall Management Center | `Cisco ASA firewall http config`; FMC title and certificate | FMC CVE-2026-20079, 20131, 20316 (all KEV). ASA web services: `enterprise-vpn-attack`. |
| Juniper J-Web | Title `Log In - Juniper Web Device Manager`, `Server: Mbedthis-Appweb` | CVE-2023-36844/36845/36846/36847/36851 (KEV chain), CVE-2024-21591, CVE-2020-1631 (KEV); CVE-2025-6549 is J-Web on unintended interfaces. |
| FortiGate admin HTTPS | `Server: xxxxxxxx-xxxxx`, certificate subject | CVE-2022-40684 (KEV), CVE-2025-25249 (KEV); SSL VPN and other admin rows: `enterprise-vpn-attack`. |
| FortiManager, FortiAnalyzer, FortiGate FGFM (541) | TLS certificate only, below | CVE-2024-47575 (KEV), CVE-2024-23113 (KEV). |
| PAN-OS management | `Palo Alto PanWeb httpd`, `Palo Alto firewall http admin` | CVE-2017-15944 and CVE-2025-0111 (both KEV); the 2024-2025 auth-bypass chain: `enterprise-vpn-attack`. |

FGFM on 541 runs over TLS (verify per build): take the certificate, send no
FGFM message. The subject may carry product and serial (format verify).

```bash
probe_delay
openssl s_client -connect "$T:541" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates | tee "evidence/${T}_fgfm_cert.txt"
```

A FortiManager on 541 from the internet is the CVE-2024-47575 surface; a
FortiGate on 541 has FGFM allowed on that interface (CVE-2024-23113).

---

## Step 8: SOHO and CPE vendors

Zyxel, DrayTek, Netgear, TP-Link, D-Link, Linksys and Tenda admin UIs on the
WAN. One root request (Step 7's `curl`), then record title, `Server` header,
and the model and firmware string if the login page prints one.

- Look the model up in `references/device-cve-matrix.md` section 8: the KEV
  rows added 2023 to 2026, with precondition and fixed build. Many are **EOL**:
  no fix will come, the recommendation is replacement, and the grade rises.
- Netgear, Linksys and Tenda have no KEV additions since 2022; look the build
  up in NVD and the vendor's advisories at report time and invent nothing.
- Zyxel's IKE row (CVE-2023-28771) is `infra-vpn-ike`'s; NAS models go to
  `infra-backup-nas`, cameras to `hunt-exposed-services`.
- WAN administration is the finding even on a current build. Every SOHO CVE
  is a gate; none is triggered.

## Step 9: Wireless controllers

| Controller | Stage A | Gate rows (matrix section 9) |
|---|---|---|
| HPE Aruba (Mobility Conductor, controllers, Instant APs) | WebUI on 4343: title and certificate. PAPI 8211/udp: state from passive data or the client only; **no PAPI datagram** | CVE-2024-26304/26305/33511/33512 and CVE-2024-42505/42506/42507 (pre-auth over PAPI); mitigation Enhanced PAPI Security |
| Ruckus Wireless Admin, Unleashed, SmartZone (8443) | Title and certificate | CVE-2023-25717 (KEV, pre-auth RCE); SmartZone's SSH key row to `infra-ssh` |
| Cisco WLC (AireOS, Catalyst 9800) | Title, `Cisco Wireless LAN Controller httpd`; SSH `CISCO_WLC` to `infra-ssh` | CVE-2025-20188: only with Out-of-Band AP Image Download enabled (off by default); ask the client |

Grade by the controller: its UI manages the whole wireless estate.

## Step 10: AAA and control-plane protocols (fingerprint rows only)

Port state and read-only replies; never authenticate, join a session or send
data a collector would record. `-sU` needs root.

```bash
probe_delay
nmap -Pn -sT -sV --version-intensity 0 -p 49,179 "$T" -oA "evidence/${T}_cp_tcp"
probe_delay
sudo nmap -Pn -sU --data-length 0 -p 514,1812,1813,2055,6343 "$T" -oA "evidence/${T}_cp_udp"
probe_delay
sudo nmap -Pn -sU -sV --version-intensity 0 -p 520 "$T" -oA "evidence/${T}_rip"
probe_delay
printf 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n' \
  | udp1 "$T" 1900 | tee "evidence/${T}_ssdp.txt"
```

- **TACACS+ 49 and RADIUS 1812/1813:** state only. `--data-length 0` keeps
  nmap from sending its `RADIUS_ACCESS` Access-Request. Blast-RADIUS
  (CVE-2024-3596) needs an on-path position: not external.
- **BGP 179:** the NULL probe only reads (`connection rejected` or `open`).
  Never send OPEN.
- **RIP 520/udp:** nmap's RIPv1 whole-table request. A reply lists internal
  routes: record the count, quote none in full.
- **Syslog 514/udp, NetFlow 2055, sFlow 6343:** receive-only collectors, state
  only. A test message would land in the client's logs.
- **SSDP 1900/udp:** one M-SEARCH with `ST: upnp:rootdevice` (one reply, not
  nmap's `ssdp:all`). Record `SERVER`, `ST` and the ratio; **never fetch the
  `LOCATION` URL and never SUBSCRIBE** (CallStranger, CVE-2020-12695). Reading
  the reply: fingerprints section 7.

---

## Step 11: Version gates

`references/device-cve-matrix.md`: affected and fixed builds, KEV status
(catalog 2026.10.13), how the version is known, stance.

- A build from the device's own reply (Winbox plugin list, discovery firmware,
  UniFi `/status`) or the client is evidence, its source named; a title,
  certificate or passive banner is a lead. Either way: "version in range, not
  exploited".
- RouterOS September 2026 set: fixed in 6.49.21, 7.23.4, 7.24.2.
  CVE-2026-84411 needs 7.24; CVE-2026-16347 has no fix.
- For a KEV-range RouterOS build with SSH exposed, give the client CERT.PL's
  checks to run themselves: a privileged user named `ops`, log lines
  `login failure for user -2 ... added by ssh:-2@<ip>`, and the `Flagged`
  marker in `/system/device-mode/print`. You do not log in to look.
- **Never send a CVE trigger.** Every pre-auth row is a memory corruption,
  command injection or authentication bypass on production edge equipment.

---

## Step 12: Stage B, gated

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the device and a window, recorded before the first packet:

```
Stage B authorization
  Host/port:      192.0.2.10:8291/tcp (client-owned edge router, not subscriber CPE)
  Action:         one Winbox login, user admin, blank password (documented default)
  Blast radius:   a logged login; on success, administrative control of the edge
  Reversibility:  log entry remains
  Window:         <date/time, time zone>
  Authorized by:  <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| One documented default login on any admin UI or API here, per `infra-ssh`'s factory table or the vendor's documentation | Login logged; on success, administrative control. Proof is the authenticated reply; read nothing, change nothing. |
| Winbox username enumeration (CVE-2024-54772), any password guessing | Failed-login entries per attempt; `hunt-brute-force` rules. |
| Log4Shell check on a UniFi Network Application in 5.13.29 to 6.5.53 | One JNDI lookup to your DNS canary. Out-of-band DNS only, no LDAP or class loading. |
| A CWMP Connection Request with credentials, or any TR-064 SOAP action | Session or configuration action on a customer device and its ISP's ACS; needs the ISP's authorization too. |
| GenieACS NBI anything beyond the 6.2 query | Fleet-wide reach into customer devices. |
| RADIUS or TACACS+ protocol probes | Authentication-log entries on the client's AAA server. |

Declined, signed off or not:

- Any Winbox file request (CVE-2018-14847) or WebFig request beyond page load
  (CVE-2026-67281): both return credential stores.
- The declined scripts in Step 1, SSDP SUBSCRIBE or a LOCATION fetch, an FGFM
  message, a BGP OPEN, a syslog message, a bandwidth test.
- Every DoS-class row and every pre-auth exploit or implant check in the
  matrix. FMC's hard-coded password (CVE-2026-20316) is a credential: declined.
- Using the device as a proxy, SOCKS relay, bandwidth source, tunnel or
  "intermediary" (CVE-2019-3924) into the client network.

---

## Step 13: Grade by what you proved

| What you proved | Grade |
|---|---|
| ACS NBI answers unauthenticated queries | Critical: control of every managed CPE. Notify the same day. |
| Compromise marker (`HACKED-ROUTER-HELP-SOS`, client-confirmed IOCs) | High, reported as an incident. Notify the same day. |
| A KEV pre-auth row matched by a build from the device or the client (Winbox legacy plus build, UniFi OS, IOS XE web UI, J-Web, FGFM, FMC, Ruckus, SOHO KEV model) | High, unconfirmed exploitation |
| RouterOS API reachable on 8728 | High: clear-text admin logins, unlimited guessing, no fix (CVE-2026-16347) |
| UniFi Network Application build in the CVE-2026-22557 or Log4Shell range | High, unconfirmed |
| EOL SOHO model with a KEV row, admin UI on the WAN | High: no fix exists |
| Management plane reachable, build current or unknown (Winbox, WebFig, REST, btest, UniFi, EdgeOS, airOS, IOS XE, ASDM, FMC, J-Web, FortiGate admin, FGFM, PAN-OS, controller UIs, SOHO admin) | Medium; High once the client's build sits in a KEV or pre-auth range |
| Ubiquiti discovery or SSDP answering (ratio recorded), RIP answering with routes | Medium: reflector or information leak |
| CPE accepts an unauthenticated Connection Request (200/204), or TR-064 on the WAN | Medium; High for TR-064 when the model has a public pre-auth CVE |
| RomPager in the Misfortune Cookie range | Medium, labelled unconfirmed |
| TACACS+, RADIUS, BGP, syslog or flow collector port reachable | Low; BGP answering an unknown peer with OPEN is Medium |
| Any other version in a CVE range, not exploited | Medium for a pre-auth row, otherwise Low; always unconfirmed |
| ISP-managed CPE: 7547 answering 401 on the client's line | Informational, third-party-managed exposure |

### What is NOT a finding

- 7547 on an ACS; UniFi 8080 inform and 3478/udp beside a hosted controller;
  7547 answering 401 on a subscriber or ISP-managed CPE, on its own.
- 2000/tcp that is SCCP; a `ROSSSH` or `CISCO_WLC` banner alone (`infra-ssh`).
- Rows that need adjacency, a path position or credentials: CVE-2023-32154,
  CVE-2026-67278, CVE-2023-23912, CVE-2024-3596, CVE-2020-24363, post-auth rows.
- ACS-delivered CPE command injections (CVE-2025-67113, CVE-2026-15427): they
  need the ACS, so they raise the grade of an exposed ACS instead.
- Bulletin rows for products you did not fingerprint; anything seen only in
  passive data; any version claimed "vulnerable".

Evidence follows `evidence-hygiene`: exact command, source IP, time, raw reply
saved at probe time. Discovery, SSDP and RIP replies hold internal addresses;
quote only the fields that prove the finding. An NBI `[]` is the whole proof.
Compromise markers also get a `mid-engagement-ir-detection` record.

---

## Chain table

| Confirmed | Standalone | Where it goes next |
|---|---|---|
| Winbox legacy plus build in range | High | Decline the file read. Recommend rotating every RouterOS password: `user.dat` may already be gone. |
| RouterOS in the September 2026 KEV range with SSH reachable | Per `infra-ssh` | Client runs CERT.PL's IOC checks (Step 11). |
| IOS XE web UI, J-Web, FGFM or FMC reachable with a KEV-range build | High | Client runs the vendor's compromise checks; recommend removing internet reach first. |
| UniFi Network Application in the Log4Shell range | High, unconfirmed | Stage B out-of-band DNS check only. |
| Unauthenticated ACS NBI | Critical | Stop. ACS-delivered CPE injections in the matrix raise the impact narrative. |

## Validation checklist

- [ ] Probed from outside every client range; egress IP recorded.
- [ ] Every address client-owned and in scope; subscriber CPE only from a
      written sample; ISP-managed CPE labelled as such.
- [ ] Every listener proven by a protocol reply; honeypot signs checked.
- [ ] No `-sC`, `-A` or category selection; port-registered probes counted;
      declined scripts not run; `--data-length 0` on RADIUS and collectors.
- [ ] Winbox: `-sV` and the version script only. API: no `/login`. 10001/udp
      and 1900/udp: one datagram each, bytes in and out recorded.
- [ ] 7547: one unauthenticated GET, no path guessing, no SOAP. NBI: the
      nonexistent-ID query only. FGFM: TLS handshake only. PAPI: nothing sent.
- [ ] No bandwidth test; no request beyond the root or login page on any UI.
- [ ] Versions labelled with source and "unconfirmed"; logins only with a
      logged sign-off; compromise markers reported the same day.
- [ ] The report ends at exposure and impact. The device was not used as a hop.

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/device-cve-matrix.md` | Every family's CVEs with affected and fixed builds, KEV status (catalog 2026.10.13), how the version is known, test stance, owned-elsewhere pointers, the `infra-ssh` cross-reference, sources | mikrotik cve, winbox cve-2018-14847, mikrotrick ssh, unifi os kev, cve-2026-22557, misfortune cookie, genieacs cve, ios xe cve-2023-20198, j-web cve-2023-36845, fortimanager cve-2024-47575, fgfm 541, pan-os management cve, zyxel kev, draytek kev, tp-link kev, d-link kev, aruba papi cve, ruckus cve-2023-25717, callstranger, blast-radius |
| `references/fingerprints-and-ports.md` | Port and owner map, banners, titles and nmap labels, probes that fire on these ports, collisions, honeypot signs, offline discovery decoder, SSDP reading, AAA and control-plane rows | which skill for 8291, winbox fingerprint, routeros api 8728, btest 2000, ubiquiti 10001, unifi ports, cwmp 7547, genieacs ports, fgfm port 541, aruba 4343 8211, tacacs 49, radius 1812, bgp 179, rip 520, ssdp 1900, sccp 2000 collision |

## Related Skills & Chains

- `infra-external-methodology` routes these ports here. `infra-ssh` owns SSH
  and the factory-credential table; `infra-ftp`, `infra-dns`, `infra-vpn-ike`,
  `infra-windows-perimeter`, `infra-voip-sip` and `hunt-exposed-services`
  (SNMP, Smart Install, telnet, proxies, BMCs) own a device's other ports;
  `enterprise-vpn-attack` owns SSL VPNs and its listed admin rows;
  `hunt-exposed-panels` and `infra-backup-nas` own consoles and NAS models.
- `hunt-tls-network`, `hunt-brute-force`, `mid-engagement-ir-detection`,
  `evidence-hygiene`, `triage-validation`, `report-writing`,
  `redteam-report-template`: certificates, credential guessing, compromise
  markers, evidence and write-up.

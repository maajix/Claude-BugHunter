# Fingerprints and ports

Which skill owns a port seen on a network device, what identifies the device
from a read-only reply, and where ports collide. nmap names and match strings
were read from `nmap-services` and `nmap-service-probes` of nmap 7.991; an
`-sV` result is a label from those files, not proof.

---

## 1. Port and owner map

"Here" means `infra-network-devices`, with the SKILL.md step. Everything else
is routed; the device family does not move a protocol away from its owner.

| Port | Service | Family | Owner | Stage A read |
|---|---|---|---|---|
| 8291/tcp | Winbox (nmap name `winbox`) | MikroTik | Here, Step 4 | `-sV` plus `mikrotik-routeros-version` |
| 8728/tcp, 8729/tcp | RouterOS API, API-SSL (no nmap service name) | MikroTik | Here, Step 4 | `-sV` (`!fatal not logged in`) |
| 80, 443/tcp | WebFig, REST (`/rest`, RouterOS 7.1beta4 and later) | MikroTik | Here, Step 4 | Root page; REST `401` without credentials |
| 2000/tcp | Bandwidth-test server (nmap labels the port `cisco-sccp`) | MikroTik | Here, Step 4; SCCP to `infra-voip-sip` | `-sV` NULL probe reads the hello |
| 5678/udp | MNDP neighbour discovery | MikroTik | Here: record from passive data only | None (link-local by design) |
| 21, 22, 23/tcp | FTP, SSH (`ROSSSH`), telnet | MikroTik | `infra-ftp`, `infra-ssh`, `hunt-exposed-services` | Per owner |
| 8080, 1080/tcp | Web proxy (`Server: Mikrotik HttpProxy`), SOCKS | MikroTik | `hunt-exposed-services` (open proxies) | Per owner; never relay through it |
| 445/tcp, 53, 161/udp | SMB, DNS, SNMP | MikroTik and others | `infra-windows-perimeter`, `infra-dns`, `hunt-exposed-services` | Per owner |
| 500, 4500/udp, 1701, 1723, 1194 | IKE, L2TP, PPTP, OpenVPN | Any router | `infra-vpn-ike` | Per owner |
| 10001/udp | Ubiquiti discovery (nmap name `scp-config`) | Ubiquiti | Here, Step 5 | One 4-byte datagram |
| 8443/tcp | UniFi Network Application GUI and API | Ubiquiti | Here, Step 5 | `/status` |
| 8080/tcp | UniFi device inform | Ubiquiti | Here: by design on a hosted controller | None beyond `-sV` |
| 8880, 8843/tcp | UniFi guest portal | Ubiquiti | Here: confirms the controller, no finding | None |
| 6789/tcp, 3478/udp | UniFi throughput test, STUN | Ubiquiti | Here: confirms the controller, no finding | None |
| 5514/udp, 1900/udp | UniFi remote syslog, L2 discovery | Ubiquiti | Step 10 rows | Per Step 10 |
| 443/tcp | UniFi OS consoles and UniFi OS Server | Ubiquiti | Here, Step 5 | Title only |
| 80, 443/tcp | EdgeOS, airOS web UI | Ubiquiti | Here, Step 5 | Title, certificate |
| varies | UniFi Protect, Access, Talk, Connect, UISP | Ubiquiti | `hunt-exposed-panels` | Per owner |
| 7547/tcp | CWMP connection-request listener on a CPE (nmap name `cwmp`) | TR-069 | Here, Step 6 | One GET to `/` |
| 7547/tcp | CWMP endpoint on an ACS (CPEs call in) | TR-069 | Here, Step 6: by design | None |
| 7557, 7567/tcp | GenieACS NBI, file server | TR-069 | Here, Step 6 | NBI nonexistent-ID query; FS none |
| 3000/tcp | GenieACS UI, or Grafana | TR-069 | Here if GenieACS; Grafana to `hunt-exposed-panels` | Title |
| 80, 443/tcp | Cisco IOS XE web UI | Cisco | Here, Step 7 | Root page, title, certificate |
| 443/tcp | ASA ASDM, Firewall Management Center | Cisco | Here, Step 7; AnyConnect and `+CSCOE+` to `enterprise-vpn-attack` | Title, certificate |
| 4786/tcp, 161/udp | Smart Install, SNMP | Cisco | `hunt-exposed-services` `management-interfaces.md` | Per owner |
| 80, 443/tcp | J-Web | Juniper | Here, Step 7 | Title, certificate |
| 541/tcp | FGFM (FortiManager and FortiGate management tunnel; nmap name `uucp-rlogin`) | Fortinet | Here, Step 7 | TLS handshake and certificate only |
| 443 or admin port/tcp | FortiGate admin HTTPS | Fortinet | Here, Step 7; `/remote/` SSL VPN to `enterprise-vpn-attack` | Root page headers, certificate |
| 443/tcp | PAN-OS management web interface | Palo Alto | Here, Step 7 for the rows it keeps; `enterprise-vpn-attack` for the auth-bypass chain and GlobalProtect | Title, certificate |
| 80, 443, 8080, 8443/tcp | SOHO and CPE web admin | Zyxel, DrayTek, Netgear, TP-Link, D-Link, Linksys, Tenda | Here, Step 8 | Root page, title, `Server` header |
| 4343/tcp | Aruba controller WebUI (nmap name `unicall`) | Aruba | Here, Step 9 | Title, certificate |
| 8211/udp | Aruba PAPI (nmap lists `aruba-papi` on 8211/tcp only) | Aruba | Here, Step 9 | None: no PAPI datagram |
| 443, 8443/tcp | Ruckus Wireless Admin / Unleashed, SmartZone | Ruckus | Here, Step 9 | Title, certificate |
| 443/tcp | Cisco WLC (AireOS, Catalyst 9800) web UI | Cisco | Here, Step 9 | Title, certificate |
| 49/tcp | TACACS+ (nmap name `tacacs`) | AAA | Here, Step 10 | Port state only |
| 1812, 1813/udp (1645, 1646 legacy) | RADIUS authentication, accounting | AAA | Here, Step 10 | Port state with an empty datagram |
| 179/tcp | BGP | Control plane | Here, Step 10 | `-sV` NULL probe (reads only) |
| 520/udp | RIP (nmap name `route`) | Control plane | Here, Step 10 | One RIPv1 request |
| 514/udp | Syslog receiver | Control plane | Here, Step 10 | Port state only; never send a message |
| 2055/udp, 6343/udp | NetFlow (nmap name `iop`), sFlow collector | Control plane | Here, Step 10 | Port state only |
| 1900/udp | UPnP SSDP | Control plane | Here, Step 10 | One M-SEARCH |
| 623/udp | IPMI/BMC | Out of scope here | `hunt-exposed-services` | Per owner |

---

## 2. Banners, titles and `-sV` labels

| Family | Read-only identifier | Source |
|---|---|---|
| MikroTik | `-sV` on 8291: `MikroTik WinBox`, probes `MikroTik_Winbox` (`>=6.43`) and `MikroTik_Winbox_Legacy` (`<6.43`) | nmap-service-probes |
| MikroTik | 8728 reply `!fatal not logged in` to the `NotesRPC` probe | nmap-service-probes |
| MikroTik | 2000: the server's 4-byte hello `\x01\0\0\0`, label `MikroTik bandwidth-test server` | nmap-service-probes |
| MikroTik | FTP `220 MikroTik FTP server (MikroTik <ver>) ready`; SSH `SSH-2.0-ROSSSH`; proxy `Server: Mikrotik HttpProxy` | nmap-service-probes |
| MikroTik | Web title `mikrotik routeros > administration` (older WebFig); labels `MikroTik router http config`, `MikroTik router config httpd` | nmap-service-probes |
| Ubiquiti | `Ubiquiti Discovery Service` (10001/udp), `Ubiquiti Edge router httpd`, `Ubiquiti UniFi guest redirection` | nmap-service-probes |
| Ubiquiti | UniFi Network Application `/status` JSON `meta.server_version`; login page `angular/g<hash>` asset path; UniFi OS title `UniFi OS` | Metasploit check, Censys |
| TR-069 | `Allegro RomPager`, `ZyXEL RomPager`; `Thomson TR-069 remote access` (401 with Digest realm `Thomson_cwmp_<model>`); `FRITZ!Box TR-069 service` (400, empty body) | nmap-service-probes |
| Cisco | `Cisco IOS http config`, `Cisco IOS httpd`; `Cisco ASA firewall http config`; `Cisco Wireless LAN Controller httpd`; SSH `SSH-2.0-CISCO_WLC` (to `infra-ssh`) | nmap-service-probes |
| Juniper | J-Web title `Log In - Juniper Web Device Manager` with `Server: Mbedthis-Appweb/<ver>`; `Juniper router http config` | nmap-service-probes |
| Fortinet | `Server: xxxxxxxx-xxxxx` (label `Fortinet security device httpd`); `Fortinet FortiGate firewall http proxy admin` | nmap-service-probes |
| Palo Alto | `Palo Alto PanWeb httpd`, `Palo Alto firewall http admin`; `Palo Alto GlobalProtect Gateway httpd` goes to `enterprise-vpn-attack` | nmap-service-probes |
| Aruba | `Aruba wireless switch http admin`, `Aruba router http config` | nmap-service-probes |
| SOHO | `DrayTek Vigor router` (webadmin, telnetd, ftpd, sshd); `ZyXEL Prestige webadmin`, ZyWALL ftpd; `TP-Link TL-SG3210 switch admin httpd`, `TP-Link ADSL+ modem httpd`; `D-Link <model> http config`; `Linksys <model> router http config`; `Tenda WAP http admin` | nmap-service-probes |
| BGP | `bgp`, `connection rejected` (a NOTIFICATION) or `open` (an OPEN message), from the NULL probe | nmap-service-probes |
| RADIUS | `Juniper Steel-Belted Radius radiusd` matches an Access-Reject to nmap's `RADIUS_ACCESS` probe | nmap-service-probes |

nmap's SOHO signatures mostly cover old models. The login page's model string,
title and `Server` header decide; a label alone is a lead.

---

## 3. nmap probes that fire on these ports

A probe whose `ports` directive names the target port "is tried regardless of
intensity level" (nmap man page). UDP payloads for `-sU` and `-PU` come from
the same file (verify a port with `--packet-trace`); `--data-length 0` sends
no protocol payload.

| Port | Probe | Bytes or content | Effect |
|---|---|---|---|
| 10001/udp | `UbiquitiDiscoveryv1`, `UbiquitiDiscoveryv2` | Discovery requests | Two datagrams; Step 5 sends one instead |
| 1812/udp, 1645/udp | `RADIUS_ACCESS` | An Access-Request, code 1, length 20, no attributes | Lands in the server's authentication log; use `--data-length 0` |
| 520/udp | `RIPv1` | A RIPv1 whole-table request | Read-only; the reply lists routes |
| 1900/udp | `UPNP_MSEARCH` | M-SEARCH with `ST: ssdp:all`, `MX: 5` | Draws one reply per service; Step 10 sends `ST: upnp:rootdevice` instead |
| 3478/udp | `STUN_BIND` | A STUN binding request | Read-only |
| 179/tcp, 2000/tcp, 8291/tcp | `NULL` and port-registered probes | Connect and read | Read-only |
| 8728/tcp | `NotesRPC` | A Lotus Notes RPC request | RouterOS answers `!fatal not logged in`; no login sent |

---

## 4. Collisions

| Port | Possible owners | How to tell |
|---|---|---|
| 2000/tcp | MikroTik bandwidth-test; Cisco SCCP (nmap's default label) | The 4-byte hello `\x01\0\0\0` is MikroTik; anything else goes to `infra-voip-sip` |
| 3000/tcp | GenieACS UI; Grafana; Node development servers | Title; Grafana to `hunt-exposed-panels` |
| 7547/tcp | CPE connection-request listener; ACS CWMP endpoint | A CPE answers GETs (401, 200/204, 404); an ACS expects CWMP SOAP POSTs and sits beside 7557/7567 |
| 8080/tcp | UniFi inform; RouterOS web proxy; SOHO alternate admin port; generic HTTP | `Server` header and title |
| 8443/tcp | UniFi Network Application; Ruckus SmartZone; SSL VPN portals; SOHO alternate admin | Title and certificate; SSL VPN to `enterprise-vpn-attack` |
| 443/tcp | Every family here, plus SSL VPN portals | Title, `Server` header, certificate subject |
| 514 | tcp is `rsh` (`hunt-exposed-services`); udp is syslog (Step 10) | Transport |
| 541/tcp | FGFM; nmap's registered name is `uucp-rlogin` | TLS certificate subject (Fortinet serial or product names, verify format) |
| 4343/tcp | Aruba WebUI; nmap's name `unicall` | Title, certificate |
| 10001/tcp | nmap's `scp-config`; the Ubiquiti service is UDP | Transport |

---

## 5. Honeypot and sensor signs

- 7547, 8291, 8728 and 10001 all answering on one address beside unrelated
  vendor banners.
- RomPager 4.07 beside a modern TLS stack, or Winbox on a host whose other
  ports describe a Linux server.
- Several vendors' admin titles on one address (FortiGate on 443, J-Web on
  8443, RouterOS on 80).
- A scrubbing or DDoS-protection range: handshakes complete on every port.
  Only a protocol reply proves a listener.

A discovery hostname `HACKED-ROUTER-HELP-SOS` is not a sensor: it is a
compromise marker (Rapid7, 2019) and goes to the client the same day.

---

## 6. Reading a saved Ubiquiti discovery reply offline

The Step 5 probe saves the reply as a `raw <hex>` line. Decode it offline,
without sending anything. TLV types from `ubiquiti-discovery.nse`: 0x01 MAC,
0x02 MAC plus IPv4, 0x03 firmware, 0x0a uptime, 0x0b hostname, 0x0c product,
0x0d ESSID, 0x0f management port, 0x14 and 0x15 model, 0x16 version; the
header is 4 bytes (version, command, 2-byte length).

```bash
ubnt_decode() {  # usage: ubnt_decode evidence/<ip>_ubnt_discovery.txt
  grep '^raw ' "$1" | cut -d' ' -f2 | python3 -I -c '
import sys
data = bytes.fromhex(sys.stdin.read().strip())
names = {0x03: "firmware", 0x0b: "hostname", 0x0c: "product", 0x0d: "essid",
         0x14: "model", 0x15: "model", 0x16: "version"}
pos = 4
while pos + 3 <= len(data):
    typ, ln = data[pos], int.from_bytes(data[pos + 1:pos + 3], "big")
    val = data[pos + 3:pos + 3 + ln]
    if typ == 0x02 and ln >= 10:
        print("mac+ip", val[:6].hex(":"), ".".join(map(str, val[6:10])))
    elif typ in names:
        print(names[typ], val.decode("ascii", "replace"))
    pos += 3 + ln'
}
```

- `firmware` names platform and build (`EdgeRouter.ER-e50.v1.10.7...`,
  `XW.v6...`, UniFi device firmware): the version for the matrix.
- `mac+ip` lists interface addresses, internal ones included: record, never
  scan them. `essid` is client data; quote only what proves the finding.

---

## 7. Reading an SSDP reply

One M-SEARCH (Step 10) draws an HTTP-style reply, saved as hex. Print it
offline:

```bash
grep '^raw ' evidence/<ip>_ssdp.txt | cut -d' ' -f2 \
  | python3 -I -c 'import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode("ascii", "replace"))'
```

Record `SERVER` (OS, UPnP
stack and version, for example a MiniUPnPd build) and `ST`, and the sent and
received sizes. `LOCATION` is a URL on the device: record it, **never fetch
it**. Fetching it, or any SUBSCRIBE, is the CallStranger (CVE-2020-12695)
surface and the D-Link CVE-2019-17621 endpoint class. A reply from the
internet is the finding: SSDP is a LAN protocol and a known reflector.

---

## 8. AAA and control-plane rows

| Protocol | What a reply proves | Grade alone | Notes |
|---|---|---|---|
| TACACS+ 49/tcp | Port open; nmap has no TACACS+ probe | Low, Medium for an exposed device-admin AAA server | Every TACACS+ packet starts an AAA exchange: none sent |
| RADIUS 1812/1813/udp | Usually nothing: servers drop packets from unknown clients | Low | The empty-datagram state is the only Stage A read. Blast-RADIUS (CVE-2024-3596) needs on-path position |
| BGP 179/tcp | NULL-probe reply: `connection rejected` NOTIFICATION or `open` | Low; Medium when it answers an unknown peer with OPEN (AS number and router ID disclosed) | Never send OPEN or complete a session |
| RIP 520/udp | A whole-table reply lists internal routes | Medium (routing information to the internet) | Record the route count; quote none in full |
| Syslog 514/udp | Nothing (receive-only) | Informational unless the client confirms the collector | Sending a message writes into the client's logs: not Stage A |
| NetFlow 2055, sFlow 6343/udp | Nothing (receive-only collectors) | Informational | Port state and passive data only |
| SSDP 1900/udp | One reply per M-SEARCH, size ratio | Medium: reflector plus device information | Section 7 |

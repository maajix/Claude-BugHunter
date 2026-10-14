# Remote-display protocols

Citrix ICA, CGP, XML service and StoreFront; Apache Guacamole and guacd; NoMachine;
SPICE; and the routing for Microsoft RD Gateway. CVE rows are in `cve-matrix.md`.

The recurring finding in this file is not a CVE. It is a **display or brokering
protocol reachable from the internet without the gateway that was supposed to
authenticate it**: a VDA without Citrix Gateway, guacd without the Guacamole web
application, a hypervisor console port without its management plane.

Sources were fetched 2026-10-13; nmap facts are from nmap 7.991's
`nmap-service-probes` and NSE sources on the test host.

---

## Citrix Virtual Apps and Desktops

NetScaler ADC/Gateway is `enterprise-vpn-attack`'s. Everything behind it is here.

| Item | Value | Source |
|---|---|---|
| Ports | VDA ICA/HDX TCP/UDP 1494 (EDT needs UDP 1494); ICA with Session Reliability (CGP) TCP/UDP 2598; Delivery Controller TCP 80 and 443, which carry the XML service | Citrix "default network ports" (7.15 LTSR) |
| ICA greeting | The server speaks first: `\x7f\x7fICA\0` repeated. nmap matches it under the NULL probe as "Citrix Metaframe XP ICA" | `nmap-service-probes` line 356 |
| CGP greeting | Not documented in the sources checked; identify with `nmap -sV` and the port's context (verify) | n/a |
| XML service | nmap matches `Server: XMLD HTTPServer/<ver>` as "Citrix XML Service"; the `citrix-enum-*-xml` scripts POST `text/xml` to `/scripts/WPnBr.dll` (`RequestAppData` with access lists, or `RequestServerData`) on 80, 443, 8080 | `nmap-service-probes` line 8988; `nselib/citrixxml.lua` |
| Legacy ICA browser | UDP 1604, matched as `icabrowser` | `nmap-service-probes` |
| Vendor position | "To allow remote users to securely connect to StoreFront and the VDAs, deploy a NetScaler gateway." Enable HTTPS and restrict XML-service access (security keys, firewalls, IPsec) before enabling XML trust. Citrix does not use the word misconfiguration for direct VDA exposure | Citrix CVAD security best practices |

```bash
T="198.51.100.20"
# 1 connection each, nothing sent. A VDA answers with the ICA greeting.
timeout 10 nc -v -w 5 "$T" 1494 </dev/null | head -c 32 | xxd | head -2
probe_delay
nmap -Pn -n -sT -sV -p 2598 "$T"
```

### StoreFront

| Item | Value | Source |
|---|---|---|
| Paths | Store `/Citrix/<StoreName>`, auth service `/Citrix/<StoreName>Auth`, Receiver for Web `/Citrix/<StoreName>Web` (`/Citrix/StoreWeb` is Citrix's own example) | Citrix StoreFront docs; CTX237970 |
| Unauthenticated discovery | `GET <store>/discovery` (e.g. `/Citrix/Store/discovery`) "does not require an authorization token" and returns XML naming the store's endpoints, authentication service, beacons and gateways. No product version | Citrix StoreFront Store Services API |
| Version | No passive version disclosure found in headers, JavaScript or CSS (verify) | n/a |

```bash
# 1 request to a documented, token-free endpoint. Gateway and beacon names are recon.
curl -sk -m 15 "https://${T}/Citrix/Store/discovery" | head -c 2000
```

Do not POST to `/Citrix/<store>Auth/SamlTest` (the CVE-2023-5914 nuclei
template's reflection probe) or launch an ICA file from Receiver for Web.

### Reading the Citrix results

| Observation | Meaning | Grade |
|---|---|---|
| ICA greeting on 1494 or a CGP listener on 2598 from the internet | VDA or session host reachable without Gateway; clients still need a launch ticket, but the session host's own attack surface is exposed | Medium |
| `XMLD HTTPServer` answering from the internet | Delivery Controller XML service exposed; published-application enumeration is one request away | Medium |
| StoreFront `discovery` answers | Expected on an internet StoreFront; the content (internal Gateway or beacon hostnames) may be Low | Info to Low |
| StoreFront with NetScaler Gateway in front | Gateway CVEs | `enterprise-vpn-attack` |

Stage B, with sign-off naming the host: one `nmap --script citrix-enum-apps-xml`
run. It returns published application names and their access lists, which name
directory groups. Stop at the list; do not request launch data.

---

## Apache Guacamole

Two components with different exposure: the **web application** (Tomcat,
usually 8080 or 443 under `/guacamole/`) authenticates users; **guacd** (TCP
4822) is the proxy daemon that opens RDP, VNC, SSH and telnet connections on the
web application's instruction.

| Item | Value | Source |
|---|---|---|
| guacd default bind | `bind_host` defaults to localhost ("only connections from within the server hosting guacd will succeed"); `bind_port` 4822; TLS optional | Guacamole manual, configuring Guacamole |
| guacd authentication | Apache's docs put authentication in the web application and say nothing about guacd authenticating clients. Check Point's Mobile Access guide states "guacd does not authenticate its clients" | Guacamole architecture chapter; Check Point R81.20 Mobile Access guide |
| guacd handshake | Instructions are `LENGTH.VALUE` elements, comma-separated, ending in `;`. Client sends `6.select,3.vnc;`; guacd replies `4.args,13.VERSION_x_y_z,8.hostname,...`. Nothing connects until the client sends `connect` | Guacamole protocol chapter and protocol reference |
| Version from guacd | Coarse: the first `args` element is the **protocol** version. guacd 1.5.5 and 1.6.0 both send `VERSION_1_5_0`; 1.4.0 sends `VERSION_1_3_0` | `guacamole-server` `protocol-constants.h` at tags 1.4.0, 1.5.5, 1.6.0 |
| Version from the web app | `/guacamole/translations/en.json` carries `"APP":{"NAME":"Apache Guacamole","VERSION":"<version>"}` (Maven-filtered at build) | `guacamole-client` `en.json` and `pom.xml` |
| Default credential (Stage B only: one attempt, with written sign-off) | "The default Guacamole user created by the provided SQL scripts is `guacadmin`, with a default password of `guacadmin`" (database authentication) | Guacamole manual, PostgreSQL authentication |

```bash
T="198.51.100.30"
# Web app version: 1 request.
curl -sk -m 15 "https://${T}/guacamole/translations/en.json" | grep -o -E '"VERSION":"[^"]*"'
probe_delay
# guacd: 1 connection, one select, read args, close. Never send a connect instruction.
printf '6.select,3.vnc;' | timeout 10 nc -w 5 "$T" 4822 | head -c 300; echo
```

Reading the results:

- Any `args` reply from 4822 on a public address is the finding: guacd is
  meant to bind to localhost, and whoever reaches it can instruct it to connect
  anywhere it can route. High to Critical by what sits behind it. The proof is
  the `args` line; sending `connect` with a hostname is pivoting and is never
  done, signed off or not.
- The web application on the internet is normal. Grade it by version
  (`cve-matrix.md`: every Guacamole row since 2021 needs an authenticated user)
  and by the default credential, tried once under Stage B.
- Ivanti Connect Secure embeds Guacamole under `/dana-na/.../html5acc/guacamole/`;
  that path and its CVEs are `enterprise-vpn-attack`'s.

---

## NoMachine

| Item | Value | Source |
|---|---|---|
| Ports | nxd TCP 4000; multimedia UDP 4000 from v8 (4011-4999 before v8); web (nxhtd) HTTPS 4443, with up to v8 a 4080 listener redirecting to HTTPS (the KB writes "4043", likely a typo for 4443, verify); SSH-based NX on 22 (Linux/macOS) or nxsshd 4022 (Windows) | NoMachine KB AR01L00770 |
| Banner | nmap sends `NXSH-5.6.7\n` to 4000 ("could be anything") and matches `NXD-<version>\n` as "NoMachine NX Server". That this equals the installed product version is nmap's mapping, not the vendor's (verify) | `nmap-service-probes` lines 16863-16869 |
| Authentication | System accounts (password or key) by default, so 4000 on the internet is a password-login surface (verify per edition) | n/a |

```bash
# 1 connection: the same client greeting nmap sends.
printf 'NXSH-5.6.7\n' | timeout 10 nc -w 5 "$T" 4000 | head -c 64; echo
```

Reading the result: NoMachine's 2021-2026 CVEs are local, client-side, or need
a logged-in user (CVE-2026-18264, web service on TCP 4000, fixed 9.8.2 and
8.26.1). Exposure alone is Low to Medium, and password guessing against it is
`hunt-brute-force`'s decision. A login with a client test account is Stage B.

---

## SPICE

| Item | Value | Source |
|---|---|---|
| Ports | libvirt binds SPICE to 127.0.0.1 by default; display ports from 5900 upward (range to 65535); oVirt hosts open TCP 5900-6923 for VNC/SPICE; Proxmox VE's SPICE proxy is TCP 3128 | libvirt `qemu.conf.in`; oVirt install guide; Proxmox VE firewall wiki |
| Link handshake | Client `SpiceLinkMess` starts with magic `REDQ`, version 2.2; server `SpiceLinkReply` carries an error code, a 1024-bit RSA public key and capabilities; the client then sends the ticket RSA-OAEP encrypted; the server answers 0 (OK) or 7 (permission denied) | SPICE protocol spec |
| nmap | Matches `REDQ\x02\0\0\0\x02\0\0\0` as SPICE 2.2, from the LANDesk-RC probe's reply | `nmap-service-probes` line 15120 |
| Auth state | Capabilities in the reply advertise `AUTH_SASL` or `AUTH_SPICE`. Whether ticketing is disabled needs an active step: send any ticket and read 0 or 7. Ticketing is on by default; libvirt sets no password unless `spice_password` is configured | `spice` `server/reds.cpp`; libvirt `qemu.conf.in` |

```bash
# 1 connection set. Identification only; no ticket is sent.
nmap -Pn -n -sT -sV -p 5900-5910 "$T"
```

Reading the result: a SPICE port on a public address is a hypervisor console
exposed outside its management plane, Medium as an exposure. Whether it needs a
ticket is a Stage B question: one ticket exchange with a random value, stopping
at the 0 or 7 result code, under sign-off naming the port. A 0 means anyone can
open that VM's console: Critical, and nothing more is done. On 3128, tell Squid
from Proxmox `spiceproxy` by the response before routing (`hunt-exposed-services`
owns Squid).

---

## Microsoft RD Gateway and RD Web Access (routing only)

| Fingerprint | Source |
|---|---|
| RD Gateway HTTP transport bound at `/remoteDesktopGateway/`, custom methods `RDG_OUT_DATA` and `RDG_IN_DATA`, `RDG-Connection-Id` header | MS-TSGU specification |
| RD Web client at `/RDWeb/webclient/index.html` | Microsoft RD web client admin docs |

Owners: `infra-windows-perimeter` for the RD Gateway and KDC Proxy CVE rows (its
`windows-service-cve-matrix.md`) and RDP on 3389; `hunt-ntlm-info` for NTLM
metadata on `/RDWeb` and the gateway; `hunt-brute-force` for RD Web password
spraying. Nothing about RD Gateway is repeated here.

---

## Sources (fetched 2026-10-13)

- Citrix: <https://docs.citrix.com/en-us/xenapp-and-xendesktop/7-15-ltsr/technical-overview/default-network-ports>,
  <https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/secure/best-practices>,
  <https://docs.citrix.com/en-us/storefront/current-release/configure-manage-stores/create-store.html>,
  <https://developer-docs.citrix.com/en-us/storefront/storefront-store-services-api/discovery-service>
- Guacamole: <https://guacamole.apache.org/doc/gug/configuring-guacamole.html>,
  <https://guacamole.apache.org/doc/gug/guacamole-protocol.html>,
  <https://guacamole.apache.org/doc/gug/protocol-reference.html>,
  <https://guacamole.apache.org/doc/gug/postgresql-auth.html>,
  <https://github.com/apache/guacamole-client> (`translations/en.json`, `pom.xml`),
  <https://github.com/apache/guacamole-server> (`protocol-constants.h`),
  Check Point R81.20 Mobile Access guide (Guacamole-based clientless RDP/SSH)
- NoMachine: <https://knowledgebase.nomachine.com/AR01L00770>
- SPICE: <https://www.spice-space.org/spice-protocol.html>,
  <https://gitlab.freedesktop.org/spice/spice/-/raw/master/server/reds.cpp>,
  <https://gitlab.com/libvirt/libvirt/-/raw/master/src/qemu/qemu.conf.in>,
  <https://pve.proxmox.com/wiki/Firewall>
- RD Gateway: MS-TSGU <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/>;
  <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-web-client-admin>
- nmap 7.991: `/usr/share/nmap/nmap-service-probes`, `/usr/share/nmap/nselib/citrixxml.lua`

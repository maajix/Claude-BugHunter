# Exposed management interfaces and out-of-band control

This is the highest-value group in the skill and the one where the scope
boundary is tightest. A management interface is, by definition, the thing that
controls the host. Reaching one from the internet is Critical before you touch
anything, and almost everything you could do *after* reaching it is outside this
bundle.

So the discipline is blunt: **prove you can reach the management plane
unauthenticated, describe what that plane controls, and stop.** No shell, no
console session, no configuration read, no credential cracking.

| Port | Service | What the exposure means |
|---|---|---|
| 623/udp (and 623/tcp, 664/udp) | IPMI on a BMC (iDRAC, iLO, IMM, CIMC, Supermicro) | Out-of-band control of the server independent of its OS: power cycle, virtual console, virtual media, firmware. A BMC on the internet is Critical before any auth test. |
| 161/udp, 162/udp | SNMP agent and trap receiver | A working community string reads the device's whole configuration view: interfaces, routes, ARP tables, running processes, serial numbers, sometimes credentials in a vendor MIB. A read-write string rewrites the configuration. |
| 5985, 5986 | WinRM, and the Linux OMI agent on the same ports | Windows remote management. OMI is the Linux management agent Azure installs, and it has had a pre-auth authentication-bypass. |
| 5900-5906 | VNC / RFB | Interactive console. RFB security type `1` means *no authentication at all*. |
| 389, 636, 3268, 3269 | LDAP and LDAPS, plus AD Global Catalog | Anonymous bind leaks the directory's structure, naming contexts and host naming. |
| 264 | Check Point FW-1 SecuRemote topology service | Historically returns the firewall's topology: internal network objects, address ranges and encryption domains. |
| 4786 | Cisco Smart Install | A director/client protocol with no authentication, able to push configuration and images to switches. |
| 12346/udp | Cisco Catalyst SD-WAN control plane | Control-plane reachability for an SD-WAN fabric. |
| 3299 | SAProuter | An application-level router into an SAP landscape. |
| 10000 | NDMP **or** Webmin | IANA's registry assigns 10000/tcp and 10000/udp to NDMP and to nothing else; Webmin is unregistered but its own documentation says it "usually listens for connections on port 10000 on all of your system's IP addresses". So the port number does not decide this one: the banner does. Backup and restore control plane, or a root-privileged web admin panel. Two completely different findings, so fingerprint before you write. |

## Stage A probes

### SNMP (161/udp)

```bash
TARGET="192.0.2.40"

# One community string per attempt, serial, with the standard delay. Try only
# the documented vendor defaults, once each: anything more is brute force.
snmpwalk -v 2c -c public -r1 -t5 "$TARGET" 1.3.6.1.2.1.1      # system MIB only
snmpget  -v 2c -c public -r1 -t5 "$TARGET" 1.3.6.1.2.1.1.1.0  # sysDescr

# SNMPv3 with no credentials: does the agent accept noAuthNoPriv?
snmpget -v 3 -l noAuthNoPriv -u probe -r1 -t5 "$TARGET" 1.3.6.1.2.1.1.1.0

# nmap equivalents, both safe: snmp-info and snmp-sysdescr.
```

Stop at the system MIB (`1.3.6.1.2.1.1`). `sysDescr`, `sysName`, `sysLocation`
and `sysContact` identify the device, its firmware and frequently its physical
site: a complete finding. Walking the full tree pulls interface tables, ARP
caches and route tables, which is a large volume of internal topology you do not
need and should not hold.

**Never** `snmpset`. A write community is a configuration change on a production
device. The Cisco pattern of using a read-write community plus TFTP to pull the
running configuration is a configuration read **and** a file transfer: Stage B,
with the config's credential contents as the named blast radius.

### IPMI / BMC (623/udp)

```bash
# Detection only. Does a BMC answer, and which IPMI version and cipher suites
# does it advertise?
nmap -Pn -sU -p 623 --script ipmi-version --scan-delay 1s "$TARGET"
```

Three findings live here, in increasing severity, and the first two are Stage A:

1. **A BMC answers at all from the internet.** Critical on its own. Write it up
   before testing anything else.
2. **IPMI 2.0 RAKP password-hash disclosure (CVE-2013-4786).** The RAKP
   message-2 exchange returns an HMAC of the user's password to an
   *unauthenticated* requester, which can then be cracked offline. The hash
   being returned **is the finding**; it is an unauthenticated
   credential-material disclosure. Record that the BMC returned hash material
   for a username, with the username redacted in the report body. One
   precondition to state honestly: it needs a **valid username**, so this is
   rated partial rather than fully pre-auth. Use a documented vendor default
   (`ADMIN`, `root`) once; do not enumerate usernames.
3. **Cipher suite 0.** In the IPMI 2.0 specification's Cipher Suite IDs table,
   ID `0` has the algorithm triple `00h, 00h, 00h`, i.e. **RAKP-none
   authentication, None integrity, None confidentiality**, and the table
   characterises it as "no password". The spec states plainly that RAKP-none
   provides neither password authentication nor packet-level integrity checking,
   and that the RAKP steps establish a session ID and privilege level using only
   the supplied username and role. A BMC that negotiates it therefore accepts
   **any** password for a valid user. BMCs from Supermicro, Dell (iDRAC6 and
   iDRAC7), HP (iLO) and Raritan all shipped accepting it, each with its own CVE.

   **Reading the advertised cipher suites with `ipmi-version`
   (`discovery`, `safe`, a Get Channel Auth Capabilities request) is Stage A.**
   The `ipmi-cipher-zero` script is not: it carries the `vuln` category and
   sends an RMCP+ Open Session Request with cipher zero, which crosses the
   authentication boundary.

   Using cipher 0 to log in, create a user, change a password or control power
   is Stage B. For the record, `ipmitool`'s cipher selection is `-C
   <ciphersuite>` on a `lanplus` connection, where the default is 17, so a
   cipher-0 session is `ipmitool -I lanplus -C 0 -H <host> -U <user> -P
   <anything> <command>`. It is written here so you recognise it in a
   write-up, not so you run it.

Hard limits here:

- **Cracking a captured RAKP hash is Stage B.** The hash is already the
  reportable finding. Cracking it produces a live credential to a power-control
  plane, which the engagement usually does not need and the operator must
  authorise explicitly.
- **Nothing that reaches the host through the BMC.** Virtual media, virtual
  console, serial-over-LAN and power control are all outside this bundle's
  boundary. The chain ends at the BMC.
- **One username per probe, serial.** Username enumeration against a BMC is
  brute force; use only a documented vendor default such as `ADMIN` or `root`,
  once.

### WinRM and OMI (5985, 5986)

```bash
# Which authentication schemes does the endpoint advertise to an anonymous
# client? A 401 listing the schemes is the expected, correct behaviour.
curl -s -i -m 10 -X POST "http://$TARGET:5985/wsman" \
  -H 'Content-Type: application/soap+xml;charset=UTF-8' --data '' | head -20

curl -sk -i -m 10 -X POST "https://$TARGET:5986/wsman" \
  -H 'Content-Type: application/soap+xml;charset=UTF-8' --data '' | head -20
```

A `401` with `WWW-Authenticate: Negotiate, Basic` is the normal reply. The
findings are: WinRM reachable from the internet at all (Medium, because it is a
remote-management plane that belongs behind a VPN); `Basic` offered over plain
HTTP on 5985 (credentials in cleartext); and a response that is **not** a 401,
which points at OMI.

**CVE-2021-38647 ("OMIGOD").** The Linux OMI agent, which Azure installs with
several management extensions, treats a request carrying **no `Authorization`
header** as `uid=0, gid=0`, i.e. root. Affected: OMI before 1.6.8-1, and the
bundling agents (OMS Agent for Linux before 1.13.40-0, LAD, the DSC agent, SCOM's
OMI). The ports confirmed by Microsoft's own `omiserver.conf` are **5985
(`httpport`) and 5986 (`httpsport`)**; the shipped configuration sets both to
`0`, so a listening OMI means something enabled it. A fourth port, 1270, is
widely quoted for the SCOM case but is not stated in any Microsoft source, so
treat it as unconfirmed if you cite it.

Detection is the request above: if an unauthenticated POST to `/wsman` returns
something other than a 401, flag it and escalate. **Do not send a command
payload.** The exploit is a single unauthenticated request that runs a command
as root, and running it is both past the boundary and unnecessary: a non-401
response on a version in range is the finding.

The NTLM Type-2 message you can extract from the `Negotiate` challenge leaks
the NetBIOS domain, the internal DNS forest name and the computer name. That is
`hunt-ntlm-info`'s territory, not a second finding here.

**Never** open a WinRM session, authenticated or otherwise. A shell is past the
boundary.

### VNC (5900-5906)

RFB (RFC 6143) opens with the server sending a 12-byte ProtocolVersion string
`RFB xxx.yyy\n`. The server only sends its list of security types **after** the
client answers with its own version, so a probe that sends nothing gets the
version banner and no security list. Send the version reply and nothing more:

```bash
# Server version, then the security-type list. Stops before ClientInit.
{ sleep 1; printf 'RFB 003.008\n'; sleep 2; } \
  | timeout 15 nc -w 10 "$TARGET" 5900 | xxd | head -4
# Bytes 0-11  : server ProtocolVersion, e.g. "RFB 003.008\n"
# Byte  12    : number of security types that follow
# Bytes 13..  : the type values. 1 = None, 2 = VNC Authentication, 0 = failure
#               (followed by a length-prefixed reason string)
```

Security type `1` means **None**: no authentication, direct framebuffer access.
That is the finding, and the handshake alone proves it. You do not need a viewer.
`vnc-info` (`default`, `discovery`, `safe`) does the same handshake read and
stops before ClientInit, so it is an acceptable alternative.

Stopping here is also what makes the probe safe. The shared-versus-exclusive
decision is carried in **ClientInit**, which comes after the security handshake.
A probe that ends before ClientInit never requests a session, so it cannot
disconnect the person currently using the console. Displays listen on 5900 plus
the display number, so check 5900-5906.

**Connecting a viewer is Stage B, not a flag you can make safe.** TigerVNC's
`-Shared` only *requests* that existing connections be left open, and the server
decides: `Xvnc -NeverShared` ignores the client's request entirely, and
`Xvnc -DisconnectClients` defaults to **on**, which disconnects existing clients
when an incoming connection is non-shared. So a viewer connection can still
knock the person at the console off, and you cannot tell in advance. If the
operator signs off on a screenshot, use `-Shared -ViewOnly`, name "may
disconnect the live console user" as the blast radius, and accept that it may
happen anyway.

Do not recover stored VNC passwords, and do not send input events. Never run
`realvnc-auth-bypass`: it is tagged `safe` but carries `vuln` because it
actually performs the CVE-2006-2369 bypass, offering security type None even
when the server did not advertise it.

### LDAP (389, 636, 3268, 3269)

```bash
# rootDSE only. Base scope, empty base DN.
ldapsearch -x -H "ldap://$TARGET:389" -s base -b "" \
  "(objectClass=*)" namingContexts defaultNamingContext \
  supportedLDAPVersion supportedSASLMechanisms dnsHostName

ldapsearch -x -H "ldaps://$TARGET:636" -s base -b "" "(objectClass=*)" 2>/dev/null | head -40
```

An anonymous bind returning rootDSE attributes is the finding: it hands over the
directory's naming contexts, the server's own DNS host name and, on Active
Directory, the forest and domain structure. Grade it Medium.

**Stop at rootDSE.** Enumerating users, groups, service principal names or
`userPassword` attributes against a directory is Active Directory
reconnaissance, which `SECURITY.md` excludes from this bundle. LDAP *injection*
against an application is a different vulnerability class and belongs to
`hunt-ldap`.

### Check Point 264, Cisco Smart Install 4786, Cisco SD-WAN 12346/udp

```bash
# Check Point SecuRemote topology service: does it answer?
timeout 10 nc -w 5 "$TARGET" 264 < /dev/null | head -c 256 | xxd | head -4

# Cisco Smart Install: SINGLE probe for reachability. See the warning below.
nmap -Pn -p 4786 -sV --version-intensity 0 --scan-delay 2s --max-retries 1 "$TARGET"
```

**Cisco Smart Install is the most dangerous probe in this skill.** The protocol
has no authentication and is designed to push configuration and images to
switches, and **CVE-2018-0171** is an unauthenticated buffer overflow in the
Smart Install client on TCP 4786. Cisco's own advisory lists three possible
impacts of that single overflow: triggering a reload of the device, executing
arbitrary code on the device, and causing an indefinite loop that triggers a
watchdog crash. Two of the three are an outage.

Note the affected-version trap: the real test is **"is the Smart Install client
enabled"**, not a version range. Cisco's advisory gives no range and defers to
its Software Checker, and NVD's single CPE for this CVE is incomplete, so do not
quote a version range for it.

A single reachability probe is Stage A. Everything else is Stage B with the
switch's availability as the named blast radius. Never attempt a configuration
fetch, never attempt a configuration or image push, and never run a `vuln` or
`exploit` category script against it. If port 4786 answers, you have a Critical
finding. File it.

Check Point 264 and Cisco SD-WAN 12346/udp are reachability findings. Record
that the service answers and what it fronts. Topology retrieval from 264 is a
configuration read: treat it as Stage B.

### Appliance CVEs: pre-auth, in CISA KEV, detect by version only

| CVE | Product and range | Class | Notes |
|---|---|---|---|
| CVE-2026-20182 | Cisco Catalyst SD-WAN Controller (vSmart), Manager (vManage) and Validator (vBond). Many branches: below 20.9.9.1, and bands across 20.10 to 20.18.2.2, plus 26.1 to 26.1.1.1. Check the advisory for the exact band. | Peering-authentication bypass leading to administrative takeover (CWE-287) | **Pre-auth, CVSS 10.0**, `AV:N/PR:N/UI:N`. In CISA KEV from 2026-05-14. |
| CVE-2026-16232 | Check Point SmartConsole with Quantum and Multi-Domain Security Management: R82.10 up to JHF Take 36, R82 up to Take 118, R81.20 up to Take 158, plus the R81.10 and older line | Login-token authentication bypass giving full administrative access (CWE-287) | Pre-auth but **configuration-gated**: it needs a reachable Management Server and unrestricted Trusted Clients. Exploited in the wild; KEV 2026-07-22. |
| CVE-2022-27668 | SAProuter, via SAP NetWeaver / ABAP Platform KERNEL 7.49, 7.77, 7.81, 7.85-7.88; KRNL64NUC and KRNL64UC 7.49; SAP_ROUTER 7.53 and 7.22 | Improper authorization (CWE-863) permitting remote SAProuter administrative commands | **PARTIAL**, not reliably pre-auth: whether it works depends on the `saprouttab` route-permission entries. Report the version and the exposure; do not claim command execution you have not been authorised to attempt. |

Two Check Point boundaries, so you file in the right place:

- **CVE-2024-24919 is not this skill's finding.** It is reached over the
  HTTPS VPN portal, which is a web surface, and `offensive-osint` already
  carries it with the portal paths. Go there. (For accuracy if you do write it
  up: Check Point words it as **information disclosure**, CWE-200, "read
  certain information", not as arbitrary file read, whatever the write-ups say.)
- **CVE-2023-28130 is not a network finding at all.** It is a Gaia Portal
  command injection reachable by a *local* user (`PR:H`), described by the
  vendor as local privilege escalation.

### Veeam Backup & Replication on 9401

A backup server should never be internet-reachable, and this is the clearest
case in the file of a finding you complete from the version string alone.

| CVE | Range | Class |
|---|---|---|
| CVE-2023-27532 | All builds before 12 build 12.0.0.1420 P20230223, and before 11a build 11.0.1.1261 P20230227 | Missing authentication (CWE-306) in `Veeam.Backup.Service.exe` on **TCP 9401**, returning encrypted credentials from the configuration database to, in Veeam's words, an "unauthenticated user operating within the backup infrastructure network perimeter". KEV 2023-08-22. |
| CVE-2024-40711 | 12.0.0.1420 and above, below 12.2.0.334 (Veeam's KB lists 12.1.2.172 and all earlier v12 builds) | Deserialization of untrusted data (CWE-502) giving remote code execution. KEV, flagged as used in ransomware. |

On CVE-2024-40711, know the ambiguity before a client challenges you. Veeam's KB
and the CVE record both say **unauthenticated** RCE and the record carries
`PR:N` with 9.8, and NVD's change history shows no revision of that. But the KB
prints a `PR:L` vector string next to the 9.8 score, which is internally
inconsistent, and third-party analysis describes the path as working both with
and without authentication. Report it as the vendor and the CVE record state it,
unauthenticated, and if pressed, cite the record rather than the KB's vector.

Everything the knowledge base covers *after* this point, which is credential
recovery from the configuration database and extracting data out of backup
files, is post-access work and is out of scope for this bundle. The finding is
the reachable version. Stop there.

### SAProuter 3299 and NDMP / Webmin on 10000

```bash
# SAProuter: an information request returns the route table and connected hosts.
# This is Stage A. Routing a connection THROUGH it is not.
nmap -Pn -p 3299 -sV --version-intensity 0 --scan-delay 2s "$TARGET"

# Port 10000: disambiguate NDMP from Webmin before writing anything.
curl -sk -i -m 10 "https://$TARGET:10000/" | head -15   # Webmin serves HTTP(S)
nmap -Pn -p 10000 -sV --version-intensity 0 --scan-delay 2s "$TARGET"
```

SAProuter: stop at the info or route-table response. **Using the router to reach
an internal SAP host is pivoting** and is excluded from this bundle regardless
of how the scope is worded.

NDMP: the version/connect handshake leaks the hostname, OS and NDMP version.
That is the whole Stage A test. Anything beyond it touches the backup and
restore plane, where a misdirected job can overwrite a backup set: Stage B, with
that named as the blast radius.

Webmin on 10000 is a root-privileged web admin panel. If that is what answers,
the finding is a web-application exposure, not an NDMP one, and the version
matters: **CVE-2019-15107** is a command injection in the `old` parameter of
`password_change.cgi` affecting Webmin up to and including 1.920, rated PR:N and
UI:N, i.e. unauthenticated remote command execution. Detect by version; do not
send the injection.

## Grading

| Proof | Grade |
|---|---|
| BMC/IPMI reachable from the internet | Critical |
| RAKP hash material returned to an unauthenticated requester | Critical |
| Cipher suite 0 offered | Critical |
| Cisco Smart Install (4786) answering | Critical |
| VNC offering security type None | Critical |
| SNMP read community working on a network device | High |
| SNMP read-write community working | Critical (configuration write capability, untested) |
| WinRM/OMI reachable; `Basic` over plain HTTP | Medium to High |
| Anonymous LDAP bind returning rootDSE | Medium |
| Check Point 264, SAProuter 3299, SD-WAN 12346/udp answering | Medium to High by what it fronts |
| NDMP handshake returning host and OS | Medium |

## Checklist

- [ ] Every finding filed at reachability level; no management session opened.
- [ ] No `snmpset`, no configuration read via SNMP plus TFTP.
- [ ] SNMP walk bounded to the system MIB; no interface, ARP or route tables
      retained.
- [ ] At most one documented default community string or username per service,
      tried once.
- [ ] IPMI: cipher-0 availability detected only, never used. No RAKP hash
      cracked. No virtual media, console, SOL or power action.
- [ ] VNC: handshake read only; if a viewer was used it was shared and
      view-only, and that is recorded.
- [ ] LDAP: rootDSE only. No user, group or SPN enumeration.
- [ ] Cisco Smart Install: one reachability probe, no config or image operation,
      no vuln-category script.
- [ ] SAProuter: no connection routed through it.
- [ ] Port 10000 disambiguated between NDMP and Webmin in the report.
- [ ] No WinRM session, no shell, nothing after the auth boundary.

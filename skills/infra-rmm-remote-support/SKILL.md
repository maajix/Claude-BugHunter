---
name: infra-rmm-remote-support
description: "Triage internet-exposed RMM and remote-support servers and the remote-display protocols behind them: ConnectWise ScreenConnect, SimpleHelp, BeyondTrust Remote Support and PRA, N-able N-central, Kaseya VSA, ManageEngine Endpoint Central, Splashtop and AnyDesk on-premises, SaaS RMMs (Atera, NinjaOne, Datto RMM), TeamViewer 5938 and AnyDesk 7070 listeners, Citrix ICA 1494, CGP 2598, XML service and StoreFront, Apache Guacamole and guacd 4822, NoMachine 4000 and SPICE. Separates vendor cloud from client-owned servers, fingerprints product and version passively, and version-gates against a 2021-2026 CVE matrix with CISA KEV status and fixed builds (ScreenConnect CVE-2024-1709, SimpleHelp CVE-2024-57727, BeyondTrust CVE-2026-1731, N-central CVE-2026-86218). Stage A is read-only; any exploit path, login, session or agent enrollment is Stage B with written sign-off. Use when a scan, certificate or Shodan record shows a remote-support console or remote-display port on an in-scope host."
sources: nvd, cisa_kev, vendor_advisories, cve_org, divd_csirt, project_documentation, nmap_service_probes, bugcrowd_vrt
report_count: 0
---

## When to use

Trigger when external recon has produced a remote-management or remote-support
service on a host you are authorized to test, and you need to decide whether it
is a finding. The finding here is **the exposure plus what it leaks or grants**:
a console in a known-exploited version range, a remote-display port reachable
without its gateway, a setup page or default credential, or an unauthenticated
protocol endpoint that relays into the client's network.

Use when any of these is true:

- A title, header, certificate or Shodan/Censys record names ScreenConnect,
  SimpleHelp, BeyondTrust or Bomgar, N-central, Kaseya VSA, Endpoint Central or
  Desktop Central, Splashtop, AnyDesk, TeamViewer, Citrix, Guacamole or NoMachine.
- A port from the Step 3 table answers on a public, client-owned address.
- The client (or its MSP) says remote support is "cloud only" or "VPN only" and
  a self-hosted console answers anyway.
- An installer, agent link or tenant name for an RMM turns up in a repo, page or
  app bundle (`hunt-source-leak`), and you need to know what it exposes.

**Do not use this skill for discovery.** Host, port and ASN discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation to `recon-scope-triage`.

### Where the chain ends

An RMM server is a remote shell on every endpoint it manages. That is why these
products sit in CISA KEV and why the bar for touching them is higher than for any
other console. This skill stops at **exposure confirmed, version gated, impact
described, evidence captured**. Concretely:

- A version inside a KEV range is reported from the version, unconfirmed, with a
  same-day notice to the client. No exploit request for any CVE in the matrix is
  shipped here or signed off by default.
- A working default credential or reachable setup wizard ends the test. Do not
  open the device list, start a session, push a script, enroll an agent, create
  an API key or read the technician list.
- An unauthenticated relay (guacd, Citrix XML broker, SPICE without a ticket)
  is proven by its handshake. Never make it connect to a host behind it: that is
  pivoting.

Nothing after login, nothing on managed endpoints, no lateral movement, no
persistence (`SECURITY.md`).

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| VNC/RFB on 5900-5906 | `hunt-exposed-services`, `references/management-interfaces.md`. SPICE also answers on 5900+; the handshake decides (Step 3) |
| RDP 3389, RD Gateway and RD Web Access on 443, KDC Proxy | `infra-windows-perimeter` (its `windows-service-cve-matrix.md` carries the RD Gateway rows); NTLM metadata on `/RDWeb` to `hunt-ntlm-info` |
| NetScaler ADC/Gateway in front of StoreFront (CitrixBleed and the rest) | `enterprise-vpn-attack` |
| MeshCentral | `hunt-exposed-panels`, `references/devops-and-orchestration.md` |
| Ivanti Connect Secure's embedded Guacamole path | `enterprise-vpn-attack` |
| NoMachine over SSH (NX on 22) | `infra-ssh` |
| Any credential guessing or spraying of a console | `hunt-brute-force` |
| TLS protocol and certificate findings on any of these ports | `hunt-tls-network` |
| Agent and client CVEs that need local access (most Splashtop, NoMachine, Endpoint Central 2024-2026 rows) | Nobody. Not reachable from outside |
| Phishing users into installing a remote-support client | Nobody. Not a perimeter test |

---

## Step 1: Inherit the host and port, never generate them

Take hosts from the signed scope and ports from recon. Confirm IP ownership
(ASN, WHOIS/RDAP, reverse DNS) before the first packet. A Shodan or Censys lookup
of data someone else collected is `offensive-osint`'s job and costs the target
nothing; use it first, because it often settles product and version without a
single packet.

### Rate posture

RMM consoles carry more KEV entries than almost any other product class, and
their owners watch them. Vendors ship compromise indicators with their bulletins
(N-able's CVE-2026-18577 notice lists attacker IPs and dropped files), so an
MSP's SOC may treat your fingerprint as an intrusion and start incident response
(see `mid-engagement-ir-detection`).

- Serial, one host at a time, at least 5 s between requests, plus jitter.
- Stage A budget: **20 HTTP requests and 5 raw TCP connections per host per
  engagement day**.
- No directory brute force, no wordlists, no nuclei CVE or KEV template sets.
  Several public templates for this product class request the exploit path
  itself (Step 4). Run a nuclei template only after reading every request in it,
  and only technology-detection templates.
- Tell the client's contact before the first request to an RMM console, so a
  SOC escalation can be stood down quickly.

```bash
# 5s base delay + 0-3s jitter between requests to the same host.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 5+rand()*3}')"; }
```

---

## Step 2: Prove the server is the client's, not the vendor's or the MSP's

This is the false-positive class that kills most RMM reports. Three owners are
possible, and only one of them is usually in scope.

| Owner | Tells | What you do |
|---|---|---|
| The RMM vendor's cloud | Hostnames under the vendor's domains (see `references/rmm-self-hosted.md` and `references/saas-and-relays.md` per product), vendor ASN, shared certificates across thousands of tenants | Out of scope unless the **vendor's** own program lists it. Never test a vendor's multi-tenant platform from a client engagement |
| The client's MSP | Console on the MSP's ASN or domain; the client is one tenant among many | The MSP's asset. Testing it needs the MSP's written authorization, not only the client's. Its compromise is a supply-chain event (Kaseya VSA, July 2021) |
| The client | Client ASN, client hostname and certificate, self-hosted edition | In scope if the scope document says so |

SaaS-only products (Atera, NinjaOne, Datto RMM) have no client-hosted server at
all. The client's exposure there is what it publishes: installer links, tenant
identifiers, agent configuration. That is `references/saas-and-relays.md`.

Also clear, before reporting anything:

| Check | Why |
|---|---|
| External vantage, egress IP recorded | A console reached over the client VPN is not exposed |
| Not a honeypot or sensor | Internet sensors imitate popular login pages. A login page with no product assets, an implausible version, or the same certificate on many unrelated IPs is a sensor until shown otherwise |
| Not a CNAME or proxy to SaaS | Vendor cloud sites are often CNAMEd to the client's hostname (BeyondTrust documents `<site>.beyondtrustcloud.com` this way). Resolve the CNAME and read the certificate and redirects before calling a host client-owned |

---

## Step 3: Triage the port or fingerprint to one reference file

Load only the reference file for what is in front of you.

| Port(s) | Fingerprint | Product | Load |
|---|---|---|---|
| 8040 web, 8041 relay; or 443 behind a proxy | `Server: ScreenConnect/<version>` on every response | ConnectWise ScreenConnect (on-premise) | `references/rmm-self-hosted.md` |
| 80, 443 (other ports if taken) | `/welcome` titled "Welcome to SimpleHelp"; `/allversions` | SimpleHelp server | `references/rmm-self-hosted.md` |
| 80, 443 | "Remote Support Portal" title, `Server: Bomgar` on a 404 (nmap) | BeyondTrust RS or PRA appliance | `references/rmm-self-hosted.md` |
| 8443 UI; 443 and 80 for agents | "N-central Login", cookie `ncentral_version` | N-able N-central (self-hosted) | `references/rmm-self-hosted.md` |
| 443; 5721 agents on VSA 9 | `/vsapres/web20/core/login.aspx` | Kaseya VSA (on-premise) | `references/rmm-self-hosted.md` |
| 8020, 8383; MSP edition 8040, 8041 | `/configurations.do` login with `buildNum` | ManageEngine Endpoint Central | `references/rmm-self-hosted.md` |
| Vendor-hosted consoles, Splashtop On-Prem, AnyDesk On-Premises, 5938, 7070 | Atera, NinjaOne, Datto RMM, Splashtop, TeamViewer, AnyDesk | SaaS RMM, relays, direct-connection listeners | `references/saas-and-relays.md` |
| 1494, 2598; XML service on 80/443/8080; StoreFront on 443 | `\x7f\x7fICA\0` greeting; `/Citrix/` paths | Citrix Virtual Apps and Desktops | `references/remote-display-protocols.md` |
| 4822; web on 8080 or 443 under `/guacamole/` | guacd `args` reply; Guacamole login | Apache Guacamole | `references/remote-display-protocols.md` |
| 4000 (TCP and UDP); 4080, 4443 web | `NXD-<version>` reply | NoMachine | `references/remote-display-protocols.md` |
| 5900 and up; 3128 on Proxmox VE | `REDQ` reply | SPICE | `references/remote-display-protocols.md` |
| 5900-5906 answering `RFB 003.00x` | RFB | VNC | `hunt-exposed-services` |
| 3389; `/RDWeb`, `/remoteDesktopGateway/` | RDP, RD Gateway | Microsoft | `infra-windows-perimeter` |

Every CVE row for every product above lives in one place:
`references/cve-matrix.md`.

Port collisions: 8040/8041 is ScreenConnect or Endpoint Central MSP, 5900 is
VNC or SPICE, 3128 is Squid or Proxmox `spiceproxy`, 4000 and 8080 are claimed
by many products. The protocol response decides, never the port number.

---

## Step 4: Stage A, read-only fingerprint

A Stage A probe sends no credential, follows no exploit path, creates no session
or account, and stays inside the Step 1 budget. Two requests settle most web
consoles together with one product-specific request from the reference file.

```bash
T="remote.client.example"; P="443"; mkdir -p evidence
# A1. Landing page headers and body: 1 request.
curl -sk -m 15 -D "evidence/${T}_${P}_headers.txt" -o "evidence/${T}_${P}_index.html" "https://${T}:${P}/"
grep -i -E '^(server|location|set-cookie|x-powered-by):' "evidence/${T}_${P}_headers.txt"
grep -o -i -m1 '<title>[^<]*' "evidence/${T}_${P}_index.html"
probe_delay

# A2. Certificate subject and SANs: 1 handshake. Internal hostnames and
# tenant names in the SAN list are recon input and sometimes a finding.
openssl s_client -connect "${T}:${P}" -servername "$T" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName | tee "evidence/${T}_${P}_cert.txt"
```

For a raw TCP display protocol, read the greeting once. ICA speaks first; the
others are in `references/remote-display-protocols.md`.

```bash
# A3. Citrix ICA greeting: 1 connection, nothing sent.
timeout 10 nc -v -w 5 "$T" 1494 </dev/null | head -c 32 | xxd | tee "evidence/${T}_1494_greeting.txt"
```

nmap: `nmap -Pn -n -sT -sV -p <port> "$T"` is enough for ICA, NoMachine, SPICE,
TeamViewer and Splashtop; `nmap-service-probes` (7.991) carries match lines for
each. Name every NSE script, never `-sC` or `-A`.

### Requests that look like fingerprinting and are not

| Request | Why it is not Stage A |
|---|---|
| ScreenConnect `SetupWizard.aspx` with any trailing path segment | On a vulnerable server that GET **is** CVE-2024-1709: it reaches the setup wizard that creates an administrator. Version comes from the `Server` header instead |
| Kaseya VSA `/dl.asp`, `/mkDefault.asp` and other paths named in CVE-2021-30116 to 30121 write-ups | They are the disclosed exploit surface, not fingerprints |
| SimpleHelp `toolbox-resource` paths with traversal (CVE-2024-57727) | Reads server configuration and password hashes |
| BeyondTrust `/get_portal_info`, `/get_mech_list`, `/download_client_connector`, the `/nw` WebSocket | Steps of the public CVE-2024-12356 injection chain; `/nw` carries the command |
| N-central `/dms/services/ServerMMS`, `/dms/services/ServerUI` | Exploit-chain endpoints in Horizon3's N-central research |
| Endpoint Central `/SamlRequestServlet`; StoreFront `<store>Auth/SamlTest` | CVE-2022-47966 and CVE-2023-5914 probes |
| Any public "check" script for a KEV row in `references/cve-matrix.md` | Read it first. Most send the exploit and look at the response |
| nmap `citrix-brute-xml` | `brute`, `intrusive`. Credential guessing |
| nmap `realvnc-auth-bypass`, `vnc-brute` | VNC is `hunt-exposed-services`'s, and these are not safe |
| A guacd `connect` instruction | Makes guacd open a connection to a host behind it. Pivoting |
| Launching an ICA file from StoreFront, or a SPICE/NoMachine session | Starts a real session on a production host. Stage B |

Some lists in this bundle file KEV exploit paths under "fingerprint paths"
(`offensive-osint/references/probes-and-wordlists.md` lists the ScreenConnect
setup wizard and two Kaseya VSA paths). Use the passive tells in the reference
files instead.

---

## Step 5: Read the results, version gate

Find the version through the product's passive disclosure (reference file), then
check `references/cve-matrix.md`. Four rules decide whether the version can
decide:

- **Patch-named fixes.** BeyondTrust ships `BT24-10-ONPREM1`-style patches, and
  Metasploit's BeyondTrust module states the patch "does not change the servers
  version number". SimpleHelp's 5.4/5.3 fixes are jar replacements visible only
  in the server log. ConnectWise's interim fix is its own build, 22.4.20001. An
  in-range BeyondTrust or SimpleHelp 5.3/5.4 version is "possibly patched" until
  the client confirms.
- **Build granularity.** N-central fixes are four-part builds (`2026.3.1.14`);
  a page that shows only `2026.3` cannot decide the 2026 KEV rows. Endpoint
  Central's `buildNum` is confirmed only on 10.x login pages; Kaseya VSA has no
  confirmed passive version source at all.
- **Configuration-gated rows.** CVE-2022-47966 needs SAML SSO active,
  CVE-2026-48558 needs OIDC login, CVE-2026-40138/40139 need a specific
  authentication configuration, CVE-2024-5322 needs Entra SSO. A login page that
  offers the SSO button is evidence for the precondition; its absence proves
  nothing.
- **Client-side rows.** CVE-2026-84869 (ScreenConnect, KEV) affects clients, not
  the server. A server version is only a proxy for the clients it distributes.

### KEV summary (catalog 2026.10.13)

| Product | KEV rows (date added) | Minimum fixed |
|---|---|---|
| ScreenConnect | CVE-2024-1709 (2024-02-22), CVE-2025-3935 (2025-06-02), CVE-2024-1708 (2026-04-28), CVE-2026-84869 client (2026-09-11) | 25.2.4 for the server rows; 26.6.5 for clients |
| SimpleHelp | CVE-2024-57727 (2025-02-13), CVE-2024-57726 and CVE-2024-57728 (2026-04-24), CVE-2026-48558 (2026-06-29) | 5.5.16 |
| BeyondTrust RS/PRA | CVE-2024-12356 (2024-12-19), CVE-2024-12686 (2025-01-13), CVE-2026-1731 (2026-02-13) | RS 25.3.2, PRA 25.1.1 (or 25.1, verify), or the BT patches |
| N-central | CVE-2025-8875 and CVE-2025-8876 (2025-08-13), CVE-2026-18577 (2026-08-03), CVE-2026-18556 (2026-08-04), CVE-2026-86218 (2026-09-08) | 2026.3.1.14 |
| Kaseya VSA | CVE-2021-30116 (2021-11-03) | 9.5.7a |
| Endpoint Central | CVE-2021-44515 (2021-12-10), CVE-2022-47966 SAML only (2023-01-23) | 10.1.2228.11 |
| Citrix (not NetScaler) | CVE-2024-8068/8069 Session Recording (2025-08-25): internal-AD precondition, out of scope; StoreFront CVE-2019-13608 predates the window | n/a |
| TeamViewer | CVE-2019-18988 only: local, pre-2021 | n/a |
| Guacamole, NoMachine, SPICE, Splashtop, AnyDesk, Atera, NinjaOne, Datto RMM | None. AnyDesk CVE-2026-109390 (Linux, pre-auth RCE over 7070) has a public exploit per press but is not KEV-listed | see the matrix |

---

## Step 6: Exposure findings that need no CVE

| Observation | Why it matters |
|---|---|
| guacd (4822) answering from the internet | guacd binds to localhost by default and authentication lives in the web application (Apache docs); Check Point's guide states guacd "does not authenticate its clients". Whoever reaches it can ask it to open RDP, VNC or SSH connections to hosts it can route to |
| ICA 1494 or CGP 2598 reachable directly, not through Citrix Gateway | Session hosts exposed without the gateway's authentication layer |
| Citrix XML service answering from the internet | Published-application enumeration without credentials |
| SPICE port with no ticket requirement (Stage B to prove) | Console of a virtual machine, including its boot screen |
| NoMachine 4000 reachable | Interactive desktop login (system accounts by default, verify); version from the `NXD-` reply |
| AnyDesk 7070 (TLS, certificate CN `AnyDesk Client`) or a TeamViewer match on 5938 answering inbound | An endpoint accepts direct connections from the internet, outside the vendor relay; pre-auth client CVEs (AnyDesk CVE-2026-109390, CVE-2025-27918) become reachable. TeamViewer's vendor docs call 5938 outbound; that its LAN listener uses it is unconfirmed (verify) |
| RMM console reachable from the internet, patched | Design for most products; Informational unless policy or contract says consoles must be behind a VPN or allowlist |
| Setup or first-run page reachable on a production console | Whoever completes it owns the server |
| Installer or enrollment link for the client's RMM tenant published openly | Anyone can enroll a device into the tenant; impact depends on the product (`references/saas-and-relays.md`) |
| Certificate SANs naming internal hosts or other tenants | Information disclosure, Low; recon input |

---

## Step 7: Stage B, anything that logs in, connects or exploits

Stage B is **blocked by default**. It requires explicit written operator
sign-off naming the action, the host, the account and a time window. A Slack
thumbs-up or "critical findings are in scope" is not sign-off. Record before
the first packet:

```
Stage B authorization
  Host/port:        192.0.2.30:8080
  Action:           one login to the Guacamole web application with the documented
                    default guacadmin/guacadmin, stopping at the home screen
  Blast radius:     a login record on the client's remote-access gateway; the
                    home screen lists connection names (internal hostnames)
  Reversibility:    nothing to reverse; client must rotate the password
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| One vendor-documented default credential, once (Guacamole `guacadmin`/`guacadmin`; others per reference file) | A login on a remote-access gateway; a success shows connection names and lands one click from every target host |
| One SPICE ticket exchange with a random ticket, stopping at the result code | Reads whether a VM console needs a ticket; a 0 means it does not, and nothing further is done |
| One NoMachine login with a client-provided test account | A real desktop session on a production host |
| One `citrix-enum-apps-xml` run against an exposed XML service | Lists published apps and their access lists, which name directory groups |
| One `curl -sI` on a leaked RMM installer or enrollment link | Shows the link is live; no download, no install |
| Launching one published app from StoreFront with a client test account | A session on a VDA, licence consumption, logon scripts run |
| Opening the setup page beyond its first screen | On a live server, completing it creates an administrator. Stop at the screenshot of the first screen |

**Declined by default, sign-off or not:** confirming any CVE in
`references/cve-matrix.md` by exploitation. Most KEV rows there are pre-auth
remote code execution, authentication bypass or arbitrary file read on a server
that controls a fleet; a "harmless" confirmation creates an administrator,
reads password hashes or runs a command as the RMM service. Report from the
version, unconfirmed, and escalate the same day.

**Forbidden outright:** every row marked DoS in the matrix (CVE-2026-40140,
CVE-2021-20201, CVE-2025-27917 and the rest); starting a remote session to any managed endpoint; pushing a
script, file or agent; enrolling a device; creating an API key or technician;
making guacd, an XML broker or any relay connect onward; reading another
tenant's data on a shared console.

---

## Step 8: Grade by what you proved

| What you proved | Grade |
|---|---|
| Default credential accepted, or a setup wizard reachable, on a production RMM or remote-access gateway | Critical |
| guacd reachable from the internet (handshake answered) | High to Critical: an unauthenticated relay into whatever guacd can reach |
| Version inside a KEV pre-auth row (ScreenConnect, SimpleHelp, BeyondTrust, N-central, Kaseya, Endpoint Central) | High, labelled unconfirmed, escalated the same day |
| Version inside a non-KEV pre-auth row, or a KEV row gated on configuration you could not see | Medium, unconfirmed, with the precondition named |
| ICA/CGP or SPICE reachable without the gateway; Citrix XML service enumerates published apps | Medium to High by what is published |
| TeamViewer or AnyDesk accepting inbound direct connections from the internet | Medium; High once the client confirms a build inside a pre-auth row (the handshake shows no version) |
| NoMachine reachable, password login | Low to Medium (hardening, plus `hunt-brute-force` surface) |
| Certificate or redirect leaks internal hostnames | Low |
| RMM console on the internet, current build, MFA documented by the client | Informational |

### What is not a finding

- **A patched RMM console on the internet.** These products are built to be
  reached by technicians and agents; exposure alone is a hardening note.
- **Banner or version disclosure.** HackerOne lists it as core ineligible;
  Bugcrowd's VRT rates "Fingerprinting/Banner Disclosure" P5.
- **Anything on the vendor's cloud** (`*.screenconnect.com`, `*.beyondtrustcloud.com`,
  hosted N-central, SaaS RMMs). Report to the vendor's program if it has one.
- **Local or authenticated CVEs** listed in the matrix as Local or Auth.
- **TeamViewer or AnyDesk IDs, relay traffic, or outbound connectivity.** That is
  how the products work.
- **"Outdated version" with no reachable row.** VRT "Outdated Software Version" is P5.

---

## Step 9: Evidence

Follow `evidence-hygiene`. Minimum per finding: the A1 headers and title, the
certificate output, the raw greeting or handshake bytes for TCP protocols, the
version source (header, page or reply) with timestamp, the egress IP, the
matrix row and its source, and for Stage B the sign-off record plus one
screenshot of the landing screen. Redact session cookies and connection names
beyond what proves the class. Never keep files, configuration or hashes from an
RMM server.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| ScreenConnect `Server` version below 23.9.8 | CVE-2024-1709 KEV, setup-wizard admin creation | Critical-class, unconfirmed | Same-day notice. No request to the wizard |
| BeyondTrust appliance below RS 25.3.2 / PRA 25.1.1 | CVE-2026-1731 KEV pre-auth command injection; BT26-02 patch status is not visible | Critical-class, unconfirmed | Same-day notice; ask for patch status |
| N-central below 2026.3.1.14 | CVE-2026-86218 KEV pre-auth RCE | Critical-class, unconfirmed | Same-day notice |
| SimpleHelp `/allversions` below 5.5.8 | CVE-2024-57727 KEV file read of config and hashes | Critical-class, unconfirmed | Same-day notice; ransomware-linked |
| guacd 4822 answers `args` | Unauthenticated relay to internal RDP/VNC/SSH | High to Critical | Report. Never send `connect` |
| Guacamole web app, default credential (Stage B) | Admin of the remote-access gateway | Critical | Stop at the home screen |
| Leaked RMM installer or tenant link (`hunt-source-leak`) | Device enrollment into the client's tenant | Product-dependent | `references/saas-and-relays.md` |
| StoreFront behind NetScaler Gateway | Gateway CVEs | Per `enterprise-vpn-attack` | That skill |
| RD Web Access next to the RMM | RD Gateway rows, NTLM leak | Per those skills | `infra-windows-perimeter`, `hunt-ntlm-info` |
| Console login page | Password spraying | Decided by `hunt-brute-force` | Hand off; do not spray from here |

---

## Validation checklist

- [ ] Probed from outside every client network; egress IP recorded.
- [ ] Every IP confirmed client-owned and in the signed scope; vendor cloud and
      MSP-owned consoles excluded or separately authorized in writing.
- [ ] Client contact told before the first request to an RMM console.
- [ ] Stage A stayed inside 20 HTTP requests and 5 TCP connections per host,
      serial, 5 s apart; no wordlists, no nuclei CVE/KEV sets.
- [ ] No request to any path from the "not Stage A" table or the KEV write-ups.
- [ ] Version taken from a passive source, with its granularity limits stated
      (patch-named fixes, two-part N-central versions).
- [ ] Configuration-gated rows name their precondition; client-side rows are not
      reported as server findings.
- [ ] Display-protocol findings proven by a greeting or handshake only; no
      session opened, no guacd `connect`, no ICA file launched without sign-off.
- [ ] Every Stage B action has a logged written sign-off; default credentials
      tried exactly once, from the documented list only.
- [ ] No exploit run for any matrix row; no DoS-class row tested.
- [ ] Nothing done on a managed endpoint; no agent enrolled, no script pushed.
- [ ] Not reporting banner disclosure or an exposed patched console as a
      vulnerability unless the program accepts it.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/rmm-self-hosted.md` | ScreenConnect, SimpleHelp, BeyondTrust RS/PRA, N-central, Kaseya VSA, Endpoint Central: ports, cloud tells, passive fingerprint, version disclosure, what not to request | screenconnect exposed, screenconnect version, simplehelp allversions, bomgar appliance, beyondtrust remote support exposed, n-central login exposed, kaseya vsa on premise, desktop central 8383, endpoint central version |
| `references/saas-and-relays.md` | Atera, NinjaOne, Datto RMM, Splashtop cloud and On-Prem, TeamViewer 5938, AnyDesk 7070 and On-Premises: vendor domains, inbound listeners, installer and tenant exposure | atera installer link, ninjaone agent, datto rmm agent, splashtop on-prem, teamviewer 5938 exposed, anydesk 7070 direct connection, anydesk on-premises |
| `references/remote-display-protocols.md` | Citrix ICA 1494, CGP 2598, XML service, StoreFront; Apache Guacamole and guacd 4822; NoMachine 4000; SPICE; RD Gateway routing | citrix ica exposed, 1494 open, session reliability 2598, citrix xml service, storefront version, guacd 4822 exposed, guacamole default password, nomachine 4000, nx server version, spice console exposed, proxmox spiceproxy |
| `references/cve-matrix.md` | All products: 2021-2026 CVE rows with class, pre-auth, affected, fixed, KEV date, source | screenconnect cve-2024-1709, slashandgrab, simplehelp cve-2024-57727, beyondtrust cve-2026-1731, cve-2024-12356, n-central cve-2026-86218, kaseya vsa cve-2021-30116, endpoint central cve-2021-44515, guacamole cve, anydesk cve-2025-27918 |

Primary sources (fetched 2026-10-13): CISA KEV feed, catalog 2026.10.13
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>; NVD API
<https://services.nvd.nist.gov/rest/json/cves/2.0>; CVE.org records
<https://cveawg.mitre.org/api/cve/>; vendor bulletins and docs listed in
each reference file's Sources section; nmap 7.991 `nmap-service-probes` and NSE
`--script-help`; HackerOne core ineligible findings
<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>;
Bugcrowd VRT <https://github.com/bugcrowd/vulnerability-rating-taxonomy>.

---

## Related Skills & Chains

- `hunt-exposed-services`: the generic non-HTTP triage this skill specialises,
  and the owner of VNC; its Stage A/B model is inherited here.
- `infra-windows-perimeter`, `hunt-ntlm-info`: RDP, RD Gateway, RD Web Access.
- `enterprise-vpn-attack`: NetScaler Gateway in front of Citrix, and other SSL VPNs.
- `hunt-exposed-panels`: MeshCentral and other web admin consoles.
- `infra-external-methodology`: the external test plan and port routing table.
- `hunt-source-leak`, `supply-chain-attack-recon`: where leaked installers,
  tenant IDs and RMM API keys come from.
- `hunt-brute-force`: any credential guessing against a console.
- `mid-engagement-ir-detection`: when the client's SOC reacts to your probes.
- `offensive-osint`, `web2-recon`, `recon-scope-triage`: discovery and scope.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence, gates, write-up.

# Self-hosted RMM and remote-support servers

ScreenConnect, SimpleHelp, BeyondTrust RS/PRA, N-able N-central, Kaseya VSA,
ManageEngine Endpoint Central. Per product: ports, vendor-cloud tells, passive
fingerprint, where the version shows without authentication, and the requests
that look like fingerprinting but are the exploit. CVE rows are in
`cve-matrix.md`.

Every request below is one ordinary page load or a vendor-documented status
page. Run them serially inside the Step 1 budget of `SKILL.md`, with
`probe_delay` between them. Sources were fetched 2026-10-13; nuclei matchers are
cited from `projectdiscovery/nuclei-templates` (main) and Metasploit modules
from `rapid7/metasploit-framework` (master) as **detection logic only**. Do not
run either against the target without reading every request first (`SKILL.md`
Step 4).

Port collision to remember: ScreenConnect (web 8040, relay 8041) and Endpoint
Central **MSP** (agent HTTP 8040, HTTPS 8041) use the same numbers. The response
decides.

---

## ConnectWise ScreenConnect (on-premise)

| Item | Value | Source |
|---|---|---|
| Ports | Web 8040, relay 8041. The installer default `WebServerListenUri` is `http://+:8040/` (plain HTTP); many deployments put 443 in front | ConnectWise community; MasterKale/IAmDocumentation |
| Vendor cloud | `*.screenconnect.com` (relay hosts look like `instance-<id>-relay.screenconnect.com`), `*.hostedrmm.com` | ConnectWise bulletins and community |
| Fingerprint | `Server` header contains `ScreenConnect`; login at `/Login`; body "ConnectWise Control Remote Support Software" on older builds; favicon mmh3 `-82958153` | nuclei `connectwise-panel.yaml`, `connectwise-control-detect.yaml` |
| Version | `Server: ScreenConnect/<version>`, e.g. `ScreenConnect/23.9.8.8811`. Metasploit's comment: even 302 and 404 responses carry it | nuclei issue 9185; MSF `connectwise_screenconnect_rce_cve_2024_1709.rb` |
| Exposure context | Censys counted 6,000+ vulnerable hosts on 2024-02-19 and 4,338 exposed servers, all showing their version, in June 2025 | Censys advisories |

```bash
T="sc.client.example"; URL="http://${T}:8040"     # or https://${T} behind a proxy
# 1 request. The Server header carries the version on any status code.
curl -sk -m 15 -o /dev/null -D - "${URL}/Login" | grep -i -E '^(server|location):'
```

Do not request:

- `SetupWizard.aspx` followed by any path segment (`/SetupWizard.aspx/x`). That
  GET is CVE-2024-1709 on a vulnerable server ("SlashAndGrab"); the nuclei
  CVE-2024-1709 template requests exactly this.
- Any extension endpoint or `Bin/` client download with crafted parameters
  (CVE-2023-25719 class). The version header already decides the gate.

Reading the result: below 23.9.8 is the KEV pre-auth row, Critical-class and
unconfirmed. 22.4.20001 is a patched interim build for servers off maintenance,
not a vulnerable 22.4. From 23.9.8 up to 25.2.3 only the machine-key-conditional
CVE-2025-3935 remains, which an outsider cannot assess.

---

## SimpleHelp

| Item | Value | Source |
|---|---|---|
| Ports | Tries 80 and 443 on first install; if taken, falls back to other ports the guide does not list | SimpleHelp network-ports guide |
| Vendor cloud | None confirmed: SimpleHelp is sold as a self-hosted server (verify for hosted resellers) | n/a |
| Fingerprint | `/welcome` titled `Welcome to SimpleHelp`; favicon mmh3 `1117165781`; nmap 7.991 matches the session page text "Leaving this page will end the remote help session" | nuclei `simplehelp-login-panel.yaml`, `favicon-detect.yaml`; `nmap-service-probes` |
| Version | `/allversions` is a vendor-documented page showing `SH Version` (e.g. `SSuite-5-2-20200319-154226`) and `Visual Version` (e.g. `5.2.6`). Horizon3 reports the `Server` header also carries the version (format unconfirmed) | SimpleHelp "checking the version" guide; MSF `simplehelp_toolbox_path_traversal.rb`; Horizon3 disclosure |
| Exposure context | Shadowserver: about 580 vulnerable instances on 2025-01-27 | SecurityAffairs citing Shadowserver |

```bash
T="help.client.example"
# 1 request to the vendor's own version page.
curl -sk -m 15 "https://${T}/allversions" | grep -o -E '(Visual Version|SH Version):?[^<]{0,40}'
```

Do not request any `toolbox-resource` path with traversal sequences: that is
CVE-2024-57727 and it returns the server configuration and password hashes.

Reading the result: `Visual Version` below 5.5.8 on the 5.5 line is the KEV
row. On 5.4.x and 5.3.x the fix is a jar patch that the public page does not
show (the vendor tells admins to look for `Patch 070125` in the server log), so
those versions are "possibly patched". Below 5.5.16 matters only if the login
page offers OIDC (CVE-2026-48558).

---

## BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA)

| Item | Value | Source |
|---|---|---|
| Ports | Inbound "the only required ports are 80 and 443"; outbound 443 to `btupdate.com` (optional), 22 to BeyondTrust, 123 NTP | BeyondTrust on-prem network considerations |
| Vendor cloud | `<site>.beyondtrustcloud.com`, often CNAMEd to the customer's own hostname. **Resolve the CNAME before calling a host client-owned** | BeyondTrust RS getting-started |
| Fingerprint | RS: title "Remote Support Portal", body "BeyondTrust Remote Support", favicon mmh3 `-694003434`. PRA: `/login/login` titled "BeyondTrust Privileged Remote Access Login". Legacy `/appliance/login.ns` contains "bomgar". nmap 7.991 matches `Server: Bomgar` on a 404 | nuclei `beyondtrust-remotesupport-version.yaml`, `beyondtrust-priv-panel.yaml`, `bomgar-login-panel.yaml`; `nmap-service-probes` |
| Version | `/get_rdf?comp=sdcust&locale_code=en-us` returns `0 Successful`, a timestamp, and a binary `BRDF` blob containing the version string. It is the customer-client customisation download, not an exploit step; Metasploit's `check()` uses it | MSF `lib/msf/core/exploit/remote/http/beyondtrust.rb` |
| Patch visibility | Metasploit: "the patch does not change the servers version number". A version check **cannot prove a host is patched** | MSF `beyondtrust_pra_rs_unauth_rce.rb` |
| Exposure context | Censys: 13,548 RS and PRA instances on 2025-01-06. Unit 42 (Cortex Xpanse): over 16,400 potentially vulnerable to CVE-2026-1731 on 2026-02-19 | Censys CVE-2024-12356 advisory; Unit 42 |

```bash
T="support.client.example"
dig +short CNAME "$T"                      # *.beyondtrustcloud.com = vendor cloud, stop
# 1 request. Read the version out of the blob; check the parse against a known build (verify).
curl -sk -m 15 "https://${T}/get_rdf?comp=sdcust&locale_code=en-us" | strings | head -20
```

Do not request `/get_portal_info`, `/get_mech_list`, `/download_client_connector`
or the `/nw` WebSocket. Public CVE-2024-12356 tooling uses them as the
company-name and WebSocket steps of the injection chain, and the `/nw` step is
where the command is sent.

Reading the result: because patches do not change the version, every in-range
appliance is reported as "in range of CVE-2024-12356 / CVE-2026-1731, patch
status unknown", with a request that the client confirm BT24-10 and BT26-02 are
applied. RS 25.3.2 and later, and PRA 25.1.1 and later, are outside both KEV
rows on version alone.

---

## N-able N-central (self-hosted)

| Item | Value | Source |
|---|---|---|
| Ports | 8443 "the default port for the N-central UI"; 443 and 80 for agent and probe traffic; 22 optional (remote control); 5280 XMPP; 8014 Backup Manager (LAN only); 10000 NAC (deprecated after 2025.4). 10004 and 15000 are on the **probe**, not the server | N-able port access requirements |
| Vendor cloud | Hosted server URLs begin with `ncod` (trial servers `nce`); hosted is N-able's infrastructure (NCOD). Domain suffix (verify) | N-able "logging in for the first time (hosted)" |
| Fingerprint | Title "N-central Login"; `/login` body contains `class="ncentral"`; favicon mmh3 `1519363246` or `1937353549`; cookie `ncentral_version=` | nuclei `ncentral-panel.yaml` |
| Version | The normal `/login` page: `ncentralVersion: "<version>"` in the page and `Set-Cookie: ncentral_version=<version>` | nuclei `ncentral-panel.yaml` |
| Exposure context | Shadowserver: 1,077 unpatched IPs on 2025-08-15. Horizon3: about 3,000 instances on Shodan, 2025-11-17 | SecurityWeek citing Shadowserver; Horizon3 |

```bash
T="ncentral.client.example"
# 1 request to the login page; version in the cookie and the page script.
curl -sk -m 15 -D - "https://${T}:8443/login" -o "evidence/${T}_ncentral_login.html" | grep -i '^set-cookie: ncentral_version'
grep -o -E 'ncentralVersion:\s+"[0-9.]+"' "evidence/${T}_ncentral_login.html"
```

Do not request `/dms/services/ServerMMS` or `/dms/services/ServerUI`. Horizon3's
N-central research uses them as exploit-chain endpoints.

Reading the result: the 2026 KEV rows need the full four-part build
(`2026.3.1.14` fixes CVE-2026-86218; `2026.3.1.7` fixes CVE-2026-18577). If the
page shows fewer parts, report "2026.3 line, hotfix level not visible".

---

## Kaseya VSA (on-premise)

| Item | Value | Source |
|---|---|---|
| Ports | VSA 9: TCP 80/443 web UI; TCP and UDP 5721 agents (changeable); 1433/1434 only when SQL Server is on a separate host. VSA 10 on-premise: 443 for web and agents ("Agent traffic will no longer use port 5721") | Kaseya VSA 9 and VSA 10 help |
| Vendor cloud | VSA 10 contacts `slv.vsax.net`, `slv2.vsax.net`, `dispatcher.vsax.net` (vendor service endpoints). SaaS instances under `*.kaseya.net` per a third-party integrator, not Kaseya (verify) | VSA 10 on-prem help; Axonius docs |
| Fingerprint | Body references `/vsapres/web20/core/login.aspx`; favicon mmh3 `-1445519482` | nuclei `kaseya-vsa-login-panel.yaml`, `CVE-2021-30116.yaml` |
| Version | **No passive source confirmed.** A login-page version option was not found in the VSA 9 documentation fetched (verify) | n/a |

```bash
T="vsa.client.example"
# 1 request. Product identification only; there is no version to read.
curl -sk -m 15 "https://${T}/" | grep -o -m1 '/vsapres/web20/core/login.aspx'
```

Do not request `/dl.asp`, `/mkDefault.asp` or any path named in the
CVE-2021-30116 to CVE-2021-30121 write-ups. Some bundle lists and public scanners
treat them as fingerprints; they are the 2021 exploit surface.

Reading the result: an on-premise VSA 9 on the internet is reported as an
exposed fleet-control plane with the version unknown, and the client is asked
for the build. Anything below 9.5.7a is a KEV row with ransomware history.

---

## ManageEngine Endpoint Central (formerly Desktop Central)

| Item | Value | Source |
|---|---|---|
| Ports | Web console 8020 (HTTP); 8383 HTTPS for web client and agent-server traffic; 8027 for Notification Server on-demand tasks; 135/139/445 only for push agent installation (internal) | ManageEngine "working of Desktop Central", general how-to, agent footprint |
| Ports, MSP edition | 8040 HTTP and 8041 HTTPS agent-server; 8057 on-demand; 8047/8048 remote desktop; 8058 remote PostgreSQL | ManageEngine MSP ports page |
| Vendor cloud | `endpointcentral.manageengine.{com,eu,in,com.au,cn,jp,ca,uk,sa}` | ManageEngine OAuth endpoint domains |
| Fingerprint | `/configurations` titled "ManageEngine Desktop Central 10" on 10.x builds | nuclei `zoho/manageengine-desktop.yaml` |
| Version | Hidden input `id="buildNum"` on the normal login page `/configurations.do`; build `100474` = 10.0.474. Confirmed for 10.x-era builds only; 11.x unconfirmed (verify). Metasploit's CVE-2022-47966 module states it found no banner to determine the version | MSF `desktopcentral_deserialization.rb`; MSF `manageengine_endpoint_central_saml_rce_cve_2022_47966.rb` |

```bash
T="ec.client.example"
# 1 request to the normal login page.
curl -sk -m 15 "https://${T}:8383/configurations.do" | grep -o -E 'id="buildNum"[^>]*'
```

Do not request `/SamlRequestServlet` or any SAML endpoint with a crafted
assertion (CVE-2022-47966). A visible SAML/SSO login option on the login page is
the only Stage A evidence of its precondition.

Reading the result: CVE-2022-23779 builds (below 10.1.2137.8) leak the internal
server name in redirect `Location` headers, which A1 in `SKILL.md` already
captures. That is a passive, reportable Low on its own.

No default credential is listed here: none was confirmed from vendor
documentation while this file was written (verify before any Stage B attempt).

---

## Common grading notes

- The console being reachable is by design for every product above except
  Endpoint Central's console and Kaseya VSA's admin UI, which vendors and CISA
  guidance (AA23-025A on RMM abuse, verify the exact recommendation) expect
  behind a VPN or allowlist. Grade exposure alone as Informational to Low.
- An in-range version is High and unconfirmed for KEV pre-auth rows, and the
  report says which caveat applies: patch not visible (BeyondTrust, SimpleHelp
  5.3/5.4, ScreenConnect interim builds), build granularity (N-central), or
  configuration gate (SAML, OIDC, Entra).
- An MSP-run console is the MSP's asset. Without the MSP's written
  authorization, report it to the client as third-party exposure and stop.

---

## Sources (fetched 2026-10-13)

- ScreenConnect ports: <https://screenconnect.product.connectwise.com/communities/1/topics/4579-allow-sc-web-and-relay-server-to-be-both-proxied-on-cloudflare-using-cloudflare-tunnels>;
  installer default: <https://github.com/MasterKale/IAmDocumentation/blob/master/Setting%20up%20ScreenConnect%20with%20SSL.md>;
  version header: <https://github.com/projectdiscovery/nuclei-templates/issues/9185>;
  exposure: <https://censys.com/blog/connectwise-screenconnect-cve-2024-1709-cve-2024-1708/>, <https://censys.com/advisory/cve-2025-3935/>
- SimpleHelp: <https://guides.simple-help.com/kb---network-ports-and-routing-requirements-for-the-simplehelp-server>,
  <https://guides.simple-help.com/kb---checking-the-version-and-build-of-your-simplehelp-server>,
  <https://horizon3.ai/attack-research/disclosures/critical-vulnerabilities-in-simplehelp-remote-support-software/>
- BeyondTrust: <https://docs.beyondtrust.com/rs/docs/on-prem-network-considerations>,
  <https://docs.beyondtrust.com/rs/docs/remote-support-getting-started>,
  <https://censys.com/advisory/cve-2024-12356/>, <https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/>
- N-central: <https://documentation.n-able.com/N-central/userguide/Content/ReleaseDocs/Install_Config/PortAccessRequirements.htm>,
  <https://documentation.n-able.com/N-central/userguide/Content/Introduction-GettingStarted/RB-Logging-in-for-the-first-time-hosted.htm>,
  <https://horizon3.ai/attack-research/attack-blogs/n-able-n-central-from-n-days-to-0-days/>
- Kaseya VSA: <https://help.vsa9.kaseya.com/help/Content/VSA/install/10292.htm>,
  <https://help.vsa10.kaseya.com/help/Content/0-Home/setup/on-prem.htm>
- Endpoint Central: <https://www.manageengine.com/products/desktop-central/help/getting_started/working_of_desktop_central.html>,
  <https://www.manageengine.com/products/desktop-central/general-how-to.html>,
  <https://www.manageengine.com/desktop-management-msp/dc-msp-ports-used.html>,
  <https://www.manageengine.com/products/desktop-central/oauth-authentication-endpoint-domain.html>
- Detection logic: <https://github.com/projectdiscovery/nuclei-templates> (`http/exposed-panels/`,
  `http/technologies/`), <https://github.com/rapid7/metasploit-framework> (modules and
  `lib/msf/core/exploit/remote/http/beyondtrust.rb` named above)

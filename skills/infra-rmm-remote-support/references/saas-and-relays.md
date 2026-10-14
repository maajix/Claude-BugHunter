# SaaS RMMs, vendor relays and direct-connection listeners

Atera, NinjaOne, Datto RMM, Splashtop (cloud and On-Prem Gateway), TeamViewer,
AnyDesk (cloud and On-Premises). CVE rows are in `cve-matrix.md`.

Most of this surface is **vendor infrastructure**. The relays, consoles and APIs
below are multi-tenant platforms run by the vendor; a client engagement does not
authorize testing them. What belongs to the client is:

1. A self-hosted edition, where one exists (Splashtop Gateway, AnyDesk
   On-Premises, TeamViewer DEX On-Premises).
2. An endpoint that accepts **inbound** connections from the internet (AnyDesk
   7070, Splashtop or TeamViewer LAN listeners exposed by a port forward).
3. Artifacts the client publishes: installer links, enrollment tokens, tenant
   identifiers.

Sources were fetched 2026-10-13 from vendor documentation unless stated.

---

## Vendor domains: out of scope on sight

Use these to classify a hostname found in recon, a certificate SAN, or a
firewall rule the client shares. A hit means "vendor platform, not the client's
server".

| Product | Vendor-operated names and ports | Source |
|---|---|---|
| TeamViewer | `*.teamviewer.com` including `master*`/`router*`; `configdl.teamviewer.com`, `webapi.teamviewer.com` on 443. Outbound TCP/UDP 5938, falling back to 443 then 80. Vendor: "No inbound ports need to be opened" | TeamViewer KB "ports used by TeamViewer" |
| AnyDesk | `*.net.anydesk.com` on outbound TCP 80, 443 or 6568; LAN discovery UDP 50001-50003 to multicast 239.255.102.18 | AnyDesk firewall docs |
| Splashtop | `*.api.splashtop.com`, `*.relay.splashtop.com`, `update.splashtop.com`, `update-g3.splashtop.com`; regional `*.api.splashtop.eu` and `.cn` variants. Outbound 443, UDP 3479 and dynamic UDP (QUIC), 80 for updates | Splashtop Business firewall article |
| Datto RMM | `*.rmm.datto.com`, `*.centrastage.net`; per-platform hosts `agent-gateway.<platform>.rmm.datto.com`, `<platform>-agent.centrastage.net`, `ts.centrastage.net`, `tunnel.rmm.datto.com` (platforms include syrah, vidal, merlot, concord, zinfandel, pinotage). Outbound 443; Web Remote uses 3478 and 49152-65535 | Datto RMM allow-list requirements |
| Atera | `*.atera.com` (`app`, `agent-api`, `agent-api-v2`, `agenthb`, `appcdn`, `ps`, `pubsub`); third-party channels (PubNub, AWS IoT eu-west-1, Azure Service Bus and Blob). Outbound 443 and 8883 | Atera firewall article |
| NinjaOne | `app.ninjarmm.com`, `rtc-*.ninjarmm.com`, `agent-tun-*.ninjarmm.com`, `connect-*.ninjarmm.com`, `*.rmmservice.com`, NinjaOne Remote `nc-*.ninjarmm.net`; outbound 443, Remote falls back to TCP 7075. **The official allow-list returned 401; this list is from an MSP's published copy for US-West (verify for other regions)** | help.allegiantnow.com; NinjaOne Remote docs |

Datto RMM, Atera and NinjaOne are described by their vendors as cloud services;
no customer-hosted server edition was found for them or for TeamViewer's remote
access product (verify). TeamViewer DEX On-Premises (formerly 1E DEX) is a
separate, self-hosted endpoint-management product.

---

## Direct-connection listeners on client endpoints

These are client-owned: a workstation or server on a client address accepting
remote-desktop connections straight from the internet, outside the vendor relay
and whatever access controls the tenant enforces there.

### AnyDesk, TCP 7070

| Item | Value | Source |
|---|---|---|
| Purpose | "AnyDesk uses TCP port 7070 by default for direct connections", configurable | AnyDesk settings docs |
| Default state | Whether "Allow direct connections" is on by default is not stated (verify) | n/a |
| Fingerprint | TLS starts immediately, no plaintext banner. Self-signed certificate, subject and issuer CN `AnyDesk Client`, RSA 2048, roughly 50-year validity | Praetorian Nerva fingerprint plugin (third-party) |
| Version | Not exposed by the handshake as far as documented (verify) | n/a |
| Why it matters | CVE-2026-109390 (Linux 8.0.0 to before 8.0.3, published 2026-10-12): pre-auth heap overflow in the session protocol, root code execution "without the victim approving desktop control". Press reports a public exploit on 2026-10-08 attacking direct TCP 7070. Not in KEV catalog 2026.10.13 | CVE.org record; The Hacker News 2026-10 |

```bash
T="198.51.100.40"
# 1 TLS handshake, nothing sent beyond it.
openssl s_client -connect "${T}:7070" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

`subject=CN = AnyDesk Client` from a client address is the finding: an endpoint
reachable for direct AnyDesk sessions from the internet. Grade Medium; High when
the client confirms a Linux AnyDesk build in the CVE-2026-109390 range. Never
send AnyDesk protocol traffic past the TLS handshake.

### TeamViewer, TCP 5938

| Item | Value | Source |
|---|---|---|
| Purpose | 5938 is TeamViewer's **outbound** port to its routers. "Incoming LAN connections" is a setting, off by default (Accept / Accept exclusively); the vendor page names no listening port | TeamViewer KB, LAN connections article |
| Fingerprint | nmap 7.991 has four binary matches (`^\x17\x24\x0a\x20\x00...`) under the NULL probe, so the service speaks first, plus an HTTP match "This site is running TeamViewer". `nmap-services` maps 5938/tcp to teamviewer | `nmap-service-probes` lines 3833-3836, 8697-8700 |
| Caveat | That an endpoint listens on 5938 when incoming LAN connections are enabled, and that this listener is what the nmap match sees, was not confirmed from vendor documentation (verify) | n/a |

```bash
# 1 connection; TeamViewer speaks first if it is the service.
nmap -Pn -n -sT -sV -p 5938 "$T"
```

A TeamViewer match on a client address means a TeamViewer listener reachable
from the internet. Report the exposure; the relevant CVEs (`cve-matrix.md`) are
authenticated or need user interaction, so grade Low to Medium.

### Splashtop Streamer, TCP 6783

| Item | Value | Source |
|---|---|---|
| Purpose | Streamer accepts TCP 6783 **from the LAN only**, for same-LAN direct connections; 9527-9528 are loopback | Splashtop Business and On-Prem firewall articles |
| Fingerprint | nmap 7.991: `SRS:Ready\0` under the NULL probe, "Splashtop Remote Server". Which component and port emit it is not documented (verify) | `nmap-service-probes` line 3537 |

6783 answering from the internet means a port forward or exposed host that the
vendor designed for LAN use. Report the exposure; every Splashtop CVE in NVD for
2021-2026 is local (`cve-matrix.md`).

---

## Self-hosted editions

### Splashtop On-Prem (Splashtop Gateway)

| Item | Value | Source |
|---|---|---|
| Ports | TCP 443 inbound by default (changeable): authentication, relay, web console and Streamer registration. Loopback only: 9080, 5432 (PostgreSQL), 7080, 7081, 5080. Online licensing calls `*.splashtop.com:443` | Splashtop On-Prem Gateway ports article |
| Fingerprint | Vendor-published WAF path prefixes: `/api/fulong/v1/`, `/shortcut/remote/`, `/web/assets/`; with SAML also `/api/saml/acs`, `/web/assets/sso/` | same |
| CVEs | None found for the Gateway. Gateway 3.36.3 upgraded PostgreSQL to 16.10 "addressing recent CVEs" without naming them | Splashtop On-Prem release notes |

```bash
# 1 request: the web console landing page under the vendor's asset prefix.
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' "https://${T}/web/assets/"
```

Loopback-only ports (5432, 7080, 7081, 5080, 9080) answering externally are a
misconfiguration finding on their own; PostgreSQL then goes to
`hunt-exposed-services` `databases.md`.

### AnyDesk On-Premises

An appliance on physical or virtual hardware; AnyDesk recommends a DMZ
restricted to internal IPs. Its listening and web-UI ports were not retrieved
(verify). Fingerprint by certificate and landing page; report reachability from
the internet against the vendor's own DMZ guidance.

### TeamViewer DEX On-Premises (formerly 1E DEX)

Self-hosted endpoint-management platform. CVE-2026-8381 (broken access control)
and CVE-2026-2695 (command injection, low-privilege) are fixed in 9.2; both are
network-reachable but need an account. Version gate only.

---

## Installer links, enrollment tokens and tenant identifiers

The SaaS products enroll devices with an installer bound to the client's tenant.
When that installer or link is published (a support page, a public repo, a
pastebin, a mobile app bundle), the client's tenant identity leaks and, depending
on the product's approval settings, anyone may be able to add a device to it.

Never run an installer found this way, signed off or not. The Atera command
below documents what a leaked link or script carries; it is not a test step.

| Product | What the installer carries | Source |
|---|---|---|
| Atera | MSI properties naming the account email and company ID, e.g. `msiexec /I Setup.msi /qn INTEGRATORLOGIN='<email>' COMPANYID='<id>'`. A "Share download link" option exists; a one-time password expires 30 minutes after the MSI is opened but is "not enforced consistently" and is skipped for GPO/system deployments | Atera installation and OTP articles |
| NinjaOne | Installer tokens map to an organization and location (one per combination with auto-tokenization), hosted at "a persistent URL", no stated expiry, revocable | NinjaOne agent tokenization docs |
| Datto RMM | "downloaded or emailed installer executable"; how it binds to a site is not described on the page fetched (verify) | Datto RMM install docs |

Whether any of these lets an outsider enroll a device without further approval
was not confirmed (verify per product and per tenant setting).

Abuse context: threat actors have used free Atera trials with unverified email
to generate agents (HarfangLab, MuddyWater campaign) and stolen live Atera
accounts (Immersive Labs). An enrollment link for the **client's** tenant is a
different and worse thing: it lands a device inside a tenant the client trusts.

Handling:

- **Stage A:** record where the link or token was found, the tenant
  identifiers it carries, and the date. That is the evidence.
- **Stage B, with sign-off naming the link:** one `curl -sI` against the link to
  show it is still live (status and content type only, no download).
- **Forbidden:** running the installer, enrolling any device, or calling the
  vendor API with the token. Enrolling a device writes into the client's
  production tenant, may receive the client's scripts and policies, and is
  indistinguishable from an intrusion.

Grade: Medium for a live enrollment link or token for the client's tenant
(tenant takeover is not shown, device injection is plausible); Low for a dead
link or a bare tenant ID. Tell the client to revoke the token the same day.

---

## Not findings here

- TeamViewer or AnyDesk IDs, relay connectivity, or outbound 5938/6568/443 from
  client hosts. That is how the products work.
- Anything observed on a vendor-domain host above.
- Agent and client local privilege escalation CVEs (Atera CVE-2023-26077/26078,
  NinjaOne CVE-2021-26273/26274, Splashtop Streamer, AnyDesk local rows).
- Datto RMM's bundled UltraVNC 1.3.8.1 CVEs (CVE-2026-7829/7830/7831/7838/7839/7840):
  Kaseya states none is exploitable as deployed and VNC is "limited to
  localhost"; current agents ship UltraVNC 1.8.2.4.
- The 2024 AnyDesk production breach and the June 2024 TeamViewer corporate
  breach (TV-2024-1005, attributed to APT29, contained to corporate IT per the
  vendor) have no CVE and say nothing about a given client's exposure.

---

## Sources (fetched 2026-10-13)

- TeamViewer: <https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/troubleshooting/ports-used-by-teamviewer/>,
  <https://www.teamviewer.com/en-ca/global/support/knowledge-base/teamviewer-remote/remote-control/use-teamviewer-remote-in-lan>,
  <https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1005/>
- AnyDesk: <https://support.anydesk.com/docs/firewall.md>, <https://support.anydesk.com/docs/settings>,
  <https://support.anydesk.com/docs/on-premises.md>,
  <https://pkg.go.dev/github.com/praetorian-inc/nerva/pkg/plugins/services/anydesk>,
  <https://thehackernews.com/2024/02/anydesk-hacked-popular-remote-desktop.html>
- Splashtop: <https://support-splashtopbusiness.splashtop.com/api/v2/help_center/en-us/articles/115001811966.json>,
  <https://support-splashtoponprem.splashtop.com/api/v2/help_center/en-us/articles/56952118977561.json>,
  <https://support-splashtoponprem.splashtop.com/api/v2/help_center/en-us/articles/49410845289241.json>
- Datto RMM: <https://rmm.datto.com/help/en/Content/1INTRODUCTION/Requirements/AllowListRequirements.htm>,
  <https://rmm.datto.com/help/en/Content/1INTRODUCTION/Infrastructure/Overview.htm>
- Atera: <https://support.atera.com/api/v2/help_center/en-us/articles/360015461139.json>,
  <https://support.atera.com/api/v2/help_center/en-us/articles/115015619747.json>,
  <https://support.atera.com/api/v2/help_center/en-us/articles/23230440105628.json>,
  <https://harfanglab.io/insidethelab/muddywater-rmm-campaign/>
- NinjaOne: <https://www.ninjaone.com/docs/new-to-ninjaone/agent-installation/agent-tokenization/>,
  <https://help.allegiantnow.com/en_US/ninjarmm-public/ninjarmm-firewall-allow-list>

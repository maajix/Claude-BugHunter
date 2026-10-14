# Adobe ColdFusion, Liferay Portal / DXP, Pega Platform

Rule for every row: **a version gate, not an exploit.** A reachable component
plus a version inside a listed range is "reachable, version in range,
unconfirmed" until the client confirms the update level. Nothing in this file
sends a request body, an RDS command, a JSONWS call with parameters, a Pega
activity, a JMX message, an upload or a credential.

Owned elsewhere: RMI and JMX transport (`hunt-exposed-services`,
`references/remote-debug.md`); Consul on 8500 (`hunt-exposed-panels`);
gadget chains (`hunt-deserialization`); Liferay or Pega SQL injection proofs
(`hunt-sqli`, Stage B there); the Elasticsearch sidecar of a Liferay bundle
(`hunt-exposed-services`, `references/databases.md`).

---

## Adobe ColdFusion

### Ports and paths

| Port / path | What it is | Where it should be reachable from |
|---|---|---|
| 8500 | Built-in web server (developer and standalone installs) | Localhost or admin hosts. Port 8500 is also Consul's HTTP API: check the banner before reporting. |
| 80 / 443 | Production behind IIS or Apache with the ColdFusion connector | Internet, for the application only |
| `/CFIDE/administrator/` | ColdFusion Administrator | **Never** from the internet. Adobe's lockdown guide blocks it at the web server. |
| `/CFIDE/adminapi/` | Admin API CFCs | Same as the Administrator |
| `/CFIDE/main/ide.cfm` | Remote Development Services (RDS) endpoint | Should not exist in production. Not requested in Stage A: ask the client whether RDS is enabled. |
| `/cf_scripts/scripts/` | Client-side script directory (2016 and later) | Public is normal; a fingerprint only |

### Stage A fingerprint

```bash
T="cf.client.example"; B="https://$T"; mkdir -p evidence
# One GET per path, 2 s apart, headers only. Never the RDS endpoint, never a body.
for P in / /CFIDE/administrator/ /CFIDE/administrator/index.cfm /CFIDE/adminapi/ \
         /cf_scripts/scripts/cfform.js; do
  printf '%s  ' "$P"
  curl -sk -m 15 -o /dev/null -D - "$B$P" | grep -i -E '^(HTTP/|server:|x-powered-by:|location:|set-cookie: (CFID|CFTOKEN|JSESSIONID))' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_coldfusion_http.txt"
```

| Signal | Meaning |
|---|---|
| `CFID` / `CFTOKEN` cookies, `/cf_scripts/` present | ColdFusion behind the front end. |
| `/CFIDE/administrator/` serves the Administrator login | Admin panel internet-exposed. High on its own, and the stated precondition of CVE-2024-20767 and CVE-2024-53961. |
| `/CFIDE/adminapi/` answers `200` or lists CFCs | Admin API reachable. Same severity. |
| Administrator login page or the admin API WSDL comment shows a build number (verify per release) | Version source. Map the build to the update level in Adobe's ColdFusion update notes. |

Do not run the NSE scripts `http-coldfusion-subzero` (category `exploit`,
retrieves the password file) or `http-adobe-coldfusion-apsa1301` (`exploit`,
steals an admin session). Both are exploitation.

Ask the client for the update level (Administrator > Settings Summary, or
`cfusion/lib/updates`) and whether RDS is enabled.

### CVE matrix 2020-2026 (pre-auth)

Adobe fixes by ColdFusion update, announced in an APSB bulletin. Affected
ranges are from the CVE records ("version N and earlier"); "Fixed in" is the
next update on each line, the convention of every APSB bulletin (verify the
exact number in the bulletin). CVSS is Adobe's CNA score. KEV dates from the
CISA catalog 2026.10.13.

| CVE | Bulletin | Type | Affected | Fixed in | KEV added |
|---|---|---|---|---|---|
| CVE-2023-26360 | APSB23-25 | Improper access control, code execution (CNA 8.6) | 2018 U15, 2021 U5 and earlier | 2018 U16, 2021 U6 | 2023-03-15 |
| CVE-2023-26359 | APSB23-25 | Deserialization, code execution (9.8) | 2018 U15, 2021 U5 and earlier | 2018 U16, 2021 U6 | 2023-08-21 |
| CVE-2023-29298 | APSB23-40 | Access control bypass to the administration CFM/CFC endpoints (7.5) | 2018 U16, 2021 U6, 2023.0.0.330468 and earlier | 2018 U17, 2021 U7, 2023 U1 | 2023-07-20 |
| CVE-2023-29300 | APSB23-40 | Deserialization, code execution (9.8) | Same as 29298 | Same as 29298 | 2024-01-08 |
| CVE-2023-38203 | APSB23-41 | Deserialization, code execution (9.8) | 2018 U17, 2021 U7, 2023 U1 and earlier | 2018 U18, 2021 U8, 2023 U2 | 2024-01-08 |
| CVE-2023-38205 | APSB23-47 | Access control bypass to the administration CFM/CFC endpoints (7.5) | 2018 U18, 2021 U8, 2023 U2 and earlier | 2018 U19, 2021 U9, 2023 U3 | 2023-07-20 |
| CVE-2024-20767 | APSB24-14 | Improper access control, file read; **requires the admin panel exposed to the internet** (7.4) | 2023.6, 2021.12 and earlier | 2023 U7, 2021 U13 | 2024-12-16 |
| CVE-2026-48282 | APSB26-68 | Path traversal leading to code execution (10.0). Secondary reporting (Deepwatch CA-26-024, ZeroDayHub) ties exploitation to RDS enabled without RDS authentication (verify against Adobe). | 2025 U9, 2023 U20 and earlier | 2025 U10, 2023 U21 (CVE record) | 2026-07-07 |

Pre-2020 ColdFusion KEV entries (CVE-2010-2861, CVE-2013-0625, CVE-2013-0629,
CVE-2013-0631, CVE-2013-0632, CVE-2017-3066, CVE-2018-4939, CVE-2018-15961)
apply only to 2018 and older releases, which are out of support and in range
for every row above. Report the release, not each CVE.

Not in KEV, pre-auth, CNA 9.0 or higher unless noted:

| CVE | Bulletin | Type | Affected | Fixed in |
|---|---|---|---|---|
| CVE-2023-38204 | APSB23-47 | Deserialization (9.8) | 2018 U18, 2021 U8, 2023 U2 and earlier | 2018 U19, 2021 U9, 2023 U3 |
| CVE-2023-44350, CVE-2023-44351 | APSB23-52 | Deserialization (9.8) | 2023.5, 2021.11 and earlier | 2023 U6, 2021 U12 |
| CVE-2024-41874 | APSB24-71 | Deserialization (9.8) | 2023.9, 2021.15 and earlier | 2023 U10, 2021 U16 |
| CVE-2024-53961 | APSB24-107 | Path traversal, file read; requires the admin panel exposed (8.1, AC:H) | 2023.11, 2021.17 and earlier | 2023 U12, 2021 U18 |
| CVE-2025-24447 | APSB25-15 | Deserialization (9.1) | 2025.0, 2023.12, 2021.18 and earlier | 2025 U1, 2023 U13, 2021 U19 |
| CVE-2025-54261 | APSB25-93 | Path traversal, code execution (10.0) | 2025.3, 2023.15, 2021.21 and earlier | 2025 U4, 2023 U16, 2021 U22 |
| CVE-2025-61809 | APSB25-105 | Input validation, security feature bypass (9.1) | 2025.4, 2023.16, 2021.22 and earlier | 2025 U5, 2023 U17, 2021 U23 |
| CVE-2026-48276, CVE-2026-48283 | APSB26-68 | Unrestricted upload, code execution (10.0) | 2025 U9, 2023 U20 and earlier | 2025 U10, 2023 U21 |
| CVE-2026-48277, CVE-2026-48281, CVE-2026-48316 | APSB26-68 | Input validation, code execution (10.0) | 2025 U9, 2023 U20 and earlier | 2025 U10, 2023 U21 |
| CVE-2026-48362 | APSB26-90 | OS command injection (10.0) | 2025.0.11, 2023.0.22 and earlier | 2025 U12, 2023 U23 (CVE record) |

How to read it externally: ColdFusion 2021 does not appear in the 2026
records (end of core support, verify the date). A 2021 install, or a 2023/2025
install below U21/U10, is in range for the KEV-listed CVE-2026-48282 and the
APSB26-68 set; one below 2025 U12 / 2023 U23 is in range for CVE-2026-48362.
An exposed `/CFIDE/administrator/` plus any of these is the escalate-now case.

---

## Liferay Portal (CE) and Liferay DXP

### Fingerprint

Ports: 8080 in the Tomcat bundle, 443 in production; the bundle's
Elasticsearch sidecar is a separate exposure (owner above).

```bash
T="portal.client.example"; B="https://$T"; mkdir -p evidence
for P in / /c/portal/login /api/jsonws /o/api; do
  printf '%s  ' "$P"
  curl -sk -m 15 -o /dev/null -D - "$B$P" | grep -i -E '^(HTTP/|server:|liferay-portal:|location:|set-cookie: (JSESSIONID|GUEST_LANGUAGE_ID|COOKIE_SUPPORT))' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_liferay_http.txt"
```

| Signal | Meaning |
|---|---|
| `Liferay-Portal: Liferay Community Edition Portal 7.x.y CE GAnn (...)` or a DXP string with a build | Full version. Default verbosity was `full` in Portal 7.2.0 to 7.4.3.25 and DXP before 7.4 U26 / 7.3 U5 / 7.2 FP19 (CVE-2024-26267, CNA 5.3); later defaults print less (verify the exact string). |
| `GUEST_LANGUAGE_ID` / `COOKIE_SUPPORT` cookies, `/web/guest` redirects | Liferay without the header. Version unknown: ask. |
| `/api/jsonws` returns the JSON Web Services API page to a guest | JSONWS discoverable anonymously (verify the default per release). Low on its own; the CVE-2020-7961 surface on old releases. Do not invoke any service from the page. |
| `/o/api` answers | Headless API explorer (7.4 and DXP quarterly releases, verify). |

### CVE matrix 2020-2026

Liferay publishes fixes as Portal CE GA builds and DXP updates or fix packs
(`liferay.dev/portal/security/known-vulnerabilities`). Only CVE-2020-7961 is in
KEV (added 2021-11-03).

| CVE | What | Pre-auth | Affected | Fixed in | KEV |
|---|---|---|---|---|---|
| CVE-2020-7961 | JSONWS deserialization, code execution | Yes, NVD 9.8 | Portal before 7.2.1 CE GA2 | 7.2.1 CE GA2; DXP per the Liferay advisory (verify) | Yes, 2021-11-03 |
| CVE-2022-42120 | Fragment module SQL injection (`namespace` attribute) | Yes per NVD (9.8) | Portal 7.3.3 to 7.4.3.16; DXP 7.3 before U4, 7.4 before U17 | 7.4.3.17; DXP 7.3 U4, 7.4 U17 | No |
| CVE-2022-42122 | Friendly URL SQL injection (`title` field); writing a friendly URL normally needs edit rights (verify) | NVD scores pre-auth (9.8) | Portal 7.3.7; DXP 7.3 FP2 to U4 | Next GA / DXP 7.3 U5 (verify) | No |
| CVE-2025-3594 | Xuggler download path traversal in the Server Administration portlet; needs an admin to act (UI:A) | No in practice (CNA 8.6) | Portal 7.0.0 to 7.4.3.4; DXP 7.4 GA, 7.3 through U34, older | Per advisory (verify) | No |
| CVE-2024-26267 | Version disclosure by default header verbosity | Yes (5.3) | See the fingerprint row | Portal 7.4.3.26; DXP 7.4 U26, 7.3 U5, 7.2 FP19 | No |

Authenticated-only (list as patch items when the version is known, do not
test): CVE-2020-13445 (template API, 8.8), CVE-2021-29053 (Commerce SQL
injection, 8.8), CVE-2025-43766 (style books upload, PR:H), CVE-2025-43773
(`expandoTableLocalService`, PR:H). CVE-2021-33990 (Portal 6.2.5 FCKeditor
upload) is disputed by Liferay; mention only if the asset is 6.2.

---

## Pega Platform (Pega Infinity)

### Fingerprint

Ports: 8080 / 8443 on the bundled Tomcat, 443 in production. Pega Cloud
tenants live on vendor-managed hosts: confirm the IP belongs to the client
before touching it.

```bash
T="pega.client.example"; B="https://$T"; mkdir -p evidence
for P in /prweb/ /prweb/PRRestService/ /prweb/api/v1/; do
  printf '%s  ' "$P"
  curl -sk -m 15 -o /dev/null -D - "$B$P" | grep -i -E '^(HTTP/|server:|location:|www-authenticate:|set-cookie: (Pega-RULES|JSESSIONID))' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_pega_http.txt"
```

| Signal | Meaning |
|---|---|
| `/prweb/` redirects to a Pega login page; `Pega-RULES` cookie (verify the cookie name per release) | Pega Platform present. |
| `/prweb/api/v1/` or `PRRestService` answers `401` | REST services reachable; authentication enforced. |
| Version | Not shown before login on current releases (verify). Ask the client for the Platform version and applied hotfixes. |
| A JMX/RMI port answering on the Pega host | CVE-2022-24082 precondition. Reachability check per `remote-debug.md`; never send a JMX message. |

### CVE matrix 2020-2026

Pega fixes by release and hotfix (Pega security advisories on
`support.pega.com`). None of these is in KEV (catalog 2026.10.13).

| CVE | What | Pre-auth | Affected | Fix | KEV |
|---|---|---|---|---|---|
| CVE-2020-15390 | `pyActivity=GetWebInfo` access-control misconfiguration | Yes per NVD (9.8) | Platform 8.4.0.237 | Later 8.4 patch (verify) | No |
| CVE-2021-27651 | Password reset for local accounts bypasses local authentication | Yes, 9.8 | Infinity 8.2.1 to 8.5.2 | Pega hotfix per advisory (verify) | No |
| CVE-2022-24082 | JMX port exposed to the internet accepts serialized payloads (on-premises only, not Pega Cloud) | Yes, 9.8 | Infinity 8.1.0 to before 8.7.3 | 8.7.3 and network filtering | No |
| CVE-2023-32090 | Default operator credentials may be in use | Yes, 9.8 | Platform 6.1 to 7.3.1 | Pega advisory: rotate or disable default operators | No |
| CVE-2023-28094 | Default operator credentials after upgrading from a pre-8.x release | Yes, CNA 8.1 (AC:H) | 7.4 to 8.8.x upgraded from before 8.x | Pega advisory C23 | No |

Not tested: CVE-2024-10094 (code generation, PR:H, Platform 6.x to Infinity
24.1.1, fixed 24.1.2) and CVE-2026-13761 (excessive looping, a denial of
service, 7.1.0 to 25.1.2). Do not call `pyActivity` or any activity by URL to
"check" CVE-2020-15390: an activity call runs rule code.

---

## Stage B (written sign-off naming host, port, action and window)

| Action | Blast radius to name |
|---|---|
| One ColdFusion Administrator login with client-supplied credentials | Admin access can schedule tasks and deploy code. Read the Settings Summary only. |
| Any RDS request (`/CFIDE/main/ide.cfm`) | RDS reads and writes files and runs queries. Not done in this bundle; ask the client instead. |
| One documented default credential on Liferay (first-run administrator) or Pega (default operators, the CVE-2023-32090 / CVE-2023-28094 case) | Lockout of a shared operator account; a successful default login is the finding, stop at the landing page. One pair, once. |
| Any JSONWS service invocation, Liferay headless write, or Pega activity call | Server-side code runs. Never. |
| Any JMX or RMI message to Pega | Deserialization. Never; `hunt-deserialization` owns proofs on a test instance. |
| Any upload (ColdFusion APSB26-68 upload CVEs, Liferay style books) | The exploit itself. Never. |

## What is not a finding

- A `Liferay-Portal` header with a current version: version disclosure only.
- `/cf_scripts/scripts/` reachable: normal for any ColdFusion application.
- A Pega login page on 443: how Pega is published.
- Port 8500 answering with a Consul banner: route to `hunt-exposed-panels`.
- A ColdFusion version in range with the Administrator and RDS both
  unreachable and the client confirming RDS off: patch item, not RCE.

Sources (checked 2026-10-13): CVE records via
<https://github.com/CVEProject/cvelistV5> (Adobe APSB, Liferay and Pega
advisory references), NVD keyword queries, CISA KEV catalog 2026.10.13 (CVE
notes for CVE-2026-48282 and CVE-2024-20767), Deepwatch and ZeroDayHub
reporting on CVE-2026-48282 (secondary), Adobe ColdFusion lockdown guidance,
nmap 7.991 NSE categories. Adobe's helpx bulletin pages refused automated
fetches on 2026-10-14; bulletin numbers come from the CVE records.

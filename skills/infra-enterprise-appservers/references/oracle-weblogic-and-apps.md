# Oracle WebLogic, the WebLogic proxy plug-in, E-Business Suite, PeopleSoft, Siebel, JD Edwards

Rule for every row: **a version gate, not an exploit.** Oracle never prints a
patch level on the wire. The T3 reply and the console give the WebLogic release
(`12.2.1.4.0`), not the Critical Patch Update applied to it, so every Oracle row
below is reported as "release in range, patch level unknown" until the client
shows `opatch lsinventory` output or the patch list for the named release.

Oracle TNS 1521 behind these applications belongs to `hunt-exposed-services`
(`references/databases.md`). Native-credential login endpoints that bypass SSO
(`/console/login/LoginForm.jsp`, `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login`)
are listed in `hunt-auth-bypass`.

---

## How Oracle ships fixes (read before quoting a "fixed in")

From Oracle's Security Alerts page, read 2026-10-13:

- **Critical Patch Update (CPU)**: quarterly and cumulative, third Tuesday of
  January, April, July and October. The October 2026 CPU falls on 2026-10-20;
  re-check the matrix after it.
- **Critical Security Patch Update (CSPU)**: targeted fixes, introduced
  2026-05-28, released on the third Tuesday of February, March, May, June,
  August, September, November and December. Released so far: May, June, August
  and September 2026.
- **Security Alert**: out-of-band, for fixes too urgent to wait. Since 2025:
  CVE-2025-61882 and CVE-2025-61884 (EBS), CVE-2026-21992 (Identity Manager and
  Web Services Manager), CVE-2026-35273 (PeopleSoft).
- Oracle's advisories evaluate **only supported versions** ("Supported versions
  that are affected are ..."). A release line that stopped appearing in the
  lists (WebLogic 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0 by the 2024 advisories)
  is not "unaffected"; it receives no fixes at all.

Write the fix as the release vehicle (for example "CPU July 2026" or "CSPU
September 2026"), because that is what the client's patch list names.

---

## WebLogic Server

### Ports and protocols

| Port | What answers |
|---|---|
| 7001 | Default listen port. HTTP, T3 and IIOP share the same listener unless the administrator disabled tunnelling or protocols. |
| 7002 | Default SSL listen port (HTTPS, T3S, IIOPS). |
| 5556 | Node Manager. nmap's probe file recognises its error banner. Not meant to be reachable from outside the domain. |
| 9002 | Domain-wide administration port when enabled (verify per domain). |

### Stage A fingerprint

```bash
T="wls.client.example"; mkdir -p evidence
# T3 handshake + CORBA naming list + title/headers. Nothing else is sent after HELO.
nmap -Pn -sV --scan-delay 2s -p 7001,7002,5556 \
  --script weblogic-t3-info,giop-info,http-title,http-server-header \
  "$T" -oN "evidence/${T}_wls_nmap.txt"
```

| Signal | Meaning |
|---|---|
| `weblogic-t3-info`: `T3 protocol in use (WebLogic version: 14.1.1.0.0)` | T3 reachable from the internet, release identified. The script re-asks with a second version and reports "Unknown WebLogic version" if the server only echoes. |
| `giop-info` returns naming objects | IIOP reachable. The IIOP rows in the matrix apply. |
| Classic WebLogic `Error 404--Not Found` page (citing RFC 2068) | WebLogic serving HTTP directly, not behind a front end. |
| `X-Powered-By: Servlet/<v> JSP/<v>` | WebLogic HTTP (nmap probe file). |
| `GET /console/login/LoginForm.jsp` returns the login form | Administration Console reachable from the internet. The release is usually shown on the page (verify per release; the classic console is not shipped from 14.1.2 onward, verify). |
| `GET /wls-wsat/CoordinatorPortType`, `GET /_async/AsyncResponseService` answer with a service page | Legacy WLS-WSAT and async web-service components deployed (the 2017/2019 KEV CVEs; verify paths per release). A component signal, not a test. |
| A WebLogic application behind Oracle HTTP Server, Apache or IIS | Ask whether the WebLogic proxy plug-in is in use: CVE-2026-21962 (KEV) and the July 2026 plug-in CVEs are on the front end, not the WebLogic server. |

Not Stage A, and not done in this bundle: any T3 or IIOP message after the
handshake, any JNDI lookup or remote object call, the encoded console path
used to bypass authentication (proving it renders an authenticated console),
and any request to the legacy web-service components with a body.

### CVE matrix 2020-2026: pre-auth, network-reachable

Affected versions are Oracle's "supported versions that are affected" text.
KEV dates from the CISA catalog 2026.10.13.

**KEV-listed (escalate the same day):**

| CVE | Component, protocol | Affected | Fixed in | KEV added |
|---|---|---|---|---|
| CVE-2020-2551 | WLS Core Components, IIOP | 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4 | CPU Jan 2020 | 2023-11-16 |
| CVE-2020-2555 | Coherence (shipped with WebLogic), reached over T3 | Coherence 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 | CPU Jan 2020 | 2021-11-03 |
| CVE-2020-2883 | Core, T3 and IIOP | 10.3.6.0 to 12.2.1.4 | CPU Apr 2020 | 2025-01-07 |
| CVE-2020-14644 | Core, T3 and IIOP | 12.2.1.3, 12.2.1.4, 14.1.1 | CPU Jul 2020 | 2024-09-18 |
| CVE-2020-14882 | Console, HTTP | 10.3.6.0 to 14.1.1 | CPU Oct 2020 | 2021-11-03 |
| CVE-2020-14883 | Console, HTTP (needs a high-privileged session; chained with 14882 in the wild) | 10.3.6.0 to 14.1.1 | CPU Oct 2020 | 2021-11-03 |
| CVE-2020-14750 | Console, HTTP (bypass of the CVE-2020-14882 fix) | 10.3.6.0 to 14.1.1 | Security Alert, Nov 2020 | 2021-11-03 |
| CVE-2023-21839 | Core, T3 and IIOP (confidentiality impact, CVSS 7.5) | 12.2.1.3, 12.2.1.4, 14.1.1 | CPU Jan 2023 | 2023-05-01 |
| CVE-2024-21182 | Core, T3 and IIOP (confidentiality impact, CVSS 7.5) | 12.2.1.4, 14.1.1 | CPU Jul 2024 | 2026-06-01 |
| CVE-2026-21962 | Oracle HTTP Server and WebLogic proxy plug-in for Apache and IIS, HTTP, CVSS 10.0 | 12.2.1.4, 14.1.1, 14.1.2 | CPU Jan 2026 | 2026-08-24 |

Pre-2020 WebLogic CVEs that are also KEV-listed matter only on releases that
are already in range for the rows above: CVE-2015-4852 (added 2021-11-03),
CVE-2019-2725 (2022-01-10), CVE-2017-10271 (2022-02-10), CVE-2018-2628
(2022-09-08), CVE-2017-3506 (2024-06-03). Oracle ADF Faces CVE-2022-21445
(ADF 12.2.1.3.0 and 12.2.1.4.0, pre-auth, CPU Apr 2022, KEV 2024-09-18) applies
when ADF applications are deployed on the WebLogic domain; ask the client.

**Not KEV-listed, CVSS 9.8 or higher, unauthenticated:**

| Release | CVEs | Protocol | Affected |
|---|---|---|---|
| CPU Jan 2020 | CVE-2020-2546 | T3 | 10.3.6.0, 12.1.3.0 |
| CPU Apr 2020 | CVE-2020-2801, CVE-2020-2884 | T3, IIOP | 10.3.6.0 to 12.2.1.4 |
| CPU Jul 2020 | CVE-2020-14625, CVE-2020-14645, CVE-2020-14687 | T3, IIOP | 12.2.1.3 to 14.1.1 (14645 also 10.3.6, 12.1.3) |
| CPU Oct 2020 | CVE-2020-14825, CVE-2020-14841, CVE-2020-14859 | T3 and/or IIOP | up to 14.1.1 |
| CPU Jan 2021 | CVE-2021-1994 (Web Services, HTTP), CVE-2021-2047, CVE-2021-2064, CVE-2021-2075, CVE-2021-2108 | HTTP; T3, IIOP | 10.3.6.0 to 14.1.1 per CVE |
| CPU Apr 2021 | CVE-2021-2135, CVE-2021-2136 | T3, IIOP | 12.1.3 to 14.1.1 |
| CPU Jul 2021 | CVE-2021-2382, CVE-2021-2394, CVE-2021-2397 | T3, IIOP | 10.3.6.0 to 14.1.1 |
| CPU Oct 2021 | CVE-2021-35617 | IIOP | 12.1.3 to 14.1.1 |
| CPU Jan 2022 | CVE-2022-21306 | T3 | 12.1.3 to 14.1.1 |
| CPU Oct 2023 | CVE-2023-22069, CVE-2023-22072, CVE-2023-22089 | T3, IIOP | 12.2.1.3 to 14.1.1 per CVE |
| CPU Jul 2024 | CVE-2024-21181 (and CVE-2024-21175, HTTP, CVSS 9.1) | T3, IIOP | 12.2.1.4, 14.1.1 |
| CPU Oct 2024 | CVE-2024-21216 | T3, IIOP | 12.2.1.4, 14.1.1 |
| CPU Jan 2025 | CVE-2025-21535 | T3, IIOP | 12.2.1.4, 14.1.1 |
| CSPU Jun 2026 | CVE-2026-35292 (Console, 10.0), CVE-2026-35301 (Console, 10.0), CVE-2026-35300 (Core, TCP) | HTTP; TCP | 35292: 14.1.2, 15.1.1. 35301: 12.2.1.4, 14.1.1. 35300: 12.2.1.4 to 15.1.1 |
| CPU Jul 2026 | CVE-2026-60198, CVE-2026-60202, CVE-2026-60204 (T3, IIOP); CVE-2026-60199, CVE-2026-60291, CVE-2026-60292 (HTTP); CVE-2026-60200, CVE-2026-60294 (SOAP); CVE-2026-60205 (TCP) | as listed | 12.2.1.4 to 15.1.1 per CVE |
| CPU Jul 2026 | CVE-2026-60364 (12.2.1.4, 14.1.2), CVE-2026-60365 (15.1.1, CVSS 10.0) | HTTP, WebLogic proxy plug-in for third-party web servers | front end, as listed |
| CSPU Aug 2026 | CVE-2026-60672, CVE-2026-60696 (T3, IIOP), CVE-2026-60698 (IIOP), CVE-2026-60977 (RMI) | as listed | 12.2.1.4 to 15.1.1 per CVE |
| CSPU Sep 2026 | CVE-2026-70748, CVE-2026-70756, CVE-2026-70757 (T3, IIOP), CVE-2026-83021 (Web Container, HTTP, CVSS 10.0) | as listed | 12.2.1.4 to 15.1.1 per CVE |

The practical reading: **every supported WebLogic line has had new
unauthenticated criticals in each Oracle release from June to September 2026**
(TCP and console HTTP in June; T3/IIOP in July, August and September). T3 or IIOP reachable from the internet on anything older than the
September 2026 CSPU is in range of a pre-auth critical by default, and on
10.3.6, 12.1.3 or 12.2.1.3 it can never be patched. The fix for the exposure is
a connection filter or firewall that keeps T3/IIOP off the internet, whatever
the patch level.

---

## Oracle E-Business Suite (12.2)

Stage A paths (one `GET` each, no body):

| Path | Signal |
|---|---|
| `/OA_HTML/AppsLogin` | Redirects to the local login (`/OA_HTML/AppsLocalLogin.jsp`) or to SSO: EBS present. |
| `/OA_HTML/BneUploaderService` | Web ADI servlet family (CVE-2022-21587, Rapid7 analysis). Status only; never send a body. |
| `/OA_HTML/ibytransmit` | Oracle Payments file-transmission endpoint observed in CVE-2026-46817 exploitation (Defused, reported by SOCRadar and Beazley). Status only. |
| `/OA_HTML/configurator/UiServlet`, `/OA_HTML/SyncServlet` | Endpoints named in public CVE-2025-61882/61884 reporting (verify against Oracle's IOC list). Status only. |

The EBS release is not reliably shown before login (verify). Ask the client for
the release (12.2.x) and the applied CPU, CSPU and Security Alert patches.

| CVE | Component | Pre-auth | Affected | Fixed in | KEV added |
|---|---|---|---|---|---|
| CVE-2022-21587 | Web Applications Desktop Integrator (Upload) | Yes, CVSS 9.8 | 12.2.3 to 12.2.11 | CPU Oct 2022 | 2023-02-02 |
| CVE-2025-61882 | Concurrent Processing, BI Publisher Integration; KEV marks known ransomware use | Yes, CVSS 9.8 | 12.2.3 to 12.2.14 | Security Alert (Rev 2, 2025-10-06) | 2025-10-06 |
| CVE-2025-61884 | Configurator Runtime UI, SSRF | Yes, CVSS 7.5 | 12.2.3 to 12.2.14 | Security Alert (Rev 1, 2025-10-11) | 2025-10-20 |
| CVE-2026-46817 | Oracle Payments, File Transmission | Yes, CVSS 9.8 | 12.2.3 to 12.2.15 | CSPU May 2026 | 2026-07-15 |

Not in KEV but pre-auth, CVSS 9.8 (NVD), affected 12.2.3 to 12.2.14 or 12.2.15
unless noted. The release is the Oracle CPU or CSPU published on the NVD
publication date (verify the patch number in the advisory):

- CPU Apr 2025: CVE-2025-30727 (Scripting, iSurvey Module).
- CPU Oct 2025: CVE-2025-53072, CVE-2025-62481 (Marketing Administration).
- CPU Apr 2026: CVE-2026-34275 (Advanced Inbound Telephony).
- CPU Jul 2026: CVE-2026-60880 (Work in Process).
- CSPU Aug 2026: CVE-2026-60782 (Payments, File Transmission, the same
  component as CVE-2026-46817), CVE-2026-70926 (Workflow Notification Mailer).
- CSPU Sep 2026: CVE-2026-83327 (Applications Framework, Personalization),
  CVE-2026-83452 (Document Management and Collaboration), CVE-2026-83462
  (Mobile Application Server, MWA Terminal Server).

An EBS host that is internet-facing and missing any 2026 release is in range
for several of these at once; report the patch level, not each CVE.

---

## PeopleSoft (PeopleTools and applications)

Stage A paths: `/psp/<site>/?cmd=login` and `/psc/<site>/` (PeopleSoft Internet
Architecture; `<site>` is often `ps`, `hrprd`, `fsprd` and similar),
`/PSIGW/PeopleSoftServiceListeningConnector` (Integration Broker gateway; what
it returns to a bare `GET` varies, verify), and the `PS_TOKEN` and `PS_LOGINLIST`
cookies. The PeopleTools release (8.5x/8.6x) is the
gate; it is not reliably visible before login (verify), so ask the client.

| CVE | Component | Pre-auth | Affected | Fixed in | KEV added |
|---|---|---|---|---|---|
| CVE-2022-21543 | PeopleTools, Updates Environment Management | Yes, CVSS 9.8 | PeopleTools 8.58, 8.59 | CPU Jul 2022 | No |
| CVE-2026-35273 | PeopleTools, Updates Environment Management; exploited as a zero-day from late May 2026 (Rapid7, citing Mandiant) | Yes, CVSS 9.8, RCE | PeopleTools 8.61, 8.62 | Security Alert, 2026-06-10 | 2026-06-12 |
| CVE-2026-35278 | PeopleTools, Performance Monitor | Yes, CVSS 9.8 | PeopleTools 8.61, 8.62 | CSPU Jun 2026 | No |
| CVE-2026-60821 | PeopleTools, Business Interlink | Yes, CVSS 9.8 | PeopleTools 8.61 to 8.63 | CSPU Aug 2026 | No |
| CVE-2026-61233, CVE-2026-61237, CVE-2026-61245 | PeopleSoft application Integration components | Yes, CVSS 9.8 to 9.9 | application 9.1 | CPU Jul 2026 | No |

The July 2026 CPU also fixed a long list of unauthenticated 9.0-9.4 issues in
PeopleSoft 9.2 application modules (Expenses, Security, Common Objects,
eProcurement, Manufacturing). Treat "PeopleSoft 9.x on the internet, July 2026
CPU not applied" as in range. The Environment Management hub is an
administrative component; if it answers from the internet, that alone is a
High finding given CVE-2026-35273.

---

## Siebel CRM

Stage A paths: `/<app>_<lang>/start.swe` (for example `callcenter_enu`) on older
releases and `/siebel/app/<app>/<lang>` on Siebel IP 17 and later. Siebel
releases are named by year and month (17.0 to 26.x).

Oracle's 2026 CSPU and CPU releases fixed many unauthenticated HTTP criticals
across Siebel components. Representative rows:

| CVE | Component | Affected | Fixed in |
|---|---|---|---|
| CVE-2026-46884, CVE-2026-46887, CVE-2026-46889, CVE-2026-46890 | Marketing, CVSS 9.8 | 17.0 to 26.5 | CSPU Jun 2026 |
| CVE-2026-46919 | Siebel Cloud Manager, CVSS 9.8 | 17.0 to 26.5 | CSPU Jun 2026 |
| CVE-2026-47036 | Siebel Approval Manager, CVSS 9.8 | 17.0 to 26.3 | CPU Jul 2026 |
| CVE-2026-61318, CVE-2026-62452 | Siebel Cloud Manager, CVSS 9.8/9.9 | 22.3 to 26.6 | CSPU Aug 2026 |
| CVE-2026-62585, CVE-2026-62592 | Data Archival, Open Integration, CVSS 9.8 | 25.12 to 26.6 | CSPU Aug 2026 |
| CVE-2026-83154, CVE-2026-83201, CVE-2026-83202 | Open UI (SOAP), Server Infrastructure, CVSS 9.1 | 17.0 to 26.7 | CSPU Sep 2026 |

No Siebel CVE is KEV-listed as of 2026-10-13. No unauthenticated Siebel critical
from 2020-2025 met this file's threshold (CVSS 8.8+) in NVD.

---

## JD Edwards EnterpriseOne

Stage A paths: `/jde/E1Menu.maf` and `/jde/owhtml/` on the HTML server (which
runs on WebLogic or WebSphere: fingerprint that layer too). The Tools release
(9.2.x.y) is the gate. JDENET, the enterprise-server protocol, should never be
reachable from the internet; its port is configured per installation (verify),
so identify it from `-sV` output rather than assuming a number.

| CVE | Component | Pre-auth | Affected (Tools) | Fixed in |
|---|---|---|---|---|
| CVE-2020-2733 | Monitoring and Diagnostics, HTTP | Yes, CVSS 9.8 | 9.2 | CPU Apr 2020 |
| CVE-2025-21524 | Monitoring and Diagnostics SEC, HTTP | Yes, CVSS 9.8 | before 9.2.9.0 | CPU Jan 2025 |
| CVE-2026-46878 to CVE-2026-46883, CVE-2026-46904 | Enterprise Infrastructure Security, **JDENET** | Yes, CVSS 9.8 | 9.2.0.0 to 9.2.26.2 | CSPU Jun 2026 |
| CVE-2026-46905, CVE-2026-46909 | Web Runtime Security, Enterprise Infrastructure Security, HTTP | Yes, CVSS 9.8 | 9.2.0.0 to 9.2.26.2 | CSPU Jun 2026 |
| CVE-2026-61272 | Web Runtime SEC, HTTP | Yes, CVSS 9.8 | 9.2.0.0 to 9.2.26.4 | CSPU Aug 2026 |

No JD Edwards CVE is KEV-listed as of 2026-10-13. A JDENET port answering from
the internet is High on reachability alone, given the June 2026 set.

---

## Stage B and forbidden actions for this family

| Action | Stage |
|---|---|
| One documented default credential on the WebLogic console or a PeopleSoft/JDE demo account | B, one attempt; a failed attempt counts toward the domain's lockout (WebLogic user lockout is on by default, verify the threshold) |
| Rendering the console through an authentication-bypass path | B; stop at the first page |
| Anything after the T3/IIOP handshake, JNDI lookups, remote object calls | Forbidden |
| Requests with a body to EBS Web ADI, Payments transmission, Configurator, or the PeopleSoft Environment Management hub | Forbidden |

Sources (checked 2026-10-13): CISA KEV catalog 2026.10.13; NVD API 2.0 and
cvelistV5 records (Oracle "supported versions that are affected" text, CPU/CSPU
reference URLs); Oracle Security Alerts page
<https://www.oracle.com/security-alerts/> (CPU and CSPU schedule, alert list);
nmap 7.991 `weblogic-t3-info.nse`, `giop-info.nse` and `nmap-service-probes`;
Rapid7 CVE-2022-21587 analysis; Rapid7 and Horizon3 on CVE-2026-35273; SOCRadar,
Beazley and Defused reporting on CVE-2026-46817; SentinelOne and NetSPI
summaries of CVE-2026-21962.

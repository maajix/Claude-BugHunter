# SAP NetWeaver ABAP and Java, Web Dispatcher, Message Server, Gateway

Rule for every row: **a version gate, not an exploit.** A component that answers
and a release inside a listed range is reported as "reachable, version in range,
unconfirmed" until the client's own patch list (SAP Note implementation status
in SNOTE, or the kernel patch level from `disp+work -v`) confirms it. Nothing in
this file sends an RFC call, a DIAG logon, a P4 object, a smuggled request or an
upload.

SAPRouter on 3299 is **not** here: `hunt-exposed-services`
(`references/management-interfaces.md`) owns it, including CVE-2022-27668.
OData services under `/sap/opu/odata/` go to `hunt-api-misconfig`.

---

## Ports (NN = the two-digit instance number)

| Port | Service | Where it should be reachable from |
|---|---|---|
| 32NN | Dispatcher, DIAG protocol (SAP GUI) | Client LAN or VPN only |
| 33NN | Gateway, RFC (`sapgw<NN>`) | Application servers and RFC partners only |
| 48NN | Gateway secured with SNC (verify) | Same as 33NN |
| 36NN | Message server (`sapms<SID>`) | Application servers and logon-balancing clients |
| separate port when `rdisp/msserv_internal` is non-zero, commonly 39NN (verify) | Internal message server port, application-server registration only | **Never** outside the SAP server segment |
| 80NN, 443NN | ICM HTTP (default 8000) and HTTPS (443NN by convention, not active by default) | Internet only through a Web Dispatcher or reverse proxy |
| 81NN, 444NN | Message server HTTP (default 8100) and HTTPS | Internal |
| 5NN00, 5NN01 | AS Java HTTP and HTTPS | Through a Web Dispatcher or reverse proxy |
| 5NN02, 5NN03, 5NN06 | AS Java IIOP initial context, IIOP over SSL, IIOP | Internal |
| 5NN04, 5NN05 | AS Java P4 (and JMS), P4 over SSL | Internal. P4 on the internet is a finding by itself |
| 5NN07 or 5NN08 | AS Java Telnet administration (port index 7 in the 7.3 documentation; 5NN08 in older tables, verify per release) | Localhost |
| 5NN13, 5NN14 | SAP start service (`sapstartsrv`, SOAP "SAPControl") HTTP and HTTPS | Administrators only |
| 5NN20 + n*5 and up | AS Java cluster join, debug and DSR ports per server process | Inside the cluster only |

Sources: SAP Help "Ports of AS Java" (7.3) gives the `50000 + 100*NN + index`
formula and indices 0-7, and lists 5NN13/5NN14 for the start service; SAP Help
"Ports used by the ICM and message server" gives 80NN/8000, 81NN/8100, 36NN,
33NN. The canonical list is SAP's "TCP/IP Ports of All SAP Products"
(help.sap.com/viewer/ports) and KBA 2506865, both behind SAP login for the
full text.

**Exposure is the first finding.** DIAG, Gateway, Message Server, P4, IIOP,
Telnet admin, cluster ports and `sapstartsrv` have no business on a public
address. Every unauthenticated SAP CVE below lands on one of them or on the
ICM. Report the open port with the service fingerprint before any version work.

---

## Stage A fingerprint

Read-only: TCP connect, the service's own greeting, one HTTP `GET` per path.
No SAP GUI logon, no RFC, no SOAP method call, no credentials.

```bash
T="sap.client.example"; NN="00"; mkdir -p evidence
# Service detection on the instance's ports only. nmap's probe file knows the
# message server HTTP banner, SAP NetWeaver HTTP, SAP Logviewer and SAProuter.
nmap -Pn -sV --version-intensity 5 --scan-delay 2s \
  -p "32$NN,33$NN,36$NN,39$NN,80$NN,81$NN,443$NN,5${NN}00,5${NN}01,5${NN}04,5${NN}13,5${NN}14" \
  "$T" -oN "evidence/${T}_sap_nmap.txt"
```

```bash
# ICM / AS Java HTTP: Server header first. 2 s apart, one GET each.
B="https://$T"     # or http://$T:80$NN / http://$T:5${NN}00 for a direct ICM or AS Java port
for P in / /sap/public/info /sap/bc/gui/sap/its/webgui /irj/portal /nwa \
         /CTCWebService/CTCWebServiceBean /developmentserver/metadatauploader \
         /sap/wdisp/admin/public/default.html; do
  printf '%s  ' "$P"
  curl -sk -m 15 -o /dev/null -D - "$B$P" | grep -i -E '^(HTTP/|server:|www-authenticate:|location:)' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_sap_http.txt"
```

| Signal | Meaning |
|---|---|
| `server: SAP NetWeaver Application Server ...` / `SAP Web Application Server (...)` | ICM in front of ABAP or Java. The release string, when present, is the SAP release, not the kernel patch level. |
| `server: SAP Message Server, release NNN` on 81NN | Message server HTTP port exposed; the release is the kernel release. |
| `/sap/public/info` returns XML | ABAP system information service (ICF node under `/sap/public`, no logon by design). Typically leaks SID, release, kernel release, OS, database and host addresses. Low-Medium on its own; the fix is deactivating the node in `SICF`. |
| `/sap/bc/gui/sap/its/webgui` answers with a logon page | SAP GUI for HTML reachable from the internet. Exposure, not a vulnerability. |
| `/irj/portal`, `/nwa` redirect to a logon page | AS Java, Enterprise Portal and NetWeaver Administrator. |
| `/CTCWebService/CTCWebServiceBean` answers without `401` | The LM Configuration Wizard component behind CVE-2020-6287 is deployed and reachable. It is **not** proof of the CVE: Tenable's early plugin for this check was reported to false-positive on the wrong endpoint. Reachable component + release in range = unconfirmed. |
| `/developmentserver/metadatauploader` answers without a credential prompt | Visual Composer development server reachable unauthenticated: exposure condition for CVE-2025-31324 (Truesec, Censys guidance). Visual Composer is not installed by default. |
| `/sap/wdisp/admin/public/...` answers | Web Dispatcher administration UI's public part reachable (verify path per release). |
| `nmap --script http-sap-netweaver-leak` (categories `safe`, `discovery`) | Checks anonymous access to the Portal KM navigation page `/irj/go/km/navigation?Uri=/`, which lists repository folders and users. A listing is the finding. |

Do **not** request the known webshell names dropped by CVE-2025-31324 exploitation
(`/irj/root/*.jsp` and similar). A hit is an incident, not a test result:
stop, tell the client the same day, and leave the artefact to their responders.

`sapstartsrv` (5NN13/5NN14): a `GET /?wsdl` that returns the SAPControl WSDL
proves the start service is reachable. Which SOAP methods answer without
credentials depends on `service/protectedwebmethods` (verify the default set on
the client's kernel). Calling any method is Stage B.

Gateway (33NN) and message server (36NN, internal port): the nmap service
fingerprint is the whole Stage A test. **Never** register an external RFC
server program at the gateway (`reginfo` abuse), start one (`secinfo` abuse),
send a message-server administration packet, or try to register as an
application server. Each of those is code execution or a takeover of logon
balancing, and none is needed to report the exposure.

---

## CVE matrix 2020-2026 (unauthenticated or KEV-listed)

SAP fixes by SAP Note on its monthly Security Patch Day (second Tuesday). The
publication dates below are the CVE record's `datePublished`, which is the
Patch Day. KEV dates from the CISA catalog 2026.10.13. Kernel-level CVEs are
fixed by a kernel patch named in the Note; the Note, not a release number, is
what the client confirms.

| CVE | Component, reach | Pre-auth | Affected (CNA record) | Fix | KEV |
|---|---|---|---|---|---|
| CVE-2020-6287 ("RECON") | AS Java LM Configuration Wizard, `/CTCWebService/CTCWebServiceBean` | Yes; creates an administrator | AS Java 7.30, 7.31, 7.40, 7.50 | Note 2934135, July 2020 | Yes, 2021-11-03 |
| CVE-2020-6207 | Solution Manager 7.2 User Experience Monitoring (EEM) | Yes; compromises connected SMD agents | SolMan 7.2 | Note 2890213, March 2020 | Yes, 2021-11-03 |
| CVE-2020-26829 | AS Java P2P cluster communication (cluster ports) | Yes | AS Java 7.11 to 7.50 | Note 2974774, Dec 2020 | No |
| CVE-2021-37535 | AS Java JMS Connector Service (JMS rides the P4 port index) | Yes | AS Java 7.11 to 7.50 | Note 3078609, Sep 2021 | No |
| CVE-2021-38162 | Web Dispatcher request smuggling (AC:High) | Yes | WEBDISP 7.49, 7.53, 7.77, 7.81; kernel 7.22, 7.49, 7.53, 7.77, 7.81, 7.83 | Note 3080567, Sep 2021 | No |
| CVE-2021-38163 | Visual Composer 7.0 RT file upload | **No** (low-privileged user) | 7.30 to 7.50 | Note 3084487, Sep 2021 | Yes, 2022-06-09 |
| CVE-2022-22536 ("ICMAD") | ICM HTTP request smuggling and concatenation: ABAP, Java, Web Dispatcher, Content Server 7.53 | Yes | Kernel 7.22, 7.49, 7.53, 7.77, 7.81, 7.85-7.87, 8.04 and Web Dispatcher equivalents | Note 3123396, Feb 2022 | Yes, 2022-08-18 |
| CVE-2022-22532 | AS Java HTTP shared-memory handling | Yes | Kernel 7.22, 7.49, 7.53 | Note 3123427, Feb 2022 | No |
| CVE-2022-41271, CVE-2023-0017, CVE-2023-23857 | Open JNDI naming interface: PI messaging system (41271), AS Java (0017, 23857) | Yes | PI 7.50; AS Java 7.50 | Notes 3267780 (Dec 2022), 3268093 (Jan 2023), 3252433 (Mar 2023) | No |
| CVE-2023-33987 | Web Dispatcher request smuggling (CNA 8.6, NVD 9.4) | Yes | WEBDISP 7.49 to 7.90 and matching kernels | Note 3233899, July 2023 | No |
| CVE-2025-31324 | Visual Composer Metadata Uploader, `/developmentserver/metadatauploader` | Yes; uploads executables (webshells in the wild) | VCFRAMEWORK 7.50 | Note 3594142, out-of-band 2025-04-24 | Yes, 2025-04-29 |
| CVE-2025-42999 | Visual Composer Metadata Uploader deserialization | No (privileged user); chained with CVE-2025-31324 in the wild | VCFRAMEWORK 7.50 | Note 3604119, May 2025 | Yes, 2025-05-15 |
| CVE-2025-42944 | RMI-P4 deserialization on the P4 port (5NN04) | Yes; OS command execution, CVSS 10.0 | SERVERCORE 7.50 | Note 3634501, Sep 2025 (follow-up Notes 3660659, 3670067) | No |
| CVE-2026-40128 | AS Java Web Container logon request, file-inclusion path traversal (AC:High) | Yes | ENGINEAPI 7.50 | Note 3727078, June 2026 | No |
| CVE-2026-27671 | ABAP kernel RFC handling, memory corruption, reached on the gateway | Yes | Kernels 7.22 to 9.18 (see Note) | Note 3717897, June 2026 | No |
| CVE-2026-34265 | ABAP DIAG protocol parsing, memory corruption, reached on 32NN | Yes | Kernels 7.22 to 9.19 (see Note) | Note 3714806, Aug 2026 | No |
| CVE-2026-58240 | Message Server accepts unauthenticated application-server registration | Yes | Kernel 9.16, 9.18, 9.19, 9.20 | Note 3759472, Sep 2026 | No |
| CVE-2017-12637 (older, KEV-listed 2025) | AS Java scheduler UI directory traversal, `scheduler/ui/js/...` | Yes; file read | AS Java 7.5 | Note 2486657; KEV notes cite 3476549 | Yes, 2025-03-19 |

Older NetWeaver CVEs in KEV (pre-2020 fixes, relevant only on systems that
missed years of Patch Days): CVE-2010-5326 (Invoker Servlet, added
2021-11-03), CVE-2016-3976 and CVE-2016-9563 (2021-11-03), CVE-2016-2386 and
CVE-2016-2388 (2022-06-09). A system old enough for these is in range for
CVE-2020-6287 as well.

Authenticated-only criticals (CVE-2025-42922 AS Java upload, CVE-2025-42963
Log Viewer deserialization, CVE-2026-0509 RFC authorization, CVE-2026-44748 XML
signature) matter only once a credential is in play. They are out of Stage A
scope; list them for the client as patch items if the version is known.

How to read the matrix externally:

- The ICM and Web Dispatcher never print the kernel patch level. ICMAD and the
  Web Dispatcher smuggling CVEs are **always** "version unknown, ask the client"
  from the outside. `hunt-http-smuggling` owns the technique; on SAP it stays a
  version-gate item (Stage B below).
- A non-HTTP SAP port answering from the internet is reportable on reachability
  alone, and the 2026 kernel CVEs make it urgent: DIAG (CVE-2026-34265),
  Gateway (CVE-2026-27671), Message Server (CVE-2026-58240), P4 (CVE-2025-42944).
- CVE-2025-31324 and CVE-2020-6287 are the two where Stage A can show the
  vulnerable component answering. Escalate both the same day.

---

## Stage B (written sign-off naming host, port, action and window)

| Action | Blast radius to name |
|---|---|
| One default-credential attempt (well-known ABAP pairs such as `SAP*`, `DDIC`, `EARLYWATCH`, `TMSADM` with their installation defaults) against WebGUI, an ICF service with basic auth, or DIAG | A failed logon counts toward `login/fails_to_user_lock` (default 5, verify on the client's release) and can lock a technical user that interfaces depend on; `SAP*` behaviour depends on `login/no_automatic_user_sapstar`. One pair, one client, once. |
| Any SOAP method call on `sapstartsrv` | Several methods stop, restart or reconfigure the instance. Read-only methods only, named in the sign-off. |
| Any request to the Visual Composer uploader other than the Stage A `GET` | An upload is the exploit. Never. |
| A RECON check beyond reachability (a SOAP call to `CTCWebServiceBean`) | Configuration tasks run on a production Java stack. Never. |
| ICMAD / Web Dispatcher smuggling probe | A desynchronised ICM serves another user's response to someone else. Version-gate only; a probe needs a dedicated test instance. |
| RFC call, gateway program registration, message-server packet, P4 or IIOP object | Code execution or logon-balancing takeover. Not done in this bundle. |
| CVE-2026-27671, CVE-2026-34265 triggers | Memory corruption on a production kernel; the work process or the whole instance dies. Forbidden. |

---

## What is not a finding

- A Web Dispatcher or reverse proxy publishing Fiori, WebGUI or the Portal on
  443 with a logon page. That is how SAP is meant to be published.
- `/sap/public/bc/icons/` and similar static public ICF nodes.
- A `server:` header naming SAP with no release, or a release with no
  reachable CVE (version disclosure is core ineligible on HackerOne).
- "Unpatched SAP" with no version evidence. Every kernel CVE here needs the
  client's Note status.

Sources (checked 2026-10-13): CVE records via
<https://github.com/CVEProject/cvelistV5> (SAP Note references), NVD,
CISA KEV catalog 2026.10.13, SAP Help port documentation
(<https://help.sap.com/saphelp_nw73/helpdata/en/a2/f9d7fed2adc340ab462ae159d19509/content.htm>,
<https://help.sap.com/saphelp_em92/helpdata/en/4e/c26cdc58e968b9e10000000a42189e/content.htm>),
Truesec and Censys advisories for CVE-2025-31324, Onapsis RECON
(<https://www.onapsis.com/recon-sap-cyber-security-vulnerability>), Tenable
community thread on the RECON false positive, Acunetix/Invicti notes on
`/sap/public/info`, nmap 7.991 `nmap-service-probes` and NSE categories.

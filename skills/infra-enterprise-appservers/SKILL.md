---
name: infra-enterprise-appservers
description: "Triage internet-exposed enterprise application servers and ERP platforms: SAP NetWeaver ABAP and Java (DIAG 32NN, Gateway 33NN, Message Server 36NN, ICM 80NN/443NN, AS Java 5NN00-5NN04), SAP Web Dispatcher, Oracle WebLogic (7001/7002, T3 and IIOP), E-Business Suite, PeopleSoft, Siebel, JD Edwards, IBM WebSphere (9060/9080/9443/8880), JBoss EAP and WildFly management (9990, 4447), GlassFish and Payara (4848), Adobe ColdFusion (8500), Liferay, Pega, Apache Tomcat version gates, and Atlassian Confluence, Jira, Bitbucket and Bamboo Data Center. The finding is the exposure plus a version inside a known-exploited range: fingerprinting, version disclosure, a 2020-2026 CVE matrix with CISA KEV status and fixed releases, and read-only reachability checks. Stage A is read-only; any login, upload, deserialization payload, smuggling probe or exploit confirmation is Stage B with written sign-off. Use when a scan, banner or page title shows one of these products on an in-scope host."
sources: nvd, cvelistv5, cisa_kev, vendor_advisories, vendor_documentation, oracle_security_alerts, sap_security_notes, nmap_nse_source, researcher_writeups
report_count: 0
---

## When to use

Trigger when external recon has produced an enterprise application server or
ERP front end on a host you are authorized to test, and you need to decide
whether it is a finding. The finding here is **the exposure plus a version
inside a known-exploited range**, or a management or cluster protocol that
answers from the internet. It is not an exploit you ran.

Use when any of these is true:

- A port from the table in Step 3 answers on a public address (7001, 4848,
  9990, 8880, 8090, 7990, 8085, an SAP 32NN/33NN/36NN/5NN04 port, and so on).
- A page title, `Server` header, cookie or redirect names SAP, WebLogic, Oracle
  E-Business Suite, PeopleSoft, Siebel, JD Edwards, WebSphere, JBoss, WildFly,
  GlassFish, Payara, ColdFusion, Liferay, Pega, Confluence, Jira, Bitbucket or
  Bamboo.
- A CISA KEV addition or vendor alert lands for one of these products and the
  client wants to know whether their perimeter is affected.

**Do not use this skill for discovery.** Hosts, ports and ASNs come from
`offensive-osint`, `web2-recon` and `infra-external-methodology`; scope
confirmation from `recon-scope-triage`. This skill starts from "the product
answers and is in scope".

### Where the chain ends

This skill stops at **product identified, version or patch level established
(or stated as unknowable), vulnerable component shown reachable, KEV status
named, evidence captured**. Nothing here logs in, uploads, deserializes, smuggles
or triggers memory corruption. Concretely:

- A KEV-listed pre-auth CVE in range is reported **unconfirmed** and escalated to
  the client the same day. Confirmation is the client's patch list, not a PoC.
- A management or cluster protocol (T3/IIOP, SAP P4, DIAG, RFC, Message Server,
  JBoss remoting, Hazelcast, SOAP connector) answering from the internet is
  reported on reachability. Nothing is sent after the handshake.
- A default-credential hit or an authenticated listing is Stage B, one attempt,
  and the report stops at the privilege shown. No configuration change, no
  deployment, no data browsing.
- Signs of prior compromise (an unexpected JSP in a web root, a known webshell
  name) end testing on that host and go to the client's incident responders.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| Tomcat Manager (`/manager/html`, `/manager/text`), JBoss `jmx-console`, `web-console`, invoker servlets, Tomcat CVE-2025-24813 write test | `hunt-exposed-panels` (`references/java-app-servers.md`) |
| AJP 8009 and Ghostcat CVE-2020-1938, Java RMI registry 1099, JDWP | `hunt-exposed-services` (`references/remote-debug.md`) |
| SAProuter 3299 and CVE-2022-27668 | `hunt-exposed-services` (`references/management-interfaces.md`) |
| Oracle TNS 1521 behind EBS, PeopleSoft or JDE | `hunt-exposed-services` (`references/databases.md`) |
| Spring Boot Actuator, Jolokia, H2 console | `hunt-springboot` |
| Gadget chains and deserialization payloads | `hunt-deserialization`, under its own Stage B |
| Request smuggling technique (SAP ICMAD is only version-gated here) | `hunt-http-smuggling` |
| OData under `/sap/opu/odata/` | `hunt-api-misconfig` |
| Native-credential REST login bypassing SSO (Jira, Confluence, WebLogic, EBS, PeopleSoft) | `hunt-auth-bypass` |
| `WWW-Authenticate: NTLM` on any of these | `hunt-ntlm-info` |
| TLS on every port | `hunt-tls-network` |
| Credential guessing beyond one documented default | `hunt-brute-force` |
| Jenkins, TeamCity, GitLab and other build servers | `hunt-cicd` |
| Anything after a login: internal pivoting, AD, lateral movement | Not in this bundle (`SECURITY.md`) |

---

## Step 1 — Inherit host and port, then hold the rate posture

Take hosts from the signed scope and ports from recon. Confirm ownership (ASN,
RDAP, PTR) before the first packet. If the product sits behind a CDN or WAF
edge, only HTTP testing of the client's hostname is allowed; never port-scan
the edge address (`infra-external-methodology` Step 2).

ERP and application servers are production business systems. The defence
that hurts here is not a ban on your IP but a locked technical user, a
saturated work process or an alert to the client's SOC.

- Serial, one host at a time, 2 s base delay plus 0-3 s jitter between requests.
- Stage A budget: about 40 HTTP requests and one nmap service run per host per
  day. The path lists in the reference files fit inside it.
- No directory brute force, no `http-enum`, no nuclei tag sweeps against ERP
  hosts in Stage A. Use the named paths only.
- Under an engagement request ceiling, `curl` is governed and `nmap` is refused
  by `hooks/throttle-guard.py` (`docs/rate-limiting.md`); run the nmap step
  only when no ceiling is set or the operator adds it to the `TOOLS` table.
- A run of `503`, resets or WAF block pages is a defence, not "host down". Stop
  for 10 minutes; do not retry in a loop.

```bash
T="app.client.example"; mkdir -p evidence
UA="Mozilla/5.0 (authorized-test; ticket-<id>)"   # if the RoE requires an identifying UA
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

---

## Step 2 — Prove the exposure is real, external, the client's, and not a decoy

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN and office range; record the egress IP. | A console reached over the client's VPN is not an exposure. |
| Ownership | ASN + RDAP + reverse DNS, cross-checked with scope. | SaaS-hosted ERP (SAP RISE, Oracle Cloud, Atlassian Cloud) is the provider's infrastructure; see below. |
| Two signals agree | Product and version from two independent places (header and page asset, T3 reply and console page, REST version endpoint and page meta tag). | Honeypots for WebLogic, Confluence and Tomcat are common, and they echo whatever version you ask for. `weblogic-t3-info` already re-asks with a second version string to catch an echoing server. |
| Proxy or real server | A `Server` header from a WAF or load balancer in front of the product is the proxy's version, not the product's. | Oracle HTTP Server, Apache, IIS and SAP Web Dispatcher front most of these products. Fingerprint both layers; the front end has its own CVEs. |
| Cloud-hosted variant | `*.atlassian.net`, Oracle-managed EBS/PeopleSoft cloud tenants, SAP-managed RISE landscapes. | The provider patches the server; findings there are the provider's programme, not this client's. Tenant configuration (anonymous access, public pages) is still the client's. |

Record raw output for every probe so Stage B evidence has a baseline.

---

## Step 3 — Triage the port or fingerprint to one reference file

| Product | Default ports | First Stage A fingerprint | Reference |
|---|---|---|---|
| SAP AS ABAP, ICM | 32NN DIAG, 33NN Gateway, 36NN Message Server, 80NN/443NN ICM, 81NN Message Server HTTP | `server:` header, `/sap/public/info` | `sap-netweaver.md` |
| SAP AS Java | 5NN00/5NN01 HTTP(S), 5NN04 P4, 5NN13/5NN14 start service | `/irj/portal`, `/nwa`, component paths | `sap-netweaver.md` |
| SAP Web Dispatcher | Configured; usually 80/443 or 80NN/443NN | SAP `server:` header in front of other back ends | `sap-netweaver.md` |
| Oracle WebLogic | 7001 (HTTP, T3, IIOP on one listener), 7002 (SSL), 5556 Node Manager | `weblogic-t3-info` `HELO:` reply, `/console/` | `oracle-weblogic-and-apps.md` |
| Oracle EBS, PeopleSoft, Siebel, JD Edwards | Deployment-specific, usually 443 through Oracle HTTP Server or WebLogic | `/OA_HTML/AppsLogin`, `/psp/<site>/?cmd=login`, `start.swe`, `/jde/E1Menu.maf` | `oracle-weblogic-and-apps.md` |
| IBM WebSphere traditional | 9060/9043 admin console, 9080/9443 applications, 8880 SOAP connector, 2809 bootstrap (IIOP) | `/ibm/console`, nmap `WebSphere Application Server/<ver>` | `java-ee-servers.md` |
| JBoss EAP, WildFly | 8080 HTTP, 9990 management HTTP, 9999 native management and 4447 remoting (EAP 6) | `/management` answering `401` Digest, nmap `jboss-remoting` | `java-ee-servers.md` |
| GlassFish, Payara | 4848 admin, 8080/8181 applications | Admin console login page on 4848 | `java-ee-servers.md` |
| Apache Tomcat | 8080/8443 (8009 AJP is owned elsewhere) | Default error page footer `Apache Tomcat/<ver>` | `java-ee-servers.md` (version gate only) |
| Adobe ColdFusion | 8500 built-in server, or behind IIS/Apache on 80/443 | `/CFIDE/administrator/`, `/CFIDE/adminapi/` | `coldfusion-liferay-pega.md` |
| Liferay Portal / DXP | 8080 in the Tomcat bundle, 443 in production | `Liferay-Portal` response header | `coldfusion-liferay-pega.md` |
| Pega Platform | 8080/443 | `/prweb/` | `coldfusion-liferay-pega.md` |
| Confluence DC | 8090, Synchrony 8091 | `ajs-version-number` meta on `/login.action` | `atlassian-data-center.md` |
| Jira DC | 8080 | `/rest/api/2/serverInfo` | `atlassian-data-center.md` |
| Bitbucket DC | 7990, SSH 7999, Hazelcast cluster 5701 | `/rest/api/1.0/application-properties` | `atlassian-data-center.md` |
| Bamboo DC | 8085 | `/rest/api/latest/info` | `atlassian-data-center.md` |

**Port collisions the response must settle, never the port number:**

- **8500**: Consul (`hunt-exposed-panels`) or the ColdFusion built-in server.
- **9443**: Portainer (`hunt-exposed-panels`) or WebSphere's HTTPS transport.
- **8000**: SAP ICM's default HTTP port, and a common JDWP port
  (`hunt-exposed-services`). A `JDWP-Handshake` echo is not SAP.
- **8080**: Tomcat, Jira, WildFly, Liferay, Pega, Airflow and proxies all use it.
- **5701**: Bitbucket DC's Hazelcast cluster port, or any other Hazelcast
  deployment. A generic Hazelcast member has no owner in the bundle.
- **50000-59999**: SAP AS Java uses the `5NN00 + index` scheme; other products
  pick ports in the same range.

---

## Step 4 — Stage A: read-only fingerprint

A Stage A probe sends no credential, no request body, no serialized object and
no request that the product documents as changing state. `GET` and `HEAD` only,
plus the protocol greetings named below.

### 4a. Service detection with named scripts

```bash
# One nmap run per host, ports from recon only. Scripts named one by one.
nmap -Pn -sV --version-intensity 5 --scan-delay 2s -p "$PORTS" \
  --script weblogic-t3-info,giop-info,http-title,http-server-header,http-headers \
  "$T" -oN "evidence/${T}_appserver_nmap.txt"
```

What each named script does (categories checked with `nmap --script-help`,
nmap 7.991):

| Script | Categories | What it sends | Stage |
|---|---|---|---|
| `weblogic-t3-info` | `default`, `safe`, `discovery`, `version` | One T3 handshake line; reads `HELO:<version>`. Re-asks with a second version to detect a server that only echoes. Ports 7001-7003 or anything `-sV` calls WebLogic. | A |
| `giop-info` | `default`, `discovery`, `safe` | Asks a CORBA naming service for its object list. | A |
| `http-title`, `http-headers` | `default`/`discovery`, `safe` | One `GET /` (title follows up to 5 redirects). | A |
| `http-server-header` | `version` | Reads the `Server` header. | A |
| `http-sap-netweaver-leak` | `safe`, `discovery` | One `GET` of the Portal KM navigation page. Only on an AS Java Portal. | A |
| `http-enum` | `discovery`, `intrusive`, `vuln` | Hundreds of path requests. | Not on ERP hosts |
| `http-default-accounts` | `discovery`, `auth`, `intrusive` | Tries default credentials for many products, Tomcat among them. | `hunt-brute-force`, not here |
| `http-coldfusion-subzero` | `exploit` | Retrieves `password.properties` from ColdFusion 9/10. | **Never** |
| `http-adobe-coldfusion-apsa1301` | `exploit`, `vuln` | Steals an admin session cookie. | **Never** |
| `rmi-vuln-classloader` | `intrusive`, `vuln` | Remote class-loading check. | B, and owned by `hunt-exposed-services` |
| `-sC`, `-A` | the whole `default` category | Includes scripts you did not choose. | Never; name scripts |

The T3 handshake is the whole T3 test. After `HELO:` nothing else is sent on
that connection: every WebLogic T3/IIOP CVE in the matrix is triggered by a
serialized object or a JNDI lookup that follows the handshake.

### 4b. HTTP fingerprint, one GET per named path

```bash
# get <base-url> <path>: status, identity headers and redirect, one line per path.
get() {
  curl -sk -m 15 -A "$UA" -o /dev/null -D - "$1$2" \
    | grep -i -E '^(HTTP/|server:|x-powered-by:|location:|www-authenticate:|liferay-portal:|x-arequestid:|x-confluence|x-ausername:|set-cookie: (PS_TOKEN|JSESSIONID|CFID|PS_LOGINLIST))' \
    | tr -d '\r' | tr '\n' ' '
  printf ' <- %s\n' "$2"; probe_delay
}
B="https://$T"
for P in $PATHS; do get "$B" "$P"; done | tee "evidence/${T}_paths.txt"
```

`$PATHS` is the per-product list in the reference file. Keep the response
bodies of version endpoints (`/rest/api/2/serverInfo`, `/sap/public/info` and
similar) as evidence with a plain `curl -sk -m 15 -o evidence/<name> URL`.

### 4c. What to record

| Observable | Why |
|---|---|
| Exact version and build, with its source | The matrix is keyed on it. WebLogic `12.2.1.4.0`, Confluence `8.5.3`, ColdFusion `2023 Update 20`, Liferay `7.4.3.25`, SAP release plus "kernel patch unknown". |
| Which components answer, and with what status | A `401` on a component path proves it is deployed and protected; `200` without a credential prompt proves it is reachable. Several KEV CVEs need a component, not just a version. |
| Management and cluster ports reachable from outside | T3/IIOP on 7001, SAP P4/DIAG/RFC/Message Server, JBoss 9990/9999/4447, GlassFish 4848, WebSphere 8880/2809/9060, Bitbucket Hazelcast 5701. |
| Front-end product and version | Oracle HTTP Server with the WebLogic proxy plug-in, SAP Web Dispatcher, IIS with a ColdFusion connector: each has its own CVEs. |
| Release line support status | A line the vendor no longer lists as "supported" in its advisories gets no fixes. That is a finding in itself when the line is internet-facing. |

---

## Step 5 — Read the results: the version gate

Map what Step 4 recorded to the reference file's matrix. Rules:

- **Use the vendor's patch unit.** SAP: the Security Note on a Patch Day (kernel
  CVEs by kernel patch). Oracle: the quarterly Critical Patch Update, the
  Critical Security Patch Update released in the months between CPUs (first one
  2026-05-28), or an out-of-band Security Alert. Adobe: the ColdFusion update number from the APSB bulletin.
  IBM: the fix pack or interim fix. Atlassian, Tomcat, Liferay, Payara: the
  release number.
- **Most of these products never show their patch level from outside.** SAP
  ICM, WebLogic (the T3 reply gives the release, not the CPU level), EBS and
  PeopleSoft fall in this group. Write "release in range, patch level unknown,
  client to confirm", never "vulnerable".
- **Vendor builds differ from upstream.** Red Hat JBoss EAP versions are not
  WildFly versions; distro Tomcat packages backport fixes; IBM ships Liberty and
  traditional WebSphere on different streams. Gate against the right stream.
- **KEV plus pre-auth plus reachable component is escalate-now**, even
  unconfirmed. The current set across this skill: SAP CVE-2025-31324,
  CVE-2020-6287, CVE-2022-22536; WebLogic CVE-2020-14882/14750, CVE-2023-21839,
  CVE-2024-21182 and the older T3/IIOP set; Oracle HTTP Server / WebLogic proxy
  plug-in CVE-2026-21962; EBS CVE-2025-61882, CVE-2025-61884, CVE-2026-46817;
  PeopleSoft CVE-2026-35273; ColdFusion CVE-2026-48282, CVE-2023-26360;
  Confluence CVE-2023-22527, CVE-2023-22515, CVE-2022-26134; Bitbucket
  CVE-2022-36804; Tomcat CVE-2025-24813 (component condition in
  `hunt-exposed-panels`). Dates and versions are in the reference files.
- **A version in range with the vulnerable component absent is not the CVE.**
  ColdFusion CVE-2026-48282 is reported to need RDS (verify); EBS CVE-2022-21587 needs Web ADI; SAP
  CVE-2025-31324 needs Visual Composer; Bitbucket CVE-2022-43781 needs public
  signup to be unauthenticated. Say which condition you saw and which you could
  not see.

---

## Step 6 — Stage B: anything that authenticates, writes, executes or stresses

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the host, the account if any, the number of requests and a
window. "ERP is in scope" is not sign-off. Record before the first packet:

```
Stage B authorization
  Host/port:        erp.client.example:443
  Action:           one documented default-credential attempt, account <name>
  Blast radius:     one failed-logon count on a technical user; lockout threshold
                    per the client's policy; no session kept, nothing changed
  Reversibility:    a lock is reset by the client's basis/admin team
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| One vendor-documented default credential (SAP standard users, WebLogic or GlassFish admin, Liferay or Pega first-run accounts) | A failed attempt counts toward lockout on technical or service users that interfaces depend on. One pair, one account, once. A success stops at the landing page. |
| An authenticated read with a client-issued test account (version page behind login, role listing) | A login record on a production ERP. Read the one page that proves the point. |
| Any SOAP or REST method on a management interface (SAP `sapstartsrv`, WebSphere SOAP connector, WildFly `/management`, GlassFish REST admin) | Several methods stop, restart or reconfigure the server. Name the single read-only operation. |
| Confirming an authentication bypass (WebLogic console path handling, Jira Seraph, servlet-filter bypass) | Proving it means rendering an authenticated page. Stop at the first page; touch nothing on it. |

**Forbidden outright, sign-off or not.** These are exploitation, irreversible,
or put other users at risk. Report from the version gate and component
reachability instead:

- Any serialized object, JNDI lookup or gadget sent over T3, IIOP, SAP P4,
  RMI, JMX (Pega), Hazelcast (Bitbucket CVE-2022-26133) or a deserializing HTTP
  endpoint.
- Any request to an upload or file-write endpoint behind a CVE: SAP Visual
  Composer uploader, EBS Web ADI uploader, ColdFusion RDS file operations,
  Tomcat partial `PUT` (that one has its own gated test in `hunt-exposed-panels`).
- OGNL, template or expression injection "harmless" probes against Confluence
  (CVE-2021-26084, CVE-2022-26134, CVE-2023-22527) or any other product. An
  evaluated expression is code execution.
- Confluence setup and restore endpoints (CVE-2023-22515, CVE-2023-22518).
  The first changes server state; the second destroys data.
- Request smuggling or desync probes against SAP ICM and Web Dispatcher. A
  desynchronised front end serves other users' responses.
- Memory-corruption triggers (SAP DIAG, RFC and Message Server 2026 CVEs, Web
  Dispatcher CVE-2023-35871) and every DoS-class check.
- Registering anything with an SAP Gateway or Message Server, or routing through
  a SAProuter.
- Requesting known webshell paths left by in-the-wild exploitation. If one
  answers, the host is already compromised: stop and tell the client.

---

## Step 7 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Unauthenticated administrative access (console with no login, Stage B default credential accepted on an admin account) | Critical |
| KEV-listed pre-auth CVE: version in range **and** the vulnerable component reachable without credentials | High, labelled unconfirmed; escalated the same day. Critical once the client confirms the patch is missing. |
| Management or cluster protocol reachable from the internet (T3/IIOP, SAP P4/DIAG/RFC/Message Server, JBoss 9990/9999/4447, WebSphere 8880/2809, GlassFish 4848 with secure admin on, Bitbucket Hazelcast 5701) | Medium to High by protocol; High when a pre-auth CVE in the matrix lands on that port |
| Non-KEV pre-auth critical CVE, version in range, component reachable | Medium, labelled unconfirmed |
| Release line out of vendor support, internet-facing | Medium |
| Anonymous data exposure by configuration (SAP KM navigation listing, Confluence anonymous spaces with internal content, Jira public filters) | Low to High by the data |
| System information leak (`/sap/public/info`, full `Liferay-Portal` header, stack traces with internal hosts) | Low |
| Admin console login page reachable from the internet, current version | Low to Medium (exposure of a management plane) |
| Product identified, current version, no management surface | Not a finding |

### What is not a finding

- **A banner or version string alone.** HackerOne's core ineligible list
  includes software version disclosure; Bugcrowd's VRT rates banner disclosure
  P5. It is input to the gate, not the result.
- **"Outdated" with no reachable issue.** VRT "Outdated Software Version" is P5.
- **A CVE whose component is absent or whose precondition you could not see**,
  presented as confirmed.
- **The vendor's cloud service** (Atlassian Cloud, SAP-managed RISE, Oracle
  Cloud) behaving as designed.
- **A login page on 443 for an ERP that is meant to be used from the internet**,
  such as a self-service HR or supplier portal. The exposure is the business
  model; the version and management surfaces are what you grade.
- **Product honeypots** that echo whatever version you ask for (Step 2).

---

## Step 8 — Evidence

Follow `evidence-hygiene`. Minimum per finding: the nmap output with script
results, the header line or JSON field that gave the version, the status line
for each component path, the egress IP and timestamps, and the reference row
(CVE, KEV date, fixed release) you mapped to. For Stage B, the sign-off record
and the single response that proves the point. Redact session cookies and any
credential. Never keep page content behind a login beyond what proves access.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| WebLogic T3/IIOP on 7001 from the internet, release with open CPU items | Pre-auth T3/IIOP CVEs in the matrix | High, unconfirmed | Same-day client notice; `hunt-deserialization` only under its own Stage B |
| Oracle HTTP Server or WebLogic proxy plug-in in front of an app | CVE-2026-21962 (KEV) on the front end | High, unconfirmed | Patch both the plug-in and the front-end server |
| EBS login page on 443 | Version 12.2.3-12.2.15 plus reachable `OA_HTML` components | High, unconfirmed, KEV | Ask for the patch list; no requests to upload or transmit servlets |
| SAP ICM or Web Dispatcher on 443 | ICMAD and Web Dispatcher smuggling, version unknown | Medium, unconfirmed | Client confirms kernel patch; technique in `hunt-http-smuggling` |
| SAP P4, DIAG, Gateway or Message Server port reachable | 2025-2026 pre-auth kernel and P4 CVEs | High | Report the exposure; firewall is the fix |
| Confluence version in range | CVE-2023-22527 / CVE-2022-26134 class | High, unconfirmed, KEV | No probes; client confirms |
| Jira, Confluence, Bitbucket public pages | Anonymous content, user directory, public signup (Bitbucket CVE-2022-43781 condition) | Low to High | `hunt-idor`, `offensive-osint` for content; `hunt-auth-bypass` for native-login REST |
| Admin console reachable (4848, 9060, 9990, `/console`, `/CFIDE/administrator`) | One documented default credential (Stage B) | Critical if accepted | Stop at the landing page |
| ColdFusion version in range | CVE-2026-48282 reportedly needs RDS enabled (verify) | High, unconfirmed, KEV | Ask whether RDS is enabled; no RDS requests |
| `NTLM` challenge on any of these | Internal domain and host names | Low, chain input | `hunt-ntlm-info` |

---

## Validation checklist

- [ ] Every host confirmed client-owned and in the signed scope; vendor cloud
      tenants not tested as if they were the client's servers.
- [ ] Probed from outside every client network; egress IP recorded.
- [ ] Product and version confirmed by two independent signals; honeypot and
      proxy-header confusion ruled out.
- [ ] nmap scripts named one by one and category-checked; no `-sC`, `-A`,
      `http-enum`, `http-default-accounts` or `exploit`-category scripts.
- [ ] Nothing sent after a T3, IIOP, P4, DIAG, RFC or Message Server greeting.
- [ ] Only `GET`/`HEAD` on named paths; no request bodies, no uploads, no
      expression or template payloads, no smuggling probes.
- [ ] Every version claim names its source and the vendor's patch unit, and is
      labelled unconfirmed where the patch level is invisible.
- [ ] KEV status and date taken from the catalog, not from memory; KEV hits
      escalated the same day.
- [ ] Component preconditions (RDS, Web ADI, Visual Composer, public signup)
      stated as seen or not seen.
- [ ] Every Stage B action has a logged written sign-off; default credentials
      tried once per account; nothing changed after login.
- [ ] Known webshell paths not requested; any sign of prior compromise handed
      to the client immediately.
- [ ] Tomcat Manager, JBoss consoles, AJP, RMI, SAProuter and smuggling handed
      to their owning skills rather than duplicated.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/sap-netweaver.md` | SAP port scheme (32NN/33NN/36NN/80NN/5NN00-5NN14), ICM, AS Java, Web Dispatcher, Message Server, Gateway, `sapstartsrv`; fingerprint paths; CVE matrix 2020-2026 with SAP Notes and KEV dates (RECON, ICMAD, Visual Composer, P4, 2026 kernel CVEs) | sap exposed, sap netweaver cve, cve-2025-31324, recon cve-2020-6287, icmad, sap p4 port, sap message server exposed, sap gateway internet, web dispatcher cve |
| `references/oracle-weblogic-and-apps.md` | WebLogic T3/IIOP/console fingerprint and CVE matrix through the September 2026 CSPU, Oracle HTTP Server proxy plug-in, E-Business Suite, PeopleSoft, Siebel, JD Edwards; Oracle CPU/CSPU/Alert cadence | weblogic t3 exposed, weblogic cve, cve-2020-14882, cve-2026-21962, oracle ebs cve-2025-61882, peoplesoft cve-2026-35273, siebel exposed, jd edwards exposed |
| `references/java-ee-servers.md` | WebSphere traditional and Liberty, JBoss EAP / WildFly management and remoting, GlassFish / Payara admin, Tomcat version gate | websphere exposed, websphere soap connector 8880, wildfly 9990, jboss remoting 4447, glassfish 4848, payara traversal, tomcat version cve |
| `references/coldfusion-liferay-pega.md` | ColdFusion admin and RDS exposure with APSB update levels, Liferay JSONWS and version header, Pega `prweb` and JMX | coldfusion exposed, cfide administrator, cve-2026-48282, coldfusion rds, liferay jsonws, liferay-portal header, pega prweb, pega jmx |
| `references/atlassian-data-center.md` | Confluence, Jira, Bitbucket, Bamboo DC: version endpoints, anonymous-access checks, CVE matrix with fixed versions and KEV dates, checks that are not read-only | confluence version, confluence cve-2023-22527, jira serverinfo, jira cve-2021-26086, bitbucket cve-2022-36804, bitbucket hazelcast 5701, bamboo exposed |

Primary sources (checked 2026-10-13): CISA KEV catalog version 2026.10.13
(<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>), NVD API 2.0
(<https://services.nvd.nist.gov/rest/json/cves/2.0>), CVE records
(<https://github.com/CVEProject/cvelistV5>), Oracle Security Alerts and CPU/CSPU
pages (<https://www.oracle.com/security-alerts/>), SAP Help port documentation,
Adobe APSB bulletins, Atlassian security advisories, Apache Tomcat security
pages, nmap 7.991 NSE sources and `nmap-service-probes`, HackerOne core
ineligible findings, Bugcrowd VRT.

---

## Related Skills & Chains

- `infra-external-methodology` — the port-to-skill routing this skill extends.
- `hunt-exposed-panels` — Tomcat Manager, JBoss consoles and other admin panels.
- `hunt-exposed-services` — AJP, RMI, JDWP, SAProuter, Oracle TNS and the generic
  Stage A/B model this skill follows.
- `hunt-deserialization`, `hunt-http-smuggling`, `hunt-ssti`, `hunt-rce` — the
  technique skills for the CVE classes here, each under its own Stage B.
- `hunt-auth-bypass`, `hunt-ntlm-info`, `hunt-api-misconfig` — native-login
  REST, NTLM metadata, SAP OData.
- `hunt-springboot`, `hunt-cicd` — adjacent Java and build-server surfaces.
- `offensive-osint` §16.16 — vendor fingerprint paths used during discovery.
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence,
  false-positive gates, write-up.

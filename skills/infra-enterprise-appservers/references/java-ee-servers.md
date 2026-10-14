# Java EE servers: WebSphere, JBoss EAP / WildFly, GlassFish / Payara, Tomcat version gate

Rule for every row: **a version gate, not an exploit.** A reachable listener
plus a version inside a listed range is "reachable, version in range,
unconfirmed" until the client confirms the fix level. Nothing in this file
sends a serialized object, an IIOP or remoting message, a SOAP envelope, a
`PUT`, an upload or a credential.

Owned elsewhere, cross-reference only:

| Topic | Owner |
|---|---|
| Tomcat Manager (`/manager/html`, `/manager/text`), host-manager, JBoss `jmx-console`, `web-console`, `/invoker/*`, CVE-2017-12149, the CVE-2025-24813 write test | `hunt-exposed-panels` (`references/java-app-servers.md`) |
| AJP 8009 and Ghostcat CVE-2020-1938, Java RMI registry 1099, JDWP | `hunt-exposed-services` (`references/remote-debug.md`) |
| Gadget chains, ysoserial-style payloads, any deserialization proof | `hunt-deserialization` (Stage B there) |
| Spring Boot actuators on the same Tomcat | `hunt-springboot` |
| Request smuggling technique (WebSphere CVE-2026-8646, CVE-2026-11541) | `hunt-http-smuggling` |

---

## IBM WebSphere Application Server (traditional) and WebSphere Liberty

### Ports (defaults; profiles and `portbase` shift them)

| Port | Service | Where it should be reachable from |
|---|---|---|
| 9060 / 9043 | Administrative console HTTP / HTTPS (`/ibm/console/`) | Administrators only |
| 9080 / 9443 | Application HTTP / HTTPS transport (traditional and Liberty) | Internet only through IHS or a reverse proxy |
| 8880 | SOAP JMX connector of a standalone server or node (deployment manager: 8879, verify) | Cell members and admin hosts only |
| 2809 | Bootstrap / naming (IIOP) (deployment manager: 9809, verify) | Internal |
| 9100 | ORB listener (verify) | Internal |
| 9402 / 9403 | CSIv2 SSL (IIOP over TLS) (verify) | Internal |
| 7276 / 7286 | Service integration bus (verify) | Internal |

Liberty has no 9060/8880 by default: administration is the `adminCenter-1.0`
feature (`/adminCenter/`) and the `restConnector-2.0` JMX REST connector
(`/IBMJMXConnectorREST`, verify) on the normal HTTPS port, both only when the
feature is in `server.xml`.

**Exposure is the first finding.** 8880, 2809, 9100 and the CSIv2 ports carry
serialized Java objects. Every pre-auth WebSphere RCE below lands on one of
them. Report the open port with its nmap fingerprint before version work.

### Stage A fingerprint

```bash
T="was.client.example"; mkdir -p evidence
# nmap-service-probes matches "WebSphere Application Server/<version>" on HTTP.
# giop-info (default, discovery, safe) reads the ORB's GIOP reply; no object sent.
nmap -Pn -sV --version-intensity 5 --scan-delay 2s \
  -p 2809,8879,8880,9043,9060,9080,9100,9443,9809 \
  --script giop-info,ssl-cert "$T" -oN "evidence/${T}_websphere_nmap.txt"
```

```bash
# One GET per path, 2 s apart. Headers only.
for U in "https://$T:9043/ibm/console/" "http://$T:9060/ibm/console/" \
         "https://$T:9443/" "https://$T:9443/adminCenter/" "https://$T:9443/IBMJMXConnectorREST"; do
  printf '%s  ' "$U"
  curl -sk -m 15 -o /dev/null -D - "$U" | grep -i -E '^(HTTP/|server:|location:|www-authenticate:)' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_websphere_http.txt"
```

| Signal | Meaning |
|---|---|
| `Server: WebSphere Application Server/9.0` (or 8.5) | Traditional WAS; the header carries the major line only, never the fix pack. |
| `/ibm/console/` redirects to `logon.jsp` (verify the path per release) | Admin console reachable. High on exposure alone; CVE-2026-14446 targets it. |
| `/adminCenter/` answers with the Liberty login | Liberty `adminCenter-1.0` enabled (CVE-2026-11546 precondition, authenticated). |
| `/IBMJMXConnectorREST` returns `401` | Liberty JMX REST connector enabled. Reachability is the finding; never authenticate. |
| `giop-info` returns object keys or a GIOP reply on 2809/9100 | IIOP reachable: precondition for the deserialization rows. |
| 8880 accepts TCP and nmap names a SOAP/HTTP service | SOAP connector exposed. Do not post a SOAP envelope to it. |

The fix pack (for example 9.0.5.x) is not visible from outside. Ask the client
for `versionInfo.sh` output (traditional) or `productInfo version` (Liberty)
and the list of installed interim fixes.

### CVE matrix 2020-2026 (unauthenticated or near-unauthenticated)

IBM fixes by interim fix (iFix) and fix pack, named in the security bulletin
(`ibm.com/support/pages/node/<id>`). The bulletin node, not a version string,
is what the client confirms. CVSS is the CNA (IBM) score. KEV: none of these
is in the CISA catalog 2026.10.13; the only WebSphere entry there is
CVE-2015-7450 (added 2022-01-10).

| CVE | Component, reach | Pre-auth | Affected (CNA record) | Fix (bulletin) | KEV |
|---|---|---|---|---|---|
| CVE-2020-4450 | Deserialization over IIOP (ZDI-20-689) | Yes, 9.8 | Traditional 8.5, 9.0 | node 6220294 | No |
| CVE-2020-4448 | Deserialization, Network Deployment (ZDI-20-688) | Yes, 9.8 | ND 7.0, 8.0, 8.5, 9.0 | node 6220336 | No |
| CVE-2020-4464 | Deserialization over the SOAP connector (8880) | **No**, PR:L, 8.8 | 7.0, 8.0, 8.5, 9.0 | node 6250059 | No |
| CVE-2020-4589 | Deserialization from untrusted sources | Yes, 8.1 (AC:H) | 7.0, 8.0, 8.5, 9.0 | node 6258333 | No |
| CVE-2023-23477 | Deserialization | Yes, 8.1 (AC:H) | Traditional 8.5, 9.0 | node 6891111 | No |
| CVE-2025-36038 | Deserialization | Yes, 9.0 (AC:H) | 8.5, 9.0 | node 7237967 | No |
| CVE-2026-8633 | Web Server Plug-ins (IHS / Apache / IIS plug-in in front of WAS and Liberty), crafted request | Yes, 9.8 | Plug-ins 8.5, 9.0 | node 7274072 | No |
| CVE-2026-14512 | Pre-authentication deserialization: auth bypass or RCE | Yes, 9.8 | Traditional 8.5, 9.0 | node 7281649 | No |
| CVE-2026-14446 | Admin console broken access control / privilege escalation | Yes per vector, 9.8 | 8.5, 9.0 | node 7281631 | No |
| CVE-2026-14974 | Deserialization | Yes, 8.1 (AC:H) | Traditional 8.5, 9.0 | node 7281641 | No |
| CVE-2026-16184 | Authentication bypass, crafted request | Yes, 7.0 (AC:H) | 8.5, 9.0 | node 7281628 | No |
| CVE-2026-14525 | Liberty `rtcomm-1.0` / `rtcommGateway-1.0` auth bypass | Yes, 9.4 | Liberty 17.0.0.3 to 26.0.0.8 | node 7283488 | No |
| CVE-2026-14976 | Liberty `collectiveController-1.0` RCE | AV:A, UI:R, 7.1 | Liberty 17.0.0.3 to 26.0.0.8 | node 7281633 | No |
| CVE-2026-11546 | Liberty `adminCenter-1.0` SSRF | **No**, PR:L, 7.1 | Liberty 17.0.0.3 to 26.0.0.7 | node 7278572 | No |
| CVE-2026-8646, CVE-2026-11541 | Request smuggling, traditional and Liberty | Yes, 7.4 (AC:H) | 8.5, 9.0; Liberty 17.0.0.3 to 26.0.0.6 | nodes 7276579, 7281750 | No |

How to read it externally: the July 2026 bulletins (CVE-2026-14512, 14446,
14974, 16184) cover every supported traditional line. A traditional WAS whose
console or IIOP ports answer from the internet is reportable on exposure, and
"no evidence of the July 2026 iFixes" is the version-gate line. Liberty rows
apply only when the named feature is enabled; ask for `server.xml`.

---

## Red Hat JBoss EAP and WildFly

### Ports (defaults)

| Port | Service | Where it should be reachable from |
|---|---|---|
| 8080 / 8443 | HTTP / HTTPS (Undertow); in EAP 7+ and WildFly 8+ remoting and EJB also ride 8080 via HTTP Upgrade | Internet through a proxy |
| 9990 / 9993 | HTTP management: HAL console `/console`, management API `/management` | Bound to 127.0.0.1 by default (`jboss.bind.address.management`); an internet-reachable 9990 is a configuration change |
| 9999 | Native management (EAP 6 and AS 7; later only if configured, verify) | Localhost |
| 4447 | Remoting (EAP 6 and AS 7; EJB remote, JNDI) | Internal |
| 8009 | AJP | See `hunt-exposed-services` `remote-debug.md` |

### Stage A fingerprint

```bash
T="jboss.client.example"; mkdir -p evidence
# nmap-service-probes has a jboss-remoting match for 4447/9999.
nmap -Pn -sV --version-intensity 5 --scan-delay 2s -p 4447,8080,8443,9990,9993,9999 \
  "$T" -oN "evidence/${T}_jboss_nmap.txt"
for U in "http://$T:9990/management" "http://$T:9990/console" "http://$T:8080/"; do
  printf '%s  ' "$U"
  curl -sk -m 15 -o /dev/null -D - "$U" | grep -i -E '^(HTTP/|server:|x-powered-by:|location:|www-authenticate:)' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_jboss_http.txt"
```

| Signal | Meaning |
|---|---|
| `/management` returns `401` with `WWW-Authenticate: Digest realm="ManagementRealm"` | Management API reachable and requiring a login. High on exposure; the realm name confirms JBoss/WildFly. |
| `/management` returns `200` with JSON and no `401` | Management API open without authentication. Critical; stop at that one response and report. |
| `/console` serves HAL | Admin console reachable. Same severity logic as above. |
| `Server: WildFly/NN` or `X-Powered-By: Undertow/1` | Older WildFly defaults; current releases omit or genericise these (verify per release). |
| nmap `jboss-remoting` on 4447 or 9999 | Remoting or native management exposed. Never open a remoting channel. |

### CVEs

An NVD keyword search (2026-10-13, 2020 onward, CVSS 8.8+ or KEV) for
"WildFly" and "JBoss Enterprise Application Platform" returned no pre-auth,
no-interaction CVE in the server itself. Treat the exposed management and
remoting ports as the finding.

| CVE | What | Pre-auth | Fix | KEV |
|---|---|---|---|---|
| CVE-2025-12543 | Undertow does not validate the `Host` header: cache poisoning, internal scanning, session hijack | Yes, but UI:R (CNA 9.6) | EAP 7.4.24; EAP 8.0.12 and 8.1.3 per NVD CPE ranges (verify against RHSA-2026:0383 and following); WildFly per its Undertow upgrade (verify) | No |
| CVE-2026-41939 | Not WildFly itself: a vendor appliance (Care Everywhere Gateway 14.3.10) bundles WildFly 8.2.0.Final with identical default management credentials | Yes, 9.8 | Vendor update | No |

The JBoss server entries in KEV (CVE-2010-0738, CVE-2010-1428,
CVE-2017-12149) are pre-2020 JBoss AS 4-6 console and invoker issues owned by
`hunt-exposed-panels`. The framework entries, JBoss Seam 2 CVE-2010-1871 (added
2021-12-10) and RichFaces CVE-2018-14667 (added 2023-09-28), live in the
deployed application, not the server: route them to `hunt-rce` /
`hunt-deserialization` when the application shows Seam or RichFaces. Default management credentials on an appliance
(the CVE-2026-41939 pattern) are a Stage B single attempt, never a list.

---

## Eclipse GlassFish and Payara

### Ports (GlassFish Administration Guide, `create-domain` output)

| Port | Service |
|---|---|
| 4848 | DAS administration: admin console and REST admin (`/management/domain`) |
| 8080 / 8181 | HTTP / HTTPS listener (8181 for the default domain1; the guide's example also shows 8081, verify) |
| 3700, 3820, 3920 | IIOP, IIOP over SSL, IIOP mutual auth |
| 8686 | JMX admin |
| 7676 | JMS (OpenMQ broker) |

The guide states the installer default login is `admin` with **no password**.
Remote administration is refused unless secure admin is enabled
(`enable-secure-admin`), so an empty password is usually only reachable from
the host itself (verify per release). Payara uses the same layout plus
Hazelcast clustering ports (verify); Payara Micro serves 8080 only by default
(verify).

### Stage A fingerprint

```bash
T="gf.client.example"; mkdir -p evidence
nmap -Pn -sV --version-intensity 5 --scan-delay 2s -p 3700,4848,7676,8080,8181,8686 \
  --script giop-info,ssl-cert "$T" -oN "evidence/${T}_glassfish_nmap.txt"
for U in "https://$T:4848/" "https://$T:4848/management/domain" "http://$T:8080/"; do
  printf '%s  ' "$U"
  curl -sk -m 15 -o /dev/null -D - -H 'Accept: application/json' "$U" \
    | grep -i -E '^(HTTP/|server:|x-powered-by:|location:|www-authenticate:)' | tr '\r\n' '  '
  echo; sleep 2
done | tee "evidence/${T}_glassfish_http.txt"
```

| Signal | Meaning |
|---|---|
| `Server:` / `X-Powered-By:` naming GlassFish Server Open Source Edition, Eclipse GlassFish or Payara Server with a version | Product and release line (verify the exact header format per release). |
| 4848 serves the console login | DAS reachable from the internet. High on exposure alone. |
| `/management/domain` returns `401` | REST admin reachable, password set. |
| `/management/domain` returns `200` JSON without any credential | Admin has no password and remote admin is open. Critical; that single response is the proof. Do not call any command resource. |
| 3700 / 7676 answer | IIOP or OpenMQ exposed: preconditions for CVE-2023-5763, CVE-2023-28462, CVE-2026-24457. |

### CVE matrix 2020-2026

None of these is in KEV (catalog 2026.10.13). CNA scores where the CNA gave
one, otherwise NVD.

| CVE | Product, reach | Pre-auth | Affected | Fixed in | KEV |
|---|---|---|---|---|---|
| CVE-2021-41381 | Payara Micro directory traversal | Yes | Micro Community 5.2021.6 and earlier | Next Community release (verify) | No |
| CVE-2022-37422 | Payara directory traversal (Server, Micro, Embedded) | Yes | Through 5.2022.2 | 5.2022.3 (verify) | No |
| CVE-2022-45129 | Payara, app on the root context exposes `META-INF` / `WEB-INF` | Yes | Community before 4.1.2.191.38, 5.2022.4, 6.2022.1; Enterprise before 5.45.0 | Those versions | No |
| CVE-2023-28462 | Payara JNDI rebind via the default ORB listener | Yes (NVD 9.8) | Enterprise 4.1.2.191, 5.20.0+; Community 5.2020.1+; **only on Java 8u181 or older** | Update the JDK (Payara blog) | No |
| CVE-2023-5763 | GlassFish 5 / 6 insecure ORB listeners on old JDKs | Yes, UI:R (CNA 6.8, NVD 9.8) | GlassFish 5 and 6 (record: 5.0 to below 5.1, 6.0.0 to below 6.2.5) on JDK below 6u211, 7u201 or 8u191 | Current JDK, secure ORB | No |
| CVE-2024-9408 | GlassFish SSRF in specific endpoints | Yes (CNA 8.9 v4.0, AC:H) | Since 6.2.5 | Not stated in the record (verify) | No |
| CVE-2024-9342 | GlassFish admin login has no brute-force limit | Yes (CNA 6.3) | Before 8.0.3 (5.1.0, 6.x, 7.x, 8.0.0 to 8.0.2) | 8.0.3 | No |
| CVE-2026-24457 | OpenMQ configuration parsing: arbitrary file read, RCE in some setups | Yes (CNA 9.1) | OpenMQ below 6.5.2 and 6.6.0 to below 6.9.0; GlassFish below 7.0.26, 7.1.0, 8.0.0 to 8.0.1 | GlassFish 7.0.26, 7.1.1, 8.0.2 | No |
| CVE-2026-2587 | GlassFish gadget handler EL evaluation, RCE | Yes, UI:R (CNA 9.6) | 7.0.0 to 7.0.25, 7.1.0, 8.0.0 to 8.0.1 (5.1-6.2.5 unknown) | 7.0.26, 7.1.1, 8.0.2 | No |
| CVE-2026-12605 | GlassFish CSRF + SSRF leaks the admin REST token | Needs a logged-in admin victim (UI:R, CNA 9.6) | 8.0.0 to 8.0.3 | 8.0.4 | No |
| CVE-2026-2586 | GlassFish admin console OS command execution | **No**, PR:H | 7.0.0 to 7.0.25, 7.1.0, 8.0.0 to 8.0.1 | 7.0.26, 7.1.1, 8.0.2 | No |

---

## Apache Tomcat (version gate only)

Manager, host-manager and the CVE-2025-24813 write test belong to
`hunt-exposed-panels`; AJP belongs to `remote-debug.md`. What stays here is
reading the version and mapping it to the rows below.

```bash
# The default error page footer prints "Apache Tomcat/<version>" unless the
# ErrorReportValve has showServerInfo="false". One GET to a path that cannot exist.
curl -sk -m 15 "https://tomcat.client.example/cbh-404-check" | grep -o -E 'Apache Tomcat/[0-9.]+' | head -1
```

| CVE | Precondition (all non-default) | Affected 9.0.x (10.1.x, 11.0.x) | Fixed | KEV |
|---|---|---|---|---|
| CVE-2024-50379, CVE-2024-56337 | Default servlet write-enabled (`readonly=false`) on a case-insensitive file system; 56337 also needs the JVM setting from the advisory | 9.0.0.M1 to 9.0.97 (10.1.33, 11.0.1) | 9.0.98, 10.1.34, 11.0.2 | No |
| CVE-2025-24813 | Write-enabled default servlet, partial `PUT` (default on), and for RCE file-based session persistence plus a gadget | 9.0.0.M1 to 9.0.98 (10.1.34, 11.0.2); 8.5.0 to 8.5.100 EOL | 9.0.99, 10.1.35, 11.0.3 | Yes, 2025-04-01 |
| CVE-2025-55752 | Rewrite rules that move query parameters into the URL; RCE only if `PUT` is also enabled | 9.0.0.M11 to 9.0.108 (10.1.44, 11.0.10) | 9.0.109, 10.1.45, 11.0.11 | No |
| CVE-2026-29146 | Cluster `EncryptInterceptor` in use (padding oracle) | 9.0.13 to 9.0.115 (10.0.0-M1 to 10.1.52, 11.0.0-M1 to 11.0.18) | 9.0.116, 10.1.53, 11.0.19 | No |
| CVE-2026-34486 | `EncryptInterceptor` bypass introduced by the 29146 fix | Exactly 9.0.116, 10.1.53, 11.0.20 per the CNA record (verify the 11.0.x line) | 9.0.117, 10.1.54, 11.0.21 | Yes, 2026-08-04 |

Older Tomcat KEV entries: CVE-2017-12615 and CVE-2017-12617 (`PUT` JSP
upload, added 2022-03-25; test owned by `hunt-exposed-panels`), CVE-2016-8735
(JMX remote listener, 2023-05-12; JMX transport owned by `remote-debug.md`),
CVE-2020-1938 (AJP, `remote-debug.md`).

Every Tomcat row needs a non-default configuration. A version in range is
"version in range, precondition unknown" unless the client confirms the
setting. The two EncryptInterceptor rows matter only when the Tribes cluster
receiver is reachable, which on the internet is a finding in itself (cluster
receiver port 4000 by default, verify).

---

## Stage B (written sign-off naming host, port, action and window)

| Action | Blast radius to name |
|---|---|
| One login to a WebSphere console, JBoss/WildFly management, GlassFish/Payara DAS or Liberty adminCenter with credentials the client supplied | Failed logins may lock the account (WAS and GlassFish 8.0.3+ lockout, verify per product). One attempt, named account. |
| One default-credential attempt on an appliance that bundles one of these servers | Same lockout risk; the vendor's documented default only, once. |
| Any management API call beyond the Stage A `GET` (JBoss `/management` operations, GlassFish REST command resources, Liberty JMX REST) | Many operations deploy, undeploy, restart or reconfigure. Read operations only, each named in the sign-off. |
| Any IIOP, remoting, SOAP-connector or JMX message | Deserialization surface. Not done in this bundle: `hunt-deserialization` owns proofs. |
| Request smuggling probes (WebSphere CVE-2026-8646, CVE-2026-11541) | Desync serves one user's response to another. `hunt-http-smuggling`, test instance only. |
| Any `PUT`, upload, deploy or WAR/EAR push | The exploit itself. Never. |

## What is not a finding

- `Server: WebSphere Application Server/9.0` or an `Apache Tomcat/9.0.x`
  error-page footer with no reachable CVE precondition: version disclosure.
- A management port that answers `401` only from the client's own admin
  range you were given for testing (check where you are scanning from).
- A Tomcat version in range for CVE-2025-24813 with no evidence of a
  write-enabled default servlet. Report as a patch item, not as RCE.
- Liberty CVE rows when the named feature is not in `server.xml`.

Sources (checked 2026-10-13): CVE records via
<https://github.com/CVEProject/cvelistV5> (IBM bulletin nodes, Red Hat errata,
Eclipse GitLab CVE issues, Apache mailing-list announcements), NVD keyword
queries, CISA KEV catalog 2026.10.13, Eclipse GlassFish Administration Guide
(<https://glassfish.org/docs/latest/administration-guide.html>, default ports
and default login), Apache Tomcat security pages
(<https://tomcat.apache.org/security-9.html>), Payara blog posts referenced by
the CVE records, nmap 7.991 `nmap-service-probes` and NSE categories.

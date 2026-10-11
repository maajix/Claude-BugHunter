---
name: hunt-exposed-panels
description: "Triage internet-exposed HTTP admin, monitoring and infrastructure-tooling panels: an enterprise web console answering from the public internet that belonged behind a VPN. Fingerprint the product and version first, then route to default credentials, unauthenticated endpoints, information disclosure and pre-auth CVEs. Covers Zabbix, Grafana, Prometheus, Netdata, JBoss/WildFly (jmx-console, web-console, JMXInvokerServlet), Tomcat Manager, phpMyAdmin, Adminer, Jupyter, Apache Spark UI, Flink JobManager, Airflow, JFrog Artifactory, Consul, Nomad, Portainer, MeshCentral, ServiceNow public data exposure, and the nginx alias off-by-slash traversal that fronts them. Stage A read-only by default; deploy, write, execute and config-change probes gated on written sign-off. Default-credential attempts capped at one pair per account. Use when an HTTP service on an in-scope external host is clearly an internal admin tool. Non-HTTP ports belong to hunt-exposed-services; CI/CD to hunt-cicd."
sources: hacktricks_coverage_checklist, nvd, vendor_documentation, vendor_advisories, github_security_advisories, researcher_writeups, gixy, authorized-engagement
report_count: 0
---

## When to use

Trigger when recon has produced an **HTTP service on an in-scope external host
that is clearly an internal tool**: a monitoring dashboard, a database admin UI,
an application-server console, a container manager, an artifact repository, a
notebook server. The finding is the exposure plus what it leaks or grants, and
the job is to identify the product and version fast, then route to the four
things that actually pay: default credentials, unauthenticated endpoints,
information disclosure, and pre-auth CVEs.

Use when any of these is true:

- A web root, a virtual host or a reverse-proxy prefix renders a login page for
  an infrastructure product rather than for the client's own application.
- A TLS certificate, reverse-DNS name or page title names one of the products in
  the Step 3 routing table.
- An HTTP port outside 80/443 answers on a public address: 3000, 4040, 8080,
  8081, 8888, 9090, 9443, 19999.
- The client's asset inventory says "internal only" and you can reach it anyway,
  or a VPN or firewall migration is suspected to have left a console open.

**This skill is not for discovery.** Host, port, subdomain and prefix discovery
belong to `offensive-osint`, `web2-recon` and `hunt-subdomain`; scope
confirmation belongs to `recon-scope-triage`. This skill starts from "an HTTP
admin panel answers and is in scope".

**Structure note:** this file follows the numbered-step shape of
`vmware-vcenter-attack` and its sibling `hunt-exposed-services`, not the
11-section `hunt-*` order. The content is a triage sequence — fingerprint, then
route — and the sibling skill that owns the non-HTTP half of this surface
already uses that shape, so the pair reads consistently.

### Where the chain ends

This skill stops at **access confirmed, privilege level demonstrated, impact
described, evidence captured**. It contains nothing about what you do once you
are inside a panel: no OS privilege escalation, no lateral movement into the
hosts a monitoring server watches, no Active Directory, no credential dumping,
no persistence, no C2, no evasion.

Three concrete cuts, because the usual public write-ups walk straight past them:

- **Zabbix and Grafana:** the source material for both continues into reverse
  shells and pivoting through monitored hosts. Stop at the administrative
  session.
- **MeshCentral:** remote-controlling an enrolled endpoint is lateral movement.
  Stop at the exposed management plane and the enrolled-device count.
- **Tomcat Manager, JBoss invoker, Jupyter kernels, Airflow DAGs, Portainer
  containers:** each is code execution by design. Proving you hold the privilege
  is the finding; using it is Stage B and usually unnecessary.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| Any non-HTTP port: Elasticsearch 9200, Kibana 5601, RabbitMQ management 15672, Redis, MongoDB, `splunkd` 8089, Hadoop 9870/8088, AJP 8009 Ghostcat, IPMI, SNMP, JDWP, VNC, printers, ICS | `hunt-exposed-services` |
| Jenkins, GitLab CI, TeamCity, Drone, Argo, GitHub Actions | `hunt-cicd` |
| Kubernetes API, kubelet, etcd, Kubernetes Dashboard, `docker.sock`, container escape | `hunt-k8s` |
| Spring Boot Actuator, Jolokia, H2 console, Spring4Shell | `hunt-springboot` |
| WordPress, Drupal, Joomla, Moodle, PrestaShop, Roundcube, Bolt, and groupware generally | `hunt-cms` |
| vCenter, ESXi, Workspace ONE | `vmware-vcenter-attack` |
| SSL VPN and remote-access gateways, including Fortinet products | `enterprise-vpn-attack` |
| SharePoint, ASP.NET/Webforms surface | `hunt-sharepoint`, `hunt-aspnet` |
| Cloud-managed service exposure, public buckets, IMDS | `hunt-cloud-misconfig` |
| The generic vulnerability classes themselves | `hunt-sqli`, `hunt-lfi`, `hunt-rce`, `hunt-deserialization`, `hunt-auth-bypass`, `hunt-ssrf` |

This skill's contribution to the generic classes is the product-specific route
to them: which path, which parameter, which version.

---

## Step 1 — Inherit the host list and hold the rate posture

Take the hosts and prefixes from the signed scope document and the recon phase.
Never generate them here, never scan address space the client does not own, and
never mass-scan: there is no step in this skill that sweeps a range.

Every looping step below is serial, one host at a time, with jitter:

```bash
# 2s base delay + 0-3s jitter between probes. One host at a time.
# ServiceNow and any vendor-hosted SaaS: raise the base delay to 10s (Step 3).
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

A timeout is a result. Retry once at most, and never tighten the delay to get
through a list faster. Several products here are single-process Python or Node
services where a retry storm is a denial of service with extra steps.

---

## Step 2 — Prove the panel is external, the client's, and real

Four false-positive classes kill more of these findings than any technical
mistake. Clear all four before writing a word.

| Check | How | Why |
|---|---|---|
| External vantage | Probe from a host outside every client VPN, tunnel and office range. Record the egress IP in evidence. | "Exposed" means exposed. A panel reached over the client's own VPN is not a finding. |
| Ownership | ASN plus WHOIS/RDAP plus reverse DNS per address, cross-checked against the scope document. For SaaS, the scope must name the **tenant**. | Shared hosting and CDN edges answer for addresses that are not in scope. |
| Not a decoy | A console that accepts any credential, implausible version strings, every path returning `200`. | Admin-panel honeypots are cheap and common. |
| Not the client's own public service | Some products are deliberately public: a status page, a public Grafana, a public knowledge base. | Check the client's intent before grading. A deliberately public dashboard with no sensitive data is not a finding. |

Save the raw baseline response for every probe at probe time. Step 4's and Step
6's confirmation gates both diff against it, and a baseline reconstructed later
is not evidence.

---

## Step 3 — Fingerprint the product and version, then route

This is the step that makes the skill fast. Identify the product from a
read-only response, then load **one** reference file. Do not read all five.

```bash
TARGET="target.example"

# Stage A — read-only. Title, server header and generator in one pass.
curl -s -m 15 -D - "https://${TARGET}/" -o /tmp/panel.html \
  | grep -i -E '^(HTTP/|Server:|X-Powered-By:|WWW-Authenticate:|Set-Cookie:)'
grep -o -i -m1 '<title>[^<]*</title>' /tmp/panel.html
```

Then the product's own unauthenticated version oracle, which is faster and more
exact than a banner:

| Product | Read-only version probe | Load |
|---|---|---|
| Zabbix | `POST api_jsonrpc.php` with method `apiinfo.version` (documented as available **only** to unauthenticated users) | `references/monitoring-and-dashboards.md` |
| Grafana | `GET /api/health` → `version`, `commit`, `database`. Default port 3000 | `references/monitoring-and-dashboards.md` |
| Prometheus | `GET /api/v1/status/buildinfo`. Default port 9090 | `references/monitoring-and-dashboards.md` |
| Netdata | `GET /` on port 19999 | `references/monitoring-and-dashboards.md` |
| JBoss / WildFly | `GET /jmx-console/`, `/web-console/`, `/invoker/JMXInvokerServlet` | `references/java-app-servers.md` |
| Tomcat Manager | `GET /manager/html` → `401` with the Basic realm | `references/java-app-servers.md` |
| phpMyAdmin | `PMA_VERSION` in the login page source | `references/data-and-notebook-tools.md` |
| Adminer | Version in the page footer at `/adminer.php` | `references/data-and-notebook-tools.md` |
| Jupyter | `GET /api/` returns the version and is documented as needing no authentication | `references/data-and-notebook-tools.md` |
| Spark UI | `GET /api/v1/applications` on port 4040 | `references/data-and-notebook-tools.md` |
| Flink | `GET /jobmanager/config` on port 8081 (`rest.port`) | `references/data-and-notebook-tools.md` |
| Airflow | `GET /api/v2/version`, port 8080 (`[api] port`) | `references/data-and-notebook-tools.md` |
| Artifactory | `GET /artifactory/api/system/version` (security requirement is a valid user, which **may be anonymous**) | `references/devops-and-orchestration.md` |
| Consul | `GET /v1/agent/self` on port 8500 | `references/devops-and-orchestration.md` |
| Nomad | `GET /v1/agent/self` on port 4646 | `references/devops-and-orchestration.md` |
| Portainer | `GET /api/system/status` and `GET /api/users/admin/check` on port 9443 (both public routes in Portainer's own router) | `references/devops-and-orchestration.md` |
| MeshCentral | Login page on 80/443; agent endpoint `/agent.ashx` | `references/devops-and-orchestration.md` |
| ServiceNow | Instance login page; `/api/now/sp/widget/{id}`, `/api/now/table/{table}` | `references/saas-and-proxy-exposure.md` |
| Any proxied prefix serving static files | Off-by-slash probe on the prefix | `references/saas-and-proxy-exposure.md` |

If the product is not in the table, fingerprint it as an unknown internal tool
and describe the exposure generically. **Do not invent product specifics** — no
guessed paths, no guessed default credentials, no CVE you have not read.

ServiceNow is vendor-hosted SaaS and carries extra rules before the first
request: the scope must name the tenant, the probe count must be small, and the
base delay rises to 10 seconds. Read that section before touching it.

---

## Step 4 — Stage A: unauthenticated endpoints and information disclosure

**Stage A is the default and covers almost every finding in this skill.** A
Stage A probe must satisfy all four:

1. It only reads. No deploy, write, delete, execute, submit, reconfigure or
   restart.
2. It is a single request per endpoint, not a loop over credentials or IDs.
3. Its failure mode is a timeout or an error reply, never a service restart.
4. It leaves no artefact behind: no created user, no queued job, no running
   kernel, no planted file, no claimed instance.

The generic sweep, before anything product-specific: request the product's own
status, config, version and listing endpoints from the reference file, serially,
and record each status code with the first bytes of the body.

Two confirmation gates apply to everything in Stage A:

- **A `200` is not access.** A `200` carrying a login page, an SSO redirect or a
  WAF block page is the opposite of a finding. Access is a `200` carrying the
  product's own structured data: a JSON array of sessions, a table of deployed
  contexts, a list of scrape targets, a directory listing.
- **A file read is confirmed by content, never by status code.** Aim traversal
  at a file whose content you can predict, require a match on a distinctive
  pattern (`^root:[^:]*:0:0:` for `/etc/passwd`), and diff the body against the
  Step 2 baseline. A status-code difference between path variants is a reason to
  keep probing, not a finding.

Read one predictable, non-sensitive file to prove a traversal primitive, then
**name** what else would be readable instead of reading it. Pulling the
credential store converts a clean finding into data you are now responsible for.

---

## Step 5 — Default credentials, capped and logged

Only the **vendor-documented** default pair, never a wordlist. Credential
guessing beyond this is `hunt-brute-force`'s territory and needs its own
authorisation.

**The cap: one attempt per account, at most two attempts per host, then stop.**
Stop immediately on any `429`, any lockout message, or any change in response
timing that suggests throttling.

| Product | Documented default | Lockout behaviour (vendor-documented) |
|---|---|---|
| Zabbix frontend | `Admin` / `zabbix` | After **5 consecutive failures** the interface pauses 30 s. A throttle, not a permanent lock. |
| Grafana | `admin` / `admin` (set on first run) | Brute-force protection **on by default**; `brute_force_login_protection_max_attempts` default **5**. |
| Artifactory (self-managed only) | `admin` / `password` | No vendor-published threshold. Assume a lockout exists; one attempt is the whole budget. |
| JBoss `/admin-console` (JBoss 5/6) | `admin` / `admin` | Not published. One attempt. |
| Tomcat Manager | **No vendor default** — no user is assigned the manager roles in the shipped `conf/tomcat-users.xml` | `LockOutRealm` defaults: `failureCount` **5**, `lockOutTime` **300 s**. Failures are recorded for **non-existent usernames too**; further failures during a lockout **reset the timer**; valid credentials during a lockout **do not succeed**. |
| Prometheus, Netdata, Spark, Flink, Consul, Nomad | None — these products ship with **no authentication layer**, so there is nothing to guess | n/a |

Read the Tomcat row twice. Because a lockout extends on every further attempt
and rejects correct credentials while active, a spray there locks the real
administrator out of their own console and silently breaks the engagement
credentials you were given. That is a client impact, not a test artefact.

Products that ship with no authentication at all change the finding's shape: the
root cause is not a weak password, it is a service with no authentication layer
placed on a public address. Say that in the report, because it changes the fix
from "rotate the credential" to "put it behind authentication".

---

## Step 6 — Stage B: anything that deploys, writes, executes or reconfigures

Stage B is **blocked by default**. It requires explicit written operator sign-off
naming the specific action, the specific host and a window. A verbal yes, a chat
thumbs-up, or "the scope says critical findings are in scope" is not sign-off.

Record this block in the engagement log before the first Stage B request:

```
Stage B authorization
  Host/path:        192.0.2.10:8080 /manager/text/list
  Action:           single authenticated manager listing (no deploy)
  Blast radius:     read-only against the servlet container; no artefact created
  Reversibility:    n/a
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

Always Stage B, with the blast radius you must name:

| Action | Blast radius |
|---|---|
| Tomcat Manager WAR deploy (`PUT /manager/text/deploy`) | Arbitrary code in the servlet container as the Tomcat user; a persistent context you must undeploy; an outage if the context path collides with a live application. |
| JBoss invoker gadget / MBean invocation | Code inside a live application-server JVM; a wrong gadget hangs or kills the application; `DeploymentFileRepository` writes a WAR to disk. |
| Jupyter kernel or terminal creation | Code as the notebook owner on a possibly shared analytics or GPU host; a kernel consumes memory until you delete it. |
| Airflow DAG trigger | Production code on worker nodes: may move data, call third-party APIs, spend money. |
| Portainer container create or `exec` | Arbitrary workload on the container host; a host bind-mount is host compromise. |
| Portainer initial-admin creation on an uninitialised instance | **Permanently claims the instance** and locks the rightful owner out. |
| phpMyAdmin or Adminer query execution | Arbitrary SQL against production data. |
| Consul KV write, service deregistration, Nomad job submission | Service discovery and scheduling: a deregistration takes the application out of rotation. |
| Flink CVE-2020-17518 arbitrary file write | A file planted anywhere the JobManager user can write, including over a Flink config file. |
| Tomcat CVE-2025-24813 partial `PUT` | A file in the web root that you must delete; a mis-scoped `PUT` overwrites an application file. |
| Prometheus admin API (`delete_series`, `clean_tombstones`) | **Destroys monitoring data. Never call these** — prove the flag from read-only `/api/v1/status/flags` instead. |
| Any credential guessing beyond Step 5's cap | Account lockout and log flooding; `hunt-brute-force`'s territory. |
| Any exploitation against vendor-hosted SaaS (ServiceNow) | A shared control plane and another company's infrastructure. Needs the platform vendor's testing policy, not only the client's sign-off. |

### The confirmed-RCE gate

A confirmed-RCE claim needs a **unique canary echoed back** plus a **body diff
against the Stage A baseline**. A plausible-looking `uid=` with no canary is a
WAF page, an error template or wishful reading.

```bash
# Stage A — baseline first. Keep it; Stage B diffs against it.
curl -sk -o /tmp/panel_baseline.txt -w '%{http_code}\n' "https://${TARGET}/<endpoint>"

# Stage B — ONLY with written RCE-attempt sign-off. Emit a unique canary so a
# coincidental error page containing command-like output cannot be mistaken
# for real execution.
CANARY="PNL$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# ... single product-specific request carrying: echo ${CANARY}; id ...

# Confirmed RCE ONLY if the response contains the exact $CANARY echoed back
# AND command output ("uid=") that is absent from /tmp/panel_baseline.txt.
# Then stop. Remove every artefact and record the removal.
```

---

## Step 7 — Grade on what you proved

| What you proved | Grade |
|---|---|
| Unauthenticated administrative access to a management plane controlling hosts, containers, fleets or builds (Portainer, MeshCentral, Zabbix admin, Artifactory write, Tomcat Manager) | Critical |
| Unauthenticated code execution by design (Jupyter kernels, Spark CVE-2022-33891 with ACLs on, JBoss invoker in range) | Critical |
| Unauthenticated read of production data or credentials (Prometheus `status/config` with `basic_auth` blocks, Consul KV key names under `prod`, Airflow with `expose_config`, exposed notebooks) | Critical to High |
| Default credentials accepted on a production panel | Critical or High, by what the account reaches |
| Confirmed file read via traversal (Grafana CVE-2021-43798, Flink CVE-2020-17519, nginx alias off-by-slash) | High |
| Unauthenticated access to a non-production panel holding real data | High |
| Internal topology disclosure: scrape targets, service catalog, job list, node names, internal addressing | Medium |
| Panel exposed, authentication enforced, version inside a CVE range | Medium, stated plainly as **not exploited** |
| ServiceNow `count_oracle`: record counts confirmed, no rows returned | Low to Medium, and **never** written up as record access |
| Version or banner disclosure only | Low to Informational |
| Panel exposed, authenticated, no reachable pre-auth issue | Informational, as a hardening item: it still belongs behind the VPN |

Two rules triage will hold you to: a version inside a CVE range is not a
confirmed vulnerability, and a precondition you did not verify (SAML enabled for
Zabbix CVE-2022-23131, `duckdb` on `$PATH` for Grafana CVE-2024-9264, writes
enabled for Tomcat CVE-2025-24813, ACLs enabled for Spark CVE-2022-33891)
downgrades the finding to patch hygiene.

---

## Step 8 — Capture evidence once, immutably

Follow `evidence-hygiene`. Minimum set per finding:

- The exact request and response with timestamps, saved at probe time, including
  the source IP you ran it from.
- Product and version exactly as returned, with the endpoint that returned it.
- The Step 2 baseline, so every diff-based confirmation can be re-checked.
- Impact proven by **counts and names**, never by the data: repository names and
  artefact counts, Consul KV key names with values withheld, record counts,
  field names, one redacted sample.
- For personal data (ServiceNow tables, attachments, Netdata process lines), a
  written note that nothing was retained.
- For any Stage B action, the sign-off reference plus proof the artefact was
  removed.

---

## Chain table

| Confirmed | Standalone severity | Where it goes next |
|---|---|---|
| Unauthenticated Portainer, MeshCentral or Tomcat Manager | Critical | Report. Container and host-escape mechanics are `hunt-k8s`'s, not yours. |
| Unauthenticated Jupyter with `/api/sessions` and `/api/contents/` | Critical | Report. No kernel creation. |
| Prometheus or Consul config/KV exposing credentials | Critical | Report the leak. Using the credential is a new authorisation question. |
| JBoss invoker reachable, version in a deserialisation CVE range | Critical | `hunt-deserialization` for gadget mechanics, under Stage B sign-off only. |
| Grafana, Flink or nginx-alias file read confirmed | High | `hunt-lfi` for what else is reachable; `hunt-source-leak` for recovered config. |
| Zabbix or Airflow SQLi reachable with a supplied account | High | `hunt-sqli` owns the injection; keep the version and method name here. |
| Adminer SSRF in range | Medium to High | `hunt-ssrf` owns the out-of-band confirmation gate. |
| ServiceNow widget or Table API returning rows | High to Critical by data class | Report with counts. `hunt-idor` for the authorisation model. |
| Default credentials accepted | Critical to High | Report with the account's visible privilege. Nothing further. |
| Panel exposed behind enforced authentication | Informational to Medium | Hardening finding: it belongs behind the VPN. |
| TLS or certificate weakness on any of these | Per `hunt-tls-network` | Separate finding, separate skill. |

---

## Validation checklist

- [ ] Probed from outside every client VPN, tunnel and office range; egress IP in
      the evidence.
- [ ] Every host confirmed client-owned by ASN plus WHOIS/RDAP and present in the
      signed scope; for SaaS, the tenant is named in the scope document.
- [ ] The product was identified from its own response, not from the port number.
- [ ] Decoy and deliberately-public cases ruled out.
- [ ] Access was proven by the product's own structured data, not by a `200` on a
      login page or an SSO redirect.
- [ ] Every file read was confirmed by predictable content plus a body diff
      against the saved baseline, never by a status code.
- [ ] `--path-as-is` was used for every traversal probe.
- [ ] Default-credential attempts stayed inside the cap: one pair per account, two
      per host, stop on any throttle signal. No wordlist.
- [ ] No Tomcat Manager spray (it extends the lockout and rejects valid logins).
- [ ] Every probe was Stage A, or has a logged written sign-off naming the host,
      the action and the blast radius.
- [ ] No deploy, job submission, kernel, container, query, KV write, admin-API
      call or initial-admin creation.
- [ ] Every RCE claim carries a unique canary echoed back plus a baseline diff.
- [ ] Every Stage B artefact was removed, and the removal is evidenced.
- [ ] No dataset copied. Impact is evidenced by counts and names.
- [ ] Unverified CVE preconditions are stated as unverified, and version-in-range
      findings are labelled not exploited.
- [ ] The report ends at exposure plus impact. No internal follow-up written.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `monitoring-and-dashboards.md` | Zabbix frontend and API (CVE-2022-23131, CVE-2024-42327, CVE-2024-22120), Grafana (CVE-2021-43798, CVE-2024-9264), Prometheus 9090 status and admin API, Netdata 19999 | exposed zabbix, zabbix apiinfo version, zabbix admin zabbix, grafana path traversal, grafana public plugins, grafana admin admin, grafana api health, exposed prometheus, prometheus status config leak, prometheus targets internal hosts, netdata 19999 exposed |
| `java-app-servers.md` | JBoss / EAP / WildFly (`jmx-console`, `web-console`, `EJBInvokerServlet`, `JMXInvokerServlet`, `admin-console`; CVE-2010-0738, CVE-2015-7501, CVE-2017-12149), Tomcat Manager (`/manager/html`, `/manager/text`, `jmxproxy`, `host-manager`; LockOutRealm; CVE-2025-24813) | exposed jmx-console, jboss invoker servlet, jmxinvokerservlet exposed, jboss verb bypass, wildfly management exposed, tomcat manager exposed, manager/html 401, tomcat war deploy, tomcat lockoutrealm, tomcat partial put |
| `data-and-notebook-tools.md` | phpMyAdmin (CVE-2018-12613, setup script), Adminer (CVE-2021-21311), Jupyter Server (`/api/`, sessions, kernels, terminals, contents), Spark UI 4040 (CVE-2022-33891), Flink 8081 (CVE-2020-17519, CVE-2020-17518), Airflow 8080 (`expose_config`, secret key) | exposed phpmyadmin, phpmyadmin 4.8 file inclusion, adminer exposed, adminer ssrf, jupyter no token, jupyter api kernels open, exposed spark ui, spark doas command injection, flink jobmanager traversal, exposed airflow, airflow expose_config |
| `devops-and-orchestration.md` | JFrog Artifactory (anonymous access, `api/system/version`, CVE-2026-42018, CVE-2026-69107), Consul 8500 (`default_policy` allow, KV), Nomad 4646, Portainer 9443 (setup token, 5-minute window), MeshCentral (ports, GHSA-c7hr-448w-65px) | exposed artifactory, artifactory anonymous access, artifactory admin password, exposed consul, consul kv secrets, consul catalog services, exposed nomad, portainer exposed, portainer initial admin, portainer setup token, meshcentral exposed |
| `saas-and-proxy-exposure.md` | ServiceNow public data exposure (`/api/now/sp/widget/{id}`, `/api/now/table/{table}`, count oracle, CVE-2024-4879, CVE-2024-5217), nginx `alias` off-by-slash traversal, `merge_slashes` posture | servicenow public data, servicenow widget api, servicenow table api sys_user, snowpick, nginx alias traversal, off-by-slash, alias lfi misconfiguration, merge_slashes off |

Attribution: the product coverage list was checked against the HackTricks
pentesting-web section (<https://github.com/HackTricks-wiki/hacktricks>,
CC BY-NC 4.0), used as a checklist only. All prose, tables, staging and safety
guidance here are original. Paths, ports, parameter names, default credentials,
version ranges and CVE identifiers were verified this session against NVD,
vendor documentation and advisories, GitHub Security Advisories, the Gixy
`alias_traversal` check documentation and the cited researcher write-up.

---

## Related Skills & Chains

- `hunt-exposed-services` — the **non-HTTP** half of this surface, and the owner
  of Elasticsearch, Kibana, RabbitMQ management, `splunkd`, Hadoop, AJP 8009 and
  every raw-port management plane. Same root cause, different protocol. If a
  product's exposure is a raw port, it belongs there.
- `offensive-osint`, `web2-recon`, `hunt-subdomain`, `recon-scope-triage` — they
  produce the input to Step 1; this skill does not re-teach discovery.
- `hunt-cicd` — Jenkins and every build server. `hunt-k8s` — Kubernetes,
  Dashboard, Docker. `hunt-springboot` — Actuator, Jolokia, H2.
- `hunt-cms` — WordPress, Drupal, Joomla, Moodle, PrestaShop, Roundcube, Bolt.
- `hunt-sqli`, `hunt-lfi`, `hunt-rce`, `hunt-deserialization`, `hunt-ssrf`,
  `hunt-auth-bypass`, `hunt-idor` — the generic classes. This skill routes to
  them with the product-specific path, parameter and version.
- `hunt-brute-force` — anything beyond Step 5's one-pair cap.
- `hunt-tls-network` — TLS and certificate findings on any of these ports.
- `hunt-source-leak` — notebooks, DAGs, job JARs and configuration files
  recovered through a traversal.
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence handling,
  the false-positive gate, and write-up.

---
name: infra-devops-platforms
description: "Triage internet-exposed DevOps control planes, secret stores, service discovery, artifact registries and source-control daemons: HashiCorp Vault 8200, Consul 8500, Nomad 4646, Jenkins agent port 50000, TeamCity 8111, GitLab, Gitea, Gerrit SSH 29418, git daemon 9418, Nexus, Artifactory, Harbor, Docker Registry 5000, SonarQube 9000, Drone, Argo CD, Argo Workflows, Portainer, Rancher. Version oracles, default auth posture, a KEV-tagged CVE matrix, GET-only checks; registering, pushing or executing is Stage B. Use when a scan or certificate shows one of these products."
metadata:
  sources: nvd, cisa_kev, vendor_advisories, vendor_documentation, project_source_code, github_security_advisories, bugcrowd_vrt
  report_count: 0
---

## When to use

Trigger when external recon has produced one of the products in the Step 3
table on a host you are authorized to test, and you need to decide whether
that exposure is a finding. These systems hold the keys to everything else:
secrets, service topology, build pipelines, signed artifacts and source code.
The finding is **the exposure plus what it leaks or grants**, graded on the
unauthenticated API surface and the product's version against the matrix in
`references/devops-cve-matrix.md`.

Use when any of these is true:

- A port from the Step 3 table answers on a public, client-owned address.
- A TLS certificate, page title, response header or SSH banner names Vault,
  Consul, Nomad, Jenkins, TeamCity, GitLab, Gitea, Gerrit, Nexus, Artifactory,
  Harbor, SonarQube, Argo, Rundeck, AWX or one of the others.
- A leaked config (`.npmrc`, `settings.xml`, `pip.conf`, `bootstrap.yml`, a
  Jenkinsfile, a Drone or Argo manifest) names a self-hosted DevOps host.
- The client says the build or secrets plane is "VPN only" and you can reach it.

**Do not use this skill for discovery.** Hosts, ports and subdomains come from
`offensive-osint` and `web2-recon`; scope confirmation from
`recon-scope-triage`. This skill starts from "the product answers and is in scope".

### Where the chain ends

This skill stops at **unauthenticated access or a version inside a known
exploited range confirmed, impact described, evidence captured**. Nothing here
runs after access: no secret values read, no job or pipeline run, no artifact
or image pulled or pushed, no repository cloned, no service registered, no
cluster joined, no instance initialised or claimed. Three cuts the public
write-ups walk straight past:

- **Vault:** stop at `seal-status` and `health`. An uninitialised Vault is a
  Critical finding *as a state*; running `init` claims it and hands you the
  root token and unseal keys of a production secret store.
- **Consul and Nomad:** stop at "ACL support disabled" plus names (services,
  nodes, jobs, KV key names). Job submission, `exec` and script checks are
  remote code execution across the fleet.
- **Registries and forges:** stop at names and counts. Pulling a layer,
  downloading an artifact or cloning a private repository makes you the breach.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| Jenkins web UI, `/script`, CLI file read (CVE-2024-23897), GitHub Actions, GitLab CI runner tokens and pipeline variables, Terraform state files, pipeline secrets in logs | `hunt-cicd` |
| HTTP panel triage for Artifactory, Consul (`/v1/agent/self`, catalog, KV key names), Nomad (`/v1/jobs`), Portainer (`/api/users/admin/check`) and MeshCentral | `hunt-exposed-panels` `references/devops-and-orchestration.md`. This skill adds only their non-HTTP ports, ACL oracle and CVE rows. |
| Login-page fingerprinting of any web console, default-credential policy for HTTP panels | `hunt-exposed-panels` |
| Kubernetes API, kubelet, etcd, Docker API 2375/2376, container escape, Rancher-managed clusters | `hunt-k8s` |
| Spring Boot Actuator, `/env` and `/refresh`, Eureka client XStream gadget, Jolokia | `hunt-springboot` |
| Public package registries, dependency confusion, typosquats, public Docker Hub/GHCR/Quay.io images | `supply-chain-attack-recon` |
| SSH algorithm posture and OpenSSH CVEs on any port, including Gerrit 29418 and forge SSH | `infra-ssh` |
| TLS on any port | `hunt-tls-network` |
| Credential guessing of any kind | `hunt-brute-force` |
| Leaked tokens and keys for these products | `hunt-source-leak`, `cloud-iam-deep` |
| Mattermost and Rocket.Chat | Fingerprint rows only (Step 3). Their web surface goes to `hunt-exposed-panels` and the generic `hunt-*` classes. |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/secrets-and-discovery.md` | Vault 8200/8201 unauthenticated `sys/*`, redaction options, uninitialised state; Consul 8600 DNS and gossip/RPC ports, ACL oracle; Nomad 4647/4648; Eureka 8761; Spring Cloud Config key-name extraction | vault exposed, vault seal-status, consul dns 8600, consul acl disabled, nomad acl disabled, eureka apps exposed, spring cloud config exposed |
| `references/build-and-automation.md` | Jenkins agent port 50000 and `/tcpSlaveAgentListener/`; TeamCity; Drone `/version` and `/varz`; Argo CD; Argo Workflows auth modes; Rundeck; AWX `/api/v2/ping/`; Terraform Enterprise; SonarQube | jenkins 50000, jnlp port, teamcity exposed, drone varz, argocd settings, argo workflows auth-mode server, rundeck 4440, awx ping, sonarqube api exposed |
| `references/source-control.md` | GitLab self-managed, Gitea, Gogs, Forgejo, Gerrit 8080/29418, git daemon 9418, open registration | gitlab self-managed version, gitea api version, gogs exposed, gerrit 29418, git daemon 9418, git ls-remote |
| `references/artifact-registries.md` | Nexus, Harbor, Docker Registry v2 on 5000, Quay, Verdaccio, devpi; Artifactory cross-reference | nexus 8081, harbor systeminfo, docker registry catalog, registry v2 exposed, quay exposed, verdaccio 4873, devpi 3141 |
| `references/devops-cve-matrix.md` | 2021-2026 CVE matrix with KEV status and fixed versions for every product above; older KEV entries; client-side rows not to report | teamcity cve, gitlab kev, artifactory kev, gogs cve, gitea cve, vault cve, nexus cve, harbor cve, argo cd cve, kev devops |

---

## Step 1 — Inherit the host and port, hold the rate posture

Take hosts from the signed scope and ports from recon. Confirm IP ownership
(ASN, WHOIS/RDAP, reverse DNS) before the first request. Never sweep ranges.

Vendor SaaS is not the client's host: `gitlab.com`, `*.jfrog.io`,
`app.terraform.io`, `sonarcloud.io`, `quay.io`, Docker Hub and HCP-hosted Vault
or Consul answer for many tenants. Test only what the program scope names, at
the HTTP layer, with the tenant's own hostname. No port work against them.

### Rate posture

These are production control planes with login lockouts, audit logs that page
someone, and in Vault's case rate limits and quotas.

- Serial, one host at a time, never parallel tools against one host.
- 2 s base delay plus 0-3 s jitter between requests; 10 s on Vault and on
  anything that answers `429`.
- Stage A budget: **40 requests per host per engagement day.**
- A `429`, `503` or a sudden run of resets is the target defending itself.
  Stop, wait 10 minutes, do not retry in a loop.

```bash
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

---

## Step 2 — Prove the exposure is real, external, the client's, and which product

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN and office range; record the egress IP. | A control plane reached over the client's VPN is not an exposure. |
| IP ownership | ASN + WHOIS/RDAP + reverse DNS, cross-checked with scope. | Shared cloud addresses answer for other tenants. |
| Product, not port | Identify the product from its own oracle (Step 3), never from the port number. | See the collisions below. |
| Path prefix | Many installs live under a prefix: `/jenkins`, `/nexus`, `/artifactory`, `/gitlab`, `/sonar`, `/vault`. A `404` at `/` means nothing. | Fingerprint the prefix the redirect or the HTML base names. |
| Self-managed vs SaaS | Certificate subject, CNAME and ASN. | Step 1. |
| Honeypot | Implausible combinations (a Jenkins header on a host that also answers as GitLab), every path returning `200`, identical uptime across products. | A "Jenkins RCE" against a honeypot is a withdrawn report. |

Port collisions, all settled by the response:

| Port | Candidates |
|---|---|
| 8080 | Jenkins, Gerrit web, Argo CD (plain), Quay container, Airflow, Tomcat, any HTTP app |
| 8081 | Nexus, Artifactory service, Flink |
| 8888 | Spring Cloud Config, Jupyter |
| 9000 | SonarQube, legacy Portainer, FastCGI (`hunt-exposed-services` `remote-debug.md`) |
| 5000 | Docker Registry v2, Flask and other dev servers |
| 3000 | Gitea, Gogs, Forgejo, Rocket.Chat, Grafana |
| 8443, 9443 | Portainer, Argo CD, SSL VPN portals (`enterprise-vpn-attack`) |

---

## Step 3 — Route the product to one reference file

Load only the reference file for the product in front of you.

| Product | Ports (default or convention) | Read-only oracle | Load |
|---|---|---|---|
| HashiCorp Vault | 8200 API/UI, 8201 cluster (mTLS) | `GET /v1/sys/seal-status` (documented unauthenticated), `GET /v1/sys/health` | `references/secrets-and-discovery.md` |
| HashiCorp Consul | 8500 HTTP, 8501 HTTPS, 8502/8503 gRPC, 8600 DNS tcp+udp, 8300 RPC, 8301/8302 Serf | `GET /v1/acl/token/self` returns `ACL support disabled` when ACLs are off; one DNS query to 8600 | `references/secrets-and-discovery.md`; HTTP panel in `hunt-exposed-panels` |
| HashiCorp Nomad | 4646 HTTP, 4647 RPC, 4648 Serf | Same ACL oracle, same message | `references/secrets-and-discovery.md`; HTTP panel in `hunt-exposed-panels` |
| Netflix Eureka | 8761 by convention | `GET /eureka/apps` with `Accept: application/json` | `references/secrets-and-discovery.md` |
| Spring Cloud Config | 8888 | `GET /<application>/<profile>` key names only | `references/secrets-and-discovery.md`; Actuator in `hunt-springboot` |
| Jenkins inbound agent | 50000 in the official image; set per install | `GET /tcpSlaveAgentListener/` headers on the web port; `GET /` on the agent port | `references/build-and-automation.md`; web and CLI in `hunt-cicd` |
| TeamCity | 8111 | Version on `/login.html` | `references/build-and-automation.md` |
| Drone | 80/443 | `GET /version`, `GET /varz` (public routes in source) | `references/build-and-automation.md` |
| Argo CD | 443, 8080 | `GET /api/version`, `GET /api/v1/settings` | `references/build-and-automation.md` |
| Argo Workflows | 2746 | `GET /api/v1/version` (verify) | `references/build-and-automation.md` |
| Rundeck | 4440 HTTP, 4443 HTTPS | Version on the login page (verify) | `references/build-and-automation.md` |
| AWX / Ansible Tower / AAP controller | 80/443 | `GET /api/v2/ping/` (public by design in source) | `references/build-and-automation.md` |
| Terraform Enterprise | 443 | `GET /.well-known/terraform.json` (verify) | `references/build-and-automation.md` |
| SonarQube | 9000 | `GET /api/system/status` | `references/build-and-automation.md` |
| GitLab self-managed | 80/443, 22, registry 5050 | `/users/sign_in`; `/api/v4/version` (token needed on current releases, verify) | `references/source-control.md` |
| Gitea / Forgejo | 3000, SSH 22 or 2222 | `GET /api/v1/version` (public route in source) | `references/source-control.md` |
| Gogs | 3000 | Footer version (verify) | `references/source-control.md` |
| Gerrit | 8080 web, 29418 SSH | `GET /config/server/version`; SSH ident `GerritCodeReview_<ver>` | `references/source-control.md` |
| git daemon | 9418 | `git ls-remote` advertisement, `agent=git/<ver>` | `references/source-control.md` |
| Sonatype Nexus | 8081 | `Server: Nexus/<ver>` header (verify) | `references/artifact-registries.md` |
| JFrog Artifactory | 8081 service, 8082 router/UI | `GET /artifactory/api/system/version` | `hunt-exposed-panels` for the probe; CVE rows in `references/devops-cve-matrix.md` |
| Harbor | 80/443 | `GET /api/v2.0/systeminfo` (anonymous allowed, some fields omitted) | `references/artifact-registries.md` |
| Docker Registry v2 | 5000 | `GET /v2/` and its `Docker-Distribution-Api-Version` header | `references/artifact-registries.md` |
| Quay | 80/443, 8080/8443 in the container | `GET /api/v1/discovery` (verify) | `references/artifact-registries.md` |
| Verdaccio | 4873 | `GET /-/ping` (verify), web UI | `references/artifact-registries.md` |
| devpi | 3141 | `GET /+api` (verify) | `references/artifact-registries.md` |
| Portainer | 9443, 9000, 8000 | `hunt-exposed-panels` | CVE rows only here |
| Rancher | 80/443 | `GET /version`, `GET /rancherversion` (SUSE hardening guide names both) | Route to `hunt-k8s`; CVE rows only here |
| Mattermost | 8065 | `GET /api/v4/system/ping` (verify) | Fingerprint only |
| Rocket.Chat | 3000 | `GET /api/info` (verify) | Fingerprint only |

If the product is not in the table, describe the exposure generically. Do not
invent paths, defaults or CVEs.

---

## Step 4 — Stage A: read-only fingerprint and unauthenticated-surface check

A Stage A request must satisfy all of:

1. **GET or HEAD only** over HTTP. The non-HTTP exceptions are reads in their
   own protocol: one DNS query to Consul 8600, the git upload-pack
   advertisement on 9418, the SSH ident on 29418, and the `GET /` hello on the
   Jenkins agent port.
2. **No credential.** Not a default pair, not a token found elsewhere, not an
   empty password. Those are Stage B (Step 6).
3. **Names and counts, never contents.** A listing is page-limited (`n=20`,
   `limit=20`) and recorded as names plus totals. No secret value, artifact,
   layer, archive or source file is downloaded.
4. **No state left behind.** No account, token, session, service registration,
   webhook, job, build or upload.

```bash
T="target.example"; mkdir -p evidence
# Generic first touch: headers and title, nothing else.
curl -s -m 15 -D - -o "evidence/${T}_root.html" "https://${T}/" \
  | grep -i -E '^(HTTP/|Server:|X-Jenkins|X-Hudson|X-Gitlab|X-Gitea|X-Vault|X-Consul|X-Nomad|Docker-Distribution|X-Artifactory|X-JFrog|X-Content-Type|WWW-Authenticate:)'
grep -o -i -m1 '<title>[^<]*</title>' "evidence/${T}_root.html"
```

Then the product oracle from Step 3, from the reference file.

### Per-family hard limits

- **Secret stores (Vault, Config Server, Consul KV):** never request a secret
  value. For Config Server the oracle itself returns values, so pipe it through
  `jq` to key names before anything touches disk (the reference shows how).
- **Registries (Nexus, Artifactory, Harbor, Registry v2, Quay, Verdaccio,
  devpi):** catalog and tag listings, page-limited. No manifest-by-digest
  walk, no blob or layer `GET`, no artifact download.
  `supply-chain-attack-recon` treats an internal registry as out of scope for
  enumeration; this skill's evidence is one listing page, which is the
  boundary between proving the exposure and enumerating it.
- **Forges (GitLab, Gitea, Gogs, Forgejo, Gerrit, git daemon):** `ls-remote`
  and public API listings only. No `clone`, no archive download, no LFS fetch.
  Read whether registration is open from the sign-in page; never sign up.
- **Orchestrators and CI (Nomad, Jenkins, TeamCity, Argo, Rundeck, AWX,
  Drone):** listings of names only. Job and build specs often hold secrets; do
  not pull a spec to "check".
- **SonarQube:** `api/system/migrate_db` appears in the vendor's list of
  endpoints reachable without authentication. It is a POST that migrates the
  database. Never call it.

### Tools that look like Stage A and are not

| Tool / action | Why it is not Stage A |
|---|---|
| CVE-tagged scanner templates for these products (nuclei and similar) | Many perform the exploit instead of detecting it: they create a token or user, read a file outside the web root, or trigger the bypass. Read each template's requests first. Anything that is not a version or header match is Stage B. Default to version-gating from the oracle. |
| `docker pull`, `crane pull`, `skopeo copy`, blob `GET` | Copies image layers, the registry's data. Stage B. |
| `docker login`, `npm login`/`adduser`, `devpi login`, `vault login` | Sends or creates a credential. Stage B. |
| `git clone`, `git fetch`, archive or raw-file download | Copies source. Stage B, and only for a named repository. |
| `consul agent -join`, `nomad agent` pointed at the target, any Serf/gossip client | Joins the cluster. Forbidden (Step 6). |
| `vault operator init`/`unseal`/`generate-root`/`rekey` | Claims or disrupts the secret store. Forbidden. |
| `-sC`, `-A`, NSE category selectors | Pull whole script categories. Name each script and check it with `nmap --script-help`. |

---

## Step 5 — Read the results

### 5a. Version gate

Look the version up in `references/devops-cve-matrix.md`. The rules:

- **A version inside a range is unconfirmed** until the client confirms it or
  a Stage B check is signed off. Say so in the report.
- **Release trains differ per product.** Jenkins has weekly (`2.4xx`) and LTS
  (`2.4xx.y`) lines with separate fixed versions; GitLab, Artifactory, Vault,
  Harbor, Argo CD and Gitea patch several minor lines at once. Match the line
  before you compare numbers.
- **Some oracles hide the version on purpose:** Vault's listener options
  `redact_version`, `redact_addresses` and `redact_cluster_name`, Gitea's
  footer setting, Argo CD returning only the version string to anonymous
  callers. A missing version is not a patched version.
- **DoS-class CVEs are detected by version only and never tested.**
- **KEV status** in the matrix is from the CISA KEV feed, catalog 2026.10.13.

### 5b. Default auth posture: the finding is often the default

| Observation | What it means |
|---|---|
| Vault `initialized: false` | Uninitialised secret store on the internet. Anyone can claim it. Critical, as a state. |
| Vault `sealed: true` | Not a finding alone. Report exposure plus version. |
| Consul or Nomad `ACL support disabled` | No authorization on the API. Every read and write API is open; prove it with names only. |
| Eureka `/eureka/apps` answers | Service registry with no authentication: every instance's hostname, IP and port. Registration is open too (do not test it). |
| Config Server returns property sources | Application configuration, usually including credentials, served to anyone. |
| Argo Workflows started with `--auth-mode server` | The server's own service account answers for every caller (the default is `client`). |
| Open self-registration on a forge, registry or Verdaccio | Every "authenticated (PR:L)" CVE in the matrix becomes reachable by anyone. Grade those rows as pre-auth for this host. |
| Anonymous read on Nexus, Artifactory, Harbor, Gitea, SonarQube | Internal packages, images, source or code-quality data readable without login. |

---

## Step 6 — Stage B: anything that writes, registers, submits, pushes or executes

Stage B is **blocked by default**. It requires explicit written operator
sign-off naming the action, the host, the account and a time window. A chat
thumbs-up or "critical findings are in scope" is not sign-off. Record before
the first request:

```
Stage B authorization
  Host/port:        target.example:8081
  Action:           one documented default-credential login to the Nexus UI
  Account:          admin
  Blast radius:     one login event in the audit log; a failure may count
                    toward lockout; a success is an administrator session
  Reversibility:    session is logged out; nothing written
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| One vendor-documented default credential (see each reference) | Audit-log entry; possible lockout; on success an admin session on a build or secrets plane. |
| Pulling one named image manifest or one artifact to prove a secret inside it | Copies client data. Name the single object; hash it, do not keep it. |
| Cloning one named repository to prove exposure of private source | Copies source. Prefer `ls-remote` plus a file listing from the API. |
| Running a CVE confirmation template that creates a token or user | Leaves an account or token in production; requires verified removal. |
| Creating an account through open registration (forge, Verdaccio, Harbor) | A persistent account in the client's system; requires verified deletion. |
| Reading one Consul KV value or one Config Server value | A live production credential in your evidence. The key name is normally enough. |

**Forbidden outright, sign-off or not:**

- Vault `init`, `unseal`, `generate-root`, `rekey` on any node. Claiming an
  uninitialised Vault is the attack; starting root-token generation or rekey
  occupies the single operation slot (CVE-2026-5807 is exactly that DoS).
- Consul or Nomad ACL bootstrap on a cluster with ACLs disabled. It claims the
  cluster and locks the owner out of their own token management.
- Joining Consul or Nomad gossip, registering or deregistering a service in
  Consul or Eureka, submitting a Nomad job, Consul `exec`, script checks.
  Service registration hijacks production traffic; deregistration is an outage;
  the rest is fleet-wide code execution.
- Pushing an image, publishing a package, uploading an artifact or pushing a
  commit to anything a build consumes. That is a supply-chain compromise.
- Launching a job template, pipeline, workflow or build on AWX, Rundeck,
  Jenkins, TeamCity, Argo, Drone or Terraform Enterprise.
- Any DoS-class CVE in the matrix.

---

## Step 7 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Uninitialised Vault reachable from the internet | Critical |
| Consul or Nomad with ACLs disabled, or Eureka/Config Server unauthenticated, on production | Critical when the names show production secrets or services, otherwise High |
| Unauthenticated read of private source, internal packages or images (forge, Nexus, Artifactory, Harbor, Registry v2) | High to Critical, by what the names show |
| Version inside a KEV-listed pre-auth range (TeamCity, GitLab, Artifactory, Gogs and others in the matrix) | High, labelled unconfirmed; tell the client the same day |
| Version inside a non-KEV pre-auth range | Medium, labelled unconfirmed |
| Open self-registration that reaches PR:L RCE rows in the matrix | High, labelled unconfirmed |
| Internal IP or hostname disclosure (Jenkins agent hello `Server:` line, AWX `ping` instances, Vault `leader_address`, Drone `varz` SCM URL) | Low, chain input |
| Product exposed, authentication enforced, current version | Informational hardening item |

### What is not a finding

- **Version or banner disclosure alone.** HackerOne lists "Software version
  disclosure / Banner identification issues" as core ineligible; the Bugcrowd
  VRT rates "Fingerprinting/Banner Disclosure" P5.
- **A login page.** Exposure of an authenticated console with a current
  version is a hardening note at most.
- **"Outdated version" without a reachable issue.** VRT "Outdated Software
  Version" is P5.
- **Client-side CVEs.** Git CVE-2025-48384 (KEV) needs a victim to clone a
  malicious repository. An exposed git server is not evidence of it.
- **Public projects being public.** A public GitLab project or public Harbor
  project is the owner's choice unless it holds secrets.

---

## Step 8 — Evidence

Follow `evidence-hygiene`. Minimum per finding: the oracle request and raw
response headers, the egress IP, timestamps, the version string, the matrix
row, and for listings the names and counts only. Redact tokens, internal
passwords and anything that looks like a credential before it reaches the
report; keep key names, not values. For Stage B, the sign-off record and proof
that any created account, token or session was removed.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| Consul ACLs disabled | KV key names such as `config/prod/db/password` | Critical | Report the names. Reading values is a separate sign-off. |
| Eureka or Consul catalog | Internal hostnames, IPs and service ports | Recon multiplier | `offensive-osint`; scope check every new address. |
| Spring Cloud Config without auth | Property names prove credentials are served | Critical | `hunt-springboot` for the Actuator side of the same apps. |
| Jenkins agent-port hello | Version plus internal server IP | Low alone | `hunt-cicd` for the web UI and CLI CVEs. |
| Docker Registry v2 catalog | Image names | High if internal | `supply-chain-attack-recon` for public mirrors of the same images. |
| Verdaccio or Nexus proxying npmjs with internal scopes | Dependency-confusion candidates | Decided there | `supply-chain-attack-recon`. |
| Open forge registration | PR:L RCE rows (Gogs, Gitea, Forgejo, GitLab) become pre-auth | High, unconfirmed | Report; do not register. |
| Argo CD `/api/v1/settings` | OIDC issuer and client IDs | Low, chain input | `hunt-oauth`. |
| Drone `/varz` | Internal SCM URL | Low, chain input | The forge's own row in Step 3. |
| Artifactory version in a KEV range | Unauthenticated admin or token exposure | Critical-class, unconfirmed | `hunt-exposed-panels` for the anonymous-access check. |
| Rancher version | Rancher CVE rows here | Unconfirmed | `hunt-k8s` for the managed clusters. |

---

## Validation checklist

- [ ] Probed from outside every client VPN; egress IP recorded.
- [ ] Every IP client-owned (ASN + WHOIS/RDAP) and in the signed scope; vendor
      SaaS tenants handled at the HTTP layer only.
- [ ] Product identified from its own oracle, not the port; path prefixes tried.
- [ ] Stage A was GET/HEAD only, inside 40 requests per host, serial, with jitter.
- [ ] No credential, default pair or token sent outside a logged Stage B.
- [ ] Listings page-limited and recorded as names and counts; no layer,
      artifact, archive, clone or secret value downloaded.
- [ ] Config Server output reduced to key names before it touched disk.
- [ ] No registration, account creation, token creation or ACL bootstrap.
- [ ] No Vault `init`/`unseal`/`generate-root`/`rekey`, no gossip join, no
      service registration, no job, build or workflow launched.
- [ ] Every CVE template read before running; none that writes, reads files or
      creates accounts ran without sign-off.
- [ ] Version claims labelled unconfirmed, matched to the right release line,
      with KEV status from the 2026.10.13 catalog.
- [ ] DoS-class CVEs reported from version only.
- [ ] Banner disclosure and client-side CVEs not reported as findings.
- [ ] Created accounts, tokens and sessions (Stage B only) removed and the
      removal recorded.

---

## Sources

Primary sources (checked 2026-10-13): CISA KEV feed, catalog 2026.10.13
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>; NVD API
<https://services.nvd.nist.gov/rest/json/cves/2.0>; Vault API docs
<https://developer.hashicorp.com/vault/api-docs/system/seal-status> and listener
options <https://developer.hashicorp.com/vault/docs/configuration/listener/tcp>;
Jenkins `TcpSlaveAgentListener` source <https://github.com/jenkinsci/jenkins>;
Consul and Nomad ACL error strings <https://github.com/hashicorp/consul>,
<https://github.com/hashicorp/nomad>; Gerrit REST and `SshDaemon` source
<https://gerrit-review.googlesource.com/Documentation/rest-api-config.html>;
Harbor swagger <https://github.com/goharbor/harbor>; AWX `ApiV2PingView`
<https://github.com/ansible/awx>; Argo CD and Argo Workflows source
<https://github.com/argoproj>; Drone web routes <https://github.com/harness/drone>;
Gitea API routes <https://github.com/go-gitea/gitea>; Verdaccio default config
and htpasswd plugin <https://github.com/verdaccio/verdaccio>; SonarQube user
accounts docs <https://docs.sonarsource.com/sonarqube-server/latest/instance-administration/security/user-accounts>;
HackerOne core ineligible findings
<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>;
Bugcrowd VRT <https://github.com/bugcrowd/vulnerability-rating-taxonomy>.

---

## Related Skills & Chains

- `hunt-cicd` — Jenkins web, script console and CLI, pipeline logic, runner and
  token abuse, Terraform state.
- `hunt-exposed-panels` — HTTP panel triage for Artifactory, Consul, Nomad,
  Portainer; login-page fingerprinting and default-credential policy.
- `hunt-exposed-services` — every other non-HTTP port; the Stage A/B model and
  NSE trap list this skill follows.
- `hunt-k8s` — Kubernetes, Docker API, Rancher-managed clusters.
- `hunt-springboot` — Actuator and the Spring apps behind Eureka and Config Server.
- `supply-chain-attack-recon` — public registries, dependency confusion,
  public images.
- `infra-ssh` — SSH on Gerrit 29418 and forge SSH ports; Apache MINA SSHD rows.
- `infra-external-methodology` — the master port-to-skill routing table.
- `hunt-source-leak`, `cloud-iam-deep` — where leaked tokens for these products
  come from and what they grant.
- `hunt-brute-force` — all credential guessing.
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence, false
  positives, write-up.

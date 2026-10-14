# Build servers, deploy controllers and automation planes

Jenkins (inbound-agent port only), TeamCity, Drone, Argo CD, Argo Workflows,
Rundeck, AWX / Ansible Tower / AAP controller, Terraform Enterprise and
SonarQube. Every one of them executes code or holds the credentials that do, so
the line is sharp: **names and versions are Stage A; anything that runs is out.**

Scope note: the Jenkins web UI, `/script`, the CLI and CVE-2024-23897, GitLab CI
runners and pipeline logic belong to `hunt-cicd`. Login-page fingerprinting and
default-credential policy for HTTP consoles belong to `hunt-exposed-panels`.

Rate posture: serial, 2 s base plus 0-3 s jitter (`probe_delay` in `SKILL.md`).

---

## Jenkins: the inbound-agent port and its advert

Inbound ("JNLP") agents connect to a dedicated TCP port. The official container
image uses 50000; other installs choose a fixed port, a random one, or disable
it. The web UI advertises it.

### Stage A

```bash
J="https://target.example"   # the Jenkins web root, prefix included if any

# A1. The web UI's advert for agents. Headers only; the body is the word "Jenkins".
curl -s -m 15 -D - -o /dev/null "${J}/tcpSlaveAgentListener/" \
  | grep -i -E '^(HTTP/|X-Jenkins-JNLP-Port|X-Hudson-JNLP-Port|X-Jenkins-JNLP-Host|X-Jenkins-Agent-Protocols|X-Instance-Identity|X-Remoting-Minimum-Version)'
probe_delay

# A2. The agent port itself. The listener peeks at the first bytes; a request
# starting "GET / " gets a plain-text diagnostic reply and the socket closes.
P=50000   # use the X-Jenkins-JNLP-Port value from A1
printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 nc -w 5 target.example "$P"
```

From `hudson/TcpSlaveAgentListener.java` (`respondHello`), the reply carries:

| Line | What it leaks |
|---|---|
| `Jenkins-Version:` | Exact controller version, even when the web UI hides `X-Jenkins` behind a proxy |
| `Jenkins-Agent-Protocols:` | Enabled agent protocols (normally `JNLP4-connect`, `Ping`) |
| `Jenkins-Session:` | Session hash, changes on restart (uptime signal) |
| `Client:` | Your address as the controller sees it (confirms NAT path) |
| `Server:` | **The controller's local socket address.** Behind NAT or a load balancer this is the internal IP. |
| `Remoting-Minimum-Version:` | Oldest agent remoting build accepted |

A2 is a finding only as information disclosure (Low) plus an exposed control
channel: the agent port should face build agents, not the internet. Connecting
as an agent needs the agent's secret; with a leaked secret (agent launch
commands in logs, `hunt-source-leak`), an attacker can attach as that agent and
reach agent-to-controller CVEs (matrix). Attaching is forbidden here.

Version gate: `Jenkins-Version` against the Jenkins rows in
`devops-cve-matrix.md`, weekly and LTS lines separately. The web-UI CVEs are
`hunt-cicd`'s to confirm.

---

## TeamCity (8111)

### Stage A

```bash
TC="http://target.example:8111"
curl -s -m 15 "${TC}/login.html" | grep -o -i -m2 'Version [0-9][^<]\{0,40\}'
probe_delay
curl -s -m 15 -o /dev/null -w 'app/rest/server %{http_code}\n' "${TC}/app/rest/server"
```

The login page prints the version and build. `app/rest/server` returning `401`
is the expected posture; a `200` without credentials means guest or anonymous
REST access is on. A "Log in as guest user" link on the login page means guest
access is enabled (verify on the version); its presence is the evidence, do not
follow it.

TeamCity has the densest KEV record in this skill: CVE-2023-42793,
CVE-2024-27198, CVE-2024-27199 and CVE-2026-63077 (unauthenticated RCE through
the agent polling protocol, fixed in 2025.11.7 and 2026.1.3). Version-gate
only. The public scanner templates for the 2023-2024 bypasses perform the
bypass, and some create an access token for an existing user (verify per
template): that is a write to production and Stage B.

Unauthenticated agent registration is a designed feature: agents announce
themselves and wait for an administrator to authorise them. Registering a fake
agent to test that path is Stage B (it appears in the administrators'
"Unauthorized agents" list, and CVE-2026-59795 was stored XSS through exactly
that path).

---

## Drone

Two public routes, both registered on the web router in `handler/web/web.go`:

```bash
D="https://target.example"
curl -s -m 15 "${D}/version"; echo        # source repo, version, commit
probe_delay
curl -s -m 15 "${D}/varz" | jq '{scm: .scm.url, license: .license.kind, seats: .license.seats, repos: .license.repos}'
```

`/varz` (`handler/web/varz.go`) returns the SCM base URL (often an internal
GitLab or Gitea address), the SCM API rate-limit state and the licence (kind,
seats, repository limits). The SCM URL is a chain input (`source-control.md`).
Drone's login is delegated to the SCM, so who can sign in is decided by
`DRONE_USER_FILTER` and the SCM itself: read it from documentation the client
provides, do not test it by signing in. Drone development continues as Harness
Open Source; fingerprint by `/version` and route new builds by what it reports.

---

## Argo CD

```bash
A="https://target.example"
# Anonymous callers get only {"Version": ...}; logged-in callers get the full
# build matrix (server/version/version.go).
curl -s -m 15 "${A}/api/version"; echo
probe_delay
# SettingsService/Get is explicitly exempt from authentication because the
# login page needs it (server/settings/settings.go, AuthFuncOverride).
curl -s -m 15 "${A}/api/v1/settings" | jq '{url, oidcConfig: (.oidcConfig | {name, issuer, clientID, cliClientID}), dexConnectors: [.dexConfig.connectors[]?.type]}'
```

`/api/v1/settings` gives the external URL, the OIDC issuer and client IDs and
the Dex connector types. Low on its own, a chain input for `hunt-oauth`.

Anonymous access is configured with `users.anonymous.enabled` in `argocd-cm`
and grants whatever `policy.default` says. Detect it by whether
`GET /api/v1/applications` returns application names without a session; list
names only. The initial `admin` password is random (`argocd-initial-admin-secret`),
so there is no vendor default to try. Applications and repositories hold
deploy credentials; syncing, creating or deleting an application is a
production deployment and forbidden.

---

## Argo Workflows (2746)

`argo server` listens on 2746 and its `--auth-mode` defaults to `client`
(`cmd/argo/commands/server.go`). With `--auth-mode server` the server logs
"You are running without client authentication" and answers every caller with
its own service account.

```bash
W="https://target.example:2746"
curl -s -m 15 "${W}/api/v1/version"; echo        # (verify) anonymous behaviour
probe_delay
# Namespaced list. 401/403 = client auth enforced. 200 with items = server mode.
curl -s -m 15 "${W}/api/v1/workflow-templates/argo" | jq -r '.items[]?.metadata.name' | head -20
```

Use a namespace the client named or the default `argo`; do not loop
namespaces. Submitting a workflow or template is code execution in the cluster:
forbidden. Cluster-side follow-up belongs to `hunt-k8s`.

---

## Rundeck (4440 / 4443)

Rundeck's documented defaults are HTTP 4440 and HTTPS 4443. The login page
carries the product name and, on most versions, the version string (verify per
version). API calls need a token; `GET /api/<n>/system/info` answering without
one is a finding. Do not iterate API versions; read the version from the page.

Many installs and container images ship a `realm.properties` with an
`admin`/`admin` entry; whether a given package does is not confirmed from a
primary source here (verify). One documented pair, once, is Stage B under
`SKILL.md` Step 6. Rundeck runs commands on every node it manages: never run a
job or an ad-hoc command.

---

## AWX / Ansible Tower / AAP automation controller

`ApiV2PingView` in `awx/api/views/root.py` sets `permission_classes = (AllowAny,)`
and `authentication_classes = ()`, and its docstring says everything it returns
"should be considered public / insecure".

```bash
X="https://target.example"
curl -s -m 15 "${X}/api/v2/ping/" | jq '{ha, version, active_node, install_uuid, instances: [.instances[]? | {node, node_type}], instance_groups: [.instance_groups[]?.name]}'
```

The `instances` list names every controller, execution and hybrid node by
hostname. Version from `version`. Report: version (matrix) plus internal
hostnames (Low, chain input). Everything past `ping` needs a session;
launching a job template is code execution on the managed fleet and forbidden.

---

## Terraform Enterprise

TFE is self-hosted HCP Terraform; `app.terraform.io` is the vendor's SaaS
(Step 1 of `SKILL.md`). Read-only fingerprints (verify on the target's release):

```bash
TF="https://target.example"
curl -s -m 15 "${TF}/.well-known/terraform.json"; echo   # service discovery: tfe.v2, modules.v1, providers.v1
probe_delay
curl -s -m 15 -o /dev/null -w '_health_check %{http_code}\n' "${TF}/_health_check"
```

The workspace, state and variable APIs need a token. Terraform state is the
prize and is `hunt-cicd`'s territory when it leaks elsewhere. TFE CVE rows in
the matrix are authenticated privilege escalations; none is a pre-auth route.

---

## SonarQube (9000)

Forced authentication is on by default ("By default, authentication is
forced", user-accounts documentation). Even so, status endpoints answer:

```bash
S="http://target.example:9000"
curl -s -m 15 "${S}/api/system/status"; echo     # id, version, status
probe_delay
curl -s -m 15 -o /dev/null -w 'components/search %{http_code}\n' "${S}/api/components/search?qualifiers=TRK&ps=20"
```

A `200` with project names from `api/components/search` means forced
authentication is off. When it is off, the vendor's list of endpoints reachable
without authentication includes `api/sources/show` and `api/sources/scm` for
public projects and `api/users/search`: report names and counts, never pull
source through the API.

**Never call `api/system/migrate_db`.** It is on that same unauthenticated list
and it is a POST that migrates the database.

SonarQube ships an `admin` account with the password `admin` and forces a change
at first login on recent versions (verify per version). One attempt is Stage B
under `SKILL.md` Step 6. SonarQube stores tokens for the SCM and CI it
integrates with; an admin session is a credential store.

# Artifact repositories, service mesh and remote-management panels

JFrog Artifactory, HashiCorp Consul, HashiCorp Nomad, Portainer, MeshCentral.
These are the panels that sit closest to the supply chain and to the endpoint
fleet, which is why their exposure grades higher than their CVE lists suggest.

Scope note: Jenkins, GitLab CI, TeamCity, Drone and Argo belong to `hunt-cicd`.
The Kubernetes API, kubelet, etcd, the Kubernetes Dashboard and the Docker
socket belong to `hunt-k8s`. Package-ecosystem and dependency attacks belong to
`supply-chain-attack-recon`. This file covers the HTTP panel exposure only.

Rate posture: serial, 2 s base delay plus 0-3 s jitter.

---

## JFrog Artifactory

### Fingerprint (Stage A)

```bash
TARGET="target.example"

# Stage A — read-only. Documented as requiring "a valid user (can be
# anonymous)", so it answers unauthenticated wherever anonymous access is on.
curl -s -m 15 "https://${TARGET}/artifactory/api/system/version" | head -c 400
```

`GET /artifactory/api/system/version` returns the version, the revision and the
installed add-ons, and JFrog documents its security requirement as a valid user
that **may be the anonymous user**. An unauthenticated `200` here therefore
proves two things at once: the product and version, and that anonymous access is
enabled.

### Anonymous access and default credentials

- The platform installs a predefined `anonymous` user. Anonymous access is
  disabled until the "Allow Anonymous Access" option is enabled under
  Security > General. JFrog's own guidance warns that enabling it can expose
  existing **and future** repositories. From Artifactory 7.161.5, anonymous
  users can only be assigned actions a platform administrator has approved.
- The default administrator for **self-managed** instances is `admin` /
  `password`, per the user-management documentation. SaaS instances do not ship
  this account.

One attempt with that pair, on an in-scope self-managed host, and only after
reading SKILL.md Step 5. JFrog does not publish a default lockout threshold, so
assume a lockout exists and treat the single attempt as your whole budget.

### Verified CVEs

| CVE | What it is | Affected (NVD, all upper bounds exclusive) |
|---|---|---|
| CVE-2026-42018 | Artifactory could return an internal anonymous-user token to an **unauthenticated** caller even when anonymous access is **disabled**, potentially exposing sensitive resources. | < 7.111.20; 7.117.0 to < 7.117.27; 7.125.0 to < 7.125.19; 7.133.0 to < 7.133.28; 7.146.0 to < 7.146.8 |
| CVE-2026-69107 | An unauthenticated user may access restricted artifacts under specific conditions. | < 7.104.16; 7.111.0 to < 7.111.14; 7.117.0 to < 7.117.21; 7.125.0 to < 7.125.14; 7.133.0 to < 7.133.21; 7.146.0 to < 7.146.8 |

Both are genuinely pre-auth, which makes the version string from the fingerprint
step the whole triage. Neither NVD record publishes the request shape, so do not
reconstruct one from guesswork: report the reachable version against the range
and let the client patch. If the engagement wants exploitation, the correct next
step is JFrog's own advisory for the fixed-version list, not a crafted request
you invented.

### What exposure means here

An Artifactory instance is the build system's source of truth. Grade on what the
anonymous or default-credential session can see:

- Read access to an internal repository means proprietary source, internal
  packages and sometimes `.npmrc`/`settings.xml` files containing tokens.
- **Write** access to a repository that build systems consume is a supply-chain
  compromise. Prove read-only reachability and stop; uploading an artefact is
  Stage B with "every downstream build consumes it" as the blast radius, and is
  not something this skill asks you to do.

Evidence shape: repository names and artefact counts, not downloaded artefacts.

---

## HashiCorp Consul

### The default that produces the finding

Consul's ACL system is **optional**, and `acl.default_policy` defaults to
`"allow"`, which HashiCorp documents as making ACLs a denylist: any operation
not explicitly prohibited is permitted. The documentation notes this default
"will be changed in a future major release"
([ACL configuration reference](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)).
The HTTP API port defaults to **8500**, DNS to 8600, and gRPC to `-1`, meaning
disabled outside `-dev` mode
([general agent parameters](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)).

```bash
# Stage A — read-only. Serial, one endpoint at a time.
for P in /v1/agent/self /v1/catalog/services /v1/catalog/nodes; do
  echo "== $P"
  curl -s -m 15 "https://${TARGET}:8500${P}" | head -c 500; echo
  sleep 3
done
```

`GET /v1/agent/self` returns the agent's own configuration, including the
version and the datacenter name; it requires the `agent:read` ACL, which the
`allow` default policy grants
([agent API](https://developer.hashicorp.com/consul/api-docs/agent)).
`GET /catalog/services` and `GET /catalog/nodes` map the internal estate: every
registered service, its tags, its node and its address
([catalog API](https://developer.hashicorp.com/consul/api-docs/catalog)).

The KV store is the part that turns a topology leak into a credential leak:
teams use Consul KV for application configuration, and that is where database
passwords live.

```bash
# Stage A — key NAMES only. On GET /kv/:key the `keys` parameter returns an
# array of key-name strings with no values and no metadata, and specifying it
# implies `recurse`. Do NOT add ?recurse alone: that returns base64 values.
curl -s -m 15 "https://${TARGET}:8500/v1/kv/?keys=true" | head -c 800
```

([KV store API](https://developer.hashicorp.com/consul/api-docs/kv))

Request key names, not values. A list of keys such as
`config/prod/db/password` proves the exposure and the data class without you
holding the secret. Reading the value is a judgement call you should resolve
toward "do not": the name is sufficient evidence, and a retrieved production
credential is a liability for the rest of the engagement.

**Never** `PUT` to the KV store, deregister a service, or touch
`/v1/agent/service/*`. Service deregistration removes a service from discovery
and takes the application down. Consul's exec feature is remote command
execution across the fleet and is out of scope for this bundle.

---

## HashiCorp Nomad

The HTTP API port defaults to **4646**, and the agent configuration reference
lists the `acl` block with a default of `nil`, so a stock agent has no ACL
enforcement configured
([agent configuration](https://developer.hashicorp.com/nomad/docs/configuration)).

```bash
# Stage A — read-only. GET /v1/jobs is the documented job list.
curl -s -m 15 "https://${TARGET}:4646/v1/agent/self" | head -c 500; echo
sleep 3
curl -s -m 15 "https://${TARGET}:4646/v1/jobs" | head -c 500
```

([Nomad jobs API](https://developer.hashicorp.com/nomad/api-docs/jobs))

An unauthenticated `/v1/jobs` listing exposes every scheduled workload, its
image or binary, and its environment-variable **names**. Job specifications are
another routine credential store.

Where the chain ends, unambiguously: Nomad's purpose is running arbitrary
workloads on a fleet. `POST /v1/jobs` submits one and is remote code execution
across the cluster. Do not submit a job, not even a benign one — it schedules
onto production capacity. Note also that `hunt-rce` already covers Nomad's Go
`text/template` injection in configuration UIs; that is a different finding from
this exposure and belongs there.

---

## Portainer

### Ports and the setup window

From the vendor installation documentation
([install CE server](https://docs.portainer.io/start/install-ce/server/docker/linux)):

- **9443** — the web UI over HTTPS. This is the panel.
- **8000** — a TCP tunnel server, optional, only needed for Edge agents.
- **9000** — legacy HTTP, **not exposed by default**; it requires an explicit
  `-p 9000:9000`.

The historically famous Portainer finding was an uninitialised instance letting
any visitor create the first administrator. Current Portainer has closed it in
two ways, and knowing both keeps you from filing a stale finding
([setup token FAQ](https://docs.portainer.io/faqs/installing/setup-token)):

- From **2.43** and **2.39.4**, a new instance with no administrator requires a
  **setup token**, printed in the server logs as `setup_token=`. The flags are
  `--setup-token <value>` to supply your own, `--no-setup-token` to disable the
  requirement, and `--admin-password` / `--admin-password-file` to pre-set the
  password so no token is generated.
- The administrator must be created **within 5 minutes of startup**. After that
  window the setup page is no longer usable and the operator has to follow the
  vendor's timeout procedure.

Two endpoints answer without authentication, and this is verifiable in the
product's own router rather than inferred: in `api/http/handler/system/handler.go`
the status route is registered on the public subrouter
(`publicRouter.Use(bouncer.PublicAccess)`, then
`publicRouter.Handle("/status", ...).Methods(http.MethodGet)`), while `/version`,
`/info` and `/nodes` sit on the authenticated subrouter. In
`api/http/handler/users/handler.go`, both
`publicRouter.Handle("/users/admin/check", ...).Methods(http.MethodGet)` and
`publicRouter.Handle("/users/admin/init", ...).Methods(http.MethodPost)` are
public.

```bash
# Stage A — read-only, both documented as public routes in Portainer's own
# router. Neither sends nor creates a credential.
curl -s -m 15 "https://${TARGET}:9443/api/system/status" | head -c 300; echo
sleep 3
curl -s -m 15 -o /dev/null -w 'users/admin/check %{http_code}\n' \
  "https://${TARGET}:9443/api/users/admin/check"
```

Interpretation: `GET /api/users/admin/check` is the whole triage. It tells you
whether an administrator account exists **without sending a single
credential**. If one exists, the finding is "container management plane exposed
to the internet", graded on blast radius. If none exists, the instance is
uninitialised and `POST /api/users/admin/init` would create the administrator.

**That `POST` is Stage B and you should decline it even with sign-off.** It
permanently claims the instance, locks the rightful owner out of their own
container platform, and is indistinguishable from the attack it is meant to
demonstrate. The `check` response is sufficient evidence of pre-auth
administrative takeover. Report the state; do not claim it.

### What exposure means

A Portainer session manages Docker or Kubernetes: container creation, volume
mounts, and `exec` into running containers. Container creation with a host
bind-mount is host compromise, which is why this grades Critical on exposure
alone. Creating or `exec`-ing into a container is Stage B with "arbitrary
workload on the container host" as the blast radius, and the host-escape
mechanics belong to `hunt-k8s`, not here.

---

## MeshCentral

Thin coverage, honestly labelled: MeshCentral has few verifiable pre-auth
routes, so this section is short rather than padded.

Default ports are TCP **80**, **443** and **4433** (Intel AMT CIRA), plus UDP
**16990** for LAN server discovery, per the vendor documentation. The agent and
relay WebSocket endpoints appear in vendor material as `/agent.ashx` and
`/meshrelay.ashx` — for example a MeshAgent configured with
`MeshServer=wss://target.example:443/agent.ashx`.

```bash
# Stage A — read-only fingerprint of the login page only.
curl -s -m 15 "https://${TARGET}/" | grep -o -i -m1 "meshcentral" 
```

The one advisory worth recording is
[GHSA-c7hr-448w-65px](https://github.com/Ylianst/MeshCentral/security/advisories/GHSA-c7hr-448w-65px):
no assigned CVE, affecting the `meshcentral` npm package **below 1.1.60**, fixed
in 1.1.60. It is stored cross-site scripting through unsanitised
agent-supplied fields — `osdesc` in the agent's `coreinfo` WebSocket message,
plus `node.name`, `cpuinfo.thermals[].InstanceName` and `volumes[].name` — which
the server stores unescaped and renders in the device details panel, where it
executes in an administrator's browser.

Read the trust direction carefully before you reach for it: the payload comes
from a **rogue or compromised agent**, so reaching it requires control of an
enrolled endpoint. That is not an internet-facing pre-auth route, and chasing it
would walk into the endpoint-compromise territory this bundle excludes. For an
exposed MeshCentral, the reportable finding is the exposure of a fleet remote-
control plane plus the version against 1.1.60.

Grade it on what the panel controls, not on its CVE count: MeshCentral is remote
desktop, file transfer and terminal access to every enrolled machine. An exposed
instance with weak authentication is a Critical by blast radius. Stop at
"management plane exposed, N devices enrolled per the login page or public
statistics". Do not connect to a device.

---

## Cross-references

- `hunt-cicd` — Jenkins, GitLab CI, TeamCity, Drone, Argo, and pipeline secrets.
- `hunt-k8s` — Kubernetes API, kubelet, etcd, the Kubernetes Dashboard,
  `docker.sock` and container escape.
- `supply-chain-attack-recon` — what to do with a reachable artifact repository
  as a supply-chain problem rather than a panel exposure.
- `hunt-exposed-services` — the raw ports behind these products (for example
  Consul's DNS listener on 8600).
- `hunt-xss` — stored-XSS confirmation mechanics, for the MeshCentral advisory
  if an engagement genuinely scopes an agent-side test.
- `hunt-rce` — Nomad template injection in configuration UIs.

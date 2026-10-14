# Secret stores and service discovery

HashiCorp Vault, Consul, Nomad, Netflix Eureka and Spring Cloud Config. These
answer the question "where is everything and what are its credentials", so an
unauthenticated read here grades higher than the same read anywhere else.

Scope note: the HTTP panel triage for Consul (`/v1/agent/self`, catalog, KV key
names) and Nomad (`/v1/agent/self`, `/v1/jobs`) already lives in
`hunt-exposed-panels` `references/devops-and-orchestration.md`. Run that first;
this file adds the ACL oracle, the non-HTTP ports and the CVE context. Actuator
on the Spring apps behind Eureka and Config Server belongs to `hunt-springboot`.

Rate posture: serial, 2 s base plus 0-3 s jitter; 10 s between requests to
Vault. Use the `probe_delay` helper from `SKILL.md` Step 1.

---

## HashiCorp Vault

### Ports

`8200` is the API and UI listener (default `address` `127.0.0.1:8200`); `8201`
is the cluster listener (`cluster_address`, one port higher), used for
request forwarding and Raft between nodes and protected by mutual TLS. An
internet-facing 8201 is a hardening finding by itself: it should only ever face
the other nodes.

### Stage A

```bash
T="target.example"; V="https://${T}:8200"

# A1. Documented as unauthenticated. Initialisation, seal state, version.
curl -s -m 15 "${V}/v1/sys/seal-status" \
  | jq '{type, initialized, sealed, t, n, version, build_date, cluster_name, storage_type}'
probe_delay

# A2. Status code alone encodes the node's role.
curl -s -m 15 -o /dev/null -w 'sys/health %{http_code}\n' "${V}/v1/sys/health"
probe_delay

# A3. HA leader. leader_address and leader_cluster_address often carry
# internal hostnames or RFC 1918 addresses (unless redact_addresses is set).
curl -s -m 15 "${V}/v1/sys/leader" | jq '{ha_enabled, is_self, leader_address, leader_cluster_address}'
```

`sys/health` status codes, per the API docs: `200` initialised, unsealed and
active; `429` unsealed standby; `472` DR secondary; `473` performance standby;
`474` standby that cannot reach the active node; `501` not initialised; `503`
sealed; `530` removed from the cluster.

Optional, one request each, only if the login page suggests them:

- `GET /v1/sys/internal/ui/mounts` returns the auth methods marked for
  unauthenticated listing (what the login page tabs show), such as `ldap`,
  `oidc`, `userpass` (verify the anonymous response shape on the target's version).
- `GET /v1/sys/metrics?format=prometheus` answers without a token only when the
  operator set `unauthenticated_metrics_access`. A `200` is an information leak
  (mount names, request rates, lease counts). Do not request `/v1/sys/pprof`:
  profile endpoints sample the process for seconds at a time.

### Reading the results

| Result | Meaning |
|---|---|
| `"initialized": false` | **Critical as a state.** Anyone who reaches the API can initialise it and receive the root token and unseal keys. Report; do not touch. |
| `"sealed": true` | Not a finding by itself. Exposure plus version. |
| `"storage_type": "inmem"` | Very likely a `vault server -dev` instance: in-memory storage, data lost on restart, often a root token chosen on the command line (verify per version). Guessing that token is credential guessing (`hunt-brute-force`, Stage B). |
| `version` and `build_date` missing | `redact_version` is set on the listener. Not evidence of a patched build. |
| `cluster_name` missing | `redact_cluster_name`. |
| `leader_address` with an internal name or address | Low, chain input for `offensive-osint`. Vault before 1.5.7 / 1.6.2 also leaked the node's internal IP on some invalid unauthenticated requests (CVE-2021-3024); do not send malformed requests to prove it, the version decides. |
| Enterprise fields (`license`, `replication_*`) | Edition fingerprint; Enterprise-only CVE rows apply. |

### Never

`PUT /v1/sys/init`, `/v1/sys/unseal`, `/v1/sys/generate-root/attempt`,
`/v1/sys/rekey/init` and their DELETE counterparts. Initialisation claims the
store. Root-token generation and rekey hold the single in-progress operation
slot; repeatedly starting or cancelling them is the unauthenticated DoS fixed
in Vault 2.0.0 (CVE-2026-5807). None of this is Stage B; it is out.

Vault rows in `devops-cve-matrix.md`: CVE-2024-2048 (TLS cert auth bypass with
a non-CA trusted certificate), the 2025 "Vault Fault" set (lockout bypass
CVE-2025-6004, userpass timing CVE-2025-6011, privileged-operator RCE
CVE-2025-6000), and the unauthenticated DoS rows (never tested).

---

## HashiCorp Consul: what the panel file does not cover

### The ACL oracle (Stage A, one request)

Consul returns the literal error `ACL support disabled` from ACL endpoints when
ACLs are off (`acl/errors.go`, `errDisabled`). That is the cleanest single proof
that nothing on the API is authorised.

```bash
curl -s -m 15 "https://${T}:8500/v1/acl/token/self"; echo
# "ACL support disabled"  -> no ACL system at all: every API is open
# "ACL not found"          -> ACLs on; the anonymous token is in use
# "Permission denied"      -> ACLs on and enforced for this call
```

ACLs on with `default_policy = "allow"` (the documented default) still lets the
anonymous token read most things; the panel file's catalog and KV-name checks
show what it can read.

### Ports

| Port | Purpose | Stage A |
|---|---|---|
| 8500 / 8501 | HTTP / HTTPS API | `hunt-exposed-panels` plus the oracle above |
| 8502 / 8503 | gRPC / gRPC TLS (xDS for Envoy) | Report exposure only |
| 8600 tcp+udp | DNS interface | One query, below |
| 8300 | Server RPC | Report exposure only |
| 8301 / 8302 tcp+udp | Serf LAN / WAN gossip | Report exposure only. Never join. |

```bash
# One DNS query. consul.service.consul resolves to the server nodes and is
# always registered, so no name guessing is needed.
dig @"${T}" -p 8600 consul.service.consul SRV +short +time=5 +tries=1
```

An answer proves the catalog is readable over DNS, and the target names in the
SRV records are node names (often internal hostnames). Do not walk service
names with a wordlist; use the names the HTTP catalog already gave you. If the
agent has `recursors` configured, the DNS port may also resolve arbitrary
names for anyone: that is an open-resolver question for `infra-dns`, tested
there with its own rules.

Gossip (8301/8302) without an `encrypt` key, and server RPC (8300) without
`verify_incoming`, let a stranger take part in the cluster. Neither can be
proven without joining, and joining is forbidden. Report the open port with the
configuration question for the client.

---

## HashiCorp Nomad: what the panel file does not cover

Nomad uses the same message for the same condition: `ACL support disabled`,
returned with code 400 by the ACL endpoints when ACLs are off
(`nomad/acl_endpoint.go`).

```bash
curl -s -m 15 "https://${T}:4646/v1/acl/token/self"; echo
```

| Port | Purpose |
|---|---|
| 4646 | HTTP API and UI (`hunt-exposed-panels`) |
| 4647 | RPC between agents and servers |
| 4648 tcp+udp | Serf WAN gossip between servers |

4647 and 4648 facing the internet are the cluster's control channel. Report
the exposure; never connect an agent. With ACLs disabled, `POST /v1/jobs` is
remote code execution on every client node; the ACL oracle plus the job-name
listing in the panel file is the whole proof.

---

## Netflix Eureka (Spring Cloud Netflix server)

Eureka is a service registry: every instance of every service announces its
hostname, IP, port, status and metadata. The Spring Cloud Netflix server has no
authentication unless the application adds Spring Security. 8761 is the port
the Spring documentation uses for a standalone server; Spring Boot's own
default is 8080, so fingerprint both.

### Stage A

```bash
E="http://${T}:8761"
# Dashboard: the HTML at / lists registered instances and "General Info".
curl -s -m 15 "${E}/" | grep -o -i -m3 'eureka[^<]\{0,60\}'
probe_delay
# Registry: names and counts, not the full instance dump.
curl -s -m 15 -H 'Accept: application/json' "${E}/eureka/apps" \
  | jq -r '.applications.application[] | "\(.name)\t\(.instance | length)"' | head -50
```

One line per application with its instance count is the evidence. If a sample
is needed to show internal addressing, take the `hostName` and `ipAddr` of one
instance and stop. Instance metadata sometimes carries management URLs
(`management.port`, `/actuator` paths): those route to `hunt-springboot`.

A `401` with `WWW-Authenticate: Basic` means Spring Security is in front of it.
Credentials for it usually live in the clients' `eureka.client.serviceUrl.defaultZone`
(`http://user:pass@host:8761/eureka/`), which leaks through Config Server or an
Actuator `/env` (`hunt-springboot`).

### Never

`POST /eureka/apps/<APP>` registers an instance, and clients will start sending
production traffic to whatever address it names. `DELETE` and the status
`PUT` take real instances out of rotation. Both are forbidden, not Stage B.

No CVE for the Netflix Eureka server itself was found in NVD for 2021-2026
(verify): keyword hits were for Apollo and Steeltoe clients, not this server.
The exposure is the finding.

---

## Spring Cloud Config Server

Config Server serves application configuration over HTTP from a Git, SVN,
Vault, native filesystem or cloud secret-manager backend. Paths follow
`/{application}/{profile}[/{label}]` and `/{application}-{profile}.yml`; the
server's bundled `configserver.yml` sets port 8888. By default it decrypts
`{cipher}` values server-side before serving them (verify on the target's
version), so "the repository stores them encrypted" does not protect anything
the server will serve.

### Stage A: key names only

The oracle returns values. Reduce it to names in the pipe so no value is ever
written to disk or terminal scrollback.

```bash
C="http://${T}:8888"
# Property-source names reveal the backend (Git URL, file path, Vault mount).
# Then key names only, per source. Never save the raw response.
curl -s -m 15 "${C}/application/default" \
  | jq -r '.propertySources[] | "== \(.name)", (.source | keys[] | "   \(.)")' | head -80
probe_delay
# Encryption configured? Read-only status endpoint (verify on the version).
curl -s -m 15 -o /dev/null -w 'encrypt/status %{http_code}\n' "${C}/encrypt/status"
```

Use at most three application names, taken from Eureka, Consul or the
`propertySources` names above. No wordlist.

| Result | Meaning |
|---|---|
| `propertySources` with keys such as `spring.datasource.password`, `*.secret`, `*.token` | Critical: production credentials served to anyone. The key names are the evidence. |
| Property-source name is a Git URL | The backing repository; route it to `hunt-source-leak` (do not clone it). |
| `401` | Spring Security in front. Exposure plus version only. |

`POST /decrypt` turns any `{cipher}` value you found elsewhere into plaintext.
It writes nothing, but its output is a live credential: Stage B with sign-off
naming the single value, and usually unnecessary.

Version: Config Server has no version endpoint of its own. If the app's
Actuator answers, `hunt-springboot` reads it there; otherwise report the
exposure without a version. CVE rows (2026 directory traversal and backend
issues, plus the KEV-listed CVE-2020-5410) are in `devops-cve-matrix.md`.

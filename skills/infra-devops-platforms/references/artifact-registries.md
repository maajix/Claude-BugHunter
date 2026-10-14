# Artifact and container registries

Sonatype Nexus, Harbor, Docker Registry v2, Quay, Verdaccio and devpi, plus the
Artifactory cross-reference. A registry is what every build trusts, so the two
questions are always the same: **can a stranger read internal artifacts**, and
**can a stranger write anything a build will consume**. Stage A answers the
first with names and counts. The second is never tested by writing.

Scope boundaries:

- `supply-chain-attack-recon` owns public registries (npmjs, PyPI, Docker Hub,
  GHCR, quay.io), dependency confusion and typosquats, and treats enumerating
  an internal registry as out of its scope. This file's boundary: one oracle
  request plus one page-limited listing per registry is the evidence that the
  registry is exposed. Walking every repository, pulling manifests, configs,
  layers or packages is Stage B, one named object at a time.
- JFrog Artifactory's fingerprint (`/artifactory/api/system/version`),
  anonymous-access semantics and default administrator live in
  `hunt-exposed-panels` `references/devops-and-orchestration.md`. Its 2026 KEV
  rows are in `devops-cve-matrix.md`.
- Kubernetes image pulls and `docker.sock` belong to `hunt-k8s`.

Rate posture: serial, 2 s base plus 0-3 s jitter (`probe_delay` in `SKILL.md`).

---

## Sonatype Nexus Repository (8081)

### Stage A

```bash
N="http://target.example:8081"        # add /nexus for Nexus 2 or a prefixed install
curl -s -m 15 -D - -o /dev/null "${N}/" | grep -i -E '^(HTTP/|Server:)'
probe_delay
curl -s -m 15 -o /dev/null -w 'status %{http_code}\n' "${N}/service/rest/v1/status"
probe_delay
# Repositories readable by the anonymous user. Names, formats and types only.
curl -s -m 15 "${N}/service/rest/v1/repositories" | jq -r '.[] | [.name, .format, .type] | @tsv' | head -30
```

Nexus 3 has commonly sent `Server: Nexus/<version> (OSS)` or `(PRO)` (verify
on the target; a reverse proxy may strip it). A repository list without
credentials means anonymous read is on. `hosted` repositories hold the
client's own artifacts; `proxy` repositories mirror public ones and are not a
leak by themselves; `group` repositories merge both.

Defaults:

- Nexus 3 from 3.17 generates a random `admin` password into
  `$data-dir/admin.password` at first start; Sonatype's post-install checklist
  documents it. Older Nexus 3 and Nexus 2 shipped `admin`/`admin123` (verify per
  version). One documented pair, once, is Stage B.
- Anonymous access is chosen in the first-run wizard (verify the default per
  version). The listing above is the proof either way.

Hosted Maven repositories routinely contain `settings.xml`, and npm hosted
repositories `.npmrc`, with deploy credentials. Report the repository names;
pulling one named file to prove a credential is Stage B.

CVE rows (matrix): CVE-2024-4956 (unauthenticated path traversal), CVE-2026-5189
(hard-coded credentials for the internal database, unauthenticated, 3.0.0
through 3.70.5), the older KEV entries CVE-2019-7238 and CVE-2020-10199.

---

## Harbor

```bash
H="https://target.example"
# Documented in Harbor's swagger as callable anonymously, with some attributes
# omitted for anonymous callers.
curl -s -m 15 "${H}/api/v2.0/systeminfo" | jq '{harbor_version, auth_mode, primary_auth_mode, self_registration, registry_url, external_url}'
probe_delay
# Public projects, first page.
curl -s -m 15 "${H}/api/v2.0/projects?page_size=20" | jq -r '.[] | "\(.name)\tpublic=\(.metadata.public)\trepos=\(.repo_count)"'
```

Fields that come back `null` were omitted for an anonymous caller; whether
`harbor_version` and `self_registration` are among them depends on the version
(verify). `auth_mode` names the backend (`db_auth`, `ldap_auth`, `oidc_auth`).

| Result | Meaning |
|---|---|
| `self_registration: true` | Anyone can create a Harbor account. Do not. Grade authenticated rows as reachable. |
| Public projects with internal-looking names | Public by an administrator's choice, but an internal image in a public project is a leak. NVD carries CVE-2022-46463 for this behaviour; the vendor disputes it as documented design. Report the project, not the CVE. |
| `auth_mode: db_auth` on an internet-facing instance | Local accounts, including the installer's `admin`. |

The installer's `harbor.yml` sets `harbor_admin_password: Harbor12345`; NVD
records the unchanged default as CVE-2026-4404 (2.15.0 and below). One attempt
with that pair is Stage B. Harbor's own registry endpoint (`/v2/`) uses token
auth with the realm at `/service/token`; treat it as below.

---

## Docker Registry v2 / CNCF Distribution (5000)

```bash
RG="https://target.example:5000"     # plain http on many internal registries
# The API version check. 200 = no auth; 401 + WWW-Authenticate = auth required.
curl -s -m 15 -D - -o /dev/null "${RG}/v2/" \
  | grep -i -E '^(HTTP/|Docker-Distribution-Api-Version|WWW-Authenticate)'
probe_delay
# One catalog page, small n. Names only.
curl -s -m 15 "${RG}/v2/_catalog?n=20" | jq -r '.repositories[]'
probe_delay
# Tags for ONE repository the catalog named.
curl -s -m 15 "${RG}/v2/<repository>/tags/list?n=20" | jq -r '.tags[]?'
```

| Result | Meaning |
|---|---|
| `200` on `/v2/` with `Docker-Distribution-Api-Version: registry/2.0` | Registry with no authentication in front of the read API. |
| `401` with `WWW-Authenticate: Bearer realm="https://auth.example/token",service="..."` | Token auth. The realm names the auth server (GitLab `/jwt/auth`, Harbor `/service/token`, a cloud registry): route to that product's section. |
| `401` with `Basic realm` | htpasswd or a proxy. Exposure plus nothing. |
| Catalog names such as `internal/*`, `prod-*`, `*-secrets` | High: internal images readable by anyone. |

Keep `n` small. Distribution before 2.8.2 could be driven out of memory through
a large `n` on the catalog endpoint (CVE-2023-2253); a large value is not
needed and is never sent.

**Stage B, one named object:** fetching a manifest and its config blob (image
config carries `ENV` lines and build history, where secrets often sit) or any
layer. **Forbidden:** `PUT`/`POST` to `/v2/<name>/blobs/uploads/` or
`/manifests/` (a push). Whether anonymous push is enabled cannot be proven
without pushing; report the unauthenticated read and ask the client about write.

---

## Quay (self-hosted Project Quay / Red Hat Quay)

```bash
Q="https://target.example"
curl -s -m 15 -o /dev/null -w 'discovery %{http_code}\n' "${Q}/api/v1/discovery"   # (verify)
probe_delay
curl -s -m 15 -o /dev/null -w 'health %{http_code}\n' "${Q}/health/instance"       # (verify)
probe_delay
curl -s -m 15 "${Q}/api/v1/repository?public=true" | jq -r '.repositories[]? | "\(.namespace)/\(.name)"' | head -20  # (verify)
```

Fingerprint by the discovery document and the UI. Public repositories are the
owner's choice; internal names in them are the finding. Account creation is a
`FEATURE_USER_CREATION` setting: never test it. `quay.io` is Red Hat's SaaS and
belongs to `supply-chain-attack-recon`.

---

## Verdaccio (4873)

Verdaccio's shipped `default.yaml` grants `access: $all` and
`publish: $authenticated` on both `@*/*` and `**`, proxies to npmjs, and uses
the htpasswd plugin, whose `max_users` falls back to `Infinity` when unset
(`packages/plugins/htpasswd/src/htpasswd.ts`). So on a default install anyone
can read every package, and `npm adduser` against it creates an account that
may publish (unconfirmed until tested, and testing is Stage B).

```bash
VD="http://target.example:4873"
curl -s -m 15 -o /dev/null -w 'ping %{http_code}\n' "${VD}/-/ping"                         # (verify)
probe_delay
curl -s -m 15 "${VD}/-/v1/search?text=&size=20" | jq -r '.objects[]?.package.name'         # (verify)
```

| Result | Meaning |
|---|---|
| Search lists scoped internal names (`@client/...`) | Internal packages readable by anyone: High. Same names feed `supply-chain-attack-recon` for dependency-confusion checks against npmjs. |
| Default config inferred (no `max_users`, `$authenticated` publish) | Report as "registration and publish likely open, unconfirmed". |

**Stage B:** `npm adduser` (creates an account; requires verified deletion).
**Forbidden:** `npm publish` or `unpublish` against it, under any name.

---

## devpi (3141)

devpi-server's default port is 3141. Indexes live under `/<user>/<index>`,
with `root/pypi` the PyPI mirror.

```bash
DP="http://target.example:3141"
curl -s -m 15 "${DP}/+api" | jq '.'                                     # (verify) server API info
probe_delay
curl -s -m 15 -H 'Accept: application/json' "${DP}/" | jq -r '.result | keys[]'   # users with indexes
```

The user list and index names are the evidence. Two defaults to ask about, not
test: the `root` account's initial password (historically empty unless set at
init; verify per version) and whether anyone may create users (governed by
`--restrict-modify`; verify the default per version). Trying the empty root
password is Stage B; creating a user is Stage B; `devpi upload` is forbidden.

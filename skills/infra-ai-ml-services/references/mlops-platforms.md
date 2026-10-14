# MLOps, orchestration and notebook hubs

MLflow, ClearML, Label Studio, Prefect, Dagster, JupyterHub and
jupyter-server-proxy. Plain Jupyter Server, JupyterLab and Notebook on 8888,
and Airflow, belong to `hunt-exposed-panels`
(`references/data-and-notebook-tools.md`). Do not re-probe them here; this
file adds only the hub layer and the version gates.

Load this file from `SKILL.md` Step 3. Version gates are in
`ai-ml-cve-matrix.md`. Every probe uses the `aiget` helper from `SKILL.md`
Step 1.

## Rules for this file

- These platforms store experiments, datasets, labels, model artifacts and
  pipeline credentials. Read metadata (versions, counts, names); never
  download an artifact, dataset or label export in Stage A.
- Read-only `POST` exceptions are named in the block that uses them (Prefect
  filter queries, Dagster GraphQL read queries). Nothing else is posted.
- Creating an account through open signup, or logging in with a documented
  default password, is Stage B: it is use of an account you were not given.
- Running a job, flow, pipeline or notebook kernel is Stage B, and in
  practice it is not needed: the read-only proof that it is unauthenticated
  already carries the grade.

---

## MLflow tracking server (5000)

| Item | Value | Source |
|---|---|---|
| Bind / port | `--host` default `127.0.0.1` (`MLFLOW_HOST`), `--port` 5000 (`MLFLOW_PORT`) | `mlflow/utils/cli_args.py` (3.x) |
| Authentication | None by default. The optional basic-auth app (`--app-name basic-auth`) shipped `admin` / `password1234` through 3.7.x (CVE-2026-2635); later releases refuse to start without a password | GHSA-gq3w-7jj3-x7gr |
| Host validation | `--allowed-hosts` (`MLFLOW_SERVER_ALLOWED_HOSTS`) protects against DNS rebinding; `/health` and `/version` are exempt | `mlflow/server/security_utils.py` |
| Version oracle | `GET /version` returns the bare version string | same |

False-negative trap: on 3.x with host validation active, a request that
sends the IP in the `Host` header can be rejected while `/health` and
`/version` still answer. Repeat the read-only `GET`s against the hostname
from the scope before you call the API protected.

```bash
# Stage A: read-only GETs.
P=5000; S=http
aiget /health  mlflow_health      # "OK"
aiget /version mlflow_version
aiget '/api/2.0/mlflow/registered-models/search?max_results=5' mlflow_models   # documented GET; names and latest versions
aiget '/api/2.0/mlflow/experiments/search?max_results=5'       mlflow_exps     # GET accepted by the server (verify per version)
```

Reading the results:

- `200` with JSON on the search routes = unauthenticated read and write of the
  whole tracking server. Model names, run parameters and artifact locations
  (`s3://...`, `gs://...`) are the impact. Artifact URIs point at the client's
  bucket; their access is `cloud-iam-deep`'s question, not this file's.
- `401` with `WWW-Authenticate: Basic` = the basic-auth app is on. The
  version decides whether the default password and CVE-2026-2652 (only
  `/gateway/` routes checked under uvicorn) apply.
- KEV CVE-2026-64849 (webhook test SSRF) applies to 3.3.0 up to 3.15.0 on any
  default server. Version gate it. Its trigger is a webhook test request and
  is never sent.

Stage B: one login with the documented default pair on a basic-auth server
below 3.8.0, artifact download, run or model creation, the jobs API under
`/ajax-api/3.0/jobs`, AI Gateway routes (they spend the client's provider
budget). Forbidden: webhook test calls, artifact upload or overwrite, deleting
anything.

---

## ClearML server

| Port | Service (verify ports per deployment) |
|---|---|
| 8080 | Web UI |
| 8008 | API server |
| 8081 | File server |

The ClearML security documentation states that without Web Login
authentication the server does not restrict access, and that the default
deployment ships default secrets in `secure.conf` that must be replaced. The
file server had no authentication before server 1.16.0, even with web login.

```bash
# Stage A: read-only GETs.
P=8080; S=http
aiget /             clearml_web       # login page: a name-only form means no web login is configured (verify UI)
P=8008
aiget /debug.ping   clearml_ping      # API server liveness (verify path)
aiget /server.info  clearml_info      # server version and build (verify path and whether it needs auth)
```

A name-only login page is the finding: anyone who types a name is a user
with access to every project, dataset and stored credential. Do not log in.

Default secrets in `secure.conf` would let anyone sign API tokens. Proving it
means forging a token: forbidden. Report it as a configuration question for
the client whenever web login is absent or the server version predates the
hardening guidance.

Stage B: logging in, any API call that lists tasks or datasets with a
session, any file server download. Forbidden: enqueuing tasks for agents
(code execution on the client's GPU workers).

---

## Label Studio (8080)

| Item | Value | Source |
|---|---|---|
| Version | `GET /api/version/` (JSON) and `/version/` (HTML) (verify whether login is required per release) | |
| Signup | `DISABLE_SIGNUP_WITHOUT_LINK` defaults to `False`: anyone can create an account | `label_studio/core/settings/base.py` |
| Secret key | Hard-coded Django `SECRET_KEY` below 1.8.2 (CVE-2023-43791): session forgery | GHSA-f475-x83m-rx5m |

```bash
# Stage A: read-only GETs.
P=8080; S=http
aiget /api/version/ ls_version
aiget /health/      ls_health
aiget /user/signup/ ls_signup     # a signup form that renders without an invite token = open registration
```

Open registration is a finding when the instance holds client data, which
you cannot see without registering. Grade it as "open registration on a
data-labelling platform" and let the client confirm the data. Registering is
Stage B. Forging a session with the old key is forbidden.

---

## Prefect server (4200)

Open-source Prefect has no authentication unless `PREFECT_SERVER_API_AUTH_STRING`
sets a basic-auth `user:password` pair. The UI and API share port 4200.

```bash
# Stage A: read-only GETs.
P=4200; S=http
aiget /api/health        prefect_health
aiget /api/admin/version prefect_version   # bare version string (verify path per release)
```

```bash
# Stage A, read-only POST (named exception): Prefect's filter endpoints are
# POST by design and return a page of objects without changing anything.
curl -sk -m 15 -o "evidence/${T}_4200_deployments.json" -w '%{http_code}\n' \
  -H 'Content-Type: application/json' -d '{"limit": 5}' \
  "$S://$T:4200/api/deployments/filter"
probe_delay
```

Deployment names, schedules and work pools describe what the server can
run. Parameters may contain secrets: count, redact. Do not call the block
documents API; blocks are the credential store.

The CVE-2026-3514 bypass (paths ending in `health` or `ready` skip the auth
middleware) is a version gate. Do not craft paths to test it.

Stage B: creating a flow run from a deployment. Forbidden: deleting or
pausing deployments, work pools or schedules.

---

## Dagster webserver (3000)

Open-source Dagster has no authentication. `GET /server_info` (and the
legacy `/dagit_info`) returns `dagster_webserver_version`, `dagster_version`
and `dagster_graphql_version`.

```bash
# Stage A: read-only GET.
P=3000; S=http
aiget /server_info dagster_info
```

```bash
# Stage A, read-only POST (named exception): one GraphQL query that lists
# repository and job names (verify field names per release). Queries read;
# only mutations change state.
curl -sk -m 15 -o "evidence/${T}_3000_dagster_repos.json" -w '%{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ repositoriesOrError { ... on RepositoryConnection { nodes { name jobs { name } } } } }"}' \
  "$S://$T:3000/graphql"
probe_delay
```

Stage B: the `launchRun` mutation (code execution on the client's workers).
Forbidden: run termination, asset wipe, schedule and sensor changes.

---

## JupyterHub and jupyter-server-proxy

JupyterHub serves on port 8000 by default through its proxy. `GET /hub/api`
returns `{"version": "..."}` without authentication; `/hub/api/info` needs a
token with the `read:hub` scope.

```bash
# Stage A: read-only GETs.
P=8000; S=http
aiget /hub/api   jhub_version
aiget /hub/login jhub_login     # the login page names the authenticator: OAuth buttons, LDAP form, or plain form
```

A plain username and password form can be the `DummyAuthenticator` (any
password accepted) or a real PAM or LDAP backend; the page alone does not
tell you which. Testing it is a login attempt: Stage B, one attempt with a
username you were given, never a guessed real user.

After a login, each user server is a Jupyter Server; its probes and the
kernel-creation rule are in `hunt-exposed-panels`. `jupyter-server-proxy`
routes look like `/user/<name>/proxy/<port>/`; CVE-2024-28179 (WebSocket
proxying without authentication) is a version gate the client confirms, since
the package version is not visible from outside.

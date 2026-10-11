# Database admin, notebook and data-processing panels

phpMyAdmin, Adminer, Jupyter Server, Apache Spark UI, Apache Flink JobManager,
Apache Airflow. Every one of these is a developer convenience that carries a
code-execution or arbitrary-query primitive as its primary feature. Exposure is
the whole finding; you rarely need to use the primitive to prove it.

Scope note: generic SQL injection is `hunt-sqli`'s (including the Airflow
filter-parameter pattern it already documents). Hadoop NameNode 9870 and YARN
ResourceManager 8088 belong to `hunt-exposed-services`
(`references/databases.md`). Elasticsearch and Kibana likewise.

Rate posture: serial, 2 s base delay plus 0-3 s jitter.

---

## phpMyAdmin

### Fingerprint (Stage A)

```bash
TARGET="target.example"

# Stage A — read-only. One GET per candidate path.
for P in /phpmyadmin/ /phpMyAdmin/ /pma/ /myadmin/ /db/ /sql/; do
  CODE=$(curl -s -m 15 -o /tmp/pma.txt -w '%{http_code}' "https://${TARGET}${P}")
  VER=$(grep -o -m1 'PMA_VERSION[^;]*' /tmp/pma.txt | head -c 60)
  echo "$CODE  $P  $VER"
  sleep 3
done
```

The version lands in two reliable places without authentication: the
`PMA_VERSION` JavaScript variable in the login page source, and
`/phpmyadmin/ChangeLog` or `/phpmyadmin/README` on installs that did not strip
the distribution docs. Record whichever you get, exactly.

### CVE-2018-12613 — file inclusion

phpMyAdmin 4.8.0 and 4.8.1 (NVD: 4.8.0 up to but excluding 4.8.2) contain an
improper whitelist test in the code that redirects and loads pages internally,
allowing an attacker to include — view, and potentially execute — files on the
server. Fixed in 4.8.2
([PMASA-2018-4](https://www.phpmyadmin.net/security/PMASA-2018-4/)).

The authentication requirement is the part that decides the severity, and both
the advisory and NVD state it precisely:

- An attacker **must be authenticated**, except in two configurations.
- `$cfg['AllowArbitraryServer'] = true` — an attacker points phpMyAdmin at a
  database server they control and executes code.
- `$cfg['ServerDefault'] = 0` — bypasses the login requirement and runs the
  vulnerable code with no authentication at all.

So: an exposed 4.8.0 or 4.8.1 with `ServerDefault = 0` is pre-auth code
execution. The same version with normal configuration is a post-auth finding
that you should not try to reach by guessing database credentials. Neither
primary source publishes an example request, so do not invent one — describe the
reachable version and the configuration dependency, and let the client's own
configuration review settle which case applies.

### Setup script and other exposed artefacts

`/phpmyadmin/setup/index.php` is the configuration wizard. Where it is reachable
it writes a `config.inc.php` containing database credentials, so it is a
configuration-write surface: Stage B, and in practice never worth touching. A
`200` on it is itself the finding.

### Where the chain ends

A phpMyAdmin session is arbitrary SQL against the backing database. Running a
query is Stage B. The Stage A evidence that establishes impact without touching
data is the login page plus the server list it renders, and, if the engagement
supplied credentials, the database names visible in the navigation pane.
**Never** run `SELECT` against production tables to "prove" access; a schema
listing proves it. `SELECT ... INTO OUTFILE` and `sys_exec`-style routines are
code execution and write to the filesystem — out of scope for this skill.

---

## Adminer

A single-PHP-file database client, which is why it turns up at unpredictable
paths that were never meant to survive a deployment: `adminer.php`,
`adminer-4.8.1.php`, `db.php`, `_adminer.php`.

```bash
# Stage A — read-only.
for P in /adminer.php /adminer/ /db.php /_adminer.php; do
  CODE=$(curl -s -m 15 -o /tmp/adm.txt -w '%{http_code}' "https://${TARGET}${P}")
  grep -q -i 'adminer' /tmp/adm.txt && echo "$CODE  $P  adminer present"
  sleep 3
done
```

Adminer renders its version in the page footer. Capture it.

**CVE-2021-21311** is server-side request forgery in Adminer from 4.0.0 up to
but excluding 4.7.9, affecting the builds that bundle all database drivers (the
single `adminer.php` distribution). Fixed in 4.7.9.

The route is the login form's server field: Adminer will connect outward to a
host you name, which is the SSRF. Confirming it is `hunt-ssrf`'s protocol — an
out-of-band interaction on a collaborator domain you control, with a unique
subdomain per attempt. The product-specific contribution here is only the
version range and the fact that the SSRF lives in the connection form, so an
unauthenticated attacker reaches it without a valid database credential. Hand
the rest to `hunt-ssrf`, and cross-reference rather than re-deriving the
confirmation gate.

---

## Jupyter Server / JupyterLab

### What the defaults actually are

This is the product where the defaults matter most, because an internet-facing
Jupyter is almost always the result of three deliberate changes rather than one
oversight. From the vendor configuration reference
([full config](https://jupyter-server.readthedocs.io/en/latest/other/full-config.html)):

- `ServerApp.ip` defaults to `'localhost'`.
- `ServerApp.allow_remote_access` defaults to `False`.
- `ServerApp.base_url` defaults to `'/'`.
- `ServerApp.port` defaults to `0`.

Token authentication is **on by default**, and the token may be supplied as a
URL parameter (`?token=...`). Authentication is disabled only by setting both
`c.ServerApp.token = ""` and `c.ServerApp.password = ""`, which the vendor's
security page labels "NOT RECOMMENDED"
([Jupyter Server security](https://jupyter-server.readthedocs.io/en/latest/operators/security.html)).
Note also that enabling a password turns token authentication off.

That gives the report a strong root-cause sentence: a reachable Jupyter with no
token is not a vendor default, it is `ip` rebound plus `allow_remote_access`
flipped plus the token emptied.

### Fingerprint (Stage A)

```bash
# Stage A — read-only. GET /api/ returns the server version only and is
# documented as requiring no authentication.
curl -s -m 15 "https://${TARGET}:8888/api/"
echo; sleep 3

# Unauthenticated-access test: these require auth when a token is configured.
for P in /api/status /api/sessions /api/kernels /api/terminals /api/contents/; do
  CODE=$(curl -s -m 15 -o /tmp/jp.txt -w '%{http_code}' "https://${TARGET}:8888${P}")
  echo "$CODE  $P  $(head -c 160 /tmp/jp.txt | tr -d '\n')"
  sleep 3
done
```

([REST API reference](https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html))

Interpretation:

- `GET /api/` returning a version with no credential is **expected behaviour**,
  not a finding. It is your version oracle.
- `GET /api/sessions` or `/api/kernels` returning a JSON array with no
  credential is unauthenticated access. A `403` means the token is enforced.
- `GET /api/contents/` returning a directory listing is unauthenticated read of
  the notebook tree. Notebooks routinely contain API keys, database URIs and
  sample production data in their saved cell outputs, so name that as the
  impact — and do not download the notebooks.

### Where the chain ends

A running kernel is arbitrary code execution as the Jupyter user, and
`POST /api/kernels` plus a message on the kernel's WebSocket is how you would
use it. **That is Stage B and it is almost never needed.** An unauthenticated
`/api/sessions` listing, plus a `/api/contents/` directory listing, is a
complete Critical: it proves both the access and the code-execution privilege it
implies. `POST /api/terminals` is the same situation with a shell attached.

If execution sign-off exists, the blast radius to name is: code runs as the
account owning the notebook server, a new kernel consumes memory on a possibly
shared GPU or analytics host, and `DELETE /api/kernels/{id}` cleanup is your
responsibility.

---

## Apache Spark UI

The project's security documentation is unusually blunt: "Security features like
authentication are not enabled by default", and "none are secure by default"
([Spark security](https://spark.apache.org/docs/latest/security.html)). Spark
provides no built-in authentication filters; authentication must come from a
custom servlet filter. `spark.authenticate` defaults to `false` and
`spark.acls.enable` defaults to `false`. The application UI is on **4040**
(`spark.ui.port`), and the REST API base is `/api/v1` on that port; the history
server serves the same API on **18080** (`spark.history.ui.port`)
([Spark monitoring](https://spark.apache.org/docs/latest/monitoring.html)).

```bash
# Stage A — read-only. Running application first, then the history server.
curl -s -m 15 "https://${TARGET}:4040/api/v1/applications"  | head -c 600; echo
sleep 3
curl -s -m 15 "https://${TARGET}:18080/api/v1/applications" | head -c 600
```

An exposed history server is the more common of the two, because it is the one
teams deliberately keep running after the jobs finish.

An exposed Spark UI leaks the job graph, the environment tab (which carries
every `spark.*` configuration value, routinely including object-store keys and
JDBC URLs with passwords), the executor list with internal addressing, and the
stdout/stderr logs of every stage.

**CVE-2022-33891** is the pre-auth code-execution route, and its precondition is
counter-intuitive: it needs ACLs **on**. With `spark.acls.enable` set, a code
path in `HttpSecurityFilter` allows impersonation by supplying an arbitrary user
name, and that name reaches a permission-check function that builds a Unix shell
command from it and executes it — arbitrary shell commands as the user Spark
runs as. Affected: 3.0.3 and earlier, 3.1.1 to 3.1.2, 3.2.0 to 3.2.1.

So an exposed Spark UI with ACLs disabled is an information-disclosure finding,
and one in the affected range **with ACLs enabled** is pre-auth RCE. Check the
environment tab for `spark.acls.enable` before you decide which you are looking
at. Executing the injection is Stage B under the SKILL.md Step 6 canary
protocol; the blast radius is a shell command on a cluster node as the Spark
service account.

---

## Apache Flink JobManager

`rest.port` defaults to **8081**, and `rest.address` has no default
([Flink configuration reference](https://nightlies.apache.org/flink/flink-docs-release-1.20/docs/deployment/config/)).
The configuration reference documents no authentication or authorisation for the
REST API or web UI; the only related options are
`security.ssl.rest.enabled` and `security.ssl.rest.authentication-enabled`, both
defaulting to `false`.

```bash
# Stage A — read-only. Note the two different config endpoints: /jobmanager/config
# returns the CLUSTER configuration, while the top-level /config returns only the
# WebUI's own configuration. Ask for the one that matters.
curl -s -m 15 "https://${TARGET}:8081/jobmanager/config" | head -c 500; echo
sleep 3
curl -s -m 15 "https://${TARGET}:8081/jobs/overview" | head -c 400
```

Both are `GET`
([Flink REST API reference](https://nightlies.apache.org/flink/flink-docs-release-1.20/docs/ops/rest_api/)).
The cluster configuration is the valuable one: it carries checkpoint and
savepoint storage URIs, which are object-store paths, and the full set of
`*.dir` and `high-availability.*` settings describing internal infrastructure.

Two verified traversal CVEs, both fixed in 1.11.3 and 1.12.0:

| CVE | Direction | Affected |
|---|---|---|
| CVE-2020-17519 | **Read** any file on the JobManager's local filesystem through the REST interface, limited to files the JobManager process can access. Introduced by a change in 1.11.0. | 1.11.0 up to before 1.11.3 |
| CVE-2020-17518 | **Write** an uploaded file to an arbitrary location on the local filesystem, through a maliciously modified HTTP header. | 1.5.1 up to before 1.11.3 |

CVE-2020-17519 is a Stage A read when you aim it at a predictable file and diff
against a baseline (see SKILL.md Step 4's confirmation gate). CVE-2020-17518 is
a **write** and therefore Stage B: the blast radius is a file planted anywhere
the JobManager user can write, which includes overwriting a Flink configuration
file and taking the cluster down.

Where the chain ends: a Flink cluster accepts job submissions, and a submitted
JAR is code execution on the cluster. Do not submit one. The unauthenticated
`/config` and `/jobs/overview` responses are the finding.

---

## Apache Airflow

Airflow 3 restructured its configuration, so state the version before you quote
a setting name. From the current configuration reference
([configurations-ref](https://airflow.apache.org/docs/apache-airflow/stable/configurations-ref.html)):

- The API server port is `[api] port`, default **8080**
  (`AIRFLOW__API__PORT`).
- `[api] expose_config` defaults to `False`, which hides the configuration
  completely (`AIRFLOW__API__EXPOSE_CONFIG`).
- `[core] auth_manager` defaults to
  `airflow.api_fastapi.auth.managers.simple.simple_auth_manager.SimpleAuthManager`.
- `[api] secret_key` ships as a `{SECRET_KEY}` placeholder rather than a
  concrete value.

```bash
# Stage A — read-only version and auth-posture probe. /api/v2/version and
# /api/v2/monitor/health are both present in Airflow's generated OpenAPI spec
# (airflow-core/.../openapi/v2-rest-api-generated.yaml).
curl -s -m 15 "https://${TARGET}:8080/api/v2/version" | head -c 300; echo
sleep 3
curl -s -m 15 "https://${TARGET}:8080/api/v2/monitor/health" | head -c 300; echo
sleep 3
curl -s -m 15 -o /dev/null -w 'login %{http_code}\n' "https://${TARGET}:8080/login/"
```

On an Airflow 2.x instance those paths are under `/api/v1/` instead. Try the
version endpoint under both prefixes before concluding the API is disabled.

Three things to look for, in order of value:

1. **An unauthenticated UI.** A DAG list reachable without a session is a
   Critical: DAG code, connection names, variable names and task logs are all
   visible, and task logs are where Airflow leaks credentials most often.
2. **`expose_config` turned on.** The default is `False`, so a rendered
   configuration page means someone enabled it. The page carries the metadata
   database URI and the Fernet key, which decrypts every stored connection
   password.
3. **A default or placeholder `secret_key`.** A known signing key means
   forgeable session cookies. You can report the placeholder-default risk from
   the configuration page without forging anything.

Where the chain ends: triggering a DAG executes code on worker nodes. That is
Stage B with a named blast radius — a DAG may move production data, call
third-party APIs or spend money — and it is unnecessary, because a visible DAG
list already proves the privilege. Airflow's authenticated SQL-injection pattern
is already documented in `hunt-sqli`; cross-reference it rather than repeating
it.

---

## Cross-references

- `hunt-sqli` — query injection, and the Airflow filter-parameter case.
- `hunt-ssrf` — the confirmation gate for Adminer CVE-2021-21311, and for
  Prometheus or Consul reached through a web application rather than directly.
- `hunt-lfi` — traversal mechanics behind Flink CVE-2020-17519 and phpMyAdmin
  CVE-2018-12613.
- `hunt-exposed-services` — the database ports themselves (3306, 5432, 9200),
  Hadoop and YARN.
- `hunt-rce` — generic command-execution confirmation discipline.
- `hunt-source-leak` — notebooks, DAG source and job JARs as leaked source.

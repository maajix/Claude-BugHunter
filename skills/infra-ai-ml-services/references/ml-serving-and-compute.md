# ML serving and distributed compute

Ray (dashboard, Jobs API, Ray Client, GCS, Serve), TorchServe, NVIDIA Triton
Inference Server, BentoML, and the Kubernetes-hosted stack (Kubeflow
Pipelines, KServe, Seldon).

Load this file from `SKILL.md` Step 3. Version gates are in
`ai-ml-cve-matrix.md`. Every probe uses the `aiget` helper from `SKILL.md`
Step 1.

## Rules for this file

- These products execute code by design. Ray's own security page says anyone
  who can reach the dashboard, Jobs or Client port can run arbitrary code on
  the cluster. The finding is proven by read-only signals (authentication
  mode, a job list, a model list), never by submitting work.
- Inference requests are Stage B for the same reasons as in
  `llm-inference-servers.md`: GPU cost and eviction of production models.
- Binary and gRPC ports (Ray Client 10001, Ray GCS 6379, Triton gRPC 8001,
  TorchServe gRPC 7070/7071) are proven by the TCP connect in the port scan.
  Do not speak their protocol: a Ray Client connection is a driver session,
  which is code execution.
- Destructive routes are named in prose only. No request in this file stops,
  deletes, unloads or scales anything, signed off or not.

---

## Ray

| Port | Service | Protocol |
|---|---|---|
| 8265 | Dashboard and Jobs REST API | HTTP |
| 10001 | Ray Client server (`ray://`) | gRPC |
| 6379 | GCS server (head node) | gRPC, **not Redis** |
| 8000 | Ray Serve HTTP proxy (the client's deployed apps) | HTTP |

Authentication: none before 2.52.0. Token authentication exists from 2.52.0
(`RAY_AUTH_MODE=token`); 2.59 turns it on by default for local clusters only,
and the Ray docs say 2.61 extends the default to all clusters.
`RAY_AUTH_MODE=disabled` opts out. CVE-2023-48022 ("ShadowRay") is the
unauthenticated Jobs API itself; it is disputed and not in KEV, and it is
still the finding.

```bash
# Stage A: read-only GETs. The first one decides the grade.
P=8265; S=http
aiget /api/authentication_mode ray_authmode   # {"authentication_mode": "disabled"} or "token"; public by design
aiget /api/version             ray_version    # ray_version, ray_commit, session_name
aiget /api/cluster_status      ray_cluster    # node count, CPU/GPU totals, autoscaler state
aiget /api/jobs/               ray_jobs       # job list; entrypoint and runtime_env can hold secrets: count, redact
aiget /api/serve/applications/ ray_serve      # deployed Serve apps and their routes (404 when Serve is not running)
```

Reading the results:

- `"authentication_mode": "disabled"` with `200` on `/api/jobs/` is the full
  finding: unauthenticated code execution on every node, GPU access, and every
  secret in job environments. That grade needs no submission.
- `"token"` with `401` on `/api/jobs/` is the patched posture. Report version
  gates only.
- The job list shows what the cluster runs (training scripts, S3 buckets,
  model names). Record counts and one redacted example. If an entrypoint shows
  a cryptominer or an unknown `curl | sh`, stop and escalate: the cluster is
  already compromised (ShadowRay campaigns).
- 6379 on a Ray head is GCS, not Redis. If `hunt-exposed-services` tried a
  Redis `PING` there and got no `+PONG`, check 8265 on the same host before
  calling the port unknown.

Not Stage A, although they are `GET`: `/worker/cpu_profile`,
`/task/cpu_profile`, `/worker/gpu_profile`, `/worker/jax_profile`,
`/memory_profile`, `/worker/traceback`, `/task/traceback`. They attach a
profiler or debugger to live worker processes, and CVE-2023-6019 was command
injection in exactly that parameter. Also skip `/api/v0/logs` and
`/api/jobs/{id}/logs` unless signed off: they return training output and
often credentials.

Stage B (sign-off from `SKILL.md` Step 6): `POST /api/jobs/` (job
submission), `PUT /api/packages/...` (upload a runtime_env package),
`PUT /api/serve/applications/` (deploy), any Ray Client connection on 10001.
Forbidden: stopping or deleting jobs, deleting Serve applications
(CVE-2026-27482 made those reachable without the browser guard below 2.54.0).

---

## TorchServe

| Port | API | Default bind |
|---|---|---|
| 8080 | Inference | `127.0.0.1` |
| 8081 | Management (register, scale, unregister models) | `127.0.0.1` |
| 8082 | Metrics | `127.0.0.1` |
| 7070 / 7071 | gRPC inference / management | localhost from 0.11.0; all interfaces before (CVE-2024-35199) |

From 0.11.0, token authorization is on by default (disabled by
`--disable-token-auth`, `TS_DISABLE_TOKEN_AUTHORIZATION=true` or
`disable_token_authorization=true`), and the model API that registers and
deletes models is off by default (`enable_model_api=false`). The project is in
limited maintenance and archived: nothing will be patched.

```bash
# Stage A: read-only.
P=8080; S=http
aiget /ping ts_ping          # {"status": "Healthy"}; the inference port fingerprint
P=8081
aiget /models ts_models      # 401/403 = token auth on; 200 = management API open
P=8082
aiget /metrics ts_metrics    # Prometheus series name models and the host
```

The API description is served on `OPTIONS /` of the inference and management
ports, and its OpenAPI `info.version` is the TorchServe version (verify per
release). It is read-only:

```bash
# Stage A, read-only OPTIONS on the management port.
curl -sk -m 15 -X OPTIONS -o "evidence/${T}_8081_api_description.json" \
  -w '%{http_code}\n' "$S://$T:8081/"
probe_delay
```

Grading: management `200` without a token on a version below 0.11.0 is the
ShellTorch posture (CVE-2023-43654): model registration from any URL. On
0.11.0 and later, `200` means someone disabled token auth by hand.

Stage B: `POST /predictions/{model}` (inference), `POST /models?url=...`
(registering a model from a URL is the ShellTorch exploit path, so it is a
Stage B item that is in practice not run), `PUT /models/{name}` (scaling
workers). Forbidden: `DELETE /models/{name}`.

---

## NVIDIA Triton Inference Server

| Port | Service |
|---|---|
| 8000 | HTTP/REST (KServe v2 protocol) |
| 8001 | gRPC |
| 8002 | Prometheus metrics |

No authentication beyond optional per-API header keys
(`--http-restricted-api=<api>:<header>=<value>`). Model control mode defaults
to `none` (`--model-control-mode=none`); `explicit` and `poll` enable the
repository load and unload APIs.

```bash
# Stage A: read-only GETs.
P=8000; S=http
aiget /v2                   triton_meta     # {"name":"triton","version":"2.x.y","extensions":[...]}
aiget /v2/health/ready      triton_ready
aiget /v2/models/stats      triton_stats    # every loaded model with request counts
P=8002
aiget /metrics              triton_metrics  # nv_gpu_* series: GPU model and memory, per-model counters
```

```bash
# Stage A, read-only POST (named exception): the model repository index lists
# every model in the repository, loaded or not, and changes nothing.
curl -sk -m 15 -o "evidence/${T}_8000_repo_index.json" -w '%{http_code}\n' \
  -H 'Content-Type: application/json' -d '{}' "$S://$T:8000/v2/repository/index"
probe_delay
```

For at most three models from the index, `aiget /v2/models/<name>/config`.
A `"backend": "python"` model on a version before 25.07 is the condition of
the Wiz chain (CVE-2025-23319/23320/23334). The `extensions` list in `/v2`
tells you which APIs exist; a restricted API returns an error naming the
missing header rather than `404` (verify the exact status).

Mapping the server `version` (`2.x.y`) to a container release (`YY.MM`) uses
NVIDIA's release notes; do it from the documentation, not by probing.

Stage B: `POST /v2/models/<name>/infer` and `/generate` (inference).
Forbidden: repository load and unload, shared-memory region register and
unregister, `POST` to the logging and trace settings APIs. Those are the
primitives of the 2024 and 2025 chains and they change server state.

---

## BentoML

Default `bentoml serve` port 3000 (verify per deployment); no built-in
authentication on the open-source server (verify). Infrastructure routes
(verify each per release):

```bash
# Stage A: read-only GETs.
P=3000; S=http
aiget /healthz   bento_health
aiget /readyz    bento_ready
aiget /docs.json bento_openapi   # OpenAPI: service name, every API route and its input type
aiget /metrics   bento_metrics
```

The OpenAPI document names the service and its routes. An input type of
file or image with a URL field is the SSRF condition of CVE-2025-54381.
BentoML has no dedicated version endpoint that was confirmed (verify);
`info.version` in the OpenAPI document is the Bento's own tag, not the
framework version.

Stage B: every service API route (inference). Forbidden: any request with a
pickle content type. CVE-2025-27520 and CVE-2024-2912 are pickle
deserialization, so the trigger is the exploit.

---

## Kubeflow Pipelines, KServe, Seldon

These run inside Kubernetes behind an Istio, Knative or NGINX ingress. The
external question is what the ingress exposes without login. Cluster plane
work (API server, kubelet, service accounts, `storageUri` SSRF from the
controller) belongs to `hunt-k8s`.

| Component | External signal | Notes |
|---|---|---|
| Kubeflow central dashboard | HTML title "Kubeflow Central Dashboard" (verify) | Standard manifests put Dex or oauth2-proxy in front (verify). A redirect to `/dex/auth` is the healthy state |
| KFP UI / frontend | `/pipeline/` path, `/_proxy/` route | CVE-2026-54745: `/_proxy/` forwards arbitrary requests up to kfp-frontend 2.16.0 |
| KServe predictor, V1 protocol | `GET /v1/models/<name>` returns `{"name":..., "ready":...}` | Host-based routing; the hostname usually encodes `<model>.<namespace>` (verify) |
| KServe / Seldon MLServer, V2 (Open Inference Protocol) | `GET /v2` returns name, version, extensions | Same probes as Triton's `GET` set |

```bash
# Stage A: read-only GETs, only on a hostname that resolved to the client.
aiget /           kf_root          # dashboard HTML or an auth redirect
aiget /v2         kserve_v2_meta   # Open Inference Protocol server metadata
aiget /v2/health/ready kserve_v2_ready
```

`/_proxy/` is never requested, with any target: one request through it is
the CVE-2026-54745 exploit. Version gate it from the frontend version shown
in the UI or its static asset names.

Stage B: creating runs, uploading pipelines, inference against predictors.

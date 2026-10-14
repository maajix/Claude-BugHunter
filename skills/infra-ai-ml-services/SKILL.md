---
name: infra-ai-ml-services
description: "Triage internet-exposed AI/ML serving, training, orchestration and agent-builder services: Ollama 11434, vLLM, TGI, llama.cpp, LiteLLM and OpenAI-compatible endpoints, Ray (ShadowRay CVE-2023-48022), MLflow, JupyterHub, Gradio, ComfyUI, Open WebUI, Langflow (CISA KEV), Flowise, Dify, n8n, and MCP servers over SSE or Streamable HTTP. The finding is unauthenticated access plus what it exposes: model lists, system prompts, provider keys, tool lists, unclaimed first-run admin. Stage A reads version and config endpoints only. Use when a scan or JS bundle shows one of these on an in-scope host."
metadata:
  sources: nvd, cisa_kev, github_advisories, osv, vendor_documentation, project_source, bugcrowd_vrt
  report_count: 0
---

## When to use

Trigger when external recon has produced an AI/ML service on a host you are
authorized to test and you need to decide whether that service is a finding.
The finding here is **the exposure plus what it leaks or grants**: a model
server that answers without a credential, a dashboard that submits jobs for
anyone, an agent builder with no owner account yet, an MCP server whose tool
list includes a shell. Not an exploit you wrote.

Use when any of these is true:

- A port scan, Shodan or Censys record shows 11434, 8265, 8000-8002, 8080-8082,
  5000, 7860, 8188, 4200, 3000, 3001, 5678, 1234 or 50052 with an HTTP banner
  that is not a plain web app.
- A JS bundle, mobile app, docker-compose file or CI log names an internal
  model endpoint, an MCP URL or a Gradio share link (`hunt-source-leak`,
  `offensive-osint`).
- The target's product has a chat, copilot or document-QA feature and you want
  the serving layer behind it, not the chat window (that is `hunt-llm-ai`).
- The client says a GPU box or notebook server is "internal only" and it
  answers from outside.

**Do not use this skill for discovery.** Host and port discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation to `recon-scope-triage`.
This skill starts from "a service answers on an in-scope host".

### Where the chain ends

This skill stops at **unauthenticated access confirmed, what it exposes
described, evidence captured**. Nothing here runs a model, submits a job,
pulls or pushes a model, calls a tool, uploads a file or creates an account
outside a signed-off Stage B item. If a listing endpoint answers with no
credential, the finding is already complete. Write it up and stop.

### Not covered here, on purpose

- Prompt injection, jailbreaks, system-prompt extraction through the model,
  tool poisoning, data exfiltration through model output: `hunt-llm-ai`.
- Vector databases (Chroma, Qdrant, Weaviate, Milvus, pgvector): `hunt-rag-vector`.
- Plain Jupyter Server and JupyterLab on 8888, Airflow: `hunt-exposed-panels`
  (`references/data-and-notebook-tools.md`). JupyterHub's delta is here.
- The Kubernetes side of Kubeflow, KServe and Ray-on-K8s: `hunt-k8s`.
- Spark, Flink, NiFi, Zeppelin, Livy and the Hadoop family: `infra-data-platforms`.
- Redis on 6379 when it is really Redis: `hunt-exposed-services`
  (`references/databases.md`). Ray's GCS also sits on 6379; Step 3 tells them apart.
- Validating a provider API key you read from a config: `cloud-iam-deep`.
- Credential guessing of any kind: `hunt-brute-force`.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/ai-ml-cve-matrix.md` | 2023-2026 version-gate table for every product in this skill with KEV status (catalog 2026.10.13), unauthenticated-or-not column, affected and fixed versions, GHSA sources; the twelve-row KEV escalation set; MCP SDK rows | shadowray, cve-2023-48022, shelltorch, ollama cve, langflow kev, cve-2025-3248, mlflow cve, litellm mcp, triton cve, gradio file read |
| `references/llm-inference-servers.md` | Ollama, vLLM, TGI, llama.cpp server and RPC, LM Studio, LiteLLM, any OpenAI-compatible endpoint: ports, default binds, version and model-list endpoints, what the listing leaks | ollama 11434, /api/tags, /v1/models no auth, vllm exposed, litellm proxy, lm studio 1234, ggml-rpc |
| `references/ml-serving-and-compute.md` | Ray dashboard, client and GCS ports, TorchServe three-port layout, NVIDIA Triton `/v2` API, BentoML, Kubeflow Pipelines, KServe, Seldon | ray dashboard 8265, ray jobs api, torchserve 8081, triton 8000, bentoml, kubeflow pipelines exposed |
| `references/mlops-platforms.md` | MLflow tracking server, ClearML server, Label Studio, Prefect, Dagster, JupyterHub and jupyter-server-proxy | mlflow 5000 no auth, clearml 8008, label studio exposed, prefect 4200, dagster graphql, jupyterhub /hub/api |
| `references/ai-web-uis.md` | Gradio and Hugging Face Spaces, ComfyUI, Open WebUI, AnythingLLM: config and status endpoints, unclaimed-admin states, share links | gradio /config, gradio.live, comfyui 8188, open webui onboarding, anythingllm setup |
| `references/agent-builders-and-mcp.md` | Langflow, Flowise, Dify, n8n status and version endpoints, owner-setup states, webhook surfaces; MCP servers over SSE and Streamable HTTP, protected-resource metadata, `initialize` and `tools/list`, MCP Inspector proxy | langflow auto_login, flowise chatflows, dify setup not_started, n8n /rest/settings, mcp server exposed, /sse endpoint, tools/list, mcp inspector 6277 |

---

## Step 1 — Inherit the host and port, define the helper

Take the host from the signed scope document and the port from recon. Confirm
IP ownership (ASN, WHOIS/RDAP, reverse DNS) before the first packet. Hugging
Face Spaces, `*.gradio.live` share links, Replicate and hosted notebook
providers are third-party infrastructure; they are in scope only when the
program names them.

### Rate posture

Each GPU-backed service runs one request at a time per worker. A single
inference request can evict the production model from VRAM. Stage A therefore
sends **GET requests only** (plus the two read-only POSTs named in the
references: Ollama `/api/show` and the MCP `initialize` handshake), serial,
spaced, capped at 30 requests per host.

Every reference in this skill calls one helper. Define it once per host:

```bash
T=TARGET-HOST; P=PORT; S=http          # S=https where TLS answers
UA="assessment/<engagement-id>"
mkdir -p evidence
aiget() {                                # aiget <path> <label>: one logged, read-only GET
  sleep 3
  curl -s -m 15 -A "$UA" -o "evidence/$2.json" \
    -w "$(date -u +%FT%TZ) %{http_code} $S://$T:$P$1\n" "$S://$T:$P$1" | tee -a evidence/aiget.log
}
```

No `-sC`, no `-A`, no `vuln` or `exploit` NSE categories, no nuclei template
whose request body is an inference or job call. Name every script and
template you run.

---

## Step 2 — Prove the exposure is real, external, the client's

- Probe from outside every client VPN and office range; record the egress IP.
- Fingerprint the product before anything else: `GET /` title, `Server`
  header, and the one version endpoint per product in Step 3. A reverse proxy
  that returns the same page for every path is not an exposed model server.
- Decide whether an authenticating front door exists: `401`/`403` with a
  `WWW-Authenticate` header, a login form at `/`, or an `auth=` login page
  (Gradio) ends Stage A at "exposed, authenticated" unless a documented
  bypass row in the matrix applies by version.
- Note which other ports on the host belong to the same product (Ray 8265 +
  10001 + 6379; TorchServe 8080 + 8081 + 8082; Triton 8000 + 8001 + 8002).
  One finding per product, not per port.

---

## Step 3 — Stage A: read-only fingerprint, routed by product

| Port or path seen | Product | Reference | First Stage A probe |
|---|---|---|---|
| 11434 | Ollama | `references/llm-inference-servers.md` | `aiget /api/version`, `aiget /api/tags` |
| 8000 `/v1/models`, `/docs` | vLLM, TGI, generic OpenAI-compatible | `references/llm-inference-servers.md` | `aiget /v1/models`, `aiget /version` |
| 8080 `/health`, `/info` | TGI | `references/llm-inference-servers.md` | `aiget /info` |
| 8080 or 9931 (verify) `/props` | llama.cpp `llama-server`; 50052 `ggml-rpc-server` | `references/llm-inference-servers.md` | `aiget /props`, `aiget /v1/models` |
| 1234 | LM Studio | `references/llm-inference-servers.md` | `aiget /v1/models` |
| 4000 `/health/readiness` | LiteLLM proxy | `references/llm-inference-servers.md` | `aiget /health/readiness` (KEV rows, version gate only) |
| 8265 dashboard, 10001 client, 6379 GCS, 8000 Serve | Ray | `references/ml-serving-and-compute.md` | `aiget /api/version`, `aiget /api/cluster_status` |
| 8080 inference, 8081 management, 8082 metrics, 7070/7071 gRPC | TorchServe | `references/ml-serving-and-compute.md` | `aiget /ping` on 8080, `aiget /models` on 8081 |
| 8000 HTTP, 8001 gRPC, 8002 metrics `/v2` | NVIDIA Triton | `references/ml-serving-and-compute.md` | `aiget /v2`, `aiget /v2/health/ready` |
| 3000 `/healthz`, `/docs` with Bento title | BentoML | `references/ml-serving-and-compute.md` | `aiget /healthz`, `aiget /metadata` |
| `/pipeline`, `/apis/v1beta1`, `/v1/models` on a K8s ingress | Kubeflow Pipelines, KServe, Seldon | `references/ml-serving-and-compute.md` | `aiget /apis/v2beta1/healthz` then `hunt-k8s` |
| 5000 `/api/2.0/mlflow` | MLflow | `references/mlops-platforms.md` | `aiget /version`, `aiget /api/2.0/mlflow/experiments/search?max_results=1` |
| 8080 web, 8008 API, 8081 fileserver | ClearML | `references/mlops-platforms.md` | `aiget /debug.ping` on 8008 |
| 8080 `/api/version` with Label Studio title | Label Studio | `references/mlops-platforms.md` | `aiget /api/version` |
| 4200 `/api/health` | Prefect | `references/mlops-platforms.md` | `aiget /api/health`, `aiget /api/version` |
| 3000 `/graphql` with Dagster title | Dagster | `references/mlops-platforms.md` | `aiget /server_info` |
| 8000 `/hub/api` | JupyterHub | `references/mlops-platforms.md` | `aiget /hub/api` |
| 7860 `/config` | Gradio, Hugging Face Space | `references/ai-web-uis.md` | `aiget /config` |
| 8188 `/system_stats` | ComfyUI | `references/ai-web-uis.md` | `aiget /system_stats` |
| 8080 or 3000 `/api/config` with Open WebUI title | Open WebUI | `references/ai-web-uis.md` | `aiget /api/config` |
| 3001 `/api/ping` | AnythingLLM | `references/ai-web-uis.md` | `aiget /api/setup-complete` |
| 7860 `/api/v1/version` with Langflow title | Langflow | `references/agent-builders-and-mcp.md` | `aiget /api/v1/version`, `aiget /api/v1/config` |
| 3000 `/api/v1/ping` with Flowise title | Flowise | `references/agent-builders-and-mcp.md` | `aiget /api/v1/chatflows` (count only) |
| `/console/api/setup` | Dify | `references/agent-builders-and-mcp.md` | `aiget /console/api/setup` |
| 5678 `/healthz` | n8n | `references/agent-builders-and-mcp.md` | `aiget /rest/settings` |
| `/mcp`, `/sse`, `/messages`, 6277 | MCP server, MCP Inspector proxy | `references/agent-builders-and-mcp.md` | `aiget /.well-known/oauth-protected-resource`, `initialize` handshake |

Ports 8000, 8080, 3000 and 7860 are shared by several products: the title and
the first probe decide, never the port. A 6379 that refuses `PING` and sits
beside an 8265 is Ray, not Redis.

### Tools that look like Stage A and are not

- Any `POST /v1/chat/completions`, `/api/generate`, `/api/chat`,
  `/v1/embeddings`, `/predictions/*`, `/v2/models/*/infer`, `/gradio_api/call/*`,
  `/prompt` (ComfyUI), `/api/v1/prediction/*` (Flowise), `/webhook/*` (n8n),
  `tools/call` (MCP). Each one is inference or execution: Stage B.
- `ollama pull`, `POST /api/pull`, `/api/push`, `/api/create`, TorchServe
  `POST /models?url=`, Triton `/v2/repository/models/*/load`: they fetch or
  load models from URLs you chose, and some of those are the CVE triggers.
- Ray `POST /api/jobs/`, Prefect deployment runs, Dagster launches, Kubeflow
  pipeline runs, n8n `/setup`, Dify `POST /console/api/setup`, any signup.
- Gradio `/file=` and `/gradio_api/file=` with a path you chose, MLflow
  artifact routes with `..`, Label Studio and ClearML file-serving routes with
  absolute paths: the file-read CVEs. Version gate only.
- nuclei templates under `http/vulnerabilities/` for these products: read the
  request body first; most send an inference or a traversal.

---

## Step 4 — Read the results

### 4a. Authentication posture

The grade turns on one question per product: does the listing endpoint answer
with no credential on the default configuration? The references give the
expected `200` body per product. Record the exact request, the status and the
first line of the body. A `401` with `WWW-Authenticate`, a login redirect or a
Gradio login page ends the product at "exposed, authenticated".

### 4b. Version gate

Every version string goes against `references/ai-ml-cve-matrix.md`. A version
inside an affected range is "version in range, unconfirmed" until the client
confirms the installed package. The twelve KEV rows (Langflow, n8n, Ray,
MLflow, LiteLLM) are same-day escalation. DoS-class rows are never tested.
Client-side rows (`mcp-remote`, MCP Inspector XSS, Ray dashboard DNS rebinding
CVE-2025-62593) need a victim and are not evidence against an exposed server.

### 4c. What the listing leaks

- **Model names and Modelfiles / chat templates** (Ollama `/api/show`, LM
  Studio): system prompts are client data; quote the first line at most.
- **Provider keys and connection strings** in config endpoints (Open WebUI
  `/api/config`, AnythingLLM settings, Langflow config, n8n settings, MLflow
  webhooks): record the key name and the first four characters, never the
  value. Validation is `cloud-iam-deep`'s.
- **Job, experiment, flow and workflow listings**: count them; do not fetch
  parameters, artifacts, logs or flow JSON.
- **Tool lists** (MCP `tools/list`, Flowise and Langflow flow nodes): names and
  descriptions are the evidence; a shell, filesystem, database or HTTP-fetch
  tool makes the exposure Critical on the listing alone.
- **Unclaimed first-run admin** (Open WebUI `onboarding: true`, AnythingLLM
  with no password, Dify `not_started`, n8n owner setup pending, Langflow
  `auto_login`): reported from the status endpoint. Never claim it.

### 4d. Cost and resource exposure

An OpenAI-compatible endpoint with no key behind LiteLLM or a gateway spends
the client's upstream budget; a bare Ollama or vLLM spends their GPU. Say which
in the impact statement. The model list proves it without a single prompt.

---

## Step 5 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Unauthenticated job, flow or code submission surface (Ray Jobs API, TorchServe management, Triton repository API, Kubeflow runs, Langflow `auto_login`, MCP `tools/list` with shell/file/DB tools) | Critical |
| Unclaimed first-run admin on any product | Critical |
| Unauthenticated listing exposes provider keys, connection strings or system prompts | High to Critical, by what the key reaches |
| Version in range of a KEV-listed unauthenticated row (Langflow, MLflow, LiteLLM) | High, unconfirmed; same-day client notice |
| Unauthenticated inference endpoint (model list answers, no key), no secrets visible | High (cost and abuse), Medium when rate-limited or air-gapped from paid upstreams |
| Version in range of a non-KEV unauthenticated RCE or file-read row (ShadowRay, ShellTorch, Triton, Ollama, Gradio) | High, unconfirmed |
| Unauthenticated metrics, health or experiment metadata only | Low to Medium |
| Authenticated version in range of an authenticated-only row | Medium, patch item |
| Service exposed, authenticated, current version | Not a finding |

### What is not a finding

- **Version disclosure alone** (`/api/version`, `/version`, `/props`):
  HackerOne core ineligible, Bugcrowd VRT P5.
- **An OpenAI-compatible endpoint behind a working API key**: that is the
  design.
- **Ray's own documentation says the dashboard is not meant to be exposed**;
  the finding is still the exposure, but ShadowRay is reported as a design
  posture plus version, not as a CVE you confirmed.
- **Client-side CVEs** against a victim developer, as in 4b.
- **Gradio share links** found in OSINT: the leak of the link is the finding,
  the tunnel host belongs to Gradio.
- **Rate limiting missing on inference**: out of scope on most programs;
  mention it inside the unauthenticated-inference finding, not separately.

---

## Step 6 — Stage B: anything that runs, submits, pulls, uploads or signs up

Stage B needs **written sign-off naming the product, the host, the single
request and the expected side effect**, logged before the request. Each item
is run once. Items marked forbidden are never run.

| Item | Single demonstration under sign-off | Forbidden |
|---|---|---|
| B1. Unauthenticated inference | One `chat/completions` with `max_tokens: 1` and a fixed marker prompt against the smallest listed model | Any prompt that asks for data, long outputs, loading an unloaded model |
| B2. Job or flow submission (Ray, Prefect, Dagster, Kubeflow, Langflow, Flowise, n8n) | One job that writes a canary file or echoes a marker and exits, on a runner the client named | Anything that reads the filesystem, environment or network; loops; GPU jobs |
| B3. Model management (Ollama, TorchServe, Triton) | `GET` of the model list is already the proof; at most a `POST /models` pointing at a client-provided URL | Pull or push from any URL you chose; the traversal and SSRF CVE triggers |
| B4. MCP tool call | One `tools/call` of a documented no-op or echo tool | Shell, filesystem, database, fetch tools; `sampling/*`; session-id reuse |
| B5. File read rows (Gradio, MLflow, Label Studio, ClearML, Langflow) | One read of a file the client named, on a non-production replica | Any path you chose; `/etc/passwd`; traversal fuzzing |
| B6. Account creation | Never. Unclaimed admin is reported from the status endpoint. | Signup, `/setup`, `POST /console/api/setup`, claiming an owner |
| B7. DoS-class rows | Never. Version only. | Any trigger |

---

## Step 7 — Evidence

Follow `evidence-hygiene`. Minimum per finding: `evidence/aiget.log` with the
timestamped requests and egress IP, the version endpoint body, the listing
endpoint body with secrets and prompts redacted to key names and first lines,
and for Stage B the sign-off record plus the single request and response.
Never include generated images, chat history, artifacts, flow JSON or
workflow exports. Tell the client to rotate any provider key that was
readable, whether or not you validated it.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| Internal model URL in a JS bundle or APK (`hunt-source-leak`) | Endpoint answers from outside with no key | High | Report; `hunt-llm-ai` for the app that uses it |
| Open WebUI, AnythingLLM, Langflow or n8n config exposes a provider key | Key is live | Critical | `cloud-iam-deep` validates read-only |
| Ray dashboard 8265 with no auth | Jobs API submits code on the head node | Critical | Report from the listing; B2 only on a client runner |
| MCP server with no auth and a shell or DB tool | Tool list alone | Critical | Report; `hunt-llm-ai` for poisoning of the client that uses it |
| MLflow, ClearML, Label Studio with no auth | Experiment and dataset metadata, artifact paths, S3 URIs | High | `hunt-cloud-misconfig` for the bucket |
| Gradio `/config` with a URL-taking endpoint | SSRF row by version | High, unconfirmed | `hunt-ssrf` if the client signs off |
| Dify, n8n, Open WebUI with setup not finished | First visitor becomes admin | Critical | Report the state; never claim it |
| Kubeflow or KServe on an ingress | Cluster-level surface | Decided by `hunt-k8s` | Hand off |
| Ollama with a Modelfile `SYSTEM` prompt | Business logic and tool secrets in the prompt | Medium to High | `hunt-llm-ai` |

---

## Validation checklist

- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Host confirmed client-owned and in the signed scope; third-party hosts
      (Spaces, `gradio.live`, hosted notebooks) tested only when the program names them.
- [ ] Product fingerprinted from the title and version endpoint, not the port.
- [ ] Stage A was `GET` only plus the two named read-only POSTs, serial, at
      most 30 requests per host, every request in `evidence/aiget.log`.
- [ ] No completion, embedding, job, flow, pull, push, upload, signup or tool
      call outside a logged sign-off.
- [ ] No CVE trigger endpoint was requested; every CVE claim is a version gate
      labelled unconfirmed.
- [ ] Shared ports (8000, 8080, 3000, 7860, 6379) were disambiguated before reporting.
- [ ] Secrets, prompts, histories and artifacts redacted to names, counts and first lines.
- [ ] Unclaimed first-run admin reported from the status endpoint; no account created.
- [ ] Client-side and DoS-class rows were not reported against the server.
- [ ] Not reporting version disclosure, missing rate limiting or an
      authenticated current service as a vulnerability.
- [ ] The report ends at access proven plus what it exposes. No post-access content.

---

## Sources

Primary sources (fetched 2026-10-13): CISA KEV catalog 2026.10.13, NVD and
cvelistV5 records, GitHub advisories and OSV for the PyPI, npm and Go packages
named in the matrix, each product's documentation and source repository for
ports, default binds and endpoints, the MCP specification (revision
2025-06-18) for transports and authorization, Bugcrowd VRT and HackerOne core
ineligible findings for grading.

---

## Related Skills & Chains

- `hunt-llm-ai` — everything that goes through the model: prompt injection,
  tool poisoning, system-prompt extraction, exfiltration. This skill stops at
  the serving layer.
- `hunt-rag-vector` — vector databases and retrieval stores behind these UIs.
- `hunt-exposed-panels` — plain Jupyter, Airflow and the login-page triage of
  every web UI named here.
- `hunt-exposed-services` — Redis, databases and brokers these stacks sit on;
  its Stage A/B model is the template for this skill.
- `infra-data-platforms` — Spark, Flink, NiFi, Zeppelin, Livy, Hadoop.
- `hunt-k8s` — Kubeflow, KServe, Ray-on-K8s and every ingress-level finding.
- `cloud-iam-deep`, `hunt-cloud-misconfig` — provider keys and bucket URIs
  read from a config or an experiment record.
- `hunt-source-leak`, `offensive-osint`, `web2-recon` — where the endpoint
  URLs, share links and MCP configs come from.

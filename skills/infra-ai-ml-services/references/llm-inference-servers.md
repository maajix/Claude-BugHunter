# LLM inference servers and OpenAI-compatible endpoints

Ollama, vLLM, Hugging Face TGI, llama.cpp (`llama-server` and `ggml-rpc-server`),
LM Studio, LiteLLM proxy, and any other server that answers `GET /v1/models`.

Load this file from `SKILL.md` Step 3 once the fingerprint names one of these
products. Version gates for every product here are in `ai-ml-cve-matrix.md`.

## Rules for this file

- Stage A is `GET` only, plus the read-only `POST` named in a block's comment
  (Ollama `/api/show`). Every probe uses the `aiget` helper from `SKILL.md`
  Step 1, so each request is logged, serial and spaced.
- **No completion, chat, embedding or tokenize request in Stage A.** Each one
  spends GPU time, can load a model into VRAM and evict the one production
  traffic uses, and behind LiteLLM or any gateway spends the client's money at
  an upstream provider. The model list plus the absence of authentication
  already proves unauthenticated inference.
- System prompts, Modelfiles and chat templates you read are client data.
  Record that they were readable, quote the first line at most, redact the rest.
- Prompt injection, jailbreaks and app-layer abuse of the model are
  `hunt-llm-ai`'s. This file stops at "the server answers without credentials,
  and here is what it exposes".

---

## Ollama (11434)

| Item | Value | Source |
|---|---|---|
| Bind default | `127.0.0.1:11434`; `OLLAMA_HOST` changes it (`0.0.0.0` exposes it) | `envconfig/config.go` |
| CORS | `OLLAMA_ORIGINS` adds origins to the built-in localhost list | `envconfig/config.go` |
| Authentication | None on any route. CVE-2025-63389 records this; no fix exists | GHSA-f6mr-38g8-39rg |
| Version oracle | `GET /api/version` returns `{"version": "..."}`, unauthenticated | `docs/api.md` |
| Fingerprint | `GET /` answers with a short plain-text "Ollama is running" style banner (verify exact text per version) | |

```bash
# Stage A: read-only. Four GETs and at most three /api/show calls.
P=11434; S=http
aiget /api/version ollama_version
aiget /api/tags    ollama_tags      # every local model: name, size, digest, family, quantization
aiget /api/ps      ollama_ps        # models loaded right now, VRAM use, expiry time
aiget /v1/models   ollama_openai    # OpenAI-compatible listing; same data, confirms the compat layer
```

```bash
# Stage A, read-only POST (named exception): /api/show returns the Modelfile,
# template, parameters, license and SYSTEM prompt of one model and changes nothing.
# Only for custom-named models from /api/tags (not stock library names), at most three.
curl -sk -m 15 -o "evidence/${T}_${P}_show_1.json" -w '%{http_code}\n' \
  -H 'Content-Type: application/json' -d '{"model":"<custom-model-name-from-tags>"}' \
  "$S://$T:$P/api/show"
probe_delay
```

What the results mean:

- A `200` on `/api/tags` from outside is the finding: anyone can run, copy and
  delete these models. Custom names (`acme-support-ft:latest`) and a `SYSTEM`
  prompt in `/api/show` mean proprietary fine-tunes and prompt IP are exposed.
- `/api/ps` shows whether a GPU is attached and which model is hot. A model
  loaded with a long `expires_at` is production traffic you must not disturb.
- A `401` or `403` on every path means a reverse proxy adds authentication;
  Ollama itself never does. Record the proxy's `Server` header.

Stage B and forbidden actions (paths only; sign-off rules in `SKILL.md` Step 6):

| Route | Effect | Stage |
|---|---|---|
| `POST /api/generate`, `/api/chat`, `/api/embed`, `/api/embeddings`, `/v1/*` completions | Inference: GPU time, may load a model and evict another | Stage B, one smallest request, and usually unnecessary |
| `POST /api/pull`, `/api/create`, `/api/copy`, `POST /api/blobs/:digest` | Writes gigabytes to disk; a pull from an attacker registry is the Probllama path | Stage B; a pull from your own registry is still exploitation of CVE-2024-37032-class bugs. Not done. |
| `POST /api/push` | Uploads the client's model to a registry you name: model theft | Forbidden |
| `DELETE /api/delete` | Deletes a model | Forbidden |

---

## vLLM OpenAI-compatible server (8000)

| Item | Value | Source |
|---|---|---|
| Port / bind | `port` default 8000; `host` default unset, which binds all interfaces (verify per release) | `vllm/entrypoints/launchers/cli_args.py` (v0.31.0) |
| CORS | `allowed_origins` default `["*"]` | same file |
| Authentication | Optional: `--api-key` or `VLLM_API_KEY`; default none | same file |
| What the key covers | The middleware checked only paths starting with `/v1` in v0.14.0, so `/version`, `/health`, `/metrics` stay open with a key set; CVE-2026-48746 bypassed even that before 0.22.0 | GHSA-94f4-hr76-p5j6 |
| Version oracle | `GET /version` returns `{"version": "..."}` | `vllm/entrypoints/serve/instrumentator/basic.py` |

```bash
# Stage A: read-only GETs.
P=8000; S=http
aiget /version      vllm_version
aiget /v1/models    vllm_models     # id = served model name; "root" often leaks the local path or HF repo
aiget /health       vllm_health
aiget /metrics      vllm_metrics    # Prometheus vllm:* series: model name, request and token counters
aiget /openapi.json vllm_openapi    # the route list; dev-mode routes appear here when enabled
```

Interpretation:

- `/v1/models` `200` = no API key. `401` with `/version` `200` = key enforced
  on `/v1` only, which is the designed behaviour; report the version gate.
- `VLLM_SERVER_DEV_MODE` adds development routes (cache reset, sleep, RPC,
  server info) under `vllm/entrypoints/serve/dev/`. Their presence in
  `/openapi.json` on an internet host is a finding by itself. Never call them;
  the RPC route invokes engine methods (verify exact paths per release).
- vLLM opens internal ZeroMQ, NCCL and KV-transfer ports in multi-node and
  disaggregated setups (CVE-2025-30202, CVE-2025-32444, CVE-2025-47277). An
  unknown high port on a vLLM host is reported as exposure from the port scan.
  Never send it bytes: those sockets unpickle what they receive.

Stage B: every `POST /v1/*` (completions, chat, embeddings, responses),
`/invocations`, `/tokenize`, LoRA adapter loading, and anything in the dev
routes. The video-URL and media-URL CVEs (CVE-2026-22778, CVE-2025-6242,
CVE-2026-24779) are version gates; a media URL pointing at your listener is
an SSRF proof that only Stage B may send, and only with the rules of `hunt-ssrf`.

---

## Hugging Face Text Generation Inference (TGI)

| Item | Value | Source |
|---|---|---|
| Port / bind | Launcher default port 3000, hostname `0.0.0.0`; container deployments commonly publish another port (verify per deployment) | `launcher/src/main.rs` |
| Authentication | Optional `--api-key`. It is applied as a layer on the generation routes only; `/info`, `/health`, `/metrics`, `/v1/models`, `/ping` and the KServe `/v2` routes stay unauthenticated | `router/src/server.rs` |
| Maintenance | Repository archived (GitHub `archived: true`) | GitHub API |

```bash
# Stage A: read-only GETs.
aiget /info      tgi_info      # model_id, model_sha, dtype, max token limits, version, sha, docker_label
aiget /health    tgi_health
aiget /metrics   tgi_metrics
aiget /v1/models tgi_models
```

`/info` answering while `POST /generate` returns `401` is expected with a key.
Grade on whether generation is open, not on `/info`.

Stage B: `POST /`, `/generate`, `/generate_stream`, `/v1/chat/completions`,
`/v1/completions`, `/invocations`, `/vertex`, `/tokenize`, `/chat_tokenize`.

---

## llama.cpp: `llama-server` and `ggml-rpc-server`

| Item | Value | Source |
|---|---|---|
| `llama-server` bind | `--host` default `127.0.0.1` (`LLAMA_ARG_HOST`) | `tools/server/README.md` |
| `llama-server` port | Docker examples publish 8080; the current README lists `--port` default 9931 (verify per build) | same |
| Authentication | `--api-key` / `LLAMA_API_KEY`, default none. `/health` is always public | same |
| Optional endpoints | `/metrics` only with `--metrics`; `POST /props` only with `--props`; `/slots` **enabled by default** (`--no-slots` disables); Web UI on by default | same |
| Version oracle | `GET /props` returns `build_info` (`b<build>-<commit>`) | same |
| `ggml-rpc-server` | Example endpoint `127.0.0.1:50052`; README: "Never run the RPC server on an open network". No authentication, binary protocol | `tools/rpc/README.md` |

```bash
# Stage A: read-only GETs against llama-server.
aiget /health    llama_health
aiget /props     llama_props     # build_info, model path, chat template, default sampling settings
aiget /v1/models llama_models
aiget /slots     llama_slots     # per-slot state; record counts only, content may include request data (verify)
```

`ggml-rpc-server` on any reachable port is the finding: CVE-2026-34159 gives
unauthenticated memory read/write and RCE up to build b7991, and the
2024 RPC bugs did the same below b3561. **Stage A for the RPC port is the TCP
connect from the port scan and nothing else.** Every RPC command allocates or
touches GPU memory on the target; do not send one.

Stage B: completions, `/infill`, `/embedding`, slot save/restore actions,
`POST /props`.

---

## LM Studio (1234)

| Item | Value | Source |
|---|---|---|
| Port | 1234 by default (verify; secondary sources) | third-party integration guides |
| Bind | Localhost unless "Serve on Local Network" is switched on | lmstudio.ai/docs/developer/core/server/settings (setting described; default not stated, verify) |
| Authentication | "Require Authentication" switch: clients send an API token in `Authorization`. Off by default (verify) | same page |
| CVEs | None found (verify) | `ai-ml-cve-matrix.md` |

```bash
# Stage A: read-only GETs.
P=1234; S=http
aiget /v1/models     lmstudio_models
aiget /api/v0/models lmstudio_rest_models   # REST API listing with load state and quantization (verify path per version)
```

LM Studio is a desktop application. An internet-reachable instance usually
means a workstation behind port forwarding, often on a residential address.
Re-check IP ownership and scope before the first request: an employee's home
connection is rarely in scope even when the employee is.

---

## LiteLLM proxy

| Item | Value | Source |
|---|---|---|
| Port | 4000 is the documented default (verify per deployment) | |
| Authentication | Master key (`LITELLM_MASTER_KEY`) and virtual keys; LLM routes require a key when a master key is set | project docs (verify) |
| Unauthenticated routes | `GET /health/liveliness`, `/health/liveness`, `/health/readiness`, `/health/drain` | `litellm/proxy/health_endpoints/_health_endpoints.py` |
| Version oracle | `/health/readiness` includes `litellm_version` | same file |

```bash
# Stage A: read-only GETs.
P=4000; S=http
aiget /health/readiness litellm_ready    # status, db, cache, litellm_version
aiget /health/liveliness litellm_live
aiget /v1/models        litellm_models   # 401 = key enforced; 200 = open proxy holding the client's provider keys
```

Read the version first:

- `litellm_version` 1.82.7 or 1.82.8: the malicious PyPI releases
  (GHSA-5mg7-485q-xm76). Same-day client notice: every credential that proxy
  held must be rotated, whatever else you find.
- Between 1.81.16 and 1.83.6: KEV CVE-2026-42208 (pre-auth SQL injection
  through the `Authorization` header). Version gate only. Do not send a
  crafted header.
- Below 1.84.0 with MCP routes enabled: KEV CVE-2026-59822. Version gate
  only; sending an arbitrary Bearer token to `/mcp/` **is** the exploit.

Stage B: any LLM route (spends the client's upstream budget), `/key/*`,
`/mcp-rest/test/*` (KEV CVE-2026-42271 spawns processes), `/prompts/test`
(CVE-2026-37004).

---

## Any other OpenAI-compatible endpoint

When `GET /v1/models` answers with an OpenAI-shaped list (`{"object":"list",
"data":[...]}`) and the product is not one of the above, describe it
generically: the product if a header or error names it, the model ids, and
whether a key was required. Do not invent product-specific probes, default
keys or CVEs. Unauthenticated access to such an endpoint is graded like Ollama.

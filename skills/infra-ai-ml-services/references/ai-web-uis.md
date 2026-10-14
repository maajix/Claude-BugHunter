# AI web UIs: Gradio and Hugging Face Spaces, ComfyUI, Open WebUI, AnythingLLM

Front ends that wrap a model for people: demo apps, image pipelines, chat
UIs, document chat. They usually hold provider API keys, uploaded documents
and conversation history, and they can reach a GPU or an upstream API.

Load this file from `SKILL.md` Step 3. Version gates are in
`ai-ml-cve-matrix.md`. Every probe uses the `aiget` helper from `SKILL.md`
Step 1.

## Rules for this file

- Stage A reads configuration and status endpoints that the product serves
  to anonymous visitors. It never submits a prompt, queues a workflow,
  uploads a file or creates an account.
- An unclaimed first-run admin (Open WebUI `onboarding: true`, AnythingLLM
  with no password) is reported from the status endpoint. **Never sign up
  to claim it**, signed off or not: the first account becomes the
  instance's administrator and you cannot hand it back cleanly.
- Chat history, uploaded documents and generated images are client data.
  Count them where an endpoint reports counts; do not fetch them.
- Prompt injection, jailbreaks, data leaks through the model and embed-widget
  abuse are `hunt-llm-ai`'s. Retrieval stores behind these UIs are
  `hunt-rag-vector`'s.

---

## Gradio apps (7860) and Hugging Face Spaces

| Item | Value | Source |
|---|---|---|
| Bind / port | `GRADIO_SERVER_NAME` default `127.0.0.1`, `GRADIO_SERVER_PORT` 7860 | Gradio environment-variables guide |
| Authentication | Optional `auth=` (username/password login page); none by default | docs |
| Share links | `share=True` publishes the app at `https://<id>.gradio.live` through Gradio's FRP tunnel; links expire after one week | docs |
| API prefix | Gradio 5 and later serve their API under `/gradio_api` | `gradio/route_utils.py` (`API_PREFIX`) |

```bash
# Stage A: read-only GETs.
P=7860; S=http
aiget /config           gradio_config   # app config: Gradio version, components, named endpoints (verify key names per major)
aiget /gradio_api/info  gradio_api      # every API endpoint with parameter types (Gradio 5+); try /info on 4.x
```

Reading the results:

- `/config` `200` with a component list = no `auth=`. `/config` redirecting
  or returning `401` while `/` shows a login form = `auth=` is set.
- The Gradio version in `/config` places the app against the file-read and
  SSRF rows (CVE-2023-51449, CVE-2024-1728, CVE-2024-47167). Version gate
  only.
- `/gradio_api/info` describes what each endpoint does. An endpoint that
  takes a URL, a file path or shell-like text is the attack surface; reaching
  it is Stage B.

Never request `/file=` or `/gradio_api/file=` with any path you chose: those
routes are the file-read CVEs.

**Share links** (`*.gradio.live`) run through infrastructure that belongs to
Gradio, not to the client. A share link found in OSINT points at a client
machine, usually a workstation, through a third party's tunnel. It is in
scope only if the program names it; otherwise report the leak of the link
itself.

**Hugging Face Spaces** is a platform. A client's Space
(`https://huggingface.co/spaces/<owner>/<name>`, served from
`https://<owner>-<name>.hf.space` (verify the host pattern)) is testable only
if the program names it; Hugging Face's own infrastructure is out of scope.
A public Space's source and commit history are readable by anyone; hard-coded
tokens there are an OSINT finding for `offensive-osint`, and validating a
found key belongs to `cloud-iam-deep`.

Stage B: `POST /gradio_api/call/<api_name>`, `/run/<api_name>`,
`/gradio_api/queue/join` (each runs the app's function: inference, often on a
paid GPU), and uploads.

---

## ComfyUI (8188)

| Item | Value | Source |
|---|---|---|
| Bind / port | `--listen` default `127.0.0.1`; `--listen` without a value binds all interfaces; `--port` 8188 | `comfy/cli_args.py` |
| Authentication | None | |
| Version oracle | `GET /system_stats` returns `comfyui_version` | `server.py` |

```bash
# Stage A: read-only GETs.
P=8188; S=http
aiget /system_stats comfy_stats   # comfyui_version, python and pytorch versions, OS, RAM, argv, GPU name and VRAM
aiget /queue        comfy_queue   # running and pending counts; record counts only
aiget /extensions   comfy_ext     # frontend extensions: names custom node packs and ComfyUI-Manager
```

Reading the results:

- Any `200` from outside is the finding: ComfyUI has no authentication, and
  custom nodes plus ComfyUI-Manager turn a reachable instance into code
  execution (XLab's 2025 "Pickai" report and later cryptomining campaigns
  used exactly this exposure; see the matrix).
- `argv` in `/system_stats` shows the launch flags (`--listen`, any
  `--enable-cors-header`). Quote it in the evidence.
- Unknown custom node packs in `/extensions`, or a queue that never empties
  on an idle host, can mean the instance is already compromised. Stop and
  escalate to the client the same day.
- Do not fetch `/history`: it returns users' prompts and generated outputs.

Stage B: `POST /prompt` (queues a workflow on the GPU; also the
`LoadImage` traversal path of CVE-2026-56673), image and mask uploads, any
`userdata` write. Forbidden: ComfyUI-Manager install, update and
configuration routes (installing a node pack is code execution, and the
CVE-2025-67303 config write lowers the instance's security level for
everyone), `POST /interrupt`, `POST /free`, queue and history deletion.

---

## Open WebUI

| Item | Value | Source |
|---|---|---|
| Port | Container listens on 8080; the common `docker run` publishes it as 3000 | project README |
| Version oracle | `GET /api/version` returns `version` and `deployment_id`, unauthenticated | `backend/open_webui/main.py` |
| Public config | `GET /api/config` returns `onboarding` (true when no user exists), `name`, `version`, and `features` including `auth`, `enable_signup`, `enable_ldap`, `enable_login_form`, and the OAuth providers | same file |

```bash
# Stage A: read-only GETs.
P=8080; S=http      # or 3000
aiget /health      owui_health
aiget /api/version owui_version
aiget /api/config  owui_config
```

Reading `/api/config`:

| Signal | Meaning | Grade input |
|---|---|---|
| `"onboarding": true` | No account exists; the first sign-up becomes admin | Unauthenticated admin takeover available to anyone. Report, never claim |
| `features.auth` false | `WEBUI_AUTH=False`: no login at all, every visitor is the admin | Same severity as above |
| `features.enable_signup` true | Open registration. New accounts may land in a pending role until an admin approves them (verify the default role per release) | Lower: registration, not access |
| `features.enable_ldap` true | LDAP login; places the version against CVE-2026-44551 and CVE-2026-45675 | Version gate |
| OAuth providers listed | Places the version against CVE-2026-70482 | Version gate |

Stage B: creating an account on an instance with open signup, any chat
request (inference through the connected Ollama or provider keys).
Forbidden: signing up while `onboarding` is true.

---

## AnythingLLM (3001)

| Item | Value | Source |
|---|---|---|
| Port | 3001 (server and bundled frontend) | project Docker docs |
| Authentication | Single-user password (`AUTH_TOKEN`) or multi-user mode; neither by default | `server/models/systemSettings.js` |
| Unauthenticated status | `GET /api/ping` returns `{"online": true}`; `GET /api/setup-complete` returns current settings including `RequiresAuth`, `MultiUserMode`, the LLM provider and model, the vector database and embedding provider | `server/endpoints/system.js` |

```bash
# Stage A: read-only GETs.
P=3001; S=http
aiget /api/ping           allm_ping
aiget /api/setup-complete allm_settings   # RequiresAuth, MultiUserMode, providers; redact any key-like value
```

`"RequiresAuth": false` with `"MultiUserMode": false` = no password: every
workspace, uploaded document and configured provider key is reachable
through the UI. Below 1.10.0 the settings payload itself leaked provider keys
(CVE-2026-24477); if a key-shaped value appears, record its field name and
the last four characters only, and tell the client to rotate it.

`GET /api/env-dump` is a `GET` with a side effect: in production builds it
writes the server's environment to its `.env` file. Never call it.

Stage B: any workspace chat (inference), the developer API (needs an API
key), document upload. Embed widgets and their data leaks are
`hunt-llm-ai`'s.

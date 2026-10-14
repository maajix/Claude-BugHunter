# Agent builders and MCP servers: Langflow, Flowise, Dify, n8n, exposed MCP endpoints

Low-code platforms that wire models, tools and credentials into flows, and
the Model Context Protocol servers that hand tools to an LLM client. They hold
provider keys, database credentials and webhook secrets, and most of them
execute code or shell commands as a feature. That is why the agent-builder
block of `ai-ml-cve-matrix.md` is the longest and why Langflow carries six KEV
rows.

Load this file from `SKILL.md` Step 3. Version gates are in
`ai-ml-cve-matrix.md`. Every probe uses the `aiget` helper from `SKILL.md`
Step 1.

## Rules for this file

- Stage A reads status, version and setup endpoints that the product serves
  to anonymous visitors. It never creates an account, runs a flow, saves a
  node, posts to a webhook or calls a tool.
- Endpoints named in a CVE row are **never requested**, not even "to see if it
  is there". A `404` or a `401` from them proves nothing, a `200` is the
  exploit. The version string decides, the client confirms.
- A platform with no owner account yet (Dify `"step": "not_started"`, n8n
  owner setup pending, Langflow with `AUTO_LOGIN` on) is reported from the
  status endpoint. **Never claim the first account**, signed off or not.
- Flows, credentials, workflows and chat logs are client data. Record that a
  listing was readable and its count; do not download it.
- Prompt injection against a published flow, tool poisoning and anything the
  model does with the tools are `hunt-llm-ai`'s.

---

## Langflow (7860)

| Item | Value | Source |
|---|---|---|
| Port | 7860 (`langflow run` default); Docker images publish 7860 | Langflow docs |
| Authentication | `LANGFLOW_AUTO_LOGIN` defaults to `True`: the UI logs in as the superuser without a password | `lfx/services/settings/auth.py` (see matrix prose) |
| Version | `GET /api/v1/version` returns the installed version as JSON (verify key names) | Langflow API |
| Health | `GET /health` | Langflow API |

```bash
P=7860; S=http
aiget /health           langflow_health
aiget /api/v1/version   langflow_version   # version string: place it against the six KEV rows
aiget /api/v1/config    langflow_config    # feature flags incl. auto_login (verify field name per release)
```

Reading the results:

- `auto_login: true` in the config (or the UI landing on the flow list with
  no login form) = every visitor is the superuser. Critical on its own; the
  CVE rows add nothing to the grade, only to the write-up.
- Version at or below a KEV `Fixed` column = same-day escalation, labelled
  "version in range, unconfirmed".
- `/api/v1/validate/code`, `/api/v1/auto_login`, `build_public_tmp`,
  `/api/v1/responses` are CVE triggers. Not requested.

Stage B: running or building any flow, the webhook endpoint
(`/api/v1/webhook/<flow>`), file upload, Knowledge Base routes.

---

## Flowise (3000)

| Item | Value | Source |
|---|---|---|
| Port | 3000 | Flowise docs |
| Authentication | Releases before 3.0.1 had no authentication by default (matrix, CVE-2025-8943); 3.x ships an account/login flow and API keys | Flowise release notes (verify minor) |
| Fingerprint | HTML title `Flowise`, `/api/v1/ping` answers `pong` (verify) | docs |

```bash
P=3000; S=http
aiget /api/v1/ping            flowise_ping
aiget /                       flowise_root      # title, bundle hash; login form present or not
aiget /api/v1/chatflows       flowise_flows     # 401 = API protected; 200 + list = unauthenticated flow listing: count only
```

Reading the results: a `200` list from `/api/v1/chatflows` with no `Authorization`
header is the finding (flows embed system prompts, tool configs and credential
ids). Version comes from the UI bundle or the `About` dialog; the matrix rows
need it before anything in the 2026 authenticated-RCE wave can be cited, and
those rows stay unconfirmed from outside.

Stage B: `POST /api/v1/prediction/<id>` (runs a flow, spends tokens), any
`CustomMCP` or tool node creation, credential routes.

---

## Dify (80/443 behind nginx; API 5001, web 3000)

| Item | Value | Source |
|---|---|---|
| Setup state | `GET /console/api/setup` returns `{"step": "finished"}` or `"not_started"` | Dify API (matrix row) |
| Version | `GET /console/api/version?current_version=0.0.0` returns the current release and the instance version (verify field names) | Dify API |
| Features | `GET /console/api/system-features` lists SSO and signup settings (verify) | Dify API |

```bash
P=443; S=https
aiget /console/api/setup                          dify_setup
aiget "/console/api/version?current_version=0.0.0" dify_version
aiget /console/api/system-features                dify_features
```

Reading the results:

- `"step": "not_started"` = no admin exists and `POST /console/api/setup`
  would create one, gated only by an optional init password. Report it as
  unclaimed-admin, Critical, from the GET alone. Do not post.
- Published apps live under `/chat/<token>` and `/api/` with app tokens
  found in client JS; reaching them is `hunt-llm-ai` territory.
- The cross-tenant and SSRF rows need a version at or below their `Fixed`
  column; cite as unconfirmed.

Stage B: setup, signup, workspace invitation, remote-file upload, any app run.

---

## n8n (5678)

| Item | Value | Source |
|---|---|---|
| Port | 5678 (`N8N_PORT`) | n8n docs |
| Health | `GET /healthz` returns `{"status":"ok"}` | n8n docs |
| Settings | `GET /rest/settings` is readable before login and returns the version and whether the owner account is set up (verify exact field, historically `userManagement.showSetupOnFirstLoad`) | n8n source (verify) |
| Webhooks | `/webhook/<path>`, `/webhook-test/<path>`, `/form/<path>` | n8n docs |

```bash
P=5678; S=http
aiget /healthz        n8n_health
aiget /rest/settings  n8n_settings   # versionCli, owner setup state, enterprise flags; redact nothing else is needed
aiget /rest/login     n8n_login      # 401 = user management on
```

Reading the results:

- Owner setup not completed = any visitor can become the owner at `/setup`.
  Report from the settings JSON. Do not visit `/setup` with a POST.
- `versionCli` below 1.122.0 (or the 2.x fixed releases in the matrix) places
  the instance in range of the KEV sandbox-escape row; it needs an editor
  account, so the external grade is Medium, raised to Critical only when the
  owner setup is also open.
- Webhook and form paths in client JS or OSINT are attack surface for the
  conditional rows (CVE-2026-21858, CVE-2026-27493, CVE-2026-42231); they are
  reported as "exposed webhook with a version in range" and never posted to.

Stage B: anything under `/webhook*`, `/form*`, `/setup`, `/rest/workflows`,
`/rest/credentials`.

---

## Exposed MCP servers (any port; `/mcp`, `/sse`, `/messages`)

MCP servers reachable from the internet come in two transports: the legacy
HTTP+SSE pair (`GET /sse` opens a stream that announces a `/messages?sessionId=`
endpoint) and Streamable HTTP (`POST /mcp` with JSON-RPC, `Accept:
application/json, text/event-stream`). Both are found by their paths in client
configs, JS bundles, Docker compose files and the `*.well-known` discovery
below.

| Item | Value | Source |
|---|---|---|
| Authorization | Spec revision 2025-06-18: an MCP server is an OAuth 2.1 resource server and publishes `/.well-known/oauth-protected-resource`; a `401` carries `WWW-Authenticate: Bearer resource_metadata=...` | MCP specification, Authorization |
| Default transports | Python SDK and TypeScript SDK bind `127.0.0.1` by default in current releases; DNS-rebinding protection is off by default below the matrix `Fixed` versions | matrix, SDK rows |
| Handshake | `initialize` is a read-only JSON-RPC call that returns `serverInfo.name`, `serverInfo.version` and capabilities | MCP specification, Lifecycle |

```bash
P=8000; S=http
aiget /.well-known/oauth-protected-resource  mcp_prm     # 200 = auth configured per spec; 404 = decide from the next two
aiget /sse                                    mcp_sse     # curl -m 5: an 'event: endpoint' line = legacy transport, no auth

# Stage A read-only POST: the lifecycle handshake. Logged like every aiget call.
curl -s -m 15 -A "$UA" -o evidence/mcp_init.json -w '%{http_code}\n' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"assessment","version":"0"}}}' \
  "$S://$T:$P/mcp"
```

Reading the results:

- `401` with `WWW-Authenticate` = authorization in place; the finding is at
  most the exposure of the metadata (Informational).
- `200` with `serverInfo` and no credential sent = unauthenticated MCP server.
  `tools/list` (read-only, one call, after `notifications/initialized`) shows
  what the tools do; the names and descriptions are the evidence. A server
  whose tool list contains shell, filesystem, database or HTTP-fetch tools is
  Critical on the listing alone.
- `serverInfo.version` places SDK-based servers against the matrix. The
  LiteLLM `/mcp` rows (CVE-2026-42271, CVE-2026-59822) are version gates on
  LiteLLM, not something to demonstrate.
- `Mcp-Session-Id` reuse across clients (CVE-2026-25536, CVE-2026-52869) is a
  version gate; never attempt a session-id swap.

Stage B: `tools/call` of any tool, `resources/read` on anything but a
documented sample, `prompts/get` with arguments, `sampling/*`. One `tools/call`
of a documented no-op tool under sign-off is the maximum demonstration.

Client-side rows (`mcp-remote`, MCP Inspector XSS) need a developer to connect
out to a hostile server; an exposed server is not evidence of them. MCP
Inspector's proxy on 6277 (CVE-2025-49596) is the exception: a reachable
proxy is the finding, reported from its `GET /` title and version header.

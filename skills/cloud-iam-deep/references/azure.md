# Azure depth

> Reference for `cloud-iam-deep`. Moved out of SKILL.md (2026-10); content kept verbatim except where marked "refreshed". Credential validation (`az login`, `az account show`, role assignments) stays in SKILL.md. Entra ID / Graph abuse beyond the token: `m365-entra-attack`. Federated identity credentials (CI OIDC trusts): `references/iac-state-and-ci-tokens.md`.
>
> Stage A: obtaining the token through an in-scope SSRF and one read call that shows what it is (`/subscriptions`). Reading Key Vault secrets, blob contents or Graph mail, and every row of the privesc table, is Stage B and needs written sign-off.

## Azure — Managed Identity abuse

```bash
# From inside Azure VM (post-RCE or SSRF to IMDS-equivalent):
# Endpoint: http://169.254.169.254/metadata/identity/oauth2/token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns access_token for the Managed Identity. Use:
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Get token for Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Get token for Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
# → If Managed Identity has Graph permissions, read all M365 data
```

### Token endpoints and IMDS changes (refreshed 2026-10)

- **VM IMDS:** `api-version` must be `2018-02-01` or later; the `Metadata: true` header (lowercase `true`) is an SSRF mitigation, and a request without it gets `400 bad_request_102` ("Required metadata header not specified"). With several user-assigned identities on the VM, pick one with `client_id`, `object_id` or `msi_res_id` (Microsoft Learn, "Use managed identities on a virtual machine to acquire access token").
- **App Service / Functions:** not IMDS. The platform sets `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`; the request is a GET to `$IDENTITY_ENDPOINT?resource=<uri>&api-version=2019-08-01` with header `X-IDENTITY-HEADER: $IDENTITY_HEADER`. The header value is rotated and exists to block SSRF, so the token is reachable only with code execution or an env-var disclosure (Microsoft Learn, App Service managed identity overview). The older `MSI_ENDPOINT` / `MSI_SECRET` pair with `api-version=2017-09-01` still shows up in old apps (verify current support).
- **Metadata Security Protocol (MSP):** opt-in per VM / scale set. The Guest Proxy Agent signs (HMAC) every request to IMDS (`169.254.169.254`) and WireServer (`168.63.129.16`) and moves both to default-closed, with Audit and Enforce modes and an optional per-process allowlist. Default authorization still leaves IMDS open to all in-guest users, so an SSRF from the web process works unless the allowlist excludes that process. GA announced November 2025 (verify date). Not supported on RHEL 9+, Rocky 9+, SLES 15 SP4+ (Microsoft Learn, "Metadata Security Protocol (MSP)").
- **Graph audience:** request `resource=https://graph.microsoft.com`. Azure AD Graph (`graph.windows.net`) is retired; Microsoft's migration guide gives 2025-08-31 as the end of extended access (verify current status).

---

## Azure privesc patterns

| You have | Escalate via |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` on tenant | Self-assign Owner |
| `Microsoft.Authorization/roleDefinitions/write` | Modify role def to add powers |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run command on VM (with VM's MI) |
| `Microsoft.Compute/virtualMachines/login/action` or `loginAsAdmin/action` (VM has a privileged MI) | Entra ID login to the VM → MI token from IMDS |
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` + `Microsoft.Compute/virtualMachines/write` | Attach a privileged user-assigned MI to an existing VM (or create a new VM with it; needs network join/write actions too), then run command / log in. Source: Praetorian, "Azure RBAC Privilege Escalations: Azure VM" (2025-02-13) |
| `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Read all KV secrets |
| `Microsoft.Storage/storageAccounts/listkeys/action` | Read all storage blobs |
| `Microsoft.Web/sites/publishxml/action` | Get publish profile → RCE on app |
| `Microsoft.Web/sites/host/listkeys/action` | Func app key → RCE via function trigger |
| `Microsoft.AAD.Directory.* (App reg) + RoleManagement.ReadWrite.Directory` | Grant self Global Admin |
| Service principal with Application Administrator / Cloud Application Administrator / `Application.ReadWrite.All` | "I SPy" (Datadog, 2025-07-16): add a credential to the Office 365 Exchange Online SP (`00000002-0000-0ff1-ce00-000000000000`) → `Domain.ReadWrite.All` → federated domain → hybrid Global Admin. Microsoft fixed it 2025-08-07; today an unexpected credential on that SP is an IR finding, not a working path |

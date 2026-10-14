# Second-tier cloud providers: leaked-token triage

> Reference for `cloud-iam-deep`. Written 2026-10 against provider docs, SDK source and the gitleaks / GitHub secret-scanning catalogs (sources at the end). Anything not confirmed in a fetched source is marked (verify).

Covers DigitalOcean, Hetzner Cloud, OVHcloud, Linode/Akamai, Vultr, Scaleway, Alibaba Cloud, Oracle OCI, IBM Cloud, Cloudflare and Backblaze B2. Firebase, Supabase and Cognito backends are owned by `hunt-cloud-backends`. Finding the token is `hunt-source-leak`, `hunt-cicd` and `apk-redteam-pipeline`.

Regexes already in `offensive-osint/references/secret-patterns.md` are cited by row (#35 Cloudflare API token, #36 Cloudflare Global API Key, #37 DigitalOcean PAT) and not repeated. Log every validation with the schema in `offensive-osint/references/secret-validators.md` §23.10 and follow its hard rules (§23.11).

---

## Enumeration tiers (same for every provider)

| Tier | Stage | What | Typical bug-bounty policy |
|---|---|---|---|
| 0 | offline | Match the format, note where it leaked (file, env var, CI job), check whether the provider auto-revokes GitHub leaks | always fine |
| 1 | A | The single proof call below. One request, read-only, no resource data | accepted as proof of a live credential |
| 2 | A, only if the program allows going beyond identity | Read the token's own scope metadata; list resource *names* (first page, `per_page`/`limit` of 1-5) | usually accepted; stop at names |
| 3 | B, written sign-off | Object/file downloads, DNS record export, DB connection strings, workspace secrets; any POST/PUT/PATCH/DELETE; creating keys or tokens; "testing" write access by writing | out of scope unless the program says otherwise |

Most programs treat "valid credential + what it can reach" as the finding and "used it to read data" as a policy breach. When the scope cannot be read without a write (Hetzner, DigitalOcean custom scopes), report it as "live, permission level unknown" and name the leak context that suggests write access (a Terraform pipeline that creates servers needs write).

## Where these tokens leak

| Provider | Env vars / files to grep for | Source |
|---|---|---|
| DigitalOcean | `DIGITALOCEAN_TOKEN`, `DIGITALOCEAN_ACCESS_TOKEN` (verify), doctl config (verify) | provider docs (verify) |
| Hetzner Cloud | `HCLOUD_TOKEN`; Terraform `provider "hcloud" { token = ... }` | terraform-provider-hcloud docs |
| OVHcloud | `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY`; `./ovh.conf`, `~/.ovh.conf`, `/etc/ovh.conf` | python-ovh README |
| Linode | `LINODE_TOKEN` (verify), linode-cli config (verify) | (verify) |
| Vultr | `VULTR_API_KEY` (verify) | (verify) |
| Scaleway | `SCW_ACCESS_KEY`, `SCW_SECRET_KEY`, `SCW_DEFAULT_ORGANIZATION_ID`, `SCW_DEFAULT_PROJECT_ID`, `SCW_PROFILE`; `$HOME/.config/scw/config.yaml` | scaleway-sdk-go `scw/README.md` |
| Alibaba Cloud | `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, `ALIBABA_CLOUD_SECURITY_TOKEN`; deprecated `ALICLOUD_ACCESS_KEY`, `ALICLOUD_SECRET_KEY`, `ALIBABACLOUD_ACCESS_KEY_ID`; `~/.aliyun/config.json` | terraform-provider-alicloud docs, Alibaba CLI docs |
| Oracle OCI | `~/.oci/config` (`user`, `fingerprint`, `key_file`, `tenancy`, `region`, `security_token_file`) plus the PEM it points to | OCI SDK config docs |
| IBM Cloud | `IC_API_KEY`, `IBMCLOUD_API_KEY` (verify) | (verify) |
| Cloudflare | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL` (verify); `account_id` in `wrangler.toml` | (verify) |
| Backblaze B2 | `B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY` (verify) | (verify) |

High-yield places, in order: CI job logs that echo env or run with debug (`TF_LOG=DEBUG`, `set -x`); `docker-compose.yml` / `.env` committed next to it; container image layers (`docker history`, `trufflehog docker`, see `hunt-cicd` Phase 6); mobile apps that upload straight to object storage (Spaces / B2 / R2 keys in the APK, see `apk-redteam-pipeline`); Terraform state. Provider blocks are not written to state, but resources that mint credentials (for example a provider's API-token or access-key resource) store the secret as an attribute (verify per resource), and `hunt-cicd` Phase 5 has the `jq` extraction.

---

## DigitalOcean

- **Formats** (gitleaks): PAT `dop_v1_[a-f0-9]{64}` (`digitalocean-pat`, catalog #37), OAuth access token `doo_v1_[a-f0-9]{64}` (`digitalocean-access-token`), refresh token `dor_v1_[a-f0-9]{64}` (`digitalocean-refresh-token`). Spaces access keys are S3-style; the `DO00` prefix commonly seen on newer keys is (verify).
- **Auto-revocation:** GitHub secret scanning partner for `digitalocean_personal_access_token`, `digitalocean_oauth_token`, `digitalocean_refresh_token` and `digitalocean_system_token`, with push protection.
- **Proof (Tier 1):**
  ```bash
  curl -s -H "Authorization: Bearer $DO_TOKEN" https://api.digitalocean.com/v2/account \
    | jq '.account | {email, uuid, status, team}'
  # 200 = live. The operation needs the account:read scope (DigitalOcean OpenAPI spec),
  # so a live custom-scoped token without it is refused rather than 401 (status code: verify).
  ```
  The account object carries `droplet_limit`, `floating_ip_limit`, `email`, `name`, `uuid`, `email_verified`, `status`, `status_message` and `team {uuid, name}`.
- **Scope model:** Full Access (`api:write` alias), Read Only (`api:read`) or Custom Scopes named `resource:action` (for example `droplet:update`, `database:create`), each mapping to API endpoints; custom scopes went GA in April 2024. There is no documented endpoint that returns the calling token's own scopes (verify), so infer from which GETs succeed.
- **Tier 2:** `GET /v2/projects`, `GET /v2/droplets?per_page=1` (names only).
- **Spaces keys:** Full access (all buckets, create/configure, list all) or Limited (per bucket, Read or Read/Write/Delete). Proof is a bucket list against `https://<region>.digitaloceanspaces.com` with any S3 client (verify the endpoint for your region); a Limited key may fail `ListBuckets` but work on its bucket.

## Hetzner Cloud

- **Format:** undocumented; tokens are commonly 64 alphanumeric characters (verify). No gitleaks rule and no GitHub partner pattern, so leaks are not auto-revoked.
- **Scope model:** a token belongs to one project. Read = only `GET`; Read & Write = `GET`, `DELETE`, `PUT`, `POST` (Hetzner docs, "Generating an API token"). The token value is shown once.
- **Proof (Tier 1):** there is no documented whoami or token-introspection call (verify). Use the least sensitive authenticated read:
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $HCLOUD_TOKEN" \
    https://api.hetzner.cloud/v1/locations     # 200 = live, 401 = dead (verify that /locations requires auth)
  ```
- **Read vs Read & Write cannot be told apart without a write.** Do not create or delete anything to find out; that is Stage B.
- **Tier 2:** `GET /v1/servers?per_page=1` shows the project has servers (names, IPs).
- **2025-2026:** `api.hetzner.com` is a separate API (Storage Boxes); Cloud resources stay on `api.hetzner.cloud`, and the Terraform provider exposes both endpoints (`endpoint`, `endpoint_hetzner`).

## OVHcloud

- **Credentials:** three values. Application Key (AK), Application Secret (AS), Consumer Key (CK, bound to the account and to access rules). Requests are signed: `"$1$" + SHA1_HEX(AS+"+"+CK+"+"+METHOD+"+"+QUERY+"+"+BODY+"+"+TSTAMP)` (OVHcloud API first-steps guide). Use the `ovh` Python client rather than signing by hand. Newer setups use OAuth2 service accounts (`client_id` / `client_secret` in `ovh.conf`), scoped through OVHcloud IAM (python-ovh README).
- **Endpoints:** `ovh-eu` (`https://eu.api.ovh.com/1.0`), `ovh-ca`, `ovh-us` (`https://api.us.ovhcloud.com/1.0`), plus the Kimsufi / So you Start variants.
- **Proof and scope in one call (Tier 1):**
  ```bash
  python3 -c 'import ovh, json; c = ovh.Client(endpoint="ovh-eu", application_key="<AK>", application_secret="<AS>", consumer_key="<CK>"); print(json.dumps(c.get("/auth/currentCredential"), indent=1))'
  ```
  `/auth/currentCredential` returns `rules` (the method + path pairs this CK may call), `status` (`validated`, `pendingValidation`, `refused`, `expired`), `expiration`, `allowedIPs`, `applicationId`, `credentialId`, `lastUse` (OVHcloud API schema `auth.json`). A rule of `GET /*`, `POST /*`, `PUT /*`, `DELETE /*` is a full-account key.
- **Tier 2:** `GET /me` returns the account holder's nichandle, name and address. That is PII: call it only when the rules allow it and the program accepts it.
- **No GitHub partner pattern** for OVH.

## Linode / Akamai

- **Format:** PATs are commonly 64 hex characters (verify). No gitleaks rule, no GitHub partner pattern.
- **Proof (Tier 1):**
  ```bash
  curl -s -H "Authorization: Bearer $LINODE_TOKEN" https://api.linode.com/v4/profile \
    | jq '{username, email, restricted, uid, two_factor_auth}'
  ```
  Returns `username`, `email`, `restricted`, `uid`, `authorized_keys`, `two_factor_auth` and more (Linode API reference, "Get a profile").
- **Own scope (Tier 2):** `GET /v4/profile/tokens` (needs `account:read_only`) lists every PAT with `id`, `label`, `scopes`, `created`, `expiry` and the first 16 characters of `token`. Match the leaked token's first 16 characters to read its scopes without writing. `restricted: true` means the user itself is limited by grants (`GET /v4/profile/grants`, verify).

## Vultr

- **Format:** API keys are commonly 36 uppercase alphanumeric characters (verify). No gitleaks rule, no GitHub partner pattern. Keys can be limited to source IP ranges (verify), so a 401 from your IP can still be a live key.
- **Proof and scope (Tier 1):**
  ```bash
  curl -s -H "Authorization: Bearer $VULTR_API_KEY" https://api.vultr.com/v2/account | jq '.account | {name, email, acls}'
  ```
  The account object has `name`, `email`, `acls`, `balance`, `pending_charges`, `last_payment_date`, `last_payment_amount` (govultr `account.go`). `acls` is the scope (sub-users carry a reduced list).

## Scaleway

- **Format:** access key `^SCW[A-Z0-9]{17}$`, secret key a UUID (scaleway-sdk-go `validation/is.go`). The secret is sent as `X-Auth-Token: <secret_key>` (sdk `internal/auth/token.go`). No GitHub partner pattern.
- **Proof (Tier 1):**
  ```bash
  curl -s -H "X-Auth-Token: $SCW_SECRET_KEY" \
    "https://api.scaleway.com/iam/v1alpha1/api-keys/$SCW_ACCESS_KEY" \
    | jq '{application_id, user_id, default_project_id, expires_at, creation_ip, managed}'
  ```
  The bearer is either an application (`application_id`) or a user (`user_id`). Reading API keys needs an IAM read permission set (verify); a refusal with a valid-looking body still shows the secret authenticated, but record it as (verify) until you see the status code.
- **Scope (Tier 2):** `GET /iam/v1alpha1/policies?application_ids=<id>` (or `user_ids=`), then `GET /iam/v1alpha1/rules?policy_id=<id>` returns `permission_set_names`, `project_ids`, `organization_id`. `GET /iam/v1alpha1/permission-sets` names what each set allows.

## Alibaba Cloud

- **Format** (gitleaks): AccessKey ID `\b(LTAI(?i)[a-z0-9]{20})` (`alibaba-access-key-id`); secret 30 characters, matched only near the word `alibaba` (`alibaba-secret-key`). STS tokens are issued as a separate security token (prefix `STS.` is (verify)). GitHub partner: `alibaba_cloud_access_key_id`, `alibaba_cloud_access_key_secret`, with push protection.
- **Proof (Tier 1):** `GetCallerIdentity` needs no RAM authorization (Alibaba STS API reference).
  ```bash
  aliyun configure --profile leak --mode AK        # local config only, prompts for ID and secret
  aliyun sts get-caller-identity --profile leak
  # IdentityType (RAMUser / AssumedRoleUser / main account), AccountId, Arn, PrincipalId, UserId or RoleId
  ```
  A main-account (root) AccessKey is the worst case: stop after this call.
- **Scope (Tier 2):** RAM policies attached to the user or role (`aliyun ram ListPoliciesForUser --UserName <name>`, verify syntax) need `ram:List*` permissions the key may not have.

## Oracle Cloud Infrastructure (OCI)

- **Credentials:** API signing key = RSA PEM (2048-bit minimum) + `fingerprint` + `user` OCID + `tenancy` OCID + `region` in `~/.oci/config`. Session auth uses `security_token_file` instead of user/fingerprint. Other user credentials: auth tokens (third-party APIs), Customer Secret Keys (S3 Compatibility API), OAuth 2.0 client credentials, SMTP credentials, IAM database passwords (OCI docs, "Working with user credentials"). OCIDs look like `ocid1.user.oc1..<unique_ID>`. GitHub partner: `oracle_api_key` (no push protection).
- **Proof (Tier 1):**
  ```bash
  oci os ns get --config-file ./leak.config --profile DEFAULT   # returns the tenancy's Object Storage namespace
  ```
  Retrieving your own tenancy's namespace has no documented policy requirement (verify). Users manage their own API keys without any policy (OCI docs), so `oci iam user api-key list --user-id <user-ocid>` (verify flags) shows whether the leaked fingerprint is still registered.
- **Scope model:** policy statements `Allow <subject> to <verb> <resource-type> in <location> where <conditions>`; `manage all-resources in tenancy` is admin (OCI policy syntax docs). Reading policies (`oci iam policy list --compartment-id <tenancy-ocid>`, verify) needs inspect rights on policies.

## IBM Cloud

- **Credentials:** IAM API keys for users or service IDs; length and charset are not published (commonly 44 characters, verify). GitHub partner: `ibm_cloud_iam_key` (no push protection). No gitleaks rule.
- **Proof (Tier 1):** exchange the key for a short-lived IAM token and decode it locally. This mints a token for the key's own identity; it changes nothing in the account.
  ```bash
  curl -s -X POST https://iam.cloud.ibm.com/identity/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=urn:ibm:params:oauth:grant-type:apikey' \
    --data-urlencode "apikey=$IBM_API_KEY" | jq -r .access_token | cut -d. -f2 | base64 -d 2>/dev/null | jq .
  # identity and account claims (iam_id, account): claim names (verify)
  ```
  Endpoint, path, grant type and form field are from IBM `go-sdk-core` (`iam_authenticator.go`).
- **Key metadata:** `GET https://iam.cloud.ibm.com/v1/apikeys/details` with `Authorization: Bearer <token>` and `IAM-ApiKey: <key>` (IBM platform-services SDK) returns the key's record (field names: verify).
- **Scope model:** IAM policies attach to users, service IDs and access groups; reading them needs account-management viewer access (verify).

## Cloudflare

- **Formats** (Cloudflare docs, "Token formats", page updated 2026-04-20):

  | Credential | New scannable format | Pre-2026 format (still valid) |
  |---|---|---|
  | User API token | `cfut_` + 40 characters + checksum | 40-character alphanumeric |
  | Account API token | `cfat_` + 40 characters + checksum | 40-character alphanumeric |
  | Global API Key | `cfk_` + 40 characters + checksum | 37-45 character lowercase hex |

  Charset and checksum length are not published, so a working regex is `\bcf(?:ut|at|k)_[A-Za-z0-9_-]{40,}` (verify). Origin CA keys: `v1\.0-[a-f0-9]{24}-[a-f0-9]{146}` (gitleaks `cloudflare-origin-ca-key`). **Drift:** catalog rows #35-36 in `secret-patterns.md` only know the legacy formats.
- **Auto-revocation:** Cloudflare scans for and revokes leaked tokens in old and new formats; GitHub partner patterns `cloudflare_user_api_token`, `cloudflare_account_api_token`, `cloudflare_global_user_api_key` with push protection. Expect public-GitHub leaks to be dead.
- **Proof (Tier 1):**
  ```bash
  # User token (cfut_ or legacy)
  curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify | jq .result
  # Account-owned token (cfat_ or legacy) needs the account ID (wrangler.toml, dashboard URLs, CI vars)
  curl -s -H "Authorization: Bearer $CF_TOKEN" "https://api.cloudflare.com/client/v4/accounts/<account_id>/tokens/verify" | jq .result
  ```
  Returns `id`, `status` (`active`, `disabled`, `expired`), `expires_on`, `not_before`; no permissions. A user-token verify that fails may simply mean it is an account token: try the account path before calling it dead.
- **Global API Key:** sent as `X-Auth-Email` + `X-Auth-Key` (legacy auth, verify the exact `/client/v4/user` call); it carries the user's full access, so stop at the proof call.
- **Scope:** tokens have permission groups + resources (account / zone), optional client IP filtering and TTL. Reading a token's policies (`GET /client/v4/user/tokens/<id>`) needs the token to hold API-token read permission (verify). Otherwise infer at Tier 2 with `GET /client/v4/zones?per_page=1` (zone names). DNS record export, Workers script download and R2 object reads are Stage B.

## Backblaze B2

- **Credentials:** `applicationKeyId` + `applicationKey`. The master key's ID equals the account ID; app key IDs are longer and application keys are commonly 31 characters starting with `K` (formats: verify). No gitleaks rule, no GitHub partner pattern.
- **Proof and full scope in one call (Tier 1):**
  ```bash
  curl -s -u "$B2_APPLICATION_KEY_ID:$B2_APPLICATION_KEY" \
    https://api.backblazeb2.com/b2api/v4/b2_authorize_account \
    | jq '{accountId, allowed: .apiInfo.storageApi.allowed, applicationKeyExpirationTimestamp}'
  ```
  `allowed.capabilities` (for example `listBuckets`, `readFiles`, `writeFiles`, `writeKeys`; names: verify), `allowed.buckets[]` (`id`, `name`), `allowed.namePrefix`. v4 moved bucket info into `allowed.buckets`; v1-v3 reject multi-bucket application keys (Backblaze API docs). `writeKeys` on a master key = account takeover primitive.
- **Tier 2:** bucket names come back in `allowed.buckets`. Listing or downloading file names/contents is Stage B.

---

## Severity guidance

| Finding | Severity |
|---|---|
| Account-wide write token (OVH `*` rules, DO Full Access, Hetzner R&W on prod project, Cloudflare Global API Key, B2 master key, Alibaba main-account AK, OCI admin group) | Critical |
| Token with DNS edit on the target's zones (Cloudflare `Zone.DNS` edit) | Critical: subdomain takeover and certificate issuance at will |
| Read-only token on production (DO Read Only, Hetzner Read, B2 `readFiles` on customer bucket) | High (Critical if the readable data is sensitive) |
| Live token, scope unknown without a write | High; say what the leak context implies |
| Token live but scoped to a non-production project / empty account | Medium |
| Token dead or already revoked by the provider | Informational (report the leak path if it is still public) |

## Sources (checked 2026-10)

gitleaks `config/gitleaks.toml` (github.com/gitleaks/gitleaks); GitHub Docs, "Supported secret scanning patterns"; DigitalOcean docs "How to create a personal access token", OpenAPI `resources/account/account_get.yml` and `models/account.yml` (github.com/digitalocean/openapi), Spaces "manage access"; Hetzner docs "Generating an API token", docs.hetzner.cloud, terraform-provider-hcloud `docs/index.md`; OVHcloud "First steps with the OVHcloud APIs", `https://eu.api.ovh.com/1.0/auth.json`, python-ovh README; Akamai Linode API reference ("Get a profile", "List personal access tokens"); vultr/govultr `account.go`; scaleway-sdk-go (`scw/README.md`, `validation/is.go`, `api/iam/v1alpha1/iam_sdk.go`, `internal/auth/token.go`); Alibaba Cloud STS `GetCallerIdentity` reference, CLI "Configure credentials", terraform-provider-alicloud `index.html.markdown`; OCI docs "SDK and CLI configuration file", "Working with user credentials", "Object Storage namespaces", "Policy syntax"; IBM `go-sdk-core/core/iam_authenticator.go`, `platform-services-go-sdk/iamidentityv1`; Cloudflare docs "Create API token", "Account API tokens", "Token formats", "API keys", API reference "Verify account token"; Backblaze "b2_authorize_account" API docs.

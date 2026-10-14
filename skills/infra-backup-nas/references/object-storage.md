# Self-hosted object storage: MinIO, Ceph RGW, SeaweedFS

These speak the S3 API on a client-owned address. The hosted-cloud version of the
same mistakes (public AWS, GCS and Azure buckets, bucket-name guessing, leaked
cloud keys) belongs to `hunt-cloud-misconfig` and `cloud-iam-deep`. This file
covers the server software itself and the read-only checks that are safe against
it. Object stores are where backup repositories land (Veeam, Commvault and others
write to S3-compatible targets), so treat every listing as potentially a backup
index.

Rules for every row below:

- **Detected by version only.** Never send the request a CVE describes. On MinIO
  CVE-2023-28432 that request is a single unauthenticated call and the response
  carries the server's root credentials; that is exploitation, however small.
- KEV column: CISA KEV catalog 2026.10.13.
- "(verify)" marks a detail that could not be confirmed from a primary source
  while this file was written.

---

## MinIO

| Port | Service |
|---|---|
| 9000/tcp | S3 API. **Collides with FastCGI (`hunt-exposed-services` `remote-debug.md`), Dell NetWorker NMC, and many HTTP products** |
| 9001/tcp | Web console in most deployments (`--console-address ":9001"`); without that flag the console port is chosen at startup (verify). **Collides with HSQLDB and NetWorker NMC RPC** |

**Fingerprint.** `Server: MinIO` on every S3 response, S3-style XML errors, the
documented unauthenticated liveness check `/minio/health/live` (200, no body), and
the console's login page. **Version observable?** Not in the `Server` header
(verify). The Prometheus endpoint carries build information but needs a bearer
token unless the operator set `MINIO_PROMETHEUS_AUTH_TYPE=public` (verify); one GET
tells you which. Otherwise ask the client (`minio --version` or `mc admin info`).

**Maintenance status.** MinIO moved the community edition to maintenance mode in
late 2025 and later archived the repository; sources disagree on the dates
(February or April 2026). CVE records nevertheless name fixed releases dated 2026
(below). Ask whether the client runs a source build, a third-party patched build,
or the commercial AIStor, and report an unmaintained build as its own finding.

**Default credentials.** MinIO documents `minioadmin` / `minioadmin` as the root
pair when `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` are unset (verify the current
docs). One attempt, Stage B, see `SKILL.md` Step 6.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2021-41266 | Operator Console authentication bypass when an external IdP is enabled | console before v0.12.3 | v0.12.3 | No |
| CVE-2023-28432 | Distributed (cluster) deployments return all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, unauthenticated | RELEASE.2019-12-17T23-16-33Z up to before RELEASE.2023-03-20T20-16-18Z | RELEASE.2023-03-20T20-16-18Z | Yes, 2023-04-21 |
| CVE-2023-28434 | `PostPolicyBucket` metadata check bypass writes into any bucket; needs credentials with `arn:aws:s3:::*` and Console API access; Linux/macOS | before RELEASE.2023-03-20T20-16-18Z | same | Yes, 2023-09-19 |
| CVE-2024-24747 | Access keys inherit the parent's `admin:*` actions: privilege escalation | before RELEASE.2024-01-31T20-20-33Z | that release | No |
| CVE-2024-55949 | Privilege escalation in the IAM import API | RELEASE.2022-06-25T15-50-16Z up to before RELEASE.2024-12-13T22-19-12Z | that release | No |
| CVE-2025-31489 | Incomplete signature validation on unsigned-trailer uploads; needs an access key and a user with write permission on the bucket | before RELEASE.2025-04-03T14-56-28Z | that release | No |
| CVE-2025-62506 | Session-policy bypass for service accounts and STS accounts | before RELEASE.2025-10-15T17-29-55Z | that release | No |
| CVE-2026-33322 | OIDC JWT algorithm confusion: anyone who knows the OIDC client secret forges tokens with any policy, including `consoleAdmin` | RELEASE.2022-11-08T05-27-07Z up to before RELEASE.2026-03-17T21-25-16Z | RELEASE.2026-03-17T21-25-16Z | No |
| CVE-2026-33419 | STS `AssumeRoleWithLDAPIdentity`: username enumeration plus no rate limit (CNA text names AIStor) | before RELEASE.2026-03-17T21-25-16Z | that release | No |
| CVE-2026-40344, CVE-2026-41145 | Object write to any bucket by anyone who knows a valid **access key ID** (no secret): Snowball auto-extract handler and query-string unsigned-trailer path | RELEASE.2023-05-18T00-05-36Z up to before RELEASE.2026-04-11T03-20-12Z | RELEASE.2026-04-11T03-20-12Z | No |

The last row changes the value of a leak: an access key ID without its secret,
found in a JS bundle or config file, is enough on an affected build. Report the
leak plus the version; do not test the write.

---

## Ceph Object Gateway (RGW, radosgw)

| Port | Service |
|---|---|
| 7480/tcp | RGW default frontend (beast) (verify) |
| 80/443/8080 | Common in cephadm and Rook deployments behind a load balancer (verify) |

**Fingerprint.** An unsigned `GET /` typically returns a `ListAllMyBucketsResult`
whose owner is `anonymous` and whose bucket list is empty (verify); request IDs
of the form `tx...` (verify). **Version observable?** No; ask the client
(`ceph versions`) or read the distribution's package.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2023-43040 | RGW bucket validation against browser POST policies: unauthorized writes to buckets (IBM CNA record, 6.5) | Ceph before the fixes | Pacific 16.2.15 and Reef 18.2.1 changelogs; Red Hat Ceph Storage 5.3 via RHSA-2024:0745; IBM Storage Ceph 6.1z2 (verify per distribution) | No |
| CVE-2024-48916 | RGW OIDC provider accepts a JWT with `alg: none`, signature unchecked (PR:L) | up to 19.2.3 per CNA, "no patched version" at publication; the Ceph tracker attributes a fix to 19.2.3 (conflict, verify) | (verify) | No |

---

## SeaweedFS

| Port | Service (project Production-Setup wiki) |
|---|---|
| 9333/tcp (gRPC 19333) | Master |
| 8080/tcp (gRPC 18080) | Volume server. Collides with every HTTP alt service. gRPC is the CVE-2026-73080 surface |
| 8888/tcp (gRPC 18888) | Filer. Collides with Jupyter (`hunt-exposed-panels`). gRPC is the CVE-2026-72920 surface |
| 8333/tcp | S3 gateway |
| 7333/tcp | WebDAV (verify) |

**Security model.** Without a `security.toml` that sets JWT signing keys, the
master, volume and filer HTTP APIs answer anyone (verify against the wiki's
Security Configuration page). The S3 gateway authenticates only when identities
are configured.

**Fingerprint.** Master cluster and directory status pages return JSON naming the
leader, peers and volume layout; the master and filer UIs show the build (verify
paths per release). **Version observable?** Usually, from those pages.

The gRPC ports matter as much as the HTTP ones: two 2026 critical advisories
are unauthenticated gRPC services. Stage A on a gRPC port is a TCP connect, never
an RPC. Versions are Go pseudo-versions in the advisories; release numbers come
from the advisory text where it gives one.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2024-40120 | SQL injection in the abstract SQL filer store (medium) | v3.68 as published | commit of 2024-06-25 (verify release) | No |
| CVE-2026-72920 | Filer IAM gRPC service with no authentication: mint access keys and S3 admin policies (9.8) | before the 2026-05-12 fix | release 4.24 (verify; same-day commit as the next row) | No |
| CVE-2026-73080 | Volume server `FetchAndWriteNeedle` gRPC: unauthenticated SSRF with response read-back, cloud metadata included | before 4.24 | 4.24 | No |
| CVE-2026-72921 | Filer JWT `allowed_prefixes` literal prefix match: one tenant's token reads sibling tenants' paths | before the 2026-05-12 fix | 4.24 (verify) | No |
| CVE-2026-54917, CVE-2026-58372 | Path traversal in the S3 and Iceberg REST gateways: cross-bucket access | before 4.30 | 4.30 | No |
| CVE-2026-55874 | Path traversal through the S3 copy-source header: cross-bucket object read (PR:L) | after the 4.30 hardening, before the 2026-06-12 fix | (verify release) | No |

Even fully patched, an open master or filer with no `security.toml` lets anyone
read, write and delete every file. That is the usual finding.

---

## Stage A and Stage B for this family

Stage A, one request each, names and counts only:

- Headers and the unsigned error body on the S3 port; the MinIO liveness check.
- An unsigned listing of a bucket whose name you already have (from the app, a JS
  bundle, DNS, an error page). Bucket-name discovery belongs to
  `hunt-cloud-misconfig`; no wordlists here. Cap the listing at 20 keys.
- SeaweedFS master status and a filer listing of the root only (names, sizes).

Stage B, written sign-off naming host, bucket and action: one documented default
credential; an authenticated version read with client credentials; a single
canary object to prove anonymous write, with a unique name the client removes.

**Forbidden outright:** downloading objects (above all anything that looks like a
backup, dump, VM image or key material; the listing proves it); changing bucket
policies, lifecycle rules, versioning, replication or object lock; deleting any
object or version; any `mc admin` command that changes state; reading MinIO's
environment through any path; and any request to a CVE's named component.

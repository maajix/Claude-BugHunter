# GCP depth

> Reference for `cloud-iam-deep`. Moved out of SKILL.md (2026-10); content kept verbatim except where marked "refreshed". SA JSON activation and first enumeration stay in SKILL.md. Workload Identity Federation trusts: `references/iac-state-and-ci-tokens.md`.
>
> Every row of the privesc table is Stage B (written sign-off): it mints keys or tokens, changes IAM or deploys code. Stage A is showing that the permission is granted (`get-iam-policy`, `testIamPermissions`-style reads).

## GCP privesc patterns

| You have | Escalate via |
|---|---|
| `iam.serviceAccounts.getAccessToken` on higher-priv SA | Get token for that SA |
| `iam.serviceAccounts.implicitDelegation` | Chain through delegate SAs |
| `iam.serviceAccounts.signBlob` / `signJwt` on higher SA | Forge JWT for that SA |
| `iam.serviceAccountKeys.create` | Create new key for any SA → impersonate |
| `iam.serviceAccounts.setIamPolicy` | Grant self impersonation rights |
| `iam.roles.update` (on custom role) | Add admin permissions to a role you have |
| `cloudfunctions.functions.update` (function runs as high-priv SA) | Replace code → exfil creds |
| `cloudfunctions.functions.call` + above | Trigger replacement |
| `cloudfunctions.functions.create` / `update` (any function) | ConfusedFunction (Tenable, 2024-07-24): deployment runs as the default Cloud Build SA → its token. Google's fix only covers Cloud Build SAs created after mid-June 2024; older projects keep the broad default SA |
| `run.services.update` + `iam.serviceAccounts.actAs` | ImageRunner (Tenable): deploy a revision that pulls other private images in the project. Fixed 2025-01-28 |
| `composer.environments.update` | Tenable TRA-2025-03 ("ConfusedComposer"): reach the default Cloud Build SA. Fixed for new envs 2025-02-18, existing envs mid-April 2025 |
| `roles/eventarc.messageBusUser` + `roles/eventarc.developer` | Tenable TRA-2026-15: Eventarc Pipelines → tokens for any SA incl. the Eventarc Service Agent. Fixed 2026-02-12 |
| `compute.instances.setMetadata` | Add ssh-keys metadata → SSH as root |
| `compute.instances.setServiceAccount` | Attach higher-priv SA to instance |
| `cloudbuild.builds.create` (build runs as project SA) | Build executes attacker code |
| `deploymentmanager.deployments.create` | Resources created as DM SA |

**Secure-by-default caveats (refreshed 2026-10).** Before reporting a row as live, check what the org enforces:

- Organizations created on or after 2024-05-03 enforce `constraints/iam.managed.disableServiceAccountKeyCreation`, `constraints/iam.disableServiceAccountKeyUpload` and `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` by default (some orgs created February-April 2024 too). There, `iam.serviceAccountKeys.create` returns a policy violation unless the constraint was relaxed, and default service accounts no longer get Editor automatically (Google Cloud, "Manage secure-by-default organization resources").
- Cloud Build's default service account changed during May-June 2024: projects whose first build ran after the change default to the Compute Engine default SA instead of the legacy Cloud Build SA; older projects keep the legacy SA (Google Cloud, "Cloud Build service account updates"). This is why the ConfusedFunction and ConfusedComposer rows depend on project age.

---

## GCP IMDS attack (via SSRF or post-RCE)

```bash
# GCP IMDS endpoint:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Returns access token. Use:
TOKEN=...
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

### Metadata server facts (refreshed 2026-10)

- Hosts: `metadata.google.internal` (recommended), `169.254.169.254`, `metadata.goog`, and `fd20:ce::254` on IPv6-only instances. Shielded VMs can also use HTTPS endpoints (Preview).
- `Metadata-Flavor: Google` is required; the legacy `X-Google-Metadata-Request` header is deprecated. Any request carrying `X-Forwarded-For` is rejected, which kills most proxy-style SSRF (Google Cloud, "Access VM metadata").
- The header-less `v0.1` and `v1beta1` endpoints were deprecated 2019-09-30 and shut down 2020-09-30, so a GET-only SSRF that cannot set headers gets nothing from GCP metadata (Google Cloud, "v0.1 and v1beta1 metadata server endpoints deprecation").
- Endpoint discovery and SSRF bypass belong to `hunt-cloud-misconfig` / `hunt-ssrf`.

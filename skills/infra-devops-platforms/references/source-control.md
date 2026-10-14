# Source-control servers and daemons

GitLab self-managed, Gitea, Forgejo, Gogs, Gerrit and the bare git daemon. The
asset is source code plus the credentials committed into it, and the forges
also run CI. Two rules dominate this family:

- **Open registration changes every grade.** Most 2021-2026 RCE rows for these
  products need "an authenticated user". Where anyone can sign up, that is
  everyone. Read the setting from the sign-in page; never create an account.
- **Names, not contents.** `ls-remote`, project and repository listings are
  Stage A. `clone`, `fetch`, archive and raw-file downloads copy the client's
  source and are Stage B for one named repository at most.

Scope note: GitLab CI runners, pipeline variables and the ruby-saml chain
CVE-2025-25291/25292 belong to `hunt-cicd`. SSH on any forge port, including
Gerrit 29418, is graded by `infra-ssh` (Gerrit embeds Apache MINA SSHD, whose
rows are in `infra-ssh` `references/ssh-cve-matrix.md`). Secrets inside public
repositories are `hunt-source-leak`.

Rate posture: serial, 2 s base plus 0-3 s jitter (`probe_delay` in `SKILL.md`).

---

## GitLab self-managed

### Stage A

```bash
G="https://target.example"
# Sign-in page: product, edition hints, and whether a "Register now" link exists.
curl -s -m 15 "${G}/users/sign_in" | grep -o -i -m5 'gitlab [a-z ]\{0,30\}edition\|register now\|users/sign_up\|saml\|omniauth[a-z_/]*' | sort -u
probe_delay
# Version API: needs a token on current releases (verify). The status code is the result.
curl -s -m 15 -o /dev/null -w 'api/v4/version %{http_code}\n' "${G}/api/v4/version"
probe_delay
# Public projects, first page only. Names and counts.
curl -s -m 15 -D - -o /tmp/gl_projects.json "${G}/api/v4/projects?visibility=public&per_page=20&simple=true" \
  | grep -i -E '^(HTTP/|x-total:|x-total-pages:)'
jq -r '.[].path_with_namespace' /tmp/gl_projects.json
```

| Result | Meaning |
|---|---|
| `/api/v4/version` answers `200` without a token | Older release or a permissive configuration: exact version and revision. |
| `401` on the version API | Expected. Fall back to the version in the client's documentation, or report without one. Static-asset hashing tools exist for GitLab (third-party, verify their accuracy) and are acceptable Stage A only if they issue plain GETs for public assets. |
| "Register now" on the sign-in page | Sign-up is enabled. New instances may still require administrator approval of each sign-up (verify on the version); the page text usually says so. |
| SAML or OmniAuth buttons | Identity-provider integration: `hunt-saml`, `hunt-oauth`, and CVE-2024-45409 in the matrix. |
| Public project list | Public by the owner's choice. A finding only when the names show internal code or the projects hold secrets (`hunt-source-leak`). |

The GitLab container registry, when enabled on the GitLab domain, commonly
listens on 5050; treat it with `artifact-registries.md` (Docker Registry v2,
token auth realm pointing at GitLab's `/jwt/auth`).

KEV rows (matrix): CVE-2021-22205 (unauthenticated RCE through image upload),
CVE-2023-7028 (password-reset account takeover), CVE-2021-39935 (unauthenticated
SSRF through the CI Lint API), CVE-2021-22175 (webhook SSRF) and CVE-2026-85706
(unauthenticated arbitrary file read through the repository commits API, fixed
in the 19.3.2 patch release). All are version-gated here. Sending a password
reset for a real account, or a crafted file to the upload path, is an attack on
a user or on the server, not a check.

---

## Gitea and Forgejo

Gitea registers `/api/v1/version`, `/signing-key.gpg` and `/signing-key.pub` in
its "public accessible" route group (`routers/api/v1/api.go`). Forgejo is a
Gitea fork and keeps the same route.

```bash
F="https://target.example"
curl -s -m 15 "${F}/api/v1/version"; echo          # {"version":"..."}; Forgejo appends +gitea-<base> (verify)
probe_delay
# Installer reachable means INSTALL_LOCK is false. Read the page title only.
curl -s -m 15 -o /tmp/gitea_install.html -w 'install %{http_code}\n' "${F}/install"
grep -o -i -m1 '<title>[^<]*</title>' /tmp/gitea_install.html
probe_delay
# Registration and explore visibility.
curl -s -m 15 -o /dev/null -w 'user/sign_up %{http_code}\n' "${F}/user/sign_up"
curl -s -m 15 "${F}/api/v1/repos/search?limit=20" | jq -r '.data[]?.full_name'
```

| Result | Meaning |
|---|---|
| `/install` renders the installation page | **Critical as a state.** The web installer is live. Gitea before 28.0.0 issued an authenticated session for an existing administrator name submitted through it (CVE-2026-96404); on any version it lets anyone rewrite the configuration. Never submit the form. |
| `user/sign_up` returns `200` with a form | Registration open. Grade the PR:L rows in the matrix (Gitea, Forgejo) as reachable by anyone. |
| `repos/search` returns names without a session | Anonymous browsing on (`REQUIRE_SIGNIN_VIEW` off). Names and count only. |
| Version | Gitea switched to a new major numbering in 2026 (28.x follows 1.27.x in NVD records); match the line before comparing. |

---

## Gogs

Gogs prints its version in the page footer on default installs (verify per
version). Registration is open on a default `app.ini` (verify) and
`RequireSigninView` is off by default; CVE-2026-25242 (unauthenticated file upload, fixed in
0.14.1) depends on exactly that default.

```bash
O="https://target.example:3000"
curl -s -m 15 "${O}/" | grep -o -i -m2 'gogs[^<]\{0,40\}'
probe_delay
curl -s -m 15 -o /dev/null -w 'user/sign_up %{http_code}\n' "${O}/user/sign_up"
```

Gogs has the longest unpatched-RCE history in this family: the SonarSource
2024 set (CVE-2024-39930 through CVE-2024-39933, including argument injection
in the built-in SSH server), then a chain of incomplete fixes for `.git`
directory writes (CVE-2024-56731, CVE-2025-64111) and the KEV-listed symlink
`PutContents` flaw CVE-2025-8110. All need an account, which open registration
supplies. Version-gate only.

---

## Gerrit (8080 web, 29418 SSH)

### Stage A

```bash
R="https://target.example"        # or http://target.example:8080
# Gerrit prefixes JSON with )]}' — strip the first line before parsing.
curl -s -m 15 "${R}/config/server/version"; echo
probe_delay
curl -s -m 15 "${R}/config/server/info" | tail -n +2 | jq '{auth_type: .auth.auth_type, register_url: .auth.register_url, sshd: .sshd, download_schemes: (.download.schemes | keys?)}'
probe_delay
# SSH ident only. No key exchange, no login.
timeout 10 nc -w 5 target.example 29418 </dev/null | head -1
```

The REST paths without the `/a/` prefix are the anonymous view; `/a/` forces
authentication. From `SshDaemon.java`, the SSH ident is
`SSH-2.0-GerritCodeReview_<gerrit version> (<Apache MINA SSHD version>)`, so the
SSH port alone gives both the Gerrit version and the embedded SSHD version
(`infra-ssh` grades the latter).

`config/server/info` names the authentication type (`LDAP`, `OAUTH`,
`OPENID`, `HTTP`, `DEVELOPMENT_BECOME_ANY_ACCOUNT`) and the SSH address.
**`DEVELOPMENT_BECOME_ANY_ACCOUNT` on an internet-facing Gerrit is Critical as a
state**: it is the development mode that lets anyone sign in as any account.
Report it; do not use it.

Anonymous project listing (`GET /projects/?n=20`) answers when "Anonymous
Users" keep read access on `All-Projects`, which is the shipped default (verify
per version). Names only.

---

## git daemon (9418)

The git daemon serves repositories over `git://`, unauthenticated by design.
It sends no banner; the version comes from the `agent=` capability in the
upload-pack advertisement.

```bash
# Needs a repository path. Take it from the client, a gitweb/cgit page or the
# forge; do not guess paths with a wordlist.
GIT_TRACE_PACKET=1 timeout 20 git ls-remote "git://target.example/<repo>.git" 2>&1 \
  | grep -o -m1 'agent=git/[^ ]*'
timeout 20 git ls-remote "git://target.example/<repo>.git" | head -20
```

| Result | Meaning |
|---|---|
| Ref list returned | The repository is exported to the internet. High when it is private source. Ref names and count are the evidence. |
| `access denied or repository not exported` | Path wrong or not exported. Not evidence either way. |
| `agent=git/<version>` | Server git version for the matrix. |

Configuration you cannot see but should ask about: `--export-all` (exports
every repository under the base path, not only those with
`git-daemon-export-ok`), `--enable=receive-pack` (anonymous **push**) and
`--enable=upload-archive` (`git archive --remote`). Testing anonymous push
writes to the repository: forbidden. Git CVE-2025-48384 (KEV) is a client-side
clone flaw and is not evidence against an exposed daemon.

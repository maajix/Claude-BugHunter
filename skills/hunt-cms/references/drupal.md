# Drupal

Drupal core is comparatively well audited, and the project publishes unusually
precise advisories. Two consequences for a hunt: the branch-support question is
the highest-value core check, and the contrib module layer is where the
unreviewed code lives.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter. Caps per host:
15 version requests, 200 module probes, 50 user probes, 25 leftover paths.

```bash
# Define this before any loop below. Never tighten it to finish a list faster.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }
```

## 1. Fingerprint corroboration

| Artifact | Request | What it proves |
|---|---|---|
| Response headers | `X-Generator: Drupal N`, `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache` | Drupal, and often the major version |
| Core JS | `GET /core/misc/drupal.js` (Drupal 8 and later) or `/misc/drupal.js` (Drupal 7) | Which era the install belongs to |
| Files directory | `/sites/default/files/` or `/sites/all/` references in the baseline HTML | Drupal layout |
| Canonical node route | `GET /node/1` | Drupal routing, even when path aliases hide it everywhere else |
| Generator meta | `<meta name="Generator" content="Drupal N (https://www.drupal.org)" />` | Major version |

The `/core/` prefix versus a bare `/misc/` and `/modules/` layout is the
cheapest Drupal 7 versus Drupal 8-and-later discriminator.

## 2. Version pinning, then the support verdict

```bash
T="https://target.example"
# Changelog. Newer installs block these by default, so absence proves nothing.
curl -s -m 15 "$T/CHANGELOG.txt"      | head -3   # Drupal 7 layout
curl -s -m 15 "$T/core/CHANGELOG.txt" | head -3   # Drupal 8 and later
# Generator header and meta tag
curl -sI -m 15 "$T/" | grep -i '^x-generator'
curl -s  -m 15 "$T/" | grep -oiE 'content="Drupal [^"]+'
# Core asset version query strings track the core release
curl -s -m 15 "$T/" | grep -oE '/core/[^"'"'"']+\?v=[0-9.]+' | head -5
```

Then the question that actually matters, answered by the project's own release
feed rather than from memory:

```bash
# Which branches currently receive releases at all
curl -s https://updates.drupal.org/release-history/drupal/current | \
  grep -oE '<supported_branches>[^<]+</supported_branches>'
# Latest release per branch
curl -s https://updates.drupal.org/release-history/drupal/current | \
  grep -oE '<version>[^<]+' | head -10
```

Queried this session, that endpoint reported supported branches `10.6.`, `11.3.`,
`11.4.`, `11.5.` and `12.0.`, with a 12.0 beta published. Re-query it; the point
is the method, not the snapshot. Anything on 8.x, 9.x or an unsupported 10.x or
11.x minor is outside security coverage, which is itself a reportable finding
even without a specific CVE.

## 3. Core advisories with verified ranges

Read from the project's advisories this session. Drupal expresses severity on a
25-point scale, which is more useful than CVSS here.

| Advisory | CVE | Severity | Affected | Fixed |
|---|---|---|---|---|
| SA-CORE-2026-004, SQL injection in the database abstraction API | CVE-2026-9082 | Highly critical, 23/25, exploitable by anonymous users, exploit attempts detected in the wild | 8.9.0 to before 10.4.10; 10.5.0 to before 10.5.10; 10.6.0 to before 10.6.9; 11.0.0 to before 11.1.10; 11.2.0 to before 11.2.12; 11.3.0 to before 11.3.10 | 10.4.10, 10.5.10, 10.6.9, 11.1.10, 11.2.12, 11.3.10. Drupal 9 and 8.9 received best-effort patches only. |
| SA-CORE-2026-005, PHP object injection in JSON:API | CVE-2026-55803 | Critical, 18/25, requires a user with JSON:API write permission | 10.5.x before 10.5.12; 10.6.x before 10.6.11; 11.2.x before 11.2.14; 11.3.x before 11.3.12 | 10.5.12, 10.6.11, 11.2.14, 11.3.12 |
| SA-CORE-2024-007, gadget chain | CVE-2024-55637 | Moderately critical | 8.0.0 to before 10.2.11; 10.3.0 to before 10.3.9; 11.0.0 to before 11.0.8 | 10.2.11, 10.3.9, 11.0.8. Drupal 7 not affected. |
| SA-CORE-2024-008, gadget chain | CVE-2024-55638 | Moderately critical | Drupal 7 before 7.102; 8.0.0 through 10.2.x before 10.2.11; 10.3.0 before 10.3.9 | 7.102, 10.2.11, 10.3.9 |

Two conditions on CVE-2026-9082 decide whether it is live on your target, and
both must be checked before you write it up:

- **It only affects sites using PostgreSQL.** On MySQL or MariaDB the injection
  does not occur. Do not claim it without evidence of the database engine, and
  do not go hunting for that evidence inside the application.
- The same releases also bundled third-party dependency updates (Symfony and
  Twig) that apply to all sites, so the release is worth installing regardless.

CVE-2026-55803 needs an entity reference field type that stores a serialised
property, and JSON:API write access. The advisory states that no field type
shipped with core meets the first condition, and JSON:API is read-only by
default. That makes it a contrib-dependent finding, not a core one, which is
exactly the pattern of the 2024 gadget chains: a chain in core becomes code
execution only when some other component passes request data to `unserialize()`.

Also current in 2026 and worth checking against the version you pinned:
SA-CORE-2026-008 (server-side request forgery), SA-CORE-2026-010 (information
disclosure), SA-CORE-2026-011 and 2026-012 (cross-site scripting),
SA-CORE-2026-013 (third-party libraries). Read each at
`https://www.drupal.org/sa-core-2026-<nnn>` and use its own affected-version
expression. The whole core feed is at <https://www.drupal.org/security/rss.xml>.

## 4. Module and theme enumeration

The highest-value trick is not a wordlist. It is the exported configuration
directory, which some sites leave inside the web root and serve as static files.
One request gives you the complete enabled-extension list, which converts a
blind guess into a precise target list.

```bash
# Exported configuration. Yields every enabled module and theme.
curl -s -o /tmp/d-ext.yml -w '%{http_code} %{size_download}\n' -m 15 \
  "$T/config/sync/core.extension.yml"
head -40 /tmp/d-ext.yml
# Core service definitions, sometimes readable
curl -s -o /dev/null -w '%{http_code}\n' -m 15 "$T/core/core.services.yml"
```

If `core.extension.yml` is readable, other files in the same directory are too,
and they are named after the modules they configure (mail transports, search
backends, API clients). Fetch only what the engagement needs, record what you
fetched, and redact any credential a configuration file hands you rather than
copying it into notes.

Failing that, the passive and active ladder:

```bash
# Passive: module and theme paths already present in the rendered page
grep -oE '/(core/)?(modules|themes)/(contrib/)?[a-z0-9_-]+' /tmp/cms-baseline.html | sort -u
# Active: a module's own info file is the authoritative version source
for m in "<candidate-module>" "zz_not_real_$RANDOM"; do
  printf '%s ' "$m"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 \
    "$T/modules/contrib/$m/$m.info.yml"
  pace
done
```

Drupal 7 modules use `<name>.info` rather than `<name>.info.yml`, and may sit
under `/sites/all/modules/`. Contrib advisories live at
<https://www.drupal.org/security/contrib> as `SA-CONTRIB-<year>-<nnn>`; that
feed is where the realistic findings are.

## 5. Content and user enumeration

```bash
# Nodes: find content that is published but not linked from navigation.
for i in $(seq 1 30); do
  printf 'node/%s ' "$i"
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -m 15 "$T/node/$i"
  pace
done

# Users: profile route. Compare status, length and redirect target, not status alone.
for i in 1 2 3 4 5; do
  printf 'user/%s ' "$i"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 "$T/user/$i"
  pace
done
```

Two more channels, both of which are only enumeration oracles when the site
returns distinguishable answers:

- `GET /user/register` and submit a username that is already taken. The form
  reports the collision. **This posts a form.** It creates no account when the
  username collides, but it is still a write attempt against a public form:
  treat it as Stage B unless the engagement explicitly allows registration
  attempts, and never complete a registration.
- The password-reset form reports clearly whether an account exists. Same
  caution: a reset request sends mail to a real person. Do not use it on a
  production site without sign-off, and never against an address you do not own.

Drupal's default role structure is Administrator, Authenticated user and
Anonymous user, but permissions are fully site-configurable and sites add roles
freely. Test effective permissions, never a role name.

`/jsonapi/` and `/user/login?_format=json` as native-credential entry points
that sit beside an SSO layer belong to `hunt-auth-bypass`.

## 6. Leftover and misconfiguration paths

Detect only. Never submit an installer form.

| Path | Meaning |
|---|---|
| `/core/install.php`, `/install.php` | Installer reachable. On a configured site it normally refuses, but a reachable installer on an unconfigured or half-migrated site is a takeover. Detect and stop. |
| `/core/rebuild.php`, `/rebuild.php` | Cache rebuild endpoint. Needs a valid token on a configured site; reachable without one is a finding. |
| `/config/sync/*.yml` | Exported configuration in the web root. See section 4. |
| `/sites/default/files/` with a listing | Public files directory. Look for exported CSVs, private attachments and backup archives. |
| `/sites/default/settings.php` served as text | Should never be readable. Confirm the content type and that the first bytes are PHP source, then stop. Do not harvest the credentials; the readability is the finding. |
| `/update.php` | Database update runner. Requires authentication on a healthy site. |
| `/web.config`, `/.ht.router.php`, `/composer.json`, `/composer.lock` | Build metadata. `composer.lock` pins the exact core and contrib versions, which is the best version artifact when the changelog is blocked. |

## 7. Admin-to-RCE and XSS-to-RCE

Drupal, unlike WordPress, does not ship a PHP template editor. Historically the
route was the PHP Filter module, which lets a privileged user store PHP inside
content; it was removed from core and exists only as contrib. Other routes
require installing a module, which is a module upload.

Consequences for a hunt:

- **Enumerating whether a PHP-evaluation module is enabled is Stage A** and
  valuable: it turns any administrator-level compromise into code execution.
  Check `core.extension.yml` if you have it, or probe for the module's own info
  file.
- **Installing a module, enabling one, or saving content containing PHP is
  Stage B** and needs written sign-off plus a tester-owned site. Use an
  inert marker, prove evaluation, then disable and remove.
- Published "XSS to RCE" tooling for Drupal automates administrator-session
  abuse to create an administrative user and upload a backdoored template.
  **Do not run third-party exploitation frameworks against a client site.** The
  reportable content is the XSS plus the demonstrated administrator capability,
  and the chain description from the advisory.

One deliberate exclusion: the published "configuration synchronisation
backdoor" technique for Drupal is not reproduced in this skill. It installs
modules, rewrites site configuration and deliberately disguises its own requests
in the target's access log. Log manipulation to avoid detection is out of scope
for this bundle, and the state changes are unacceptable on a client site.

## 8. False-positive killers specific to Drupal

- **A missing `CHANGELOG.txt` means nothing.** Current installs block it by
  default. Use `composer.lock`, the generator header or core asset versions.
- **CVE-2026-9082 needs PostgreSQL.** Without evidence of the database engine,
  the version match is not a confirmed finding.
- **CVE-2026-55803 needs JSON:API write access and a serialising field type.**
  JSON:API is read-only by default and no core field type qualifies. A version
  match alone is not a finding.
- **A gadget-chain advisory is not directly exploitable.** It is a chain half.
  Report it as hygiene unless you can name the component that reaches
  `unserialize()` with request data.
- **`/node/<n>` returning 403 is information.** It distinguishes "node exists
  but is unpublished or restricted" from "node does not exist", which is a
  content-enumeration oracle, not an access-control bug by itself.
- **A path alias can mask the canonical route.** The absence of `/node/1` does
  not mean the site is not Drupal.
- **`droopescan` reports possible versions from heuristics.** Treat every output
  version as a hypothesis and confirm it against a vendor artifact.

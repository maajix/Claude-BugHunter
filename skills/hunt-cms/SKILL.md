---
name: hunt-cms
description: "Hunt internet-facing content-management and groupware applications: WordPress, Drupal, Joomla, Moodle, PrestaShop, Roundcube, Bolt CMS and Adobe Experience Manager (AEM, Sling, CRX). Covers per-product version fingerprinting and branch-support checks, the plugin/module/extension/theme supply chain where most real bugs live (wp-content/plugins, admin-ajax.php wp_ajax_nopriv handlers, register_rest_route permission_callback, Drupal contrib modules, Joomla com_* components, Moodle /mod/ /blocks/ /local/), leftover installer and configuration paths (install.php, /installation/, /install/, /config/sync/*.yml, CHANGELOG.txt), user and author enumeration, and the authenticated-admin-to-RCE path per product (theme and template editors, plugin ZIP upload, Twig templateselect, calculated questions, CRX package manager). Stage A read-only by default; anything that installs, posts or updates is Stage B behind written sign-off. Use when a target fingerprints as a CMS, webmail or e-commerce platform."
sources: hacktricks_coverage_checklist, nvd, vendor_advisories, patchstack_advisories, project_documentation, vendor_release_apis, authorized-engagement
report_count: 0
---

## Crown Jewel Targets

The money is almost never in CMS core. Core is read by thousands of people and
patched on a schedule. The money is in the three layers bolted on around it.

1. **The extension supply chain.** A plugin, module, component or theme written
   by one person, installed on a corporate domain, running with the same
   database credentials as everything else. A $0 plugin on a Fortune 500
   marketing site inherits that brand's severity. This is the single highest
   yield surface in this skill.
2. **The forgotten satellite install.** `blog.`, `careers.`, `events.`,
   `shop.`, `mail.`, `learn.` and country-code subdomains. Marketing stood it
   up, nobody owns it, autoupdate was disabled years ago to protect a custom
   theme.
3. **Leftover installer and migration state.** An installer route that still
   answers, a `/config/sync/` directory served as static files, a staging copy
   at `/old/` or `/wp2/` with the pre-migration plugin set.
4. **Author and editor accounts as a pivot.** Many products hand a non-admin
   content role a template, formula or upload primitive that reaches PHP. The
   finding is not "a low-privileged user exists". The finding is that the
   low-privileged role crosses into code execution.
5. **Groupware and webmail front doors.** Roundcube on `mail.<target>` is a
   credential-bearing application sitting on the public internet. A post-auth
   RCE there is worth more than its CVSS vector suggests, because one phished
   or sprayed mailbox password reaches it.

## OOB/Confirmation Gate

A CMS fingerprint is not a finding and a version number is not a finding. What
counts as proof, per claim:

| Claim | Proof required | Not proof |
|---|---|---|
| Product X is running here | Two independent artifacts (a path that only X serves **and** a header, cookie, meta tag or JS global that only X sets) | One guessed path returning 200, one `/robots.txt` line, a theme name reused by other products |
| Version is N | A vendor-shipped version artifact (manifest XML, upgrade.txt, JS global, asset `?ver=` on a core file) corroborated by a second artifact | A scanner's single "possible version", a copyright year, a CDN `?ver=` on a plugin asset |
| Version N is vulnerable to CVE-Y | The vendor advisory's own affected-version expression, read this session, **plus** a behavioural check against the target | "N is less than the fixed version" alone. Backports exist. See Gate 0. |
| This extension is installed | The extension's own asset or readme served from its own directory, plus its version string | A 403 on its directory. A 403 frequently means "directory listing denied" for a directory that does not exist. |
| This user exists | Two enumeration channels agreeing (for example an ID probe and a REST or author route) | A single differential response on a login form behind a WAF |
| The bug is real | A unique canary you generated, echoed in the response body, plus a body diff against a saved baseline of the same request with a benign value | A 500, a stack trace, a timing wobble, a WAF block page |

For any server-side-request or callback claim, the callback must land on
infrastructure you control and must carry a per-request canary that ties it to
one parameter. Follow the `hunt-ssrf` confirmation discipline verbatim; this
skill does not restate it.

## Attack Surface Signals

### Fingerprint, then load exactly one reference file

Run the passive fingerprint first. It costs one request per host.

```bash
T="https://target.example"
curl -sSik -m 15 -A "<UA>" "$T/" -o /tmp/cms-baseline.html -D /tmp/cms-baseline.hdr
grep -iE 'x-generator|x-drupal|x-powered-by|x-dispatcher|^set-cookie' /tmp/cms-baseline.hdr
grep -oiE '<meta name="generator" content="[^"]+"' /tmp/cms-baseline.html
grep -oE '(wp-content|wp-includes|/sites/(default|all)/|/media/(system|jui)/|/etc\.clientlibs/|/theme/[a-z]+/|/modules/ps_|rcmail\.env\.rcversion|/theme/image\.php)[^"'"'"' ]*' /tmp/cms-baseline.html | sort -u | head -30
```

Keep `/tmp/cms-baseline.html` and `/tmp/cms-baseline.hdr`. Every later body
diff in this skill compares against them.

| Signal seen | Product | Load |
|---|---|---|
| `wp-content/`, `wp-includes/`, `/wp-json/`, `meta generator WordPress`, `wp-settings-time` cookie | WordPress | `references/wordpress.md` |
| `X-Generator: Drupal`, `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache`, `/sites/default/files/`, `/core/misc/drupal.js`, `/node/<n>` | Drupal | `references/drupal.md` |
| `meta generator Joomla!`, `/media/system/js/`, `/media/jui/`, `/administrator/`, `/index.php?option=com_` | Joomla | `references/joomla.md` |
| `/theme/image.php`, `/theme/yui_combo.php`, `MoodleSession` cookie, `/login/index.php` with Moodle branding, `M.cfg` JS global | Moodle | `references/moodle.md` |
| `/etc.clientlibs/`, `X-Dispatcher`, `/libs/granite/core/content/login.html`, `/content/dam/`, `CQ` HTML comment | Adobe Experience Manager | `references/aem.md` |
| `/modules/ps_`, `/themes/classic/assets/`, `prestashop` JS global, `/index.php?controller=` | PrestaShop | `references/prestashop-roundcube-bolt.md` |
| `rcmail.env.rcversion`, `/program/js/app.js`, `roundcube_sessid` cookie, `?_task=login` | Roundcube | `references/prestashop-roundcube-bolt.md` |
| `/bolt/` back end, `/theme/<name>/` Twig assets, Symfony `X-Debug-Token` on a Bolt route | Bolt CMS | `references/prestashop-roundcube-bolt.md` |

**Not this skill.** SharePoint goes to `hunt-sharepoint`. Sitecore and
DotNetNuke go to `hunt-aspnet`. A bare `/xmlrpc.php` or `/wp-json/wp/v2/users`
probe used as an SSO or MFA bypass is already owned by `hunt-auth-bypass` and
its Legacy-Protocol Matrix, which also covers the Drupal `/jsonapi/` and
`/user/login?_format=json` and Joomla `/administrator/index.php?option=com_login`
native-credential paths. Do not re-run that matrix here; this skill picks up
after it, at version and extension level.

### Secondary signals worth a note

- A `Link:` response header advertising `<.../wp-json/>; rel="https://api.w.org/"`
  proves WordPress even when the generator tag is stripped.
- A product's 404 body is a fingerprint. Save it; several products leak a
  version or a theme path only on 404.
- Asset query strings (`?ver=`, `?v=`) on **core** files track core version.
  On plugin files they track the plugin version. Do not mix them up.
- A CDN or WAF in front changes nothing about fingerprinting but changes
  everything about rate limits. See Step 2.

## Step-by-Step Methodology

### Step 1 - Confirm scope and the chain's end

This skill stops at **vulnerability confirmed, impact described, evidence
captured**. It contains no database access, no credential extraction from a
session store, no operating-system work after code execution, no persistence.
If a product hands you code execution, you already have the finding. Two
explicit cuts, because public write-ups walk straight past them:

- Never run a `SELECT` or `UPDATE` against a CMS database, never read a
  `wp-config.php`, `settings.php`, `configuration.php` or `config.inc.php` for
  the purpose of harvesting credentials, and never decrypt stored session
  secrets. Proving you can read the file is the finding. Reading its contents
  into your notes is data handling you do not need.
- Never submit an installer form. Detecting a reachable installer is Stage A and
  is the finding. Completing it can reinitialise the database.

### Step 2 - Set the rate posture before the first loop

Extension and version enumeration is the noisiest thing in this skill. Every
loop below is serial with jitter. No exceptions, no "just this once".

```bash
# One request at a time, 1.5s base + 0-1.5s jitter. Default for every loop here.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }

# Hard caps per host, per run. Write them down before you start.
#   version artifacts:        <= 15 requests
#   extension slug probes:    <= 200 requests   (curated list, never a 100k wordlist)
#   user/ID enumeration:      <= 50 requests
#   installer/leftover paths: <= 25 requests
```

If a tool is used instead of a loop, give it the same posture. For `wpscan`,
the verified flags are `--throttle <milliseconds>` (which forces max threads to
1), `-t`/`--max-threads` (default 5), `--request-timeout <seconds>` (default
60), `--random-user-agent`/`--rua`, `--plugins-detection <mixed|passive|aggressive>`
and `-e` with values `vp,ap,p,vt,at,t,tt,cb,dbe,bf,u,m`. Start passive:

```bash
# Stage A. Passive plugin detection only, serial, 600ms between requests.
wpscan --url "$T" --rua --throttle 600 --plugins-detection passive -e vp,vt,cb,dbe,u1-20
```

Escalate to `--plugins-detection aggressive` only with the operator's agreement,
because that mode probes a large slug list and is trivially visible in logs.
`droopescan scan <drupal|joomla|moodle> -u "$T" -t 1` keeps the same posture
(its `-t` is thread count; the published examples use 32, which is far too
aggressive for a production target).

**Scanners are not installed by default in this environment.** `curl` and
`nuclei` are. Prefer the explicit `curl` probes in the reference files: they are
reproducible in a report, and you can see exactly how many requests you sent.

### Step 3 - Pin the version to a branch, then ask whether that branch is supported

A raw version string is worth little on its own. What matters is whether the
installed build still receives security fixes, and whether the applicable
backport landed. Each product publishes a machine-readable answer. Use it, and
record the date you queried it:

```bash
# WordPress: per-version verdict (latest / outdated / insecure)
curl -s https://api.wordpress.org/core/stable-check/1.0/ | python3 -I -c \
  'import json,sys; print(json.load(sys.stdin).get("<VERSION>","unknown"))'

# Drupal: currently supported branches and releases
curl -s https://updates.drupal.org/release-history/drupal/current | \
  grep -oE '<supported_branches>[^<]+</supported_branches>'

# Joomla: current release per branch
curl -s https://update.joomla.org/core/extension.xml | grep -oE '<version>[^<]+' | tail -5

# Roundcube, PrestaShop, Bolt: GitHub releases of the upstream project
curl -s "https://api.github.com/repos/roundcube/roundcubemail/releases?per_page=5" | \
  python3 -I -c 'import json,sys; [print(r["tag_name"], r["published_at"][:10]) for r in json.load(sys.stdin)]'
```

Moodle and AEM have no equivalent public verdict API. For Moodle, read the
project's security announcements forum for the branch you fingerprinted. For
AEM, read the Adobe `APSB` bulletin whose quarter matches the deployed service
pack. Do not infer either from memory.

### Step 4 - Enumerate extensions passively before actively

Order matters, both for noise and for accuracy.

1. **From the saved baseline HTML.** Extract every extension path and version
   query string already present in the page you fetched in the fingerprint
   step. Zero extra requests.
2. **From other crawled pages.** A contact form, a search page and a checkout
   page load different extensions than the home page.
3. **From sitemaps and feeds.** `wp-sitemap.xml` (WordPress core since 5.5),
   `/sitemap.xml`, RSS feeds. Still passive.
4. **Only then, actively**, against a curated slug list built from what the
   passive pass suggests (a job-board theme implies job-board plugins; a shop
   implies payment extensions). Capped at 200 probes, serial, with `pace`.

Each reference file names the exact directory layout and version artifact for
its product.

### Step 5 - Enumerate users, and keep it cheap

User enumeration is a finding on its own (low severity, consistently accepted)
and it is the input to everything authenticated. Each product has two or three
channels; they are listed per product in the reference files. Two rules that
apply everywhere:

- Cross-check two channels before asserting a username exists. One channel can
  be a WAF artifact.
- **Never** turn an enumerated list into a password-guessing run from this
  skill. Credential testing has its own skill, scope rules and lockout risk:
  `hunt-brute-force`.

### Step 6 - Map version plus extension set to advisories

For each confirmed extension and version, read the advisory, not a summary. The
reference files carry a verified version-to-CVE table per product with the
source link. For anything not in those tables:

- WordPress plugins and themes: the WPScan and Patchstack vulnerability
  databases, then the plugin's own `trac` changeset for the fix.
- Drupal contrib: `drupal.org/security/contrib` advisories (`SA-CONTRIB-...`).
- Joomla core: the Joomla Security Centre. Joomla extensions: the Vulnerable
  Extensions List.
- Moodle: the project's security announcements, which name the exact fixed
  point release per branch.
- Roundcube, PrestaShop, Bolt: the upstream GitHub security advisories.

### Step 7 - Behavioural check, Stage A only

Confirm the bug with the least invasive observable the advisory allows. The
per-product Stage A probes are in the reference files. A version in a
vulnerable range plus a matching behavioural signal is a report. A version in a
vulnerable range alone is not (Gate 0).

### Step 8 - Stage B, only on written sign-off

Stage B is **anything that changes state on the target**: installing or
activating an extension, uploading a file, editing a template or theme, saving
content, triggering an update, switching a session into another account,
creating a user. Every Stage B step in this skill requires:

1. The operator's explicit written sign-off, quoting the specific action.
2. A tester-owned account or a tester-created object as the subject. Never a
   real customer, student or employee account.
3. An inert proof first (an arithmetic marker, a canary string), never a shell.
4. A named restore step, executed immediately, and recorded.

Where the only published route to proof is destructive, do not take it. Write
the Stage A reachability proof, state the impact from the advisory, and stop.

### Step 9 - Grade by what the chain actually reaches

| Outcome | Typical grade |
|---|---|
| Unauthenticated code execution, or unauthenticated admin account creation | Critical |
| Unauthenticated read of the application's configuration file or database contents | Critical or High, depending on what the file holds |
| Authenticated-low-role to code execution (editor, author, subscriber, teacher) | High |
| Authenticated-admin to code execution where admin is intended to be able to edit templates | Low by itself. This is designed behaviour in most of these products. It is only a finding as the back half of a chain whose front half you have proven. |
| Version disclosure, user enumeration, installer path reachable | Low or Informational. Report, do not inflate. |

The admin-to-RCE row is where most CMS reports lose credibility. Read it twice.

## Payload & Detection Patterns

### The canary pattern, used for every behavioural check

```bash
CANARY="cmsprobe$(date +%s)$RANDOM"
# 1. baseline with a benign value
curl -sSik -m 15 "$T/<endpoint>?<param>=benign" -o /tmp/base.out
# 2. same request, canary value
curl -sSik -m 15 "$T/<endpoint>?<param>=$CANARY" -o /tmp/test.out
# 3. the canary must appear in the response, and the diff must be attributable
grep -c "$CANARY" /tmp/test.out
diff <(sed 's/[0-9a-f]\{16,\}//g' /tmp/base.out) <(sed 's/[0-9a-f]\{16,\}//g' /tmp/test.out) | head -40
```

A WAF block page, an error page and a cached response all diff. Only a diff
that contains your canary, in a position the application chose, is evidence.

### Template-engine and formula markers

Use arithmetic, never code, for the first proof. `{{7*7}}` rendering as `49`
in a Twig theme, or a calculated-question formula evaluating, proves controlled
evaluation. Follow `hunt-ssti` for the engine-specific escalation; this skill
only identifies which CMS field reaches which engine.

### Detection greps for source review

When the extension source is available (a public repository, a free version on
the vendor's directory, a readable file on disk), these patterns find the bug
faster than any request:

```bash
# WordPress: unauthenticated AJAX and permissionless REST
grep -rn "wp_ajax_nopriv_" --include=*.php .
grep -rn "permission_callback'\s*=>\s*'__return_true'" --include=*.php .
grep -rn "wp_set_auth_cookie\|wp_set_current_user" --include=*.php .
# nonce treated as authorization (it is not)
grep -rn "wp_verify_nonce\|check_ajax_referer" --include=*.php . | \
  xargs -I{} true   # then confirm each hit is paired with current_user_can()

# Any PHP CMS: user input into a path or an include
grep -rnE "(include|require|file_get_contents|unlink|\\\$wp_filesystem->delete)\s*\(.*\\\$_(GET|POST|REQUEST)" --include=*.php .
# Any PHP CMS: concatenation into SQL
grep -rnE "(query|get_results|get_var)\s*\(\s*[\"'].*\\\$_(GET|POST|REQUEST)" --include=*.php .
```

The generic exploitation of what these find belongs to `hunt-sqli`, `hunt-lfi`,
`hunt-file-upload` and `hunt-deserialization`. This skill's contribution is
knowing which endpoint, which extension and which parameter to point them at.

## Common Root Causes

1. **A CSRF token mistaken for an authorization check.** The single most
   productive root cause in the WordPress ecosystem, and the pattern recurs in
   every product with an AJAX layer. A nonce proves the request came from a
   page the user loaded. It proves nothing about what that user may do. Code
   that validates a nonce and then skips the capability check hands privileged
   actions to anyone who can load the page the nonce is printed on, which
   routinely includes the lowest self-registration role.
2. **An unauthenticated hook registered for convenience.** The handler was
   written for logged-in use, then exposed to anonymous callers so a public
   widget would work.
3. **Identity derived from client input.** A header, a cookie or a POST field
   naming a user, trusted because an upstream component was supposed to set it.
4. **A permissive default left in place.** A permission callback that always
   returns true, a debug or dev mode shipped enabled, an anonymous read ACL on
   a content repository.
5. **Installer and migration leftovers.** The installer directory that was
   never deleted, the exported configuration directory served as static files,
   the `.old` copy of a template.
6. **Templates as a code surface.** Every product here lets a sufficiently
   privileged user edit a template, and every template language here reaches
   the host language. The bug is almost never the editor; it is the role
   boundary that leaks access to it.
7. **Two parsers disagreeing about the same string.** One sanitiser treats a
   construct as text, a later renderer treats it as markup. This produced a
   pre-authentication cross-site scripting bug in WordPress core itself, which
   is covered in `references/wordpress.md`.
8. **Deserialization reachable from user input.** A gadget chain in core is not
   exploitable alone; combined with any extension that passes request data to
   `unserialize()`, it becomes code execution. This is why the Drupal and
   Roundcube gadget advisories matter even though both say "not directly
   exploitable".

## Bypass Techniques

| Obstacle | Approach |
|---|---|
| Generator tag and version strings stripped | Fingerprint on paths and headers instead. Asset `?ver=` on core files, 404 body shape, and the product's own REST or API index. |
| `/CHANGELOG.txt`, `README.txt`, `license.txt` blocked | Use the product's other version artifacts: manifest XML, `upgrade.txt` under a subsystem directory, `composer.lock`, a JS global. Each reference file lists them. |
| Reverse proxy blocks a path prefix | The proxy and the application may normalise differently. Try a trailing path segment with an allowed extension, and percent-encoded separators. This is the documented AEM Dispatcher failure mode and the technique generalises; see `references/aem.md`. Always confirm the bypass changed the **application's** answer, not just the proxy's. |
| CMS installed in a subdirectory | Re-run the whole fingerprint rooted at that subdirectory. `robots.txt` and the installer paths move with it. Joomla's own documentation notes `robots.txt` must be relocated to the site root with the folder name prefixed to each path, which is a reliable subdirectory tell. |
| Login page hardened, renamed or IP-restricted | Owned by `hunt-auth-bypass`. Do not re-derive it here. |
| WAF in front of the application | Product-specific logic and authorization bugs look like ordinary traffic; a generic signature engine has nothing to match. Send the clean request first and do not obfuscate by reflex. If you are blocked, you are probably hitting a generic injection signature, which means you are testing the generic class rather than the CMS-specific path. |
| Extension directory returns 403 for everything | A 403 is not an existence oracle. Request a file the extension is known to ship (`readme.txt`, a named asset) and compare the response against a request for the same file under a deliberately invented extension slug. |

## Gate 0 Validation

Clear all of these before writing a word of the report.

1. **A version in a vulnerable range is not a finding.** Vendors backport
   security fixes to old branches, and distributions and hosts patch in place
   without changing the advertised version. WordPress's own advisory for the
   2026 login-screen XSS states the fix was backported to every branch back to
   4.7, so a site reporting an old version may be fully patched. Require a
   behavioural signal, or the host's own patch evidence, before you claim
   exploitability.
2. **Fingerprint corroborated by two artifacts**, per the OOB gate table. A
   single 200 on a guessed path is a coin flip.
3. **The response came from the application, not from an edge.** Compare
   against the saved baseline. A CDN error page, a "site for sale" parking page
   and a WAF challenge all produce plausible-looking bodies.
4. **The host is in scope, and it is actually the client's.** Shared hosting
   and multisite installs serve many organisations from one address. Confirm
   per hostname, not per IP.
5. **The extension is really installed, and really that version.** A theme
   bundling another author's library is not the same as that library's plugin
   being installed and active.
6. **The admin-to-RCE path is designed behaviour until you prove the front
   half.** "An administrator can edit a theme file and get PHP execution" is
   documented functionality in WordPress, Joomla, Bolt and Moodle. On its own
   it is not a vulnerability. It becomes one when you have proven how a
   non-admin reaches it.
7. **User enumeration is confirmed on two channels**, and you have not turned
   it into a login attempt.
8. **No state was changed without sign-off.** Check your own request log. If a
   probe wrote something, that was Stage B and it needed authorisation.
9. **An installer path that answers was detected, not completed.**
10. **The scanner did not invent the version.** `droopescan`, `moodlescan` and
    `cmsmap` all report "possible versions" from heuristics. Treat every
    scanner version as a hypothesis and confirm it against a vendor artifact.

## Real Impact Examples

Patterns, with the product-specific detail in the reference files.

- **Trusted header becomes administrator.** A payment extension for WordPress
  accepted a request header naming a user ID so that an upstream checkout
  service could act on a customer's behalf. Nothing bound that header to the
  upstream service, so an unauthenticated attacker could send it and create an
  administrator through the core users route. Fixed in the extension, not in
  core. Details and the version range in `references/wordpress.md`.
- **A plugin installer wired to a low-privileged role.** A commercial theme
  exposed an AJAX helper that downloads and activates a plugin from a URL in
  the request, gated only by a CSRF nonce that is printed on a page any
  self-registered subscriber can load. The result is attacker-chosen PHP in
  `wp-content/plugins/`, executed on activation.
- **An improper API access check leaks the application's configuration.** A
  Joomla branch shipped a web-services access check that could be bypassed,
  exposing a configuration endpoint. The response body carries database
  credentials, which is exactly why the probe is Stage A read-only and the
  evidence must be redacted before it reaches a report.
- **A content role reaching the PHP evaluator.** A Moodle question type
  evaluated an answer formula with incomplete sanitisation, so a user who could
  edit quiz questions (a teacher, not an administrator) reached code execution.
  The lesson generalises: audit every field in these products that is
  advertised as "a formula", "an expression" or "a template".
- **An exported configuration directory served as static files.** A Drupal site
  kept its configuration-synchronisation YAML inside the web root. Fetching it
  anonymously yields the full enabled-module list and service settings, which
  converts a blind version guess into a precise target list.
- **Webmail as the soft front door.** A Roundcube branch had a post-
  authentication object-deserialization bug reachable from a settings upload
  parameter. "Post-auth" sounds like a mitigation until you remember the
  application's whole purpose is to accept mailbox credentials from the
  internet.
- **A reverse proxy that normalises differently from the application.** AEM
  deployments rely on the Dispatcher to deny internal paths. Where the
  Dispatcher and the repository servlet disagree about separators and
  extensions, denied endpoints answer anyway, and the ones that answer return
  repository content including user nodes.

## References Index

Load one file. Each is self-contained and carries its own Stage A and Stage B
guards, because an agent routed by the fingerprint table reads only that file.

| File | Coverage | Trigger phrases |
|---|---|---|
| `wordpress.md` | Core version pinning and the stable-check API, 2026 core chains (login-screen XSS to RCE, REST batch route confusion plus WP_Query SQLi), plugin and theme supply chain with verified CVE table, `wp_ajax_nopriv` and `permission_callback` audit patterns, author and REST user enumeration, installer and backup leftovers, admin-to-RCE paths | wordpress version, wp-content plugins, wp-json, admin-ajax, wp_ajax_nopriv, wpscan, woocommerce payments header, suretriggers ottokit, depicter sqli, kubio lfi, funnelkit plugin install, motors theme, xss2shell, wp2shell |
| `drupal.md` | Version artifacts per major branch, supported-branch API, SA-CORE advisories with CVE and fixed versions, PostgreSQL SQL injection, JSON:API object injection, gadget chains, contrib module enumeration, config-sync and installer exposure, node and user enumeration | drupal version, changelog.txt drupal, drupal contrib module, sa-core, jsonapi drupal, config sync yml, droopescan drupal, node fuzzing, drupal gadget chain |
| `joomla.md` | Manifest and language XML version artifacts, Security Centre workflow, web-services access-check disclosure, 2026 core advisories (SSRF, MFA bypass via remember-me, filter bypass XSS), com_* extension enumeration, Vulnerable Extensions List, administrator surface, template-edit RCE as Stage B | joomla version, joomla.xml manifest, com_ component, joomla api config, joomla vulnerable extensions, joomscan, joomla template rce, joomla mfa bypass |
| `moodle.md` | Branch fingerprinting from upgrade.txt, composer.lock, behat features and environment.xml, calculated-question code injection with fixed versions, authenticated SSRF via TOCTOU DNS on calendar import and the file picker, plugin enumeration under /mod/ /blocks/ /theme/ /auth/ /local/, capability-not-role testing, plugin installer as Stage B | moodle version, moodle plugin, moodlescan, badmoodle, calculated question rce, moodle ssrf calendar import, mdl_ capability, moodle site:config |
| `aem.md` | Sling and Dispatcher fingerprinting, high-value unauthenticated endpoints, QueryBuilder and DefaultGetServlet exposure, Dispatcher path-normalisation bypasses, AEM Forms on JEE pre-auth OGNL and XXE with CVSS, APSB bulletin workflow, default credentials as a detection-only check, package manager and console as Stage B | aem version, adobe experience manager, sling servlet, dispatcher bypass, querybuilder json, crx packmgr, groovy console, adminui debug ognl, apsb bulletin, etc.clientlibs |
| `prestashop-roundcube-bolt.md` | PrestaShop version and admin-directory discovery, installer leftover, ps_checkout Express Checkout silent login with version ranges; Roundcube version from the JS global, post-auth deserialization RCE, release cadence; Bolt back-end discovery, editor async-upload to Twig template execution, template editor as Stage B. Thin products, covered honestly short | prestashop version, prestashop install folder, ps_checkout expresscheckout, roundcube version, rcversion, roundcube rce, bolt cms, bolt twig template, templateselect, role_editor upload |

Attribution: the product and technique coverage list was checked against the
HackTricks `pentesting-web` CMS pages
(<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a
checklist only. All prose, tables, staging and safety guidance here are
original. Version ranges, CVE identifiers, paths, parameter names and tool
flags were verified against NVD, vendor advisories (drupal.org, Joomla Security
Centre, roundcube.net, Adobe APSB, GitHub Security Advisories), Patchstack
database entries, vendor release APIs and project documentation.

## Related Skills & Chains

- `hunt-auth-bypass` owns the legacy-protocol and native-credential entry
  points for these products, including WordPress `xmlrpc.php` and
  `/wp-json/wp/v2/users` as SSO and MFA bypasses, Drupal `/jsonapi/` and
  `/user/login?_format=json`, and the Joomla administrator login. This skill
  starts after that matrix and works at version and extension level. Run both;
  do not duplicate either.
- `hunt-sqli`, `hunt-lfi`, `hunt-file-upload`, `hunt-deserialization`,
  `hunt-ssti`, `hunt-ssrf`, `hunt-xss` own the exploitation of each generic
  class. This skill's job is the CMS-specific route to them: which endpoint,
  which extension, which parameter.
- `hunt-sharepoint` owns SharePoint on-premises farms. `hunt-aspnet` owns
  Sitecore and DotNetNuke and the ViewState surface behind them.
- `hunt-brute-force` owns credential testing against any login this skill
  enumerates users from. Never guess passwords from here.
- `web2-recon`, `offensive-osint`, `recon-scope-triage` produce the host list,
  the subdomain inventory that surfaces forgotten satellite installs, and the
  scope confirmation. `offensive-osint` already carries the orphaned-WordPress-
  installer probe.
- `hunt-source-leak` for an exposed `.git`, backup archive or editor swap file
  found alongside a CMS, which short-circuits all extension enumeration.
- `hunt-exposed-services` if the same host also answers on a non-HTTP port.
- `triage-validation` and `evidence-hygiene` before the report: the Joomla
  configuration-disclosure and PrestaShop account-takeover probes both produce
  evidence that must be redacted.

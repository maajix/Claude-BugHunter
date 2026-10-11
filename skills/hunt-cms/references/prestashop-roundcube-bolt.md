# PrestaShop, Roundcube and Bolt CMS

Three smaller products grouped because the public research on each is thin.
This file is deliberately short: each product gets the fingerprint, the verified
advisory, and the honest statement of where the data runs out. Padding a thin
product with speculation is worse than admitting it is thin.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter.

---

# PrestaShop

An e-commerce platform, so the data at risk is customer personal information and
order history. That changes the evidence rules: a successful account-takeover
proof touches a real customer unless you create your own first.

## 1. Fingerprint corroboration

| Artifact | Request | What it proves |
|---|---|---|
| Module asset paths | `/modules/ps_<name>/` references in the baseline HTML | PrestaShop's native module naming |
| Theme assets | `/themes/classic/assets/` or `/themes/<name>/assets/` | PrestaShop theme layout |
| Front controller | `/index.php?controller=<name>` routing sensibly | PrestaShop's front controller |
| JS global | A `prestashop` JavaScript object in the page | PrestaShop front office |

Do not fingerprint on a cookie name. PrestaShop stores its state inside a single
encrypted cookie whose documented keys (`id_customer`, `id_cart`, `id_lang`,
`checksum` and others) are not visible from outside
(<https://devdocs.prestashop-project.org/9/development/components/cookie/>).

## 2. Version pinning and the back office

PrestaShop exposes no reliable public version artifact on a hardened install.
Practical approach:

- Ask the client, or read the version from the build metadata if a repository or
  `composer.lock` is exposed.
- Establish the current upstream releases rather than recalling them:

```bash
curl -s "https://api.github.com/repos/PrestaShop/PrestaShop/releases?per_page=5" | \
  python3 -I -c 'import json,sys; [print(r["tag_name"], r["published_at"][:10]) for r in json.load(sys.stdin)]'
```

Queried this session, the most recent releases were 9.2.0 (30 September 2026),
9.1.5 and 8.2.8 (both 18 August 2026). Re-query; the method is the point.

The back office directory is the interesting discovery target. Per the vendor's
own documentation, the admin folder is named `admin-dev` in a source-code
install and is renamed automatically when installing from the ZIP package, which
in practice appends a random numeric suffix (producing names of the form
`admin<digits>`). The documentation recommends additionally protecting that
folder at the web-server layer. So:

- `/admin-dev/` answering is a finding on its own: it means the site is running
  from a source checkout with the development admin path intact.
- A guessable admin path (`/admin/`, `/admin1/`) is a weak finding; an exposed
  admin login with no network restriction and no rate limiting is the real one.
  Credential testing against it belongs to `hunt-brute-force`.

## 3. Verified advisory

| CVE | What it is | Affected | Fixed | Score |
|---|---|---|---|---|
| CVE-2025-61922 | Improper authentication (CWE-287) in the `ps_checkout` module's Express Checkout flow. The flow accepts attacker JSON, validates only an order identifier, and when no customer is logged in it switches the storefront session to the account matching a payer email address taken from the request, without a password or token. Result: silent login as any customer whose email you know. | `ps_checkout` from 1.3.0 up to but not including 4.4.1, and 5.0.0 up to but not including 5.0.5 | Module 4.4.1 and 5.0.5. Patched PrestaShop builds: 7.4.4.1, 8.4.4.1, 7.5.0.5, 8.5.0.5, 9.5.0.5 | CVSS 3.1 9.1 Critical (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) |

Sources: <https://github.com/PrestaShopCorp/ps_checkout/security/advisories/GHSA-54hq-mf6h-48xh>
and the technical write-up at <https://dhakal-ananda.com.np/blogs/cve-2025-61922-analysis/>.

Mechanics worth knowing, because they drive the test design: the controller
reads the payer email from a nested field of the posted JSON, and the customer
context is updated even on a code path that ends in a 500 response. So a 500 is
not evidence the attempt failed.

**Stage A detection.** Confirm the module is installed and the endpoint is
routed, without supplying any email:

```bash
T="https://target.example"
curl -s -o /tmp/ps-ec.out -w '%{http_code} %{size_download} %{content_type}\n' -m 20 \
  -X POST "$T/module/ps_checkout/ExpressCheckout" \
  -H 'Content-Type: application/json' --data '{}'
head -c 300 /tmp/ps-ec.out
```

An answer from the module's controller (rather than a generic 404 page) plus a
module version in the affected range is a defensible report with the advisory
cited.

**Stage B, sign-off required.** The authentication-bypass proof requires sending
a real customer's email address and capturing the resulting session. Conditions,
all of them: written sign-off naming this action; a **tester-created customer
account** on the shop, never a real customer's address; no order placed and no
payment method used; the session discarded and the test account deleted
afterwards, recorded. The administrator account is a separate system and is not
affected by this flow, so there is no reason to aim at it.

Never use a real customer email. The impact statement from the advisory
(disclosure of the customer's personal data and the ability to transact with
payment methods already on the account) is sufficient for the report.

## 4. Leftover paths and false-positive killers

- `/install/` must be deleted after installation; the vendor documentation
  states this explicitly. A reachable installer directory is a finding.
  **Detect only, never submit the form:** completing it can reinitialise the
  shop database.
- `/docs/`, `/upload/`, `/download/` and `/img/` with directory listings expose
  invoices, product data and sometimes customer documents.
- A reflected or stored cross-site scripting bug in the back office is commonly
  escalated by published tooling into a module upload through an administrator's
  browser, producing persistent code execution. That chain exists and is worth
  describing. Do not run third-party exploitation frameworks against a client's
  shop; prove the XSS and cite the chain.
- Module version strings in asset paths are rewritten by caching and asset
  bundling. Corroborate before claiming a module version.
- A 500 from the Express Checkout controller does not mean the attempt failed.
  That is the specific trap in CVE-2025-61922.

---

# Roundcube

PHP webmail, typically on `mail.<target>` or `webmail.<target>`. The whole
application exists to accept mailbox credentials from the internet, which is why
a post-authentication bug here carries more weight than its vector suggests.

## 1. Fingerprint and version, in one request

Roundcube publishes its exact version into the page as a JavaScript global. This
is the cleanest version artifact of any product in this skill.

```bash
T="https://mail.target.example"
curl -s -m 15 "$T/" | grep -oE 'rcversion["'"'"']?\s*[:=]\s*["'"'"']?[0-9]+' | head
curl -s -m 15 "$T/?_task=login" | grep -oiE 'roundcube webmail [0-9.]+' | head
```

Corroborating artifacts: `/program/js/app.js`, a `roundcube_sessid` cookie, and
the `?_task=` query parameter driving the UI.

Then establish the current releases rather than recalling them:

```bash
curl -s "https://api.github.com/repos/roundcube/roundcubemail/releases?per_page=6" | \
  python3 -I -c 'import json,sys; [print(r["tag_name"], r["published_at"][:10]) for r in json.load(sys.stdin)]'
```

Queried this session, the most recent releases were 1.7.4 and 1.6.19, both
published on 6 September 2026. The project shipped seven security releases
during 2026 (February, March twice, May, July, August and September), and the
release announcements at <https://roundcube.net/news/> generally do not carry CVE
identifiers. That cadence is the important fact: a Roundcube install more than a
couple of months behind is very likely missing a security fix, and you will often
have to cite the release rather than a CVE.

## 2. Verified advisory

| CVE | What it is | Affected | Fixed | Score |
|---|---|---|---|---|
| CVE-2025-49113 | Post-authentication remote code execution. The `_from` parameter is not validated in the settings upload action (`program/actions/settings/upload.php`), which leads to PHP object deserialization and a gadget chain. | Roundcube before 1.5.10, and 1.6.x before 1.6.11 | 1.5.10 and 1.6.11, released 1 June 2025 | CVSS 3.1 9.9 Critical (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`) |

Sources: <https://nvd.nist.gov/vuln/detail/CVE-2025-49113> and
<https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10>.

**Stage A is sufficient here and is what you should do.** Read `rcversion` from
the page, corroborate with a second artifact, and compare against the fixed
releases. A version below 1.5.10 or in 1.6.0 to 1.6.10 is the finding, with the
advisory's own impact statement.

**Stage B, sign-off required, and usually unnecessary.** The exploitation route
needs valid mailbox credentials and writes to the application. If the operator
insists on a demonstration, use a tester-owned mailbox on a tester-owned
instance, and prove evaluation with an inert observable (a timing delay) rather
than a shell. Do not run a public exploit script against a client's mail server:
the gadget chain executes in the web worker's context and a failed attempt can
leave the application in a broken state.

The generic exploitation of PHP object injection belongs to
`hunt-deserialization`; this file only identifies the product, parameter and
version range.

## 3. Explicitly out of scope here

The widely published follow-on for Roundcube is to read the application's
configuration file, extract the session-encryption key, dump the session store
and decrypt stored mailbox passwords, then reuse them elsewhere. **That is
credential extraction and lateral movement, and it is excluded from this
bundle.** Code execution in the web context is already the finding; write it up
and stop. Do not read `config/config.inc.php` for its secrets, do not query the
session store, and do not decrypt anything.

## 4. False-positive killers

- A reverse proxy or a branded login theme can suppress the `rcversion` global.
  Its absence is not a version.
- `rcversion` is set by the application and is reliable when present, but a
  distribution package can carry a patched build with an unchanged version
  string. Where the client can tell you the package build, prefer that.
- A webmail login page on a hostname does not mean the mail server itself is in
  scope. Confirm per hostname against the scope document.

---

# Bolt CMS

A small Symfony and Twig based CMS. Thin public research, one well-documented
authorisation bug, and a template editor that is intended administrator
functionality.

## 1. Fingerprint and version

| Artifact | Request | What it proves |
|---|---|---|
| Back end | `GET /bolt` returning a Bolt login | Bolt, and the default back-end prefix (it is configurable) |
| Theme assets | `/theme/<name>/` serving Twig-rendered assets | Bolt theme layout |
| Symfony signals | Symfony profiler or debug headers on a Bolt route | A development configuration left enabled, which is a finding in itself |

Current upstream releases, queried rather than recalled:

```bash
curl -s "https://api.github.com/repos/bolt/core/releases?per_page=6" | \
  python3 -I -c 'import json,sys; [print(r["tag_name"], r["published_at"][:10]) for r in json.load(sys.stdin)]'
```

Queried this session: 6.1.9 (9 October 2026), 6.1.8, 6.1.7 (13 August 2026),
6.1.6.

## 2. Verified advisory

| Advisory | CVE | What it is | Affected | Fixed |
|---|---|---|---|---|
| GHSA-m2j9-f9xw-xxgw | None assigned ("no known CVE"), severity Moderate | An authenticated user holding `ROLE_EDITOR` could chain two permission flaws into code execution: upload a `.twig` file into the active theme directory through the asynchronous upload controller (which should have been restricted to administrators), then select that template in an editable record's `templateselect` field. Rendering the record evaluates the attacker's Twig with the web server user's privileges. | Bolt CMS 6.1.6 and earlier | 6.1.7, in commit `9795d39`, which enforces the location-specific `managefiles:<location>` permission |

Source: <https://github.com/bolt/core/security/advisories/GHSA-m2j9-f9xw-xxgw>.

Preconditions, all required: valid editor credentials with the generic upload
permission; `twig` present in the configured accepted file types; a writable
active-theme directory; an editable content type containing a `templateselect`
field; and knowledge of the active theme name and its template directory if one
is configured.

**The important subtlety for a retest.** The vulnerable controller does validate
the upload CSRF token, does constrain the path to the selected location, and does
apply the configured extension and size rules. It simply never authorised the
caller for the requested location. Therefore an invalid-token response or a
disallowed-extension response **does not** show the authorisation flaw is fixed.
A correct retest uses a valid token and an inert, allowed file, and expects a
patched build to reject an editor who lacks `managefiles:themes` before anything
is written.

**Stage B, sign-off required.** Any test of this chain writes a file into the
theme directory and modifies a content record. Conditions: written sign-off; a
tester-owned editor account; a tester-created record, never an existing one; an
inert template first (a file containing an arithmetic marker, so a rendered
result of `49` from `{{ 7 * 7 }}` proves controlled evaluation); the record's
original template selection restored and the uploaded file removed immediately,
with both recorded.

## 3. The administrator template editor

Bolt's back end lets an administrator edit the active theme's Twig templates and
the main configuration, and clearing the cache makes the change live. Whether a
given expression reaches the host language depends on the Bolt and Twig versions
and on which functions and filters the installation exposes, so verify the
configuration rather than assuming a published payload works.

As with every product in this skill, administrator template editing is intended
behaviour and is not a finding on its own. It is the back half of a chain whose
front half you must prove, and the editor authorisation bug above is exactly
such a front half.

Editing a live template affects every visitor. If an engagement requires it:
back up the original file first, use a benign marker, restore immediately, and
record all three steps.

## 4. False-positive killers

- The back-end prefix is configurable. `/bolt` returning 404 does not mean the
  product is not Bolt.
- A Symfony error page proves Symfony, not Bolt.
- An upload rejection does not prove the authorisation fix landed. See
  section 2.
- `{{ 7 * 7 }}` rendering as `49` proves template evaluation, not code
  execution. The escalation from one to the other is `hunt-ssti`'s territory and
  depends on the exposed function set.

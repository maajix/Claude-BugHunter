# Craft CMS

A PHP CMS built on the Yii 2 framework. One advisory dominates the public
record: a pre-authentication remote code execution bug that was exploited in the
wild within days of the patch and later added to CISA's Known Exploited
Vulnerabilities catalog. This file is short because the research is: fingerprint,
the verified advisory, and where the data runs out.

All probes here are **Stage A (read-only)** unless a heading says Stage B.
Serial, one request at a time, 1.5s base plus up to 1.5s jitter.

## 1. Fingerprint corroboration

Defaults below are from the Craft 5 general-config reference
(<https://craftcms.com/docs/5.x/reference/config/general.html>). Every one is
configurable, so require two.

| Artifact | Request | What it proves |
|---|---|---|
| Response header | `X-Powered-By: Craft CMS` (`sendPoweredByHeader`, default `true`) | Craft, stated by the application itself |
| Session cookie | `CraftSessionId` (`phpSessionName` default) | Craft session handling |
| Control panel | `GET /admin/login` (`cpTrigger` default `admin`) with a hidden `CRAFT_CSRF_TOKEN` input | Craft control panel, CSRF protection on |
| Published resources | `/cpresources/` paths in control-panel HTML (`resourceBaseUrl` default `@web/cpresources`) | Craft asset publishing |

## 2. Version pinning

No unauthenticated version artifact was found in the vendor documentation. Treat
the version as unknown unless the client supplies it or a `composer.lock`
(package `craftcms/cms`) is exposed. Establish current releases rather than
recalling them:

```bash
curl -s "https://api.github.com/repos/craftcms/cms/releases?per_page=6" | \
  python3 -I -c 'import json,sys; [print(r["tag_name"], r["published_at"][:10]) for r in json.load(sys.stdin)]'
```

Queried this session: 5.11.5.1 (8 October 2026), 5.11.5 (7 October 2026),
5.11.4 (1 October 2026), plus 6.0.0 alpha builds. Re-query; the method is the
point.

## 3. Verified advisory

| CVE | What it is | Affected | Fixed | Score |
|---|---|---|---|---|
| CVE-2025-32432 (GHSA-f3gw-9ww9-jmc3) | Pre-authentication remote code execution in image-transform generation. The `actions/assets/generate-transform` controller action does not require authentication, and Yii's object-configuration handling lets request JSON instantiate classes and attach behaviours. Craft describes it as an additional fix for CVE-2023-41892, built on a Yii issue fixed in Yii 2.0.52. | `craftcms/cms` 3.0.0-RC1 to 3.9.14, 4.0.0-RC1 to 4.14.14, 5.0.0-RC1 to 5.6.16 | 3.9.15, 4.14.15 and 5.6.17, released 10 April 2025 | CVSS 3.1 10.0 Critical (NVD: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`). Exploitation evidence from 17 April 2025; CISA KEV entry dated 20 March 2026 |

Sources: <https://craftcms.com/knowledge-base/craft-cms-cve-2025-32432>,
<https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3>,
<https://nvd.nist.gov/vuln/detail/CVE-2025-32432>, and the in-the-wild analysis
at <https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/>.

Mechanics worth knowing, because they drive the test design (per SensePost):
Craft 3.x validates the asset ID before building the transform object, so the
3.x route needs a valid asset ID; 4.x and 5.x validate it afterwards. With CSRF
protection on, the request also needs a token, which the login page hands out.

**Stage A detection.** Two-artifact fingerprint, then a version from the client
or an exposed `composer.lock`, compared against the fixed releases above. A
version in range on a self-hosted install is reportable with the advisory, the
KEV listing and the vendor's impact statement. The controller answering a
request is **not** evidence: the route exists on patched builds too.

**No Stage B for this bug.** Craft's own indicator of attack is a POST to
`generate-transform` carrying `__class` in the body, and SensePost's is
`as`-prefixed body fields. Sending either shape is sending the exploit. The
public nuclei template for this CVE does exactly that; do not run it against a
client site. Where the only route to proof is the exploit, write the Stage A
version finding and stop.

**Remediation notes for the report** (from the vendor knowledge base and
SensePost): update, and as an interim control block `__class` in POST bodies to
that endpoint; upgrading does not remove files an earlier intrusion dropped, so
the client must check web-root and asset-upload folders; if compromise is
suspected, rotate `CRAFT_SECURITY_KEY` (`php craft setup/security-key`), other
environment secrets and database credentials.

## 4. False-positive killers

- `X-Powered-By` can be switched off and `cpTrigger` renamed. Their absence is
  not evidence the product is not Craft.
- Craft Cloud's global firewall blocks this exploit, per the vendor. A
  Cloud-hosted site in range is not a confirmed finding.
- Craft published a "Security Patches" library as a temporary workaround. A
  version in range may carry it, so ask before asserting exploitability.
- A `generate-transform` POST containing `__class` in the client's logs means
  probing, not confirmed compromise. Craft says this explicitly.

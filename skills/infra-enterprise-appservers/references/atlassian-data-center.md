# Atlassian Data Center and Server: Confluence, Jira, Bitbucket, Bamboo

Rule for every row: **a version gate, not an exploit.** These products print
their exact version to anonymous visitors, so the version gate is usually
conclusive about range; it is still "version in range, unconfirmed" until a
precondition you cannot see (anonymous access, public signup, an app) is
confirmed. Nothing in this file sends an OGNL or template expression, a setup
or restore request, a traversal path, or a credential.

Atlassian Cloud (`*.atlassian.net`) is out of scope for every row: Atlassian
hosts it and the advisories exclude it. Crowd, Fisheye and Crucible are not
covered here, and no other skill in the bundle owns them yet (Crowd
CVE-2019-11580 is KEV-listed: report the exposure and the version only).
Native-login REST endpoints belong to
`hunt-auth-bypass`; public page and space content to `hunt-idor` and
`offensive-osint`; request smuggling research on Jira and Bitbucket to
`hunt-http-smuggling`.

Support status: Server licences reached end of support on 2024-02-15 (verify);
any Server install is unsupported and receives no fixes. Data Center has an
announced end of life of 2029-03-28 (verify). Fixes ship as bug-fix releases
of each Long Term Support line.

---

## Ports

| Port | Service | Where it should be reachable from |
|---|---|---|
| 8090 | Confluence HTTP (Tomcat) | Internet through a proxy |
| 8091 | Confluence Synchrony (collaborative editing) | Proxied path or internal (verify per release) |
| 5801 | Confluence DC Hazelcast cluster (verify) | Cluster nodes only |
| 8080 | Jira HTTP (Tomcat) | Internet through a proxy |
| 40001, 40011 | Jira DC Ehcache RMI (CVE-2020-36239) | Cluster nodes only |
| 7990 | Bitbucket HTTP | Internet through a proxy |
| 7999 | Bitbucket SSH (Git) | Developers; public is a business decision |
| 5701 | Bitbucket DC Hazelcast cluster (CVE-2022-26133) | Cluster nodes only |
| 8085 | Bamboo HTTP | Internet through a proxy |
| 54663 | Bamboo agent broker (verify) | Remote agents only |

Cluster ports (5701, 5801, 40001, 40011) answering from the internet are a
finding on reachability. RMI transport checks are owned by
`hunt-exposed-services` (`references/remote-debug.md`); Hazelcast has no owner
in the bundle, so `nmap -sV` reachability is the whole test. Never send a
cluster join or an RMI call.

---

## Stage A fingerprint and anonymous-access checks

One `GET` per path, 2 s apart, no cookies, no credentials.

```bash
T="atl.client.example"; B="https://$T"; mkdir -p evidence
get() { curl -sk -m 15 -H 'Accept: application/json' "$B$1"; echo; sleep 2; }
{
  echo "== Jira";       get /rest/api/2/serverInfo
  echo "== Bitbucket";  get /rest/api/1.0/application-properties
  echo "== Bamboo";     get /rest/api/latest/info
  echo "== Confluence"; curl -sk -m 15 "$B/login.action" | grep -o -E 'ajs-version-number" content="[^"]+"' | head -1; sleep 2
} | tee "evidence/${T}_atlassian_version.txt"
curl -sk -m 15 -o /dev/null -D - "$B/" | grep -i -E '^(HTTP/|x-arequestid:|x-ausername:|x-confluence-request-time:|x-asen:|server:)'
```

| Signal | Meaning |
|---|---|
| Jira `/rest/api/2/serverInfo` JSON with `version`, `buildNumber`, `deploymentType` | Exact Jira version; `deploymentType` says Server or Data Center. |
| Bitbucket `/rest/api/1.0/application-properties` with `version`, `buildNumber` | Exact Bitbucket version. |
| Bamboo `/rest/api/latest/info` with `version` (anonymous access to it varies, verify) | Exact Bamboo version. |
| Confluence `<meta name="ajs-version-number" content="8.5.3">` on `/login.action` | Exact Confluence version. |
| `X-AUSERNAME: anonymous`, `X-AREQUESTID`, `X-Confluence-Request-Time` | Atlassian product behind the proxy even when the version is hidden. |

Preconditions you may read, still anonymous and `GET` only:

| Check | Path | Why it matters |
|---|---|---|
| Bitbucket public signup | `/signup` serves a form instead of redirecting to login | Makes CVE-2022-43781 unauthenticated. |
| Bitbucket public repositories | `/rest/api/1.0/repos?limit=1` returns a repository | Makes CVE-2022-36804 reachable without an account. |
| Confluence anonymous access | `/rest/api/space?limit=1` returns a space | Makes CVE-2023-22522 reachable as anonymous. |
| Jira or Confluence signup | `/secure/Signup!default.jspa`, `/signup.action` serve a form | Self-registration widens every authenticated CVE. |

Do **not** request `/server-info.action` with parameters, `/setup/*`,
`/json/setup-restore*.action`, `/s/` traversal paths, `/WEB-INF/` paths,
`/pages/createpage-entervariables.action`, `/template/aui/text-inline.vm` or
any URL carrying `${`, `%{` or `#{`. Each is an exploit path for a row below.

---

## CVE matrix 2020-2026

Affected and fixed versions from the CVE records (Atlassian CNA). KEV dates
from the CISA catalog 2026.10.13; "ransomware" is the catalog's
`knownRansomwareCampaignUse = Known`.

### KEV-listed

| CVE | Product, type | Pre-auth | Fixed in (first fixed release per line) | KEV added |
|---|---|---|---|---|
| CVE-2021-26084 | Confluence, OGNL injection | Yes | 6.13.23, 7.4.11, 7.11.6, 7.12.5 | 2021-11-03, ransomware |
| CVE-2021-26085 | Confluence, `/s/` file read | Yes | 7.4.10, 7.12.3 | 2022-03-28, ransomware |
| CVE-2021-26086 | Jira, path traversal to `/WEB-INF/web.xml` (5.3) | Yes | 8.5.14, 8.13.6, 8.16.1 | 2024-11-12 |
| CVE-2022-26134 | Confluence, OGNL injection | Yes | 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 | 2022-06-02, ransomware |
| CVE-2022-26138 | Questions for Confluence app 2.7.34, 2.7.35, 3.0.2 creates `disabledsystemuser` with a hardcoded password | Yes | Update the app and disable or delete the account (Atlassian advisory, verify the fixed app version) | 2022-07-29 |
| CVE-2022-36804 | Bitbucket, command injection in API endpoints; needs read on any repository (public repo = no account) | Conditional | 7.6.17, 7.17.10, 7.21.4, 8.0.3, 8.1.3, 8.2.2, 8.3.1 (7.0.0 and later affected) | 2022-09-30 |
| CVE-2023-22515 | Confluence DC/Server 8.0.0 to 8.5.1, broken access control, creates administrators | Yes | 8.3.3, 8.4.3, 8.5.2 | 2023-10-05, ransomware |
| CVE-2023-22518 | Confluence, improper authorization, resets the instance (data loss) | Yes | 7.19.16, 8.3.4, 8.4.4, 8.5.3, 8.6.1 | 2023-11-07, ransomware |
| CVE-2023-22527 | Confluence 8.0.0 to 8.5.3, template injection RCE | Yes | 8.5.4, 8.6.0 and later | 2024-01-24, ransomware |

Pre-2020 Atlassian KEV entries (Confluence CVE-2019-3396, CVE-2019-3398, Jira
CVE-2019-11581, Crowd CVE-2019-11580) matter only on very old installs; any
version that old is already in range for the 2021-2023 rows.

### Not in KEV

| CVE | Product, type | Pre-auth | Fixed in |
|---|---|---|---|
| CVE-2020-36239 | Jira DC and JSM DC, Ehcache RMI on 40001 / 40011 without authentication, deserialization | Yes, if the ports are reachable | Jira 8.5.16, 8.13.8, 8.17.0; JSM 4.5.16, 4.13.8, 4.17.0 |
| CVE-2022-0540 | Jira and JSM, Seraph authentication bypass; impact depends on apps and actions using it | Yes (NVD 9.8) | Jira 8.13.18, 8.20.6, 8.22.0; JSM 4.13.18, 4.20.6, 4.22.0 |
| CVE-2022-26133 | Bitbucket DC, Hazelcast cluster authenticator deserialization (5701) | Yes, if 5701 is reachable | 7.6.14, 7.17.6, 7.18.4, 7.19.4; 7.20.0 affected (verify its fix); 5.14.0 and later affected |
| CVE-2022-26136 | Servlet filter bypass across Bamboo, Bitbucket, Confluence, Crowd, Fisheye/Crucible, Jira, JSM; impact per app | Yes | Bamboo 8.0.9, 8.1.8, 8.2.4; Bitbucket 7.6.16, 7.17.8, 7.19.5, 7.20.2, 7.21.2 (8.0.0, 8.1.0 affected); Confluence 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4 (7.18.0 affected); Jira 8.13.22, 8.20.10, 8.22.4; JSM 4.13.22, 4.20.10, 4.22.4 |
| CVE-2022-43781 | Bitbucket, command injection through environment variables; unauthenticated only with "Allow public signup" | Conditional | 7.6.19, 7.17.12, 7.21.6, 8.0.5, 8.1.5, 8.2.4, 8.3.3, 8.4.2, 8.5.0 (7.0 and later affected) |
| CVE-2023-22501 | JSM, signup-token impersonation; needs User Directory write and outgoing mail, plus access to the token emails | Conditional | Per Atlassian advisory (verify) |
| CVE-2023-22522 | Confluence, template injection RCE by any user **including anonymous** | Conditional on anonymous access (CNA 9.0, AC:H) | 7.19.17, 8.4.5, 8.5.4, 8.6.2, 8.7.1 |
| CVE-2026-21580 | Confluence DC/Server, unauthenticated stored XSS with privilege escalation (CNA 8.6, CVSS 4.0) | Yes | 9.2.21, 10.2.13 and later. Affected bands include 7.19.27-7.19.30, 8.5.15-8.5.31, 9.2.0-9.2.20, 10.2.0-10.2.11 (full list in the record) |
| CVE-2026-21589 | Arbitrary file read inside the web application root; needs the exact file path (CNA 9.3, CVSS 4.0), published 2026-10-05 | Yes | Bitbucket 9.4.26, 10.2.8, 10.5.1; Confluence 9.2.26, 10.2.19; Jira Software 9.12.40, 10.3.26, 11.3.12; JSM 5.12.40, 10.3.26, 11.3.12; Bamboo 10.2.24, 12.1.12; Crowd 6.3.7, 7.0.3, 7.1.7, 7.2.4; Fisheye/Crucible 4.9.15 |

Authenticated-only or not exploitable on their own, list as patch items, do
not test: CVE-2020-14172 (Jira Velocity hardening, only exploitable through a
separate template injection; fixed 7.13.0, 8.5.0, 8.8.1), CVE-2023-22513
(Bitbucket, authenticated RCE), CVE-2024-21683 (Confluence, authenticated
RCE).

An NVD keyword search for Bamboo Data Center (2026-10-13, CVSS 8.8+ or KEV)
returned only CVE-2026-21589 as pre-auth; Bamboo's other critical entries are
authenticated or bundled-dependency CVEs.

### How to read it externally

- The version string is anonymous and exact. Map it straight to the rows and
  say which precondition is unseen (anonymous access, public signup, public
  repositories, the Questions app, reachable cluster ports).
- Any Confluence 8.0.0 to 8.5.3 that is internet-facing is in range for
  CVE-2023-22527 and, below 8.5.2, CVE-2023-22515: escalate the same day.
- Every Confluence below 7.19.16 / 8.3.4 / 8.4.4 / 8.5.3 / 8.6.1 is in range
  for CVE-2023-22518 regardless of configuration.
- Every product line below its CVE-2026-21589 fix is in range; it is the
  newest cross-product row (published 2026-10-05).

---

## Stage B (written sign-off naming host, port, action and window)

| Action | Blast radius to name |
|---|---|
| One request that reads a file through CVE-2021-26085, CVE-2021-26086 or CVE-2026-21589, naming the non-sensitive file in the sign-off | Proves the bug; a wrong path can read credentials (`dbconfig.xml`, `confluence.cfg.xml`). One file, named in advance. |
| Login with client-supplied credentials to check authenticated rows or app versions (Questions for Confluence) | Account lockout and CAPTCHA after failed logins. One attempt, named account. |
| Logging in as `disabledsystemuser` (CVE-2022-26138) | It is a working login with a hardcoded password: account access to every space that group can read. Ask the client to check the app version instead. |
| Any OGNL, Velocity or template expression (CVE-2021-26084, CVE-2022-26134, CVE-2023-22522, CVE-2023-22527) | An evaluated expression is code execution on production. Never in this bundle. |
| Any setup, restore or `server-info.action` parameter request (CVE-2023-22515, CVE-2023-22518) | Creates administrators or **wipes the instance**. Forbidden outright. |
| Any Bitbucket API call with crafted arguments (CVE-2022-36804) or a signup to test CVE-2022-43781 | Command execution, or an account created on the client's system. Never. |
| Any RMI call on 40001/40011 or Hazelcast message on 5701/5801 | Deserialization against a cluster node. Never. |

## What is not a finding

- An exact version string on a current, patched release: version disclosure.
- `X-AUSERNAME: anonymous` on its own.
- Anonymous read of spaces or projects the client published on purpose
  (check the site's purpose before calling it data exposure).
- A Server or DC version in range for an authenticated-only CVE with no
  self-signup and no anonymous access: patch item, Informational to Low.
- An `*.atlassian.net` site: Atlassian Cloud, not the client's server.

Sources (checked 2026-10-13): CVE records via
<https://github.com/CVEProject/cvelistV5> (Atlassian CNA ranges and
`jira.atlassian.com` tracking issues), NVD keyword queries for Confluence
Data Center, Jira Data Center, Jira Server, Bitbucket Data Center and Bamboo
Data Center, CISA KEV catalog 2026.10.13 (including
`knownRansomwareCampaignUse`), Atlassian security advisories linked from the
records.

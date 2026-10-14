# File-sync and share platforms: Nextcloud, ownCloud, Seafile, Syncthing, FileCloud

These are meant to face the internet, so exposure alone is rarely the finding.
What is: a version inside a known-exploited range, an admin interface that needs
no login (Syncthing), a public share or listing that reaches data it should not,
and a platform past end of support. Web-application bugs in these products
(XSS, IDOR, SSRF in previews) are found with the `hunt-*` web skills; this file
is the version gate and the exposure triage.

Rules for every row below:

- **Detected by version only.** The ownCloud CVE-2023-49103 path and a forged
  CVE-2023-49105 pre-signed URL are the exploits themselves. Do not send either.
- KEV column: CISA KEV catalog 2026.10.13.
- "(verify)" marks a detail that could not be confirmed from a primary source
  while this file was written.

---

## Nextcloud Server

| Port | Service |
|---|---|
| 443 | Web, WebDAV (`/remote.php/dav`), OCS API |

**Fingerprint and version.** `GET /status.php` returns JSON with `installed`,
`maintenance`, `needsDbUpgrade`, `version`, `versionstring`, `edition` and
`productname` (verify the field set per release). Nextcloud's own community answer
is that the version string is not itself a security issue unless the server is
behind on updates; that is also how to grade it.

**Matrix.** Nothing from Nextcloud is in CISA KEV (catalog 2026.10.13). In the
100 most recent advisories in `nextcloud/security-advisories` (late 2023 to
2026-10), the high-severity rows needing no privileges are below; no
unauthenticated RCE in Server itself appeared. Older 2021-2023 advisories were not
reviewed row by row (verify).

| CVE | Class / precondition | Fixed | KEV |
|---|---|---|---|
| CVE-2024-37313 | Second-factor bypass (Server) | Server 26.0.13, 27.1.8, 28.0.4; Enterprise 21.0.9.17 through 25.0.13.8 | No |
| CVE-2026-45156 | User OIDC app: ID4me JWT signature not verified, authentication bypass (UI:R) | User OIDC 3.1.0, 4.1.0, 5.1.0, 6.4.0, 8.3.0 | No |
| CVE-2026-29059 | Flow app bundles a vulnerable Windmill: RCE, adjacent network | Flow 1.3.0 | No |

Apps carry their own versions; `status.php` shows only Server's. Grade by:

- Major version past end of support: report as unsupported software, and list the
  advisories published after its last release.
- Supported major, old maintenance release: map the version to the advisories and
  report only the ones whose preconditions you can see (an enabled app, public
  shares, federation).
- `maintenance: true` or `needsDbUpgrade: true` on a production host: an operational
  note, not a vulnerability.

Nextcloud runs a public scanner that tests a host from Nextcloud's own servers.
Submitting a client's hostname to it sends client data to a third party; do it
only with the client's permission.

---

## ownCloud (Classic server 10.x; Infinite Scale)

| Port | Service |
|---|---|
| 443 | Web, WebDAV, OCS API |

**Fingerprint and version.** `GET /status.php`, same JSON shape as Nextcloud
(shared ancestry). ownCloud Infinite Scale (oCIS) is a different, Go-based
product; the Classic rows below do not apply to it (verify oCIS's own status
endpoint before relying on it).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2023-49103 | `graphapi` app relies on a third-party library file that prints `phpinfo()`: every web-server environment variable, which in containerized deployments may include the admin password, mail server credentials and licence key. Disabling the app does not remove it. Unauthenticated | graphapi 0.2.x before 0.2.1, 0.3.x before 0.3.1 (bundled with some core 10.x releases, verify which) | graphapi 0.2.1 / 0.3.1, plus deleting the test file as ownCloud advised; core 10.13.1+ when graphapi ships with it | Yes, 2023-11-30 |
| CVE-2023-49105 | WebDAV pre-signed URLs accepted when the file owner has no signing key: access, modify or delete any file of a known username, unauthenticated | core 10.6.0 through 10.13.0 | 10.13.1 per the CVE record; ownCloud's guidance cites 10.13.3 or a support patch (verify) | Yes, 2026-08-27 |
| CVE-2023-49104 | `oauth2` app redirect-URL validation bypass when "Allow Subdomains" is enabled | oauth2 before 0.6.1 | 0.6.1 | No |
| CVE-2025-53827 | Updater exposes a dangerous function; administrator required | core before 10.15.3 | 10.15.3 | No |

The 49105 precondition (a known username with no signing key) is the default
state for users who never used the feature. A version in range is therefore close
to sufficient; report it unconfirmed and escalate the same day.

---

## Seafile

| Port | Service |
|---|---|
| 8000/tcp | Seahub web (when not behind a proxy). **Collides with Asustor ADM HTTP** |
| 8082/tcp | Fileserver (usually proxied under `/seafhttp`) (verify) |
| 80/443 | The usual published front end |

**Fingerprint and version.** The Web API server-information call
(`/api2/server-info/`) returns the version and enabled features without
authentication (verify the field names per release); the login page names the
product.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2021-43820 | Cached sync token not checked against the requested library: access to other libraries (7.4, AC:H, PR:N) | seafile-server Community before 8.0.8, Pro before 8.0.15 | 8.0.8 / 8.0.15 | No |
| CVE-2025-41079, CVE-2025-41080, CVE-2025-65516 | Stored XSS (authenticated) | 12.0.10 as tested; Community Edition before 13.0.12 for 65516 | (verify) / 13.0.12 | No |
| CVE-2026-30587 | Stored XSS through the Seadoc (sdoc) editor's websocket messages, authenticated | 13.0.15, 13.0.16-pro, 12.0.14 and earlier | 13.0.17, 13.0.17-pro, 12.0.20-pro | No |
| CVE-2026-56768 | Seahub does not enforce `SHARE_LINK_LOGIN_REQUIRED` on the share-link zip task: anyone holding a folder share-link token downloads the whole tree | Seahub before 13.0.23 | 13.0.23 | No |

---

## Syncthing

| Port | Service |
|---|---|
| 8384/tcp | Web GUI and REST API. **Default bind is 127.0.0.1:8384**, so an internet-facing GUI was configured that way on purpose |
| 22000/tcp, 22000/udp | Sync protocol (TLS over TCP, and QUIC) (verify UDP) |
| 21027/udp | Local discovery (verify) |
| 22067/tcp, 22070/tcp | Relay server and its status page (`strelaysrv`) (verify) |

**Fingerprint.** GUI title; the documented unauthenticated health endpoint
(`/rest/noauth/health`, verify); on 22000 the TLS certificate is self-signed and
its hash is the device ID, so record it: the same device ID on another address is
the same node (verify the certificate CN convention).

**The finding that matters.** A GUI that loads with no login is full
administrative control of the node: add a folder at any path the service account
can read, share it to a device you control, and the files sync out. That is
Critical. Stage A proves it with one page load and a screenshot of the dashboard
(device name, folder labels, remote device count). Do not click anything: no
"Add Folder", no "Add Remote Device", no settings dialog, no "Actions" menu.
Syncthing warns in its own logs when insecure admin settings are enabled; GUI
with authentication but without HTTPS sends credentials in cleartext (Low).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2021-21404 | Relay protocol message with negative length crashes `strelaysrv` and clients. **DoS-class: never tested** | before 1.15.0 | 1.15.0 | No |
| CVE-2022-46165 | Stored XSS in the GUI via synced file names or device names | before 1.23.5 | 1.23.5 | No |

---

## FileCloud (CodeLathe)

| Port | Service |
|---|---|
| 443 | Web UI, WebDAV, API |

**Version observable?** From the client or the admin portal (verify any
unauthenticated version source).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2022-39833 | Crafted HTTP request: unauthorized API access and potential RCE (vendor advisory 2022-10/01, CVSS 9.3) | 20.2 and later before the fix | 21.3.7.18607 | No |
| CVE-2022-1958 | NTFS handler improper access control (PR:L) | before 21.3.5.18513 | 21.3.5.18513 | No |
| CVE-2025-26127 | Stored XSS in "Send for Approval" | 23.241.2 as tested (verify) | (verify) | No |

---

## Stage A and Stage B for this family

Stage A: the status or server-info call, title, certificate, and for Syncthing
one GUI page load. A public share link you were given or found in the client's
own published material may be opened once to see what it exposes; record the
listing (names, counts), download nothing.

Stage B, written sign-off: logging in with the engagement test account to read the
version in the admin panel (where the status call hides it); opening a share link
that was not published by the client. **Forbidden outright:** creating or editing
shares, adding Syncthing folders or devices, uploading anything, enabling apps,
reading other users' files, and any request to a CVE's named component.

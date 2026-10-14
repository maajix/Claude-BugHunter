# NAS appliances: fingerprint, ports and version-gate matrix

A consumer or SMB NAS on the internet is usually there on purpose: remote access,
a vendor relay, or a router that opened ports by UPnP. That intent does not make
it safe. QNAP, Synology and Asustor fleets have been mass-encrypted from the
internet (Qlocker, DeadBolt, eCh0raix), and the entry point was the web admin
service or an app running on it.

Rules for every row below:

- **Detected by version only.** No request to the CGI, app or endpoint a CVE names.
  A version in range is "unconfirmed" until the client confirms it.
- KEV column: CISA KEV catalog 2026.10.13. "Known" = known ransomware campaign use.
- Ranges and fixed builds come from the vendor advisory or the CNA record in the
  CVE List. "(verify)" marks a detail that could not be confirmed from a primary
  source while this file was written.

**Before anything else:** a NAS whose login page already shows a ransom note
(DeadBolt replaces the page; Qlocker left a README ransom note in shares, verify the file name) is a live
incident, not a test target. Stop, capture the page, escalate the same hour.

## Other services on the same box have other owners

| Service | Owner |
|---|---|
| SSH on the NAS, and the one documented default (QNAP QTS 4.4.1 and earlier `admin`/`admin`; QTS 4.4.2+ uses the MAC address) | `infra-ssh` (`references/appliance-ssh.md`) |
| FTP / FTPS | `infra-ftp` |
| SMB 445 | `infra-windows-perimeter` |
| NFS, rsync 873, iSCSI 3260, AFP 548, TFTP | `hunt-exposed-services` (`references/printers-and-storage.md`) |
| TLS on the admin port | `hunt-tls-network` |
| Vendor relays: Synology QuickConnect (`*.quickconnect.to`), myQNAPcloud Link | **Vendor infrastructure, not the client's.** Never test the relay. Find the NAS's own address and test that, if it is in scope |

---

## QNAP (QTS, QuTS hero, QuTScloud)

| Port | Service |
|---|---|
| 8080/tcp | QTS web admin, HTTP (default system port; verify per model) |
| 443/tcp | QTS web admin, HTTPS (some builds use 8081 or a custom port; verify) |

**Fingerprint.** Login page title and `/cgi-bin/` paths; a GET of the login CGI
with no parameters returns XML that commonly carries firmware version and build
(field names verify; send no parameters: parameters on that CGI have carried
command injection before). **Version observable?** Often, see above; otherwise the
client's Control Panel. Apps (HBS 3, Photo Station) have their own versions.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2020-2509 | QTS command injection (published 2021-04-17) | QTS before 4.5.2.1566 b20210202, 4.5.1.1495 b20201123, 4.3.6.1620 b20210322, 4.3.4.1632 b20210324, 4.3.3.1624 b20210416, 4.2.6 b20210327; QuTS hero before h4.5.1.1491 b20201119 | those builds | Yes, 2022-04-11 |
| CVE-2021-28799 | HBS 3 Hybrid Backup Sync improper authorization (hard-coded credential): remote login. Qlocker | HBS 3 before 16.0.0415 (QTS 4.5.2), 3.0.210412 (QTS 4.3.6), 3.0.210411 (QTS 4.3.4/4.3.3), 16.0.0419 (QuTS hero, QuTScloud) | those builds | Yes, 2022-03-31, Known |
| CVE-2022-27593 | Photo Station externally controlled reference: modifies system files. DeadBolt | Photo Station before 6.1.2 (QTS 5.0.1), 6.0.22 (5.0.0/4.5.x), 5.7.18 (4.3.6), 5.4.15 (4.3.3), 5.2.14 (4.2.6) | those builds | Yes, 2022-09-08, Known |
| CVE-2022-27596 | QTS code injection, unauthenticated (9.8) | QTS 5.0.1 before 5.0.1.2234 b20221201; QuTS hero before h5.0.1.2248 b20221215 | those builds | No |
| CVE-2023-23368 | OS command injection, unauthenticated (9.8) | QTS 5.0.x before 5.0.1.2376 b20230421, 4.5.x before 4.5.4.2374 b20230416; QuTS hero before h5.0.1.2376 / h4.5.4.2374 b20230417; QuTScloud before c5.0.1.2374 | those builds | No |
| CVE-2024-21899 | Improper authentication (9.8, Pwn2Own 2023 batch, QSA-24-09) | QTS 5.1.x before 5.1.3.2578 b20231110, 4.5.x before 4.5.4.2627 b20231225; QuTS hero before h5.1.3.2578 / h4.5.4.2626; QuTScloud before c5.1.5.2651 | those builds | No |
| CVE-2024-27130 | Buffer overflow to code execution (CNA 7.2, PR:N). The researchers' write-up says a valid share-link session ID is needed (verify) | QTS 5.1.x before 5.1.7.2770 b20240520; QuTS hero before h5.1.7.2770 b20240520 | those builds | No |
| CVE-2024-50388 | HBS 3 OS command injection, unauthenticated (CVSS 4.0 9.5, AT:P) | HBS 3 25.1.x before 25.1.1.673 | 25.1.1.673 | No |
| CVE-2023-47565 | Legacy **VioStor NVR** (not a NAS) QVR 4.x command injection, authenticated, adjacent | QVR firmware 4.x | QVR 5.0.0 | Yes, 2023-12-21 |

QNAP's Pwn2Own Ireland 2025 advisory lists QTS/QuTS hero 5.2.x fixes at
5.2.7.3297 build 20251024 (verify the CVE IDs and HBS 3 build in the advisory
before citing). KEV also holds older QNAP entries outside this window
(CVE-2019-7192 to CVE-2019-7195 Photo Station/QTS, CVE-2018-19943/19949/19953
File Station, CVE-2020-2506 Helpdesk); a firmware old enough to hit them is in
range of everything above too.

---

## Synology DiskStation Manager (DSM) and Synology apps

| Port | Service |
|---|---|
| 5000/tcp | DSM web, HTTP |
| 5001/tcp | DSM web, HTTPS |
| 6690/tcp | Synology Drive client sync (verify) |

**Fingerprint.** DSM login page, `/webman/` paths, and the public API catalogue
(`/webapi/query.cgi` with `api=SYNO.API.Info`, `method=query`), which lists the
APIs the box serves without authentication. **Version observable?** Recent DSM no
longer reveals the full version pre-auth; scanners report false positives on
micro versions. Ask the client for the full string (e.g. `7.2.2-72806 Update 4`).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2022-27624 | Out-of-band management packet decryption overflow, unauthenticated RCE. Specific models only (DS3622xs+ and others with OOB) | DSM before 7.1.1-42962-2 | 7.1.1-42962-2 | No |
| CVE-2024-10443 | RISK:STATION: command injection in the Task Manager of Synology Photos / BeePhotos, unauthenticated, zero-click, root | Photos before 1.6.2-0720 (DSM 7.2) and 1.7.0-0795 (DSM 7.2.2); BeePhotos before 1.0.2-10026 and 1.1.0-10053 | those builds | No |
| CVE-2026-32746 | GNU inetutils telnetd out-of-bounds write (9.8); affects DSM only with Telnet enabled | DSM 7.1/7.2.x/7.3 per third-party reporting (verify the Synology advisory) | per Synology advisory (verify) | No |
| CVE-2026-13684 | SCGI output encoding: unauthenticated arbitrary file read/write and DoS (9.8) | DSM before 7.2.1-69057-12, 7.2.2-72806-9, 7.3.2-86009-4, 7.4-90075 | those builds (Synology-SA-26:13) | No |
| CVE-2026-13639 | Insufficient entropy in login logic: unauthenticated file read/write and DoS (9.8) | same | same | No |

Synology ships no factory admin credential; the account is created at setup.
There is no default-credential step for DSM.

---

## TrueNAS (CORE, SCALE / Community Edition)

| Port | Service |
|---|---|
| 80/443 | Web UI and API (SCALE also exposes its middleware API over websocket on the same port) |

**Fingerprint.** Title and UI assets. **Version observable?** After login (verify);
otherwise the client.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2024-11944 | TrueNAS CORE `tarfile.extractall` directory traversal, unauthenticated RCE, **network-adjacent** (Pwn2Own) | CORE 13.3-RELEASE per CNA | (verify: third-party coverage names 13.0-U6.3, which conflicts with the CNA's 13.3 range) | No |
| CVE-2024-11946 | CORE plugin package fetch over cleartext, tampering (3.1) | CORE 13.3-RELEASE per CNA | (verify) | No |

TrueNAS publishes impact statements for third-party components (Samba 2026
release: Medium for TrueNAS, fixed in 25.10.4 per its impact statement; verify).

---

## Western Digital My Cloud

| Port | Service |
|---|---|
| 80/443 | Dashboard (My Cloud OS 5) |
| 21 | FTP, if enabled (`infra-ftp`; CVE-2022-22989 below is reachable there) |

**Version observable?** Dashboard after login (verify). WD cut cloud access for
devices below 5.25.132 from 2023-03-15, so a device that still works remotely is
at least that version unless it is accessed directly.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2022-22989 | FTP service pre-auth stack overflow | My Cloud OS 5 before 5.19.117 | 5.19.117 | No |
| CVE-2024-22170 | Dynamic DNS client buffer overflow (CVSS 4.0, AC:H, AT:P) | before 5.29.102 | 5.29.102 | No |
| CVE-2025-30247 | Unauthenticated OS command injection in the web UI via crafted POST | before 5.31.108 | 5.31.108 | No |

---

## Asustor ADM

| Port | Service |
|---|---|
| 8000/tcp | ADM web, HTTP. **Collides with Seafile's seahub default** |
| 8001/tcp | ADM web, HTTPS |

**Version observable?** After login (verify).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2026-24936 | Unauthenticated arbitrary file write in a CGI, only when a specific option was enabled while joining an AD domain | ADM 4.1.0 through 4.3.3.ROF1, 5.0.0 through 5.1.1.RCI1 | per advisory AS-2026-002 (verify) | No |
| CVE-2026-105324 | `start-page-loader.cgi` header injection: unauthenticated arbitrary file read via the web server's X-Sendfile | ADM 5.0.0 through 5.1.4.RL21, 4.1.0 through 4.3.3.RWC1 | 5.1.4.RM62 and 4.3.3.RY62 per advisory coverage (verify) | No |
| CVE-2026-6644 | PPTP VPN client command injection, **administrator** required | ADM 5.0.0 through 5.1.2.REO1, 4.1.0 through 4.3.3.RR42 | 5.1.3.RGL1; 4.x fix pending at publication (verify) | No |

DeadBolt hit Asustor in February 2022; the vendor shipped ADM 4.0.4.RQO2
without a CVE that could be found (verify).

---

## Buffalo TeraStation / LinkStation

| Port | Service |
|---|---|
| 80/443 | Web admin |
| 548 | AFP (`hunt-exposed-services`). Buffalo's 2022 advisory says to disable AFP on models without a fixed firmware |

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2023-49038 | Ping utility command injection, authenticated, root | LS210D 1.78-0.03 | (verify) | No |
| CVE-2023-51073 | Firmware update script abuse to code execution | LS210D 1.78-0.03 | (verify) | No |
| CVE-2023-39620 | Guest account information disclosure | TeraStation TS5410R (range as published, verify) | (verify) | No |

KEV's "Buffalo Firmware" entry, CVE-2021-20090, is the Arcadyan path traversal in
Buffalo **routers**, not in TeraStation or LinkStation. Do not cite it against a
NAS.

---

## Stage A and Stage B for this family

Stage A: login page, title, certificate, headers, the one public API catalogue or
version XML named above, and nothing that needs a session. NAS web servers are
small embedded daemons: keep to the rate posture in `SKILL.md`, no directory
brute-forcing, no scanner templates that fire exploit checks.

Stage B, written sign-off: logging in with a client-provided account to read the
firmware and app versions; one vendor-documented default credential where the
vendor documents one for that exact model and firmware (QNAP QTS 4.4.1 and earlier
only). **Forbidden outright:** opening shares or File Station, listing user
folders, Hybrid Backup Sync / Hyper Backup / snapshot replication settings,
snapshot or recycle-bin actions, firmware updates, app installs, enabling SSH or
Telnet, and any request to a CVE's named component.

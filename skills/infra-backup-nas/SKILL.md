---
name: infra-backup-nas
description: "Triage internet-exposed backup servers, NAS appliances, object storage and file-sync platforms. Backup: Veeam Backup & Replication and Enterprise Manager (9392, 9401, 9380, 9443), Commvault (8400-8403), NetBackup (1556, 13724), Backup Exec, Bacula (9101-9103), Acronis Cyber Protect (9877), NAKIVO (4443), Arcserve UDP (8014/8015), Dell NetWorker and Avamar, Rubrik, Cohesity. NAS: QNAP, Synology DSM (5000/5001), TrueNAS, WD My Cloud, Asustor, Buffalo. Object storage: MinIO (9000/9001), Ceph RGW (7480), SeaweedFS. File sync: Nextcloud, ownCloud, Seafile, Syncthing (8384), FileCloud. Fingerprint and version-gate against a 2021-2026 CVE matrix with CISA KEV status (CVE-2024-40711, CVE-2025-34028, CVE-2024-48248, CVE-2023-28432, CVE-2023-49105, Qlocker, DeadBolt), anonymous bucket listing, unauthenticated admin GUIs. Stage A is read-only; any login, default credential, write or restore is Stage B with written sign-off. Use when a scan, certificate or title names one of these products on an in-scope host."
sources: cisa_kev, nvd, cve_list_cna_records, vendor_advisories, vendor_documentation, project_documentation, researcher_writeups
report_count: 0
---

## When to use

Trigger when external recon shows a backup console, a NAS admin page, an
S3-compatible object store or a file-sync server answering on a public,
client-owned address. The port list in Step 3 is a hint; a page title, TLS
certificate, `Server` header or vendor API answer is what identifies the product.

These products are the ransomware target list. Veeam CVE-2022-26500/26501,
CVE-2023-27532 and CVE-2024-40711, Backup Exec CVE-2021-27876/27877/27878, QNAP
HBS 3 (Qlocker) and Photo Station (DeadBolt) all carry CISA's "known ransomware
use" flag. A backup server on the internet is the shortest path from one bug to
"no clean copy left". Grade and escalate with that in mind, and test with even
more care than usual: if your test breaks the backup plane, the client finds out
during their next incident.

The finding here is **exposure plus what the version, the listing or the missing
login grants**, never an exploit you ran.

### Where the chain ends

Stop at **version identified, exposure or unauthenticated access proven, impact
described, evidence captured**. Concretely:

- Backup consoles: stop at the login page, the certificate and the build. No
  restore, mount, job, repository, credential-store or configuration-database
  action, ever. `hunt-exposed-services` `management-interfaces.md` draws the
  same line for Veeam: credential recovery from the database is post-access work.
- NAS: stop at the admin page and the firmware. Shares and user folders are data.
- Object storage: stop at a listing of names and sizes. Downloading the object is
  taking the data.
- Syncthing or SeaweedFS with no authentication: stop at the dashboard or status
  page. Adding a folder or a device is exfiltration.
- A device already showing a ransom note: that is an incident. Stop and escalate.

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| NFS, rsync 873, iSCSI 3260, AFP 548, GlusterFS, TFTP on a NAS or backup host | `hunt-exposed-services` `references/printers-and-storage.md` |
| NDMP / Webmin disambiguation on 10000 | `hunt-exposed-services` `references/management-interfaces.md` (Backup Exec KEV rows are in this skill's matrix) |
| SMB 445, RDP, WinRM on a Windows backup server | `infra-windows-perimeter`, `hunt-exposed-services` |
| SSH on a NAS, QNAP's documented SSH default | `infra-ssh` `references/appliance-ssh.md` |
| FTP / FTPS on a NAS | `infra-ftp` |
| Hosted cloud buckets (AWS, GCS, Azure), bucket-name discovery, leaked cloud keys | `hunt-cloud-misconfig`, `cloud-iam-deep` |
| XSS, IDOR, SSRF and auth bugs inside Nextcloud, ownCloud, Seafile, FileCloud web apps | `hunt-xss`, `hunt-idor`, `hunt-ssrf`, `hunt-auth-bypass` |
| Credential guessing of any kind | `hunt-brute-force` |
| TLS posture on any of these ports | `hunt-tls-network` |
| NTLM metadata from a Windows-hosted console | `hunt-ntlm-info` |
| Anything after login, inside the network, or against Active Directory | Nobody. Out of scope by `SECURITY.md` |

---

## Step 1: Inherit hosts and ports, and spot vendor infrastructure

Take hosts from the signed scope and ports from recon. Confirm IP ownership (ASN,
RDAP, reverse DNS) before the first packet. Three things in this family look
like the client and are not:

- **Vendor relays.** Synology QuickConnect (`*.quickconnect.to`) and myQNAPcloud
  Link proxy traffic through vendor-run servers. Test the NAS's own address, if it
  is in scope, never the relay.
- **SaaS control planes.** Rubrik Security Cloud and Cohesity Helios are vendor
  infrastructure. Test the client's on-premises cluster address only.
- **Shared S3 endpoints.** A hostname that CNAMEs to a provider's object storage
  is the provider's server. That is `hunt-cloud-misconfig`'s case.

### Rate posture

Backup consoles run heavy Java or .NET stacks; NAS web servers are small embedded
daemons. Neither needs speed from you.

```bash
# 3s base delay + 0-3s jitter, one host at a time. NAS and Bacula hosts: 10s base.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 3+rand()*3}')"; }
```

- Serial, one host at a time, no parallel tools against one host.
- Stage A budget: about 25 HTTP requests per host per engagement day.
- No directory brute force, no scanner template sweep, no crawler on an admin UI.
- A timeout or reset after earlier answers is a lockout or a crash. Stop and wait;
  never retry in a loop.

---

## Step 2: Prove the exposure is real, external, the client's, and not already lost

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN and office range; record the egress IP | A console reached over the client's VPN is not an exposure |
| Ownership | ASN + RDAP + PTR, cross-checked with scope; rule out the relays and SaaS hosts above | Testing a vendor relay is testing the vendor |
| Real service | The product's own page, header or API answer, not the port number | 9000, 8080, 8000, 9443 and 4443 each belong to several products (Step 3) |
| Honeypot | Implausible combinations (a QNAP title with an IIS `Server` header), identical pages on unrelated IPs | NAS and Veeam decoys exist; a report against one is withdrawn |
| Already compromised | DeadBolt replaces the NAS login page with a ransom note; ransom notes in a share or bucket listing; a web shell path in public reporting for the CVE in range | That is an incident: stop testing, capture, escalate to the operator the same hour |

Record every raw response at probe time, before any Stage B work.

---

## Step 3: Triage the port to one reference file

Load **only** the reference the fingerprint points to.

| Port(s) | Product | Collision to rule out | Load |
|---|---|---|---|
| 9392, 9401, 9380, 9419, 9399; 9080/9443 | Veeam B&R, Enterprise Manager | 9443 Portainer (`hunt-exposed-panels`). 9401 also has a section in hes `management-interfaces.md` | `references/backup-servers.md` |
| 8400, 8401, 8403; 80/443 Command Center | Commvault | | `references/backup-servers.md` |
| 1556, 13724, 13782 | NetBackup | | `references/backup-servers.md` |
| 10000 | Backup Exec remote agent (NDMP) | Webmin. hes `management-interfaces.md` decides which | `references/backup-servers.md` |
| 9101, 9102, 9103 | Bacula Director, File, Storage daemons | **Inside the raw-print range 9100-9107.** Identify Bacula from other evidence before sending a byte | `references/backup-servers.md` |
| 9877, 7780, 9876 | Acronis Cyber Protect | | `references/backup-servers.md` |
| 4443 | NAKIVO Director | SSL VPN management (`enterprise-vpn-attack`) | `references/backup-servers.md` |
| 8014, 8015 | Arcserve UDP | | `references/backup-servers.md` |
| 7937-7938, 9000, 9001, 9090 | Dell NetWorker | 9000/9001 MinIO; 9090 Prometheus | `references/backup-servers.md` |
| 443 by title | Rubrik, Cohesity, Avamar, NetBackup web UI | | `references/backup-servers.md` |
| 8080, 443 | QNAP QTS / QuTS hero | Any HTTP alt service | `references/nas-appliances.md` |
| 5000, 5001 | Synology DSM | | `references/nas-appliances.md` |
| 8000, 8001 | Asustor ADM | 8000 Seafile seahub | `references/nas-appliances.md` |
| 80/443 by title | TrueNAS, WD My Cloud, Buffalo | | `references/nas-appliances.md` |
| 9000, 9001 | MinIO API, console | 9000 FastCGI (hes `remote-debug.md`), 9001 HSQLDB (hes `databases.md`), NetWorker | `references/object-storage.md` |
| 7480 | Ceph RGW | | `references/object-storage.md` |
| 9333, 8080, 8888, 8333; gRPC 19333, 18080, 18888 | SeaweedFS master, volume, filer, S3 | 8888 Jupyter (`hunt-exposed-panels`). gRPC ports: TCP connect only | `references/object-storage.md` |
| 443 with `/status.php` | Nextcloud, ownCloud | | `references/file-sync.md` |
| 8000, 8082 | Seafile | 8000 Asustor | `references/file-sync.md` |
| 8384, 22000, 21027/udp | Syncthing | | `references/file-sync.md` |
| 443 by title | FileCloud | | `references/file-sync.md` |

---

## Step 4: Stage A, fingerprint and read the version

A Stage A probe reads, sends no credential, is a single request, and touches no
component that a CVE in the matrix names. The generic pass for any HTTPS port:

```bash
T="192.0.2.30"; P="9443"; mkdir -p evidence
# Certificate only: subject, issuer, SANs, validity. No application bytes sent.
timeout 10 openssl s_client -connect "$T:$P" -servername "$T" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName \
  | tee "evidence/${T}_${P}_cert.txt"
probe_delay
# One page: status, headers, title.
curl -sk -m 15 -D "evidence/${T}_${P}_headers.txt" -o "evidence/${T}_${P}_index.html" "https://$T:$P/"
grep -io '<title>[^<]*' "evidence/${T}_${P}_index.html"
```

For service ports that are not HTTP (Veeam 9392/9401/9380, Commvault 8400/8401,
NetBackup 1556/13724, NetWorker 7937/7938, Acronis 7780), a TCP connect and, if
the port speaks TLS, the certificate read above are the whole of Stage A. Do not
speak the protocol.

### Where the version comes from

| Product | Stage A version source | Decides? |
|---|---|---|
| Nextcloud, ownCloud | `GET /status.php` (JSON `version`, `versionstring`) | Yes |
| Seafile | `GET /api2/server-info/` (verify fields) | Usually |
| Cohesity | The documented unauthenticated basic-cluster-info call (`backup-servers.md`) | Yes |
| SeaweedFS | Master or filer status pages (verify paths per release) | Usually |
| QNAP | Login CGI XML, requested **with no parameters** (field names verify) | Often |
| Synology | API catalogue and login page | Major version only |
| MinIO | `Server: MinIO`; build only via metrics if they are public (verify) | Rarely |
| Syncthing | The GUI itself, if it loads with no login | Yes, and that is the finding |
| Veeam, Commvault, NetBackup, Acronis, NAKIVO, Arcserve, NetWorker, Avamar, Rubrik, TrueNAS, WD, Asustor, Buffalo, FileCloud, Ceph | Title and certificate only | No. Ask the client, or Stage B B1 |

```bash
# One request each, only for the product the fingerprint already names.
curl -sk -m 15 "https://$T/status.php"                          # Nextcloud / ownCloud
curl -sk -m 15 "https://$T/api2/server-info/"                   # Seafile
curl -sk -m 15 "https://$T:5001/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query"  # Synology
curl -sk -m 15 "https://$T:8384/rest/noauth/health"             # Syncthing liveness (verify path)
curl -sk -m 15 -D - -o /dev/null "http://$T:9000/minio/health/live"   # MinIO liveness, headers
```

### Requests that look like fingerprinting and are exploitation

Never send these in Stage A, and never in Stage B either: report from the version.

| Looks like | What it really is |
|---|---|
| Asking Arcserve UDP's web service for its version | CVE-2023-26258: that method returns an authentication token |
| Anything beyond a TLS handshake on Veeam 9401 or 9380 | CVE-2023-27532 returns stored credentials; 9380 is the CVE-2022-26500/26501 service |
| Fetching an image or path through the NAKIVO Director router | CVE-2024-48248 arbitrary file read |
| MinIO cluster bootstrap or verification calls | CVE-2023-28432 returns root credentials |
| The ownCloud graphapi library path; a pre-signed WebDAV URL | CVE-2023-49103 / CVE-2023-49105 |
| Uploading an install package to Commvault Command Center | CVE-2025-34028 |
| QNAP CGI requests carrying parameters; HBS 3 or Photo Station endpoints | The Qlocker and DeadBolt entry points |
| Scanner templates tagged with these CVE IDs | Most send the exploit and match the leaked data. Read a template before running it; run fingerprint templates only |
| `nmap -sV --allports` or any payload on 9100-9107 | nmap excludes that range so a printer does not print your probe. Bacula lives there too |
| `nmap -sC` or `-A` | Pulls the `default` category, which includes scripts that log in (`iscsi-info`) |

### Object storage: one listing, names only

```bash
T="198.51.100.20"; P="9000"
# Headers and the unsigned error body identify MinIO, RGW or SeaweedFS's S3 gateway.
curl -sk -m 15 -D "evidence/${T}_${P}_headers.txt" -o "evidence/${T}_${P}_root.xml" "http://$T:$P/"
probe_delay
# A bucket name you already have (app, JS bundle, DNS, error page). No wordlists.
B="name-from-the-app"
curl -sk -m 15 "http://$T:$P/$B?list-type=2&max-keys=20" | tee "evidence/${T}_${B}_list.xml" \
  | grep -oE '<(Key|Size)>[^<]*' | head -40
```

A listing that returns keys is the finding. Record names, sizes and the count;
do not fetch an object to "see what is in it". Names such as `.vbk`, `.vib`,
`.bak`, `.sql.gz`, `.vmdk` or `id_rsa` already prove impact.

---

## Step 5: Version gates

Map the version to the product's table in the reference file. Rules:

- **"Version in range", never "vulnerable".** Unconfirmed until the client
  confirms the build or B1 reads it.
- **Builds are not always enough.** Commvault CVE-2025-34028 needs specific
  update packs on top of 11.38.20/11.38.25; distro and vendor backports exist for
  Ceph; QNAP and Synology apps (HBS 3, Photos) version separately from the OS.
- **State the invisible precondition.** Veeam's 2025 RCEs need a domain-joined
  backup server; MinIO CVE-2023-28432 needs a distributed deployment; ownCloud
  CVE-2023-49105 needs a user without a signing key (the default); Veeam
  CVE-2024-29849 needs Enterprise Manager deployed. Write "depends on X, client to
  confirm".
- **KEV row in range = same-day escalation**, unconfirmed or not. With the
  ransomware flag set, say so in the first line of the note.
- **End of support is its own finding.** An unsupported Veeam, QTS, DSM,
  Nextcloud or ownCloud major, or a MinIO community build after the project went
  into maintenance (see `object-storage.md`), is reportable without a CVE.
- **DoS-class rows are never tested** (Arcserve CVE-2024-0801, CVE-2025-34522/34523,
  Syncthing CVE-2021-21404, the DoS halves of Synology SA-26:13).

---

## Step 6: Stage B, anything that logs in, writes or speaks a backup protocol

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the host, the account or bucket, and a window. "Backup
infrastructure is in scope" is not sign-off. Record before the first packet:

```
Stage B authorization
  Host/port:        192.0.2.30:9000
  Action:           one PUT of canary object pentest-canary-<token>.txt to bucket <name>
  Blast radius:     one object created; versioning or replication may copy it to
                    other targets; the client removes it
  Reversibility:    client deletes the canary and confirms; nothing else changes
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| B1: log in with the client's test account to read the build | Login record and lockout counters. On a backup console the same session can start restores: read About, log out |
| B2: one vendor-documented default credential | Lockout; a success is administrative control of storage or backups |
| B3: one canary object to prove anonymous write | A new object, possibly replicated into backup targets |
| Bacula daemon handshake (no recipe here) | Starts authentication; logged as a failed login |
| Opening a share link the client did not publish | Possible personal data of third parties |

**Forbidden outright, sign-off or not:** restores, mounts, instant recovery,
file-level recovery, browsing restore points; creating, editing, starting or
deleting jobs; changing retention, immutability, object lock, versioning,
lifecycle, replication or bucket policy; deleting anything, including your own
canary; exporting or decrypting configuration databases or saved credentials;
downloading objects or files; adding Syncthing folders or devices; firmware
updates, app installs or enabling SSH/Telnet on a NAS; any request to a component
a CVE names; any DoS-class check.

### B1. Authenticated version read

Use the client's test account in the UI: About or Help page on backup consoles,
Control Panel on a NAS, admin overview on file-sync servers. Screenshot the build,
log out, touch nothing else. For object stores with client-issued keys:

```bash
# Stage B only, with written sign-off: client-issued keys, read-only server info.
mc alias set clientprobe "http://$T:9000" "$CLIENT_ACCESS_KEY" "$CLIENT_SECRET_KEY" \
  && mc admin info clientprobe | tee "evidence/${T}_9000_admin_info.txt"
mc alias remove clientprobe
```

### B2. One documented default credential

Only a pair the vendor documents for that exact product and version, once per
host per engagement: MinIO's root default when its variables are unset
(`object-storage.md`), QNAP QTS 4.4.1 and earlier (`nas-appliances.md`; QTS 4.4.2+
uses the MAC address, so skip). Commvault CVE-2025-57789 is a setup-window
default: report the version, never try it. Synology, TrueNAS and the backup
consoles have no factory credential worth one attempt.

```bash
# Stage B only, with written sign-off naming the host and this single documented pair.
# One attempt. Success = Critical: record the alias output, remove the alias, stop.
mc alias set probe "http://$T:9000" minioadmin minioadmin && mc admin info probe
mc alias remove probe
```

### B3. Anonymous write, one canary

Only when an anonymous listing already succeeded and the program needs write
proof. Never on a bucket whose names look like a backup repository: report the
listing instead, because a write there is the ransomware path itself.

```bash
# Stage B only, with written sign-off naming host, bucket and this exact key.
# The client removes the canary afterwards; you never issue a delete.
TOKEN="$(openssl rand -hex 8)"; KEY="pentest-canary-${TOKEN}.txt"
printf 'Authorized penetration test canary %s. Safe to remove.\n' "$TOKEN" > canary.txt
curl -sk -m 15 -o /dev/null -w '%{http_code}\n' --upload-file canary.txt "http://$T:$P/$B/$KEY"
curl -sk -m 15 "http://$T:$P/$B?list-type=2&prefix=pentest-canary-" | grep -o '<Key>[^<]*'
```

---

## Step 7: Grade on what you proved

| What you proved | Grade |
|---|---|
| Admin with no login: Syncthing GUI, open SeaweedFS master/filer, MinIO default root pair accepted (B2) | Critical |
| Anonymous listing whose names show backups, database dumps, VM images or keys | Critical (names only) |
| Anonymous listing of other non-public data | High |
| Anonymous write (B3) | High; Critical if the bucket is a backup target |
| Backup console reachable, version in a KEV row | High to Critical by row, unconfirmed, same-day escalation |
| Backup console reachable, version in a non-KEV pre-auth row | High, unconfirmed |
| NAS admin UI reachable, firmware or app in a KEV or pre-auth RCE row | High, unconfirmed, same day |
| ownCloud in the CVE-2023-49103 or CVE-2023-49105 range | High, unconfirmed, same day |
| Backup control plane reachable, version current or unknown | Low to Medium: the recovery plane belongs behind a VPN (vendors' own hardening guides say so) |
| Unsupported major version or unmaintained build | Medium |
| NAS admin UI or file-sync server reachable, current version | Low or Informational |
| Syncthing GUI with authentication over plain HTTP | Low |

### What is not a finding

- A version string from `status.php`, a `Server: MinIO` header or a product title.
  HackerOne lists banner and version disclosure as core ineligible.
- Nextcloud, ownCloud, Seafile or FileCloud reachable from the internet: that is
  their job.
- A bucket that is public on purpose (website assets, downloads).
- A version in range whose precondition you cannot see, reported as confirmed.
- Anything observed on QuickConnect, myQNAPcloud Link, Rubrik Security Cloud or
  Cohesity Helios infrastructure.

---

## Step 8: Evidence

Follow `evidence-hygiene`. Per finding: egress IP, timestamps, the exact command,
raw headers and body as saved at probe time, certificate output, the version
source, and for Stage B the sign-off record. For listings keep names, sizes and
counts; redact personal names in keys. Never store downloaded content, because
there should be none. For a canary, record its key so the client can remove it.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| Access key ID (no secret) in a JS bundle or repo | MinIO build in the CVE-2026-40344/41145 range allows writes with the ID alone | High, unconfirmed | Report; do not test the write |
| S3-compatible keys with secret leaked (`hunt-source-leak`) | B1 listing with those keys under sign-off | Per data class | `cloud-iam-deep` if they are AWS keys |
| Anonymous listing shows backup-repository names | Offline copy of the client's estate in reach of anyone | Critical | Stop at names; same-day notice |
| NAS admin page exposed | SSH, FTP, SMB, AFP, NFS, rsync on the same box | Per owner | `infra-ssh`, `infra-ftp`, `infra-windows-perimeter`, `hunt-exposed-services` |
| Veeam or Commvault console exposed, KEV build | Ransomware precursor | Critical-class | Same-day escalation; nothing further |
| Enterprise Manager or another IIS-hosted console offers NTLM | Internal host and domain names | Low | `hunt-ntlm-info` |
| Syncthing device ID or certificate | Same node on other addresses | Recon multiplier | `offensive-osint`; scope check per address |
| Nextcloud/ownCloud reachable | App-level bugs | Per class | `hunt-idor`, `hunt-xss`, `hunt-ssrf` |

---

## Validation checklist

- [ ] Probed from outside every client network; egress IP in the evidence.
- [ ] Every address client-owned and in scope; no vendor relay or SaaS host tested.
- [ ] Product identified by its own response, not by the port; collisions in
      Step 3 ruled out.
- [ ] No ransom note or compromise indicator, or the operator was told at once.
- [ ] Nothing sent to 9101-9103 before Bacula was proven by other evidence.
- [ ] Stage A stayed serial, rate-limited, within about 25 requests per host.
- [ ] No request to a component a CVE names; no scanner template that exploits.
- [ ] No `-sC`, `-A` or `--allports`.
- [ ] Listings capped and recorded as names, sizes and counts; nothing downloaded.
- [ ] Versions labelled unconfirmed, with the precondition stated; KEV rows
      escalated the same day.
- [ ] Every Stage B action has written sign-off; one default credential at most.
- [ ] No restore, mount, job, retention, policy or delete action of any kind.
- [ ] Canary keys handed to the client for removal.
- [ ] The report ends at exposure plus impact.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/backup-servers.md` | Veeam B&R, Enterprise Manager, VSPC; Commvault; NetBackup and Backup Exec; Bacula; Acronis Cyber Protect and Cyber Infrastructure; NAKIVO; Arcserve UDP; Dell NetWorker, Avamar, RecoverPoint for VMs; Rubrik; Cohesity. Ports, fingerprints, CVE/KEV matrix | veeam exposed, cve-2024-40711, cve-2023-27532, commvault command center, cve-2025-34028, nakivo 4443, arcserve udp, netbackup pbx 1556, backup exec ndmp, bacula 9101, acronis 9877, networker nsrexecd |
| `references/nas-appliances.md` | QNAP QTS/QuTS hero and apps, Synology DSM and Photos, TrueNAS, WD My Cloud, Asustor ADM, Buffalo; ransom-note triage; owner routing for other NAS services | qnap exposed, qlocker, deadbolt, hbs 3, synology 5001, dsm cve, risk:station, truenas, my cloud cve, asustor adm |
| `references/object-storage.md` | MinIO (incl. maintenance status, default root pair), Ceph RGW, SeaweedFS; anonymous listing and write rules | minio exposed, cve-2023-28432, minioadmin, s3 compatible bucket listing, ceph rgw 7480, radosgw, seaweedfs 9333 |
| `references/file-sync.md` | Nextcloud, ownCloud (KEV rows), Seafile, Syncthing (unauthenticated GUI), FileCloud | owncloud graphapi, cve-2023-49105, nextcloud status.php, seafile, syncthing 8384 exposed, filecloud |

Primary sources (fetched 2026-10-13):

- CISA KEV JSON feed, catalog 2026.10.13: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CVE List CNA records via <https://cveawg.mitre.org/api/cve/> and NVD API 2.0 <https://services.nvd.nist.gov/rest/json/cves/2.0>
- Veeam KB4288, KB4424, KB4581, KB4649, KB4724, KB4743, KB4771, KB4934 (<https://www.veeam.com/kbNNNN>); used ports <https://helpcenter.veeam.com/docs/backup/vsphere/used_ports.html>, <https://helpcenter.veeam.com/docs/backup/em/used_ports.html>
- Commvault TCP ports <https://documentation.commvault.com/v11/expert/tcp_ports_used_for_services.html>; advisories under <https://documentation.commvault.com/securityadvisories/>
- watchTowr Labs write-ups on NAKIVO CVE-2024-48248 and QNAP CVE-2024-27130: <https://labs.watchtowr.com/>
- QNAP advisories <https://www.qnap.com/en/security-advisory>; Synology advisories <https://www.synology.com/en-global/security/advisory>
- Dell KB 000204031 "NetWorker Processes and Ports"; Acronis Cyber Protect 15 network diagram; Arcserve UDP port tables (documentation.arcserve.com)
- Syncthing GUI listen address <https://docs.syncthing.net/users/guilisten.html>; SeaweedFS Production Setup wiki <https://github.com/seaweedfs/seaweedfs/wiki/Production-Setup>
- Bacula firewall ports <https://docs.baculasystems.com/>; HackerOne core ineligible findings <https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>

No lab verification was possible for this skill. Every endpoint and field marked
"(verify)" in the reference files should be checked against the product in hand.

---

## Related Skills & Chains

- `infra-external-methodology`: the port-to-skill routing table this skill plugs
  into.
- `hunt-exposed-services`: NFS, rsync, iSCSI, AFP, NDMP and the original Veeam
  9401 entry; its Stage A/B model is the template here.
- `infra-ssh`, `infra-ftp`, `infra-windows-perimeter`: the other services on the
  same NAS or backup host.
- `hunt-cloud-misconfig`, `cloud-iam-deep`: hosted buckets, bucket-name discovery
  and what a leaked cloud key grants.
- `hunt-exposed-panels`: generic admin consoles on the same ports (Portainer 9443,
  Jupyter 8888, Prometheus 9090).
- `enterprise-vpn-attack`: when 4443 or 443 turns out to be a VPN gateway.
- `hunt-source-leak`, `supply-chain-attack-recon`: where leaked object-store keys
  come from.
- `hunt-brute-force`: any credential guessing; this skill tries one documented
  default and hands off.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence, gates and
  write-up.

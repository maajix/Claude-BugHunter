# Backup servers: fingerprint, ports and version-gate matrix

A backup server holds credentials for every host it protects and a copy of every
dataset it backs up. That is why ransomware crews go for it first, and why none of
these consoles belongs on the internet. Exposure of the control plane is the
finding. A version inside a KEV row makes it urgent.

Rules for every row below:

- **Detected by version only.** A version inside a range is a lead labelled
  "unconfirmed" until the client confirms the build or an authenticated read under
  Stage B shows it. Never send a request to the component a CVE names, not even a
  GET: on several rows (CVE-2023-27532, CVE-2024-48248, CVE-2023-26258) the
  "read-only" request is the exploit and returns credentials.
- KEV column: CISA KEV catalog 2026.10.13. "Known" means CISA flags known
  ransomware campaign use.
- Ranges and fixed builds come from the vendor advisory or the CNA record in the
  CVE List. "(verify)" marks a detail that could not be confirmed from a primary
  source while this file was written.
- "Version observable?" says whether Stage A can read the version at all. For most
  backup consoles it cannot: ask the client, or read the About page under Stage B
  with the engagement test account.

---

## Veeam Backup & Replication, Enterprise Manager, Service Provider Console

| Port | Service (Veeam help center, v12 docs) |
|---|---|
| 9392/tcp | Console to backup server. From 12.1 a second port is also required (the archived 12.0 page names 9420; verify per build) |
| 9401/tcp | Secure connections / mount server to backup server; remote console file-level recovery (12.1+). The CVE-2023-27532 service |
| 9380/tcp | Veeam Distribution Service. The CVE-2022-26500/26501 service |
| 9419/tcp | VBR REST API |
| 9080/tcp, 9443/tcp | Enterprise Manager website (HTTP, HTTPS), including the Self-Service portals |
| 9399/tcp | Enterprise Manager REST API (current docs; older docs list 9398 HTTPS) |
| 6443/tcp | Cloud Connect Portal |

`hunt-exposed-services/references/management-interfaces.md` already carries a
9401 section with the CVE-2023-27532 and CVE-2024-40711 gates. This file agrees
with its ranges (checked against Veeam KB4424 and KB4649) and adds the rest.

**Fingerprint.** Enterprise Manager: the HTTPS title and login page on 9443. VBR
service ports: read only the TLS certificate (`openssl s_client`), never speak
the service protocol. A self-signed certificate naming a Veeam backup server is
the usual tell (verify the exact subject per build). **Version observable?** Not
pre-auth on the service ports; Enterprise Manager build only after login (verify).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2021-35971 | .NET remoting deserialization, unauthenticated RCE (NVD 9.8) | 10 before 10.0.1.4854 P20210609; 11 before 11.0.0.837 P20210507 | those builds | No |
| CVE-2022-26500 | Distribution Service (TCP 9380) exposes internal API; code upload and execution. KB4288 says unauthenticated; the NVD record says authenticated (PR:L) | 9.5, 10, 11 | 11a 11.0.1.1261 P20220302; 10a 10.0.1.4854 P20220304; 9.5 has no patch | Yes, 2022-12-13, Known |
| CVE-2022-26501 | Same service, incorrect access control, unauthenticated RCE | 10, 11 | as above | Yes, 2022-12-13, Known |
| CVE-2023-27532 | Missing authentication on TCP 9401 returns encrypted credentials from the configuration database | before 12.0.0.1420 P20230223 and 11a 11.0.1.1261 P20230227 | those builds | Yes, 2023-08-22, Known |
| CVE-2024-29849 | Enterprise Manager authentication bypass: log in as any user. Only where Enterprise Manager is deployed | Enterprise Manager before 12.1.2.172 | 12.1.2.172 (KB4581) | No |
| CVE-2024-40711 | Deserialization, unauthenticated RCE (CNA 9.8, PR:N) | 12.1.2.172 and all earlier v12 builds | 12.2.0.334 (KB4649) | Yes, 2024-10-17, Known |
| CVE-2024-40717, CVE-2024-42451 | Low-privileged role: RCE through job pre/post scripts; plaintext credential leak | 12.2 per CNA | (verify) | No |
| CVE-2025-23120 | RCE by any authenticated domain user. Only domain-joined backup servers | 12.3.0.310 and earlier v12 | 12.3.1.1139 (KB4724) | No |
| CVE-2025-23121 | Same class, domain-joined only | 12.3.1.1139 and earlier v12 | 12.3.2.3617 (KB4743) | No |
| CVE-2025-48983, CVE-2025-48984 | Mount service / backup server RCE by an authenticated domain user, domain-joined only | 12.3.2.3617 and earlier v12 | 12.3.2.4165 (KB4771). v13 "architecturally not impacted" | No |
| CVE-2025-64393 | Backup Viewer role to SYSTEM via Mount Service deserialization | 12.3.2.4854 and earlier v12 | 12.3.2.4934 (KB4934); v13 not affected | No |
| CVE-2026-58069 | Authenticated Cloud Connect tenant reads arbitrary files on the provider host | 12 up to 12.3.2, 13 up to 13.0.3 per CNA | (verify) | No |
| CVE-2026-21671 | Backup Administrator role RCE in high-availability deployments | Software Appliance 13.0.1 per CNA | (verify) | No |
| CVE-2024-42448 | VSPC: RCE from an authorized management agent | VSPC 8.1 per CNA | (verify) | No |
| CVE-2026-58073 | VSPC: unauthenticated impersonation of a managed agent, obtains its credentials | VSPC before 9.3 | 9.3 | No |
| CVE-2026-58071 | VSPC: unauthenticated access to the proxied appliance API as Portal Administrator in a short window after an admin logs in | VSPC before 9.3 | 9.3 | No |

The domain-joined condition on the 2025 rows is invisible from outside. Report
"version in range; impact depends on domain membership, client to confirm".

---

## Commvault (CommServe, Web Server, Command Center)

| Port | Service (Commvault "TCP Ports Used for Services") |
|---|---|
| 8400/tcp | Communications Service (GxCVD), every CommCell machine |
| 8401/tcp | Server Event Manager, CommServe only |
| 8403/tcp | Firewall tunnel (GxFWD, cvfwd), HTTP/HTTPS tunnelling; self-signed certificate on the CommServe |
| 80/443 | Web Server, Web Console and Command Center (paths such as `/commandcenter`, `/webconsole`; verify per release) |

**Fingerprint.** Command Center or Web Console login page title; the 8403
certificate. **Version observable?** Rarely. Commvault versions are
`11.<feature release>.<maintenance release>`, and CVE-2025-34028 shows the build
number alone does not decide: the fix needs specific update packs.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2021-34993 | CVSearchService authentication bypass, unauthenticated (ZDI-21-1328) | CommCell 11.22.22 as tested | (verify) | No |
| CVE-2025-3928 | Authenticated attacker plants and runs webshells on the Web Server | 11.36.0-11.36.45, 11.32.0-11.32.88, 11.28.0-11.28.140, 11.20 before 11.20.217 | 11.36.46, 11.32.89, 11.28.141, 11.20.217 | Yes, 2025-04-28 |
| CVE-2025-34028 | Command Center Innovation Release: unauthenticated install-package upload, path traversal, JSP RCE. LTS releases not affected | 11.38.0 to 11.38.20 (CNA affected range reads up to 11.38.25) | 11.38.20 with SP38-CU20-433 and SP38-CU20-436, or 11.38.25 with SP38-CU25-434 and SP38-CU25-438 | Yes, 2025-05-02 |
| CVE-2025-57788 | Unauthenticated API calls through a login mechanism | 11.32.0-11.32.101, 11.36.0-11.36.59 | 11.32.102, 11.36.60 | No |
| CVE-2025-57789 | Default credential usable between installation and the first admin login | same | same | No |
| CVE-2025-57790 | Path traversal to RCE (CNA: PR:L) | same | same | No |
| CVE-2025-57791 | Argument injection yields a low-privilege session, unauthenticated | same | same | No |
| CVE-2026-13737, CVE-2026-13738 | CommServe command-execution allowlist / authorization bypass, unauthenticated (CVSS 4.0 9.2, AC:H) | 11.46.0-11.46.9, 11.44.0-11.44.10, 11.40.0-11.40.62, 11.36.0-11.36.113 | next maintenance release per advisories CV_2026_07_8 and CV_2026_07_9 (verify exact builds) | No |

The researchers who found the 2025-08 set (watchTowr) chained 57791 with 57790,
and 57788 with 57789 and 57790, into pre-auth RCE. Grade a version in range as
pre-auth RCE-class, unconfirmed.

---

## Veritas / Cohesity NetBackup, and Veritas Backup Exec

NetBackup documentation now lives under Cohesity after Cohesity took over the
Veritas data-protection business (verify the transaction date before citing it).

| Port | Service |
|---|---|
| 1556/tcp | PBX (Private Branch Exchange), the front door for most NetBackup services |
| 13724/tcp | vnetd, NetBackup network service |
| 13782/tcp | bpcd (legacy daemon connections) |
| 443 | NetBackup web UI and OpsCenter web (verify ports per release) |
| 10000/tcp | Backup Exec remote agent over NDMP. Owned by `hunt-exposed-services` (`management-interfaces.md`, NDMP vs Webmin) |

**Fingerprint.** TCP connect to 1556/13724 only, plus the web UI title. Do not
speak PBX or vnetd. **Version observable?** No (verify).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2022-36986 | Unauthenticated remote command execution on a Primary server (CNA vector scores 8.6) | 8.1.x-8.1.2, 8.2, 8.3.x-8.3.0.2, 9.x-9.0.0.1, 9.1.x-9.1.0.1 | per Veritas VTS22 advisory (verify) | No |
| CVE-2022-36950, CVE-2022-36951 | OpsCenter unauthenticated RCE (classloader manipulation; incomplete earlier patch) | 8.x-8.3.0.2, 9.x-9.0.0.1, 9.1.x-9.1.0.1, 10 | (verify) | No |
| CVE-2022-42302 | Primary server SQL injection in NBFSMCLIENT, PR:N, AC:H | through 10.0 | (verify) | No |
| CVE-2022-46414 | NetBackup Flex Scale and Access Appliance management portal, unauthenticated command execution | Flex Scale through 3.0; Access Appliance through 8.0.100 | per VTS22-019 (verify) | No |
| CVE-2023-40256 | NetBackup Snapshot Manager: untrusted clients reach its RabbitMQ (client certificate not validated) | before 10.2.0.1 | 10.2.0.1 | No |
| CVE-2024-28222 | BPCD path validation: unauthenticated upload and execution | NetBackup before 8.1.2; Appliance before 3.1.2 | 8.1.2 / Appliance 3.1.2 | No |
| CVE-2021-27876, CVE-2021-27877, CVE-2021-27878 | **Backup Exec** (not NetBackup) agent SHA authentication scheme: file access, auth bypass, command execution | Backup Exec before 21.2 | 21.2 | Yes, all three 2023-04-07, Known |

---

## Bacula (Director, File and Storage daemons; Bacula-web, Bacularis)

| Port | Service |
|---|---|
| 9101/tcp | Director (bconsole connects here) |
| 9102/tcp | File daemon (client) |
| 9103/tcp | Storage daemon |
| HTTP | Bacula-web and Bacularis web front ends (Bacularis default port 9097, verify) |

**These three ports sit inside 9100-9107, the raw-print range.** nmap's
`nmap-service-probes` excludes 9100-9107 from `-sV` so that a version probe does
not print on a JetDirect printer, and `hunt-exposed-services` forbids sending
unrecognised bytes there. Identify Bacula from other evidence first: a Bacula-web
or Bacularis UI on the same host, reverse DNS, the client's inventory, or a
passive Shodan/Censys record. Until then, a TCP connect is all you send. Even
after that, the daemon handshake starts authentication (shared-password
challenge; verify protocol details), so it is Stage B, and no recipe is given.

| CVE | Class | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2025-45346 | Bacula-web SQL injection to code execution via crafted GET | Bacula-web before 9.7.1 | 9.7.1 | No |
| CVE-2026-88742, CVE-2026-88743, CVE-2026-95165, CVE-2026-95166 | Bacularis stored/reflected XSS | Bacularis up to 6.5.0 / 6.5.1 per CNA | (verify) | No |

No 2021-2026 network CVE for the core Bacula daemons turned up in an NVD keyword
search on 2026-10-13. Exposure plus unauthenticated reachability is the finding.

---

## Acronis Cyber Protect (and Cyber Infrastructure)

| Port | Service (Cyber Protect 15 network diagram; v16 verify) |
|---|---|
| 9877/tcp | Management server web console and REST API, TLS |
| 7780/tcp | ZeroMQ with CURVE authentication; agents and storage nodes |
| 9876/tcp | Storage node backup data |

**Fingerprint.** Web console title on 9877. **Version observable?** Build number
after login (verify); otherwise ask the client.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2025-30410 | Missing authentication: sensitive data disclosure and manipulation (9.8) | Cyber Protect 16 before build 39938; 15 before 41800; Cloud Agent before 39870 | those builds | No |
| CVE-2025-30411, CVE-2025-30412 | Improper authentication (10.0) | Cyber Protect 16 before 39938; 15 before 41800 | those builds | No |
| CVE-2025-30416 | Missing authorization (10.0) | same | same | No |
| CVE-2023-45249 | **Acronis Cyber Infrastructure** (a different product) default passwords: remote command execution | ACI before 5.0.1-61, 5.1.1-71, 5.2.1-69, 5.3.1-53, 5.4.4-132 | those builds | Yes, 2024-07-29 |
| CVE-2026-87886 | Local privilege escalation in Acronis Backup plugins for cPanel/WHM, Plesk and DirectAdmin | plugin builds before 1.9.3.1021 / 1.8.11.638 / 1.2.3.238 | those builds | Yes, 2026-09-16. **Local only: not testable from outside; listed so a KEV search does not mislead you** |

---

## NAKIVO Backup & Replication

| Port | Service |
|---|---|
| 4443/tcp | Director web UI and API (HTTPS). Collides with SSL VPN management on 4443; the page decides |

**Fingerprint.** Login page title. **Version observable?** After login (verify).

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2024-48248 | Unauthenticated absolute path traversal file read through the Director router; stored cleartext credentials make it an enterprise-wide compromise | before 11.0.0.88174 | 11.0.0.88174 (shipped silently) | Yes, 2025-03-19 |
| CVE-2025-32406 | XXE in the Director NBR component, unauthenticated (8.6) | 10.3.x through 11.0.1 | 11.0.2 | No |

---

## Arcserve Unified Data Protection (UDP)

| Port | Service (Arcserve docs; changeable at install) |
|---|---|
| 8015/tcp | Console web UI (default) |
| 8014/tcp | Agent / recovery point server web services; the only port needed for RPS replication across a WAN |

**Version observable?** **Do not ask the service.** The web-service method that
returns version information is the CVE-2023-26258 primitive: it leaks an
authentication token. Read the version from the client.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2023-26258 | Authentication bypass: a version-info method leaks an auth token that yields an admin session | through 9.0.6034 | 9.1+ (verify); 8.1 patch P00002856 | No |
| CVE-2023-41998, CVE-2023-41999, CVE-2023-42000 | Unauthenticated RCE, management auth bypass, unauthenticated path-traversal upload | before 9.2 | 9.2 | No |
| CVE-2024-0799 | Unauthenticated authentication bypass in the console login wizard | 9.2 and 8.1 and earlier | 9.2 patch P00003050; 8.1 patch P00003059; 9.0/9.1 must move to 9.2 first | No |
| CVE-2024-0800 | Path traversal upload (PR:L), chains with 0799 to pre-auth | same | same | No |
| CVE-2024-0801 | Unauthenticated DoS in ASNative.dll. **DoS-class: never tested** | same | same | No |
| CVE-2025-34520 | Authentication bypass (CVSS 4.0 vector says adjacent network) | 8.0 to 10.1 and 7.x | 10.2 | No |
| CVE-2025-34522, CVE-2025-34523 | Pre-auth heap overflows. **Never tested** | 8.0 to 10.1 and 7.x | 10.2 | No |

KEV holds only an older Arcserve entry, CVE-2015-4068 (directory traversal),
outside this matrix's window.

---

## Dell NetWorker, Avamar, RecoverPoint for VMs

| Port | Service (Dell KB 000204031 "NetWorker Processes and Ports") |
|---|---|
| 7937-7938/tcp | nsrexecd (7938 also portmapper function) |
| 9000/tcp | NMC client to NMC server, HTTP. **Collides with MinIO's S3 API port** |
| 9001/tcp | NMC Java console RPC. **Collides with the MinIO console and HSQLDB** |
| 9090/tcp | NetWorker authentication service. Collides with Prometheus |
| 7937-9936 | Default dynamic range |
| 443 | Avamar web UIs (verify paths and other ports per release) |

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2023-24576 | nsrexecd: unauthenticated "remote code execution" per Dell text (CVSS vector C:H only, 7.5) | NetWorker 19.7.0.2 and earlier; 19.8 and earlier | per DSA-2023-041 (verify exact builds) | No |
| CVE-2024-42422 | Authorization bypass, unauthenticated information disclosure | 19.10 before 19.10.0.6; 19.11 up to 19.11.0.2 | (verify) | No |
| CVE-2020-29493, CVE-2020-29495 | Avamar Fitness Analyzer SQL injection / OS command injection, unauthenticated (published 2021-01-14) | Avamar 19.1, 19.2, 19.3 before hotfix | vendor hotfix (verify) | No |
| CVE-2024-47977 | Avamar SQL injection to command execution, low-privileged | 19.4, 19.7-19.10SP1 | 19.12 with patch 338905; 19.10/19.10SP1 with patch 338869 | No |
| CVE-2026-22769 | **RecoverPoint for VMs** hardcoded credential: unauthenticated root | 5.3 SP4 P1 through 6.0 SP3 P1 | 6.0.3.1 HF1 | Yes, 2026-02-18 |

---

## Rubrik and Cohesity

Both run their own web UI on 443; both also sell SaaS control planes (Rubrik
Security Cloud, Cohesity Helios) that are **vendor infrastructure, not the
client's**. Test only the client's on-premises cluster address.

- **Cohesity.** The developer reference documents a basic cluster info endpoint
  (`/irisservices/api/v1/public/basicClusterInfo`, verify the path) as requiring no
  authentication; it returns cluster name, type and software version. One GET is
  Stage A.
- **Rubrik.** No documented unauthenticated version endpoint was found. Fingerprint
  by title and certificate; version from the client.

| CVE | Class / precondition | Affected | Fixed | KEV |
|---|---|---|---|---|
| CVE-2024-36068 | Rubrik CDM incorrect access control, network attacker executes code (NVD 9.8) | CDM before 9.1.2-p1, 9.0.3-p6, 8.1.3-p12 | those builds | No |
| CVE-2021-28123 | Cohesity DataPlatform undocumented default SSH key | 6.3 before 6.3.1g, 6.4 up to 6.4.1c, 6.5.1 through 6.5.1b | (verify) | No |
| CVE-2023-33295 | Cohesity DataProtect static TLS certificates (MITM) | before 6.8.1_u5 / 7.1 | 6.8.1_u5, 7.1, HEDP2023Dec | No |

---

## Stage A and Stage B for this family

Stage A per product: TLS certificate, page title, `Server` header, and the one
documented unauthenticated version read where it exists (Cohesity). Nothing on the
service ports beyond a TCP connect and a TLS handshake.

Stage B, with written sign-off: logging in with the client's test account to read
the build from the About page; nothing else in the console. **Forbidden outright,
sign-off or not:** starting, editing or deleting jobs; changing retention,
immutability or hardened-repository settings; restores, mounts, instant recovery,
file-level recovery; browsing restore points; exporting or decrypting the
configuration database or saved credentials; any request to a component a CVE
names; any DoS-class check. A backup server is often the last clean copy the
client has. If the test breaks it, the next ransomware incident has no recovery.

---
name: infra-windows-perimeter
description: "Triage Windows and Active Directory services answering from the public internet: SMB port 445, NetBIOS 137/138/139, MSRPC 135 and dynamic RPC 49152+, RDP 3389, Kerberos 88, CLDAP 389/udp, MSSQL 1433 and SQL Browser 1434/udp. The finding is the exposure plus what unauthenticated read-only enumeration proves: SMBv1 and dialects, SMB signing not required, null session and guest share listing, hostname, domain and OS build leaked by SMB, RDP and MSSQL NTLMSSP or the RDP certificate, NLA state, a reachable KDC, CLDAP domain disclosure, SQL Server version and instances. KEV pre-auth CVEs (EternalBlue MS17-010, BlueKeep, SMBGhost, MS08-067) are graded by version gate and read-only checks only. Stage B needs written sign-off: intrusive NSE scripts, one sa attempt, Kerberos checks on client test accounts. No Kerberoasting, AS-REP roasting, spraying, relay, Responder, pass-the-hash or exploitation. Use when a scan shows 445, 3389, 88, 135 or 1433 open on an in-scope external host."
sources: msrc_update_guide, microsoft_learn, cisa_kev, nvd, nmap_script_source, impacket_source, metasploit_source, netexec_source, project_documentation
report_count: 0
---

## When to use

Trigger when external recon has already produced an open Windows or Active
Directory service port on a host you are authorized to test. These services
belong behind a firewall or VPN. The finding is **the exposure itself plus what
an unauthenticated client is told**, never an exploit you ran.

Use when any of these is true:

- A port scan or Shodan/Censys record shows 445, 139, 135, 3389, 88, 1433,
  389/udp, 1434/udp or 137/udp answering on a public address.
- An RDP certificate, an NTLM challenge or a SQL Browser reply names an internal
  AD domain or host.
- The client says "no Windows services are internet-facing" and one answers.

**Do not use this skill for discovery.** Host, port and ASN discovery belong to
`offensive-osint`, `web2-recon` and `infra-external-methodology`; scope
confirmation belongs to `recon-scope-triage`. This skill starts from "a Windows
port is open and in scope".

### Where this sits in SECURITY.md

`SECURITY.md` limits the bundle to the external attack surface and lists
internal Active Directory attacks as out of scope by design. This skill stays on
the external side of that line. SMB, MSRPC, RDP, Kerberos and MSSQL answering
from the internet is a perimeter failure: the report is about the firewall gap
and what it leaks. `SECURITY.md` excludes the attacks that would come next, and
this skill never takes that step. **The chain ends at exposure + unauthenticated
enumeration + version gate + impact described.** If the next useful action needs
a credential, a relay, a ticket or an exploit, write the report and stop.

### What you do not do here

None of these is unlocked by sign-off. They are outside the bundle.

- **Kerberoasting or AS-REP roasting.** If a Stage B Kerberos check returns an
  AS-REP (an account without pre-authentication), discard the reply. Do not save
  it, do not crack it, and report only that such an account exists.
- **Password spraying, credential stuffing or any guessing** beyond the single
  documented-default attempt in Step 5, which follows `hunt-brute-force` rules.
- **NTLM relay** (ntlmrelayx), **Responder**, LLMNR/NBT-NS poisoning, mitm6.
- **Authentication coercion** over an exposed 135 or 445: PetitPotam (MS-EFSR),
  PrinterBug (MS-RPRN), DFSCoerce. Seeing the interface is the finding; calling it is not allowed.
- **Pass-the-hash, pass-the-ticket**, ticket forgery, Zerologon testers or any
  Netlogon authentication attempt.
- **Exploits** for SMB, RDP, MSRPC or MSSQL, including Metasploit and public PoCs.
- **Directory enumeration:** RID cycling (`lookupsid.py`), SAMR user and group
  listing (`samrdump.py`, `enumdomusers`, enum4linux), BloodHound collection,
  LDAP dumps. Counts prove the class; names are AD reconnaissance.
- **Share spidering**, recursive listings, downloads beyond one Stage B redacted
  sample, and anything that writes: `put`, `mkdir`, or a write-access test that
  creates a file or directory.
- **NetExec / CrackMapExec.** `SECURITY.md` names them as internal-RT handoff
  tooling. NetExec v1.5.1 (latest release, 2026-02-23) `--shares` also creates and
  deletes a directory on every share unless `--no-write-check` is passed.
- **Interactive sessions:** opening an RDP desktop, typing at a logon screen, a
  WinRM shell, `xp_cmdshell`, PrintNightmare (post-auth), lateral movement.

### Who owns the neighbours

| Surface | Owner |
|---|---|
| LDAP/LDAPS/Global Catalog on TCP 389, 636, 3268, 3269 (rootDSE) | `hunt-exposed-services`, `references/management-interfaces.md`. CLDAP on 389/**udp** is here. |
| WinRM and OMI 5985/5986 | `hunt-exposed-services` |
| NTLM Type-2 over HTTP (IIS, Exchange `/rpc`, `/RDWeb`) | `hunt-ntlm-info`. This skill covers the SMB, RDP and MSSQL NTLMSSP leak. |
| RD Gateway and RD Web Access on 443, KDC Proxy `/KdcProxy` | `enterprise-vpn-attack`, `hunt-exposed-panels`. Their CVE rows sit in the matrix here so the version gate is not lost. |
| Windows DNS Server on 53 | `infra-dns` |
| Any credential attempt | `hunt-brute-force` |
| TLS protocol or cipher findings on 3389, 1433, 636 | `hunt-tls-network` |

---

## Step 1: Inherit the host and port list

Follow `hunt-exposed-services` Step 1 unchanged: hosts from the signed scope,
ports from recon, ownership checked per IP, no mass scanning. The Windows probe
set is TCP 88, 135, 139, 445, 464, 593, 1433, 3268, 3389 and UDP 88, 137, 389,
1434. **Do not sweep the dynamic RPC range (49152-65535).** The endpoint mapper
on 135 lists the ports that are bound; probe only those, and only if needed.

### Rate posture

Serial, one host at a time, 2 s base delay plus 0-3 s jitter between probes. A
timeout is a result; retry once at most.

- **UDP reflectors get one unspoofed packet per host per service.** CISA
  TA14-017A lists CLDAP at a 56-70x bandwidth amplification factor and NetBIOS at
  3.8x; NETSCOUT lists SQL Server Resolution on 1434/udp at 25:1. A loop against
  these is a DDoS rehearsal.
- **`rdp-enum-encryption` opens several connections** (one per security layer and
  cipher). Run it once per host.
- **Windows Server 2025 and Windows 11 24H2 delay every failed NTLM
  authentication by 2 s** (SMB authentication rate limiter, on by default). A slow
  failure is the limiter, not packet loss. Do not retry.

### Lockout safety: which calls touch an account

Even "enumeration" can lock a real user out. Know which side of this table a
command is on before you run it.

| Action | Touches an account | Lockout risk |
|---|---|---|
| Anonymous SMB session: `smbclient -U '%' -N`, `rpcclient -U '' -N`, impacket `login('', '')` | No | None |
| `smbclient` **without** `-U` | Yes: sends your local Unix username with an empty password | Real, if that name exists in the domain. Always pass `-U '%'`. |
| nmap's SMB library with no arguments | Tries anonymous, then `guest` with an empty password, on each connection (`smbauth.lua`) | Guest is normally disabled; each try is a failed-logon event. Pass `--script-args smbnoguest`. |
| One explicit guest attempt | The built-in Guest account | No real-user lockout. Logged. Once per host. |
| `srvinfo`, `lsaquery`, `querydominfo`, `netshareenumall` over a null session | No | None |
| Any SMB, RDP, LDAP, WinRM or RPC call with a real username and a wrong password | Yes | Increments `badPwdCount`. Never in this skill. |
| SAMR password-change or set-info calls | Yes | Never |
| Kerberos AS-REQ **without** pre-auth data (`krb5-enum-users`) | Probes a principal | kerbrute's documentation says this causes no login failure and logs event 4768. Stage B, client test names only. |
| Kerberos AS-REQ **with** pre-auth (a password) | Yes | Event 4771 and `badPwdCount`. Never. |
| MSSQL login as `sa` | Yes | SQL logins with `CHECK_POLICY = ON` follow the Windows lockout policy; a locked `sa` returns error 18486 and breaks any application that (wrongly) uses it. Stage B, once. |
| Zerologon checkers | DC machine account, up to 2000 Netlogon authentications | Never |

---

## Step 2: Prove the exposure is real, external and the client's

Clear the four checks in `hunt-exposed-services` Step 2 (external vantage, IP
ownership, honeypot, filtering versus service) first. Then the Windows-specific
ones:

- **Identity consistency.** The NTLMSSP DNS name, the RDP certificate CN, the
  CLDAP `dnsHostName` and the NetBIOS name should describe one machine. Names
  that disagree across services on one IP point at NAT, a load balancer or a
  honeypot. Find out which before you report.
- **Impossible combinations are honeypots or middleboxes.** `smb-vuln-ms17-010`
  reporting VULNERABLE while the same host's NTLMSSP build is 10.0.17763 or later
  is not a finding; MS17-010's affected list ends at Windows 10 1607 / Server
  2016.
- **Identical NTLMSSP names on unrelated client IPs** usually mean a shared
  sensor or a vendor appliance, not ten client servers.
- **Samba is not Windows.** A Samba server answers on 445 with a Unix-flavoured
  OS string and its own version line. It is still an exposure finding, with
  its own CVE rows (see the matrix).

Record the baseline raw response of every probe before any Stage B work.

---

## Step 3: Map the open port to its Stage A probe

Exact commands, expected output and interpretation are in
`references/enumeration-commands.md`, one section per row.

| Port(s) | Service | Stage A probe | Record |
|---|---|---|---|
| 445/tcp, 139/tcp | SMB, SMB over NetBIOS | `smb-protocols`, `smb2-security-mode`, `smb2-time`; impacket identity script; `smbclient -L` null; one guest try; `smb-vuln-ms17-010` only if SMBv1 is offered | Dialects, SMBv1, signing required or not, NTLMSSP names and build, share names |
| 137/udp | NetBIOS name service | `nbstat`, one packet | Names and suffixes (`<1C>` = domain controllers, `<1B>` = domain master browser), MAC |
| 138/udp | NetBIOS datagram | None. Note it if open. | Reachability only |
| 135/tcp, 593/tcp, bound 49152+ ports | MSRPC endpoint mapper, RPC over HTTP | `rpcdump.py -port 135` | Interfaces: MS-NRPC (a DC), MS-RPRN, MS-PAR, MS-EFSR (coercion surface), termsrv |
| 3389/tcp (and 3389/udp) | RDP | `rdp-enum-encryption`, `rdp-ntlm-info`, certificate script | Security layers accepted (NLA enforced or not), NTLMSSP names and build, certificate CN |
| 88/tcp+udp, 464/tcp | Kerberos KDC, kpasswd | `nmap -sV -p 88` | KDC reachable, server time |
| 389/udp | CLDAP | `ldap-rootdse` over UDP, one packet | Naming contexts, `dnsHostName`, functional levels |
| 1433/tcp, 1434/udp | MSSQL, SQL Browser | `ms-sql-info`, `ms-sql-ntlm-info`, `ssl-cert` on 1433 | Exact build, instance names, named pipe, NTLMSSP names, TLS certificate CN |

**A domain controller fingerprint** is 88 + 389 + 445 + 464 (+ 3268) on one
address, MS-NRPC in the endpoint list, a `<1C>` NetBIOS name, and a CLDAP reply.
One internet-reachable DC is a different finding from one exposed file server;
grade it as such in Step 7.

---

## Step 4: Stage A, read-only enumeration

**Stage A is the default.** A Stage A probe must: only read; send a single
request or one handshake per service; touch no account (Step 1 table); fail as a
timeout or an error reply, never a service restart.

Verify every NSE script before first use: `nmap --script-help <name>`. The table
below lists categories as declared in each script's own `categories` line.
**`-sC`, `-A` and `--script smb-*` / `ms-sql-*` category globs are never Stage
A.** Name scripts one by one.

| Script or tool | Declared categories | Why it is not Stage A, or what to watch |
|---|---|---|
| `smb-enum-shares` | `discovery`, `intrusive` | Writes `nmap-test-file` to every share to test write access, then deletes it; if the delete fails the file stays. Falls back to a share-name wordlist when `NetShareEnumAll` is denied. |
| smbmap (1.10.8) default run | n/a | Creates and removes a test directory on every share unless `--no-write-check`. |
| NetExec v1.5.1 `--shares` | n/a | Same: `createDirectory` per share unless `--no-write-check`. Out of bundle anyway. |
| `smb-vuln-cve-2017-7494` | `vuln`, `intrusive` | Looks for writable shares by writing to them. |
| `smb-vuln-ms08-067` | `intrusive`, `exploit`, `dos`, `vuln` | Its own description: "may crash systems"; 52 of 82 vulnerable test systems crashed. Never run it. |
| `smb-vuln-ms10-054`, `-cve2009-3103`, `-conficker`, `-regsvc-dos`, `smb-flood` | include `dos` | Crash or flood. Never. |
| `rdp-vuln-ms12-020` | `intrusive`, `vuln` | Not `dos`-tagged, but it drives the CVE-2012-0152 channel-join path and relies on a cleanup join to avoid a crash. Stage B. |
| Metasploit `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` | `CRASH_SAFE` (module notes) | Binds the MS_T120 channel outside its slot, which is the bug's own trigger, and the same module ships a `Crash` action. There is no stock nmap BlueKeep script. Stage B. |
| `krb5-enum-users` | `auth`, `intrusive` | A user-existence oracle. Stage B, client test names only. |
| `ms-sql-empty-password` | `auth`, `intrusive` | Tries `sa` with an empty password, once per instance. Stage B. |
| `ms-sql-dump-hashes` | `auth`, `discovery`, `safe` | Despite `safe`, dumps password hashes using any credential another script in the run found. Credential dumping: never. |
| `ms-sql-query`, `-tables`, `-config`, `-hasdbaccess` | `discovery`, `safe` | Despite `safe`, they log in, reusing credentials found earlier in the same run. Never alongside `ms-sql-empty-password`. |
| `smb-enum-services` | `discovery`, `intrusive`, `safe` | Contradictory tags; needs credentials. Not Stage A. |
| `smb-enum-users`, `-groups`, `-domains`, `-sessions`, `-processes` | include `intrusive` | User and session enumeration is AD reconnaissance. Out. |
| `smb-os-discovery`, `smb-security-mode`, `smb-vuln-ms17-010`, `msrpc-enum` | `safe` variants | nmap's non-`smb2` SMB library negotiates **SMBv1 only**, and adds the guest fallback. On a modern SMB2-only host they return nothing. Silence means "no SMBv1", not "clean". |
| `smb2-vuln-uptime` | `vuln`, `safe` | Reads boot time from the SMB2 negotiate reply; returns nothing when the server sends a zero boot time. Silence is not a pass. |
| `ms-sql-info` | `default`, `discovery`, `safe` | Host script that may contact ports and named pipes you did not list. Pass `mssql.scanned-ports-only`. |
| `ssl-cert` on 3389 | `default`, `safe`, `discovery` | nmap's `sslcert` library has no RDP STARTTLS handler, so it gets nothing on 3389. Use the certificate script in the reference. On 1433 it works (TDS handler). |

The Stage A commands per service (full versions, with output, in the reference):

```bash
T=192.0.2.10
# SMB: dialects, signing, boot time. SMB2-capable scripts, no guest fallback.
nmap -Pn -p 445 --script smb-protocols,smb2-security-mode,smb2-time \
  --script-args smbnoguest --max-retries 1 "$T"
# SMB identity from the NTLMSSP challenge (works on SMB2-only hosts)
/usr/bin/python3 -I smb_identity.py "$T"          # script in the reference
# Null-session share listing: srvsvc NetShareEnumAll only, no writes
smbclient -L "//$T" -U '%' -N
# MSRPC endpoint list from 135 (Debian/Kali name: impacket-rpcdump)
rpcdump.py -port 135 "$T"
# RDP: security layers (NLA) and NTLMSSP identity
nmap -Pn -p 3389 --script rdp-enum-encryption,rdp-ntlm-info "$T"
# Kerberos reachability and server time; CLDAP rootDSE, one UDP packet
nmap -Pn -sV -p 88 "$T"
nmap -Pn -sU -p 389 --script ldap-rootdse --max-retries 0 "$T"
# NetBIOS names, one UDP packet
nmap -Pn -sU -p 137 --script nbstat --max-retries 0 "$T"
# MSSQL: exact build, instances, NTLMSSP identity, TLS certificate
nmap -Pn -sU -sT -p U:1434,T:1433 --script ms-sql-info,ms-sql-ntlm-info,ssl-cert \
  --script-args mssql.instance-all,mssql.scanned-ports-only --max-retries 0 "$T"
```

The guest probe is one explicit call per host, after the null-session listing:

```bash
smbclient -L "//$T" -U 'guest%' -N
```

**SMB share contents.** If a non-default share (anything other than `IPC$`,
`ADMIN$`, `C$`, `print$`, `NETLOGON`, `SYSVOL`) is listable anonymously or as
guest, one top-level `ls` of that share is Stage A. No `recurse`, no `get`, no
second level. Record file names and counts only.

```bash
smbclient "//$T/Public" -U '%' -N -c 'ls'
```

---

## Step 5: Stage B, gated actions

Stage B is **blocked by default** and requires explicit written operator sign-off
naming the action, the host and a window, in the format of `hunt-exposed-services`
Step 5. Verbal approval or "critical findings are in scope" is not sign-off.

```
Stage B authorization
  Host/port:      192.0.2.10:1433
  Action:         one SQL login as sa with an empty password (ms-sql-empty-password, run alone)
  Blast radius:   one failed-logon event; with CHECK_POLICY ON it counts toward
                  sa lockout, which breaks any application that logs in as sa
  Reversibility:  a lockout needs a DBA to unlock; no data is read or written
  Window:         <date/time>
  Authorized by:  <operator name/role>, in writing, <link to the message>
```

| Stage B action | Blast radius to name in the sign-off |
|---|---|
| One `sa` / empty-password login (`ms-sql-empty-password`, alone in its own run) | `sa` lockout (error 18486). If it succeeds, stop: no query, no `xp_cmdshell`. |
| `krb5-enum-users` against **client-provided test account names only** | Event 4768 per name on the DC. An AS-REP returned for a no-preauth account is discarded unread. |
| `rdp-vuln-ms12-020` | Drives the CVE-2012-0152 code path on a live terminal server; a failed cleanup can crash it. |
| Metasploit BlueKeep check (`Scan` action only) | Exercises the MS_T120 binding bug on a host that may be vulnerable: **the host may blue-screen**. |
| `smb-vuln-cve-2017-7494` on a Samba host | Writes a test file to every writable share. |
| Downloading one file from an anonymously readable share | Personal or business data now on your disk. One file, redacted, deleted after reporting. |
| Any `vuln`, `intrusive`, `exploit` or `dos` script not named above | Unknown until you read its source. Read it first. |

Stage B commands, each with its gate, are in the reference. Two that recur:

Stage B, written sign-off required. Test account names from the client only, never a wordlist:

```bash
nmap -Pn -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm=CORP.EXAMPLE,userdb=client-test-accounts.txt "$T"
```

Stage B, written sign-off required. Run alone so no other `ms-sql-*` script can reuse a found credential:

```bash
nmap -Pn -p 1433 --script ms-sql-empty-password --script-args mssql.scanned-ports-only "$T"
```

---

## Step 6: Version-gate the KEV CVEs

The full matrix, with KEV dates, NVD and MSRC scores and the observable signal
per CVE, is `references/windows-service-cve-matrix.md`. Three rules govern it:

1. **The NTLMSSP Version field gives major.minor.build, never the update
   revision (UBR).** `10.0.17763` says Server 2019 / Windows 10 1809; it cannot
   say whether last month's patch is installed. A Windows build therefore proves
   a release **family**, not a patch level. Only end-of-life families and
   bug-specific read-only checks give a real verdict.
2. **SQL Server is the exception.** The TDS pre-login reply carries the exact
   product build, so `ms-sql-info` gives a real version gate.
3. **A family match alone is "in range, unconfirmed".** It becomes High when it
   is paired with an exposure condition the attack needs (BlueKeep build plus NLA
   not enforced; SMBGhost build plus SMB 3.1.1), and Critical only with a read-only
   bug-specific check (MS17-010) or a signed-off Stage B check.

KEV entries that matter here (CISA KEV snapshot 2026.10.13):

| CVE | Service | KEV added | How you gate it |
|---|---|---|---|
| CVE-2017-0143 to -0148 (MS17-010, EternalBlue) | SMBv1 | 2021-11 to 2022-05 | `smb-vuln-ms17-010` (`vuln`, `safe`), needs SMBv1 plus anonymous or guest `IPC$` |
| CVE-2019-0708 (BlueKeep) | RDP | 2021-11-03 | Build 6.1.7601 / 6.0.6002 / 5.x via `rdp-ntlm-info`, plus NLA state |
| CVE-2020-0796 (SMBGhost) | SMB 3.1.1 | 2022-02-10 | Build 10.0.18362 or 18363 plus 3.1.1 in `smb-protocols`; no stock nmap script |
| CVE-2008-4250 (MS08-067) | Server service over SMB | 2026-05-20 | Build 5.x / 6.0 via SMBv1 `smb-os-discovery`. Never run the check script. |
| CVE-2025-33073 | SMB **client**, reflected relay | 2025-10-20 | Not testable here (coercion plus relay). Inbound signing not required on the exposed host is the precondition you can observe. |
| CVE-2020-1472 (Zerologon), CVE-2014-6324 (MS14-068) | Netlogon, KDC | 2021-11-03, 2022-03-25 | DC exposure only. No tester, no ticket. |
| CVE-2019-1068 | SQL Server, authenticated | 2026-08-26 | Post-auth: exact build from `ms-sql-info` as context, nothing more |

Not in KEV but pre-auth and recent: CVE-2026-69525 (Remote Desktop Services
use-after-free, CVSS 9.8, September 2026, every supported Windows build; MSRC does
not name the listener). Its fixed builds include a UBR you cannot see from outside,
so report "RDS exposed on an affected family, patch level not externally
verifiable" and let the client's patch data close it.

---

## Step 7: Grade by what you proved

| What you proved | Grade | CVSS 3.1 example |
|---|---|---|
| `smb-vuln-ms17-010` reports VULNERABLE on an internet-facing host | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 9.8 as the program-facing vector; NVD lists 8.8 for CVE-2017-0144 (`PR:L`). Quote the one the program uses. |
| `sa` with an empty password accepted (Stage B) | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 9.8 |
| Anonymous or guest read of a share holding business data, credentials or PII | High to Critical by data class | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` 7.5 |
| KEV family match plus the exposure condition (BlueKeep build with NLA off; SMBGhost build with 3.1.1; Windows 2000/XP/2003 on 445) | High, labelled unconfirmed | Quote the CVE's NVD vector (BlueKeep 9.8, SMBGhost 10.0, MS08-067 9.8) and grade below it, stating that no exploit was attempted and the patch level is unknown |
| A domain controller reachable from the internet (88 + 389 + 445 on one IP) | High as an exposure | No single CVSS vector fits. The justification is that the domain's root of trust exposes its whole pre-auth surface: KDC user oracle, CLDAP reflector, Netlogon, every future DC bug. |
| Null-session or guest **share listing** with nothing readable | Medium | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` 5.3 |
| SMBv1 offered on an internet-facing host, no CVE confirmed | Medium | Hardening; no vector |
| RDP exposed with NLA **not** enforced (`Native RDP` or `SSL: SUCCESS`) | Medium | Pre-auth logon surface; no vector without a CVE |
| Endpoint mapper and dynamic RPC reachable, listing MS-EFSR / MS-RPRN | Medium | Coercion surface described, never invoked |
| CLDAP answering anonymously: rootDSE naming contexts plus a 56-70x reflector | Medium | `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L` 5.8 for the reflector (others are the victims, hence `S:C`) |
| SQL Browser or NetBIOS answering as a UDP reflector | Low | Same vector; smaller factor |
| SMB signing not required on a **DC** | Medium | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` 4.8 |
| MSSQL exposed on an out-of-support build (SQL Server 2016 extended support ended 2026-07-14) | Medium | Version-in-range, unconfirmed |
| Host, domain and OS build disclosed via NTLMSSP, RDP certificate or `nbstat` | Low (one finding per host, however many services leak it) | Computes to 5.3 at `C:L`; programs usually triage it Low. State both rather than bending the vector. |
| RDP exposed, NLA enforced, supported OS; MSSQL exposed on a supported build | Low, or Informational where the program says so | None |

CLDAP at Medium matches `hunt-exposed-services`' Medium for an anonymous LDAP
rootDSE over TCP: same data, plus the reflector. The DC row goes higher only
because several pre-auth services of the domain controller are reachable at
once; say so in the report.

### What is not a finding

- An anonymous SMB session that is set up but can read nothing. Windows accepts
  anonymous logon; the `RestrictAnonymous` settings decide what it sees.
- `IPC$`, or `ADMIN$` and `C$` listed but access-denied. That is the default.
- "Message signing enabled but not required" on a **Windows Server 2025 member
  server**: Microsoft's 2025 default requires signing outbound only. Windows 11
  24H2 Enterprise, Pro and Education require it both ways; Home requires neither.
  On a member server it is a hardening note at most; on a DC it is a misconfiguration.
- A Windows build inside a CVE's family, with no exposure condition and no check.
- No output from an SMBv1-only nmap script, or from `smb2-vuln-uptime`.
- A self-signed RDP certificate. That is the Windows default; TLS concerns go to
  `hunt-tls-network`.
- SMB over QUIC on UDP 443 by itself. It is built for internet exposure with TLS
  1.3 and a certificate; record it and grade its configuration, not its presence.
- RD Gateway on 443 by itself. Designed to be exposed; cross-reference it.
- An AS-REP or ticket you obtained. Discard it; it is not report material here.

Program policy: many programs list "SMB signing not required", "RDP exposed
with NLA" and "version or banner disclosure" as out of scope or Informational.
Read the policy before filing. A KEV match with version proof and an exposure
condition is the case programs pay for.

---

## Step 8: Capture evidence once

Follow `evidence-hygiene` and `hunt-exposed-services` Step 7. Windows specifics:

- The exact nmap command line including `--script-args`, so a reviewer can see
  `smbnoguest` and `mssql.scanned-ports-only` were set.
- The NTLMSSP block and the RDP certificate subject verbatim. Redact nothing
  that proves the domain leak, but do not add internal names you did not observe.
- For share findings: share names, top-level file names and counts. Never the
  files. If a Stage B sample was taken, one file, redacted, deleted after filing.
- For a DC exposure: the full port list on that IP with timestamps, plus the CLDAP reply.

---

## Chain table

| Exposure confirmed | Realistic standalone severity | Where it goes next |
|---|---|---|
| MS17-010 VULNERABLE from the read-only check | Critical | Report. No exploit, no DoublePulsar probe beyond `smb-double-pulsar-backdoor`. A positive DoublePulsar result means the host is already compromised: stop and escalate via `mid-engagement-ir-detection`. |
| Anonymous or guest read of a data share | High to Critical | Report with names and counts. No spidering. |
| DC reachable from the internet | High | Report the port set and CLDAP reply. Realm and UPN format go to `m365-entra-attack` only if that skill's own scope allows it. |
| BlueKeep or SMBGhost family match plus exposure condition | High, unconfirmed | Stage B check only with sign-off naming "host may crash". |
| RDP without NLA | Medium | Report. Do not open a session. |
| Endpoint mapper lists MS-EFSR / MS-RPRN | Medium | Report as coercion surface. Never call them. |
| MSSQL exposed | Low to Medium by build | `sa` attempt is Stage B and single. Anything further belongs to `hunt-brute-force` rules. |
| NTLMSSP / certificate / CLDAP name leak | Low | Feeds `hunt-ntlm-info`'s grading and `offensive-osint`; one finding per host. |
| SMB signing not required | Low to Medium (DC) | Report with Microsoft's 2025 defaults as the remediation reference. Relay is out of bundle. |

---

## Validation checklist

- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Every IP confirmed client-owned (ASN, WHOIS/RDAP) and in the signed scope.
- [ ] NTLMSSP, certificate, CLDAP and NetBIOS names agree, or the disagreement is explained.
- [ ] No honeypot signals: no MS17-010 VULNERABLE on a 10.0.17763+ build, no
      identical names across unrelated IPs.
- [ ] Every SMB nmap run carried `smbnoguest`; the only guest attempt was one
      explicit `smbclient -U 'guest%'` per host.
- [ ] No command ran without an explicit username (`-U '%'` or `-U 'guest%'`).
- [ ] No `-sC`, no `-A`, no category globs. Each NSE script named and checked with `--script-help`.
- [ ] No share-enumeration tool that writes (smb-enum-shares, smbmap without
      `--no-write-check`, NetExec) was run.
- [ ] Each UDP reflector got one unspoofed packet.
- [ ] The dynamic RPC range was not swept.
- [ ] Every Stage B action has a logged written sign-off naming host, action and blast radius.
- [ ] No AS-REP, hash or ticket was kept.
- [ ] Version-in-range findings say "unconfirmed" and name the missing UBR.
- [ ] Name leaks deduplicated to one finding per host.
- [ ] The report ends at exposure plus impact. No internal follow-up written.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/enumeration-commands.md` | Stage A and gated Stage B commands per service: SMB/NetBIOS, MSRPC, RDP (NLA and certificate script), Kerberos, CLDAP, MSSQL; expected output and how to read it | null session, smbclient anonymous, smb signing not required, smbv1 enabled, rpcdump endpoint mapper, rdp nla check, rdp certificate cn, cldap ping, ldap rootdse udp, kdc reachable, ms-sql-info, sql browser 1434, nbstat |
| `references/windows-service-cve-matrix.md` | KEV and recent pre-auth CVEs for SMB, RDP, MSRPC, Kerberos, MSSQL, Samba, with the observable gate, NTLMSSP build-to-OS table, RD Gateway and KDC Proxy cross-reference rows | eternalblue, ms17-010, bluekeep, smbghost, ms08-067, cve-2026-69525, rd gateway cve, kdc proxy, zerologon, sambacry, windows build number |

External sources this skill was checked against (2026-10-13):

- CISA KEV catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA TA14-017A, UDP-based amplification: <https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks>
- Microsoft, SMB signing defaults: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing>
- Microsoft, SMB authentication rate limiter: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-authentication-rate-limiter>
- MSRC Update Guide (FAQs for each CVE row): <https://msrc.microsoft.com/update-guide>
- NVD: <https://nvd.nist.gov/>
- nmap NSE documentation: <https://nmap.org/nsedoc/>
- Metasploit BlueKeep scanner source: <https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/rdp/cve_2019_0708_bluekeep.rb>
- NetExec SMB protocol source: <https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/smb.py>
- kerbrute (pre-auth enumeration behaviour): <https://github.com/ropnop/kerbrute>
- NETSCOUT DDoS attack vectors (SQL Server Resolution amplification): <https://www.netscout.com/ddos-attack-vectors/>

---

## Related Skills & Chains

- `hunt-exposed-services`: the parent pattern. Owns LDAP over TCP and WinRM/OMI,
  and its Steps 1, 2 and 5 are inherited here unchanged.
- `hunt-ntlm-info`: NTLM Type-2 disclosure over HTTP and its severity tiers. The
  SMB, RDP and MSSQL NTLMSSP leak found here is graded by the same logic.
- `hunt-ldap`: LDAP injection in an application. Not directory access.
- `enterprise-vpn-attack`, `hunt-exposed-panels`: RD Gateway, RD Web Access and
  other remote-access front ends on 443.
- `infra-external-methodology`: the external infrastructure test plan that
  routes Windows ports here.
- `infra-dns`: Windows DNS Server exposure.
- `hunt-brute-force`: every credential attempt. This skill makes one gated `sa`
  attempt and nothing else.
- `hunt-tls-network`: TLS findings on 3389, 1433 and 636.
- `mid-engagement-ir-detection`: what to do when a check shows the host is already compromised.
- `evidence-hygiene`, `triage-validation`, `report-writing`: evidence, gates, write-up.

---
name: infra-ftp
description: "Triage an internet-exposed FTP service: plain FTP on 21, explicit FTPS via AUTH TLS, implicit FTPS on 990, and FTP on NAS boxes and MFT products. Anonymous login and what it reads, writable directories, sensitive files in listings, cleartext credentials, TLS offered but not required, PASV internal-address leaks, FTP bounce, honeypot tells, version gates for vsftpd, ProFTPD, Pure-FTPd, Serv-U, CrushFTP, Wing FTP. Stage A is banner, FEAT, one anonymous login and a bounded listing; writes and credential guesses are Stage B. Use when port 21 or 990 is open or Shodan says anonymous FTP allowed."
metadata:
  sources: rfc, nvd, cisa_kev, vendor_advisories, nmap_nsedoc, project_documentation, academic_research, bugcrowd_public_disclosure
  report_count: 0
---

## When to use

Trigger when recon has produced an FTP listener on an authorized host and you
must decide whether it is a finding. The finding is **the exposure plus what it
leaks or grants**: anonymous read or write, sensitive files in a listing,
credentials in cleartext, a version in a known-exploited range. Typical cues:
port 21 or 990 answering `220`; FEAT advertising `AUTH TLS`; a Shodan/Censys
record showing `230` for `anonymous`; a hostname (`ftp.`, `files.`, `mft.`) or
banner naming an FTP daemon, NAS, camera recorder or managed-file-transfer
(MFT) product. Discovery belongs to `offensive-osint` and `web2-recon`, scope
to `recon-scope-triage`.

### Where the chain ends

Stop at **unauthenticated or default-credential access confirmed, impact
described, evidence captured**. Nothing here uploads a working payload, plants a
webshell through an FTP-writable web root, mirrors a directory tree, uses
credentials found in a file, or turns the server into a relay. If the listing
already shows the impact, you have the finding. Write it up and stop.

### Not covered here, on purpose

| Thing | Owner |
|---|---|
| SFTP (port 22 or a custom port). It is SSH, not FTP. | `infra-ssh` |
| TFTP 69/udp, rsync 873, NFS, SVN | `hunt-exposed-services` (`references/printers-and-storage.md`) |
| `ftp://` URLs reached through an application's fetcher | `hunt-ssrf`, `hunt-lfi` |
| HTTP admin and web-client planes of MFT products (CrushFTP, Wing FTP, Serv-U, WS_FTP) beyond a version read | `hunt-exposed-panels` |
| Certificate and protocol-version weaknesses on FTPS | `hunt-tls-network` |
| Credential guessing of any kind | `hunt-brute-force` |

`hunt-exposed-services` lists FTP as not covered; this skill owns it.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/ftp-server-cve-matrix.md` | Affected and fixed versions, KEV dates and version-only detection for vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, IIS FTP, Serv-U, WS_FTP, CrushFTP, Wing FTP, Cerberus, Titan; FTP bounce | proftpd mod_copy, vsftpd backdoor, crushftp kev, wing ftp lua injection, serv-u path traversal, ws_ftp ad hoc transfer, ftp server cve |

---

## Step 1 — Inputs, ownership and rate posture

Hosts come from the signed scope, ports from recon. Confirm each IP is the
client's (ASN, RDAP, reverse DNS) first; one shared-hosting IP can serve
hundreds of customers' FTP sites. **Rate posture:** FTP daemons cap connections per IP (vsftpd `max_per_ip`, ProFTPD
`MaxClientsPerHost`, Pure-FTPd `-C`), and fail2ban ships vsftpd, ProFTPD and
Pure-FTPd jails that ban after a handful of failed logins. So: one control
connection per host, serial across hosts, 2 s plus 0-3 s jitter between
sessions. At most **one** anonymous login attempt per host; once it succeeds,
later sessions with it are reads, capped at five per host. A timeout is a
result; retry once at most.

```bash
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

---

## Step 2 — Prove the exposure is real, external and the client's

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside any client VPN or office range; log the egress IP. | Exposed means exposed. |
| IP ownership | ASN, RDAP, reverse DNS; cross-check scope. | Shared FTP hosting answers for many tenants. |
| Real daemon, not a middlebox | A firewall or load balancer with an FTP proxy can send its own `220`. FEAT, SYST and HELP from a proxy look generic and identical across hosts. | You report the client's server, not their firewall's proxy greeting. |
| Honeypot | See the list below. | A honeypot listing is bait, not data. |

Honeypot tells specific to FTP:

- A `vsFTPd 2.3.4` banner (the backdoored tarball, CVE-2011-2523, was online
  only 2011-06-30 to 2011-07-03) or a `ProFTPD 1.3.3c` banner (source trojaned
  in 2010). Outside labs and honeypots these are almost nonexistent.
- A bait root: `passwords.txt`, `wallet.dat`, a few-KB `backup.sql`, every file
  with one timestamp; or the same listing on unrelated IPs.
- A host exposing a dozen unrelated services with identical uptime (T-Pot style
  stacks with Dionaea or OpenCanary FTP modules), or greeting, FEAT and error
  strings that disagree about the daemon.

If one of the two backdoor banners is on a real production host, it may be
someone else's compromise. Trigger nothing; raise it with the operator.

---

## Step 3 — Stage A: fingerprint without logging in

**Stage A rules.** Read only. The only commands sent are the greeting read,
`FEAT`, `SYST`, `HELP`, `AUTH TLS`, one anonymous `USER`/`PASS`, `PWD`, `TYPE`,
`EPSV`/`PASV`, `LIST`/`NLST`/`MLSD`, `SIZE`, `MDTM` and `QUIT`. Never `STOR`,
`STOU`, `APPE`, `MKD`, `RMD`, `DELE`, `RNFR`/`RNTO`, `SITE` subcommands that act
on files, `PORT`/`EPRT` to any address but your own, or `RETR` of real data.

```bash
TARGET="192.0.2.21"; PORT=21; mkdir -p evidence
# One connection, no login: greeting, FEAT, SYST, HELP, QUIT.
printf 'FEAT\r\nSYST\r\nHELP\r\nQUIT\r\n' \
  | timeout 20 nc -w 8 "$TARGET" "$PORT" | head -c 8192 \
  | tee "evidence/${TARGET}_${PORT}_preauth.raw"
```

Read the reply:

- **Greeting.** Record verbatim; banners are configurable, so the name is a
  hint. vsftpd prints `(vsFTPd x.y.z)`; Pure-FTPd a dashed multi-line welcome
  and IIS `Microsoft FTP Service`, both without a version.
- **FEAT.** `AUTH TLS`/`AUTH SSL` (explicit FTPS offered), `PBSZ`/`PROT`
  (data-channel protection), `CCC` (TLS can be dropped after login), `MLST
  ...perm*;` (MLSD available; its `perm` fact shows what you may write, Step 4).
  A `530` before login is normal.
- **SYST.** `UNIX Type: L8` is meaningless; `Windows_NT` hints at IIS.
- **HELP.** If the list shows `CPFR` and `CPTO`, ProFTPD's mod_copy is loaded.
  Note it for Step 6 and send nothing further about it.

### FTPS: offered, implicit, required?

```bash
# Explicit FTPS on 21: does AUTH TLS upgrade? Captures certificate and protocol.
timeout 20 openssl s_client -connect "$TARGET:21" -starttls ftp -servername "$TARGET" \
  </dev/null 2>&1 | sed -n '1,60p' | tee "evidence/${TARGET}_21_authtls.txt"
# Implicit FTPS on 990: TLS first, the 220 greeting arrives inside the tunnel.
timeout 20 openssl s_client -connect "$TARGET:990" -servername "$TARGET" \
  </dev/null 2>&1 | sed -n '1,60p' | tee "evidence/${TARGET}_990_implicit.txt"
```

Whether TLS is **required**, not just offered, is decided by the Step 4 login,
which goes out in cleartext first:

- Refused with a 5xx naming TLS, SSL or encryption (typically IIS `534`,
  vsftpd `530`, ProFTPD `550`; the wording matters, not the code): enforced. Repeat the same single
  attempt over TLS.
- Accepted with `230`: cleartext logins work. Expected for anonymous; a finding
  only with evidence that named accounts use the same path (no `AUTH` in FEAT,
  no 990, a customer-facing welcome, an MFT product whose users log in here).

A `331` after `USER` proves little: by daemon it means "send password", "user
rejected", "send virtual-host name" or "TLS required first". Never send `PASS`
for anything but the anonymous attempt. IIS FTP defaults both channel policies
to `SslRequire`, so an IIS site taking a cleartext login had its policy loosened.

---

## Step 4 — Stage A: one anonymous login and a bounded listing

Use **one** tool for the login: curl (preferred, keeps a transcript) or nmap's
`ftp-anon`. Running both, or adding `ftp-syst`, spends a second attempt.

```bash
# The one anonymous attempt. -v keeps the control-channel transcript.
# --disable-epsv forces PASV so the 227 reply (and any internal IP in it) shows;
# an EPSV 229 reply carries no address, and curl ignores the PASV IP by default.
ANON='anonymous:anonymous@example.com'   # use the RoE contact address if required
timeout 30 curl -sS -v --disable-epsv --max-time 25 --user "$ANON" "ftp://$TARGET/" 2>&1 \
  | tee "evidence/${TARGET}_21_anon_list.txt"
# Same attempt when cleartext was refused with a TLS-required reply:
#   curl -sS -v --ssl-reqd --user "$ANON" "ftp://$TARGET/"      (explicit)
#   curl -sS -v --user "$ANON" "ftps://$TARGET:990/"             (implicit)
# nmap instead of curl (never both, never -sC):
#   nmap -Pn -p21 --script ftp-anon --script-args ftp-anon.maxlist=50 "$TARGET"
```

Read the outcome:

| Reply | Meaning |
|---|---|
| `230` then a listing | Anonymous read confirmed. Continue below. |
| `230` then `550` or an empty listing | Anonymous login works but lands in an empty or unreadable root. Informational. |
| `530` after `PASS` | Anonymous disabled. Stop: no second username. |
| 5xx naming TLS after `USER` | Not yet attempted; repeat once over TLS. |
| `421` | Connection cap or ban. Stop, wait, note it. |

### Server-reported write access, without writing

When FEAT advertises MLST, list with MLSD. RFC 3659's `perm` fact reports the
**current user's** rights per object: `c` create files in a directory, `m` make
subdirectories, `w` overwrite a file, `a` append, `d` delete, `f` rename, `r`
read, `l` list, `e` enter.

```bash
timeout 30 curl -sS --max-time 25 --user "$ANON" -X MLSD "ftp://$TARGET/" \
  | tee "evidence/${TARGET}_21_anon_mlsd.txt"
```

Signals by strength, reported as **server-reported writable, not proven by
write**: (1) MLSD `perm=` with `c`, `m`, `w` or `a`; (2) a LIST mode string
with the others-write bit (`drwxrwxrwx`, `drwx-wx-wx`), which is all nmap's
`[NSE: writeable]` checks; (3) an `incoming` or `upload` directory you can
enter but not list (write-only drop box). Windows daemons often list without
mode bits; then only MLSD can tell, and "unknown" is an honest answer.

### Bounded listing

Root plus one level, only into directories the root listing named, serial with
jitter. Never recurse, never mirror (`wget -m`, `lftp mirror`).

```bash
for d in pub incoming backup; do        # replace with names the root listing showed
  timeout 30 curl -sS --max-time 25 --user "$ANON" -X MLSD "ftp://$TARGET/$d/" \
    | head -300 | tee -a "evidence/${TARGET}_21_anon_level2.txt"
  probe_delay
done
```

Judge by names, sizes and dates, never contents: dumps (`.sql`, `.bak`,
`.dump`), dated archives under `backup`, VM disks (`.vmdk`, `.vhdx`), `.pst`,
key material (`id_rsa`, `.pem`, `.pfx`, `.kdbx`), app config (`.env`,
`web.config`, `wp-config.php`, `.htpasswd`), device configs (`.cfg`), HR or
customer exports (`.csv`, `.xlsx`), and date trees of camera `.jpg`/`.mp4`.

### Is the FTP root served by a web server?

Correlate without writing or downloading: pick a non-sensitive file the FTP
listing already shows (`index.html`, `robots.txt`, never a dump) and send a HEAD
request. `Content-Length` and `Last-Modified` matching the MLSD `size` and
`modify` facts means the FTP root is web-served.

```bash
curl -sSI "https://$TARGET/index.html" | grep -iE '^(HTTP|content-length|last-modified)'
```

**PASV leak.** Read the `227 Entering Passive Mode (a,b,c,d,p1,p2)` line in the `-v`
transcript. An RFC 1918 address there is the server's internal address, behind
NAT. Report it as a Low information leak; never connect to it.

---

## Step 5 — nmap scripts: what each one actually sends

Check any NSE script with `nmap --script-help <name>` before use. The FTP set,
categories as declared by the scripts:

| Script | Categories | What it really does |
|---|---|---|
| `ftp-anon` | `default`, `auth`, `safe` | Logs in as `anonymous` / `IEUser@`, sends `LIST`, flags `[NSE: writeable]` from the others-write bit only. This is your one attempt. |
| `ftp-syst` | `default`, `discovery`, `safe` | Sends `SYST` and `STAT`. If `SYST` is refused before login, it logs in anonymously itself: a second attempt. |
| `ftp-bounce` | `default`, `safe` | Despite `safe`: logs in anonymously and sends `PORT` pointing at `scanme.nmap.org` (ports 20560 and 80). Traffic to a third party. Never Stage A. |
| `ftp-brute` | `intrusive`, `brute` | Credential guessing. `hunt-brute-force` territory. |
| `ftp-vsftpd-backdoor` | `exploit`, `intrusive`, `malware`, `vuln` | Triggers the 2.3.4 backdoor and runs `id` through a shell on port 6200. |
| `ftp-proftpd-backdoor` | `exploit`, `intrusive`, `malware`, `vuln` | Triggers the 1.3.3c backdoor and runs `id`. |
| `ftp-vuln-cve2010-4221` | `intrusive`, `vuln` | Sends the ProFTPD Telnet-IAC stack overflow (1.3.2rc3 to 1.3.3b). |
| `ftp-libopie` | `vuln`, `intrusive` | CVE-2010-1938 probe; the script's own help says it crashes a vulnerable FTPd. |

**Therefore `-sC` and `-A` against port 21 are not Stage A.** They run
`ftp-anon`, `ftp-syst` and `ftp-bounce` together: up to two anonymous logins
and a bounce aimed at a host nobody authorized you to touch.

---

## Step 6 — Version gates

A version in a CVE range is a lead, not a finding. Distros backport fixes
without changing the banner (Debian's ProFTPD 1.3.5 packages took the mod_copy
fix under the same upstream version), and banners are configurable. Report
version-only matches as **unconfirmed**. Affected and fixed versions, KEV dates
and where each product shows its version: `references/ftp-server-cve-matrix.md`.
For the MFT products the version is usually on the HTTP side; read it there
(`hunt-exposed-panels`) and send nothing more.

Known-exploited (CISA KEV) issues to check the version against: ProFTPD
mod_copy CVE-2015-3306 (added 2026-10-08); Serv-U CVE-2021-35211,
CVE-2021-35247, CVE-2024-28995, CVE-2026-28318; WS_FTP CVE-2023-40044;
CrushFTP CVE-2024-4040, CVE-2025-31161, CVE-2025-54309; Wing FTP
CVE-2025-47812, CVE-2025-47813. vsftpd, Pure-FTPd, FileZilla Server, IIS FTP,
Cerberus and Titan have no KEV entry.

**Wing FTP below 7.4.4 with anonymous login enabled** is the strongest version
lead here: NVD states CVE-2025-47812 is exploitable through anonymous accounts
and runs commands as root or SYSTEM by default. Report it as High,
unconfirmed, flagged urgent with the KEV date, and stay at detection.

---

## Step 7 — Appliances, cameras and NAS

Embedded listeners are where anonymous and default-credential access still
turns up in volume. Same rules; different content and stakes.

- **NAS and routers with USB storage.** FTP exposes the shared folders: backup
  sets, scans, camera recordings. Guest access is usually one UI toggle.
- **Camera and NVR uploads.** Cameras are usually FTP *clients* pushing clips
  to a server; that receiving server is the exposure, often anonymous and
  writable, and its image trees are personal data. Count; never open or keep.
- **Printers and MFPs.** On some families a `STOR` is a print job on real
  paper. Listing only; printer rules in `hunt-exposed-services`.
- **PLCs, RTUs, building controllers.** FTP is a firmware and config path.
  Detection only, one session, industrial rules in `hunt-exposed-services`.
- **Default credentials.** Only the value in the vendor's manual for the exact
  model, one attempt, under Stage B (B3). Never a list.

---

## Step 8 — Stage B: anything that writes, relays, guesses or exploits

Stage B is **blocked by default**. It needs explicit written sign-off naming the
action, the host and a window. Verbal approval, a chat reaction, or "critical
findings are in scope" is not sign-off. Log this before the first Stage B byte:

```
Stage B authorization
  Host/port:        192.0.2.21:21
  Action:           <one action from B1-B6 below>
  Blast radius:     <what changes on the server, and who could notice or be hurt>
  Reversibility:    <how it is undone, and how you will verify the undo>
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

Stage A evidence (MLSD `perm`, listing, HTTP correlation) usually makes it
unnecessary. Ask that first.

### B1. Write proof with an inert canary

**Stage B, written sign-off required.** Blast radius: a file appears on the
server; antivirus, file-integrity monitoring or a sync job may react; in a
web-served directory it is publicly reachable until removed. One file, inert
text, a `.txt` name unique to the engagement, deleted immediately, deletion
verified by listing. Never a script, archive, HTML or any executable extension.
Check the directory's MLSD `perm` for `d` or `p` first: drop boxes often refuse
anonymous `DELE`, and then the sign-off must record that the client removes it.

```bash
# Stage B only, after sign-off. Upload one inert canary, then delete it.
CANARY="canary-ENGAGEMENT_ID.txt"   # unique per engagement, never a script extension
printf 'authorized security test, engagement ENGAGEMENT_ID, contact CONTACT\n' > "$CANARY"
curl -sS -v --user "$ANON" -T "$CANARY" "ftp://$TARGET/incoming/"
curl -sS -v --user "$ANON" -Q "DELE incoming/$CANARY" "ftp://$TARGET/"
curl -sS --user "$ANON" -X MLSD "ftp://$TARGET/incoming/"   # confirm it is gone
```

If the directory is web-served, one HTTP GET of the canary between upload and
delete proves the chain. That is as far as it goes; see B6.

### B2. Reading file content

**Stage B, written sign-off required.** Names, sizes and dates normally prove
the data class. If triage insists on content, read the first bytes of one file,
redact them in evidence, and delete the local copy per `evidence-hygiene`.
Never a file that is likely to hold PII when a config or dump header proves the
same point, and never a camera image.

```bash
# Stage B only, after sign-off: first 512 bytes of one file.
curl -sS --user "$ANON" -r 0-511 "ftp://$TARGET/backup/<one-file>" | head -c 512
```

### B3. One documented default credential

**Stage B, written sign-off required.** Blast radius: a failed attempt counts
toward fail2ban and account lockout; a successful one is a login to a real
account. One pair, from the vendor's manual for that model, cited in the
evidence. Anything more is guessing and belongs to `hunt-brute-force`.

### B4. FTP bounce (PORT to another host)

**Stage B, written sign-off required.** Mostly historical (CVE-1999-0017);
modern daemons refuse a foreign `PORT` by default (ProFTPD `AllowForeignAddress
off`, vsftpd `port_promiscuous=NO`). Target only a listener on a public host
**you own**: never a third party, never an internal or RFC 1918 address
(bouncing inward is internal port scanning, which this bundle excludes).

```bash
# Stage B only, after sign-off. checkhost is YOUR listener, never the default.
nmap -Pn -p21 --script ftp-bounce \
  --script-args ftp-bounce.checkhost=<your-public-listener> "$TARGET"
```

A `200` to `PORT` plus a connection arriving at your listener proves it. Grade
Medium at most, and only on servers where it reproduces.

### B5. Confirming a version CVE

**Stage B, written sign-off required, and usually not worth it.** KEV-listed
pre-auth issues (Wing FTP, CrushFTP, Serv-U, WS_FTP, ProFTPD mod_copy) are
reported at the version level with the KEV date; the client's fix is the same
either way. Never run the vsftpd 2.3.4 or ProFTPD 1.3.3c backdoor triggers or
the nmap scripts that send them. Never send a DoS-class trigger (CVE-2026-28318,
CVE-2025-14242, CVE-2024-57392) under any sign-off.

### B6. The FTP-writable web root

**Stage B, written sign-off required; the chain is described, not built.**
Anonymous write into a web-served directory lets anyone publish under the
client's domain, and run code if uploaded scripts execute. Prove the halves
separately: write (Stage A `perm` fact, or B1) and web-serving (Stage A
size/date match, or B1's GET). Never upload a script, `.htaccess`, HTML or SVG.
If a program rejects the described chain, hand over to `hunt-file-upload`.

---

## Step 9 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Anonymous write to a directory that a web server serves, on a production host | Critical |
| Anonymous read of backups, database dumps, key material, or config with credentials | High (Critical if the data class is production secrets or bulk PII) |
| Anonymous read of camera recordings, scanned documents or HR/customer exports | High (privacy) |
| Version in a KEV range with pre-auth impact and a matching precondition (Wing FTP <7.4.4 plus anonymous) | High, unconfirmed; flag urgent with the KEV date |
| Anonymous write, not web-served (storage abuse, malware staging) | Medium to High |
| Documented default credential accepted (B3) | High or Critical, by what the account reaches |
| Named-account logins accepted in cleartext; TLS absent or optional | Low to Medium |
| Version in a CVE range, no KEV, not confirmed | Medium or Low, labelled unconfirmed |
| FTP bounce to your own listener reproduced (B4) | Medium at most |
| PASV reply leaks an internal address | Low |
| Anonymous read of an intended public mirror, vendor downloads, or an empty root | Informational |

Writable means server-reported writable unless B1 ran; say which.

### What is not a finding

- Port 21 open, authentication enforced, no version issue.
- Anonymous access to content meant to be public (OS mirrors, vendor
  downloads). A public VDP disclosure of anonymous FTP with files was triaged
  P5, "accepted business risk".
- "FTP is cleartext" with no evidence named accounts use it; a version banner
  alone; `[NSE: writeable]` alone; a self-signed FTPS certificate alone
  (`hunt-tls-network`); anything on a honeypot.

---

## Evidence

Per `evidence-hygiene`: pre-auth and curl `-v` transcripts, MLSD/LIST output,
exact commands with egress IP and timestamps, counts (files, total size, newest
date). Never the dataset. For personal data, a note that nothing was opened or
kept. For Stage B, the authorization block and proof the canary is gone.

---

## Chain table

| Exposure confirmed | Standalone severity | Where it goes next |
|---|---|---|
| Anonymous read of a web root with `.env`, `.git/`, `config.php` | High | `hunt-source-leak` for what the leaked source means; use no credential you find. |
| Anonymous write plus web-served directory | Critical | Report. Execution proof is `hunt-file-upload` Stage B, normally unnecessary. |
| Cloud keys or tokens visible in a listing name or B2 read | High to Critical | Report and stop. Key triage belongs to `cloud-iam-deep`, only with the client's say-so. |
| Wing FTP, CrushFTP, Serv-U or WS_FTP version in a KEV range | High, unconfirmed; urgent | Version read via `hunt-exposed-panels`; no exploit. |
| SFTP on the same host | Per `infra-ssh` | Separate service, separate skill. |
| TFTP or rsync on the same host | Per `hunt-exposed-services` | Same exposure class, different reference. |
| Weak FTPS protocol, cipher or certificate | Per `hunt-tls-network` | Separate finding. |
| Internal address leaked in PASV | Low | Note for `infra-external-methodology` mapping; never connect to it. |

---

## Validation checklist

- [ ] Probed from outside every client network; egress IP in evidence.
- [ ] IP client-owned and in signed scope; on shared hosting, the FTP site too.
- [ ] Honeypot ruled out (no 2.3.4/1.3.3c tell, no bait, consistent fingerprint).
- [ ] The `220` came from the daemon, not a firewall's FTP proxy.
- [ ] One anonymous login attempt per host; no other username outside a signed B3.
- [ ] No `-sC`/`-A`; every NSE script named and checked with `--script-help`.
- [ ] `ftp-bounce` not run, or run under B4 with `checkhost` set to your host.
- [ ] Listing bounded to root plus one level; nothing mirrored or recursed.
- [ ] No file content read outside a signed B2; no camera image opened.
- [ ] Writability labelled "server-reported" unless a signed B1 canary ran,
      and the canary's deletion was verified.
- [ ] Web-served claim backed by a size and date match on an existing file.
- [ ] Version-only matches labelled unconfirmed; distro backports considered.
- [ ] Cleartext finding backed by evidence that named accounts use it.
- [ ] The report ends at exposure plus impact.

---

## Sources

External sources:

- RFC 959, 1635 (anonymous FTP), 2228, 2577 (bounce), 3659 (MLSD `perm`), 4217
  (FTP over TLS): <https://www.rfc-editor.org/>
- nmap NSE docs: <https://nmap.org/nsedoc/scripts/ftp-anon.html>,
  <https://nmap.org/nsedoc/scripts/ftp-bounce.html>, <https://nmap.org/nsedoc/scripts/ftp-syst.html>
- OpenSSL `s_client -starttls ftp`: <https://docs.openssl.org/3.0/man1/openssl-s_client/>
- IIS FTP SSL policy: <https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/ftpserver/security/ssl>
- CISA KEV (feed 2026.10.13): <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- Springall, Durumeric, Halderman, "FTP: The Forgotten Cloud" (13.8 M servers,
  1.1 M anonymous, 20 K+ anonymous-writable, 140 K+ accepting foreign PORT):
  <https://zakird.com/papers/dsn-ftp.pdf>
- Public VDP disclosure, anonymous FTP with files, triaged P5:
  <https://bugcrowd.com/disclosures/02d81670-37a0-42bd-8308-afc26de013e5/anonymous-ftp-access-to-sensitive-files>

---

## Related Skills & Chains

- `infra-external-methodology` — the external workflow that routes 21/990 here.
- `infra-ssh` — SFTP and SCP: same files, different protocol, different skill.
- `hunt-exposed-services` — TFTP, rsync, NFS, and the industrial and printer
  rules that also bind FTP on those devices.
- `hunt-file-upload` — the execution half of an FTP-writable web root (Stage B).
- `hunt-source-leak` — what a `.git/`, `.env` or source tree in the root means.
- `hunt-exposed-panels` — version reads on CrushFTP, Wing FTP, Serv-U, WS_FTP.
- `hunt-tls-network` (FTPS), `hunt-brute-force` (all credential guessing).
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence,
  false-positive gates, write-up.

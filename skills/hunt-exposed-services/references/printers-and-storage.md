# Printers, file shares and network storage

Two different fragility problems live in this file.

**Printers consume paper and physical state.** Port 9100 is a raw print channel:
whatever bytes arrive are a print job unless they happen to be a recognised
language command. A probe that guesses wrong prints pages, and on a device with
a panel it can leave a message on the display for the next person who walks
past. Query subcommands only.

**Storage services carry data and filesystem state.** A mount, even a read-only
one, can replay a journal and write to the volume. Listing is a finding;
mounting is not a test, it is use.

## Port map

| Port | Service | Read-only identification | Never |
|---|---|---|---|
| 631/tcp, 631/udp | IPP and CUPS; `cups-browsed` on UDP | `GET /` and `GET /printers` on the CUPS web interface; an IPP `Get-Printer-Attributes` operation. | Submitting a job, adding or modifying a printer, or sending anything to the `cups-browsed` UDP listener, which is a job-creation path. |
| 9100-9107/tcp (IANA: `hp-pdl-datastr` / `pdl-datastream`, "Printer PDL Data Stream") | Raw print (JetDirect), PJL, PostScript. Microsoft's standard TCP/IP port monitor defaults to TCP 9100 in RAW mode, meaning the job bytes go straight down the socket with no wrapper. | The `@PJL INFO` status-readback categories, verbatim from HP's PJL Technical Reference: **ID, CONFIG, FILESYS, MEMORY, PAGECOUNT, STATUS, VARIABLES, USTATUS**. One category per command; an unsupported category returns an empty response. | `@PJL RDYMSG DISPLAY=` (changes the physical display), `@PJL DEFAULT` and `@PJL SET` (change settings), `@PJL FSDOWNLOAD` / `@PJL FSDELETE` / `@PJL FSUPLOAD` (filesystem write and read on the device), `@PJL JOB`, and any raw PostScript or PCL payload. |
| 515/tcp | LPD (RFC 1179) | A queue-state query (`lpq`-style, RFC 1179 command 03/04). | Submitting a job, removing jobs. |
| 69/udp | TFTP | No authentication exists in the protocol. A `get` of a filename you have a concrete reason to expect, one attempt. | Wordlist-driven filename enumeration, which is brute force on a UDP service with no rate limiting, and any `put`. nmap's `tftp-enum` is exactly this: it is categorised `intrusive`, requests every name in `tftplist.txt` plus 256 generated `A.B.C.X-confg` names, and reads file data. A writable TFTP root is a code-delivery path. |
| 873/tcp | rsync daemon | Module listing, then a module's top-level listing. | `--delete`, any upload, any recursive download of real data. |
| 111/tcp+udp, 2049/tcp | rpcbind, NFS | `rpcinfo -p` for registered programs; `showmount -e` for exported paths and their allowed clients. | Mounting the export. |
| 3260/tcp | iSCSI | `sendtargets` discovery, which returns target IQNs and portals. | Logging in to a target, and under all circumstances mounting a LUN. Other hosts may have it mounted; a second mounter corrupts the filesystem. |
| 24007, 24008, 49152+ | GlusterFS management, and brick ports | `peer status` and `volume info` against the management port. | Mounting a volume, creating or deleting a volume, touching `gluster_shared_storage`. |
| 3690/tcp | svnserve | `svn info` and `svn ls` over `svn://`, which prove anonymous read. | Checkout of the whole repository, commit, `svnadmin` operations. |
| 548/tcp | AFP (Apple Filing Protocol) | A server-info request returns the machine type, AFP versions, UAMs and sometimes the server's name and volumes. (The protocol's registered port is 548; you will see the number 584 in older notes, which is a transposition.) | Authenticating, mounting, browsing volumes. |

## nmap deliberately refuses to version-scan 9100-9107

Nmap ships an `Exclude T:9100-9107` directive at the top of
`nmap-service-probes`, so `-sV` skips version detection on those ports by
default. Nmap's own manual gives the reason: it skips 9100 "because some
printers simply print anything sent to that port, leading to dozens of pages of
HTTP GET requests, binary SSL session requests, etc." The `--allports` flag
means "don't exclude any ports from version detection" and overrides it.

**Never pass `--allports` against a printer.** If you want the model and
firmware, the `@PJL INFO` query below gives you both without consuming paper.
This is also the single best illustration of why this skill checks tool defaults
before loosening them: the default was put there by someone who had already
printed the dozens of pages.

Two limits on that protection. The exclusion is **TCP only** and it scopes to
**version detection only**: it does not stop NSE, so `--script` aimed at 9100
still runs. In particular `pjl-ready-message` is `intrusive`; with no script
argument it sends only `@PJL INFO STATUS`, which is a read, but once
`pjl_ready_message` is set it writes the printer's physical panel. Do not set it.

## Stage A probes

```bash
TARGET="192.0.2.20"

# ---- CUPS / IPP -------------------------------------------------------------
curl -s "http://$TARGET:631/" | head -c 600          # version in the page and in Server:
curl -s -i "http://$TARGET:631/printers/" | head -30 # anonymous queue listing = finding
# IPP attribute query without submitting a job:
ipptool -tv "ipp://$TARGET:631/ipp/print" get-printer-attributes.test 2>/dev/null | head -40

# ---- Raw PJL (9100): QUERY subcommands only --------------------------------
# The UEL (ESC%-12345X) frames the PJL block. Nothing here prints.
printf '\033%%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n@PJL INFO CONFIG\r\n\033%%-12345X' \
  | timeout 15 nc -w 10 "$TARGET" 9100 | head -60

# ---- TFTP: one targeted get, no wordlist -----------------------------------
timeout 10 tftp "$TARGET" -c get <filename-you-have-a-reason-to-expect> - 2>&1 | head -20

# ---- rsync: list modules, then one module's top level ----------------------
rsync --list-only --contimeout=10 "rsync://$TARGET/"
rsync --list-only --contimeout=10 "rsync://$TARGET/<module>/"

# ---- rpcbind / NFS: enumerate exports, do not mount ------------------------
rpcinfo -p "$TARGET"          # or nmap --script rpcinfo (safe)
showmount -e "$TARGET"        # export path + allowed client spec; "*" is the finding
# nmap equivalent: --script nfs-showmount (safe, EXPORT list only).
# NOT nfs-ls: despite its `safe` tag it mounts every export and writes the
# server's mount table (rmtab).

# ---- iSCSI: sendtargets discovery only -------------------------------------
iscsiadm --mode discoverydb --type sendtargets --portal "$TARGET" --discover
# Short form of the same thing (`st` abbreviates sendtargets; port defaults 3260):
#   iscsiadm -m discovery -t st -p "$TARGET"
# Stop here. Do NOT add `-l`/`--login`: in discovery mode that logs in to EVERY
# discovered target. Do NOT mount.
#
# Do NOT use nmap's `iscsi-info` either. Despite being tagged `safe` AND
# `default`, it calls login() on each discovered target, creating sessions on
# live storage. This is the single clearest reason `-sC` and `-A` are banned.

# ---- GlusterFS management port ---------------------------------------------
gluster --remote-host="$TARGET" peer status
gluster --remote-host="$TARGET" volume info

# ---- svnserve: anonymous read check ----------------------------------------
svn info "svn://$TARGET/" --non-interactive
svn ls   "svn://$TARGET/<repo>" --non-interactive
```

## What proves the finding

| Service | Proof of unauthenticated access |
|---|---|
| CUPS / IPP | `/printers/` or `Get-Printer-Attributes` answers with queue names and printer state, with no credential. A CUPS admin interface reachable anonymously is a separate, higher finding. Printer firmware matters too: **CVE-2023-0856** is a stack buffer overflow in the IPP `sides` attribute parser on a long list of Canon office and laser MFPs with firmware Ver.11.04 and earlier, rated `AV:N/PR:N/UI:N` CVSS 9.8, so a reachable vulnerable Canon device is a pre-auth DoS-or-RCE finding by version alone. |
| PJL 9100 | `@PJL INFO ID` returns the model string. The port accepting raw data at all is the finding: anyone on the internet can print to this device, and PJL filesystem commands can read stored jobs. |
| LPD 515 | A queue-state reply naming jobs or users. |
| TFTP | A successful `get` of any file. A writable root is Critical, but prove it by the service's own error behaviour rather than by uploading. |
| rsync | A module list, and a top-level listing inside a module, with no `auth users` challenge. Record file names and counts; copy nothing. |
| NFS | `showmount -e` showing an export with a client spec of `*` or a public range. State whether the export is `rw`, which `showmount` does not tell you: do not mount to find out. Report it as "export reachable, write permission not tested". |
| iSCSI | `sendtargets` returning target IQNs without CHAP. This is Critical: the targets are raw block devices, usually VM disks or backup volumes. |
| GlusterFS | `volume info` returning volume names, brick paths and the `auth.allow` value. An `auth.allow` of `*` with a reachable management port is Critical. |
| svnserve | `svn ls` returning repository contents anonymously. Source code exposure; `hunt-source-leak` owns the follow-on triage of what the code reveals. |
| AFP | A server-info reply with machine type and AFP version. The version matters here: Netatalk has two confirmed **pre-authentication** remote-code-execution flaws reachable on 548. **CVE-2018-1160** (before 3.1.12) is an out-of-bounds write in `dsi_opensess.c` described as exploitable by a remote unauthenticated attacker. **CVE-2022-23121** (3.1.12 and earlier, fixed 3.1.13) is an error-handling flaw in AppleDouble `parse_entries` giving root code execution, and the ZDI advisory states authentication is not required. A third, **CVE-2022-45188**, needs a crafted `.appl` file already on the volume and user interaction, so it is not a pre-auth path. Detect by version; do not exploit. |

## `cups-browsed` on UDP 631: why the probe is Stage B

The 2024 CUPS chain is the reason this file forbids sending anything to the
`cups-browsed` UDP listener. **CVE-2024-47176** is the entry point:
`cups-browsed` binds port 631 on `INADDR_ANY` and, in the advisory's own terms,
allows anybody to send it UDP datagrams while "trusting any source". A single
crafted datagram naming an attacker-controlled IPP URL makes the target connect
outbound to that server, leaking its kernel and CUPS version in the `User-Agent`
header, and accept malicious printer attributes that inject a PPD directive.
The injected command then runs **as the `cups` (`lp`) user when a job is printed
to that fake printer**. The advisory records affected version 2.0.1 with no
patched version listed.

The rest of the chain, accurately:

| CVE | Component and range | Role in the chain |
|---|---|---|
| CVE-2024-47176 | `cups-browsed` <= 2.0.1 | The entry point. Anybody may send it UDP/631 datagrams, and it triggers a `Get-Printer-Attributes` request to an attacker URL. Pre-auth for the trigger. |
| CVE-2024-47076 | `libcupsfilters` <= 2.0.0 and 2.1b1 | `cfGetPrinterAttributes5` does not sanitise IPP attributes coming back from that server. Scored `AV:N/PR:N/UI:N`, but the chain still needs a print job. |
| CVE-2024-47175 | `libppd` <= 2.0.0 and 2.1b1 | `ppdCreatePPDFromIPP2` writes the unsanitised attributes into a PPD, which is where the Foomatic command lands. Same print-job precondition. |

**Do not cite CVE-2024-47177.** Its CVE record is in state **REJECTED**, as a
fully interdependent duplicate of the three above, and it carries no product or
version data. It appears in a great many write-ups anyway; citing a rejected
CVE in a client report is a credibility loss you do not need.

Also do not reach for **CVE-2024-35235** here: it is a `cupsd` <= 2.4.8
`Listen`-symlink issue scored `AV:L/PR:H`, i.e. a local root chain, not an
exposure finding.

Consequences for how you test:

- **Stage A** is establishing that a `cups-browsed` UDP listener exists and
  getting its version. Nothing is sent to it.
- **Sending the crafted datagram is Stage B**, even though it executes nothing
  by itself, because it **adds an attacker-controlled printer to the target's
  queue list**. That is persistent configuration state on the host, and it arms
  a code-execution path that fires the next time anyone prints. If the operator
  signs that off, the sign-off must include removing the planted queue, and you
  must verify the removal.
- Never send a print job to a queue you planted. That is the execution step.

## CVEs that are *not* the finding here

Resist padding a storage report with these. None of them is a pre-auth network
path, and citing them as one is the fastest way to get the whole report
discounted.

- **GlusterFS.** CVE-2018-1088 is a symlink/cron privilege escalation needing
  mount rights and the snapshot scheduler enabled; CVE-2022-48340 (11.0 only) is
  a use-after-free reproducible from a mounted volume; CVE-2023-26253 (11.0
  only) is a stack over-read that crashes the FUSE **client**. The real finding
  on an exposed Gluster is the reachable management port plus `auth.allow`.
- **Subversion.** CVE-2024-45720 is Windows-only command-line argument
  injection, not a service flaw. CVE-2024-46901 needs authenticated commit
  access through `mod_dav_svn`, and `svnserve` is not affected. The finding on
  an exposed `svnserve` is anonymous read access to source code.

## Data handling

These services are the ones most likely to hand you real data on the first
request. The rule is the same everywhere in this skill and matters most here:
**prove the data class, do not take the data.** File names, directory names,
counts and sizes. One redacted sample at most, and only if the data class is
genuinely ambiguous without it. If you have copied a customer dataset to prove a
finding, you have created a breach that you now own.

## Checklist

- [ ] Nothing was sent to port 9100 except a UEL-framed `@PJL INFO` block.
- [ ] No printer display message, setting, or stored file was changed.
- [ ] No print job submitted on 631, 9100 or 515, and nothing sent to the
      `cups-browsed` UDP listener.
- [ ] TFTP tested with at most one targeted filename; no wordlist, no upload.
- [ ] No NFS export, iSCSI LUN or Gluster volume mounted.
- [ ] iSCSI stopped at `sendtargets`; no node login.
- [ ] rsync and svn listings only; nothing downloaded or checked out.
- [ ] Impact evidenced by names, counts and sizes. No dataset copied.
- [ ] Write permission on an export described as untested rather than guessed.

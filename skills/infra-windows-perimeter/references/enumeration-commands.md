# Enumeration commands: SMB, NetBIOS, MSRPC, RDP, Kerberos, CLDAP, MSSQL

Every command here assumes the host passed Steps 1 and 2 of the skill: in
scope, client-owned, probed from an external vantage, honeypot ruled out. Stage
A blocks run as written. Stage B blocks carry their gate in the line above the
fence and need a logged written sign-off before the first packet.

Conventions used throughout:

```bash
T=192.0.2.10                     # one host at a time
mkdir -p evidence
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }
```

- Always give an explicit identity: `-U '%'` (anonymous) or `-U 'guest%'`
  (guest). Never leave `-U` out: Samba tools then send your local Unix username.
- Every nmap SMB, MSRPC or MSSQL run carries `--script-args smbnoguest` unless
  the step says otherwise, so the library does not add a guest logon per connection.
- `tee evidence/...` captures the raw output at probe time.

Script categories quoted below were read from each script's own `categories`
line. Re-check with `nmap --script-help <name>` on your installed version.

---

## SMB (445/tcp) and SMB over NetBIOS (139/tcp)

### Dialects, signing, system time (Stage A)

```bash
nmap -Pn -p 445 --script smb-protocols,smb2-security-mode,smb2-time \
  --script-args smbnoguest --max-retries 1 "$T" | tee "evidence/${T}_smb_proto.txt"
```

`smb-protocols` (`safe`, `discovery`) and `smb2-security-mode` (`safe`,
`discovery`, `default`) negotiate once per dialect and stop. Output shape:

```
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

How to read it:

- `NT LM 0.12 (SMBv1)` present: SMBv1 is offered. A Medium finding on its own
  on an internet-facing host, and the precondition for the MS17-010 check below.
- `3.1.1` present and the NTLMSSP build (next section) is 10.0.18362 or 18363:
  SMBGhost family match. See the CVE matrix.
- `Message signing enabled but not required`: grade by role. On a domain
  controller it is a misconfiguration. On a Windows Server 2025 member server it
  is Microsoft's default (outbound-only signing), so a hardening note at most.
  `Message signing enabled and required` is the good state.
- `smb2-time` (`discovery`, `safe`, `default`) prints the server's clock, and
  its boot time when the server reports a non-zero value.

For port 139 run the same command with `-p 139`. A host answering on 139 from
the internet also exposes NetBIOS session service; record it with the 445 result.

### Host identity from the NTLMSSP challenge (Stage A)

nmap's `smb-os-discovery` uses the SMBv1 library and returns nothing on an
SMB2-only host. This impacket script works on both. It performs one anonymous
session setup. Save it outside any directory that holds downloaded data, and run
it with the system Python that has impacket installed:

```python
# smb_identity.py: one anonymous SMB session setup; prints what the server discloses.
import sys
from impacket.smbconnection import SMBConnection, SessionError

host = sys.argv[1]
c = SMBConnection(host, host, sess_port=445, timeout=10)
try:
    c.login('', '')  # anonymous: no account, so no bad-password counter moves
    null = 'session set up (guest-mapped: %s)' % c.isGuestSession()
except SessionError as e:
    null = 'refused: %s' % e
# The fields below are parsed from the NTLM Type-2 challenge, which arrives
# before the Type-3 is sent, so they are populated even when login() fails.
d = c.getDialect()
print('dialect      :', hex(d) if isinstance(d, int) else d)
print('signing req. :', c.isSigningRequired())
print('anonymous    :', null)
print('NetBIOS name :', c.getServerName())
print('NetBIOS dom  :', c.getServerDomain())
print('DNS host     :', c.getServerDNSHostName())
print('DNS domain   :', c.getServerDNSDomainName())
print('OS build     :', c.getServerOS())
c.close()
```

```bash
/usr/bin/python3 -I smb_identity.py "$T" | tee "evidence/${T}_smb_identity.txt"
```

Dialect values: `0x311` = 3.1.1, `0x302` = 3.0.2, `0x300` = 3.0, `0x210` = 2.1,
`0x202` = 2.0.2, the string `NT LM 0.12` = SMBv1. `OS build` comes from the
NTLMSSP Version field: major, minor and build, **no update revision**. Map it with
the build table in `windows-service-cve-matrix.md`.

`anonymous: session set up` is **not** a finding by itself. Windows accepts
anonymous logon; what the anonymous token can read is decided by
`RestrictAnonymous`, `RestrictAnonymousSAM` and the null-session pipe and share
lists. The next two sections test exactly that.

### Null-session share listing (Stage A)

```bash
smbclient -L "//$T" -U '%' -N 2>&1 | tee "evidence/${T}_smb_shares_null.txt"
```

`smbclient -L` calls `srvsvc NetShareEnumAll` over `IPC$` and nothing else. It
connects to no share and writes nothing. Read it as:

| Output | Meaning |
|---|---|
| A share table (`Sharename  Type  Comment`) | Anonymous share enumeration allowed. Medium even if no share is readable. |
| `NT_STATUS_ACCESS_DENIED` after session setup | Anonymous logon accepted, enumeration refused. Default; not a finding. |
| `NT_STATUS_LOGON_FAILURE` / `NT_STATUS_ACCESS_DENIED` at session setup | Anonymous logon refused. Good. |
| `protocol negotiation failed: NT_STATUS_CONNECTION_RESET` or similar on an old host | Likely SMBv1-only. Retry once with `--option='client min protocol=NT1'`. |

Then the single guest attempt for this host:

```bash
probe_delay
smbclient -L "//$T" -U 'guest%' -N 2>&1 | tee "evidence/${T}_smb_shares_guest.txt"
```

Microsoft's SMB signing documentation notes that requiring signing disables
guest access, so a guest listing that works is most often a NAS, a Samba server
or an older or reconfigured Windows build.

### One top-level listing of a readable share (Stage A)

Only for a non-default share (not `IPC$`, `ADMIN$`, `C$`, `print$`, `NETLOGON`,
`SYSVOL`) that appeared in the listing. One `ls`, root of the share only:

```bash
smbclient "//$T/Public" -U '%' -N -c 'ls' 2>&1 | tee "evidence/${T}_share_Public_ls.txt"
```

Record file and directory names and the count. Do not `cd`, do not `recurse`, do
not `get`. If the names alone show the data class (`payroll_2026.xlsx`,
`backup.bak`, `passwords.kdbx`), that is the evidence. Pulling a file is Stage B
(skill Step 5), one file, redacted.

Write access is **not tested** in this skill. Every common tool that reports it
does so by writing: nmap `smb-enum-shares` writes `nmap-test-file`, smbmap
creates a directory unless `--no-write-check`, and NetExec v1.5.1 creates a
directory unless `--no-write-check`. Report write access as "not tested".

### Null-session RPC identity calls (Stage A)

One connection, four read-only calls, then stop:

```bash
rpcclient -U '' -N "$T" -c 'srvinfo;lsaquery;querydominfo;netshareenumall' 2>&1 \
  | tee "evidence/${T}_rpc_null.txt"
```

- `srvinfo`: server name, OS version, server type flags.
- `lsaquery`: domain name and domain SID. Identity disclosure of the same class
  as the CLDAP reply.
- `querydominfo`: SAMR domain info including `Total Users` and `Total Groups`.
  A number here proves anonymous SAMR access without listing anyone. **Stop at
  the count.** `enumdomusers`, `enumdomgroups`, `queryuser`, `lookupnames` and
  `lookupsids` loops are user enumeration and are out of this bundle.
- `netshareenumall`: the same share list as `smbclient -L`, via RPC.

`NT_STATUS_ACCESS_DENIED` on each call is the expected, correct state on modern
Windows.

### MS17-010 read-only check (Stage A, only when SMBv1 is offered)

```bash
nmap -Pn -p 445 --script smb-vuln-ms17-010 --script-args smbnoguest \
  --max-retries 1 "$T" | tee "evidence/${T}_ms17-010.txt"
```

`smb-vuln-ms17-010` (`vuln`, `safe`) connects to `IPC$`, runs one transaction on
FID 0 and reads the status code: `STATUS_INSUFF_SERVER_RESOURCES` means
unpatched. It needs SMBv1 and anonymous `IPC$`. If it prints nothing and the guest
listing above succeeded, rerun it once without `smbnoguest` (that is the guest
attempt the check needs); if both are refused, record "inconclusive", not "patched".

A `State: VULNERABLE` result is Critical. Run the DoublePulsar check once on that
host only:

```bash
nmap -Pn -p 445 --script smb-double-pulsar-backdoor --script-args smbnoguest "$T"
```

`smb-double-pulsar-backdoor` (`vuln`, `safe`, `malware`) pings the implant's
Trans2 channel. A positive result means the host is already compromised. Stop all
testing on it and escalate per `mid-engagement-ir-detection`.

### NetBIOS name service (137/udp, Stage A)

One unspoofed packet. NetBIOS is a 3.8x reflector per CISA TA14-017A.

```bash
nmap -Pn -sU -p 137 --script nbstat --max-retries 0 -v "$T" | tee "evidence/${T}_nbstat.txt"
```

Output: `NetBIOS name: X, NetBIOS user: <unknown>, NetBIOS MAC: ...`, and with
`-v` the full name table. Suffixes that matter: `<00>` workstation or domain
name, `<20>` file server service, `<1C>` domain controllers (group name), `<1B>`
domain master browser (the PDC emulator). A `<1C>` entry on a public address
is a domain controller.

138/udp (datagram service) has no useful read-only probe. Record it as open.

---

## MSRPC (135/tcp, 593/tcp, bound dynamic ports)

### Endpoint mapper dump (Stage A)

`rpcdump.py` (packaged as `impacket-rpcdump` on Debian and Kali) asks the
endpoint mapper on 135 for its registrations. Unauthenticated, read-only:

```bash
rpcdump.py -port 135 "$T" | tee "evidence/${T}_rpcdump.txt" \
  | grep -E '^Protocol|ncacn_ip_tcp|ncacn_http'
```

Each entry prints `Protocol:`, `Provider:`, `UUID` and `Bindings`. The bindings
name the dynamic TCP ports (`ncacn_ip_tcp:192.0.2.10[49668]`), so you never need
to sweep 49152-65535. Interfaces worth naming in the report:

| Interface label | What it tells you |
|---|---|
| `[MS-NRPC]` Netlogon, `[MS-DRSR]` directory replication | The host is a domain controller |
| `[MS-RPRN]`, `[MS-PAR]` print system | Print spooler reachable: PrinterBug coercion surface, and PrintNightmare surface for authenticated users |
| `[MS-EFSR]` EFSRPC | PetitPotam coercion surface |
| `[MS-DFSNM]` DFS namespace management | DFSCoerce surface |
| `[MS-SAMR]`, `[MS-LSAT]` | Account and policy interfaces reachable over TCP |
| Providers `termsrv.dll` | Remote Desktop Services RPC interfaces |

Report the coercion interfaces as surface. **Never call them**: coercion is the
first half of an NTLM relay, which `SECURITY.md` excludes.

For RPC over HTTP on 593 the same tool takes `-port 593`. If you must confirm
that one listed dynamic port is reachable, use a single TCP connect, not a sweep:

```bash
nc -zv -w 5 "$T" 49668
```

---

## RDP (3389/tcp)

### NLA state and NTLMSSP identity (Stage A)

```bash
nmap -Pn -p 3389 --script rdp-enum-encryption,rdp-ntlm-info --max-retries 1 "$T" \
  | tee "evidence/${T}_rdp.txt"
```

`rdp-enum-encryption` (`safe`, `discovery`) tries each security layer and RDP
encryption level in turn, so it opens several connections; run it once.

```
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     Native RDP: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Encryption level: High
```

- Only `CredSSP (NLA)` / `Early User Auth` succeed: **NLA enforced.** The
  server authenticates the user before it builds a session.
- `SSL: SUCCESS` or `Native RDP: SUCCESS`: **NLA not enforced.** An
  unauthenticated client reaches the logon UI and the pre-auth session code. With
  `Native RDP`, the RC4 encryption levels listed below it apply as well.

`rdp-ntlm-info` (`default`, `discovery`, `safe`) starts CredSSP and decodes the
server's NTLM challenge:

```
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: TS01
|   DNS_Domain_Name: corp.example
|   DNS_Computer_Name: TS01.corp.example
|   DNS_Tree_Name: corp.example
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-13T09:12:44+00:00
```

`Product_Version` is the build without update revision. The script needs
CredSSP on the server; a host offering only Standard RDP or TLS returns nothing here.

### Certificate CN (Stage A)

nmap's `ssl-cert` has no RDP STARTTLS handler, so it returns nothing on 3389.
This stdlib script sends the same X.224 Connection Request as nmap's
`TerminalServerCookie` service probe, reads the server's protocol choice,
completes the TLS handshake, prints the certificate and closes. No CredSSP
message and no credential is sent.

```python
# rdp_nla_cert.py: RDP negotiation response plus the TLS certificate.
import socket, ssl, struct, sys

host, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3389
# X.224 Connection Request + RDP_NEG_REQ asking for TLS|CredSSP (0x03).
# Byte-for-byte nmap's TerminalServerCookie probe (nmap-service-probes).
CR = (b"\x03\x00\x00\x2a\x25\xe0\x00\x00\x00\x00\x00"
      b"Cookie: mstshash=nmap\r\n"
      b"\x01\x00\x08\x00\x03\x00\x00\x00")
s = socket.create_connection((host, port), timeout=10)
s.sendall(CR)
r = s.recv(64)
if len(r) >= 19 and r[11] == 0x02:
    proto = struct.unpack("<I", r[15:19])[0]
    print("selected protocol:", {0: "Standard RDP (no TLS, no NLA)", 1: "TLS only (no NLA)",
                                 2: "CredSSP/NLA", 8: "CredSSP/NLA (HYBRID_EX)"}.get(proto, hex(proto)))
elif len(r) >= 19 and r[11] == 0x03:
    print("negotiation failure code:", struct.unpack("<I", r[15:19])[0])
    sys.exit(0)
else:
    print("no RDP_NEG_RSP; legacy RDP or not RDP:", r.hex())
    sys.exit(0)
if proto == 0:
    sys.exit(0)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
t = ctx.wrap_socket(s, server_hostname=host)
print(ssl.DER_cert_to_PEM_cert(t.getpeercert(binary_form=True)), end="")
t.close()  # stop after the TLS handshake: no CredSSP, no credentials sent
```

```bash
/usr/bin/python3 -I rdp_nla_cert.py "$T" | tee "evidence/${T}_rdp_cert.txt" \
  | openssl x509 -noout -subject -issuer -dates
```

The `selected protocol` line is the server's preference when offered TLS and
CredSSP, not proof that NLA is required; `rdp-enum-encryption` above decides
that. The certificate is self-signed by default with `CN=<host FQDN>`, so the
subject leaks the internal host and domain name. A self-signed certificate is the
Windows default and not a finding on its own.

3389/udp (RDP UDP transport) answering is recorded with the TCP result; there is
nothing further to read from it here.

### Stage B: MS12-020 and BlueKeep checks

Both checks exercise the bug they look for. Neither has a read-only form.

Stage B, written sign-off required. Blast radius: drives the CVE-2012-0152 channel-join path on a live terminal server; a failed cleanup can crash it.

```bash
nmap -Pn -p 3389 --script rdp-vuln-ms12-020 --max-retries 0 "$T"
```

Stage B, written sign-off required, naming "the host may blue-screen" as the blast radius. Use the default `Scan` action only; the same module's `Crash` action is never authorized:

```bash
msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set ACTION Scan; set RHOSTS $T; run; exit"
```

There is no stock nmap BlueKeep script. Before either Stage B check, the Stage A
gate (build 6.1.7601, 6.0.6002 or 5.x from `rdp-ntlm-info` or SMB, plus NLA not
enforced) is already a High "unconfirmed" finding. Most engagements should file
that and not run the check.

---

## Kerberos (88/tcp, 88/udp) and kpasswd (464/tcp)

### KDC reachability and server time (Stage A)

```bash
nmap -Pn -sV -p 88 "$T" | tee "evidence/${T}_kerberos.txt"
```

nmap's Kerberos service probe is an AS-REQ for `krbtgt/NM` in realm `NM` with no
client principal, so it touches no account. A domain controller answers with a
KRB-ERROR that nmap reads as:

```
88/tcp open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-13 09:12:51Z)
```

That proves a reachable KDC and leaks its clock. The realm itself comes from the
CLDAP reply, the NTLMSSP DNS domain or the RDP certificate; do not send further
AS-REQs to confirm it. 464 open next to 88 is kpasswd: record it, do not probe it.

### Stage B: Kerberos user existence, client test accounts only

The KDC answers an AS-REQ without pre-authentication differently for an existing
and a missing principal. That oracle is the finding's impact, described in
words. Demonstrating it is optional and gated.

Stage B, written sign-off required. Names come only from a client-provided list of test accounts; never a wordlist, never a guessed real name:

```bash
nmap -Pn -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm=CORP.EXAMPLE,userdb=client-test-accounts.txt "$T"
```

`krb5-enum-users` (`auth`, `intrusive`) reports existence only. Each name logs
event 4768 on the DC. Do not use kerbrute for this: for an account without
pre-authentication its user-enumeration mode can print a crackable AS-REP
(verify on the version you have), and AS-REP material is never kept in this
bundle. If any tool hands you an AS-REP, discard it unread and report only that
the client's test account has pre-authentication disabled.

---

## CLDAP (389/udp)

### rootDSE over UDP (Stage A)

```bash
nmap -Pn -sU -p 389 --script ldap-rootdse --max-retries 0 "$T" | tee "evidence/${T}_cldap.txt"
```

`ldap-rootdse` (`discovery`, `safe`) supports LDAP over UDP. It sends a
base-scope rootDSE search, and a second one with an explicit attribute list if
the first reply lacks `namingContexts`, so expect one or two packets. CLDAP is a
56-70x reflector per CISA TA14-017A: do not loop, do not repeat. OpenLDAP's
`ldapsearch` has no CLDAP transport (`cldap://` is rejected as an unparseable
URI), so nmap is the tool here.

Attributes to record:

| Attribute | Leak |
|---|---|
| `defaultNamingContext`, `rootDomainNamingContext` | AD domain and forest root (`DC=corp,DC=example`) |
| `dnsHostName` | The DC's internal FQDN |
| `serverName`, `dsServiceName` | The DC's AD site name (`CN=Sites,...`) |
| `domainFunctionality`, `forestFunctionality`, `domainControllerFunctionality` | Functional levels: `7` = Windows Server 2016 level, `10` = Windows Server 2025 level |
| `currentTime` | DC clock |

A CLDAP answer on a public address is a domain controller answering anonymous
directory pings from the internet. Grade it Medium, the same as an anonymous TCP
rootDSE in `hunt-exposed-services`, and fold it into the DC finding when the rest
of the DC port set is open. TCP 389/636/3268 rootDSE belongs to
`hunt-exposed-services`; do not repeat it here.

---

## MSSQL (1433/tcp) and SQL Browser (1434/udp)

### Version, instances, NTLMSSP identity, certificate (Stage A)

```bash
nmap -Pn -sU -sT -p U:1434,T:1433 \
  --script ms-sql-info,ms-sql-ntlm-info,ssl-cert \
  --script-args mssql.instance-all,mssql.scanned-ports-only,smbnoguest \
  --max-retries 0 "$T" | tee "evidence/${T}_mssql.txt"
```

- `ms-sql-info` (`default`, `discovery`, `safe`) asks the SQL Browser on
  1434/udp for all instances, then sends each a TDS pre-login. It does not log
  in. `mssql.scanned-ports-only` stops it from contacting ports and named pipes
  you did not list. SQL Browser is a UDP reflector (NETSCOUT lists 25:1); one run.
- `ms-sql-ntlm-info` (`default`, `discovery`, `safe`) decodes the NTLM challenge
  from a TDS login request: NetBIOS and DNS names, `Product_Version` build.
- `ssl-cert` works on 1433 because nmap has a TDS STARTTLS handler. A
  certificate with `CN=SSL_Self_Signed_Fallback` means SQL Server generated its
  own because none was configured; a real certificate's CN leaks the FQDN.

Output shape of `ms-sql-info` (adapted from the script's documented output):

```
|   192.0.2.10\PROD:
|     Instance name: PROD
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: No
|     TCP port: 1433
|     Named pipe: \\192.0.2.10\pipe\MSSQL$PROD\sql\query
|     Clustered: No
```

Unlike Windows, the TDS pre-login carries the full product build, so
`number:` is a real version gate. Compare it with the vendor's build list for the
CVE in question. Instance names, the named pipe and any extra TCP ports are part
of the disclosure. When only the SQL Browser answers (the instance port is
filtered), the version is imprecise; say so.

Optional, same rules: `ms-sql-dac` (`discovery`, `safe`) asks the Browser for the
Dedicated Admin Connection port and tests whether it is reachable. A remotely
reachable DAC is worth a line in the report.

### Stage B: the single `sa` attempt

`ms-sql-empty-password` (`auth`, `intrusive`) tries `sa` with an empty password,
once per instance, and reports a lockout if it meets one. Run it **alone**: other
`ms-sql-*` scripts tagged `safe` (`-query`, `-tables`, `-config`,
`-hasdbaccess`, `-dump-hashes`) reuse any credential found earlier in the same
run.

Stage B, written sign-off required. Blast radius: one failed login; with CHECK_POLICY ON it counts toward `sa` lockout:

```bash
nmap -Pn -p 1433 --script ms-sql-empty-password --script-args mssql.scanned-ports-only "$T"
```

`sa:<empty> => Login Success` is Critical. Stop there: no query, no
configuration read, no `xp_cmdshell`, no second account. Any further credential
work follows `hunt-brute-force`.

---

## Samba on 445

A Samba server is an SMB exposure like any other: run the SMB section. Two
differences:

- The version string is visible mainly through the SMBv1 `smb-os-discovery`
  reply; over SMB2 it is usually not disclosed. Distribution backports fix CVEs
  without changing the version, so a Samba version in range is "unconfirmed".
- Stage B, written sign-off required: `smb-vuln-cve-2017-7494` (`vuln`,
  `intrusive`) looks for writable shares by writing to them. Usually unnecessary:
  an anonymous share listing plus an in-range version is the report.

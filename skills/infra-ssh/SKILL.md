---
name: infra-ssh
description: "Triage internet-exposed SSH on port 22 and non-standard ports, including SFTP-over-SSH and SSH on appliances, firewalls, BMCs and network devices. The finding is the exposure plus what it leaks or grants: OpenSSH banner and version gates (regreSSHion CVE-2024-6387, Erlang/OTP SSH CVE-2025-32433 in CISA KEV, libssh auth bypass), algorithm posture from one ssh-audit run (Terrapin CVE-2023-48795, non-post-quantum key exchange, DHEat), authentication methods exposed (password, keyboard-interactive, none), user enumeration conditions, host-key and certificate intelligence, Cowrie honeypot false positives, one gated default-credential attempt on an appliance, git or SFTP-only accounts that grant a shell, and private keys leaked elsewhere tested against the exposed sshd. Stage A is read-only by default; any login, exploit or DoS-class check is Stage B with written sign-off. Use when a port scan, Shodan or Censys record shows an SSH banner answering on an in-scope host."
metadata:
  sources: openssh_security_advisories, nvd, cisa_kev, vendor_advisories, project_documentation, bugcrowd_vrt, lab_verified
  report_count: 0
---

## When to use

Trigger when external recon has produced an SSH service (an `SSH-2.0-` or
`SSH-1.99-` banner) on a host you are authorized to test, on port 22 or any other
port, and you need to decide whether that service is a finding. The finding here
is **the exposure plus what it leaks or grants**, not an exploit you wrote.

Use when any of these is true:

- A port scan or Shodan/Censys record shows an SSH banner on a public address.
- The banner names an appliance or an embedded stack (Erlang, libssh, Dropbear,
  Go, Paramiko, AsyncSSH, Apache MINA) rather than a distro OpenSSH.
- A private key, `authorized_keys` file or deploy credential turned up in a repo,
  CI log, container image or app bundle (`hunt-source-leak`), and an SSH service
  is in scope.
- The client says SSH is "VPN only" or "bastion only" and you can reach it anyway.

**Do not use this skill for discovery.** Host, port and ASN discovery belong to
`offensive-osint` and `web2-recon`; scope confirmation to `recon-scope-triage`.
This skill starts from "an SSH port answers and is in scope".

### Where the chain ends

This skill stops at **unauthenticated access or authentication bypass
confirmed, impact described, evidence captured**. Nothing here runs after
login: no shell exploration, no privilege escalation, no `authorized_keys`
writes, no port forwarding or SOCKS tunnelling through the target (`-L`, `-R`,
`-D` are pivoting), no agent forwarding, no lateral movement. If a credential
works, the finding is already complete. Write it up and stop.

### Not covered here, on purpose

- Credential guessing of any kind, including password spraying and username
  enumeration loops: `hunt-brute-force`. This skill tries **one** vendor-documented
  default pair, once, under Stage B, and nothing else.
- Telnet, SNMP, IPMI and other management protocols: `hunt-exposed-services`.
- SSL VPN gateways, vCenter/ESXi, Kubernetes nodes: `enterprise-vpn-attack`,
  `vmware-vcenter-attack`, `hunt-k8s`. Their SSH ports still use this skill.
- TLS on any port: `hunt-tls-network`.
- Finding the leaked key in the first place: `hunt-source-leak`,
  `supply-chain-attack-recon`.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/ssh-cve-matrix.md` | Version-gate table for OpenSSH (portable, distro deltas, Windows port), Erlang/OTP SSH, libssh, Dropbear, Go x/crypto/ssh, Paramiko, AsyncSSH, Apache MINA SSHD; KEV status; which banners can decide; client-side CVEs not to report | regresshion, cve-2024-6387, erlang otp ssh rce, cve-2025-32433, libssh auth bypass, dropbear version, openssh version vulnerable, openssh 10 cve |
| `references/algorithms-and-posture.md` | OpenSSH 9.8-10.6 default changes, PerSourcePenalties, ssh-audit output semantics and exit codes, Terrapin conditions, post-quantum warnings, DHEat, SSH certificates and FIDO keys | ssh-audit fail, weak ssh ciphers, terrapin reportable, post-quantum ssh, mlkem768x25519, dsa removed, ssh certificates, sk-ssh-ed25519 |
| `references/appliance-ssh.md` | SSH on network devices and storage appliances: banners, documented factory credentials (Cisco, Fortinet, Juniper, Ubiquiti, MikroTik, QNAP, Synology), Erlang-embedding products, management-plane grading | default ssh password appliance, mikrotik ssh, fortigate ssh admin, ubiquiti ubnt, cisco ssh exposed, qnap ssh, confd nso ssh |

---

## Step 1 — Inherit the host and port, never generate them

Take the host from the signed scope document and the port from recon. Confirm
IP ownership (ASN, WHOIS/RDAP, reverse DNS) before the first packet. Never sweep
ranges for SSH; a Shodan/Censys lookup of data someone else collected is
`offensive-osint`'s job and costs the target nothing.

### Rate posture

SSH servers defend themselves, and the defence lands on **your** egress IP, so
an impatient Stage A ruins your own Stage B. OpenSSH 9.8+ ships
`PerSourcePenalties` enabled by default: 1 s per connection that never attempts
authentication (`noauth`), 5 s per failed authentication and per invalid user
(`authfail`, `invaliduser` from 10.3), enforced once 15 s accrue (`min`), capped
at 10 minutes (`max`). In a lab run against a stock OpenSSH 10.5 sshd, roughly
fifteen probe connections inside a minute produced
`activating ipv4 penalty of 15.388 seconds for penalty: connections without attempting authentication`.
fail2ban, sshguard and appliance lockouts sit on top of that.

The default, for every step:

- Serial, one host at a time, never parallel tools against one host.
- At least 10 s between tool runs against the same host, plus 0-5 s jitter.
- Stage A budget: **25 TCP connections per host per engagement day**, counting
  each tool's own connections (listed per command below).
- A refusal, reset or banner timeout after earlier successes is a penalty, not
  "host down". Stop, wait at least 10 minutes, do not retry in a loop. A retry
  storm extends the penalty and reads as brute force in the client's SIEM.

```bash
# 10s base delay + 0-5s jitter between tool runs on the same host.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 10+rand()*5}')"; }
```

---

## Step 2 — Prove the exposure is real, external, the client's, and not a honeypot

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN, tunnel and office range; record the egress IP. | An SSH port reached over the client's own VPN is not an exposure. |
| IP ownership | ASN + WHOIS/RDAP + reverse DNS, cross-checked with scope. | Shared hosting and cloud pools answer for addresses that are not in scope. |
| Real sshd vs middlebox | The banner must arrive unprompted within a few seconds. A handshake-completing load balancer or tarpit (endlessh-style drip of junk lines) never sends a valid `SSH-2.0-` line. | No banner, no SSH service. |
| Cowrie / honeypot | Current Cowrie defaults: banner `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`, hostname `svr04`, listeners 2222/2223 (often NATed to 22), and an algorithm offer containing `3des-cbc`, `cast128-cbc`, `hmac-md5` and preauth `zlib`, which a real OpenSSH 9.2 does not offer by default. Its user database accepts `root` with almost any password. | A "root default password" report against a honeypot is the classic withdrawn SSH finding. |
| Banner vs host | The SSH banner's OS must agree with everything else the host serves (HTTP `Server`, TLS certificate, TTL, other banners). A Debian banner on a host whose web stack is IIS is a decoy or a jump box; find out which before reporting. | Implausible combinations are the cheapest honeypot tell. |
| Fleet keys | The same host-key fingerprint on many unrelated IPs (Shodan/Censys) means a shared image, a vendor default key, or a honeypot fleet. Each is a different report. | See Step 4e. |

Record raw output for every probe before Stage B, so later evidence has a baseline.

---

## Step 3 — Stage A: read-only fingerprint

A Stage A probe sends no credential, opens no session channel, runs no command,
and stays inside the budget above. Four probes cover almost every finding.

```bash
T="192.0.2.10"; P="22"; mkdir -p evidence

# A1. Banner + host keys: 3 connections (one per key type). Always pass -t: with no
# -t, ssh-keyscan 10.x opens one connection per key type it knows (6 in the lab).
# The banner is the "# host:port SSH-2.0-..." comment line in the output.
ssh-keyscan -T 10 -p "$P" -t ed25519,ecdsa,rsa "$T" 2>&1 | tee "evidence/${T}_${P}_keyscan.txt"
grep -v '^#' "evidence/${T}_${P}_keyscan.txt" | ssh-keygen -lf - | tee "evidence/${T}_${P}_fingerprints.txt"
probe_delay

# A2. Host certificate, only if A1 or ssh-audit hints at one: 1 connection.
# A host cert names its principals (often internal hostnames), CA and validity.
# -c output has no host field, so save it as-is and let ssh-keygen -L parse it.
ssh-keyscan -c -T 10 -p "$P" -t ed25519 "$T" 2>/dev/null | grep -v '^#' > "evidence/${T}_${P}_hostcert.pub"
ssh-keygen -L -f "evidence/${T}_${P}_hostcert.pub"
```

```bash
# A3. Auth methods: 1 connection, method "none", nonexistent username, no credential.
# -N opens no session channel, so even a server that accepts "none" starts no shell.
timeout 20 ssh -v -N -p "$P" -F /dev/null -o PreferredAuthentications=none \
  -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 zz-authmethods-probe@"$T" 2>&1 \
  | grep -E "remote software version|kex: algorithm|Authentications that can continue|Authenticated to|Permission denied" \
  | tee "evidence/${T}_${P}_authmethods.txt"
probe_delay

# A4. One ssh-audit run, last. --skip-rate-test is mandatory: without it ssh-audit
# opens up to 38 connections in 1.5 s on 3 sockets to infer DHEat susceptibility.
# With it: 3 connections against a server with two host-key types and no DH-GEX;
# more (one per GEX modulus probe) against servers still offering group exchange.
ssh-audit --skip-rate-test -n -t 10 -p "$P" "$T" | tee "evidence/${T}_${P}_ssh-audit.txt"
```

Offline follow-up, zero packets to the target:

```bash
# A5. Known-compromised and weak host keys (Debian CVE-2008-0166 keys, vendor
# firmware keys, small RSA, shared primes). Exit code 4 = a vulnerable key.
grep -v '^#' "evidence/${T}_${P}_keyscan.txt" | awk '{print $2, $3}' \
  | split -l 1 --additional-suffix=.pub - "evidence/${T}_${P}_hostkey_"
badkeys --update-bl && badkeys -a evidence/"${T}_${P}"_hostkey_*.pub
```

Then search the SHA256 fingerprints in Shodan/Censys host data (query syntax is
`offensive-osint`'s). Other hosts sharing the key widen scope, reveal an origin
behind a CDN, or prove a vendor default key.

If `ssh-audit` is not available, `nmap -Pn -n -sT -p "$P" --script ssh2-enum-algos "$T"`
(1 connection; add `-sV --version-light` on a non-standard port) gives the
algorithm lists without the analysis.

### Tools that look like Stage A and are not

Verify any NSE script's categories with `nmap --script-help <name>` first. Checked
against nmap 7.991:

| Script / flag | Declared categories | Why it is not a Stage A probe |
|---|---|---|
| `ssh-hostkey` | `safe`, `default`, `discovery` | Safe, but **silently empty** against OpenSSH 10.x defaults: nmap offers only finite-field DH, which 10.0 disabled (lab sshd log: `no matching key exchange method found`). Empty output is not "no host key". Use A1. |
| `ssh-auth-methods` | `auth`, `intrusive` | Declared intrusive; sends a `none` request for a random username. A3 does the same thing by hand, once. |
| `ssh-publickey-acceptance` | `auth`, `intrusive` | Offers keys as credentials. Stage B. |
| `ssh-run` | `intrusive` | Logs in and executes a command. Stage B at best. |
| `ssh-brute` | `brute`, `intrusive` | Credential guessing. `hunt-brute-force`, under its rules. |
| `-sC`, `-A` | the whole `default` category | Never; name scripts individually. |
| `ssh-audit --dheat` | n/a | Runs the DHEat denial of service (CVE-2002-20001). Forbidden. |
| `ssh-audit --conn-rate-test` | n/a | Opens N concurrent sockets to measure connection rate. Stage B. |
| `ssh-audit -T targets.txt` | n/a | Scans 32 targets in parallel by default. Serial only. |

---

## Step 4 — Read the results

### 4a. Version gate

Parse the banner `SSH-2.0-<software>[ <comment>]`, then check the matrix in
`references/ssh-cve-matrix.md`. Three rules decide whether the banner can decide:

- Debian and Ubuntu append the package revision (`OpenSSH_9.2p1 Debian-2+deb12u3`).
  Compare that suffix with the distro security tracker, never with the upstream
  range: 9.2p1 is upstream-vulnerable to regreSSHion and `deb12u3` is the fix.
- RHEL and derivatives send `OpenSSH_8.7` with no package revision. The banner
  cannot decide CVE-2024-6409 or any backported fix. Say so in the report.
- Embedded stacks expose their own version scheme: `Erlang/<ssh-app-version>` is
  the Erlang **ssh application** version, not the OTP release; `dropbear_2025.88`
  is a date-style release; `SSH-2.0-Go` carries no version at all.

A version inside a CVE range is **unconfirmed** until the client confirms the
package or you have Stage B sign-off. Every DoS-class CVE in the matrix
(regreSSHion, CVE-2025-26466, CVE-2026-3497, DHEat) is detected by banner only
and never tested.

### 4b. Algorithm posture

Read `ssh-audit` as hardening input, not as a vulnerability list (details in
`references/algorithms-and-posture.md`). A stock, fully patched OpenSSH 10.5
produced exit code 3 (FAILURE) in the lab, because its default offer still
includes `ecdh-sha2-nistp*` and `hmac-sha1` and ssh-audit marks those `[fail]`.
ssh-audit 3.9.0 also warns on every key exchange that is not post-quantum, and
prints a Terrapin note even when the server advertises `kex-strict-s-v00@openssh.com`.
None of that is reportable alone.

What can be reportable: SSHv1 (`SSH-1.99-` or `SSH-1.5-`), `diffie-hellman-group1-sha1`,
export or `none` ciphers, RSA host keys under 2048 bits, DSA host keys, and
Terrapin exposure where the server lacks the strict-kex marker **and** offers
`chacha20-poly1305@openssh.com` or a CBC cipher with an `-etm` MAC. Even these
are Low or Informational on most programs (Step 6).

### 4c. Authentication methods

| A3 result | Meaning |
|---|---|
| `Authenticated to ... using "none"` | Unauthenticated access. Critical. Stop; capture the line; nothing else. |
| `publickey` only | The expected modern posture. Not a finding. |
| `password` and/or `keyboard-interactive` | Password login reachable from the internet. Hardening item (Informational/Low) unless paired with a working credential. Spraying it is `hunt-brute-force`'s decision, not this skill's. |
| `gssapi-with-mic` | Kerberos on the internet. Before OpenSSH 10.4 GSSAPI answers differed for valid and invalid users (10.4 bugfix); Ubuntu/Debian GSSAPI patches carry CVE-2026-3497. |
| `hostbased` | Rare externally; trust is delegated to client host keys. Note it, do not test it. |

OpenSSH returns the same method list for valid and invalid users, so A3 does not
enumerate users, and its nonexistent username cannot authenticate anything.

### 4d. User enumeration: what still works

| Condition | Status in 2026 | Stage |
|---|---|---|
| CVE-2018-15473, OpenSSH up to 7.7 (fixed in 7.8) | Banner gate only. The malformed-packet check sends one auth attempt per username. | B, and `hunt-brute-force` |
| CVE-2016-6210 timing, OpenSSH before 7.3 | Requires long-password attempts per username. | B |
| GSSAPI enabled, OpenSSH before 10.4 | Observable difference fixed as a 10.4 bugfix. | B |
| CVE-2026-60001, OpenSSH before 10.4: minimum auth delay not always honoured | A timing signal, not a demonstrated enumeration. Claim it only with a reproducible median delta across 20+ samples per name. | B |
| You hold a **public** key (e.g. from a code host) | "Server accepts key" for user X proves the account and the key mapping. | B |
| Modern OpenSSH, none of the above | Timing reports are usually network jitter. Expect triage to close them. | n/a |

Bugcrowd's VRT rates "Username/Email Enumeration > Brute Force" at P5. Enumeration
matters here only as a chain input.

### 4e. Host-key and certificate intelligence

- `badkeys` hit (Debian weak key, vendor firmware key): impersonation of the host
  by anyone with the published private key. High.
- One key across unrelated hosts: a golden image that never regenerated keys, or a
  vendor default. Medium, Medium-High when the key is published (MITM still required).
- Host-certificate principals list internal hostnames; that is an information
  leak (Low) and a recon input for `offensive-osint`.
- `sk-*` and `webauthn-sk-*` in `server-sig-algs` are OpenSSH defaults. They do
  **not** mean the server enforces FIDO keys.

---

## Step 5 — Stage B: anything that logs in, exploits or stresses

Stage B is **blocked by default**. It requires explicit written operator sign-off
naming the action, the host, the account and a time window. A Slack thumbs-up or
"critical findings are in scope" is not sign-off. Record before the first packet:

```
Stage B authorization
  Host/port:        192.0.2.10:22
  Action:           one public-key acceptance check with the key leaked in <repo@commit>
  Account:          deploy (named in the leaked CI config)
  Blast radius:     one preauth connection; sshd logs "Connection closed by
                    authenticating user deploy"; no session, no login record
  Reversibility:    nothing to reverse; the key itself must be rotated by the client
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| One vendor-documented default credential on an appliance | A failed login can count toward lockout; a successful one lands in an admin CLI on network gear. |
| Public-key acceptance check with a leaked key | One preauth connection; no session. The lowest-impact proof of a leaked key. |
| Full login with a leaked key or client test account (`-N`) | A login record on a production host; still no shell or command. |
| Exec check on a git/SFTP-only account | Runs `id` as that account. Benign marker, but it is code execution. |
| Empty password or `none` for a **real** username | A credential attempt against a named account. |
| CVE-2018-15473 or timing enumeration | Username guessing. Belongs to `hunt-brute-force`. |
| CVE-2025-32433 or CVE-2018-10933 confirmation | Pre-auth code execution or an authenticated channel on a live appliance. Report from the banner instead; confirmation is rarely signed off and public PoCs execute commands. |
| Cracking a passphrase on a leaked key | Produces a live credential. Usually unnecessary: report the leak and the PK_OK result. |

**Forbidden outright, sign-off or not:** regreSSHion (the OpenSSH 9.8 notes put
lab exploitation at 6-8 hours of continuous connections at the server's
connection limit), CVE-2024-6409, CVE-2025-26466, CVE-2026-3497, `ssh-audit --dheat`,
and any other DoS-class check. SSH is usually the only remote admin path; taking
it down is an outage the client cannot fix remotely. Port forwarding, SOCKS and
agent forwarding through the target are pivoting and are never in this skill.

### B1. Leaked private key: prove authorization without logging in

The server answers "Server accepts key" (PK_OK) before the client signs anything,
so the public half alone proves the key is authorized. Lab-verified against
OpenSSH 10.5: the server logged only `Connection closed by authenticating user ... [preauth]`.

```bash
# Stage B only, with written sign-off naming key source, host and account.
# Usernames: only those the leak names (key comment, CI config, deploy script). No lists.
# Keep the .pub in its own directory so ssh cannot find the private half beside it.
mkdir -p pubonly && ssh-keygen -y -f leaked_key > pubonly/leaked.pub   # passphrase prompt: stop
ssh-keygen -lf pubonly/leaked.pub                                      # sk-* type: see below
timeout 20 ssh -v -N -p "$P" -F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes \
  -i pubonly/leaked.pub -o PreferredAuthentications=publickey -o BatchMode=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null deploy@"$T" 2>&1 \
  | grep -E "Offering public key|Server accepts key|Permission denied"
# A "Load key ... " error after "Server accepts key" is expected: there is no private key.
```

An `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-*` key file is a handle for a
hardware authenticator. PK_OK still proves the authorization, but the file alone
cannot sign: report it as an authorized-key leak, not as access.

If the program requires a real login, a second sign-off covers one
`timeout 30 ssh -v -N -i leaked_key ... deploy@"$T"` that stops at
`Authenticated to ... using "publickey"`. `-N` opens no session channel.

### B2. One default credential on an appliance

Only a pair the vendor documents for that exact product (see
`references/appliance-ssh.md`), one attempt per host per engagement. Skip it
where the documented default is not guessable from outside (QNAP QTS 4.4.2+ uses
the NAS MAC address) or cannot survive commissioning (Junos refuses to commit
without root authentication; FortiOS forces a change on first login).

```bash
# Stage B only, with written sign-off naming host, account and the single documented pair.
# One prompt, typed once by the operator. -N: no session, no CLI, no command.
timeout 60 ssh -v -N -p "$P" -F /dev/null -o PubkeyAuthentication=no \
  -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=1 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@"$T" 2>&1 \
  | grep -E "Authenticated to|Permission denied"
# A second prompt appearing = press Ctrl-C. One attempt means one.
```

A success is a finding only after the honeypot checks in Step 2 are re-run:
Cowrie accepts `root` with almost any password. Log out by letting `timeout` end
the connection; never type a command at an appliance prompt.

### B3. git-only and SFTP-only accounts that grant more

With a credential you are already allowed to use (client test account, or B1's
key under its sign-off), check whether the restriction holds.

```bash
# Stage B only, under the sign-off for the credential in use.
# git hosts: a greeting naming the mapped account is enough; no exec needed.
timeout 20 ssh -T -p "$P" -F /dev/null -o BatchMode=yes -i test_key git@"$T"
# A restricted account must refuse an exec request. A uid line back means a shell.
timeout 20 ssh -T -p "$P" -F /dev/null -o BatchMode=yes -i test_key sftpuser@"$T" id
# SFTP chroot: one listing of /, no download. /etc or other users' homes = broken chroot.
echo 'ls -la /' | timeout 30 sftp -b - -P "$P" -F /dev/null -i test_key sftpuser@"$T"
```

Stop at the listing. File names and counts prove a broken chroot; downloading
another user's files makes you the breach.

---

## Step 6 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Authenticated with no credential (`none`), a default credential, or a leaked key (PK_OK or login) on a production host | Critical |
| Same, on a management plane (firewall, BMC, hypervisor, router) | Critical, escalate immediately |
| git/SFTP-only account returns a shell, or the SFTP chroot exposes other users' files | High to Critical, by what the account reaches |
| Banner in range of a KEV-listed pre-auth RCE (CVE-2025-32433) | High, labelled unconfirmed; escalate to the client the same day |
| Banner in range of regreSSHion or another non-KEV pre-auth CVE | Medium, labelled unconfirmed, with the backport caveat |
| Known-compromised host key (`badkeys` hit) | High |
| Leaked authorized FIDO key handle, or passphrase-protected key with PK_OK | Medium to High |
| Password authentication reachable on a management plane | Low to Medium |
| Weak algorithms, Terrapin without strict kex, non-PQ key exchange | Informational to Low |
| SSH exposed, modern version, key-only auth | Not a finding |

### What is not a finding

- **SSH on the internet with a current version and key-only authentication.** That
  is the design, not a misconfiguration.
- **Banner or version disclosure.** HackerOne's core ineligible findings list
  "Software version disclosure / Banner identification issues"; Bugcrowd's
  Standard Disclosure Terms exclude "Banner disclosure on common/public services";
  the VRT rates "Fingerprinting/Banner Disclosure" P5.
- **Weak or non-PQ algorithms alone.** HackerOne lists "SSL/TLS Configurations"
  under optional hardening, and the VRT rates "Insecure SSL > Insecure Cipher
  Suite" P5. Programs apply the same logic to SSH algorithm lists. ssh-audit
  `[fail]` lines on a stock OpenSSH are the norm, not the exception.
- **Terrapin alone.** It needs an active man-in-the-middle; the impact is an
  extension-negotiation downgrade. Low at most, often closed as theoretical.
- **"Outdated OpenSSH" with no reachable issue.** VRT "Outdated Software Version"
  is P5; distro backports make most of these false.
- **Client-side CVEs** (CVE-2025-26465, CVE-2025-61984/61985, scp/sftp client
  fixes): they need a victim client to connect somewhere. An exposed server is
  not evidence of them.
- **Missing rate limiting on SSH login.** Out of scope on most programs and
  `hunt-brute-force`'s decision; `PerSourcePenalties` is on by default anyway.

Bugcrowd's VRT rates "Using Default Credentials" P1. That is the line between a
P5 hardening note and a critical here: a credential that works.

---

## Step 7 — Evidence

Follow `evidence-hygiene`. Minimum per finding: the A1 keyscan output with the
banner line, fingerprints, the A3 auth-methods lines, the ssh-audit text output,
the egress IP, timestamps, and for Stage B the sign-off record plus the single
`Authenticated to` or `Server accepts key` line. Redact the leaked key itself;
include its fingerprint and type only. Never include file contents from a
broken SFTP chroot beyond names and counts. Tell the client to rotate any leaked
key the same day, whether or not PK_OK succeeded.

---

## Chain table

| Starting point | Chain | Realistic severity | Where it goes next |
|---|---|---|---|
| Private key in a repo, CI log, image or APK (`hunt-source-leak`) | Exposed sshd answers PK_OK for the user the leak names | Critical | Report. Login only on a second sign-off. |
| Banner `Erlang/<ssh-app-version>` below the fixed version | CVE-2025-32433, KEV-listed pre-auth RCE | Critical-class, reported unconfirmed | Same-day client notice. No PoC. |
| Banner `libssh_0.7.x` / `0.8.0-0.8.3` in server mode | CVE-2018-10933 auth bypass | Critical-class, unconfirmed | Report from the banner. |
| Host-key fingerprint | Shodan/Censys pivot to other hosts with the same key | Recon multiplier | `offensive-osint`; scope check per new IP. |
| Fleet-wide shared or published host key | Host impersonation for any on-path attacker | Medium to High | Report; needs MITM to exploit. |
| Appliance banner on a management plane | One documented default credential (B2) | Critical if accepted | Vendor CVEs via `enterprise-vpn-attack` or `hunt-exposed-services`. |
| Password auth + an enumeration condition (4d) | Targeted credential attack | Decided by `hunt-brute-force` | Hand off; do not spray from here. |
| SFTP-only test account | Broken chroot lists other tenants' files | High to Critical | Stop at names and counts. |
| `gss-*` key exchange or `gssapi-with-mic` exposed | Kerberos realm and host principal leak | Low, chain input | `hunt-ntlm-info` for adjacent Windows metadata. |

---

## Validation checklist

- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Every IP confirmed client-owned (ASN + WHOIS/RDAP) and in the signed scope.
- [ ] A genuine `SSH-2.0-` banner arrived unprompted; not a tarpit or middlebox.
- [ ] Honeypot ruled out: banner, algorithm offer and host OS agree; not the
      Cowrie default banner with `3des-cbc`/`cast128-cbc`/`hmac-md5` on offer.
- [ ] Stage A stayed inside 25 connections per host, serial, 10 s apart.
- [ ] `ssh-audit` ran once, with `--skip-rate-test`; never `--dheat` or
      `--conn-rate-test`.
- [ ] No `-sC`, no `-A`; every NSE script named and checked with `--script-help`.
- [ ] An empty `ssh-hostkey` result was not read as "no host key".
- [ ] Version-gated findings are labelled unconfirmed, with the distro backport
      check (Debian/Ubuntu suffix) or an explicit "banner cannot decide" (RHEL).
- [ ] No DoS-class CVE was tested; detection was by banner only.
- [ ] Every login, key check or default-credential attempt has a logged written
      sign-off, and the default credential was tried exactly once.
- [ ] A successful default credential was re-checked against the honeypot list.
- [ ] Leaked keys: FIDO `sk-*` handles and passphrase-protected keys graded as
      such; no passphrase cracking; client told to rotate.
- [ ] No session channel, command, forward or tunnel beyond what the sign-off named.
- [ ] Not reporting banner disclosure, algorithm lists or Terrapin alone as a
      vulnerability unless the program's policy accepts them.
- [ ] The report ends at access proven plus impact. No post-login content.

---

## Sources

Primary sources (fetched 2026-10-13):

- OpenSSH security advisories and release notes: <https://www.openssh.org/security.html>, <https://www.openssh.org/releasenotes.html>
- `sshd_config(5)` PerSourcePenalties defaults: <https://man.openbsd.org/sshd_config>
- CISA KEV feed (catalog 2026.10.13): <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- NVD records via <https://services.nvd.nist.gov/rest/json/cves/2.0>
- ssh-audit (v3.9.0, 2026-07-04): <https://github.com/jtesta/ssh-audit>
- Terrapin: <https://terrapin-attack.com/>
- badkeys: <https://github.com/badkeys/badkeys>
- Cowrie defaults: <https://github.com/cowrie/cowrie/blob/main/src/cowrie/data/etc/cowrie.cfg.dist>
- nmap NSE docs: <https://nmap.org/nsedoc/scripts/ssh-auth-methods.html>
- HackerOne core ineligible findings: <https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>
- Bugcrowd VRT (release 2026-07-08): <https://github.com/bugcrowd/vulnerability-rating-taxonomy>
- Bugcrowd Standard Disclosure Terms: <https://www.bugcrowd.com/resources/essentials/standard-disclosure-terms/>

Lab verification: banner, keyscan connection counts, the `none` probe, the
public-key acceptance oracle, `ssh-hostkey` failure, ssh-audit exit code and
connection count, and the PerSourcePenalties trigger were reproduced against a
local OpenSSH 10.5p1 sshd with nmap 7.991 and ssh-audit 3.9.0.

---

## Related Skills & Chains

- `hunt-exposed-services` — every other non-HTTP port; its Stage A/B model and
  NSE trap list are the template for this skill.
- `hunt-brute-force` — all credential guessing and enumeration loops. This skill
  hands off rather than spray.
- `hunt-source-leak`, `supply-chain-attack-recon`, `apk-redteam-pipeline` —
  where leaked private keys and deploy credentials come from.
- `offensive-osint`, `web2-recon`, `recon-scope-triage` — discovery, fingerprint
  pivots and scope confirmation.
- `enterprise-vpn-attack`, `vmware-vcenter-attack`, `hunt-k8s` — appliance and
  platform CVEs once SSH has identified the product.
- `hunt-tls-network` — TLS findings on the same hosts.
- `evidence-hygiene`, `triage-validation`, `report-writing` — evidence handling,
  false-positive gates and write-up.

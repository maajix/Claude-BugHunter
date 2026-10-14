---
name: infra-vpn-ike
description: "Triage internet-exposed non-SSL VPN and tunnel endpoints: IKE/IPsec 500/udp and NAT-T 4500/udp, L2TP 1701, PPTP 1723 with GRE, OpenVPN 1194 or on 443, WireGuard 51820, SSTP, SoftEther, Tailscale, ZeroTier. ike-scan fingerprinting, IKEv1 aggressive mode with PSK returning a crackable hash, weak transforms graded against RFC 8247, OpenVPN without tls-auth, version gates for strongSwan, Libreswan, OpenVPN, SoftEther and the IKE side of ASA, FortiOS and PAN-OS. PSK cracking and tunnel establishment are Stage B. Use when 500, 4500, 1701, 1723 or 1194 is open or ike-scan output needs grading."
metadata:
  sources: nvd, vendor_advisories, rfc, project_documentation, tool_source_code, public_research
  report_count: 0
---

## When to use

Trigger when external recon has produced a VPN or tunnel listener on a host you
are authorized to test, and you need to decide whether it is a finding. The
finding here is **a misconfiguration the listener shows to any unauthenticated
peer**: a PSK hash handed out by Aggressive Mode, a deprecated cipher accepted,
a protocol that should not face the internet at all. Not a memory-corruption bug
you trigger yourself.

Use when any of these is true:

- A UDP scan shows 500, 4500 or 1701 answering, or TCP 1723, 1194 or 5555 open.
- Recon found an IPsec client profile, an `.ovpn` file, a WireGuard config or a
  PPTP dial-up guide for the client.
- An SSL VPN appliance owned by `enterprise-vpn-attack` also answers on 500/udp,
  and you need the IKE half of the picture.
- A scanner flagged "IKE Aggressive Mode with Pre-Shared Key" and the result
  needs confirming or killing before it goes into a report.

**Do not use this skill for discovery.** Host and port discovery belongs to
`offensive-osint` and `web2-recon`, scope confirmation to `recon-scope-triage`.

### Where the chain ends

This skill stops at **exposure or misconfiguration confirmed, impact
described, evidence captured**. Proof of an Aggressive Mode finding is the hash
coming back, not the cracked key. It contains nothing about using a tunnel once
you have one: no route injection, no internal scanning, no pivoting. A working
tunnel into the client network is an internal-network position, which
`SECURITY.md` puts outside this bundle.

### Not covered here, on purpose

- **SSL VPN web stacks** (FortiGate SSL-VPN, Citrix, Ivanti, GlobalProtect
  portal, Cisco ASA WebVPN and AnyConnect over HTTPS, SonicWall, F5) are owned by
  `enterprise-vpn-attack`. This skill covers the IKE/IPsec side of the same
  boxes. When an IKE fingerprint names one of those vendors, get the version
  from that skill's web fingerprinting, because IKE rarely carries one.
  AnyConnect over TLS/DTLS is theirs; AnyConnect configured for IKEv2/IPsec
  (500, 4500) is covered here.
- **TLS findings** on OpenVPN-over-TLS, SSTP or a DERP server belong to
  `hunt-tls-network`.
- **Every credential guess** (XAUTH, EAP, management passwords, default PSKs)
  is `hunt-brute-force`'s territory and Stage B here.
- **Leaked VPN configs and keys** found in repos or bundles belong to
  `hunt-source-leak`. This skill only grades what the leak exposes.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/ike-transforms.md` | IKEv1 attribute values for `--trans`, the bounded transform list, RFC 8247 and RFC 9395 grading, IKEv2 default proposal and notify codes, vendor ID and backoff notes | ike transform enumeration, weak ike ciphers, dh group 2, des md5 ike, rfc 8247, no-proposal-chosen, invalid ke payload |
| `references/other-tunnels.md` | SSTP fingerprint, SoftEther, Tailscale DERP and Headscale, ZeroTier management API | sstp vpn, softether exposed, tailscale derp, headscale exposed, zerotier 9993 |
| `references/vpn-cve-matrix.md` | strongSwan, Libreswan, OpenVPN, SoftEther, Cisco ASA/FTD IKEv2, FortiOS IKE, PAN-OS IKEv2 CVEs 2024-2026, with pre-auth, confirmability and stage, plus placement of non-IKE CVEs | strongswan cve, libreswan cve, openvpn cve, softether cve, cisco ikev2 dos, fortios ike, pan-os ikev2, check point 24919 placement |

---

## Step 1: Inherit the target list, then set the UDP rate posture

Take hosts from the signed scope and ports from recon; confirm IP ownership
before the first packet. Cloud VPN gateways (AWS, Azure, GCP) sit on provider
addresses: check the provider's testing policy before probing them.

### Rate posture for every IKE and tunnel probe

IKE responders are not web servers. Every Main Mode or Aggressive Mode opener
creates half-open responder state, appliances log IKE scans as IPS events, and
some shun the source address, which ends your testing of that gateway for the
day. UDP has no connection to tear down, so a retransmit storm is all cost.

```bash
# One host at a time, 2s base + 0-3s jitter between probes, as in hunt-exposed-services.
probe_delay() { sleep "$(awk -v s=$RANDOM 'BEGIN{srand(s);print 2+rand()*3}')"; }

# ike-scan defaults: 3 attempts per host, 500 ms first timeout, 56000 bit/s.
# Cut retries to one attempt, and set an explicit packet interval.
IKE_OPTS="--retry=1 --interval=1000 --multiline"
```

- A timeout is a result. Re-run once, later, never in a loop.
- ike-scan sends from source port 500 by default, which needs root. Some
  responders only answer source port 500, and NAT rewrites it, so probe from a
  host with a public address of its own, not from behind NAT.
- Short options with optional arguments must be attached (`-o25`, `-Pfile`).
  Use the long forms (`--showbackoff=60`, `--pskcrack=FILE`) to avoid the trap.
- Budget per IKE host for all of Stage A: about 20 packets. The transform list in
  `references/ike-transforms.md` is sized to fit.

---

## Step 2: Prove the exposure is real, external and the client's

| Check | How | Why it matters |
|---|---|---|
| External vantage | Probe from outside every client VPN and office range; record the egress IP. | A responder reached through the client's own tunnel is not exposed. |
| IP ownership | ASN + WHOIS/RDAP + reverse DNS per address, cross-checked with the scope document. | Shared and provider-managed VPN endpoints answer for addresses that are not in scope. |
| UDP open vs filtered | Only a protocol reply proves a listener. `open\|filtered` from nmap proves nothing. Compare with a closed UDP port on the same host that returns ICMP port-unreachable. | Silence is the normal state of a firewalled port, a WireGuard listener, an OpenVPN with tls-auth and a rate-limited IKE daemon alike. |
| Honeypot | A responder that accepts every transform, answers every Aggressive Mode ID with a hash, and returns vendor IDs that no real stack sends together. | A handshake from a sensor is not a client misconfiguration. |

Save the raw reply to every probe at probe time. A later diff needs a baseline.

---

## Step 3: Map the port to a section

| Port(s) | Protocol | Section | Depth |
|---|---|---|---|
| 500/udp, 4500/udp | IKEv1, IKEv2, NAT-T | Step 4 | `references/ike-transforms.md` |
| 1723/tcp (+GRE), 1701/udp, 1194/udp+tcp, 443/tcp, 51820/udp | PPTP, L2TP, OpenVPN, WireGuard | Step 5 | |
| 443/tcp, 992, 5555/tcp, 3478/udp, 9993/udp+tcp | SSTP, SoftEther, Tailscale DERP, Headscale, ZeroTier | Step 5 | `references/other-tunnels.md` |
| any of the above with a vendor match | version gate | Step 6 | `references/vpn-cve-matrix.md` |

---

## Step 4: Stage A for IKE/IPsec (500, 4500)

Stage A for IKE: a Main Mode opener, a backoff fingerprint, a bounded transform
list, **one** Aggressive Mode probe with an ID that is not a guess, one IKEv2
SA_INIT. No identity you hope is valid, nothing past the first exchange.

### 4.1 Main Mode handshake and vendor IDs

```bash
T="192.0.2.10"; mkdir -p evidence

# ike-scan's default Main Mode proposal is 8 legacy transforms:
# 3DES/DES x SHA1/MD5 x DH group 2/1, PSK auth.
sudo ike-scan $IKE_OPTS "$T" | tee "evidence/${T}_ike_mm_default.txt"
probe_delay
# A modern responder rejects all of that. Offer one modern PSK and one RSA-sig transform:
# AES-256, SHA2-256, PSK or RSA sig, DH group 14 (values in references/ike-transforms.md).
sudo ike-scan $IKE_OPTS --trans=7/256,4,1,14 --trans=7/256,4,3,14 "$T" \
  | tee "evidence/${T}_ike_mm_modern.txt"
```

Read the reply:

- `Main Mode Handshake returned` with an `SA=` line: the responder accepted the
  transform shown. From the default set, that is DES or 3DES with MD5 or SHA1
  and DH group 1 or 2. That alone is a weak-transform finding (Step 8).
- `Notify message 14 (NO-PROPOSAL-CHOSEN)`: an IKEv1 responder exists and
  rejected everything offered. Good news for the client, and still proof of a
  listener.
- `VID=` lines: vendor ID payloads, named from ike-scan's `ike-vendor-ids`
  file: a vendor (Cisco, Fortinet, Check Point, Openswan, the unmaintained
  predecessor of Libreswan **(verify)**) or a feature (XAUTH, DPD, NAT-T), almost
  never a patch level. strongSwan sends its VID only with `charon.send_vendor_id`
  and `Cisco Unity` only with `charon.cisco_unity` (both default `no`), so a
  `Cisco Unity` VID does not prove a Cisco box.
- `Auth=PSK` accepted in Main Mode: some peer policy on this gateway uses a
  pre-shared key. Main Mode does not leak it; Aggressive Mode might (4.4).
- Nothing at all: filtered, IKEv2-only, or a responder that ignores your source
  port. Go to 4.5 before concluding anything.

### 4.2 Backoff fingerprint

The responder retransmits its reply on its own schedule, and the timing
identifies the implementation. It needs an accepted transform, so reuse 4.1's.
You send one packet; the responder holds state for the whole window.

```bash
ACCEPTED="7/256,4,1,14"   # set to the transform 4.1 actually accepted
sudo ike-scan --retry=1 --showbackoff=60 --trans="$ACCEPTED" "$T" \
  | tee "evidence/${T}_ike_backoff.txt"
```

### 4.3 Transform enumeration, bounded

Walk the tiered list in `references/ike-transforms.md`, one `--trans` per run,
serial, `probe_delay` between runs, weakest tier first. Stop a tier at its
first accepted transform: the finding is "accepts a MUST NOT transform", not an
inventory of every combination. Main Mode proposals are matched before the
peer's identity is known, so what you see is the union of every peer policy on
the gateway, which is exactly what an attacker sees.

### 4.4 One Aggressive Mode probe

Aggressive Mode with a PSK sends the responder's hash, keyed by the PSK, to a
peer that has not authenticated. That hash cracks offline. The Stage A question
is only **does a hash come back**.

Use an ID that is obviously not a guess, so a hash means "answers any ID" (a
wildcard PSK, or a decoy some stacks send to resist enumeration **(verify per
vendor before naming one)**) and `INVALID-ID-INFORMATION` means "Aggressive Mode
is on and validates IDs".
Guessing real group names is enumeration, which is Stage B.

`ACCEPTED` must be a PSK-family accept (auth 1 or 65001) from 4.3's per-auth
runs. If Main Mode only accepted auth 3 (RSA), skip this: there is no PSK hash.

```bash
DHG="${ACCEPTED##*,}"   # the transform's own group; MODP only, ECP cannot be used for AM
sudo ike-scan --aggressive $IKE_OPTS --id=probe-not-a-group \
  --trans="$ACCEPTED" --dhgroup="$DHG" \
  --pskcrack="evidence/${T}_am_psk_params.txt" "$T" \
  | tee "evidence/${T}_ike_am.txt"
```

| Reply | Meaning |
|---|---|
| `Aggressive Mode Handshake returned`, `Auth=PSK`, a HASH payload | AM + PSK enabled. Parameters written to the `--pskcrack` file. **That file is credential material**: handle it under `evidence-hygiene`, never paste it into a report body. |
| `Notify message 18 (INVALID-ID-INFORMATION)` | AM enabled, the ID was rejected. A hash needs a valid group name: Stage B. |
| `NO-PROPOSAL-CHOSEN` | Transform mismatch, **not** "AM disabled". Retry once with the other transform 4.1 accepted. |
| No reply | AM disabled, or AM dropped for unknown IDs. Not distinguishable from here. |

Budget: three Aggressive Mode packets per host in total, including any nmap
`ike-version` run (it sends two of its own, see the trap table below). ike-scan
generates the AM key exchange for MODP groups only (`--dhgroup` accepts 1, 2, 5
and 14 to 18), so an ECP-only responder cannot be probed in AM this way.

### 4.5 NAT-T and IKEv2

```bash
# NAT-T: RFC 3947 encapsulation, source and destination port 4500.
sudo ike-scan --nat-t $IKE_OPTS --trans=7/256,4,1,14 "$T" | tee "evidence/${T}_ike_natt.txt"
probe_delay
# IKEv2 SA_INIT with ike-scan's default proposal: AES-CBC-256/128, 3DES, DES;
# PRF SHA1/MD5; integrity SHA1-96/MD5-96; DH 2, 5, 14. --trans is not supported with --ikev2.
sudo ike-scan --ikev2 $IKE_OPTS "$T" | tee "evidence/${T}_ike_v2.txt"
```

- An SA_INIT reply shows the one transform set the responder chose from the
  offer. DES, MD5 or group 2 chosen means a MUST NOT or SHOULD NOT algorithm is
  enabled.
- `INVALID_KE_PAYLOAD` (17) names the DH group the responder wants. One
  re-run with `--dhgroup=<that group>` (MODP only) is still Stage A; more is
  enumeration.
- `NO_PROPOSAL_CHOSEN` (14): IKEv2 listener present, legacy set refused.
- `COOKIE` (16390): the responder is challenging half-open load. Back off; you
  are part of that load.
- `SIGNATURE_HASH_ALGORITHMS` (16431) and `CERTREQ` hint at certificate auth.
- ike-scan's IKEv2 support is marked experimental and sends only the default
  proposal. Deeper IKEv2 proposal mapping needs a hand-built SA_INIT; keep it to
  the same per-host budget.

**IKEv2 stops at SA_INIT in Stage A.** The responder sends its certificate,
and with EAP its identity, only in IKE_AUTH after you send an identity. That
is an authentication attempt and Stage B. Claims of IKEv2 EAP username
enumeration have no public write-up we could find **(verify)**; if you pursue
one under sign-off, prove it with a valid-versus-invalid differential, not a
single reply.

### nmap traps for IKE and tunnel ports

| Script or probe | Declared categories | What it actually sends |
|---|---|---|
| `ike-version` | `default`, `discovery`, `safe`, `version` | Main Mode, then **two Aggressive Mode packets with ID `vpngroup`** (DH 2, then DH 1). It spends your AM budget, and `-sC` against 500/udp fires it. |
| `pptp-version` | `version` | One Start-Control-Connection-Request. Stage A. |
| `-sV` UDP probes `IKE_MAIN_MODE`, `IPSEC_START` | n/a | Legacy DES/3DES Main Mode proposals. Opens responder state like ike-scan does. |
| `-sV` probes `OpenVPN` (UDP and TCP), `OPENVPN_PKI` | n/a | A client hard-reset. A reply means the server answers unauthenticated control packets. |
| `-sV` probe `L2TP_ICRQ` | n/a | Despite the name, an SCCRQ with host name `nxp-scan`. Leaves a half-open L2TP tunnel until timeout. |
| service name `sstp` | n/a | Sakura Script Transfer Protocol. Not Microsoft SSTP. |

As in `hunt-exposed-services`: no `-sC`, no `-A`, name every script and check it
with `nmap --script-help <name>` first.

---

## Step 5: Stage A for the other tunnels

One request per protocol per host, `probe_delay` between them.

**PPTP (1723/tcp).** `nmap -Pn -sT -sV -p 1723 --script pptp-version "$T"`.
The Start-Control-Connection-Reply carries vendor, firmware and host name. A
reply is the finding: MS-CHAPv2, the usual PPTP authentication, reduces to a
single DES key (chapcrack, DEF CON 20, 2012), and Microsoft Security Advisory
2743314 tells customers to move off PPTP with MS-CHAPv2. The auth method is
negotiated in PPP after a call is set up, which is beyond Stage A, so say in
the report that MS-CHAPv2 is assumed unless the client shows EAP-TLS. GRE
reachability is not testable without a call; 1723 alone is enough to report.

**L2TP (1701/udp).** `sudo nmap -Pn -sU -sV -p 1701 "$T"`. A Start-Control-
Connection-Reply to a bare SCCRQ means L2TP answers **outside IPsec**: in a
correct L2TP/IPsec deployment 1701 is only reachable inside ESP. The SCCRP's
Host Name and Vendor Name AVPs fingerprint the stack. L2TP has no encryption of
its own. SoftEther's raw L2TP mode answers exactly like this, which is the
CVE-2026-39312 surface (matrix).

**OpenVPN (1194, 443).** `sudo nmap -Pn -sU -sV -p 1194 "$T"` and
`nmap -Pn -sT -sV -p 1194,443 "$T"`. A hard-reset reply means **no tls-auth or
tls-crypt**: the server runs its control channel and TLS handshake for
anyone, so parsing bugs there need no key. Silence means tls-auth/tls-crypt, or not OpenVPN;
you cannot tell which, and that indistinguishability is the point of the
option. OpenVPN puts no version on the wire, so every OpenVPN CVE row is
unconfirmable externally unless an Access Server web banner gives it away
(`Server: OpenVPN-AS` belongs to `hunt-exposed-panels`). On a management
interface, read the first line and send nothing: `>INFO:OpenVPN Management
Interface Version` on connect means no password is set (`manage.c` only sends
it unprompted then), `ENTER PASSWORD:` means one is. The console can
disconnect users and list who is connected.

**WireGuard (51820/udp or any).** Silent by design: the protocol description
says the server "does not even respond at all to an unauthorized client". There
is no active confirmation. Presence comes from leaked client configs
(`Endpoint = vpn.example.com:51820`, `PublicKey = <base64-key>`), DNS names
and documentation. A host that returns ICMP port-unreachable for a neighbouring
closed UDP port but nothing for the WireGuard port suggests a listener or a
filter, no more. **Never** try to provoke a cookie reply: it is sent under
load, and producing that load is a DoS. An exposed WireGuard port is not a
finding. A leaked private key is, via `hunt-source-leak`.

**SSTP, SoftEther, Tailscale DERP and Headscale, ZeroTier.** Probes and
reading in `references/other-tunnels.md`. In one line each:

| Protocol | Stage A | Finding when |
|---|---|---|
| SSTP (443/tcp) | One `SSTP_DUPLEX_POST` to the fixed `/sra_{...}/` URI | Never alone; TLS issues go to `hunt-tls-network` |
| SoftEther (443, 992, 1194, 5555/tcp) | `-sV` match `SoftEther VPN httpd` | Raw L2TP on the same host; default PSK test is Stage B |
| DERP (443/tcp) | `GET /`, `/generate_204`, `/debug/` status code | `/debug/` answers 200 from the internet |
| ZeroTier (9993/tcp) | `GET /status` status code | 401 from the internet: management API reachable |

---

## Step 6: Version gates

`references/vpn-cve-matrix.md` lists the 2024-2026 CVEs with the columns that
decide what you can say: pre-auth or not, confirmable from Stage A or not, and
the stage a check would need. **Almost nothing here is confirmable from Stage
A.** IKE vendor IDs give a vendor, not a build; OpenVPN gives nothing; nearly
every server-side CVE is a DoS, needs a specific feature (EAP, tls-crypt-v2,
post-quantum IKEv2 ciphers) or needs credentials. So:

- Report "vendor X present, IKEv2 enabled, version unknown" or "version in
  range, unconfirmed". Never "vulnerable".
- For Cisco ASA/FTD, FortiGate, PAN-OS and Check Point, get the version through
  `enterprise-vpn-attack`'s web fingerprinting of the same appliance.
- **Never send a crafted packet for a DoS-class CVE.** It is Stage B, and the
  honest default answer is to decline it: confirming means reloading a
  production VPN concentrator and dropping every remote worker on it.

---

## Step 7: Stage B, gated

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the host and a window. Record this before the first packet:

```
Stage B authorization
  Host/port:     192.0.2.10:500/udp
  Action:        IKEv1 Aggressive Mode group-name enumeration, 40-name list
  Blast radius:  40 half-open SAs on a production gateway; IPS alerts; possible
                 source shun; responder logs every ID tried
  Reversibility: state ages out; log entries remain
  Window:        <date/time>
  Authorized by: <operator name/role>, in writing, <link to the message>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| AM group-name enumeration | Half-open SA per name, IPS alerts, possible shun of your source. |
| PSK cracking, offline | Produces a live shared secret for a production gateway. With XAUTH the PSK is a group secret, and knowing it lets an attacker pose as the gateway to clients. |
| XAUTH or EAP credential attempts | Account lockout on the backing directory. `hunt-brute-force` rules apply. |
| IKEv2 IKE_AUTH with any identity | Authentication attempt in the logs; the responder certificate and EAP identity come back. |
| SoftEther default PSK, any default VPN credential | Completes phase 1 if right: the start of a tunnel. |
| DERP relay use to test `--verify-clients` | Your traffic through the client's relay. |
| Tunnel establishment with any leaked or cracked material | An internal-network position. Usually outside scope entirely. |
| Any DoS-class CVE check | Reload of the concentrator, all sessions dropped. Decline by default. |

Stage B, written sign-off required. Group-name enumeration, list of 50 names or fewer:

```bash
while read -r gid; do
  sudo ike-scan --aggressive --retry=1 --id="$gid" --trans="$ACCEPTED" --dhgroup="$DHG" "$T" \
    | grep -E "Aggressive Mode Handshake|INVALID-ID|NO-PROPOSAL" | sed "s/^/$gid: /"
  probe_delay
done < groupnames.txt | tee "evidence/${T}_am_enum.txt"
```

If the responder hashes every ID, hash presence cannot enumerate. IKEForce used
other signals (a Cisco DPD vendor ID only for valid groups, `INVALID-ID` for
invalid ones); it is archived, so check it still runs before relying on it.

Stage B, written sign-off required. Offline PSK cracking on the tester's own machine, bounded wordlist and runtime:

```bash
psk-crack -d wordlist.txt "evidence/${T}_am_psk_params.txt"
# hashcat: mode 5400 for an SHA1 PRF, 5300 for MD5; check the input format on your build.
hashcat -m 5400 -a 0 --runtime=3600 "evidence/${T}_am_psk_params.txt" wordlist.txt
```

A cracked PSK is reported redacted (length, first and last character) and is
never used to bring up a tunnel unless that is a separate signed action.

---

## Step 8: Grade by what you proved

| What you proved | Grade |
|---|---|
| AM + PSK hash returned for a real group ID: public (client profile, docs) or found by Stage B enumeration | High |
| AM + PSK hash cracked under sign-off | High; Critical only if the PSK alone authenticates (no XAUTH, no certificate) |
| AM + PSK hash returned only for your made-up ID | Medium: a wildcard PSK or a decoy, and only Stage B tells them apart. Say so. |
| AM enabled with PSK, `INVALID-ID-INFORMATION` for unknown IDs | Medium (Tenable plugin 62694 rates this class Medium, CVSS 3 5.3) |
| PPTP control channel answering on 1723 | Medium |
| L2TP answering on 1701 without IPsec | Medium |
| OpenVPN management interface reachable | High behind `ENTER PASSWORD:`; Critical when it greets with `>INFO:` unprompted |
| DERP `/debug/` or ZeroTier API reachable from the internet | Medium |
| IKE accepts an RFC 8247 MUST NOT algorithm (DES, MD5 PRF or integrity, DH group 1) | Medium if it is what a default client negotiates, Low if a stronger option is also accepted |
| IKE accepts only SHOULD NOT or MAY tier (3DES, DH group 2 or 5) | Low |
| IKEv1 enabled at all (RFC 9395 deprecates it) | Informational to Low, hardening |
| OpenVPN answers without tls-auth or tls-crypt | Low, hardening: unauthenticated reach into the TLS stack |
| Vendor or version in a CVE range, not exploited | Medium for a pre-auth RCE row, otherwise Low; always labelled unconfirmed |
| Vendor IDs, backoff fingerprint, SSTP or SoftEther presence alone | Informational |

### What is NOT a finding

- 500/udp or 4500/udp open with IKEv2, certificate auth and modern transforms.
- `NO-PROPOSAL-CHOSEN` to the legacy set. That is the correct behaviour.
- A WireGuard port, open or silent. A tls-auth OpenVPN that never answers.
- A hash from an RSA-signature Aggressive Mode exchange: nothing to crack.
- 3DES offered alongside AES when AES is what gets negotiated: RFC 8247 still
  allows 3DES (MAY). Mention it, do not headline it.
- A version string in a CVE range, presented as "vulnerable".
- Windows OpenVPN client CVEs (CVE-2024-27903, 27459, 24974): local, not
  reachable through 1194.
- strongSwan CVE-2025-62291: client-side, not a perimeter server issue.

---

## Step 9: Evidence

Follow `evidence-hygiene`. Per finding: exact command, source IP, raw output
saved at probe time, and the transform or notify that proves the point. For AM,
the report shows that a hash came back and its type; the `--pskcrack` file stays
a stored secret. No cracked key in clear, no tunnel traffic, no client lists.

---

## Chain table

| Confirmed | Standalone | Where it goes next |
|---|---|---|
| AM + PSK hash returned | High for a real group ID, Medium for a made-up one | Stage B crack only with sign-off. Report regardless. |
| Group name found in a public client profile | Raises the AM finding | `hunt-source-leak` for the leak itself. |
| PPTP or raw L2TP exposed | Medium | Report the protocol. No credential attempts. |
| Weak IKE transforms | Low to Medium | Combine with AM into one IKE configuration finding. |
| Cisco, Fortinet, Palo Alto or Check Point IKE fingerprint | Informational | `enterprise-vpn-attack` for version and the web-side CVEs. Check Point CVE-2024-24919 is HTTPS (`/clients/MyCRL`), exposed when the IPsec VPN blade sits in a Remote Access community or Mobile Access is on: it belongs there, not here. |
| OpenVPN without tls-auth plus a version leak | Low to Medium | Matrix row for the version; no DoS test. |
| SoftEther with raw L2TP | Medium, plus CVE-2026-39312 surface | Version unknown: report as unconfirmed. |
| DERP or ZeroTier management reachable | Medium | Report. Do not use the relay or the API. |
| TLS weakness on SSTP, OpenVPN-over-TLS or DERP | Per `hunt-tls-network` | Separate finding. |

---

## Validation checklist

- [ ] Probed from a public address outside every client range; egress IP recorded.
- [ ] Every IP confirmed client-owned and in the signed scope; provider-managed
      gateways cleared against the provider's testing policy.
- [ ] Every claimed listener answered with a protocol reply, not `open|filtered`.
- [ ] Per-host IKE budget kept: one attempt per probe, about 20 packets, at most
      three Aggressive Mode packets including nmap's.
- [ ] The AM probe used the transform Main Mode accepted, so a NO-PROPOSAL was
      not mistaken for "AM disabled".
- [ ] The AM ID was a non-guess; no real group name was tried outside Stage B.
- [ ] The `--pskcrack` file is stored as a secret and absent from the report body.
- [ ] Transform findings cite the RFC 8247 tier of the algorithm accepted.
- [ ] No `-sC`, `-A` or category selection; `ike-version` counted against the AM budget.
- [ ] No IKE_AUTH, XAUTH, EAP, default PSK or token attempt without a logged sign-off.
- [ ] No crafted packet for any DoS-class CVE was sent.
- [ ] Version rows labelled unconfirmed; OpenVPN and WireGuard not over-claimed.
- [ ] The report ends at exposure and impact. No tunnel was brought up.

---

## Sources

External sources used:

- ike-scan: <https://manpages.debian.org/trixie/ike-scan/ike-scan.1.en.html>, <https://github.com/royhills/ike-scan>; nmap: <https://nmap.org/nsedoc/scripts/ike-version.html>, <https://nmap.org/nsedoc/scripts/pptp-version.html>
- RFC 8247: <https://www.rfc-editor.org/rfc/rfc8247.html>; RFC 9395: <https://www.rfc-editor.org/rfc/rfc9395.html>; WireGuard: <https://www.wireguard.com/protocol/>
- MS Security Advisory 2743314: <https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2012/2743314>; Tenable 62694: <https://www.tenable.com/plugins/nessus/62694>
- IKEForce (archived): <https://github.com/SpiderLabs/ikeforce>; hashcat modes 5300/5400: <https://hashcat.net/wiki/doku.php?id=example_hashes>
- strongSwan config reference: <https://docs.strongswan.org/docs/latest/config/strongswanConf.html>; DERP and ZeroTier sources in `references/other-tunnels.md`

---

## Related Skills & Chains

- `enterprise-vpn-attack`: owns the SSL VPN web stack of the same appliances,
  and the version fingerprinting this skill cannot do over IKE.
- `infra-external-methodology`: owns scope, the discovery plan and the
  port-to-skill routing table that sends 500, 4500, 1701, 1723 and 1194 here.
- `hunt-brute-force`: every credential attempt (XAUTH, EAP, management
  passwords, default PSKs). Offline PSK cracking follows its discipline too.
- `hunt-tls-network`: TLS findings on OpenVPN-over-TLS, SSTP and DERP.
- `hunt-exposed-services`: the template for staging and rate posture, and the
  owner of SNMP (Cisco CVE-2025-20352 is SNMP, not IKE) and other non-VPN ports.
- `hunt-exposed-panels`: OpenVPN Access Server, Headscale and ZeroTier
  controller web UIs.
- `hunt-source-leak`: leaked `.ovpn`, WireGuard and IPsec client profiles,
  group names and keys.
- `offensive-osint`, `recon-scope-triage`: discovery and scope, before Step 1.
- `evidence-hygiene`, `triage-validation`, `report-writing`: handling the PSK
  parameters file, false-positive gates, write-up.

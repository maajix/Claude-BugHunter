---
name: infra-voip-sip
description: "Triage internet-exposed VoIP and unified-communications infrastructure: SIP 5060/5061, H.323 1720, IAX2 4569, STUN/TURN 3478/5349, and the PBX or SBC behind them (Asterisk, FreePBX, FreeSWITCH, Kamailio, OpenSIPS, 3CX, Cisco CUCM, Mitel, Avaya, Teams Direct Routing SBCs). Stage A is one SIP OPTIONS fingerprint, one STUN binding request and a version gate against the KEV-listed PBX CVE matrix. Toll fraud, extension enumeration and TURN relay abuse are findings whose proof is Stage B. Never calls third parties or floods. Use when 5060, 5061, 1720, 4569 or 3478 is open or a header names a PBX."
metadata:
  sources: cisa_kev, github_security_advisories, asterisk_security_advisories, freepbx_security_advisories, nmap_nse_docs, rfc_3261, rfc_5389, microsoft_learn, authorized-engagement
  report_count: 0
---

## When to use

Trigger when recon has produced one of these on a host you are authorized to test:

- 5060/udp, 5060/tcp or 5061/tcp (SIP, SIPS) answering from a public address.
- 1720/tcp (H.323), 4569/udp (IAX2), 2000/tcp (SCCP), 2427/udp (MGCP).
- 3478/udp+tcp or 5349/tcp (STUN/TURN) on a host that is not a known conferencing
  provider edge.
- A TLS certificate, reverse-DNS name (`pbx.`, `sip.`, `voip.`, `sbc.`) or HTTP
  banner that names a PBX, SBC or softswitch.
- The client's asset list says "phone system" and the port answers you anyway.

Inherit host and port from `infra-external-methodology`. Confirm IP ownership
first. The provider edge of a cloud PBX (RingCentral, 8x8, Zoom Phone, Teams
Direct Routing from Microsoft's own ranges) is not the client's asset and is not
in scope; only an SBC or PBX the client operates is.

### Where the chain ends

This skill stops at **exposure confirmed, software and version identified, KEV
or pre-auth CVE gate evaluated, impact described**. For the two findings that
need an active proof (unauthenticated call routing and TURN relay abuse) it
defines what counts as proof and requires Stage B with written sign-off; it
does not contain the procedure. No calls are placed to any number the client
did not provide. No RTP is captured. No registration is attempted with anyone
else's credentials. No flood, no fuzzing, no DoS-class CVE check.

### Not covered here

- Extension enumeration and credential guessing against SIP registrars: the
  `legacy-and-infoleak.md` reference in `hunt-exposed-services` already routes
  this to `hunt-brute-force`. Treat `svwar`, `sipvicious` cracking and nmap
  `sip-enum-users` / `sip-brute` (categories `auth,intrusive` and
  `intrusive,brute`) as out of this skill.
- PBX web administration (FreePBX admin, 3CX management console, CUCM web,
  MiCollab portal): `hunt-exposed-panels` owns the web surface. This skill
  uses the web banner only as a version source.
- Phone handset web interfaces: same, `hunt-exposed-panels`.

---

## References Index

- `references/voip-cve-matrix.md` — product, CVE, affected, fixed, KEV date, source URL.
- RFC 3261 §11 (OPTIONS), RFC 5389 (STUN), RFC 8656 (TURN).
- CISA KEV catalog (2026.10.13 snapshot used for the dates above).
- nmap NSE script categories read from the local script headers: `sip-methods` (default, safe, discovery), `sip-enum-users` (auth, intrusive), `sip-brute` (intrusive, brute), `sip-call-spoof` (discovery, intrusive), `stun-info` (discovery, safe).
- Microsoft Learn, "Plan Direct Routing": signaling source ranges and SRTP requirement.

---

## Step 1 — Stage A: one fingerprint per protocol

Stage A is read-only, one request per service, and is the whole test for most
findings here. Rate posture: one SIP request and one STUN request per host,
then stop. SIP stacks behind `fail2ban` ban a source address after a handful
of failed or malformed requests, and a ban during an engagement is both a
burned IP and a log entry the client's SOC will ask about.

### SIP OPTIONS (5060/udp, 5060/tcp, 5061/tls)

OPTIONS is the capability query RFC 3261 §11 defines for exactly this purpose
and does not change state. The probe already lives in
`skills/hunt-exposed-services/references/legacy-and-infoleak.md` (printf to
`nc -u`); reuse it. Equivalent read-only alternatives:

```bash
# nmap: sip-methods is categorised default,safe,discovery
nmap -sU -sT -p 5060,5061 --script sip-methods <host>
# sipvicious svmap sends one OPTIONS per host (svwar/svcrack are not Stage A)
svmap <host>
```

Record from the response: `Server:` / `User-Agent:` (vendor and version),
`Allow:` (methods), `Supported:`, whether 5061 completes a TLS handshake and
with which certificate, and whether UDP and TCP answer differently. A `401`
or `407` to OPTIONS reveals the digest `realm`, which usually names the PBX or
domain; that is intelligence, not a finding.

### STUN binding (3478/udp)

One Binding Request (RFC 5389) is read-only and tells you whether the host is a
STUN server, a TURN server, or neither. nmap `stun-info` is `discovery,safe`;
`stun-version` is `version`.

```bash
nmap -sU -p 3478 --script stun-info,stun-version <host>
```

A STUN server that answers Binding Requests is normal and is not a finding.
A TURN server that grants relay allocations to unauthenticated clients, or
with long-term credentials that are published in a web bundle, is the finding
(see Step 3). Proving the allocation is Stage B.

### H.323 (1720/tcp), IAX2 (4569/udp), SCCP (2000/tcp)

Service-version detection only (`nmap -sV`, `iax2-version` is category
`version`). These protocols leak vendor and version in the handshake. Do not
send call setup messages.

### Version from the web side

If the same host serves FreePBX, 3CX, CUCM or MiCollab over HTTPS, the admin
page, `/admin/config.php` login banner, the UCP `x-pjax-version` meta tag
(FreePBX UCP module) or the CUCM `/ccmadmin` login page gives a version string
that the SIP banner often hides. Read it; do not log in. Hand the web surface
itself to `hunt-exposed-panels`.

---

## Step 2 — Version gate against the CVE matrix

`references/voip-cve-matrix.md` lists pre-auth and KEV-listed CVEs by product
with affected and fixed versions as published in the vendor or GitHub
advisories. The gate is version match only: a banner or web version inside an
affected range plus the port reachable from the internet. That is the report.
Do not run an exploit to "confirm"; a KEV entry plus a version string is what
triagers accept, and anything more is Stage B.

Highest-value gates as of 2026-10-13 (details and sources in the matrix):

| Product | CVE | What it is | KEV added |
|---|---|---|---|
| FreePBX endpoint module < 15.0.66 / 16.0.89 / 17.0.3 | CVE-2025-57819 | unauthenticated access to the endpoint module, exploited in the wild Aug 2025 | 2025-08-29 |
| FreePBX | CVE-2019-19006 | authentication bypass in the framework module | 2026-02-03 |
| Sangoma Switchvox | CVE-2026-9586 | (verify class in advisory) | 2026-09-02 |
| Cisco Unified CM | CVE-2026-20045, CVE-2026-20230 | (verify class in Cisco PSIRT) | 2026-01-21, 2026-06-25 |
| Mitel MiCollab | CVE-2024-41713 + CVE-2024-55550 | path traversal chain to arbitrary file read, unauthenticated | 2025-01 (verify) |
| Mitel SIP phones | CVE-2024-41710 | post-auth; exposure of the admin interface is the finding, not this CVE | 2025-02 (verify) |
| Mitel MiVoice | CVE-2022-26143 (TP240PhoneHome) | amplification via exposed test facility; an exposed 10074/udp is the finding | 2022 |
| Asterisk | CVE-2025-47779, CVE-2025-49832, CVE-2025-57767, June 2026 batch (fixed 20.20.1 / 21.12.3 / 22.10.1 / 23.4.1) | see matrix for pre-auth vs post-auth | not in KEV |
| Grandstream GXP1600 < 1.0.7.81 | CVE-2026-2329 | handset firmware | (verify) |
| coturn | CVE-2020-26262, CVE-2026-27624, CVE-2026-53450 | peer-ACL bypass: relay reaches loopback or internal ranges | not in KEV |

Pre-auth and post-auth matter for grading: a post-auth RCE on a PBX whose
admin page is on the internet is reported as "admin interface exposed" with
the CVE as supporting impact, not as the CVE itself.

---

## Step 3 — Findings this skill defines, and what proves them

| Finding | What Stage A already shows | What proves it (Stage B) |
|---|---|---|
| PBX or SBC reachable from the internet | OPTIONS answered with a vendor banner | Nothing more needed. Grade by Step 4. |
| KEV-listed or pre-auth CVE by version | banner / web version in affected range | Nothing more needed; version match is the proof. |
| Unauthenticated call routing (toll fraud) | `Allow:` includes INVITE and OPTIONS answered without a challenge; the digest `realm` is empty or absent | A single INVITE to a number **the client supplied for this purpose**, answered with 1xx/2xx and a ring on the client's side. Written sign-off naming the destination number and the time window. The procedure is not in this skill. |
| TURN relay open to the internet or to internal ranges | 3478 answers STUN; TURN `Allocate` without credentials returns 401 with a realm, or 200 | An `Allocate` that succeeds without credentials, or with credentials harvested from the client's own web bundle, and a `CreatePermission` to an RFC 1918 peer that is accepted. Written sign-off. Never relay real traffic. |
| SIP over cleartext with authentication | 5060/udp answers, 5061 does not; `WWW-Authenticate: Digest` on 5060 | Nothing more; report the downgrade exposure as Low unless chained. |
| RTP without SRTP | SDP in a 200 OK carries `RTP/AVP` and no `crypto=` or `RTP/SAVP` | Only observable in a call you are authorized to place; otherwise report "SRTP not offered" from the SDP of a Stage B call. |
| Amplification vector (TP240, SIP OPTIONS reflection) | response size vs request size from the single probe | One request/response pair is sufficient; do not measure at volume. |

Explicit prohibition: no INVITE to any number the client did not supply in
writing, no `REGISTER` with guessed or harvested credentials, no RTP capture of
calls you are not a party to, no `svwar`, no `sip-enum-users`, no `sip-brute`,
no fuzzing. Anything that places a call, allocates a relay or submits
credentials is Stage B and requires written sign-off before the first packet.

---

## Step 4 — Grade by what the exposure grants

| Observation | Typical severity | Why |
|---|---|---|
| OPTIONS answers, current version, TLS on 5061, digest challenge present | Informational | Expected for an SBC that must be reachable for trunks. Say so and move on. |
| Vendor and version banner only, no CVE match | Low | Information disclosure; most programs mark Info. |
| Version in KEV-listed pre-auth range | High to Critical | KEV plus internet reachability; CVSS from the advisory. |
| Admin web interface on the internet plus post-auth RCE CVE | High | Exposure is the root cause; the CVE is impact context. |
| Unauthenticated INVITE routed to the PSTN (proved under sign-off) | Critical | Direct financial loss (toll fraud), often hours to detect. |
| TURN relay reachable without credentials, peer ACL reaches internal ranges | High | Internal network pivot through a sanctioned relay. |
| SIP cleartext only, no 5061 | Low | Downgrade exposure; Medium if credentials are observed in your own authorized traffic. |
| STUN server answers Binding Requests | Not a finding | That is what STUN is for. |

Microsoft Teams Direct Routing: signaling arrives at the client's SBC from
`52.112.0.0/14` and `52.120.0.0/14` over SIP/TLS, media is SRTP (Microsoft
Learn, updated 2026-09). An SBC that answers OPTIONS from arbitrary sources
rather than only Microsoft's ranges is a configuration finding (Medium) even
when everything else is current.

---

## Honeypots and false positives

SIP honeypots are among the most common on the internet. Signals: a banner that
names an old Asterisk (1.x, 11.x) on a cloud address with no 5061, OPTIONS that
accepts every method, instant `200 OK` to anything, and a `Server:` string that
matches a known honeypot default. When two or more apply, report "probable
honeypot" and do not grade a CVE match from the banner.

---

## Chain table

| Chain | Steps | Severity |
|---|---|---|
| Version gate to KEV | OPTIONS banner → affected range → KEV entry | High/Critical |
| Web bundle secret to TURN relay | `hunt-source-leak` finds TURN long-term credentials in a JS bundle → 3478 reachable → Stage B allocation | High |
| Exposed PBX admin to account control | `hunt-exposed-panels` finds FreePBX/3CX login → default or leaked credentials (one gated attempt, `hunt-brute-force` rules) → extension and trunk configuration readable | High |
| Open OPTIONS to toll fraud | no challenge on INVITE-capable registrar → Stage B call to client-supplied number | Critical |

## Validation checklist

- [ ] IP ownership confirmed; not a cloud PBX provider edge.
- [ ] Exactly one OPTIONS and one STUN request sent per host; no bans triggered.
- [ ] Vendor and version captured from SIP banner, TLS certificate or web page, with the raw response saved (`evidence-hygiene`).
- [ ] CVE gate evaluated against `references/voip-cve-matrix.md`; affected and fixed versions quoted from the advisory, not from memory.
- [ ] Honeypot signals checked before grading any banner-based CVE.
- [ ] Every Stage B item (call, relay allocation, credential use) has written sign-off naming scope, destination and time window, or was not done.
- [ ] Report states what the exposure grants, not only that the port is open.

## Related Skills & Chains

- `infra-external-methodology` — supplies the host and port; master routing table.
- `hunt-exposed-services` — the SIP OPTIONS probe text and the rule that extension enumeration is `hunt-brute-force` territory.
- `hunt-exposed-panels` — PBX and phone web administration.
- `hunt-brute-force` — all credential and extension guessing.
- `hunt-source-leak` — TURN credentials and SIP trunk secrets in web bundles.
- `hunt-tls-network` — certificate and TLS findings on 5061/5349.
- `evidence-hygiene`, `triage-validation`, `report-writing`.

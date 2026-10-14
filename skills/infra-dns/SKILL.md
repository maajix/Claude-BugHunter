---
name: infra-dns
description: "Triage internet-exposed DNS servers the client owns, authoritative and recursive, on 53/udp and 53/tcp, DoT 853 and DoH. Covers the open recursive resolver (RFC 5358) proven with one canary query, cache snooping with RD=0 queries, version.bind, hostname.bind, id.server and NSID version disclosure, unauthenticated dynamic update (RFC 2136, gated), NSEC walking and NSEC3 hash exposure, DNSSEC misconfiguration, lame delegation, split-horizon internal zone leaks, the ANY amplification factor, EDNS and TCP fallback, and DNS on non-standard ports. Version gates for BIND, PowerDNS, Unbound, Knot, NSD, Microsoft DNS, dnsmasq and Technitium with 2024-2026 CVEs and CISA KEV status, including the October 2025 cache-poisoning wave and the BIND 9.18 end of life. Stage A is read-only, a handful of queries per server. Dynamic update, full zone walks, hash cracking and amplification beyond one measured query need written sign-off. Use when port 53 is open on an in-scope host or a client nameserver needs assessment."
metadata:
  sources: rfc, isc_advisories, nlnetlabs_advisories, powerdns_advisories, msrc, cisa_kev, cve_org, nmap_nsedoc, bugcrowd_vrt, hackerone_docs, authorized-engagement
  report_count: 0
---

## When to use

Trigger when recon has produced a DNS listener on an address you are authorized
to test, and you need to decide whether it is a finding. The finding here is a
**misconfiguration of the server itself**: who it answers, what it reveals, what
it lets a stranger change, and which advisories its version sits under.

Use when any of these is true:

- A port scan shows 53/udp or 53/tcp open on an in-scope host, or `domain` is
  fingerprinted on another port (5300, 8053, 853, or anything odd).
- The client's own nameservers (not a DNS provider's) serve their zones.
- A `version.bind` answer, an SOA MNAME or a reverse-DNS name names a BIND,
  PowerDNS, Unbound, Knot, NSD, Windows DNS, dnsmasq or Technitium server.
- An edge device (firewall, router, VPN concentrator) answers DNS on its
  external interface.

**Do not use this skill for discovery or for record-level hunting.** Host and
port discovery belong to `offensive-osint` and `web2-recon`; scope confirmation
to `recon-scope-triage`. This skill starts from "a DNS server is answering and
it is the client's".

### Where the chain ends

This skill stops at **misconfiguration confirmed, impact described, evidence
captured**. It never poisons a cache, never floods, never runs amplification at
volume, never spoofs a source address, and never fires a crash PoC at a
production nameserver. A DNS outage takes every service on the domain with it.

Three cuts the public write-ups walk straight past:

- Open resolver: stop at one proving query. Measuring how hard it can be made to
  reflect is a DDoS rehearsal.
- Dynamic update: stop at a canary TXT record you add and remove under sign-off.
  Repointing a real name, an MX, or an `_acme-challenge` label to mint a
  certificate is the attack, not the proof.
- Cache-poisoning CVEs: a version in range is the finding. Racing spoofed
  answers at a live resolver poisons real users.

### Not covered here, on purpose

| Topic | Owner |
|---|---|
| AXFR / IXFR zone transfer, its procedure and grading | `hunt-tls-network` Phase 3 |
| Dangling CNAME and NS records, subdomain and NS-delegation takeover | `hunt-subdomain`, `hunt-tls-network` Phase 6.5 |
| SPF, DKIM, DMARC, CAA, certificates on DoT/DoH | `hunt-tls-network` |
| mDNS 5353/udp, LLMNR, NetBIOS name service | `hunt-exposed-services` (`references/legacy-and-infoleak.md`) and `SECURITY.md` exclusions |
| DNS rebinding and SSRF through a resolver | `hunt-ssrf` |
| Technitium (5380/53443) and PowerDNS (8081/8082) web consoles and APIs | treat as an exposed panel, `hunt-exposed-panels` method |
| Active Directory behind an exposed DC's DNS | out of scope, `SECURITY.md` |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/dns-server-cve-matrix.md` | BIND 9 (2024-2026, 9.18 EOL), PowerDNS Recursor and Authoritative, Unbound, NSD, Knot DNS and Knot Resolver, dnsmasq, Technitium, Windows DNS Server; KEV status; the October 2025 poisoning wave; how to read a version string | bind version vulnerable, cve-2025-40778, cve-2025-40780, cve-2025-11411, cve-2025-59023, bind 9.18 eol, windows dns server rce, cve-2026-62878, dnsmasq 2.92, unbound 1.26.1, keytrap, dns kev |
| `references/zone-and-dnssec-checks.md` | DNSSEC validation with delv and DNSViz, NSEC walking (a handful vs full), NSEC3 parameters and hash cracking, lame delegation, dangling NS hand-off, split-horizon leak queries, EDNS/TCP/DoT/DoH checks | nsec walking, nsec3 hashes, nsec3param, dnssec bogus, lame delegation, dangling ns, split horizon leak, internal zone exposed, _msdcs external, edns compliance, dns over tcp, dot 853 |

---

## Step 1 — Prove the server is the client's, and learn its role

Five scope errors kill more DNS findings than anything else. Clear all of them
before the first query that is not a plain SOA lookup.

| Check | How | Why it matters |
|---|---|---|
| IP ownership | ASN + WHOIS/RDAP + reverse DNS, cross-checked with the signed scope | Nameservers often sit in a hoster's or ISP's range. |
| Not a public anycast resolver | 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 208.67.222.222 and their peers answer everyone **by design** | Never test them. An "open resolver" there is the product, not a finding. |
| Not a DNS provider's nameserver | NS names under `awsdns-*`, `*.ns.cloudflare.com`, `*.azure-dns.*`, `ns-cloud-*.googledomains.com`, `*.nsone.net`, `*.ultradns.*`, `*.akam.net` | The provider's infrastructure, not the client's. The single most common scope error in this class. |
| Not customer equipment | For an ISP or hoster client: open forwarders on customer routers in the client's ranges | Not the client's server unless the scope names CPE explicitly. |
| Not a honeypot or sensor | Answers garbage instantly, identity strings change between queries, every name resolves to one address | Research sensors and DNS honeypots are common on 53. |

Probe from an external vantage outside every client VPN, and record the egress
IP. Note anycast: one IP can be many servers, so `id.server` or NSID may differ
between queries, and a version gate applies to the instance that answered.

Then learn the role, because every later step reads differently by role:

```bash
NS="192.0.2.53"; ZONE="client.example"
Q="+tries=1 +timeout=3 +norecurse"

dig $Q @"$NS" "$ZONE" SOA | grep -E 'status|flags|SOA'
# flags include "aa"     -> authoritative for the client's zone
# SOA MNAME              -> the primary; updates and AXFR are aimed there
```

Authoritative-only, recursive-only, a forwarder, or both on one listener: the
last is the classic misconfiguration and Step 2.2 tells you which you have.

### Rate posture for every step in this skill

Serial, one server at a time, **at most one query per second**, `+tries=1` so dig
does not retry on its own, and a budget of roughly 25 Stage A queries per server
for the whole engagement. No loops over wordlists or name lists.

```bash
pace() { sleep 1; }   # between every query; never parallelise across one server
```

This repo's throttle does not see `dig`, `delv`, `kdig`, `nsupdate` or `n3map`
(neither governed nor refused in `engine/throttle.py`), so the ceiling is yours to
keep. `nmap` is in its ungoverned list and is refused while a request ceiling is
set; use the dig forms below instead.

---

## Step 2 — Stage A: the complete read-only probe set

Stage A is every probe in this step and nothing else. Each one is a single
standard query that reads, writes nothing, and cannot change the server's state
beyond one cache entry the server would create for any client.

### 2.1 Identity and version (CHAOS class and NSID)

```bash
for n in version.bind version.server hostname.bind id.server; do
  dig $Q @"$NS" CH TXT "$n" | grep -E 'status|TXT' | tee -a "evidence/${NS}_chaos.txt"
  pace
done
dig $Q +nsid @"$NS" "$ZONE" SOA | grep -E 'NSID|status' | tee -a "evidence/${NS}_chaos.txt"

# Only if version.bind said dnsmasq: servers.bind lists its configured upstreams
dig $Q @"$NS" CH TXT servers.bind +short
```

If nothing answers, `fpdns -r 1 "$NS"` gives a behavioural guess from a short
series of unusual-header queries (`-p <port>` for odd ports). Its README calls it
unmaintained and unreliable: corroboration, never the sole basis for a CVE.

### 2.2 Open recursion: one query that proves it

The strongest proof is a unique name under a domain **you** run (your own
authoritative server, Burp Collaborator, or interactsh), asked with RD=1:

```bash
CANARY="rec-$(date +%s)-$RANDOM.oob.your-domain.example"
dig +tries=1 +timeout=5 +recurse @"$NS" "$CANARY" A | tee "evidence/${NS}_recursion.txt"
```

A query for that exact name arriving at your server proves recursion beyond
argument, from a name the client does not host, and its source IP is the
resolver's real egress (a different IP means a forwarder chain; a Google or
Cloudflare egress means it forwards to a public resolver). With no callback
host, one RD=1 query for a well-known name the client does not host
(`example.org A`) is the fallback; read it with Step 3.1.

### 2.3 Cache snooping: one RD=0 query

Pick **one** name only the client's own users would plausibly resolve: their
SaaS tenant (`<client>.okta.com`, `<client>.sharepoint.com`), their VPN or EDR
vendor's update host, a partner portal. A top-50 site proves nothing.

```bash
dig $Q @"$NS" "client-tenant.saas.example" A | tee "evidence/${NS}_snoop.txt"
# Reference TTL from the name's own authoritative server (not the client's):
AUTH=$(dig +short NS saas.example | head -1)
dig +noall +answer +norecurse @"$AUTH" "client-tenant.saas.example" A
```

### 2.4 Amplification factor: one measured query

```bash
dig $Q +ignore +qr +bufsize=4096 @"$NS" "$ZONE" ANY \
  | grep -E 'QUERY SIZE|MSG SIZE|status|flags' | tee "evidence/${NS}_any.txt"
# factor = MSG SIZE rcvd / QUERY SIZE, measured once
```

`+ignore` keeps the UDP answer even when it is truncated, so you measure what a
reflector would send rather than the TCP retry. Send it once. A server that
answers ANY with a single HINFO or one RRset implements RFC 8482: record that as
the result and do not go looking for the largest RRset in the zone.

### 2.5 Zone, DNSSEC and transport checks

Load `references/zone-and-dnssec-checks.md`. It holds the Stage A forms of:
DNSSEC validation from your own resolver (`delv`, `dnsviz`), an NSEC walk of at
most five names, NSEC3 parameters, lame delegation, split-horizon leak queries
(SOA MNAME, `_msdcs` SRV, RFC 1918 reverse), and the EDNS / TCP / DoT checks of
RFC 8906 style.

### 2.6 DNS on non-standard ports

If recon fingerprints `domain` on any port other than 53, run 2.1 and 2.2 with
`-p <port>`. A resolver on 5353/tcp, 5300 or 8053 is usually a forgotten
forwarder, a dev instance or a container's resolver published by mistake. Port
853 is DoT (`dig +tls`); a `/dns-query` path on 443 is DoH (`dig +https`), which
here is a fingerprint plus, at most, one Step 2.2 query.

### NSE scripts: what they actually do

Verified against the script headers shipped with nmap 7.991. Name scripts
individually; never `-sC` or `-A`.

| Script | Declared categories | Use here |
|---|---|---|
| `dns-nsid` | `discovery`, `default`, `safe` | Fine; same as `dig +nsid`. |
| `dns-recursion` | `default`, `safe` | Sends RD=1 for `www.wikipedia.org` and only checks header bits. It reports SERVFAIL-with-RA as "recursion enabled". Never cite its output alone. |
| `dns-cache-snoop` | `intrusive`, `discovery` | Default list is 50 popular domains (50 queries); `timed` mode **inserts entries into the cache**. Use the single dig query in 2.3. |
| `dns-update` | `vuln`, `intrusive` | **Writes records.** Its test mode adds and deletes four records under `cqure.net`. Stage B, and replace it with the canary in Step 5. |
| `dns-nsec-enum`, `dns-nsec3-enum` | `discovery`, `intrusive` | Full zone walks. Stage B. |
| `dns-zone-transfer` | `intrusive`, `discovery` | AXFR: `hunt-tls-network` Phase 3. |
| `dns-random-srcport`, `dns-random-txid` | `external`, `intrusive` | Make the target query `porttest.dns-oarc.net`, which returned NXDOMAIN on 2026-10-13: dead, and they relay to a third party. Do not use. |
| `dns-fuzz` | `fuzzer`, `intrusive` | Forbidden. It is a crash tool. |
| `dns-brute`, `dns-ip6-arpa-scan` | `intrusive`, `discovery` | Name enumeration loops; belongs to recon skills, not here. |

---

## Step 3 — Read the answers

### 3.1 Open resolver

| What came back for an out-of-zone name | Verdict |
|---|---|
| Canary query seen at your authoritative server | **Open recursion, proven.** |
| `NOERROR`, `ra` set, no `aa`, answer section populated | Open recursion (or a cache answer, which is the same exposure). |
| `REFUSED`, with or without `ra` | Closed. `ra` alone means nothing. |
| `SERVFAIL` with `ra` | Inconclusive. Recursion configured but failing or ACL-blocked late. Not reportable. |
| `NOERROR`, empty answer, root NS in authority | Upward referral from an authoritative-only server. Not recursion. |

What the finding is: the server resolves arbitrary names for anyone (RFC 5358,
BCP 140), so it can be used as a reflector against third parties, and it lets
any off-path attacker **trigger** resolution, which every cache-poisoning attack
needs. If the version string falls in a 2025-2026 poisoning range (Step 4), say
both facts together; that overlap is what makes the report land.

### 3.2 Cache snooping

| RD=0 reply | Reading |
|---|---|
| Answer present, no `aa`, TTL below the authoritative TTL | **Cached**: a client of this resolver looked the name up within the TTL. |
| Answer present with `aa` | The server is authoritative for it; nothing about users. |
| Referral, empty answer, or `REFUSED` | Not cached, or RD=0 cache reads are blocked. |

Evidence value depends on who uses the resolver. If it is open to the whole
internet, its cache reflects the internet and proves little. If recursion is
locked to internal clients but RD=0 cache reads are still answered to you, the
cache shows what the client's staff resolve: the finding stands on its own.

### 3.3 Identity and version

`version.bind` alone is **Informational** (HackerOne Core Ineligible:
"Software version disclosure / Banner identification issues"; Bugcrowd VRT
banner disclosure P5). It earns more only through Step 4, or when the identity
leaks something else: `hostname.bind`/`id.server` returning an internal FQDN
(Knot's default identity is the FQDN hostname), or dnsmasq `servers.bind`
listing internal upstream resolver addresses.

### 3.4 Amplification

Report the factor from the one measurement, the query type and the server role.
An authoritative server returning large answers **for its own zones** is doing
its job; the reportable case is amplification combined with open recursion.
Response Rate Limiting cannot be observed without sending volume, so never write
"no RRL". Grade at Medium at most, matching the amplification rules in
`hunt-exposed-services/references/legacy-and-infoleak.md`: the impact lands on
third parties, not on the client's confidentiality or integrity.

### What is not a finding

| Observation | Why not |
|---|---|
| `version.bind` with nothing else | Banner disclosure; ineligible or P5 on both major platforms. |
| Missing DNSSEC | Bugcrowd VRT P5. |
| NSEC3 with 0 iterations and an empty salt | Exactly what RFC 9276 recommends. |
| NSEC "white lies" / synthetic next names | Minimally covering NSEC (RFC 4470); not walkable. |
| NSEC walk revealing only public names | Nothing disclosed that the web does not already show. |
| Authoritative server answering large DNSKEY/ANY for its zones | By design. |
| `ra` bit with `REFUSED` or `SERVFAIL` | No recursion was performed for you. |
| Differing `id.server` / NSID across queries | Anycast or load balancing; normal. |
| Open recursion on a public anycast resolver or a provider NS | Not the client's server. |
| A Windows DNS version string | An OS build, not a patch level. |

---

## Step 4 — Version gates

Load `references/dns-server-cve-matrix.md`, match the Step 2.1 string, and
report "in the affected range, unconfirmed". The facts that change verdicts:

- **BIND 9.18 is end of life since 2026-07-01** (9.18.50 was the last release).
  Any 9.18 banner is unpatched for the July and September 2026 batches, which
  include a DNSSEC validation bypass with no 9.18 fix (CVE-2026-13321, CVSS 8.6).
- **October 2025 cache-poisoning wave**, resolvers only: BIND CVE-2025-40778 and
  CVE-2025-40780 (fixed 9.18.41 / 9.20.15), Unbound CVE-2025-11411 (fixed
  1.24.2), PowerDNS Recursor CVE-2025-59023 and CVE-2025-59024. Public PoC for
  CVE-2025-40778 since 2025-10-28.
- **Pre-auth RCE class in 2026**: Windows DNS Server CVE-2026-62878 (Aug) and
  CVE-2026-69730 (Sep), both CVSS 9.8; Unbound CVE-2026-33278 and
  CVE-2026-81642 (possible RCE in DNSSEC validation); Knot Resolver
  CVE-2026-66374 (DoQ only).
- **KEV (catalog 2026.10.13)** lists only two DNS-server CVEs: CVE-2020-1350
  (SIGRed) and CVE-2015-5477 (BIND TKEY, added 2026-10-08). A BIND banner below
  9.9.7-P2 or 9.10.2-P3 is now a KEV item. Nothing from 2024-2026 is listed.

Two rules on top: a distro suffix (`-Debian`, `-RH`, `-Ubuntu`) means backports,
so check the distro tracker before writing "vulnerable"; and a Windows DNS string
never maps to a CVE.

---

## Step 5 — Stage B: anything that changes state or sends volume

Stage B is **blocked by default**. It requires explicit written operator
sign-off naming the action, the server, the zone and a window. A verbal yes, a
chat thumbs-up or "critical findings are in scope" is not sign-off.

```
Stage B authorization
  Server/zone:   192.0.2.53 / client.example
  Action:        RFC 2136 UPDATE adding one TXT canary, then removing it
  Blast radius:  writes to the live zone; bumps the SOA serial and triggers
                 NOTIFY to every secondary; the change is logged; a zone with
                 DNSSEC is re-signed on the fly
  Reversibility: canary removed by a second UPDATE; serial bump is permanent
  Window:        <date/time>
  Authorized by: <name/role>, in writing, <link>
```

| Action | Blast radius to name in the sign-off |
|---|---|
| Any RFC 2136 UPDATE, including a prerequisite-only one | A write path into the authoritative zone. Even a no-op is processed by the update machinery and logged as one. |
| Canary TXT add and remove | SOA serial change, NOTIFY and transfer to all secondaries, on-the-fly re-signing. |
| Full NSEC walk or NSEC3 hash collection | Thousands of queries against the server; the AXFR-equivalent disclosure itself. |
| NSEC3 hash cracking | Produces the full name list offline. |
| Amplification measurement beyond the single Step 2.4 query | Volume aimed through a reflector. Almost never needed: the one ratio is the evidence. |
| Any exploit or PoC for a matrix CVE | Production DNS outage for every service on the domain. |

**Forbidden outright, sign-off or not:** cache poisoning or spoofed-response
races, source-address spoofing, flooding or sustained queries, RRL probing by
volume, crash PoCs (KeyTrap, assertion CVEs, `dns-fuzz`), and any UPDATE that
touches a real name.

### Dynamic update test

Passive groundwork is Stage A: the SOA MNAME (Step 1) is the primary that
accepts updates, and a Windows zone set to "Nonsecure and secure" is the classic
cause. The probe itself is Stage B.

```bash
# Stage B: requires the signed block above. TCP, one zone, one canary name.
CANARY="cbh-canary-$(date +%s).$ZONE"
nsupdate -v <<UPD
server $NS
zone $ZONE
prereq nxdomain $CANARY
update add $CANARY 60 TXT "authorized security test canary"
send
UPD
dig $Q @"$NS" "$CANARY" TXT +short     # present = unauthenticated update accepted
```

```bash
# Stage B cleanup, same sign-off: remove the canary immediately and confirm.
nsupdate -v <<UPD
server $NS
zone $ZONE
update delete $CANARY TXT
send
UPD
dig $Q @"$NS" "$CANARY" TXT | grep status   # expect NXDOMAIN
```

Reading the reply: `REFUSED` means the update ACL said no, which is the healthy
answer. `NOTAUTH` means the server is not the primary or wants TSIG. A
secondary may forward the update to the primary (BIND `allow-update-forwarding`),
so confirm on the primary which server accepted it. A prerequisite-only UPDATE
is a weaker probe whose meaning differs by implementation: RFC 2136 orders the
prerequisite check (3.2) before the permission check (3.3), while BIND checks
its query and update ACLs first (`send_update()` in `lib/ns/update.c`). For any
other product, (verify) the order before reading a non-REFUSED rcode.

---

## Step 6 — Grade by what you proved

| What you proved | Grade |
|---|---|
| Unauthenticated dynamic update accepted (canary added and removed) | Critical: anyone can rewrite the zone, including MX and `_acme-challenge` |
| External server carries the internal view (`_msdcs` SRV, internal zones, RFC 1918 PTR) | Medium; High if a domain controller's DNS is what answers |
| Open resolver whose RD=0 cache shows internal users' lookups | Medium |
| Open resolver, version inside a 2025-2026 poisoning range | Medium, unconfirmed; never demonstrated |
| Open resolver, measured amplification factor | Low to Medium |
| Full zone walkable with sensitive names (Stage B walk done) | Low to Medium, anchored to AXFR (VRT P4) |
| DNSSEC bogus on the client's zone | Low to Medium, as availability |
| Version in a pre-auth RCE range or in KEV | Medium to High by CVE, labelled unconfirmed |
| Lame delegation, EDNS/TCP noncompliance | Low / Informational |
| Version or identity disclosure only | Informational |

Program acceptance, from primary sources: HackerOne's Core Ineligible Findings
list banner and version disclosure, excessive-traffic issues and missing best
practices; Bugcrowd VRT (2026-07-08 release) rates banner disclosure P5, missing
DNSSEC P5, zone transfer P4, subdomain takeover P3, and has **no open-resolver
entry**, so file it under Server Security Misconfiguration with a severity
argument (`bugcrowd-reporting`). Practitioner guidance, not a cited policy
(verify against the program's own scope page): carry the measured factor and any
poisoning-version overlap; a bare "recursion enabled" reads as scanner output.

---

## Step 7 — Capture evidence once

Follow `evidence-hygiene`. Per finding:

- Full dig output (header, flags, sections, `QUERY SIZE` / `MSG SIZE`) saved at
  probe time, with the timestamp, the server IP and your egress IP.
- For open recursion, the log line from your authoritative server or the
  interactsh/Collaborator record showing the canary query and its source IP.
- For cache snooping, the single RD=0 reply and the reference TTL.
- For dynamic update, both UPDATE transcripts, the NXDOMAIN after removal, and
  the sign-off reference.
- For NSEC walks, the name count and a redacted sample, not a published zone.

---

## Chain table

| Confirmed | Standalone | Where it goes next |
|---|---|---|
| Open recursion | Low to Medium | One cache-snoop query (2.3); version gate (Step 4); report. Never poison. |
| Cache snooping shows internal lookups | Medium | SaaS tenants and vendors seen feed `offensive-osint` and `hunt-subdomain`. |
| Version in matrix range | Per matrix | Report unconfirmed. KEV rows escalate to the operator the same day. |
| SOA MNAME reachable from the internet | Informational | AXFR attempt belongs to `hunt-tls-network` Phase 3. |
| NSD on a version with CVE-2026-18664 (ACL ranges) | Per matrix | Same: AXFR test in `hunt-tls-network` Phase 3. |
| Lame or dangling NS | Low / takeover | `hunt-subdomain` for NS-delegation takeover; register nothing from here. |
| `_msdcs` SRV or internal zones served externally | Medium to High | Hostnames to `web2-recon`; NTLM metadata to `hunt-ntlm-info`; stop at AD. |
| Unauthenticated dynamic update | Critical | Report. Describe MX takeover and ACME DNS-01 issuance; perform neither. |
| Technitium or PowerDNS console reachable | Per panel | `hunt-exposed-panels` method. |
| DoT/DoH certificate problems | Per TLS | `hunt-tls-network`. |
| NSEC walk reveals hosts | Low to Medium | Hosts to `web2-recon` for their own testing. |

---

## Validation checklist

- [ ] Every target IP is the client's by ASN plus RDAP and in the signed scope,
      and none is a public anycast resolver or a DNS provider's nameserver.
- [ ] Probed from outside every client VPN and office range; egress IP recorded.
- [ ] Server role (authoritative, recursive, forwarder, both) established first.
- [ ] Open recursion shown by a canary query or by NOERROR + answer + no `aa`
      for an out-of-zone name, not by the `ra` bit or `dns-recursion` alone.
- [ ] Cache snooping used one RD=0 query for a client-specific name, and the
      report says whether the resolver is open to everyone.
- [ ] Amplification measured once, with `+ignore`, no repeats, no spoofing, and
      graded at Medium at most.
- [ ] Version claims say "in range, unconfirmed", distro backports were checked,
      and no Windows DNS string was mapped to a CVE.
- [ ] Stayed within one query per second and the per-server budget.
- [ ] No `-sC`, `-A`, `dns-update`, `dns-cache-snoop` timed mode, `dns-fuzz`,
      `dns-random-*` or full-walk script ran without Stage B sign-off.
- [ ] Every UPDATE, full walk and cracking run has a logged written sign-off,
      and the canary is confirmed removed.
- [ ] No poisoning, flood, spoofed packet or crash PoC was sent, ever.
- [ ] AXFR and takeover findings were handed to their owning skills, not
      re-tested here.

---

## Sources

External references (all checked 2026-10-13):

- RFC 5358 (BCP 140) open resolvers: <https://www.rfc-editor.org/rfc/rfc5358>
- RFC 2136 / RFC 3007 dynamic update: <https://www.rfc-editor.org/rfc/rfc2136>
- RFC 4892 and RFC 5001, server identity and NSID: <https://www.rfc-editor.org/rfc/rfc5001>
- RFC 8482 minimal ANY: <https://www.rfc-editor.org/rfc/rfc8482>
- RFC 9276 NSEC3 parameters: <https://www.rfc-editor.org/rfc/rfc9276>
- RFC 8906 and RFC 7766, EDNS and TCP: <https://www.rfc-editor.org/rfc/rfc8906>
- RFC 9715 fragmentation avoidance: <https://www.rfc-editor.org/rfc/rfc9715>
- ISC BIND vulnerability matrix: <https://kb.isc.org/docs/aa-00913>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- Nmap NSE scripts: <https://nmap.org/nsedoc/categories/discovery.html>
- Bugcrowd VRT: <https://github.com/bugcrowd/vulnerability-rating-taxonomy>
- HackerOne Core Ineligible Findings: <https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>

---

## Related Skills & Chains

- `infra-external-methodology`: the external-perimeter orchestrator whose
  port-routing table sends 53/tcp+udp here.
- `offensive-osint`, `web2-recon`, `recon-scope-triage`: discovery and scope.
  They produce the input to Step 1.
- `hunt-tls-network`: owns AXFR (Phase 3), dangling records (Phase 6.5),
  SPF/DMARC/CAA, and every certificate finding on DoT and DoH.
- `hunt-subdomain`: CNAME and NS-delegation takeover; the only place a dangling
  NS is claimed.
- `hunt-exposed-services`: the generic exposed-port method this skill follows,
  and the amplification grading rules this skill does not contradict.
- `hunt-exposed-panels`: DNS server web consoles and HTTP APIs.
- `hunt-ntlm-info`: AD naming that tells you which internal zone to ask about.
- `hunt-ssrf`: DNS rebinding and resolver abuse through a web application.
- `bugcrowd-reporting`, `triage-validation`, `report-writing`,
  `evidence-hygiene`: severity argument, false-positive gates, write-up.

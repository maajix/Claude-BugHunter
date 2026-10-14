# Zone configuration, DNSSEC and transport checks

Depth for SKILL.md Step 2.5. Every probe here is aimed at a server already
confirmed as the client's (SKILL.md Step 1), at no more than one query per
second, `+tries=1 +timeout=3`, serially. Set these once:

```bash
NS="192.0.2.53"; ZONE="client.example"
Q="+tries=1 +timeout=3 +norecurse"
```

---

## 1. DNSSEC validation

Validate from **your own** resolver, not by pointing tools at the client's
server. This sends the client nothing beyond ordinary resolution traffic.

```bash
# delv validates locally with its built-in root trust anchor
delv "$ZONE" SOA +vtrace 2>&1 | tee "evidence/${ZONE}_delv.txt" | tail -20
# "; fully validated"     -> chain of trust intact
# "; unsigned answer"     -> no DS at the parent: zone is not signed
# ";; resolution failed: failure" -> bogus or unreachable; dnsviz grok shows which link broke

# DNSViz in its default mode resolves through /etc/resolv.conf
dnsviz probe -o "evidence/${ZONE}_dnsviz.json" "$ZONE"
dnsviz grok -l warning -r "evidence/${ZONE}_dnsviz.json"
```

`dnsviz probe -A` queries the authoritative servers directly with a battery of
EDNS, TCP and DNSSEC variants. It is read-only and useful, but it is a burst:
run it once, after Stage A, and only against servers that are not fragile
appliances.

| Result | Meaning | Grade |
|---|---|---|
| Unsigned zone | Missing DNSSEC | Bugcrowd VRT P5; not a finding on its own |
| Bogus: expired RRSIG, DS that matches no DNSKEY, algorithm mismatch | **Every validating resolver returns SERVFAIL for the zone**: the client's own domain is down for a large share of the internet | Low to Medium, as an availability issue; it is not an attacker primitive |
| DS present but NS serve unsigned data | Same as bogus | Same |
| Weak algorithm (RSAMD5, DSA, RSASHA1 without NSEC3) | Hardening | Informational |

## 2. NSEC walking (Stage A: a handful of names)

An NSEC record names the next existing owner name, so each negative answer hands
you one real name. Five queries are enough to show whether walking is possible
and whether the names are sensitive.

```bash
# Ask for a name that cannot exist; read the NSEC "next name" in the authority section
dig $Q +dnssec @"$NS" "zz-nx-probe.$ZONE" A | grep -E 'NSEC|status'
# Repeat for at most four more names, chosen from the NSEC answers. Stop at five.
```

Reading it:

| What comes back | Meaning |
|---|---|
| `NSEC` with real next names (`admin.`, `vpn-old.`, `jira.`) | Zone is walkable. Full enumeration is Stage B (below); the handful already proves it. |
| `NSEC` whose next name is `\000.zz-nx-probe...` or similar synthetic label | Minimally covering NSEC, RFC 4470 "white lies" or a "black lies" variant. **Not walkable. Not a finding.** Typical of online-signing DNS providers (Cloudflare documents its "black lies"). |
| `NSEC3` | Hashed. Go to section 3. |
| No NSEC/NSEC3 | Zone unsigned. |

NSEC walking is protocol behaviour, not a bug. It is reportable only when the
names it reveals are sensitive (internal hostnames, pre-release products,
customer-named hosts). Then it is equivalent to AXFR in what it leaks, and the
bundle's AXFR grading (Bugcrowd VRT zone transfer P4) is the right anchor.

### Full walk: Stage B

Walking every name is a long query loop against the client's server and is the
AXFR-equivalent disclosure itself. It needs the sign-off block from SKILL.md
Step 5 naming the zone and the rate.

```bash
# Stage B: full NSEC walk. Written sign-off required; rate-capped at 5 qps.
n3map -v --limit-rate 5/s -o "evidence/${ZONE}.nsec.zone" "$NS" "$ZONE"
```

## 3. NSEC3 parameters and hash exposure

```bash
dig $Q @"$NS" "$ZONE" NSEC3PARAM +short
# 1 0 0 -        -> SHA-1, flags 0, iterations 0, empty salt: what RFC 9276 recommends
```

| Parameters | Verdict |
|---|---|
| Iterations 0, empty salt | **Correct per RFC 9276 (BCP 236).** Never report it as weak hashing. Salt and iterations add little against offline cracking. |
| High iterations (tens to hundreds) | Not a confidentiality finding. RFC 9276 lets validators treat high counts as insecure or SERVFAIL, and high counts feed resolver CPU exhaustion (CVE-2023-50868, BIND CVE-2026-1519). Report as a hardening item that may break resolution. |
| Opt-out flag set (`1 1 ...`) | Normal for large delegation-only zones. Informational. |

Collecting NSEC3 hashes needs the same walk as NSEC, and cracking them recovers
names offline. Both are Stage B, and cracking needs its own line in the sign-off
because it produces the full name list.

```bash
# Stage B: NSEC3 hash collection and cracking. Written sign-off required.
n3map -3 -v --limit-rate 5/s -o "evidence/${ZONE}.nsec3.zone" "$NS" "$ZONE"
# Convert the collected records to hashcat's mode 8300 "DNSSEC (NSEC3)" format,
# then crack against a hostname wordlist offline:
hashcat -m 8300 nsec3-hashes.txt hostnames.txt
```

## 4. Lame delegation and dangling NS

```bash
# The delegation the parent publishes
dig +short NS "$ZONE"
# Ask each listed server, once, whether it is authoritative
for ns in $(dig +short NS "$ZONE"); do
  echo "== $ns"; dig $Q @"$ns" "$ZONE" SOA | grep -E 'status|flags'; sleep 1
done
```

| Answer from a listed NS | Meaning | Owner |
|---|---|---|
| `NOERROR` with `aa` | Healthy | none |
| `REFUSED`, `SERVFAIL`, no `aa`, or timeout | **Lame delegation.** Resolution slows and fails over; an operational defect | Low / Informational here |
| NS hostname does not resolve, or its domain is unregistered or expired | **Dangling NS**: whoever registers it serves the zone | `hunt-subdomain` (NS takeover), `hunt-tls-network` Phase 6.5. Do not register anything from this skill. |
| NS at a managed provider (Route 53, Azure DNS, DigitalOcean, NS1) returning REFUSED for the zone | Zone deleted at the provider, delegation left behind: possible NS takeover | `hunt-subdomain`. Claiming the zone is that skill's gated step. |

The listed servers may belong to a DNS provider. A single SOA query to a
provider's nameserver is ordinary resolution traffic; any probe beyond that is
not, and the provider is not the client.

## 5. Split-horizon leaks on an external server

A server that serves both the internal and external views from one listener, or
an external secondary that carries an internal zone, leaks internal topology to
anyone who asks. Use at most five targeted queries:

```bash
dig $Q @"$NS" "$ZONE" SOA +short                  # MNAME/RNAME: internal primary? (e.g. dc01.corp.local.)
dig $Q @"$NS" "_ldap._tcp.dc._msdcs.$ZONE" SRV    # AD domain controllers published externally?
dig $Q @"$NS" "corp.$ZONE" SOA                    # internal sub-zone served here?
dig $Q @"$NS" -x 10.0.0.1                          # authoritative for RFC 1918 reverse zones?
```

| Signal | Reading |
|---|---|
| SOA MNAME is an internal-only name or RFC 1918 host | Low: internal naming disclosed. Also tells you where AXFR would be tried (`hunt-tls-network` Phase 3). |
| `_msdcs` SRV answers with DC hostnames | The server is, or mirrors, AD-integrated DNS. Medium: a domain controller's DNS role is internet-facing. Stop at the exposure; AD is out of scope per `SECURITY.md`. |
| An internal zone or RFC 1918 PTR answers with `aa` | Medium if the names are sensitive: the external server carries the internal view. |
| `REFUSED` / `NXDOMAIN` | Clean. |

The AD domain name is often a different zone from the web domain. Take it from
`hunt-ntlm-info` output or a certificate SAN rather than guessing a list.

## 6. EDNS, TCP and encrypted transport (RFC 8906 style)

```bash
dig $Q +tcp @"$NS" "$ZONE" SOA | grep status                       # TCP must work (RFC 7766)
dig $Q +noedns @"$NS" "$ZONE" SOA | grep status                    # plain DNS must work
dig $Q +edns=1 +noednsnegotiation @"$NS" "$ZONE" SOA | grep -E 'status|EDNS'   # expect BADVERS, EDNS 0
dig $Q +cookie @"$NS" "$ZONE" SOA | grep -i cookie                 # DNS Cookies, RFC 7873
dig $Q +tls @"$NS" "$ZONE" SOA | grep status                       # DoT on 853, if open
```

| Result | Meaning | Grade |
|---|---|---|
| TCP refused or times out on an authoritative server | Large and DNSSEC responses fail for everyone; also blocks the TC fallback resolvers rely on | Low (availability, RFC 7766 noncompliance) |
| Unknown EDNS version answered with NOERROR, or no answer | EDNS noncompliance; resolvers time out | Informational / Low |
| Advertised UDP buffer above 1232 | Fragmentation-prone; fragments are the vector in CVE-2025-59024-class poisoning against resolvers that talk to it | Hardening (RFC 9715) |
| No cookie support | Informational |
| DoT certificate expired, self-signed or wrong name | `hunt-tls-network` |
| DoH endpoint (`/dns-query` on 443) answers | Fingerprint only here. If it resolves arbitrary names for anyone, it is an open resolver over HTTPS: SKILL.md Steps 2.2 and 3.1, one request. |

## Sources

RFC 4470, RFC 5155, RFC 7766, RFC 7873, RFC 8906, RFC 9276, RFC 9715;
<https://github.com/dnsviz/dnsviz>; <https://github.com/anonion0/nsec3map>;
<https://hashcat.net/wiki/doku.php?id=example_hashes> (mode 8300).

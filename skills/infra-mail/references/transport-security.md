# Transport security: STARTTLS, cleartext AUTH, MTA-STS, TLS-RPT, DANE

Scope boundary: `hunt-tls-network` owns cipher suites, protocol versions,
certificate validity and SPF/DKIM/DMARC. This file owns the SMTP/IMAP/POP3
**transport** layer that `hunt-tls-network` does not touch: whether TLS is
offered at all, whether credentials cross in cleartext, STARTTLS command
injection, and the three DNS-published transport policies (MTA-STS, TLS-RPT,
DANE). Everything here is Stage A: DNS, one HTTPS GET, one handshake per MX.

## STARTTLS not offered / cleartext AUTH

```bash
TARGET="mx1.client.example"; EHLO="probe.canary.example.net"
# Is STARTTLS advertised on 25 and 587?
swaks --server "$TARGET" --port 25  --ehlo "$EHLO" --from probe@canary.example.net --quit-after EHLO 2>&1 | grep -i STARTTLS
swaks --server "$TARGET" --port 587 --ehlo "$EHLO" --from probe@canary.example.net --quit-after EHLO 2>&1 | grep -iE 'STARTTLS|AUTH'
```

Findings and grades:

| Observed | Meaning | Grade |
|---|---|---|
| No `STARTTLS` on 25 | MTA-to-MTA mail for this host is cleartext on the wire | Low (opportunistic TLS is the norm; High only with an on-path position or an `enforce`/DANE policy that is thereby unsatisfiable) |
| No `STARTTLS` on 587 | Clients submit in cleartext | Medium |
| `AUTH LOGIN`/`PLAIN` advertised **before** STARTTLS on 25/587 | Credentials can be sent in cleartext | Medium; prove with SKILL.md Step 6d (Stage B) |
| `AUTH` only **after** STARTTLS | correct; Postfix `smtpd_tls_auth_only = yes` | Not a finding |
| IMAP 143 lacks `LOGINDISABLED` before STARTTLS, or POP3 110 offers `USER`/SASL before `STLS` | cleartext mailbox login offered | Medium |

HackerOne lists "SSL/TLS configurations" as core-ineligible, so a bare "STARTTLS
missing on 25" with no exploitation context is usually closed as hardening.
Cleartext **AUTH accepted** (a credential actually crossing unencrypted) is a
real confidentiality issue and survives triage.

## STARTTLS command injection (plaintext-injection)

Poddebniak, Ising, Böck, Schinzel, "Why TLS is better without STARTTLS", USENIX
Security 2021 (<https://nostarttls.secvuln.info/>). A server that does not
discard buffered plaintext received before the TLS handshake will execute
commands an on-path attacker injected in the clear as though they arrived inside
the TLS session — enabling mailbox/credential theft on affected servers. Their
internet scan found ~320,000 SMTP servers (about 2%) affected.

This is a server bug confirmable without an attacker: send a command in the same
packet as (or immediately after) `STARTTLS`, before the handshake, and see
whether the server processes it post-TLS. The authors' EAST toolkit
(<https://github.com/Email-Analysis-Toolkit>) is the reference tester. The core
check:

```bash
# Buffer a command in cleartext right after STARTTLS, then negotiate TLS and
# read whether it was executed inside the session. (Read-only; no mail sent.)
printf 'EHLO %s\r\nSTARTTLS\r\nNOOP injected\r\n' "$EHLO" | \
  openssl s_client -starttls smtp -connect "$TARGET:25" -crlf -quiet 2>/dev/null | head
# A reply to "NOOP injected" seen *after* the TLS upgrade = buffer not cleared = vulnerable.
```

The IMAP and POP3 variants inject a tagged command / `CAPA` before `STLS`.
Grade Low to Medium: real impact needs an on-path (active MitM) position, so it
is contingent, but the server defect is concrete and fixable (discard the
receive buffer across the TLS boundary). Relevant history: Exim
CVE-2021-38371 (STARTTLS response injection).

## MTA-STS (RFC 8461)

MTA-STS lets a domain publish, over HTTPS, that senders must use TLS with a
valid certificate to its MX. Validate it, do not just check presence.

```bash
D="client.example"
# 1. TXT record: must be v=STS1; id=...
dig +short TXT "_mta-sts.$D"
# 2. Policy file over HTTPS with certificate validation (NOT curl -k).
curl -sS --max-time 15 "https://mta-sts.$D/.well-known/mta-sts.txt"
# 3. Does the policy's mx: cover every host in the live MX set?
dig +short MX "$D"
```

Policy fields (RFC 8461 §3.2): `version: STSv1`, `mode:` one of `enforce` /
`testing` / `none`, one or more `mx:` lines (exact name or `*.suffix`), and
`max_age:` in seconds with a documented maximum of 31557600. The HTTPS fetch
must use a certificate valid for `mta-sts.<domain>` (§3.3).

| Observed | Meaning | Grade |
|---|---|---|
| No TXT and no policy | No MTA-STS | Info (hardening; HackerOne core-ineligible) |
| TXT present, policy 404 / cert invalid / not HTTPS | Broken deployment; senders ignore it | Low |
| `mode: enforce` but `mx:` omits a live MX, or the MX cert fails PKIX/name | **Legitimate mail to that MX fails** | Low (availability), and tell the client — this breaks delivery |
| `mode: testing` | Reporting only, no enforcement | Info |
| `mode: enforce`, all MX covered, certs valid | Correct | Not a finding |
| `id` not monotonic / stale vs policy | caching confusion | Info |

Interaction with DANE (RFC 8461): a sender implementing both MUST NOT let a
passing or testing MTA-STS result override a *failing* DANE validation. So DANE
is the stronger control when both are present.

## TLS-RPT (RFC 8460)

```bash
dig +short TXT "_smtp._tls.$D"   # v=TLSRPTv1; rua=mailto:...  or  rua=https://...
```

Reporting only — never an enforcement control, so its absence is Info at most.
The one thing worth checking: if `rua` points at a mailbox on a **domain that is
unregistered or expired**, anyone can register it and harvest the TLS failure
telemetry (which MXes, which senders, TLS downgrade patterns). Confirm the rua
domain resolves to the client; if it is third-party, note who receives the
reports. Low.

## DANE (RFC 7672)

DANE for SMTP publishes a `TLSA` record at `_25._tcp.<mx-host>` that binds the
MX's certificate or key, and is only trustworthy when the MX and TLSA lookups
are **DNSSEC-validated**. Without DNSSEC, DANE provides nothing.

```bash
MX="mx1.client.example"
# TLSA records live under _25._tcp.<mx host>, not the domain.
dig +short TLSA "_25._tcp.$MX"
# DNSSEC must validate, or DANE is inert. delv reports the validation state.
delv "_25._tcp.$MX" TLSA 2>&1 | grep -iE 'fully validated|insecure|bogus'
# Check the live MX cert against the published TLSA using OpenSSL's DANE support.
RR="$(dig +short TLSA "_25._tcp.$MX" | head -1)"
openssl s_client -starttls smtp -connect "$MX:25" -dane_tlsa_domain "$MX" \
  -dane_tlsa_rrdata "$RR" </dev/null 2>/dev/null | grep -i 'DANE TLSA'
# "DANE TLSA 3 1 1 ... matched EE certificate" = the cert matches the record.
```

TLSA usages for SMTP DANE (RFC 7672; wording approximate, (verify) against the
RFC before quoting MUST/SHOULD):

- `3 1 1` (DANE-EE, SPKI, SHA-256) is the common and recommended form; name
  checks are relaxed for DANE-EE(3) because the record itself binds the key.
- `2 x x` (DANE-TA) pins a trust anchor.
- `0`/`1` (PKIX-TA/PKIX-EE) are generally not recommended for SMTP DANE, which
  does not rely on a public CA set.

| Observed | Meaning | Grade |
|---|---|---|
| No TLSA | No DANE | Info |
| TLSA present but the zone is **not** DNSSEC-signed (`delv` insecure) | DANE is inert; false sense of security | Low |
| TLSA present, DNSSEC valid, but **no TLSA matches the live cert** (stale after a cert/key rotation) | **DANE senders defer or bounce all mail to this MX** | Low (availability), tell the client immediately |
| TLSA valid and matching | Correct | Not a finding |
| `delv` returns `bogus` | DNSSEC broken | Low to Medium (can break resolution) |

The recurring real finding here is operational, not cryptographic: a key or
certificate rotated without updating the `3 1 1` TLSA record, after which every
DANE-enforcing sender (large European providers do) stops delivering. That is a
genuine availability bug worth a Low, and clients usually want to know.

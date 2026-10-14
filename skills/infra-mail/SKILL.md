---
name: infra-mail
description: "Test internet-exposed mail services at the protocol layer: SMTP port 25, submission 587, SMTPS 465, IMAP 143/993, POP3 110/995 and ManageSieve 4190, and the server software behind them (Postfix, Exim, Sendmail, Microsoft Exchange transport, Zimbra MTA, Dovecot, Courier, Cyrus, hMailServer, MailEnable, Kerio, IceWarp). Covers open relay with the correct direction matrix, user enumeration via VRFY, EXPN and RCPT TO, STARTTLS not offered, cleartext AUTH PLAIN/LOGIN, STARTTLS command injection, SMTP smuggling (CVE-2023-51764/51765/51766 and the 2026 follow-ups), banner and EHLO version gates against KEV CVEs, NTLM leaks via AUTH NTLM, and MTA-STS, TLS-RPT and DANE transport policy. Stage A is read-only: banner, EHLO, one VRFY pair, DNS. Anything that sends a message, enumerates at scale, uses a credential or risks a crash is Stage B behind written sign-off. Use when a scan shows a mail port open on an in-scope host, or an MX record points at client-owned infrastructure."
metadata:
  sources: rfc, nvd, cisa_kev, vendor_advisories, cert_cc, sec_consult_research, usenix_research, project_documentation, nmap_nse_source
  report_count: 0
---

## When to use

Trigger when 25, 465, 587, 110, 995, 143, 993 or 4190 answers on a public,
client-owned address, when an in-scope domain's MX resolves into the client's
ASN rather than a hosted provider, or when a banner or certificate names a mail
server product. The finding is a **misconfiguration of the mail protocol layer**
(relay, enumeration, cleartext credentials, smuggling, transport policy) or a
**version inside a known-exploited range**. This skill starts from "a mail port
is open and in scope": discovery belongs to `offensive-osint` and `web2-recon`,
scope confirmation to `recon-scope-triage`.

### Where the chain ends

Stop at **misconfiguration or unauthenticated access confirmed, impact
described, evidence captured**. Concretely:

- Open relay: stop at one message from you, to a mailbox you own, carrying a
  unique token. Never relay to a third party, never send a second message to
  "check the headers again", never test bulk throughput.
- User enumeration: stop at a differential on a small, operator-approved list.
  Feeding the result into a password spray is `hunt-brute-force`'s decision,
  and usually out of scope.
- Cleartext AUTH: stop at "the server accepted the engagement's test credential
  without TLS". Do not open the mailbox, read mail, or set forwarding rules.
- SMTP smuggling: stop at one smuggled message delivered to the engagement's
  own test mailbox, with a sender domain you own. Never spoof the client's
  executives, a real brand, or any user who did not consent.
- A pre-auth RCE CVE in range: stop at the version gate. Exploitation is out of
  scope for this bundle (`SECURITY.md`).

### Not covered here, on purpose

| Surface | Owner |
|---|---|
| SPF, DKIM, DMARC, inbox-delivery spoof proof | `hunt-tls-network` Phase 4. This skill does not repeat it. |
| Cipher suites, protocol versions, certificate chain on any mail port | `hunt-tls-network` Phase 1 (use its STARTTLS flags) |
| Decoding the NTLM Type-2 challenge | `hunt-ntlm-info` |
| OWA, ECP, EWS, ActiveSync, Autodiscover, MAPI/HTTP, webmail (Roundcube, Zimbra web client, SOGo, SmarterMail, IceWarp WebClient) | `hunt-exposed-panels`, `hunt-auth-bypass`, `hunt-xss` |
| Microsoft 365 and Google Workspace tenants | `m365-entra-attack`. Their MX hosts are shared provider infrastructure (Step 1). |
| Password spraying IMAP, POP3 or SMTP AUTH | `hunt-brute-force` |
| SMTP header injection from a web form | `hunt-misc` |
| Mail-borne attachment or calendar exploits (Zimbra amavis cpio CVE-2022-41352, ICS XSS CVE-2025-27915) | Nobody. Sending a weaponised message to a real user is not a protocol test and is not done. Version-gate only. |

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `references/open-relay-matrix.md` | Direction matrix, nmap's 16 encodings, submission and authenticated relay, confirmation and grading | open relay, relay test, smtp-open-relay, relay access denied, percent hack, source route |
| `references/mta-cve-matrix.md` | Postfix, Exim, Sendmail, OpenSMTPD, Exchange transport, Zimbra MTA, Dovecot and the smaller Windows servers; KEV flags; version observability | exim cve, postfix cve, sendmail smuggling, zimbra postjournal, dovecot dos, exchange smtp cve, kev mail server |
| `references/transport-security.md` | STARTTLS absent, cleartext AUTH, STARTTLS command injection, MTA-STS, TLS-RPT, DANE | starttls, cleartext auth, mta-sts, tls-rpt, dane tlsa, smtp tls policy |

---

## Step 1: Inherit the host list, then find out who actually runs the MX

Take hosts from the signed scope and ports from recon. Then, per domain:

```bash
DOMAIN="client.example"
dig +short MX "$DOMAIN"
for mx in $(dig +short MX "$DOMAIN" | awk '{print $2}'); do
  echo "== $mx"; dig +short A "$mx"; dig +short AAAA "$mx"
done
# Per address: ASN + RDAP + PTR, then cross-check the scope document.
```

**Shared provider infrastructure is not the client's server.** If the MX is
`*.mail.protection.outlook.com`, `aspmx.l.google.com` or `*.googlemail.com`,
`*.pphosted.com`, `*.mimecast.com`, `*.barracudanetworks.com` or another hosted
gateway (`offensive-osint` §16.14 has the pattern table), then:

- Do not run relay, enumeration or smuggling tests against it. The program does
  not own it, the behaviour is the provider's, and the provider has its own
  rules of engagement and bounty.
- Tenant configuration seen through it is still the client's. The 2026 case is
  Exchange Online **Direct Send** (anonymous internet mail using the tenant's
  own domain, accepted for its mailboxes); the opt-in fix is
  `Set-OrganizationConfig -RejectDirectSend $true` (MC1093237, 2025). Testing it
  is the operator's scope call; the proof belongs to `hunt-tls-network` Phase 4.

Submission (587/465), IMAP and POP3 hosts are often **not** the MX. Look for
`smtp.`, `mail.`, `imap.`, `pop.` and the `_submission._tcp`, `_submissions._tcp`,
`_imaps._tcp`, `_pop3s._tcp` SRV records (RFC 6186; `_submissions` is from RFC
8314) before you decide a host is out of the picture.

### Rate posture for every step in this skill

Mail servers punish fast clients, and the punishment lands on someone's IP.

- **One session in flight per host, 10 to 30 seconds between sessions.** Never
  parallelise against one MX. `smtp-user-enum` defaults to 5 processes; set
  `-m 1`.
- **Wait for the banner.** Postfix `postscreen` treats a client that talks
  before the 220 greeting as a bot (PREGREET) and blocks it. `swaks` and `curl`
  wait; `printf ... | nc` does not.
- **Tarpits and error limits.** Postfix sleeps after errors and disconnects past
  `smtpd_soft_error_limit` / `smtpd_hard_error_limit`; Exchange receive
  connectors tarpit 5xx replies. A run of slow replies is the server defending
  itself, not a timing oracle.
- **Greylisting.** `450`/`451 4.7.1` on a first delivery attempt is greylisting.
  It is not a rejection and not a finding. The only retry you make is the single
  Stage B delivery, once, after the delay the reply names.
- **Blocklists, both directions.** Many `RCPT TO` attempts from one IP get *your*
  egress listed and turn later results into false negatives (connection refused
  is not "port closed"). A relay test that makes the *client's* MTA deliver a
  spammy-looking message to a large provider damages the *client's* sending
  reputation. Hence: plain text, no links, no attachments, one message, to a
  receiver you run yourself.
- **Throttle guard.** Under an engagement request ceiling, `nmap` is refused by
  `hooks/throttle-guard.py` and `curl` is governed. `swaks`, `openssl s_client`,
  `smtp-user-enum` and `nc` are in neither table (`docs/rate-limiting.md`, "not
  covered"), so you are the rate limiter for them.

---

## Step 2: Stage A, fingerprint every mail port

**Stage A is read-only and is the default.** A Stage A probe sends no `MAIL
FROM`, no `RCPT TO`, no `DATA`, no credential, and at most one `VRFY` pair
(Step 3). Set your own EHLO name and sender every time: `swaks` otherwise
builds the sender from your `$LOGNAME` and local hostname, which leaks the
tester's identity into the client's logs.

```bash
TARGET="mx1.client.example"          # ownership confirmed in Step 1
EHLO_NAME="probe.canary.example.net" # a name you own, with matching PTR
mkdir -p evidence

# SMTP 25: banner + EHLO in cleartext, then QUIT. AUTH listed here = cleartext AUTH offered.
swaks --server "$TARGET" --port 25 --ehlo "$EHLO_NAME" --from "probe@canary.example.net" \
      --quit-after EHLO 2>&1 | tee "evidence/${TARGET}_25_ehlo.txt"

# Submission 587: before and after STARTTLS. Capabilities legitimately differ.
swaks --server "$TARGET" --port 587 --ehlo "$EHLO_NAME" --from "probe@canary.example.net" \
      --quit-after EHLO 2>&1 | tee "evidence/${TARGET}_587_ehlo_clear.txt"
swaks --server "$TARGET" --port 587 --ehlo "$EHLO_NAME" --from "probe@canary.example.net" \
      --tls --quit-after EHLO 2>&1 | tee "evidence/${TARGET}_587_ehlo_tls.txt"

# SMTPS 465 (implicit TLS)
swaks --server "$TARGET" --tls-on-connect --ehlo "$EHLO_NAME" --from "probe@canary.example.net" \
      --quit-after EHLO 2>&1 | tee "evidence/${TARGET}_465_ehlo.txt"

# IMAP 143 / POP3 110 / Sieve 4190: greeting + capabilities, no login
timeout 15 openssl s_client -starttls imap  -connect "$TARGET:143"  -crlf -quiet </dev/null 2>&1 | head -5
timeout 15 openssl s_client -starttls pop3  -connect "$TARGET:110"  -crlf -quiet </dev/null 2>&1 | head -5
timeout 15 openssl s_client -starttls sieve -connect "$TARGET:4190" -crlf -quiet </dev/null 2>&1 | head -5
timeout 15 openssl s_client -connect "$TARGET:993" -crlf -quiet </dev/null 2>&1 | head -5
```

For the **pre-STARTTLS** capability list on 143 and 110, use the two nmap
scripts below; `openssl s_client -starttls` has already upgraded by the time
you see anything.

What to record from each reply:

| Observable | Where | Why it matters |
|---|---|---|
| Product and version in the 220 greeting | 25/587/465 | Exim (`$version_number` in the default `smtp_banner`) and Sendmail print versions by default. Postfix, Exchange and Dovecot do not, so their version is usually unknowable remotely. Do not guess it. |
| `STARTTLS` absent on 25 | EHLO | Inbound mail crosses the internet in cleartext. |
| `AUTH PLAIN` / `AUTH LOGIN` listed **before** STARTTLS | EHLO on 25/587 | Cleartext AUTH is offered (Postfix `smtpd_tls_auth_only = no`, an Exchange connector without RequireTLS). |
| `AUTH NTLM` / `X-EXPS ... NTLM` | EHLO | NTLM Type-2 leak; run `smtp-ntlm-info` and decode per `hunt-ntlm-info`. |
| `AUTH ... EXTERNAL` or NTLM/SPA on Exim | EHLO | Version-gates CVE-2023-42114/42115/42116 (`references/mta-cve-matrix.md`). |
| `ETRN`, `CHUNKING`, `PIPELINING`, `XCLIENT`, `XFORWARD` | EHLO | ETRN gates Exim CVE-2025-26794; CHUNKING gates CVE-2026-45185 and the BDAT issues; `XCLIENT` offered to the internet lets a client claim another source IP (report it). |
| `VRFY` / `EXPN` listed | EHLO / HELP | Feeds Step 3. |
| IMAP `LOGINDISABLED` absent on 143 before STARTTLS, or POP3 `USER` / `SASL PLAIN` before `STLS` | CAPABILITY / CAPA | Cleartext IMAP/POP3 login offered. Dovecot's default refuses it. |
| Greeting product strings | 110/143/993/995/4190 | `Dovecot ready.` carries no version by default; other products vary. Record what is there. |

**Nmap scripts for mail, categories verified against Nmap 7.99 `.nse` sources.**
Name each script explicitly; never `-sC`, `-A` or a category selector.

| Script | Declared categories | Stage |
|---|---|---|
| `smtp-commands` | `default`, `discovery`, `safe` | A. Sends EHLO and HELP. |
| `smtp-ntlm-info`, `imap-ntlm-info`, `pop3-ntlm-info` | `default`, `discovery`, `safe` | A. Sends `AUTH NTLM` with null credentials; no login. |
| `imap-capabilities`, `pop3-capabilities` | `default`, `safe` (+`discovery` for POP3) | A. |
| `smtp-open-relay` | `discovery`, `intrusive`, `external` | **B.** 16 `MAIL FROM`/`RCPT TO` relay attempts in one session; the default domain `nmap.scanme.org` makes them relay attempts *to a third party*. See `references/open-relay-matrix.md`. |
| `smtp-enum-users` | `auth`, `external`, `intrusive` | **B.** Wordlist loop over RCPT, then VRFY, then EXPN. |
| `smtp-vuln-cve2010-4344` | `exploit`, `intrusive`, `vuln` | **Never.** Exploits Exim; it is not a check. |
| `smtp-vuln-cve2011-1720`, `smtp-vuln-cve2011-1764` | `intrusive`, `vuln` | **B**, and obsolete. |
| `smtp-brute`, `imap-brute`, `pop3-brute` | `brute`, `intrusive` | `hunt-brute-force`, not here. |
| `ssl-enum-ciphers` | `discovery`, `intrusive` | Belongs to `hunt-tls-network`; note it is **not** `safe`. |

```bash
nmap -Pn -sV --version-intensity 2 -p 25,465,587,110,143,993,995,4190 \
  --script smtp-commands,smtp-ntlm-info,imap-capabilities,pop3-capabilities \
  "$TARGET" -oN "evidence/${TARGET}_mail_nmap.txt"
```

---

## Step 3: Stage A, one VRFY/EXPN differential pair

One session, two commands, then stop. `postmaster` must exist on every SMTP
server that accepts mail for a domain (RFC 5321 §4.5.1), so it is the known
positive; a random string is the known negative. `curl` speaks VRFY when given
`--mail-rcpt` with no upload, waits for the banner, takes the EHLO name from the
URL path, and is governed by the throttle guard.

```bash
NEG="zz$(openssl rand -hex 6)"   # a local part that cannot exist
curl -sv --max-time 30 "smtp://$TARGET:25/$EHLO_NAME" --mail-rcpt postmaster 2>&1 \
  | grep -E '^[<>] (VRFY|EXPN|[0-9]{3})' | tee "evidence/${TARGET}_vrfy_pos.txt"
sleep 20
curl -sv --max-time 30 "smtp://$TARGET:25/$EHLO_NAME" --mail-rcpt "$NEG" 2>&1 \
  | grep -E '^[<>] (VRFY|EXPN|[0-9]{3})' | tee "evidence/${TARGET}_vrfy_neg.txt"
```

Read the pair, not either reply alone:

| Positive / negative reply | Meaning |
|---|---|
| `250`/`251` vs `550`/`551`/`553` | Enumeration oracle confirmed. Record it; stop here in Stage A. |
| `252` for both | No oracle. RFC 5321's "cannot VRFY user, but will accept message". Exchange answers this way. |
| `502`/`500`/`550 ... disabled` for both | VRFY disabled. Not a finding. |
| Same reply for both, any code | No oracle on VRFY. RCPT-based enumeration is Stage B (Step 6b). |

EXPN is the same shape with `-X EXPN --mail-rcpt <list-name>` and an agreed list
name (`postmaster` again, or one the client names). An EXPN that returns list
members leaks group membership, which is worth more than a yes/no.

---

## Step 4: Stage A, transport policy (MTA-STS, TLS-RPT, DANE)

`hunt-tls-network` has nothing on SMTP transport policy, and `offensive-osint`
§16.14 only checks presence (with `curl -k`, which skips the check that
matters). `references/transport-security.md` adds the validation: strict policy
fetch, mode, `mx` coverage, `max_age`, MX certificate against the policy,
TLS-RPT `rua` targets, DANE TLSA against DNSSEC and the live certificate, plus
STARTTLS absence, cleartext AUTH and STARTTLS command injection. All of it is DNS,
one HTTPS GET and one handshake per MX. Most results are Info or Low (HackerOne
lists "SSL/TLS configurations" and "optional email security features" as core
ineligible); what carries weight is an `enforce` policy or TLSA record that
breaks delivery, and a TLS-RPT `rua` on a domain anyone can register.

---

## Step 5: Version gates, no packets beyond Stage A

Map what Step 2 recorded to `references/mta-cve-matrix.md`. Rules:

- A version match is **unconfirmed** until a vendor-safe check or the client's
  own package list confirms it. Write "version in range", never "vulnerable".
- No version in the banner means no version claim. Postfix, Exchange and
  Dovecot hide it by default; distro backports also patch without bumping the
  upstream number (Debian `exim4 4.98.2-1+deb13u5` carries the 4.100.1
  smuggling fix). Ask the client for `postconf mail_version`, `exim -bV` or
  the package version.
- KEV-listed and SMTP-reachable (Exim CVE-2019-10149, CVE-2018-6789,
  CVE-2019-16928; OpenSMTPD CVE-2020-7247; Zimbra CVE-2024-45519 and
  CVE-2026-73570) is an **escalate-now** item: tell the operator the same day,
  even unconfirmed.
- Never send a crash or exploit trigger. DoS-class and RCE-class checks are not
  Stage A, and in practice not Stage B either (Step 6e).

---

## Step 6: Stage B, anything that sends mail, enumerates, authenticates or risks a crash

Stage B is **blocked by default**. It needs explicit written operator sign-off
naming the action, the host, the sender and recipient addresses, the number of
messages or attempts, and a window. "Mail testing is in scope" is not sign-off.

```
Stage B authorization
  Host/port:        mx1.client.example:25 (198.51.100.25)
  Action:           single relay test, MAIL FROM probe@canary.example.net,
                    RCPT TO relay-canary@canary.example.net, one message, token <hex>
  Blast radius:     if the relay is open, the client MTA delivers one message to a
                    receiver we run; the client's IP touches our MX only
  Reversibility:    the message cannot be recalled; nothing persists on the target
  Window:           <date/time>
  Authorized by:    <operator name/role>, in writing, <link to the message>
```

| Always Stage B | Blast radius to name |
|---|---|
| Any relay test, RCPT-level or with DATA | Logged as a relay attempt; trips anti-relay and IDS; with DATA, a real message leaves the client's MTA. |
| RCPT TO or VRFY enumeration beyond the Step 3 pair | Log volume, tarpit, blocklisting of your IP, possible account-existence alerts. |
| SMTP smuggling test | Each test is one real message. |
| Any AUTH with a credential, even the engagement test account | Failed-login counters, lockout, a security alert. |
| Spoofing the client's own domain inbound | Lands in a real inbox; route proof to `hunt-tls-network` Phase 4. |
| DoS-class version check | A crash on the production MX is an outage. |

### 6a. Open relay

The direction matrix, the 16 address encodings `smtp-open-relay` uses, the
submission-port and authenticated variants, and the confirmation rules are in
`references/open-relay-matrix.md`. The minimum test, after sign-off:

```bash
# Stage B: written sign-off required. One message, one token, own receiver.
TOKEN="$(openssl rand -hex 8)"
swaks --server "$TARGET" --port 25 --ehlo "$EHLO_NAME" \
      --from "probe@canary.example.net" --to "relay-canary@canary.example.net" \
      --header "Subject: relay-test $TOKEN" --body "Authorized relay test. Token $TOKEN" \
      2>&1 | tee "evidence/${TARGET}_relay_${TOKEN}.txt"
```

Confirmed only when **both** hold, mirroring the open-proxy rule in
`hunt-exposed-services/references/legacy-and-infoleak.md`: the token arrives at
your receiver, **and** that message's `Received:` chain shows the target as the
hop that handed it to your MX. A `250` after `RCPT TO` or after the final dot
proves nothing on its own: accept-then-bounce, quarantine and silent discard all
answer 250.

### 6b. User enumeration at scale

Only after the Step 3 pair or a single RCPT differential shows an oracle, and
only with a list the operator approved (size and source named in the sign-off).
One process, a delay, and stop at the first `421` or connection reset.

```bash
# Stage B: written sign-off required. Approved list only, one process.
smtp-user-enum -M RCPT -U approved-users.txt -D client.example \
  -f probe@canary.example.net -t "$TARGET" -m 1 \
  | tee "evidence/${TARGET}_rcpt_enum.txt"
```

`smtp-user-enum` (pentestmonkey) defaults to VRFY and 5 processes; `-M`, `-D`,
`-f` and `-m` are its documented flags. Check the result against catch-all
behaviour: if a random local part also gets `250`, there is no oracle. A timing
differential is reportable only if it survives repeated, interleaved runs with a
fixed control, and even then it is Low.

### 6c. SMTP smuggling

SEC Consult (Timo Longin, 18 Dec 2023; CERT/CC VU#302671): an outbound server
passes a non-standard end-of-data sequence such as `<LF>.<CR><LF>`, the inbound
server ends DATA there, and the trailing bytes become a second message with an
attacker-chosen envelope that passes SPF. Every test answers one side only:
inbound (the client MX accepts a malformed ending) or outbound (the client's
submission server passes it through). Test design, tool caveats, the outbound
variant and the version context are in `references/smtp-smuggling.md`.

```bash
# Stage B: written sign-off required. One message per sequence, named in the sign-off.
python3 smtpsmug -c lfcrlf -f probe@canary.example.net \
        -t pentest-mailbox@client.example "$TARGET"
```

Always pass `-f` and `-t`: `smtpsmug` defaults to `alice@example.org` and
`bob@example.org`. The recipient is the engagement's test mailbox at the client
domain; the sender is a domain you own, never the client's or a brand's.

### 6d. Cleartext AUTH proof

Only with the engagement's test account, once, on the port that advertised AUTH
before STARTTLS. Stop at the 235/`OK` reply.

```bash
# Stage B: written sign-off required. Engagement test credential, single attempt.
swaks --server "$TARGET" --port 587 --ehlo "$EHLO_NAME" \
      --auth LOGIN --auth-user "$TEST_USER" --auth-password "$TEST_PASS" \
      --quit-after AUTH 2>&1 | tee "evidence/${TARGET}_587_cleartext_auth.txt"
```

Without `--tls`, a `235 Authentication successful` is the finding: credentials
crossed the internet in cleartext and the server accepted them. Redact the
base64 lines in the transcript before it goes anywhere (`evidence-hygiene`).

### 6e. DoS-class CVE checks

Dovecot's 2026 pre-auth memory issues, Postfix BDAT exhaustion and the Exim
PROXY parser bugs are availability bugs: version-gate them. A trigger needs
sign-off, the asset owner and a window, and belongs on a replica. None ships here.

---

## Step 7: Grade on what you proved

| What you proved | Grade |
|---|---|
| Unauthenticated relay to an external domain, message delivered (6a) | High |
| Unauthenticated relay on 587/465 without AUTH, delivered | High |
| Relay because the sender address used the client's own domain | High |
| Authenticated user can send as any address (no sender/login binding) | Medium |
| Smuggled message delivered via a real outbound path the client's MX trusts | Medium; High if the client's outbound passes the sequence and it is a provider |
| Client MX accepts a malformed end-of-data, no passing outbound found | Low |
| Cleartext AUTH accepted with the test credential on an internet port | Medium |
| AUTH advertised before STARTTLS but not tried, or STARTTLS absent on 25 | Low |
| STARTTLS command injection confirmed | Low to Medium (needs an on-path attacker) |
| EXPN returns list members | Low to Medium |
| VRFY or RCPT oracle confirmed | Low; Info if the address format and staff names are already public |
| NTLM Type-2 leak via `AUTH NTLM` | Per `hunt-ntlm-info`, usually Low |
| `XCLIENT`/`XFORWARD` honoured from the internet | Medium (source-IP spoofing past IP-based controls) |
| KEV or pre-auth RCE CVE, version in range from the banner, unconfirmed | Medium, labelled unconfirmed, escalated the same day |
| MTA-STS/DANE misconfiguration that breaks delivery | Low (availability) |
| MTA-STS, TLS-RPT or DANE absent | Info |

Bugcrowd's VRT (2026-07-08 release) has no open-relay entry; map to the nearest
and justify (`bugcrowd-reporting`). Its enumeration entries are `Username/Email
Enumeration > Non-Brute Force` (P4) and `> Brute Force` (P5).

### What is not a finding

- Port 25 open on an MX. That is its job.
- A product name in the banner, or a version with no CVE that is reachable in
  the observed configuration. HackerOne lists banner and version disclosure as
  core ineligible.
- `250` to `RCPT TO` for an external address without a delivered message.
- `252` to every VRFY, or a catch-all that accepts every local part.
- Greylisting (`450`/`451 4.7.1`) and tarpit delays.
- A self-signed or mismatched certificate on port 25 with no MTA-STS `enforce`
  and no DANE: SMTP TLS between MTAs is opportunistic (RFC 7435).
- AUTH advertised only after STARTTLS. That is the correct configuration.
- Anything observed on Microsoft, Google or other hosted-gateway MX hosts.
- Backscatter (bounces to a forged sender) unless the program lists it; Low.

---

## Step 8: Evidence

Follow `evidence-hygiene`: transcript with timestamps saved at probe time, the
exact command and egress IP, for relay and smuggling the raw received message
with its `Received:` chain and token, the sign-off reference, AUTH lines redacted.

---

## Chain table

| Finding | Standalone | Where it goes next |
|---|---|---|
| Open relay confirmed | High | Report. Spam and phishing from the client's IP; no further sending. |
| Relay via sender-domain trust | High | Report. Also hand the inbound-spoof angle to `hunt-tls-network` Phase 4. |
| VRFY/EXPN/RCPT oracle | Low | Valid usernames feed `hunt-brute-force` against exposed OWA/IMAP/SMTP AUTH, if that is in scope. |
| Cleartext AUTH accepted | Medium | Pair with `hunt-brute-force` lockout findings; no mailbox access. |
| `AUTH NTLM` leak | Low | `hunt-ntlm-info` decodes it; internal hostname and AD domain inform `m365-entra-attack` and `hunt-exposed-panels`. |
| Smuggling, inbound accepted | Low to Medium | Spoof proof and DMARC context in `hunt-tls-network` Phase 4. |
| Exchange on-prem identified on 25/587 | Info | OWA/ECP/EWS version and CVEs: `hunt-exposed-panels`; NTLM: `hunt-ntlm-info`. Exchange 2016/2019 left support on 2025-10-14. |
| Zimbra MTA identified | Info | Web client version and KEV list: `hunt-exposed-panels`; SMTP-reachable KEVs in the CVE matrix. |
| Weak TLS on any mail port | Per `hunt-tls-network` | Separate finding, separate skill. |

---

## Validation checklist

- [ ] Every address confirmed client-owned (ASN, RDAP, PTR) and in the signed
      scope; no hosted-provider MX was tested.
- [ ] Probed from outside every client network; egress IP in the evidence.
- [ ] Stage A probes sent no `MAIL FROM`, `RCPT TO`, `DATA` or credential, and
      at most one VRFY/EXPN pair per host.
- [ ] nmap scripts named one by one and checked with `--script-help`; no `-sC`,
      `-A` or category selector.
- [ ] Every Stage B action has a logged written sign-off naming host, action,
      addresses, message count and window.
- [ ] Relay and smuggling used a sender domain you own, a recipient you own or
      the engagement test mailbox, one message per test, a unique token, no
      links or attachments.
- [ ] Relay confirmed by token arrival plus the target in the `Received:` chain,
      not by a `250`.
- [ ] Enumeration oracle checked against a random negative and catch-all.
- [ ] Greylisting, tarpit and blocklist effects ruled out before calling
      anything closed or filtered.
- [ ] Version claims come from a banner or the client, and are labelled
      unconfirmed; no exploit or crash trigger sent.
- [ ] SPF/DKIM/DMARC and cipher findings handed to `hunt-tls-network`, NTLM to
      `hunt-ntlm-info`, webmail to `hunt-exposed-panels`.
- [ ] AUTH blobs redacted; test account rotated after the engagement.

---

## Sources

External sources (checked October 2026): SEC Consult smuggling
<https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/>,
CERT/CC <https://kb.cert.org/vuls/id/302671>, Postfix
<https://www.postfix.org/smtp-smuggling.html>, Exim
<https://www.exim.org/static/doc/security/>, Sendmail
<https://ftp.sendmail.org/RELEASE_NOTES>, STARTTLS research
<https://nostarttls.secvuln.info/>, CISA KEV
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>, HackerOne
<https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings>,
Bugcrowd VRT <https://github.com/bugcrowd/vulnerability-rating-taxonomy>,
smtp-user-enum <https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum>,
Reject Direct Send <https://office365itpros.com/2025/04/30/reject-send-exo/>.
RFCs: 5321, 7435, 7672, 8314, 8460, 8461 (<https://www.rfc-editor.org/rfc/rfcNNNN>).

---

## Related Skills & Chains

- `hunt-exposed-services`: the generic non-HTTP triage this skill specialises;
  its `legacy-and-infoleak.md` open-proxy rule (own canary, token plus source
  IP) is the rule 6a applies to SMTP.
- `hunt-tls-network`: SPF/DKIM/DMARC and the inbox-delivery spoof proof (Phase
  4), cipher and certificate audit on mail ports (Phase 1).
- `hunt-ntlm-info`: decoding `AUTH NTLM` challenges from SMTP, IMAP and POP3.
- `hunt-exposed-panels`, `hunt-auth-bypass`, `hunt-xss`: OWA, ECP, EWS,
  ActiveSync and every webmail client.
- `m365-entra-attack`: hosted Microsoft tenants, including enumeration that
  runs through Microsoft rather than the client.
- `hunt-brute-force`: any credential guessing against IMAP, POP3 or SMTP AUTH.
- `offensive-osint` §16.14: MX-to-provider inference and the presence lookups
  Step 4 builds on.
- `evidence-hygiene`, `triage-validation`, `report-writing`, `bugcrowd-reporting`:
  evidence handling, false-positive gates, write-up and VRT mapping.

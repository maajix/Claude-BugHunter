# SMTP smuggling

Disclosed by Timo Longin / SEC Consult, 18 Dec 2023
(<https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/>);
CERT/CC VU#302671 (<https://kb.cert.org/vuls/id/302671>, 16 Jan 2024).

## Mechanism

SMTP ends the DATA phase with `<CR><LF>.<CR><LF>`. Servers disagree on whether a
**bare** `<LF>` or bare `<CR>` around the dot also terminates DATA. The attack
chains two servers that disagree:

- The **outbound** (sending) server accepts a message whose body contains a
  non-standard sequence such as `<LF>.<CR><LF>` and forwards it **without
  normalising** the sequence.
- The **inbound** (receiving) server reads that sequence as end-of-DATA. The
  bytes after it are parsed as a *new* SMTP transaction — `MAIL FROM`, `RCPT
  TO`, `DATA` — with an envelope the attacker chose.

Because the second (smuggled) message leaves the outbound server's IP, it passes
that server's SPF, and can carry a `From:` the attacker picked, defeating DMARC
alignment. SEC Consult demonstrated smuggling from Exchange Online (which passed
`<LF>.<CR><LF>` outbound) into Postfix, Sendmail and Cisco Secure Email inbound.

## Why every test is one-sided

A smuggling finding is a property of a **pair** of servers, so each test answers
exactly one side, and you never run it against a pair you do not both own or
have in scope:

- **Inbound test (client MX as receiver).** Does the client's MX accept a
  malformed end-of-data? Send one message to the engagement test mailbox *at the
  client domain*, from a domain you own, ending in the candidate sequence; if a
  smuggled second message also arrives, the MX is exploitable. This is the
  common bug-bounty case.
- **Outbound test (client submission server as sender).** Does the client's 587
  server pass the sequence through unfiltered? Needs the engagement test account
  and a receiving analysis server you run (the tool's analysis server, or
  Poddebniak's fake-mail-server). This matters most when the client is itself a
  mail provider: its customers could then smuggle as any domain whose SPF lists
  the client.

Never smuggle *as* a real person, a client executive, or a real brand. Sender
domain = one you own; recipient = a mailbox you own or the engagement's test
mailbox. One message per candidate sequence.

## Candidate end-of-data sequences

`smtpsmug` (Hanno Böck, <https://github.com/hannob/smtpsmug>) names them; verified
from its source:

| Test | Bytes sent around the dot |
|---|---|
| `lflf` | `\n.\n` |
| `crcr` | `\r.\r` |
| `crlf` | `\r.\n` |
| `lfcr` | `\n.\r` |
| `lfcrlf` | `\n.\r\n` |
| `crlflf` | `\r\n.\n` |
| `crcrlf` | `\r.\r\n` |
| `crlfcr` | `\r\n.\r` |
| `nullbefore` | `\r\n\x00.\r\n` |
| `nullafter` | `\r\n.\x00\r\n` |
| `pipelining` | tests whether the server accepts bad protocol synchronisation (the Postfix mitigation target) |

## Tools (both Stage B — each sends real mail)

```bash
# smtpsmug: ONE message per run. Always override the demo addresses.
python3 smtpsmug --list-tests
python3 smtpsmug -c lfcrlf -f probe@canary.example.net \
        -t pentest-mailbox@client.example "$TARGET"
```

`smtpsmug` sends a single message ending in the chosen sequence and prints
whether the server took it as end-of-data (`250`) or rejected it. Its defaults
are `alice@example.org` / `bob@example.org`, so `-f` and `-t` are mandatory.
`-s`/`--tls` switches to port 465; `-u`/`-p` authenticate for an outbound test.
Its `pipelining` test sends two messages to probe the Postfix anti-smuggling
check.

```bash
# SEC Consult scanner: sends a SERIES of messages in one run. Count them all in
# the sign-off, and set your own sender domain.
python3 smtp_smuggling_scanner.py --sender-domain canary.example.net you@canary.example.net
```

SEC Consult's `smtp_smuggling_scanner.py`
(<https://github.com/The-Login/SMTP-Smuggling-Tools>) defaults its sender to
`check.smtpsmuggling.com` (a domain with a permissive SPF the author maintains);
use `--sender-domain` with a domain you control, or expect your mail to be
filtered. It also ships an SMTP analysis server for the outbound side.

## Confirmation

A `250` to a malformed ending proves the inbound server *accepted* the sequence,
which is suspicious but not yet smuggling. Smuggling is confirmed when a
**second, smuggled message actually arrives** at your mailbox — i.e. you receive
mail from the smuggled envelope (`smuggled@...` / your injected `MAIL FROM`), not
just the wrapper message. Keep the raw received source of both messages.

## Current vendor status (version context for the report)

| Server | Status |
|---|---|
| Postfix | `< 3.9` exposed by default (`smtpd_forbid_bare_newline = no`); `3.9+` defaults to `normalize`. Backport setting exists for 3.5.23/3.6.13/3.7.9/3.8.4 but still defaults off. CVE-2023-51764. |
| Exim | Fixed CVE-2023-51766 in 4.97.1; a second variant CVE-2026-94057 fixed in 4.100.1. |
| Sendmail | 8.18.1 rejects bare CR/LF and enforces `CRLF.CRLF` by default; CVE-2023-51765. `srv_features` `U`/`G` re-open it. |
| Exchange Online | Microsoft fixed the outbound pass-through; inbound smuggling into it is constrained because its inbound path needs BDAT. |
| Cisco Secure Email | Default is "Clean messages of bare CR and LF"; the strict "Reject" option and config guidance exist. Historically the open end of the matrix. |

See `mta-cve-matrix.md` for the full version table and the exact Postfix
workaround parameters.

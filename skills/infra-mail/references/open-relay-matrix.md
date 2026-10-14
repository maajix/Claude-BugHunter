# Open relay: the test matrix

An open relay accepts mail from an unauthorized sender and delivers it to a
recipient in a domain it is not responsible for. The confusion that wastes most
reports is treating "the server took my `RCPT TO` for an external domain" as
proof. It is not. Four behaviours all answer `250`:

- true relay (the message is delivered onward),
- accept-then-bounce (delivered back to the forged sender, i.e. backscatter),
- accept-then-quarantine,
- accept-then-silently-discard.

Only the first is an open relay. The others are at most a backscatter nuisance.
**Confirmation needs the message to arrive at a mailbox you control, carrying a
unique token, with the target host in the `Received:` chain** — the same rule
`hunt-exposed-services/references/legacy-and-infoleak.md` applies to open HTTP
and SOCKS proxies.

All testing in this file is **Stage B**: it sends mail. It needs the written
sign-off block from SKILL.md Step 6, naming the exact sender and recipient
addresses and the one-message limit.

## The two directions, and why only one is usually a bug

| Direction | MAIL FROM | RCPT TO | Should the MTA accept it? |
|---|---|---|---|
| Inbound (legitimate) | any external | a domain the MTA hosts | Yes. This is how it receives mail. |
| Outbound (legitimate) | a domain it hosts, authenticated | any external | Yes, for its own authenticated users. |
| **External-to-external (relay)** | external domain you don't own | external domain the MTA does not host | **No. If yes, open relay.** |
| Null sender probe | `<>` | a domain it hosts | Yes (bounces use `<>`); not relay. |

The classic open relay is the third row: an unauthenticated client on the
internet getting the MTA to carry mail between two domains that are both
foreign to it. That is what a spammer wants and what you are testing for.

Two near-misses that look like relay and are graded lower:

- **Sender-domain trust.** The MTA rejects `MAIL FROM:<you@external>` but
  accepts `MAIL FROM:<anything@client-owned-domain>` for an external recipient,
  because it trusts its own domains as senders without authentication. Still
  abusable (spoof an internal sender to an external target), graded High, but
  the fix and the framing differ, so test it explicitly.
- **Authenticated relay with no sender binding.** After AUTH with the test
  account, the server lets that account set `MAIL FROM` to any address and
  deliver anywhere. That is an authenticated-user spoofing issue (Medium), not
  an open relay.

## The 16 address encodings

Modern MTAs reject the naive `user@external` relay but historically mishandled
alternate address forms that resolve to an external destination. `smtp-open-relay`
(Nmap, `discovery`/`intrusive`/`external`) encodes exactly these 16 `MAIL
FROM` / `RCPT TO` pairs, using the target's own name (`srvname`, parsed from the
banner), its IP, a sender local part (`antispam`) and a recipient local part
(`relaytest`). Verified against the Nmap 7.99 `smtp-open-relay.nse` source:

| # | MAIL FROM | RCPT TO | Trick |
|---|---|---|---|
| 1 | `<>` | `relaytest@DOMAIN` | null sender to foreign domain |
| 2 | `antispam@DOMAIN` | `relaytest@DOMAIN` | plain foreign-to-foreign |
| 3 | `antispam@SRVNAME` | `relaytest@DOMAIN` | sender claims to be the server itself |
| 4 | `antispam@[IP]` | `relaytest@DOMAIN` | sender as IP literal |
| 5 | `antispam@[IP]` | `relaytest%DOMAIN@[IP]` | percent-hack via IP literal |
| 6 | `antispam@[IP]` | `relaytest%DOMAIN@SRVNAME` | percent-hack via server name |
| 7 | `antispam@[IP]` | `"relaytest@DOMAIN"` | quoted local part |
| 8 | `antispam@[IP]` | `"relaytest%DOMAIN"` | quoted percent-hack |
| 9 | `antispam@[IP]` | `relaytest@DOMAIN@[IP]` | double-at via IP |
| 10 | `antispam@[IP]` | `"relaytest@DOMAIN"@[IP]` | quoted double-at |
| 11 | `antispam@[IP]` | `relaytest@DOMAIN@SRVNAME` | double-at via server name |
| 12 | `antispam@[IP]` | `@[IP]:relaytest@DOMAIN` | source route via IP |
| 13 | `antispam@[IP]` | `@SRVNAME:relaytest@DOMAIN` | source route via server name |
| 14 | `antispam@[IP]` | `DOMAIN!relaytest` | UUCP bang path |
| 15 | `antispam@[IP]` | `DOMAIN!relaytest@[IP]` | bang path + IP |
| 16 | `antispam@[IP]` | `DOMAIN!relaytest@SRVNAME` | bang path + server name |

Output `Server is an open relay (N/16 tests)` means N encodings were accepted at
the RCPT level. **The script proves acceptance, not delivery** — it never sends
DATA. So a non-zero result is a lead to confirm with a real delivery, not a
confirmed relay.

### Why the script is intrusive, and the trap in its default

- It issues real `MAIL FROM`/`RCPT TO` sequences, which anti-relay rules,
  spam filters and IDS log as relay attempts — your IP can be blocklisted.
- **Its default `domain` is `nmap.scanme.org`.** Left unchanged, every one of
  the 16 pairs is an attempt to relay mail *to a third party you do not own*,
  which is the same violation as nmap's `http-open-proxy`. Always override both
  endpoints to a domain you control:

```bash
# Stage B: written sign-off required. Both endpoints must be domains you own.
nmap -Pn -p 25,465,587 --script smtp-open-relay \
  --script-args smtp-open-relay.domain=canary.example.net,smtp-open-relay.from=probe,smtp-open-relay.to=relay-canary \
  "$TARGET" -oN "evidence/${TARGET}_relay_nse.txt"
```

Even so, the NSE result is only the acceptance half. Confirm delivery with a
single `swaks` message (SKILL.md Step 6a) carrying a token, and check your
receiver.

## Confirming delivery with swaks

```bash
# Stage B. One message, one token, your own sender and receiver.
TOKEN="$(openssl rand -hex 8)"
swaks --server "$TARGET" --port 25 --ehlo probe.canary.example.net \
      --from "probe@canary.example.net" --to "relay-canary@canary.example.net" \
      --header "Subject: relay $TOKEN" --body "Authorized relay test $TOKEN" \
      2>&1 | tee "evidence/${TARGET}_relay_${TOKEN}.txt"
# Then, at your receiver: confirm the token arrived AND the Received: chain
# names $TARGET as the hop that delivered it.
```

For the sender-domain-trust variant, repeat with `--from
"probe@<client-owned-domain>"`. For submission-port relay, add `--port 587` (and
`--tls` where STARTTLS is required) with **no** `--auth`: an unauthenticated
relay on 587 is as serious as on 25.

## Grading

| Proven | Grade |
|---|---|
| External-to-external delivery confirmed (token + Received chain), unauthenticated | High |
| Unauthenticated relay on 587/465 without AUTH | High |
| Relay accepted because the sender used the client's own domain | High |
| Authenticated account can send as any address / to anywhere with no binding | Medium |
| RCPT accepted for a foreign domain, but no message ever delivered | Not a finding (accept-then-drop/bounce); note backscatter if bounces reach a forged sender |
| Backscatter only (bounce to forged sender), program accepts it | Low |

Bugcrowd's VRT (2026-07-08) has no open-relay node; map to `Server Security
Misconfiguration > Mail Server Misconfiguration` and justify the severity in the
submission (`bugcrowd-reporting`). HackerOne has no blanket exclusion for relay,
unlike SPF/DKIM/DMARC.

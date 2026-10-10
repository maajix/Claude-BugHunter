# Legacy protocols, open relays and information leaks

These services rarely produce a Critical on their own. They produce three things
that matter: cleartext credentials in transit, internal topology for free, and a
host that other people can abuse against third parties. Triage them honestly.
A `finger` daemon is not a Critical, and saying so costs you credibility on the
findings that are.

All probes here are **Stage A**. Nothing in this file writes to a target or
attempts a login. The one exception to "sends nothing onward" is the open-proxy
test, which by its nature relays a request through the target: that relay must
terminate at a canary **you own**, never at a third party.

## Port map

| Port | Service | What the exposure is worth |
|---|---|---|
| 23 | Telnet | Credentials and the whole session in cleartext. On a network device this is the management plane. The banner usually names the vendor, model and firmware. |
| 512, 513, 514 | rexec, rlogin, rsh | Trust-based authentication from the 1980s: `.rhosts` / `hosts.equiv` grants access by source address alone, and rexec sends the password in the clear. Exposure to the internet is indefensible. |
| 79 | finger | Enumerates local usernames, login times and sometimes home directories and shell history paths. |
| 113 | ident | Maps a TCP connection back to the local username that owns it. Useful to an attacker as a service-account name oracle. |
| 1026 | rusersd (via rpcbind) | Lists logged-in users over RPC. |
| 7 | echo (TCP and UDP) | No information value. The UDP form is a reflection amplifier and is the reason it should be off. |
| 123/udp | NTP | A correctly configured NTP server is not a finding. A server answering mode-6 and mode-7 control queries (`monlist`, `rv`) leaks its peer list, internal clock sources and OS build, and amplifies reflected traffic heavily. |
| 1080 | SOCKS | An unauthenticated SOCKS proxy relays arbitrary TCP for anyone on the internet. |
| 3128, 8080 | Squid and other HTTP proxies | An open forward proxy relays HTTP for anyone. If it also reaches internal addresses or the cloud metadata service, the severity jumps. |
| 5060, 5061 | SIP | Leaks the PBX vendor and version, enumerable extensions, and in the worst case allows unauthenticated call routing (toll fraud). |
| 5353/udp | mDNS | Designed for link-local use. Reachable from the internet it leaks hostnames, service types and OS details of the whole local segment. |
| 3702/udp | WS-Discovery | Same category: intended for the LAN, leaks device inventory, and is a known reflection amplifier. |

## Stage A probes

```bash
TARGET="192.0.2.10"

# Telnet: banner only. Send nothing, do not attempt a login.
timeout 10 nc -w 5 "$TARGET" 23 < /dev/null | head -c 1024 | strings

# finger: the empty query lists logged-in users on most implementations
printf '\r\n' | timeout 10 nc -w 5 "$TARGET" 79 | head -40

# ident: ask about a connection you already own, never a guessed pair
printf '%s, %s\r\n' "$LOCAL_PORT" "22" | timeout 10 nc -w 5 "$TARGET" 113

# rpcbind: what RPC programs are registered (rusersd, mountd, nfs, ...)
rpcinfo -p "$TARGET"

# NTP: read-only variable requests only
ntpq -c rv "$TARGET"
ntpq -c "readvar 0 version" "$TARGET"
# monlist is NOT issued here: it is the amplification probe, and it is sent
# exactly once, under measurement, in the section below.

# SIP: OPTIONS is a non-state-changing method per RFC 3261
printf 'OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK-probe\r\nFrom: <sip:probe@%s>;tag=probe\r\nTo: <sip:%s>\r\nCall-ID: probe@%s\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n' \
  "$TARGET" "$LOCAL_IP" "$LOCAL_IP" "$TARGET" "$LOCAL_IP" \
  | timeout 10 nc -u -w 5 "$TARGET" 5060 | head -30
```

### Open-proxy and open-relay testing

An open proxy is confirmed by relaying a request to **your own** canary host and
seeing it arrive. Never relay to a third party: that makes you the abuser and
the log entry has your fingerprints on it.

```bash
# Stand up a canary you control that logs the source IP and the unique token.
CANARY="https://canary.example.com/$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# HTTP proxy (Squid and friends): absolute-URI request
curl -s -m 10 -x "http://$TARGET:3128" "$CANARY" -o /dev/null -w '%{http_code}\n'

# SOCKS proxy
curl -s -m 10 --socks5-hostname "$TARGET:1080" "$CANARY" -o /dev/null -w '%{http_code}\n'
```

**Do not use nmap's `socks-open-proxy` or `http-open-proxy` for this.** Both
carry the `external` category alongside `safe`, and `external` is the tell: they
confirm the proxy by relaying through the target to real third-party websites.
You are not authorized to send traffic to those sites from the client's address,
and the log entry lands in someone else's infrastructure. Both are also in the
`default` category, which is one more reason `-sC` and `-A` are not Stage A.

Confirmation requires **both**: the unique token appears in your canary's log,
**and** the source IP in that log entry is the target, not yours. A 200 from
curl alone proves nothing, because a captive portal or an error page also
returns 200. If the proxy also reaches `169.254.169.254` or an RFC 1918 address
on the target's side, record that separately and treat it as an SSRF-class
finding; `hunt-ssrf` owns the escalation logic.

### Amplification findings

For NTP, echo, mDNS and WS-Discovery, the reportable fact is the **amplification
ratio**: bytes returned divided by bytes sent, measured once, from an address
you own, with no source spoofing.

```bash
# One request, one response, measured. Do not loop this.
timeout 10 tcpdump -i any -nn -c 4 "host $TARGET and udp port 123" -w ntp-amp.pcap &
ntpdc -n -c monlist "$TARGET" > /dev/null 2>&1
wait
```

Note that nmap's `ntp-monlist` is categorised `discovery` and **`intrusive`**:
the requests are read-only, but they are precisely the amplification request
pair, so it is not a Stage A script even though the manual probe above is
acceptable as a single measured request.

Rules that are not negotiable: never spoof a source address, never send more
than a single request per service, and never aim a reflector at anything other
than your own measurement host. A spoofed packet is participation in a DDoS, not
a test.

Grade these as Medium at most. The impact is on third parties, not on the
client's confidentiality or integrity, and the remediation is a firewall rule or
`restrict noquery`. Say that in the report.

**The NTP CVE that matches this symptom** is **CVE-2013-5211**: the `monlist`
traffic-amplification denial of service in `ntpd` before 4.2.7p26, via the
`REQ_MON_GETLIST` and `REQ_MON_GETLIST_1` mode-7 requests, exploited in the wild
from December 2013. Unauthenticated, over spoofable UDP. If `monlist` answers,
cite this one.

Two near misses, because both get miscited constantly:

- **CVE-2023-26551** is an out-of-bounds write in `mstolfp` in NTP 4.2.8p15, but
  NVD states explicitly that an adversary "may be able to attack a client `ntpq`
  process" and **cannot attack `ntpd`**. It is not a finding against an exposed
  NTP server.
- **CVE-2023-33192** is a crash from an unvalidated NTS cookie length, and it is
  genuinely pre-auth (`AV:N/PR:N/UI:N`, availability High, and it crashes even
  when the server is not configured for NTS), but it affects **`ntpd-rs`**
  versions 0.3.0 up to below 0.3.3, the Rust implementation, **not** the
  reference C `ntpd`. Check which implementation answered before citing it.

## Telnet: the one place a version banner really matters

Normally a Telnet banner on its own is Informational. These three change that,
so read the banner carefully and check the version before you downgrade the
finding:

| CVE | Product and range | Class | Pre-auth? |
|---|---|---|---|
| CVE-2026-24061 | GNU Inetutils `telnetd` 1.9.3 through 2.7 | `telnetd` passes the client-supplied `USER` environment variable to `login` unsanitised, so a client can request `-f root` and be logged in as root with no credential | **YES.** The client is auto-logged-in as root. An exposed vulnerable `telnetd` is immediate unauthenticated root. |
| CVE-2024-45698 | D-Link DIR-X4860 A1 firmware 1.00 and 1.04 | Hard-coded Telnet credentials combined with OS command injection | YES, per the CNA record: unauthenticated remote attackers. |
| CVE-2023-40478 | NETGEAR RAX30 firmware before 1.0.10.94 | Stack overflow in the Telnet CLI `passwd` handler on port 23 | PARTIAL: adjacent-network, authentication required, though the auth has separately been bypassable on this device. |

If the banner identifies GNU Inetutils in the CVE-2026-24061 range, you have a
Critical finding from the banner alone. **Do not log in to prove it.** A root
shell is past this bundle's boundary, and here the proof costs you nothing: the
version string plus the advisory is the report. Record the banner, the exact
version, and stop.

## What not to write up

- A plain Telnet or finger banner with no credential, no version in a CVE range
  and no device identification: Informational. Bundle it into a hardening
  section rather than filing it separately.
- "Weak cipher on the Telnet port": Telnet has no ciphers. If the finding is TLS
  on some other port, that is `hunt-tls-network`.
- SIP extension enumeration: that is credential-adjacent brute force and belongs
  to `hunt-brute-force` with its own sign-off, not here.
- rlogin or rsh access obtained by matching a trusted source address: stop at
  "the service trusts source addresses and is internet-reachable". Actually
  obtaining the session is unauthenticated access to a host, which this bundle
  ends at. Nothing you do after the shell prompt belongs in the report.

## Checklist

- [ ] Each service identified from its own reply, not the port number.
- [ ] No login attempted on Telnet, rlogin, rsh or rexec.
- [ ] Open-proxy confirmation used a unique token on a canary you control, and
      the canary log shows the **target's** IP as the source.
- [ ] No request relayed to any third-party host.
- [ ] Amplification measured with exactly one unspoofed request per service.
- [ ] No source address spoofed, ever.
- [ ] Amplification and info-leak findings graded Medium or below, with the
      third-party nature of the impact stated plainly.

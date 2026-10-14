# Algorithm posture, ssh-audit semantics, keys and certificates

The algorithm list is where SSH reports go to die. A stock, fully patched
OpenSSH fails an ssh-audit run, so the question is never "did ssh-audit print
`[fail]`" but "does this offer let someone do something the program pays for".
Almost always the answer is no, and the honest grade is Informational or Low.

## The OpenSSH baseline moves; know which baseline you are judging

| Release (date) | Change that matters externally |
|---|---|
| 7.4 (2016-12-19) | sshd removed pre-authentication compression. A server offering plain `zlib` (not `zlib@openssh.com`) with an OpenSSH 7.4+ banner is not a real OpenSSH sshd. |
| 9.6 (2023-12-18) | Strict key exchange (`kex-strict-s-v00@openssh.com`), the Terrapin countermeasure. |
| 9.8 (2024-07-01) | regreSSHion fixed. `PerSourcePenalties` enabled by default. sshd split into a listener and `sshd-session`. |
| 9.9 (2024-09-19) | `mlkem768x25519-sha256` available by default. DSA disabled at compile time. Up to 4 s of random jitter added to the login grace time. |
| 10.0 (2025-04-09) | `mlkem768x25519-sha256` becomes the default key agreement. DSA removed. sshd drops all finite-field DH (`diffie-hellman-group*` and `diffie-hellman-group-exchange-*`) from its default `KexAlgorithms`. AES-GCM preferred over AES-CTR. |
| 10.1 (2025-10-06) | The ssh **client** warns when a non-post-quantum key agreement is negotiated (`WarnWeakCrypto`). |
| 10.3 (2026-04-02) | `invaliduser` penalty added to `PerSourcePenalties`. |
| 10.4 (2026-07-06) | GSSAPI no longer answers differently for valid and invalid users; minimum auth delay fixes (CVE-2026-60001). |
| 10.6 (2026-10-06) | sshd gains `WarnWeakCrypto`, on by default, logging clients that use a non-PQ key agreement. |

Practical consequences:

- Finite-field DH in a server's offer means OpenSSH before 10.0, a distro that
  re-enabled it, or a non-OpenSSH stack. It is also why nmap's `ssh-hostkey`
  (finite-field DH only) returns nothing against 10.x.
- A `DSA` host key on OpenSSH 10.x cannot exist; on an older server it is a
  weak-key finding (80-bit security level per the 9.9 notes).

## PerSourcePenalties: how the server treats you

Defaults from `sshd_config(5)`: `crash:90s authfail:5s invaliduser:5s
refuseconnection:10s noauth:1s grace-exceeded:10s max:10m min:15s`, no exempt
addresses, `MaxStartups 10:30:100`, `LoginGraceTime 120`, `MaxAuthTries 6`.

What a penalized source sees, lab-verified on OpenSSH 10.5 after twenty rapid
`ssh-keyscan` connections:

- `ssh` prints `kex_exchange_identification: read: Connection reset by peer`.
- `ssh-keyscan` prints **nothing at all**: an empty keyscan right after a good
  one is the penalty, not a vanished host key.
- The server logs `drop connection #0 from [...] penalty: connections without attempting authentication`.

Stop, wait out `max` (10 minutes by default), and slow down.

## Reading ssh-audit (v3.9.0, released 2026-07-04)

| Output | Meaning |
|---|---|
| `[fail]` | ssh-audit's policy says remove it. Stock OpenSSH 10.5 gets `[fail]` for `ecdh-sha2-nistp256/384/521` (NIST curves) and `hmac-sha1` / `hmac-sha1-etm`. |
| `[warn]` | Weaker than recommended. 3.9.0 warns on **every** key exchange without post-quantum protection, and on encrypt-and-MAC and 64-bit-tag MACs. |
| `[info]` | Version history ("available since OpenSSH 6.5"), defaults. |
| `(rec)` | Algorithms to add or remove. Hardening advice, not vulnerabilities. |
| `(nfo)` | Notes. The Terrapin note appears **even when the server advertises strict KEX**, because an unpatched client could still negotiate the affected modes. |
| `(fin)` | Host-key fingerprints. Same values as A1; cross-check them. |
| exit code | `0` good, `1` connection error, `2` warnings, `3` failures. Stock OpenSSH 10.5 exits `3`. |

Two facts that stop bad reports:

- Since 3.3.0 ssh-audit no longer prints CVEs from version numbers (the project
  called the old output "wildly inaccurate"). It will not tell you about
  regreSSHion. Use `ssh-cve-matrix.md`.
- The default audit includes a connection-rate test (up to 38 connections in
  1.5 s on 3 sockets) to infer DHEat exposure. Always pass `--skip-rate-test`.
  The DHEat note it would have produced is a hardening item anyway.

## Terrapin (CVE-2023-48795): when it is a finding

Server-side observation that supports a report, from the KEX offer alone:

1. `kex-strict-s-v00@openssh.com` is **absent** from the server's key exchange list, and
2. the server offers `chacha20-poly1305@openssh.com`, or any `-cbc` cipher together
   with an `-etm@openssh.com` MAC.

Then state the limits: exploitation needs an active network-layer MITM; the
practical effect is stripping the `EXT_INFO` message (most often weakening RSA
client-auth signature negotiation) and, against OpenSSH 9.5, disabling
keystroke-timing obfuscation. AES-GCM is not affected; CTR+EtM is theoretical.
Grade Low, often closed as theoretical. If the server has the strict marker, it
is not a server finding at all.

## Post-quantum key exchange

Not offering `mlkem768x25519-sha256` or `sntrup761x25519-sha512` exposes
recorded sessions to a future quantum adversary ("store now, decrypt later").
OpenSSH, ssh-audit and the 10.6 sshd log all flag it. It is a migration item:
Informational, unless the program explicitly scores crypto agility.

## DHEat (CVE-2002-20001)

Finite-field DH makes the server do expensive modular exponentiation for an
attacker who sends cheap garbage. Detection is the presence of `diffie-hellman-group*`
or `diffie-hellman-group-exchange-*` in the offer. Testing it is a denial of
service: `ssh-audit --dheat` is forbidden and `--conn-rate-test` is Stage B.
Report as a hardening item; `MaxStartups`, `PerSourcePenalties` and the 10.0
default already mitigate.

## What can carry a grade above Informational

| Observation | Usual grade | Why |
|---|---|---|
| SSH protocol 1 (`SSH-1.99-` or `SSH-1.5-`) | Low to Medium | Protocol 1 is broken; OpenSSH removed it entirely. Rare and worth a line. |
| `none` cipher or MAC offered | Medium | Plaintext session possible if both sides agree. Verify it is offered server-side, not inferred. |
| `diffie-hellman-group1-sha1` (1024-bit), `arcfour*`, `3des-cbc`, `hmac-md5*` | Low | Weak, but exploitation needs a downgrade or MITM. Also a honeypot hint on a modern banner. |
| RSA host key under 2048 bits, any DSA host key | Low to Medium | Offline factoring/forgery risk scales with size. |
| Known-compromised host key (`badkeys`) | High | Anyone can impersonate the host with the published private key. |
| Same host key across many hosts | Medium | Golden image or vendor key; host impersonation if it leaks. |

## Keys and certificates

**Host certificates.** `ssh-keyscan -c` returns them; `ssh-keygen -L` shows the
signing CA fingerprint, key ID, validity and principals. Lab-verified: principals
are printed verbatim, so a certificate issued for `host.internal.example,10.0.0.5`
leaks both the internal name and the internal address. Expired host certificates
mean clients are trained to ignore warnings. Both are Low, and both are recon
inputs.

**User certificates.** A server that trusts a user CA (`TrustedUserCAKeys`) gives
no external sign of it. If a leaked bundle contains a user certificate
(`*-cert.pub`), `ssh-keygen -L` on it shows principals, validity and
`force-command`; an unexpired certificate plus its private key is a credential
under B1. Apache MINA SSHD before 2.19.0 / 3.0.0-M5 did not enforce
`force-command` from certificates (CVE-2026-56624).

**FIDO keys.** `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`
private-key files are handles for a hardware authenticator; without the token
they cannot sign. A leaked handle that the server accepts (PK_OK) proves the
authorization exists, not that access does. `server-sig-algs` listing `sk-*`
and `webauthn-sk-*` is the OpenSSH default and says nothing about enforcement.

**Leaked private keys, recognising them.** Search patterns for
`hunt-source-leak`: the header text `BEGIN OPENSSH PRIVATE KEY`,
`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN DSA PRIVATE KEY`, and
PuTTY's `PuTTY-User-Key-File-`. `ssh-keygen -y -f key` prints the public half; a
passphrase prompt means the key is encrypted. Do not crack it; report the leak
and, under Stage B, the PK_OK result for the public half.

Sources: <https://www.openssh.org/releasenotes.html>,
<https://man.openbsd.org/sshd_config>, <https://github.com/jtesta/ssh-audit>,
<https://terrapin-attack.com/>, <https://github.com/badkeys/badkeys>,
NVD CVE-2002-20001, CVE-2023-48795, CVE-2026-56624.

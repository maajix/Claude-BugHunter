# IKE transforms, grading and reply codes

Depth for Step 4 of `SKILL.md`. Load it when you need a `--trans` value, the
bounded enumeration list, or the RFC tier of an algorithm a responder accepted.

## IKEv1 attribute values for `ike-scan --trans`

ike-scan's short transform form is `enc[/keylen],hash,auth,group`, with the
numeric values from RFC 2409 Appendix A and its IANA registry successors. The
manual's own examples: `--trans=5,2,1,2` is 3DES-CBC, SHA1, pre-shared key,
DH group 2; `--trans="(1=7,14=128,2=1,3=3,4=5)"` is AES-128, MD5, RSA
signature, DH group 5 in the attribute=value form.

| Field | Value | Meaning |
|---|---|---|
| Encryption | 1 | DES-CBC |
| | 5 | 3DES-CBC |
| | 7 | AES-CBC (add `/128` or `/256` for the key length) |
| Hash | 1 | MD5 |
| | 2 | SHA1 |
| | 4 | SHA2-256 |
| | 5 | SHA2-384 |
| | 6 | SHA2-512 |
| Auth method | 1 | Pre-shared key |
| | 3 | RSA signature |
| | 65001 | XAUTH, initiator pre-shared key (ike-scan: XAUTH uses 65001 to 65010) |
| DH group | 1 | 768-bit MODP |
| | 2 | 1024-bit MODP |
| | 5 | 1536-bit MODP |
| | 14 | 2048-bit MODP |
| | 15, 16 | 3072-, 4096-bit MODP |
| | 19, 20, 21 | 256-, 384-, 521-bit ECP |

A responder matches the auth method as well as the cipher suite. A transform
refused with auth 1 may be accepted with 3 or 65001, and that difference is
itself information: PSK, certificate or XAUTH peer policies.

## Bounded enumeration list

One `--trans` per run, serial, `probe_delay` between runs, stop each tier at
its first accept. Fourteen packets at most, inside the Stage A budget.

```bash
T="192.0.2.10"
# Tier 1: RFC 8247 MUST NOT. Any accept here is the headline transform finding.
TIER1="1,1,1,1 1,2,1,2 5,1,1,2 5,2,1,1"
# Tier 2: SHOULD NOT or MAY. Accepts here are Low.
TIER2="5,2,1,2 5,2,1,5 7/128,2,1,2 7/256,2,1,5"
# Tier 3: modern. Proves the listener and the auth methods in use.
TIER3="7/256,4,1,14 7/256,4,3,14 7/256,4,65001,14 7/128,2,1,14 7/256,5,1,20 7/256,4,1,19"

for t in $TIER1; do
  sudo ike-scan --retry=1 --interval=1000 --trans="$t" "$T" \
    | grep -qE "Handshake returned" && { echo "ACCEPTED $t" | tee -a "evidence/${T}_ike_trans.txt"; break; }
  probe_delay
done
# Repeat the loop for $TIER2 and $TIER3.
```

Tiers 1 and 2 offer PSK auth (1) only. If tier 3 shows the gateway refuses
auth 1 but accepts 65001 (XAUTH) or 3 (RSA), re-run tiers 1 and 2 with the auth
method Main Mode showed; that still fits the per-host budget of about 20
packets. In tier 3, stop at the first accept per auth method. The Aggressive
Mode probe in `SKILL.md` 4.4 needs an auth 1 or 65001 accept from these runs.

## Grading against the RFCs

RFC 8247 sets algorithm requirement levels for IKEv2; they are also the
yardstick graders use for IKEv1. RFC 9395 (April 2023) deprecates IKEv1 itself
and moves RFCs 2407, 2408 and 2409 to Historic.

| Algorithm | RFC 8247 level | Grade when accepted |
|---|---|---|
| ENCR_DES | MUST NOT | Medium if negotiated by default, else Low |
| ENCR_3DES | MAY | Low or Informational; not a headline |
| ENCR_AES_CBC (128, 256) | MUST | Fine |
| ENCR_AES_GCM_16, ENCR_CHACHA20_POLY1305 | SHOULD | Fine |
| PRF_HMAC_MD5 | MUST NOT | Medium if negotiated by default, else Low |
| PRF_HMAC_SHA1 | MUST- (expected to be downgraded) | Informational |
| AUTH_HMAC_MD5_96, AUTH_DES_MAC | MUST NOT | Medium if negotiated by default, else Low |
| AUTH_HMAC_SHA1_96 | MUST- | Informational |
| DH group 1 (768-bit MODP) | MUST NOT | Medium if negotiated by default, else Low |
| DH group 22 (1024-bit MODP, 160-bit subgroup) | MUST NOT | As group 1 |
| DH groups 2 and 5 (1024-, 1536-bit MODP) | SHOULD NOT | Low |
| DH groups 23 and 24 | SHOULD NOT | Low |
| DH group 14 (2048-bit MODP) | MUST | Fine |
| DH group 19 (256-bit ECP) | SHOULD | Fine |
| IKEv1 at all | Deprecated by RFC 9395 | Informational to Low |

"Negotiated by default" means a stock client offering its normal proposal would
end up on that algorithm, which you see when the responder picks it from
ike-scan's mixed default offer. A weak algorithm that is only accepted when it
is the sole offer is the lower grade.

## IKEv2 notes

ike-scan's IKEv2 mode sends one fixed proposal (from its source): ENCR AES-CBC
256 and 128, 3DES, DES; PRF HMAC-SHA1 and HMAC-MD5; integrity HMAC-SHA1-96 and
HMAC-MD5-96; DH groups 2, 5 and 14. The manual marks IKEv2 support
experimental, and `--trans` is not supported with it. The reply names the one
combination the responder picked, so one probe tells you one accepted set, and
whether the responder prefers weak options when offered both.

| Notify | Number | Read it as |
|---|---|---|
| NO-PROPOSAL-CHOSEN (IKEv1 and IKEv2) | 14 | Listener present, nothing offered was acceptable. |
| INVALID-ID-INFORMATION (IKEv1) | 18 | Aggressive Mode on, the ID was refused. |
| INVALID_KE_PAYLOAD (IKEv2) | 17 | Names the DH group the responder wants. One re-run with that group is Stage A. |
| COOKIE (IKEv2) | 16390 | Responder is defending against half-open load. Back off. |
| IKEV2_FRAGMENTATION_SUPPORTED | 16430 | RFC 7383 fragmentation on. Context for fragmentation CVEs in the matrix. |
| SIGNATURE_HASH_ALGORITHMS | 16431 | RFC 7427 signature auth configured. |

## Vendor IDs and backoff

- ike-scan names vendor ID payloads from its `ike-vendor-ids` pattern file and
  backoff timing from `ike-backoff-patterns`. Both come with the package; keep
  them current with the ike-scan release you run.
- Feature VIDs (XAUTH, Dead Peer Detection, RFC 3947 NAT-T, IKE fragmentation)
  describe capabilities, not vendors.
- strongSwan sends its own VID only with `charon.send_vendor_id = yes`
  (default `no`), and a `Cisco Unity` VID only with `charon.cisco_unity = yes`.
  A `Cisco Unity` VID is therefore a capability claim, not proof of Cisco.
- Backoff fingerprinting needs an accepted transform, because only then does the
  responder retransmit. `--showbackoff` waits 60 seconds after the last packet
  by default. One packet from you, a full retransmit cycle of state on their side.
- Neither VIDs nor backoff give a patch level. Version claims go through
  `enterprise-vpn-attack` for appliances, or stay "unconfirmed".

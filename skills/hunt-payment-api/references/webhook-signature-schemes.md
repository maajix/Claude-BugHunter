# Webhook and callback signature schemes

Companion to `hunt-payment-api`. Know the real scheme before claiming a deviation: the
signed material is the part implementers get wrong, and misattributing one provider's
rule to another produces a false positive that destroys credibility.

## Per-provider schemes

| Provider | Header or field | Algorithm | Signed material | Encoding |
|---|---|---|---|---|
| Stripe | `Stripe-Signature` (`t=`, `v1=`, `v0=`) | HMAC-SHA256 | `<timestamp>` + `.` + raw body | hex |
| Adyen (Standard notifications) | `additionalData.hmacSignature` | HMAC-SHA256 | `:`-joined field string, not the body | Base64 |
| PayPal | `paypal-transmission-sig` plus 4 headers | SHA256withRSA | `transmissionId\|timeStamp\|webhookId\|crc32(raw body)` | Base64 |
| Braintree | `bt_signature` + `bt_payload` | SDK `parse()` | opaque, SDK-internal | n/a |
| Checkout.com | `Cko-Signature` | HMAC-SHA256 | raw body | hex |
| Razorpay | `X-Razorpay-Signature` | HMAC-SHA256 | raw body | hex |
| Klarna | `Klarna-Signature` + `Klarna-Signing-Key-Id` | HMAC-SHA256 | raw JSON body | n/a |
| Square | `x-square-hmacsha256-signature` | HMAC-SHA256 | notification URL + raw body | Base64 |
| Worldpay | `Event-Signature: {keyId}/{hashFunction}/{signature}` | HMAC-SHA256 | raw body | hex |
| Authorize.Net | `X-ANET-Signature` | **HMAC-SHA512** | raw body | hex |
| Mollie | none; body carries only an id | n/a | n/a | n/a |

Two entries decide whole assessments:

- **Authorize.Net is SHA-512**, alone among these providers. A verifier copy-pasted
  from a Stripe or Razorpay integration is simply wrong here.
- **Mollie sends no signature.** The notification body is only a transaction id and the
  merchant must call Mollie's authenticated API for the status. Mollie also advises
  against IP allowlisting because their sending addresses change, which is the opposite
  of Stripe's guidance. Do not carry one provider's rule to another.

## Replay posture

Only Stripe and PayPal put a timestamp **inside** the signed material, so only there
can the signature carry freshness. Stripe's libraries default to a 5-minute tolerance,
and Stripe's docs warn that a tolerance of `0` disables the freshness check entirely.
For Adyen, Razorpay, Checkout.com, Square, Worldpay and Klarna, replay protection must
come from deduplication on the provider's **event id**, not on a timestamp: several
events can share a one-second `created` value, and delivery order is not guaranteed.
Stripe retries live-mode events with exponential backoff for up to three days, and
generates a fresh timestamp and signature for each delivery attempt, so a receiver with
no dedup key double-credits on the provider's own retry with no attacker involved.

## Stage A probe: Stripe scheme

Safe against an in-scope production target **only** with a canary reference that does
not exist. Serial, 3 s apart, hard cap 20 requests. Read the status code and diff the
body against a baseline captured before the probe.

```python
#!/usr/bin/env python3
"""Stripe-scheme webhook verification probe. Authorized testing only.
Canary identifiers only. No real object is referenced."""
import hashlib, hmac, json, sys, time, requests

URL = sys.argv[1]
BODY = json.dumps({
    "id": "evt_canary_probe", "object": "event",
    "type": "checkout.session.completed",
    "data": {"object": {"id": "cs_canary_probe", "status": "complete",
                        "payment_status": "unpaid", "amount_total": 100,
                        "currency": "usd",
                        "client_reference_id": "ord_canary_7f3a"}},
    "livemode": False}, separators=(",", ":"))

def sig(secret: bytes, body: str, ts: int, scheme: str = "v1") -> str:
    mac = hmac.new(secret, f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    return f"t={ts},{scheme}={mac}"

ts = int(time.time())
probes = {
    "no signature header": {},
    "empty-key signature": {"Stripe-Signature": sig(b"", BODY, ts)},
    "garbage signature":   {"Stripe-Signature": f"t={ts},v1={'0' * 64}"},
    "scheme downgrade v0": {"Stripe-Signature": sig(b"", BODY, ts, "v0")},
    "stale timestamp":     {"Stripe-Signature": sig(b"", BODY, ts - 86400)},
}
for label, extra in probes.items():
    r = requests.post(URL, data=BODY, timeout=15,
                      headers={"Content-Type": "application/json", **extra})
    print(f"{label:<22} {r.status_code}  {r.text[:120]!r}")
    time.sleep(3)
```

A 2xx is not the finding. Stage B, sandbox only, repeats the accepted variant against a
real pending object and reads the ledger.

## Raw body versus re-serialized body

The probe that catches a verifier hashing the wrong bytes. Compute one signature over
the canonical serialization, then send semantically identical variants with that same
signature. Anything accepted other than the canonical form proves the verifier
re-serializes before hashing, which is exploitable wherever the attacker controls a
field the re-serializer normalises. Amount precision is the field that matters.

```python
import hashlib, hmac, json, time

SECRET = b"<WEBHOOK-SECRET>"          # known sandbox secret, or b"" for the empty-key case
obj = {"id": "evt_1", "amount": 100, "type": "payment_intent.succeeded"}

variants = {
    "canonical":     json.dumps(obj, separators=(",", ":")),
    "spaced":        json.dumps(obj, indent=2),
    "key reorder":   json.dumps({k: obj[k] for k in reversed(list(obj))},
                                separators=(",", ":")),
    "float amount":  '{"id":"evt_1","amount":100.0,"type":"payment_intent.succeeded"}',
    "exponent":      '{"id":"evt_1","amount":1e2,"type":"payment_intent.succeeded"}',
    "duplicate key": '{"id":"evt_1","amount":1,"amount":100,"type":"payment_intent.succeeded"}',
}
ts = int(time.time())
base = variants["canonical"]
mac = hmac.new(SECRET, f"{ts}.{base}".encode(), hashlib.sha256).hexdigest()
print(f"signature over the canonical form: t={ts},v1={mac}")
for name in variants:
    print(f"  send {name:<14} with that signature; expect reject unless canonical")
```

## Adyen Standard notifications

Adyen Standard payment notifications sign a colon-joined field list rather than the
body, and the HMAC key is distributed as **hex** and must be converted to binary first.
That conversion is the most common integration error.

```python
import base64, binascii, hashlib, hmac

def adyen_sig(hmac_key_hex: str, item: dict) -> str:
    item = dict(item)
    if "amount" in item:
        item["value"] = item["amount"]["value"]
        item["currency"] = item["amount"]["currency"]
    fields = ["pspReference", "originalReference", "merchantAccountCode",
              "merchantReference", "value", "currency", "eventCode", "success"]
    signing = ":".join(str(item.get(f, "")) for f in fields)
    key = binascii.a2b_hex(hmac_key_hex)        # hex key to binary. The gotcha.
    return base64.b64encode(
        hmac.new(key, signing.encode(), hashlib.sha256).digest()).decode()
```

Two details decide whether your reproduction is correct. `success` is signed as the
string the notification carried, so pass `"true"` or `"false"` rather than a boolean.
And colons and backslashes are escaped only in Adyen's HPP scheme, never in Standard
notifications, so an implementation that escapes them here computes a different digest:
send an item whose merchant reference contains both characters to find out which rule
the target applied. Other deviations worth probing are a wrong field order, dropped
empty-string placeholders, the key consumed as UTF-8 instead of hex, and `success=true`
acted on before verification has run.

## Content binding, not just authenticity

A valid signature proves origin. It proves nothing about which object the event
describes or what state that object is in. Test every one of these:

```text
genuine event for object A, while a field the handler actually reads names object B
status versus payment_status: `complete` can carry payment_status `unpaid`
Adyen AUTHORISATION success=true read as "paid", with no CAPTURE_FAILED handling
Adyen CANCEL_OR_REFUND read as an unambiguous void (it is deliberately ambiguous)
refund.created read as completed, with no refund `failed` handling
an unrecognised event `type`: the default branch must ignore, never succeed
a livemode:false event at the live endpoint (one secret per mode and endpoint)
```

Obtaining a genuinely authentic event requires one minimal payment. Make it in the
**sandbox**. Never make it on production to set up an exploit.

## The browser return leg

Razorpay's documented formula is
`hmac_sha256(order_id + "|" + razorpay_payment_id, key_secret)` as a hex digest, with
the instruction "Retrieve the order_id from your server. Do not use the
razorpay_order_id returned by Checkout." A server verifying against the client-supplied
order id lets a valid low-value `(payment_id, signature)` pair be claimed against a
high-value order. The same shape appears wherever an order id crosses a redirect
unsigned, including the 3DS return page.

PayPal's self-verification path tells the merchant which URL to fetch the verification
certificate from, via the attacker-visible `paypal-cert-url` header. Confirm the
merchant pins the host to PayPal's own domain rather than fetching whatever it is
given. Callback-URL registration pointed at loopback, RFC1918 space or cloud metadata
is a real primitive: the methodology for it lives in `hunt-ssrf`.

## Acceptance criteria to report against

```text
missing or invalid signature returns 401, not 200
replay outside the tolerance window is rejected
duplicate event ids are deduplicated before anything is credited
oversized payloads are rejected
internal-IP callback URLs blocked at registration and again at delivery
secret rotation accepts old and new during the window, then only new
one secret per subscription and per mode, not one shared across all subscribers
signing secret at least 32 bytes, held in a secrets manager, service refuses to
  start if it is unset
verification over the raw unparsed body, constant-time comparison, then
  authoritative state re-fetched from the provider before acting
```

That last line is the control that holds even when the signature scheme turns out to be
misimplemented, and it is the recommendation to lead with.

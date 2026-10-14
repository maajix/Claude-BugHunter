---
name: hunt-payment-api
description: "Hunt payment and billing API bugs that live in the merchant's wrapper code and in what it accepts back from the PSP: webhook and IPN verification (fail-open signatures, raw-body mismatch, replay, swapped order references), provider-returned 3-D Secure state treated as authenticated, client-settable SCA exemption flags, minor-unit and zero-decimal currency confusion, fulfilment on non-terminal async states, idempotency-key breaks, payout destination binding. Use on checkout, payment-intent, invoice, subscription, refund, payout, webhook or IPN endpoints, sandbox only."
metadata:
  sources: okf_payment_api_notes, github_security_advisories, stripe_docs, adyen_docs, razorpay_docs, paypal_docs, emv_3ds_220_spec_mirror, emvco_3ds_2311_announcement, owasp_asvs_5
  report_count: 9
---

## Crown Jewel Targets

Payment bugs pay where money moves and where two systems disagree about whether it
moved. Rank targets by integration shape, not by brand:

- **Self-hosted gateways, billing panels and credit/quota top-up systems.** In-house
  verification code, no security budget, a direct path from a forged event to a
  credited balance. Every advisory cited below is this shape.
- **Multi-PSP merchants sharing one "webhook verifier" abstraction.** Algorithm,
  signed material and encoding all differ per provider (HMAC-SHA256 over
  `<timestamp>.<raw body>` for Stripe, HMAC-SHA512 for Authorize.Net, a colon-joined
  field string for Adyen Standard notifications, SHA256withRSA over a CRC32 of the
  body for PayPal). An abstraction that papers over those differences is itself the bug.
- **Marketplaces and payment facilitators.** Tokens, payout destinations and refund
  references cross tenants. A token that decrypts is not a token issued to this account.
- **Low-code and workflow-automation payment nodes.** A trigger node can store a
  signing secret and never check it (CVE-2026-21894). Async rails (ACH, SEPA, Bacs,
  BECS, Boleto) belong here too: fulfilment keyed off a non-terminal state, with a
  reversal window measured in weeks.
- **Platforms with no reconciliation.** Ask during scoping. If nothing compares the
  local ledger against the provider's balance report, no bug in this class is ever
  detected in production. That is a finding on its own.

Lower yield: one PSP called through its documented SDK helper, hosted checkout, no
merchant-side card handling. No advisory surveyed for this skill describes a
verification or money-handling flaw in a major PSP's own server SDK, and none describes
a protocol break in 3DS2. Budget the time against integration code instead.

## OOB/Confirmation Gate: Ledger-Or-It-Didn't-Happen (Read First)

**A 2xx is not a finding.** Payment handlers return 200 to events they ignored, to
events they logged and dropped, and to events a WAF answered. The only proof is a
state delta you read back out of a different surface than the one you wrote to.

Before every probe, snapshot; after every probe, re-read and diff: order status and
fulfilment flag, invoice total and amount due, account or wallet balance, entitlement,
plan and seat count, coupon redemption count, stored-value balance, and the
**provider's own** dashboard or API record for the same object.

Confirmation ladder, strongest first: (1) the provider's record and the application's
record **disagree**, which is the highest-value finding in this class and reportable
with no further exploitation; (2) the application's ledger moved in the attacker's
favour and the provider never saw a corresponding movement; (3) a status flag flipped
(order `paid`, entitlement granted) with no movement; (4) only the HTTP response body
changed, which is **not a finding**, because preview-only effects get recomputed at
capture. Trace it to fulfilment or drop it.

### Two-stage discipline, mandatory

Every probe below is two stages. Stage A is safe against an in-scope production
target. Stage B is **sandbox only**, or a pre-agreed test order with written operator
sign-off naming the value ceiling and who reverses it.

- **Stage A (detect).** Unsigned or forged input aimed at a **canary identifier that
  does not exist** (`ord_canary_<random>`). Observe status code, latency and a body
  diff against a baseline saved before the probe. A handler that returns a
  distinguishable "order not found" after accepting a forged signature has proved
  verification is absent with no state touched.
- **Stage B (execute).** The same forged input aimed at a real object, or any capture,
  void, refund, payout, race or card-testing step. Real money, real fraud signals,
  possible network fines for the merchant. Sandbox or signed-off test order only.

### Rate-limit and velocity posture

Serial with jitter is the default: one request every **3 seconds plus jitter**, hard
cap **20 attempts** per endpoint per session, stop on the first confirmed state change.
Concurrency probes are the only exception and are sandbox-only in a named window.
Card-testing and velocity probes look exactly like a BIN attack to the acquirer:
schedule them in a pre-agreed window and tell a named person at the target first.
Never run volumetric, decompression-bomb or mass-enumeration tests.

## Attack Surface Signals

Signals that this skill applies:

```text
paths        /webhook /webhooks /ipn /notify /callback /payment/verify /return
             /checkout/sessions /payment_intents /charges /invoices /refunds
             /payouts /subscriptions /mandates /top-up /wallet/transfer
headers      Stripe-Signature  Cko-Signature  X-Razorpay-Signature
             X-ANET-Signature  Klarna-Signature  Event-Signature
             x-square-hmacsha256-signature  paypal-transmission-sig
             Idempotency-Key  idempotency-key  PayPal-Request-Id  x-idempotency-key
bodies       amount amount_total unit_amount value minor_units currency
             payment_status status succeeded captured off_session
             setup_future_usage client_reference_id merchantReference trade_no
client side  publishable keys (pk_), PSP SDK script tags, hosted-field iframes,
             return URLs carrying order ids, 3DS challenge iframes
```

Fingerprint the PSP first: a publishable key, SDK script tag, iframe origin or webhook
header name identifies it, and the scheme you must not misattribute follows from it.
Then read that provider's own verification doc.

High-signal secondary observations: an order identifier that crosses a redirect
**unsigned**; a signature whose signed material the server rebuilds from a
client-supplied field; money-bearing fields beyond `amount` (`tip`, `donation`,
`shipping`, `handling`, `fee`, `tax`, `credit`, `adjustment`, `cancellation_amount`,
`seats`); several payment methods writing to one order or balance table; and
`livemode: false` or `test` flags echoed in production responses.

## Step-by-Step Methodology

### 1. Scope the money, in writing, before the first request

Settle: whether a provider sandbox exists and the target is wired to it; two
engagement-owned accounts (ideally two merchants); per-transaction and cumulative value
ceiling; who reverses test charges and by when; sandbox PANs only; the agreed velocity
window and who is told. Log every money-moving request with a timestamp. Without this,
Stage B does not happen.

### 2. Map the machine and build the field inventory

Walk one complete purchase and one complete reversal with interception on, recording
every hop: cart, quote, shipping, tax, checkout session, payment method, SCA/3DS,
authorize, capture, webhook, fulfilment, then refund, webhook, ledger, payout.

```text
field      hops it appears at       client-controlled   re-derived server-side
amount     cart, session, intent    yes                 ?
currency   cart, session, intent    yes                 ?
priceId    cart, confirm            yes                 ?
order_id   confirm, callback        yes                 ?
status     callback, confirm        ?                   ?
```

Any row whose last column is "no" is a candidate. Then find **the single endpoint that
flips an order to paid** and work outward from it.

### 3. Webhook and callback verification (highest yield, Stage A is safe)

Build the reference payload on your **own** provider sandbox first, so the handler's
parser does not reject your probe before verification runs:

```bash
stripe listen --forward-to http://localhost:4242/webhook --print-secret
stripe trigger checkout.session.completed
```

Then, against the target: Stage A, canary order id only, one request every 3 s, each
response diffed against the saved baseline.

```text
a. no signature header at all
b. signature computed with an EMPTY-STRING key          (CVE-2026-41432 class)
c. garbage signature of the right shape
d. unsupported or absent algorithm identifier           (fail-open check)
e. scheme downgrade (Stripe v0 instead of v1)
f. a signature valid over the canonical body, sent with a re-serialized variant
```

Stage B, sandbox only: repeat against a real pending object, read the ledger, and with
one genuine signed event captured from the sandbox also test replay verbatim; replay
after the tolerance window (Stripe libraries default to 5 minutes); replay N times
concurrently; replay out of order after the object was refunded or cancelled; the
genuine event with its order reference repointed at a larger order; an event whose
`type` the handler does not recognise (the default branch must ignore, not succeed);
and a `livemode: false` event at the live endpoint.

Only Stripe and PayPal put a timestamp inside the signed material. For Adyen,
Razorpay, Checkout.com, Square, Worldpay and Klarna, replay protection **cannot** come
from the signature and must come from event-id deduplication. Which model applies is
the most useful early question in the assessment. Scheme table and probe scripts:
`references/webhook-signature-schemes.md`.

### 4. Status acceptance: what the merchant believes the provider said

The signature proves origin. It proves nothing about which object the event describes
or what state that object is in.

```text
1. does the handler read `status` only and ignore `payment_status`
   (an event can be `complete` with payment_status `unpaid`)
2. is an Adyen AUTHORISATION with success=true treated as "paid", with no handling
   for a later CAPTURE_FAILED
3. is `refund.created` treated as completed, with no handling for refund `failed`
4. is the order resolved from the notification's reference, or from merchant records
5. are amount, currency and recipient compared against that specific order
```

Point 5 is the CVE-2026-9189 class: the IPN was genuinely authentic, and the handler
still marked an arbitrary higher-value order paid because it trusted the `invoice`
field and never compared `mc_gross`, `mc_currency` or `receiver_email`.

### 5. The browser return leg

Same risk, none of the protection. Razorpay's docs give the formula
`hmac_sha256(order_id + "|" + razorpay_payment_id, key_secret)` as a hex digest and
instruct: "Retrieve the order_id from your server. Do not use the razorpay_order_id
returned by Checkout." A server verifying against the **client-supplied** order id
lets a valid low-value `(payment_id, signature)` pair be claimed against a high-value
order:

```http
POST /payment/verify HTTP/1.1
Host: shop.example
Content-Type: application/json

{"razorpay_order_id":"order_HIGHVALUE",
 "razorpay_payment_id":"pay_LOWVALUE",
 "razorpay_signature":"<valid signature over order_LOWVALUE|pay_LOWVALUE>"}
```

Also test force-browsing the confirmation or success-return URL directly
(CVE-2022-29254 class: exposure of the gateway's intermediate identifier or success URL
marks a payment complete without funds taken), and substituting one genuine provider
success response body into a later failed transaction.

### 6. Amount and currency at the PSP seam

Generic client-trusted-price testing belongs to `hunt-business-logic`. What is specific
here is the minor-unit boundary between merchant and provider.

```text
zero-decimal currencies sent as if two-decimal, or the reverse (JPY, KRW, VND)
three-decimal currencies (BHD, IQD, JOD, KWD, LYD, OMR, TND)
provider deviations from ISO 4217: Adyen lists CVE and IDR as zero-decimal,
  CLP and ISK as two-decimal
charge path versus payout path: Stripe treats HUF and TWD as zero-decimal for
  PAYOUTS while charges accept two decimals, and wants ISK and UGX as
  two-decimal values whose decimal part is always 00
currency swapped between hops while the numeric amount is carried over unchanged
a client-supplied exchange rate
```

Compare **billed against granted** every time: 1000 minor units read as 10.00 by one
currency table and 1000.00 by another is a factor-of-100 error in someone's favour.
Depth in `references/settlement-and-ledger.md`.

### 7. 3-D Secure and SCA acceptance (sandbox / PSP test cards only)

```text
1. drive an authentication that resolves to transStatus=U (ACS unreachable:
   malformed device fingerprint, blocked beacon)
2. submit the resulting authorization exactly as the SDK would
3. if the merchant treats it as a completed purchase, U was accepted as Y, and
   U means NO authentication occurred
4. repeat forcing N and R: neither must ever authorize
5. confirm server-side that the authentication value (CAVV) and the liability
   indicator were present and forwarded to the acquirer, not dropped by a
   middleware hop or truncated by a field-length mismatch
6. hunt client-settable exemption flags: off_session, setup_future_usage,
   is_recurring, merchant_initiated, mit, skip_3ds, skip_sca, exemption_type,
   threeDSRequestorChallengeInd
```

The merchant-initiated flag is self-declared by the integration. The bug is not the
issuer still requiring SCA (correct behaviour); it is the merchant's own logic
short-circuiting the challenge because a client-supplied boolean said recurring.
transStatus table: `references/3ds-sca-and-tokenization.md` (written against EMV 3DS 2.2.0; EMVCo's current Protocol and Core Functions Specification is v2.3.1.1, published 30 May 2023, so cite that version and check it for deltas).

### 8. Idempotency contract (Stage A safe, Stage B sandbox only)

Know the provider's real semantics before calling a deviation. Stripe's API v1 saves
the status code and body of the first request for a given key, prunes keys after at
least 24 hours, and the idempotency layer compares incoming parameters to the
original's and **errors** if they differ.

```bash
# Same key, DIFFERENT amount, 3 s apart. Correct behaviour is an error.
K=22222222-2222-4222-8222-222222222222
for A in 10000 100; do
  curl -s -X POST https://target.example/v1/payments -H "Idempotency-Key: $K" \
    -H 'Authorization: Bearer <API-TOKEN>' -H 'Content-Type: application/json' \
    -d "{\"orderId\":\"ord_canary\",\"amount\":$A,\"currency\":\"eur\"}"; sleep 3
done
```

Three outcomes, three findings. Error: correct. Returning the **first** result while
ignoring the new body: the caller can be made to believe an amount was charged that
never was. Creating a **second** charge: the key is decorative. Also test key omitted,
key scope crossed between two merchants (merchant A's cached response returned to
merchant B is both disclosure and a denial primitive), and predictable keys (counter,
bare timestamp, order id). Concurrent-duplicate sending mechanics belong to
`hunt-race-condition`; the contract belongs here.

### 9. Post-authorization transitions (sandbox only)

The least-tested part of any integration, because the happy path never visits it.

```text
capture more than was authorized            capture twice, in full
partial captures summing past the authorized total
void an already-captured payment            re-capture after void
refund an authorized-but-uncaptured payment (should require cancel)
refund more than captured, across several partial refunds
cancel after succeeded
fulfil on a non-terminal async state (ACH/SEPA `processing`)
deliver success, then failure, then duplicate each, then an older event last
```

Adyen models `CANCEL_OR_REFUND` as one event precisely because the merchant cannot
tell from it alone whether capture already happened; a handler reading it as an
unambiguous void is wrong. Matrix and rail timings:
`references/settlement-and-ledger.md`.

### 10. Tenant, mode and destination binding

```text
merchant or tenant identity read from a request parameter rather than the verified
  token (CVE-2026-63414 class: current_shopify_domain resolved from ?shop=)
a payment token created under account A used in a charge authenticated as account B
a refund or void referencing another merchant's transaction reference
payout destination changed without re-authentication, or bound to the request
  rather than to the verified account
an order created via payment method A settled via method B on a shared table
a test-mode credential reachable in production, or one signing secret shared
  across modes
```

Generic object-reference enumeration belongs to `hunt-idor`. What belongs here is the
object being a payout destination, a saved instrument or a refund reference.

### 11. Read the ledger, then read the provider's ledger

After every test, not at the end. Re-read the gate section's snapshot list, diff it,
then cross-check the provider's dashboard, API record or transaction export. Watch for
**a request that should debit and instead credits**: the tell for overflow or a sign
error in settlement math.

## Payload & Detection Patterns

Stage A event body. Use the provider's real event shape so the handler's parser does
not reject the probe before verification runs, and point every money-bearing and
reference field at a canary:

```json
{"id":"evt_canary_probe","object":"event","type":"checkout.session.completed",
 "data":{"object":{"id":"cs_canary_probe","status":"complete",
   "payment_status":"unpaid","amount_total":100,"currency":"usd",
   "client_reference_id":"ord_canary_7f3a"}},"livemode":false}
```

The Stripe-scheme signature is
`t=<unix>,v1=hex(hmac_sha256(key, "<unix>.<raw body>"))`. Send that body five times,
3 s apart: no signature header; signature under an **empty-string** key; `v1` set to 64
zeroes; the same empty-key MAC relabelled `v0`; and an empty-key signature timestamped
86400 s old. Probe scripts and the per-provider scheme table are in
`references/webhook-signature-schemes.md`.

Detection reading: a uniform 400 across all five is a verifying handler. A 2xx on the
empty-key probe but a 400 on garbage is the CVE-2026-41432 class, because HMAC under an
empty key is computable by anyone. A 2xx on **every** probe including garbage is either
a handler that never verifies or a proxy answering: distinguish with the canary id.

Raw-body versus re-serialized detection. Sign the canonical form, send a semantically
identical variant; acceptance proves the verifier hashes re-serialized bytes:

```text
canonical       {"id":"evt_1","amount":100}
spaced/reorder  pretty-printed with indentation, or the same keys reversed
float/exponent  "amount":100.0   then   "amount":1e2
duplicate key   "amount":1,"amount":100     <- last-wins parsers disagree here
```

Money-field value battery, for every money-bearing field at every hop: `-1`, `0`,
`0.009`, `1e3`, `"100"`, `null`, `2147483647`, `2147483648`, `4294967295`,
`9223372036854775807`, `18446744073709551615`. Overflow tell: a positive purchase that
**increases** the balance. Negative charges are applied as credits in most settlement
code, so a wrapped quantity turns a debit into a large credit after the pre-consume
check has already passed.

## Common Root Causes

- **Signing secret defaults to empty string** and is passed straight to the verifier,
  so HMAC under an empty key verifies for anyone. Compounded when the service boots
  anyway instead of refusing to start.
- **Fail-open error path.** An unrecognised algorithm identifier, or any branch
  returning `true` rather than refusing, turns "cannot determine" into "verified".
- **Verification over the wrong bytes** (parsed-then-re-serialized, not the raw body
  the provider signed), or with a non-constant-time comparison (CWE-208).
- **Authenticity checked, content not bound.** The notification really came from the
  provider; amount, currency, recipient and order ownership were never compared against
  the merchant's own record. Worse when the order is resolved from the notification's
  reference instead of from merchant records.
- **No deduplication key**, so the provider's own retry double-credits with no attacker
  involved. Stripe retries live-mode events for up to 3 days.
- **Non-terminal state read as terminal.** `AUTHORISATION success=true`, `complete`,
  `refund.created` and `processing` all treated as settled.
- **Debit and credit outside one transaction**, no row lock (CWE-362).
- **Self-declared trust flags** (`off_session`, `is_recurring`) taken from the client
  rather than derived from the merchant's own mandate history.
- **Identity from a parameter** rather than the verified token in a multi-tenant
  payment path, and one signing secret shared across test and live modes.

## Bypass Techniques

- **Empty-key HMAC** when the secret is unset. Not a skipped check: a mathematically
  defeated one.
- **Body-normalisation gap.** Sign canonical bytes, send a variant the re-serializer
  normalises back. Amount precision is the field that matters.
- **Boolean-logic inversion.** A handler rejecting only when signature verification
  **and** transaction lookup both fail (`AND` where `OR` was needed) is bypassed by one
  small genuine purchase whose transaction id satisfies the lookup branch.
- **Authentic-event repointing.** Keep the real signature, change the order reference
  the handler reads. Needs one minimal **sandbox** payment to obtain a genuine event;
  never make that payment on production.
- **Return-leg identifier swap.** Pair a valid low-value payment id and signature with
  a high-value order id where the server verifies against the client-supplied order.
- **Dropped step rather than skipped step.** Let the flow start, then drop the SCA,
  address-validation or fraud-check request and see what the unset field defaults to.
- **transStatus U via induced technical failure.** Break the device-data beacon so
  authentication cannot be performed, then submit the authorization anyway.
- **Idempotency defeat by key rotation.** An integration that reads the provider's
  "retry with the same key" transient error as a hard failure and resubmits with a
  **new** key produces the double charge the mechanism existed to prevent.

## Gate 0 Validation

False-positive killers. Run all of these before writing anything up.

1. **Did state change, or only the response?** Re-read order status, balance,
   entitlement and invoice total from a different endpoint than the one you posted to.
   No delta, no finding.
2. **Did the provider see it?** Pull the provider's own record. If the provider shows
   nothing and the application shows paid, you have the strongest version of the
   finding. If both agree, you changed nothing.
3. **Is the 2xx actually the handler?** Point the same request at a path that cannot
   exist (`/webhook/<random>`). An identical 2xx means a proxy or framework is
   answering, not the payment handler. Likewise, a probe aimed at a non-existent order
   proves nothing about a real one: confirm the handler distinguishes them.
4. **Is the effect preview-only?** Carry it through capture and fulfilment. A total
   recomputed at capture is low severity at most.
5. **Was it already terminal, or is it documented?** A refund on an object the sandbox
   had already settled, a legitimate SEPA return right, an issuer still requiring SCA
   and a documented grace period are all not bugs. Report the delta between documented
   policy and observed behaviour.
6. **Timing findings stay honest.** A non-constant-time comparison confirmed by reading
   the operator is a CWE-208 code defect, not a recovered signature. Say so, and give
   the constant-time primitive for the language. Inconclusive remote timing is
   "unconfirmed", never "not vulnerable".
7. **Reproduce it, and count.** Record attempts and successes. Extrapolation
   (per-transaction gain, achievable rate, ceiling) is what moves severity, because no
   mainstream taxonomy rates business-logic payment findings.
8. **Reverse it.** Log every money-moving request with a timestamp, hand the
   reconciliation list over, and leave the sandbox clean.

## Real Impact Examples

- **Forged top-up via empty signing secret.** A Go API platform defaulted its Stripe
  webhook secret to `""`, checked only `status == "complete"` while ignoring
  `payment_status` (which can be `unpaid`), and looked up the order by reference
  without checking the payment method matched. An unauthenticated attacker created a
  pending order through a different gateway and fulfilled it with a forged Stripe
  event, crediting quota without paying. CVSS 7.1, CWE-345 plus CWE-1188 plus CWE-863.
- **Authentic IPN, arbitrary order.** A WordPress PayPal and Stripe add-on ran PayPal's
  own notification validation correctly, then marked the order named by the
  attacker-controlled `invoice` field completed without comparing amount, currency or
  receiver. One minimal payment settles an arbitrary expensive order.
- **Cart mutated after the amount was fixed at the PSP.** A Sylius PayPal plugin fixed
  the amount with PayPal at initiation, read the still-mutable order total at
  completion, and never compared the two, marking orders paid in full at a total PayPal
  had never captured. CWE-472.
- **Wallet money from nothing.** A wallet transfer read the sender's balance, checked
  sufficiency in application code, then wrote, with no transaction and no row lock.
  Concurrent transfers all passed the stale check: the sender was debited once, the
  recipient credited once per request. CWE-362.

## Disclosed Report Citations

- [GHSA-xff3-5c9p-2mr4 / CVE-2026-41432](https://github.com/advisories/GHSA-xff3-5c9p-2mr4) - Stripe webhook secret defaults to empty string, plus payment_status ignored and payment-method mismatch. CVSS 7.1.
- [GHSA-vr4h-g9wj-2p4g / CVE-2026-9189](https://github.com/advisories/GHSA-vr4h-g9wj-2p4g) - authentic PayPal IPN, amount/currency/receiver never compared to the order. CVSS 5.3.
- [GHSA-mmw7-wq3c-wf9p / CVE-2026-39366](https://github.com/advisories/GHSA-mmw7-wq3c-wf9p) - PayPal IPN replay, no transaction-id uniqueness check. CVSS 6.5.
- [GHSA-jf52-3f2h-h9j5 / CVE-2026-21894](https://github.com/n8n-io/n8n/security/advisories/GHSA-jf52-3f2h-h9j5) - Stripe trigger stored a signing secret and never validated incoming signatures. CWE-290, CVSS 6.5.
- [GHSA-mjgf-xj26-9qf9](https://github.com/advisories/GHSA-mjgf-xj26-9qf9) - non-constant-time HMAC comparison in a Paddle webhook verifier. CWE-208, CVSS 7.4. No CVE assigned.
- [GHSA-pqq3-q84h-pj6x / CVE-2025-29788](https://github.com/Sylius/PayPalPlugin/security/advisories/GHSA-pqq3-q84h-pj6x) - cart total diverges from the amount PayPal captured. CWE-472, CVSS 6.5.
- [GHSA-h54m-c522-h6qr / CVE-2026-34368](https://github.com/advisories/GHSA-h54m-c522-h6qr) - wallet transfer TOCTOU, balance read and written with no transaction or row lock. CWE-362, CVSS 5.3.
- [GHSA-6j52-38f8-qhxr / CVE-2026-63414](https://github.com/Shopify/shopify_app/security/advisories/GHSA-6j52-38f8-qhxr) - tenant identity resolved from the `shop` query parameter rather than the verified token. High.
- [GHSA-48f2-m7jg-866x / CVE-2022-29254](https://github.com/silverstripe/silverstripe-omnipay/security/advisories/GHSA-48f2-m7jg-866x) - exposed gateway intermediate identifier or success URL marks a payment complete without funds taken. CVSS 3.7.

## Related Skills & Chains

- `hunt-business-logic` owns generic business-logic flaws: client-trusted prices,
  negative quantities, coupon stacking, cart decimal overflow. Go there for the cart;
  come here for the PSP seam, the webhook and the ledger.
- `hunt-race-condition` owns concurrency mechanics: single-packet attack, HTTP/2
  specifics, Turbo Intruder, first-sequence sync. This skill owns **which** payment
  objects are worth racing and what the idempotency contract should have prevented.
- `hunt-fintech-graphql` owns the GraphQL fintech surface: money-movement mutations,
  resolver authorization, alias batching against a ledger. Use it when the payment API
  is GraphQL; use this skill for REST, webhooks and the provider seam.
- `hunt-idor` owns the generic object-reference battery. Come back here once the object
  is a payout destination, a saved instrument or a refund reference.
- `hunt-ssrf` owns callback-URL SSRF; merchant-registered webhook and donation-callback
  URL fields are a real primitive, but the methodology lives there.
- Also: `hunt-jwt-crypto` for signature-algorithm confusion beyond these schemes,
  `hunt-oauth` for open-banking consent and token binding, `hunt-api-misconfig` and
  `hunt-shadow-api` for legacy payment hosts, `hunt-mfa-bypass` for step-up auth.
- Reporting: `bugcrowd-reporting` for severity argument (no mainstream taxonomy has a
  business-logic payment category, so argue from money), `evidence-hygiene` before any
  artefact containing a PAN, token or signing secret leaves the engagement.

### Reference Files

| File | Coverage | Trigger phrases |
|---|---|---|
| webhook-signature-schemes.md | Per-provider header, algorithm, signed material and encoding; Stripe and Adyen forgery probes; raw-body versus re-serialized detection; replay and dedup posture per provider; return-leg binding | webhook signature, IPN, HMAC forgery, Stripe-Signature, Adyen hmacSignature, replay window, event dedup |
| 3ds-sca-and-tokenization.md | transStatus value set and safe-to-authorize table; CAVV and liability-indicator propagation; SCA exemption and off-session flags; PSP versus network token scope; detokenization authorization; PAN leakage Luhn sweep; card-testing velocity probe | 3-D Secure, transStatus, CAVV, ECI, SCA exemption, off_session, tokenization, detokenize, PAN in logs, card testing |
| settlement-and-ledger.md | Async rail timing and reversal windows; authorize/capture/void/refund matrix; idempotency contracts per provider; double-entry asymmetry and overflow-to-credit; reconciliation questions; payout and refund destination binding | ACH, SEPA, async settlement, capture, void, refund, payout, idempotency key, ledger, reconciliation, over-refund |

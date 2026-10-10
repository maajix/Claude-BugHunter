# Settlement, idempotency and the ledger

Companion to `hunt-payment-api`. Every transition on this page moves money or changes a
balance: **sandbox only**, or a pre-agreed test order with written sign-off naming the
value ceiling and who reverses it.

## Idempotency contracts

Know the provider's real semantics before calling a deviation.

| Provider | Mechanism | Window | Reuse with a different body |
|---|---|---|---|
| Stripe | `Idempotency-Key` header, all POSTs, up to 255 chars | keys prunable after at least 24 hours | **errors**; parameters are compared |
| Adyen | `idempotency-key` header, up to 64 chars, UUID recommended | not documented | 409 or 422 with error 704 ("request already processed or in progress"); the `transient-error` header set to `true` means retry later with the same key |
| PayPal | `PayPal-Request-Id` header, enforced on REST POSTs | docs state 45 days for their refund example; no general retention documented | not documented |

Stripe's API v1 semantics are the useful baseline, from its own documentation: the
status code and body of the first request for a given key are saved once endpoint
execution begins, retries with the same key return that saved response including `500`
errors, and the idempotency layer compares incoming parameters against the original's
and errors if they differ. Note the save-point nuance: nothing is saved if the request
fails parameter validation or conflicts with another request executing concurrently
under the same key. That gap is where concurrent duplicates live.

### What to test

```text
key omitted entirely on a money-creating POST (does it double-charge on retry)
same key, identical body (must return the first result, not a second charge)
same key, DIFFERENT amount (must error; returning the first result silently is
  itself a finding, because the caller believes an amount was charged that was not)
key generated under merchant A reused while authenticated as merchant B
  (merchant A's cached response coming back is disclosure plus a denial primitive)
predictable keys: 1 2 3, a bare timestamp, an order id, an email address
```

The self-defeating retry is worth hunting in code review. A provider's "retry later
with the **same** key" transient error, misread as a hard failure, is often "fixed" by
generating a new key and resubmitting, which defeats idempotency entirely and produces
exactly the double charge the mechanism existed to prevent.

Sending mechanics for concurrent duplicates (single-packet attack, HTTP/2 specifics,
Turbo Intruder) belong to `hunt-race-condition`. Payment objects worth racing, all
sandbox only: coupon and promo redemption, gift-card and store-credit spend, balance
debit, transfer and withdrawal, capture and refund, payout and confirmation endpoints,
seat and quantity changes, and webhook processing of the same signed event N times at
once.

## Post-authorization transition matrix

The happy path never visits these, so they are the least-tested code in the
integration. Each line is one sandbox transition; record the resulting provider state
and the resulting application state separately.

```text
capture an amount greater than the authorization
capture twice in full; then partial captures summing past the authorized total
void an already-captured payment; re-capture after a void
refund an authorized-but-uncaptured payment (should require cancel, not refund)
refund more than was captured, across several partial refunds
cancel after the payment already succeeded
fulfil on refund.created, with no handling for a later refund failure
refund destination: does it return to the original instrument, or to one named
  in the request
dispute and chargeback fees: who absorbs them in the application's own books
```

Two provider-modelling facts that cause real defects. Adyen models `CANCEL_OR_REFUND`
as a single event precisely because the merchant cannot tell from the event alone
whether capture had already happened, so a handler reading it as an unambiguous void is
wrong. And an Adyen `AUTHORISATION` with `success=true` is not "paid": a later
`CAPTURE_FAILED` can follow. Stripe's refund lifecycle runs pending to succeeded or
failed, so an application treating `refund.created` as completion records money as
refunded that never left the account.

## Async rails: fulfilment on a non-terminal state

Delayed-settlement methods break the assumption that a successful response means
settled funds. Treat the numbers below as provider-documented integration timings
subject to eligibility, cutoff and region, and reconfirm them from the provider's
current rail page before calculating exposure for a report. `T` is the provider's
processing business day, not a duration from the browser click.

| Rail | Confirmation / availability | Reversal exposure |
|---|---|---|
| ACH | standard availability around T+4, eligible faster T+2 | consumer disputes generally 60 calendar days; failures can arrive after a success state |
| SEPA | standard availability around T+6 | eight-week unconditional refund right; unauthorized-debit claims up to 13 months |
| Bacs | success around T+3, availability T+4 on an established mandate | no fixed customer dispute limit documented |
| AU BECS | confirmation up to three business days | disputes documented up to seven years |
| ACSS | up to five business days | personal 90 calendar days, business ten business days |
| Boleto | confirmation up to one business day | voucher expiry is not confirmation; no card-style disputes |

Tests:

```text
create a checkout session with a delayed method, complete the sandbox flow, then
  check whether an entitlement is granted while the session is unpaid and the
  payment intent still processing
inject a provider-supported failure or return fixture tied to that test payment and
  check whether spendable credit or an entitlement survives the reversal
deliver success, then failure, then duplicate each, then an older processing event
  last: does arrival order alone decide financial truth
swap a mandate reference between two authorized test customers, alter the recurring
  amount, and retry a revoked mandate
mutate only method-selection inputs: can a caller pick a weaker-finality rail and
  still receive the entitlement policy intended for another
```

Pass condition: transitions are justified by authoritative provider state and by
movement identifiers, with compensating entries for reversals. A legitimate return
right is not a vulnerability; an entitlement that survives the return is.

## Double-entry asymmetry

The defining ledger bug is a value movement whose debit and credit are not written in
one transaction. The verified reference case read the sender's balance, checked
sufficiency in application code, then wrote, with no transaction and no row lock:
concurrent requests all passed the same stale check, the last write won for the
sender's deduction, and **every** request credited the recipient. Net value created
from nothing (CWE-362).

Test each side of every movement independently:

```text
does the debit succeed if the credit fails, and the reverse
is the pair inside one database transaction
does a partial failure leave a dangling entry
does a retry after a timeout produce a second credit without a second debit
can a transfer be made to your own account for a net gain
can a transfer be made with a negative amount, reversing direction
does the sum of all entries still reconcile after N concurrent operations
```

That last line is the actual test: snapshot the ledger, run the operations, and check
that total value is conserved.

## Overflow that turns a debit into a credit

The most instructive settlement class. A user-controlled quantity folded into
settlement math with no upper bound and no overflow-safe conversion can wrap to a
negative value, and a negative charge is applied as a **credit**. The documented case
wrapped at settlement time, after an unbounded pre-consume check had already passed.

```text
-1   0   2147483647   2147483648   4294967295
9223372036854775807   18446744073709551615   18446744073686646784
```

The generalisable tell on any billing endpoint: **a request that should debit the
account instead credits it.** Test the reservation check and the final settlement
separately, because validation often exists at one stage and is absent at the other.
The model fix to recommend is both input-side caps **and** centralised saturating
arithmetic that clamps to the type's bounds, so wraparound cannot occur even if one
validation path is missed.

## Payout and refund destination binding

```text
payout destination taken from the request rather than from the verified account
payout destination changed with no re-authentication (then check whether a payout
  already in flight picks up the new destination)
a refund issued to an instrument other than the one charged
a void or refund referencing another merchant's transaction reference
  (the HTTP equivalent of the card-rail retrieval-reference-number IDOR: submit a
  refund as merchant B naming merchant A's reference)
an order created via payment method A settled via method B on a shared table
no maker-checker on payouts: worth raising as a design finding with no exploit,
  per ASVS 5.0 V2.3.5
```

## Reconciliation questions

Most in-house ledgers cannot answer these, and the answers are reportable on their own:

```text
does the local ledger reconcile against the provider's balance report, how often
what happens when they disagree: alert, auto-correct, or nothing
is there an invariant check (sum of balances equals sum of settled payments)
are provider-side reversals detected, or only provider-side successes
is a refund that later fails at the provider reversed locally
are duplicate provider events deduplicated before they reach the ledger
is a payout the bank returns reflected back into the balance
```

A platform with no reconciliation will not detect any bug in this class in production.

## Reporting these findings

No mainstream vulnerability taxonomy has a business-logic payment category, so the
report carries the argument. Per finding: the exact request verbatim with the field that
mattered highlighted; the **ledger delta** before and after, not the response; the
reproduction count (attempts versus successes); the extrapolation (per-transaction gain,
achievable rate, ceiling); which trust boundary failed, in one sentence; the concrete
code-level fix; and the ASVS requirement it violates. Useful ASVS 5.0 V2 anchors:
V2.2.2 (validation enforced at a trusted service layer, client-side validation is not a
security control), V2.3.1 (steps processed in sequence without skipping), V2.3.3
(business-logic transactions succeed entirely or roll back), V2.3.4 (locking so
limited-quantity resources cannot be double-booked), V2.3.5 (multi-user approval on
high-value flows), V2.4.1 (anti-automation).

Verify a fix by re-running the identical measurement. For race findings, insist on real
row-level locking or a database constraint: a flag or an in-process mutex does not
survive multiple workers, so re-test the fix by racing it again rather than reading it.

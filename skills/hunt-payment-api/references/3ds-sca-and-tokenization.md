# 3-D Secure, SCA exemptions and tokenization

Companion to `hunt-payment-api`. Everything on this page is **sandbox or PSP test-card
only**. Driving authentication outcomes against production moves real money and feeds
real fraud signals.

## transStatus: what the merchant is allowed to accept

`transStatus` arrives in the ARes, CRes or RReq and carries the authentication outcome.
The EMV 3-D Secure 2.2.0 specification defines eight ARes values (`Y N U A C D R I`);
the CRes allows only `Y` and `N`.

| Value | Specification meaning | Safe to authorize |
|---|---|---|
| `Y` | Authentication / account verification successful | yes |
| `A` | Attempts processing performed; not authenticated, proof of attempt provided | yes, see the liability note |
| `N` | Not authenticated, transaction denied | **no** |
| `U` | Could not be performed; technical or other problem | **no** |
| `C` | Challenge required, continue with CReq/CRes | not yet, flow incomplete |
| `D` | Challenge required, decoupled authentication confirmed | flow-dependent |
| `R` | Rejected by the issuer; authorization should not be attempted | **no** |
| `I` | Informational only; challenge preference acknowledged | **no** |

Liability note: Adyen's own documentation states that `A` carries liability shift "the
same way a successful authentication would", describing it as the scheme vouching for
the attempt. So accepting `A` is not automatically a defect. The defects are:

- Treating **any non-`N`** response as safe.
- Never inspecting `transStatus` at all, and concluding success because the challenge
  iframe closed.
- Failing **open on `U`**, which is the dangerous one, because `U` means no
  authentication occurred. An attacker who can force a technical failure (malformed
  device fingerprint, blocked JavaScript beacon, unreachable ACS) then skips
  authentication entirely.

### Test procedure

```text
1. drive an authentication that resolves to transStatus=U
2. submit the resulting authorization exactly as the SDK would
3. if the merchant treats it as a completed purchase, U was accepted as Y
4. repeat forcing A, then N, then R. N and R must never authorize
5. verify server-side that the authentication value (CAVV) and the liability
   indicator were present and non-null before authorization was requested
6. correlate threeDSServerTransID, acsTransID and dsTransID back to the original
   AReq; an RReq whose ids do not chain is open to message substitution
7. check messageVersion for downgrade below what the merchant's own 3DS Server
   supports
```

Most PSPs publish a 3DS2 test-card matrix that forces specific outcomes. Stripe's
documented set includes 3DS-required `4000000000003220`, 3DS-optional
`4000000000003055` and frictionless-required `4000000032200000`.

## The dropped authentication value

The subtlest finding in this area, and invisible in the 3DS response, because the
reclassification happens in the authorization and clearing layer rather than in the
authentication message. If the authentication value (CAVV) is dropped by a middleware
hop, truncated by a field-length mismatch, or never forwarded to the acquirer, the
transaction can clear with a weaker liability indicator than the merchant believes it
has, and the merchant discovers this only when a chargeback lands.

```text
1. force an attempted-authentication outcome (transStatus=A)
2. inspect the authorization request the merchant sends downstream
3. confirm the authentication value is actually populated and forwarded
4. validate it against the PSP or network schema; a length check establishes
   neither authenticity nor liability shift
```

Report this as a code and configuration finding. The scheme-specific Electronic
Commerce Indicator values and the exact eligibility rules differ by scheme and region
and change over time: **verify them against the current Visa and Mastercard operating
regulations before quoting any specific indicator value to a client.** A pentest that
checks only "was the 3DS flow triggered" misses this class entirely.

## SCA exemptions and the self-declared flag

The highest-value exemption finding, because the flag is declared by the integration
rather than proved by it. Strong customer authentication can legitimately be skipped for
a merchant-initiated transaction that follows an initial customer-initiated transaction
which was itself authenticated and carries an on-file mandate. PSP APIs expose that
through flags such as Stripe's `off_session=true`, or `setup_future_usage=off_session`
when the instrument is first saved.

The bug is not the issuer still requiring authentication, which is correct behaviour.
The bug is the merchant's own logic short-circuiting the challenge because a
client-supplied boolean claimed the transaction was recurring.

```text
1. confirm a payment intent with off_session=true for an instrument that has never
   been authenticated on this account (no prior authenticated CIT on file)
2. check whether the merchant requested an exemption on a live, attacker-controlled
   transaction
3. verify a mandate or consent record actually exists and was created under
   authentication: a server-side data check, not a client-settable boolean
```

Field names worth grepping in requests, client bundles and mobile apps:

```text
off_session  setup_future_usage  recurring  is_recurring  merchant_initiated
mit  cit  skip_3ds  skip_sca  exemption  exemption_type  challenge_indicator
threeDSRequestorChallengeInd  trusted_beneficiary  low_value  tra
```

Transaction-risk-analysis style exemptions are granted on a PSP's own self-reported
fraud rate, so the merchant-side test is whether the exemption **strategy** can be
selected per request by the caller rather than set by the PSP's configuration.

## Token scope confusion

Two structurally different token types get conflated. PSP or gateway tokens are bound
to the PSP, gateway, acquirer or vault that issued them and are generally not
interchangeable. Network tokens, issued by the schemes, are additionally scoped to a
declared domain of use (a specific merchant, device or wallet) and paired with a
per-transaction dynamic cryptogram. The testable bug is an integration treating a PSP
token as if it carried network-token scoping guarantees.

```text
1. create a card token under merchant or sub-account A's credentials
2. attempt to use that token id in a charge authenticated as sub-account B
3. secure behaviour is a hard rejection. A successful charge is scope confusion; a
   revealing error ("token exists but belongs to another account") is disclosure
4. Stripe tokens are single-use: attempt a second use of a consumed token id
5. race two uses of the same single-use token (sandbox only)
```

Multi-tenant platforms are where this matters. A shared decryption service that asks
"can I decrypt this token" rather than "was this token issued for **this** account"
crosses tenants.

## Detokenization

Scope is the whole value of a vault. One detokenization path reachable with ordinary
application or support credentials gives back every PAN the vault was bought to keep
out of the application, so grade this path on its own, not on the vault's reputation.

```text
1. enumerate every endpoint and role that can call detokenize or reveal
2. confirm it is restricted to a narrowly-scoped service identity, not general
   application or support-tooling credentials
3. attempt detokenization with a lower-privileged application key
4. check for an IDOR: does the endpoint verify the caller is authorized for THIS
   token's originating merchant or account
5. confirm every call is logged with caller identity and alerted on for volume
```

## PAN leakage sweep

The cheapest high-value check in the whole area. Run it over any log export, debug
endpoint, error page, support-tool response or object store you already have access to.
Detection only: it reads, it changes nothing.

```python
import re, sys

def luhn(n: str) -> bool:
    d = [int(c) for c in n][::-1]
    return sum(x if i % 2 == 0 else sum(divmod(x * 2, 10))
               for i, x in enumerate(d)) % 10 == 0

for line in sys.stdin:
    for m in re.findall(r'(?<!\d)(\d{13,19})(?!\d)', line):
        if luhn(m):
            print(f"{m[:6]}...{m[-4:]}  {line.strip()[:90]}")
```

Report the masked form only. Full PANs must never leave the engagement in evidence: run
`evidence-hygiene` before any artefact is attached to a report.

## Card testing and velocity, as a control test

**Pre-agreed window and a named contact at the target, or do not run it.** Card-testing
probes are indistinguishable from a real BIN attack to the acquirer, and elevated
decline rates carry network fines and merchant-account termination risk.

Within the agreed window, serial with jitter and a hard attempt cap:

```text
velocity limits per IP, per device, per email, per card and per BIN
zero-value and verification-only endpoints exempted from limits
decline-reason codes that distinguish "invalid card" from other declines
add-to-cart-to-purchase timing under one second
whether ANY defensive reaction occurred during the whole engagement
```

Answer the last line explicitly in the report. An engagement that never provoked a
throttle, a challenge or a lockout has measured the absence of an anti-automation
control, and that absence is reportable without any single exploit attached.

Two provider test cards can be turned into control checks, with different guards.

- **Test PAN at a live checkout. Stage A, explicit operator OK required, single
  request.** Acceptance proves test-mode keys are serving production traffic. Stop at
  the authorization response, do not proceed to fulfilment, and cancel or void the
  resulting order immediately: if the keys really are test-mode, a successful order can
  ship real goods against money that will never settle, so the check itself must not be
  allowed to complete.
- **Risk-engine "always blocked" card (Stripe documents `4100000000000019` as always
  blocked by Radar). Sandbox or test mode only.** In live mode a test PAN declines as
  an invalid card whatever the risk engine does, so the result carries no information
  about the fraud configuration and the attempt only adds a decline to the merchant's
  ratio.

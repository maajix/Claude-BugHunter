---
name: hunt-clickjacking
description: "Hunt clickjacking and UI redressing: missing X-Frame-Options or CSP frame-ancestors on login flows, money transfers, account settings and OAuth confirmation pages, plus DoubleClickjacking (top-level window swap during a double click, which XFO, frame-ancestors and SameSite do not stop). Header absence alone is not a finding: prove the page frames in a real browser and that a sensitive state-changing action survives the cross-site context. Use when testing framing protections."
metadata:
  sources: hackerone_public, public_research
  report_count: 6
---

## What is Clickjacking

Clickjacking (UI Redressing) lets an attacker load a target page inside a transparent iframe on a malicious site. The victim sees the attacker's decoy UI but clicks the hidden target UI beneath it. No JavaScript on the target is required.

**Highest-value targets:**
- Login / authentication pages — force login with attacker credentials
- Money transfer / checkout / "confirm payment" buttons
- Account settings (email change, password change, 2FA disable)
- OAuth / social-login "Authorize app" confirmation dialogs
- Admin actions (delete, promote user, change role)

## Scope Gate (read before testing)

Both major platforms exclude the low end of this class outright:
- **HackerOne** — Core Ineligible Findings lists "Clickjacking on pages with no sensitive actions" (https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings).
- **Bugcrowd** — the VRT's only clickjacking entry is *Server Security Misconfiguration > Clickjacking > Sensitive Click-Based Action* (P4 baseline, VRT release 2026-07-08). A framed page with no sensitive click-based action has no category to file under.

So the gate is: name the sensitive state-changing action a victim's click performs **before** building a PoC. No such action = do not file. Then check the program's own exclusions, which often go further.

## Protection Headers

Two mechanisms prevent framing:

```
X-Frame-Options: DENY              # strongest — blocks all framing
X-Frame-Options: SAMEORIGIN        # allows same-origin frames only
Content-Security-Policy: frame-ancestors 'none'     # CSP equivalent of DENY
Content-Security-Policy: frame-ancestors 'self'     # CSP equivalent of SAMEORIGIN
```

If NEITHER is present, the page is frameable from any origin.

> Scope note: `SAMEORIGIN` / `frame-ancestors 'self'` stop *cross-origin* clickjacking but do **not** stop a *same-origin* iframe trap (a page that frames itself after XSS to persist execution). Only `DENY` / `frame-ancestors 'none'` on the sensitive route defeats that. The same-origin trap is a scripting/persistence technique, not UI redressing — see `hunt-dom` Phase 8.

## How to Test

Header-absence is the **trigger for investigation, not the finding**. Two steps:

**Step 1 — Header check (screening).** Fetch the target page and inspect the response headers:

```
curl -sI https://target.example/account/transfer | grep -iE 'x-frame-options|content-security-policy'
```
If BOTH `X-Frame-Options` and CSP `frame-ancestors` are absent, the page is a *candidate*. If either is present and restrictive (`DENY`/`SAMEORIGIN`/`frame-ancestors 'none'|'self'`), stop — it's protected against **iframe** clickjacking. It is not protected against DoubleClickjacking (below), which never frames the page.

**Step 2 — Prove it actually frames and clicks (required for a real finding).** Build a minimal PoC and load it in a real browser:

```html
<!doctype html>
<h1>Win a prize — click below</h1>
<iframe src="https://target.example/account/transfer"
        style="opacity:0.1;position:absolute;top:0;left:0;width:1000px;height:800px"></iframe>
```
Confirm ALL of the following, or it is not exploitable:
- The page **actually renders inside the iframe** (no framebusting JS that blanks/redirects it — e.g. `if(top!==self)` breakout, or a `Sec-Fetch-Dest`/JS frame check).
- The **sensitive action still works while framed** — critically, the action must succeed *cross-site*. If it relies on a session cookie set `SameSite=Lax` or `SameSite=Strict` (the modern default), the cookie is **not** sent on the cross-site framed request, and the clickjack fails. Verify the victim's authenticated state carries into the frame.
- The target is a **state-changing action** (transfer, settings/email/password change, 2FA disable, OAuth authorize, admin action), not a read-only page.

**Strategy:** target the most sensitive action pages first — severity scales directly with what the victim is tricked into doing.

## DoubleClickjacking (no iframe)

Paulos Yibelo, "DoubleClickjacking: A New Era of UI Redressing", December 2024 — https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html (PortSwigger Top 10 web hacking techniques of 2024, entry 6). The attacker page opens a new window that asks the victim to double-click (a fake CAPTCHA, for example). Between the two clicks, the attacker uses `window.opener` to navigate the original tab to the sensitive page, and the first click's `mousedown` closes the top window, so the second click lands on the real target button. It exploits the timing gap between `mousedown` and `click`.

The target page loads **top-level**, not framed, so `X-Frame-Options`, CSP `frame-ancestors` and SameSite cookies do not apply: the victim's own first-party session is used.

- **Best targets:** one-click sensitive actions — OAuth "Authorize / Allow" consent screens (approve an app you control → account access), account-setting confirmations, browser-extension or wallet confirmation prompts.
- **Defence to look for:** the button stays disabled until a real gesture on the page (mouse movement or key press), which is the mitigation Yibelo proposed. A button that is live the moment the page loads is a candidate.
- **Proof (required):** a screen recording in a current browser, version noted, showing the double-click lure and the sensitive action completing on the victim test account. OAuth consent granting your own app is the strongest case. A missing gesture check alone is not a finding.

## False Positives

- Public, read-only pages (home/marketing) lacking frame protection are low/informational — no sensitive action to redress.
- APIs and non-HTML endpoints (JSON, images) are not clickjacking targets.
- **Header-absence alone is NOT a finding.** SameSite cookies, framebusting JS, or the lack of any sensitive framed action can each fully defeat it — which is why Step 2 is mandatory.

## Proof Requirements

A valid clickjacking report shows: (1) the target page rendered inside an attacker-controlled iframe in a real browser, (2) a sensitive state-changing action reachable by a framed click while the victim is authenticated (cookies survive the cross-site context), and (3) a screenshot/recording of the overlay. Reporting missing headers with no working frame PoC is a documentation-quality issue, not a vulnerability. For DoubleClickjacking, the recording requirement in its section replaces (1) and the cross-site cookie condition in (2), because the target is loaded top-level.

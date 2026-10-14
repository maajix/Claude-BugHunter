# Network: MASVS-NETWORK-1, MASVS-NETWORK-2

Scope boundary: `ios-redteam-pipeline` Stage 4 dumps the ATS dictionary and
lists the pinning-bypass options (objection, SSL Kill Switch 3, BoringSSL-level
Frida scripts); its Stage 6 covers the mitmproxy CA. This file adds Burp on
iOS 17+, proxy-unaware apps, the certificate-validation test that separates a
real bug from a hardening note, and how ATS and pinning are graded. Server TLS
configuration (ciphers, protocol versions, certificates) is `hunt-tls-network`.
Everything here is Stage A on your own device and a network you control.

MASTG IDs from OWASP/mastg `master` (fetched 2026-10-14).

---

## 1. Burp on iOS 17 and later

1. Burp proxy listener on all interfaces (or a specific LAN address).
2. Device: Settings, Wi-Fi, the network's (i) button, Configure Proxy, Manual,
   your host and port.
3. Safari on the device: open `http://burpsuite` (or `http://<host>:<port>`),
   download the CA certificate.
4. Settings shows **Profile Downloaded**; install it (labels vary; on some
   builds it sits under General, VPN & Device Management).
5. Settings, General, About, **Certificate Trust Settings**: switch on full
   trust for PortSwigger CA. Without this step HTTPS fails even though the
   profile is installed.
6. Verify with Safari on an HTTPS site, then with the app.

Sources: PortSwigger's iOS configuration guide; the trust-settings step is the
same in mitmproxy's flow (`http://mitm.it`). Remove the profile and untrust the
CA after the engagement.

---

## 2. Proxy-unaware traffic

Symptom: the app works but Burp shows nothing (or only some hosts).

| Cause | Tell |
|---|---|
| `URLSessionConfiguration.connectionProxyDictionary` set to an empty dictionary, ignoring the system proxy (verify behaviour per iOS version) | String in the binary; traffic goes direct |
| Network.framework (`NWConnection`), BSD sockets, embedded TLS stacks (BoringSSL, OpenSSL, Cronet) | Imports in the binary (MASTG-TEST-0323, 0344, 0345) |
| HTTP/3 over QUIC (UDP 443) | UDP in a packet capture; URLSession supports HTTP/3 (verify per iOS version) |
| gRPC, MQTT, WebSockets on custom ports | Non-HTTP ports in the capture |
| Cross-platform frameworks with their own HTTP stack (Flutter's Dart `HttpClient`, some React Native modules) | `hunt-mobile-frameworks` |

Options, least invasive first:

```bash
# 1. See what the app actually does: packet capture from the device over USB
pymobiledevice3 pcap --out app.pcap
#    (macOS alternative: rvictl -s <UDID>, then capture on rvi0)

# 2. VPN-mode interception: all device traffic goes through mitmproxy, proxy settings irrelevant
mitmweb --mode wireguard
#    Import the shown WireGuard config into the WireGuard app on the test device; trust the mitmproxy CA as in section 1.

# 3. QUIC: block UDP 443 on the path (your router or the host running WireGuard mode) so clients fall back to TCP (verify per app)
```

On a jailbroken device the pinning and proxy-bypass hooks in the pipeline
cover the rest. Record which method you used; it changes how reproducible the
finding is for triage.

---

## 3. Certificate validation versus pinning

These are different findings with very different grades. Test validation
first.

### 3a. Does the app accept any certificate? (MASTG-TEST-0396, 0397)

1. In Certificate Trust Settings, **switch off** trust for your proxy CA (or
   use a fresh proxy with a CA the device has never seen).
2. Keep the device proxied and use every app flow.
3. If requests from the app still complete through the proxy with a forged
   certificate, the app (or one of its stacks) accepts any certificate.

Static tells: a `URLSessionDelegate` or `WKNavigationDelegate` that answers
`didReceive challenge` with `.useCredential` and `URLCredential(trust:)`
without evaluating the trust (`SecTrustEvaluateWithError`), Alamofire
`DisabledTrustEvaluator` (named `DisabledEvaluator` in older versions,
verify), or a third-party stack with verification turned off.

This needs no device compromise: anyone on the same Wi-Fi (or a hostile
access point) reads and modifies the traffic. Capture one request carrying
your own session token as proof.

Evidence: a Certificate Trust Settings screenshot with the CA off, the proxy
history entry with your redacted token, app version and iOS build.

Grade: `Broken Authentication and Session Management > Cleartext Transmission
of Session Token` (P4) is the nearest node; personal data in the traffic:
`Insecure Data Transport > Cleartext Transmission of Sensitive Data` (VARIES).
Request more with `bugcrowd-reporting`: this is a full on-path compromise, not
a configuration opinion.

### 3b. Is pinning present? (MASTG-TEST-0385 for ATS pins)

With the CA trusted again:

| Result | Meaning |
|---|---|
| Traffic visible | No pinning on these hosts |
| TLS failures, app shows network errors | Pinning (or a stack that ignores the system trust store) |

Where pinning lives:

| Mechanism | Tell |
|---|---|
| ATS `NSPinnedDomains` (`NSPinnedCAIdentities`, `NSPinnedLeafIdentities`, SPKI SHA-256) | Info.plist; applies to the URL Loading System only |
| `URLSessionDelegate` challenge handler comparing keys or certificates | Strings `SecTrustCopyKey`, `SecCertificateCopyData`, bundled `.cer`/`.der` files |
| Alamofire `ServerTrustManager` with `PinnedCertificatesTrustEvaluator` or `PublicKeysTrustEvaluator` | Class names in the binary |
| TrustKit `TSKPinnedDomains` | Info.plist key or init dictionary |
| Native or framework stack | Not covered by ATS pins; may need native hooks |

Bypass to reach the API, using the pipeline's options: objection
`ios sslpinning disable` (1.12.5 syntax: `objection -n <bundle_id> start`,
then the command), SSL Kill Switch 3 (last release v1.4, November 2023, rootful
and rootless builds; test on your iOS), or a BoringSSL-level Frida script. On
Dopamine with iOS 26 or later, Frida needs version 17.19.0 or newer and
Dopamine 3.0.10 or newer to avoid hook panics (Dopamine 3.0.10 release notes).

Evidence: the TLS errors with the CA trusted, and the mechanism found
(Info.plist key, class names, bundled certificates).

Grade: `Mobile Security Misconfiguration > SSL Certificate Pinning > Absent`
or `> Defeatable` (P5). HackerOne lists "Lack of SSL Pinning" as core
ineligible. Pinning is a mitigation; report what you found behind it.

---

## 4. ATS exceptions (MASTG-TEST-0321, 0322, 0342)

Read the dictionary from the pipeline output, then prove use:

| Key | Default and meaning | When it is a finding |
|---|---|---|
| `NSAllowsArbitraryLoads` true | Disables ATS for all URL Loading System connections | Only with a captured cleartext request carrying a token or personal data |
| `NSAllowsArbitraryLoadsInWebContent` true | Exempts WebView content | Cleartext page in a WebView that has a bridge or a login form (`platform.md`) |
| `NSAllowsArbitraryLoadsForMedia` true | Exempts AVFoundation media | Rarely; media URLs with tokens |
| `NSAllowsLocalNetworking` true | Local addresses and unqualified names | Normal for LAN device apps; not a finding |
| `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` | Cleartext to that domain | When the domain carries auth or personal data |
| `NSExceptionMinimumTLSVersion` below TLSv1.2 | Older TLS permitted | Only if the server actually negotiates it (MASTG-TEST-0348); `hunt-tls-network` |
| `NSExceptionRequiresForwardSecrecy` false | Non-PFS suites permitted | Hardening |

MASTG-TEST-0321 also catches hardcoded `http://` URLs in the binary, and 0323
cleartext over low-level APIs that ATS does not govern. Capture proof on a
network you control:

```bash
pymobiledevice3 pcap --out cleartext.pcap      # then filter for tcp.port == 80 and your canary or token prefix
```

Evidence: the ATS dictionary, the pcap frame or proxy entry showing the
cleartext request with token or canary redacted, and its timestamp.

Grade: captured session token over HTTP: `Broken Authentication and Session
Management > Cleartext Transmission of Session Token` (P4); login over HTTP:
`Broken Authentication and Session Management > Weak Login Function > Over
HTTP` (P4); other sensitive data: `Insecure Data Transport > Cleartext
Transmission of Sensitive Data` (VARIES). A config key with no captured
traffic is hardening.

---

## 5. TLS stack configuration (MASTG-TEST-0343, 0344, 0345)

- `URLSession`: `tlsMinimumSupportedProtocolVersion` lowered below 1.2 in a
  configuration.
- Network.framework: `sec_protocol_options_set_min_tls_protocol_version` and
  `sec_protocol_options_set_verify_block` (a verify block that always returns
  true is section 3a).
- Embedded stacks: their own CA bundle and verification settings.

iOS 26 enables TLS 1.3 client-side by default in URLSession and
Network.framework, and Apple tells developers to migrate off Secure Transport,
which lacks quantum-secure TLS (NowSecure summary of WWDC25 material; verify
against Apple documentation). Secure Transport usage is therefore a
modernisation note, not a vulnerability.

Evidence: the call site or configuration value. Grade: hardening, unless the
setting disables validation (section 3a) or the server negotiates the weak
version (`hunt-tls-network`).

---

## 6. After interception works

The API is now the target. Hand it to the web skills, which carry their own
Stage A / Stage B rules:

| What you see | Skill |
|---|---|
| Routes, missing auth, IDs in paths | `hunt-spa-api`, `hunt-idor` |
| Mass assignment, method tampering, JWT handling | `hunt-api-misconfig`, `hunt-jwt-crypto` |
| GraphQL | `hunt-graphql` |
| Older API versions only the app still calls | `hunt-shadow-api` |
| BaaS endpoints (Firebase, Supabase, Cognito) | `hunt-cloud-backends` |
| Client-side signature or App Attest assertion headers | `resilience.md` section 5 |

---

## Grade summary

| Proven | VRT node | Default |
|---|---|---|
| Any-certificate acceptance, token captured | Broken Authentication and Session Management > Cleartext Transmission of Session Token | P4, request more |
| Cleartext session token | Broken Authentication and Session Management > Cleartext Transmission of Session Token | P4 |
| Login over HTTP | Broken Authentication and Session Management > Weak Login Function > Over HTTP | P4 |
| Other sensitive data in cleartext | Insecure Data Transport > Cleartext Transmission of Sensitive Data | VARIES |
| Pinning absent or defeatable | Mobile Security Misconfiguration > SSL Certificate Pinning > Absent / Defeatable | P5 |
| ATS exception without captured sensitive traffic | none; hardening | Info |

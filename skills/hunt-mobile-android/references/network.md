# Network communication (MASVS-NETWORK)

Proxy setup, the Burp/mitmproxy CA on Android 14+, and the Frida pinning
template live elsewhere: `tooling.md` §5 for the CA, `apk-redteam-pipeline`
Stages 7-8 for the generic pinning hook and mitmproxy. This file covers what
to test once you can see (or fail to see) the traffic, and how to grade it.

Everything here observes **your own session on your own device**. Intercepting
a request is Stage A. Replaying or editing a request that changes server state
(orders, transfers, profile changes, messages) is backend testing: hand it to
`hunt-spa-api`, `hunt-idor` or `hunt-api-misconfig`, under their Stage B
rules and the program's written sign-off.

## 1. Read the Network Security Config first

```bash
# From the apktool output (apk-redteam-pipeline Stage 5); the manifest names the file
grep -o 'android:networkSecurityConfig="[^"]*"' decoded/AndroidManifest.xml
grep -o 'android:usesCleartextTraffic="[^"]*"' decoded/AndroidManifest.xml
cat decoded/res/xml/network_security_config.xml
```

What to read out of `network_security_config.xml`, and how MASTG grades it:

| Setting | What it means | MASTG-TEST |
|---|---|---|
| `cleartextTrafficPermitted="true"` or a `<domain-config>` allowing cleartext for a real host | HTTP allowed; downgrade/MITM exposes traffic | 0235 (config), 0236 (observed on the wire) |
| no NSC + `android:usesCleartextTraffic="true"` | cleartext app-wide (default varies by `targetSdk`) | 0235 |
| `<debug-overrides>` trusting user CAs | only active when `android:debuggable="true"`; not a prod finding unless the shipped build is debuggable | 0286 |
| `<trust-anchors><certificates src="user"/>` outside debug-overrides | app trusts user-installed CAs in production: weakens MITM resistance | 0286, 0285 (old `targetSdk` trusting user CAs by default) |
| `<pin-set>` present | pinning configured in NSC; check expiry | 0242 (missing), 0243 (expired pins) |

Defaults that decide severity: cleartext is off by default for apps targeting
API 28+; user CAs are trusted by default only for apps targeting API 23 or
below (MASTG-TEST-0285). TLS 1.0/1.1 are disallowed for apps targeting Android
15+. State the `targetSdk` from `dumpsys package` when you grade any of these.

Related MASTG tests for TLS code: 0217/0218 (insecure TLS protocols allowed in
code / seen in traffic), 0233 (hardcoded `http://` URLs).

## 2. Cleartext and mixed transport

1. Proxy the app (`tooling.md` §5-6) and watch for `http://` requests carrying
   tokens, PII or auth. Cleartext of a session token is VRT Broken
   Authentication > Cleartext Transmission of Session Token (P4); other
   sensitive data is Insecure Data Transport > Cleartext Transmission of
   Sensitive Data.
2. Grep the decompiled code for `http://` endpoints the NSC still permits
   (`apk-redteam-pipeline` Stage 3 found the URLs; here you confirm they ride
   cleartext).
3. An app that downloads an APK, DEX or `.so` over HTTP and loads it is VRT
   Insecure Data Transport > Executable Download > No Secure Integrity Check
   (P4) and a realistic RCE primitive on a hostile network.

## 3. Certificate pinning: find it, then bypass to keep testing

**Find it.** Pinning lives in one of: NSC `<pin-set>`; an OkHttp
`CertificatePinner`; a custom `X509TrustManager` / `HostnameVerifier`; or a
pinned cert/public key in `assets/`/`res/raw` (`apk-redteam-pipeline` Stage 4
extracts those). MASTG-TEST-0242/0244 (missing), 0282/0283 (unsafe custom
trust / hostname verification).

**Bypass, on your own install only,** so you can see the traffic:

```bash
objection -n "$PKG" start          # then: android sslpinning disable
# or the generic Frida template in apk-redteam-pipeline Stage 7, or:
frida -U -f "$PKG" -l frida-multiple-unpinning.js      # MASTG-TOOL-0140
# or repackage without pinning:
apk-mitm app.apk                   # rewrites NSC + strips common pinning
```

Pinning absent or bypassable is **not a finding on its own**: Bugcrowd VRT puts
it at P5 (Mobile Security Misconfiguration > SSL Certificate Pinning >
Absent/Defeatable), HackerOne lists "Lack of SSL Pinning" as core-ineligible,
and program policies routinely exclude it. The finding is whatever the
unpinned traffic reveals (a token, an IDOR, cleartext, a shadow API). Report
the pinning bypass only as the method note.

## 4. Proxy-unaware apps

Some apps ignore the system HTTP proxy (OkHttp set to `Proxy.NO_PROXY`, gRPC,
raw sockets, Flutter's Dart HTTP stack which bypasses the system proxy). When
Burp sees nothing:

- Force traffic with a transparent approach: a VPN-mode interceptor
  (a device VPN-capture app such as PCAPdroid, or ProxyDroid/rethink-dns (verify
  the current tool), feeding mitmproxy in transparent mode), or
  hook the networking APIs at the app layer (MASTG-TECH-0119) instead of the
  proxy (MASTG-TECH-0120).
- Flutter specifically needs its own bypass (MASTG-TECH-0109); the Dart engine
  internals are owned by `hunt-mobile-frameworks`, so hand that off and just
  note "Flutter, traffic not proxied by default".

## 5. WebSocket and gRPC inside the app

Once the traffic is visible, the backend protocols are not Android-specific:

- WebSocket (`ws://`/`wss://`, socket.io, SignalR in a WebView or native
  client): plaintext `ws://` is a transport finding here; CSWSH, missing
  per-message auth and message tampering are `hunt-websocket`.
- gRPC (grpc/grpc-java, `application/grpc` over HTTP/2, `*.proto` in assets):
  plaintext gRPC is a transport finding; reflection, metadata-stripping and
  transcoding attacks are `hunt-grpc`.

Stop at "the app speaks this protocol, here is the transport posture", capture
one framed message as evidence, and hand the protocol-level testing to the
owning skill under its Stage B rules.

## 6. Evidence and severity

- Proxy flow showing the request/response, redacted per `evidence-hygiene`
  (mask the token to first/last four chars).
- The NSC file and the `targetSdk`, so a reviewer can confirm the default that
  applies.
- For a pinning bypass, note the tool and that it ran on your own install; the
  finding is the data behind the pin, graded by its own class.

# SSTP, SoftEther, Tailscale DERP and Headscale, ZeroTier

Depth for Step 5 of `SKILL.md`. Same rules: one request per protocol per host,
`probe_delay` between them, `T` set to the in-scope address.

**SSTP (443/tcp).** Fingerprint only:

```bash
curl -sk --globoff --max-time 10 -X SSTP_DUPLEX_POST -o /dev/null -w '%{http_code}\n' \
  "https://$T/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
```

A 200 to that method and URI marks an SSTP listener; anything else is
inconclusive. SSTP findings are TLS findings (`hunt-tls-network`) plus
whatever authenticates behind it (Stage B).

**SoftEther (443, 992, 1194, 5555/tcp).** `nmap -Pn -sT -sV -p 443,992,1194,5555
"$T"` matches `SoftEther VPN httpd`; the `Keep-Alive: timeout=15; max=19`
header is the tell. The build number travels in SoftEther's own handshake,
which needs the client's watermark upload, so treat the version as unknown.
One SoftEther host usually also speaks L2TP/IPsec, OpenVPN and SSTP: check 500,
4500 and 1701 on it. Testing SoftEther's documented default IPsec PSK is
Stage B. That differs from `hunt-exposed-services`' "documented default once"
rule on purpose: a correct PSK completes IKE phase 1, which is a step into a
tunnel, not a read.

**Tailscale DERP and Headscale (443/tcp, 3478/udp).**

```bash
curl -sk --max-time 10 "https://$T/" | head -20                                   # "This is a Tailscale DERP server."
curl -sk --max-time 10 -o /dev/null -w '%{http_code}\n' "https://$T/generate_204"  # 204
curl -sk --max-time 10 -o /dev/null -w '%{http_code}\n' "https://$T/debug/"        # expect 403
```

`derper` only serves `/debug/` to loopback, Tailscale addresses, operator-set
trusted ranges (`TS_ALLOW_DEBUG_IP`) or a holder of the debug key, and refuses
any request carrying `X-Forwarded-For` (`tsweb.AllowDebugAccess`). A 200 from the internet usually means a
reverse proxy on the same host forwards without that header. That is a finding;
do not follow the index into the client list. Whether the relay runs with
`--verify-clients` cannot be seen without relaying traffic (Stage B); without
it, anyone who knows the address can use the relay. Grade that Informational
unless the client confirms. Headscale and its web UIs are control planes:
fingerprint, then route web-UI issues to `hunt-exposed-panels`.

**ZeroTier (9993).** The UDP port ignores packets that are not valid ZeroTier.
The node's JSON API listens on TCP 9993 and defaults to 127.0.0.1 only
(`allowManagementFrom`). `curl -s -o /dev/null -w '%{http_code}\n'
"http://$T:9993/status"` returning 401 from the internet proves the API is
reachable and token-protected: report the widened management scope. Never try
a token.

## Sources

- MS-SSTP and a client implementation of the request line: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/c50ed240-56f3-4309-8e0c-1644898f0ea8>, <https://gitlab.com/sstp-project/sstp-client>
- SoftEther source (`HTTP_KEEP_ALIVE`, `/vpnsvc/connect.cgi`, hello pack): <https://github.com/SoftEtherVPN/SoftEtherVPN>
- Tailscale custom DERP servers: <https://tailscale.com/kb/1118/custom-derp-servers>; derper source: <https://github.com/tailscale/tailscale/tree/main/cmd/derper>
- ZeroTier One service API: <https://github.com/zerotier/ZeroTierOne/blob/dev/service/README.md>

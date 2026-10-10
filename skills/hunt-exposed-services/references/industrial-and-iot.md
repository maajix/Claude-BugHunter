# Industrial control systems, building automation and cameras

**Read this section before any probe.**

The default posture for everything in this file is **detection only**. Not
"detection first", not "detection unless the scope says critical findings are in
scope". Detection only, unless the operator **and** the asset owner have both
signed off in writing on a specific named action against a specific named device
in a specific window.

The reason is not caution for its own sake. On these devices an availability
impact is physical:

- A PLC that stops scanning stops a pump, a conveyor, a mixer or a press.
- A BACnet building controller runs the HVAC, the chillers, the lifts and
  frequently the door controllers of an occupied building.
- A protection relay or RTU sits in the path of a breaker.
- A camera is pointed at identifiable people, and the stream is personal data
  under GDPR and equivalents.

Many of these devices predate the idea of hostile input. A plain TCP port scan
has taken PLCs out of service. A malformed request can require an on-site
engineer and a physical power cycle to recover. There is no "read-only" flag
that makes an unexpected packet safe on a device with a single-threaded
embedded stack and no bounds checking.

So: the exposure is the finding. An industrial protocol answering an
unauthenticated request from the public internet is Critical on its own, with no
exploitation required and none wanted. Report it, escalate it, and stop.

## Rate bound and sequencing

1. **Passive first.** Use existing Shodan/Censys/ZoomEye records for the IP
   before you send anything. Their scanners already paid the risk. If a passive
   record establishes the device type and exposure, you may have your finding
   with zero packets. `offensive-osint` has the query workflow.
2. **Ownership check before the first packet.** ASN, WHOIS/RDAP, reverse DNS,
   cross-checked against the signed scope. Industrial addresses are routinely
   shared with a third-party integrator or a utility.
3. **One request per device, minimum 10 seconds apart, strictly serial.** No
   concurrency against the same site, even across different devices: many sites
   sit behind one constrained cellular or serial-to-IP gateway, and the gateway
   is the fragile part.
4. **Stop on the first anomaly.** A timeout after a successful reply, a changed
   response time, a connection reset: stop, notify the operator, do not retry.
5. **Never fuzz, never scan a port range, never use an `nmap -sV` intensity
   above the default against an ICS address.** Prefer a single protocol-specific
   read over a generic version scan.

## Port map and read-only identification

| Port | Protocol | Read-only identification | Write operations you must not send |
|---|---|---|---|
| 502/tcp (IANA `mbap`) | Modbus TCP. The specification makes listening on 502 mandatory by default. | `0x2B`/MEI `0x0E` Read Device Identification returns vendor, product code and revision. `0x01`-`0x04` read coils, discrete inputs, holding registers and input registers. `0x18` Read FIFO Queue reads the queue without clearing it. | `0x05` Write Single Coil, `0x06` Write Single Register, `0x0F` Write Multiple Coils, `0x10` Write Multiple Registers, `0x15` Write File Record, `0x16` Mask Write Register, and **`0x17` Read/Write Multiple Registers, which writes despite the name**. Of the `0x08` Diagnostics sub-functions, `01` Restart Communications Option runs the device's power-up confidence tests, `04` Force Listen Only Mode **isolates the device from the rest of the network**, and `0A` and `14` clear counters. |
| 47808/udp and 47808/tcp (IANA `bacnet`) | BACnet/IP | A unicast `ReadProperty` against the Device object returns `object-identifier`, `object-name`, `vendor-name`, `model-name`, `firmware-revision` and `application-software-version`. Every BACnet device is required to be able to execute `ReadProperty`, so it is the safest identification request. | `WriteProperty`, `WritePropertyMultiple`, `ReinitializeDevice`, `DeviceCommunicationControl`. The last two reboot a building controller and take it off the network. |
| 44818/tcp and /udp (IANA `EtherNet/IP-2`, messaging); 2222/tcp and /udp (`EtherNet/IP-1`, I/O) | EtherNet/IP and CIP | The encapsulation `ListIdentity` command (`0x63`) returns vendor ID, device type, product name, revision and serial number. Note that 44818/UDP is largely limited to device discovery and, like 44818/TCP and both 2222 ports, carries no TLS/DTLS. | Any CIP `Set_Attribute_Single`, tag write, or `Forward_Open` flood. `Forward_Open` connection exhaustion is a denial of service on the controller's connection table. |
| 4840/tcp (IANA `opcua-tcp`), 4843/tcp (`opcua-tls`) | OPC UA | `FindServers` and `GetEndpoints` are discovery services that run before any session. They return the application URI, product URI and every advertised endpoint with its security policy. Note that 4840 is the spec's well-known **discovery server** address, not a mandate that every server listens there. | Creating a session, browsing the address space, or writing a node value. |
| 20000/tcp | DNP3 | Device identification only. DNP3 outstations are frequently in the electricity sector. | Any control relay output block, any operate or direct-operate function. |
| 554/tcp and /udp (RFC 2326 default for both); 8554 is a convention, not a standard | RTSP | RFC 2326 says of `OPTIONS` that "it does not influence server state", and Appendix A lists `OPTIONS`, `DESCRIBE` and `GET_PARAMETER` as having no effect on client or server state. Use those two. | `SETUP`, `PLAY`, `RECORD`. Also `ANNOUNCE` and `SET_PARAMETER`: Appendix A excludes them from the *session* state machine, but `ANNOUNCE` posts a presentation description to the server and `SET_PARAMETER` sets a parameter value, so both change the server. Retrieving frames is personal-data processing. |
| 32100/udp | PPPP / CS2 peer-to-peer cameras | A single discovery packet reveals that the device speaks the vendor's P2P protocol. | Device-ID enumeration, key recovery, relay registration, cloud-storage access. |

### The read-only identification probes

```bash
TARGET="192.0.2.50"

# OPC UA: GetEndpoints reveals whether SecurityPolicy "None" with anonymous
# user tokens is advertised, which is the finding on its own.
# (opcua-client / python-opcua / OpalOPC all do this without creating a session.)

# RTSP: OPTIONS then DESCRIBE, one each, nothing further
printf 'OPTIONS rtsp://%s:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n' "$TARGET" \
  | timeout 10 nc -w 5 "$TARGET" 554 | head -20
printf 'DESCRIBE rtsp://%s:554/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n' "$TARGET" \
  | timeout 10 nc -w 5 "$TARGET" 554 | head -40
```

A `DESCRIBE` that returns SDP with no `401 Unauthorized` is the proof of an
unauthenticated camera. **That is the end of the test.** Do not `SETUP` or
`PLAY`. Do not enumerate stream paths with a wordlist; that is brute force, it
hammers an embedded device, and it is unnecessary once `DESCRIBE` on the root
path has answered.

For Modbus, BACnet, EtherNet/IP and DNP3, use the protocol's own identification
request through a library that lets you send exactly one request (`pymodbus`,
`BAC0`, `cpppo`), rather than a scanner that probes a range of registers or
object instances. State in the report which single request you sent.

### nmap scripts here: check the category, do not assume

A script in `intrusive`, `exploit`, `brute`, `dos` or `vuln` is not acceptable
against a PLC under any circumstances, and even a `safe` script is one more
packet than a passive Shodan lookup. The ICS scripts are worse than their names
suggest. Declared categories, read from nmap's own `nsedoc`:

| Script | Declared categories | Verdict for this file |
|---|---|---|
| `modbus-discover` | `discovery`, **`intrusive`** | **Not Stage A.** It is explicitly `intrusive` and it loops over unit IDs. Do not run it against a PLC. |
| `bacnet-info` | `discovery`, `version` | **No `safe` category.** Treat as not-Stage-A under this file's rule. |
| `enip-info` | `discovery`, `version` | **No `safe` category.** Same treatment. |
| `rtsp-methods` | `default`, `safe` | Acceptable Stage A for a camera. |
| `rtsp-url-brute` | **`brute`**, **`intrusive`** | Forbidden. This is the stream-path wordlist, and it hammers an embedded device. |

Because none of the three industrial scripts carries `safe`, the Stage A probe
for Modbus, BACnet and EtherNet/IP is **one identification request issued by
hand through a library** (`pymodbus`, `BAC0`, `cpppo`), not an nmap script.
State the single request you sent in the report.

Verify any script not in this table yourself before first use:
`nmap --script-help <name>` prints its declared categories.

## Pre-auth CVEs worth knowing, and the base-rate numbers

These are detection-by-version findings. None of them should be exploited.

| CVE | Product and range | Class | Pre-auth? |
|---|---|---|---|
| CVE-2019-11219 | Shenzhen Yunni Technology iLnkP2P (the P2P stack behind a very large number of white-label cameras) | Predictable device UID generation (CWE-330), letting a remote attacker establish direct connections to arbitrary devices | **YES.** `AV:N/AC:L/PR:N/UI:N`, CVSS 8.2. |
| CVE-2019-11220 | Same product | Authentication flaw permitting cleartext interception of user-to-device traffic (CWE-319), including video streams and device credentials | **YES.** `AV:N/AC:H/PR:N/UI:N`, CVSS 8.1. Paired with 11219 this is "find any device, then watch it and take its password". |
| CVE-2017-7921 | Hikvision DS-2CD2xx2F-I, DS-2CD2xx0F-I, DS-2CD2xx2FWD, DS-2CD4x2xFWD, DS-2CD4xx5, DS-2DFx, DS-2CD63xx | Improper authentication (CWE-287): impersonate any configured user and retrieve plaintext passwords for all of them | **YES.** CISA rates it CVSS v3 10.0, `PR:N`. The vendor and CISA call it improper authentication; the original researcher called it a backdoor. Both descriptions are pre-auth. |
| CVE-2024-42512 | OPC UA .NET Standard Stack before 1.5.374.158 | Application authentication bypass when the deprecated `Basic128Rsa15` policy is enabled | YES, unauthorised attacker. |
| CVE-2024-42513 | Same stack and range | Application authentication bypass when using HTTPS endpoints | YES, unauthorised attacker. |

Useful context for the severity argument, because clients routinely claim their
OPC UA deployment is secured: a 2020 internet-wide measurement of 1,114
reachable non-discovery OPC UA servers found **270 (26%) supported only
security mode `None`**, and **44% implemented no access control at all**,
meaning anyone could read and write data and call methods. The specification
itself defaults `MessageSecurityMode` to `INVALID` specifically "to avoid an
accidental choice of no security", so a server advertising `None` is a
configuration decision, not a default.

## Honeypots: the dominant false positive here

Industrial honeypots are widely deployed, and a published "we found an exposed
PLC" that turns out to be Conpot is a reputational cost to the operator. Check
all of these before filing:

- Many unrelated industrial protocols answering on one address.
- A device that answers every function code and every register instantly and
  identically.
- Vendor and model strings that match a well-known honeypot default profile.
- Uptime, TTL or TCP-timestamp behaviour inconsistent with embedded hardware.
- A generic hosting-provider ASN rather than a utility, an integrator or an
  industrial netblock.

Record the honeypot assessment in the evidence. "Assessed as genuine because X"
is part of the finding.

## Cameras and personal data

A reachable camera is both a security finding and a privacy incident in
progress. Handle it accordingly:

- Prove reachability with `DESCRIBE` metadata or an HTTP login page, not with a
  frame.
- Capture no stream, store no image, take no screenshot of a live view. If you
  accidentally receive frame data, discard it and note that you did.
- Record in the evidence, in writing, that no stream or image was retained.
- Flag to the operator that the exposure may require a privacy notification
  independent of the security report.

For PPPP/CS2 devices, a further constraint: the device-ID space and the relay
infrastructure belong to the **vendor's cloud**, a third party you are not
authorized to test. Enumerating device IDs, requesting relay sessions or
touching vendor cloud storage is unauthorized access to that third party, no
matter what the client's scope says. One discovery packet to the client's own
device is the whole permitted test.

## Checklist

- [ ] Passive Shodan/Censys record checked before any packet.
- [ ] IP ownership confirmed and present in the signed scope.
- [ ] Asset owner identified; operator informed before the first active probe.
- [ ] Exactly one read-only identification request per device, serial, at least
      10 seconds apart.
- [ ] No write function code, no reinitialize, no device-communication-control,
      no session creation, no `Forward_Open`.
- [ ] No port-range scan and no version-intensity above default against an ICS
      address.
- [ ] Honeypot assessment recorded with its reasoning.
- [ ] Camera proof is metadata only; no frame retained; the non-retention is
      documented.
- [ ] No packet sent to a camera vendor's cloud or relay infrastructure.
- [ ] Finding filed at the exposure level, with physical-availability risk stated
      as the reason exploitation was not attempted.

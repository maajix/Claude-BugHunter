# Exposed debug, RPC and build services

Every service in this file grants code execution **by design**, to anyone who
can reach the port, with no authentication anywhere in the protocol. That makes
them the easiest findings in the skill and the ones where restraint matters
most: the moment you execute anything you have crossed the bundle's boundary,
and you did not need to in order to prove the finding.

**The reachability of the port is the finding.** Write it up at Critical and
stop. Execution proof is Stage B, requires written sign-off, and is almost
always unnecessary.

| Port | Service | Authentication in the protocol |
|---|---|---|
| any (commonly 8000, 8787, 5005) | JDWP, the Java Debug Wire Protocol | None. Oracle's JDWP specification defines no authentication mechanism and says the protocol details "format and layout, not transport", so any security has to come from the transport the JVM was told to use. A connected debugger can invoke arbitrary methods in the target JVM. |
| 5555 | Android Debug Bridge over TCP | `adbd` sets `auth_required = true` by default, and since Android 4.2.2 the device shows a dialog asking the user to accept the host's RSA key. That gate is dropped when the bootloader is unlocked (`ro.boot.verifiedbootstate` is `orange`) or the build is debuggable, at which point `adbd` falls back to `ro.adb.secure`, which defaults to **false**. That is why TV boxes, kiosks, vehicle head units, rooted phones and `userdebug`/`eng` builds are the devices you actually find open. |
| 6000-6063 | X11; display N listens on 6000 + N | Host-based or cookie-based. The X.Org protocol specification defines the 6000 + N mapping, and IANA registers 6000-6063 for X11, so do not stop at 6005. With access control off (the `xhost +` state, where "access is granted to everyone, even if they aren't on the list") any client that can reach the port gets a full session with no cookie: screen capture, keystroke sniffing and input injection. |
| 1099, 1098, 1050 | Java RMI registry, RMI-IIOP | None on the registry itself. Bound object names and their remote interfaces are readable by anyone. |
| 8009 | Apache JServ Protocol (AJP) | None. AJP is a trusted back-channel between a reverse proxy and Tomcat, and was never meant to face a network. |
| 9000 | FastCGI, usually PHP-FPM | None. The protocol assumes the web server in front of it is the only client. |
| 3632 | distcc | None. The daemon compiles what it is sent. |
| user-chosen (often 1234, 2345) | gdbserver | None. A connected GDB client reads and writes process memory and runs code. |

## Stage A probes

### JDWP

```bash
TARGET="192.0.2.60"; PORT="8000"

# Per the JDWP spec the debugger side sends the 14 ASCII characters
# "JDWP-Handshake" and the VM side replies with the same 14 bytes. A server that
# echoes it is a live, unauthenticated debug port. Nothing else is sent and no
# debugger session is established.
printf 'JDWP-Handshake' | timeout 10 nc -w 5 "$TARGET" "$PORT" | head -c 14 | xxd
```

An echoed `JDWP-Handshake` is the complete proof. Record it and file at
Critical: any internet host can attach a debugger to this JVM and invoke
arbitrary code inside the application.

JDWP ports are not standardised, because the port comes from the JVM's
`-agentlib:jdwp=...,address=` option. Look for it on the ports above, on the
application port plus a small offset, and wherever `-sV` reported an unknown
service that returns nothing on connect.

The misconfiguration is specific and worth naming in the remediation section.
With the `dt_socket` transport, a bare `address=8000` listens on the **loopback
address only**; it takes an `address=*:8000` (or a routable bind address) to put
the debug port on the network. The transport's only access control is the
`allow` option, an IP/subnet allowlist whose value may be `"*"` for any address.
So the fix is either removing the agent or setting `address` to loopback and
`allow` to specific subnets. There is no credential to add.

**Stage B (sign-off required):** invoking a method or evaluating an expression
through a debugger session. Blast radius to name: code runs inside a live JVM
in the application's own process; a suspended thread or a wrong invocation hangs
or terminates the application for every user.

### Android Debug Bridge (5555)

```bash
# Connecting is enough to learn the authorisation state. READ THE WARNING FIRST.
adb connect "$TARGET:5555"
adb devices -l          # "device" = authorised (no auth required); "unauthorized" = key prompt
adb disconnect "$TARGET:5555"
```

**Side effect you must account for:** on a device with ADB security enabled,
connecting raises an authorisation dialog **on the device's physical screen**.
If the device is a kiosk, a vehicle head unit, a point-of-sale terminal or
someone's phone, a human may see that dialog and a support ticket may follow.
Note the probe time in the evidence so the client can correlate it, and do not
repeat the connection.

`adb devices` reporting `device` rather than `unauthorized` means ADB security
is off: unauthenticated shell access to the device. That is the finding, at
Critical, and it is proven without running a single command.

**Stage B (sign-off required):** `adb shell`, `adb pull`, `adb install`, port
forwarding. Blast radius: command execution on live hardware, possibly
production or safety-relevant; the action is logged on-device. The KB's
post-exploitation, data-capture and port-forwarding material for ADB is out of
scope for this bundle: forwarding a port through a device is pivoting.

### X11 (6000-6005)

```bash
# Does the server accept a connection from an unauthorised client?
# Displays 0-5 cover the common case; IANA registers 6000-6063 for X11.
nmap -Pn -p 6000-6005 --script x11-access --scan-delay 1s "$TARGET"
```

A positive `x11-access` result means access control is disabled: any internet
client can capture the screen and inject keystrokes into whatever the user has
focused. File at Critical.

**Do not capture the screen.** A screenshot of someone's live desktop is both
personal data and, very often, their credentials and open documents. The
nmap result is sufficient proof. Never inject input: keystrokes sent to a
focused window are actions taken as that user.

### Java RMI (1099) and AJP (8009)

```bash
# RMI registry: list the bound object names. Read-only.
nmap -Pn -p 1099,1098,1050 --script rmi-dumpregistry --scan-delay 1s "$TARGET"

# AJP: is the connector reachable and does it speak AJP?
nmap -Pn -p 8009 --script ajp-methods --scan-delay 1s "$TARGET"
```

An RMI registry listing bound names and their remote interfaces is a High
finding, and Critical when a bound object exposes a method that deserialises
input or when a JMX connector is reachable without authentication. Record the
bound names and interfaces.

Two Oracle CVEs get over-claimed here, so state them accurately or leave them
out. **CVE-2016-3427** is a JMX-subcomponent flaw in Java SE 6u113, 7u99 and
8u77 (and JRockit R28.3.9); Oracle's own April 2016 advisory marks it remotely
exploitable without authentication, but with high attack complexity.
**CVE-2019-2684** is in the RMI subcomponent of Java SE 7u211, 8u202, 11.0.2 and
12; it is also AC:High and its impact is **integrity only**. Neither is a
reliable pre-auth RCE, and CVE-2019-2684 is not an RCE at all.

**Stage B:** invoking a remote method, sending a deserialisation gadget, or
using a JMX MBean server to load a class. All of these are code execution.
`hunt-deserialization` owns the gadget-chain analysis if the operator authorises
exploitation; this skill stops at the registry listing.

AJP's headline issue is **CVE-2020-1938** ("Ghostcat"). Apache's own Tomcat 9
security page describes it as AJP request injection: it returns arbitrary files
from anywhere in the web application, including under `WEB-INF` and `META-INF`,
and it can have any file in the application processed as a JSP. It becomes
**remote code execution only if** the application also lets an attacker place a
file inside itself, for example through an upload feature, so that the
JSP-processing primitive has something to run.

Verified ranges, per branch: **9.0.0.M1 to 9.0.30 (fixed 9.0.31)**, **8.5.0 to
8.5.50 (fixed 8.5.51)**, **7.0.0 to 7.0.99 (fixed 7.0.100)**. Before 9.0.31
Tomcat shipped the AJP connector enabled and listening on all configured
addresses; after the fix the shipped `server.xml` has it commented out and bound
to `::1`, and `secretRequired` defaults to `true`.

One fingerprinting trap: 8009 is the AJP connector's shipped default in
Tomcat's own `server.xml`, but it is **not** IANA-registered for AJP (IANA
assigns 8009/tcp to `nvme-disc`). Identify AJP from the protocol, not the port.

Detection is a version check plus connector reachability. The file read itself
is Stage B.

### FastCGI (9000), distcc (3632), gdbserver

```bash
# FastCGI: an FCGI_GET_VALUES record asks the responder for its own limits.
# It executes no script. If the port answers with a FastCGI record, the
# responder is reachable.
nmap -Pn -p 9000 -sV --version-intensity 0 --scan-delay 2s "$TARGET"

# distcc: identify the daemon. DO NOT use the distcc-cve2004-2687 script:
# despite its name it executes a command on the target.
nmap -Pn -p 3632 -sV --version-intensity 0 --scan-delay 2s "$TARGET"
```

For all three, reachability is the finding:

- **PHP-FPM on 9000** reachable from the internet means anyone can ask it to
  execute a PHP file, and the protocol lets a client set PHP configuration
  values per request, which is the published route to arbitrary code execution.
  Critical. Do not send a request that executes a script. Note that the two
  FastCGI CVEs people reach for are **not** this finding: **CVE-2024-9026** is
  local PHP-FPM log pollution needing `catch_workers_output = yes` (PR:L, no
  network path), and **CVE-2025-23016** is an integer overflow in the `fcgi2`
  library's `ReadParams` affecting 2.0.0 to 2.4.4 and exploitable on 32-bit
  builds only. The exposure itself is the finding; neither CVE carries it.
- **distcc on 3632** compiles and runs what it is sent. Critical. The project's
  own security page is unambiguous that this is by design:
  **CVE-2004-2687** is unauthenticated remote command execution against
  `distccd` 2.x whose port is left unrestricted. The nmap script named after it
  *performs that execution*, so it is Stage B, not detection. Use version
  detection instead.
- **gdbserver** has no authentication and no fixed port. A connected GDB client
  has full read/write access to the debuggee's memory. Critical on reachability.

**Stage B for all three:** any request that executes a script, a compile job or
a command. Blast radius: arbitrary command execution as the service account on a
production or build host; on a build host this also means tampering with
artifacts that are about to be shipped, which makes it a supply-chain action.

## The NSE trap in this family

Several scripts that look like detection are not. Run `nmap --script-help <name>`
and read the declared categories before every first use. If the categories
include `intrusive`, `exploit`, `brute`, `dos` or `vuln`, it is Stage B.
`distcc-cve2004-2687` is the canonical example: the name reads like a version
check and the behaviour is remote command execution.

## Checklist

- [ ] Finding filed on reachability alone. No code executed anywhere.
- [ ] JDWP proven by the echoed `JDWP-Handshake` only; no debugger session.
- [ ] ADB: `adb devices` state read, connection closed, probe time recorded, and
      the on-screen authorisation dialog accounted for in the report.
- [ ] No `adb shell`, `adb pull`, `adb install` or port forward.
- [ ] X11 proven by the access check; no screen capture, no input injected.
- [ ] RMI stopped at the registry listing; no method invoked, no gadget sent.
- [ ] AJP affected-version range checked against the vendor's security pages
      before being quoted; no file read performed.
- [ ] FastCGI, distcc and gdbserver proven by version detection only.
- [ ] `distcc-cve2004-2687` and every other `exploit`/`intrusive` script left
      unrun.
- [ ] Every NSE script used was category-checked with `--script-help` first.

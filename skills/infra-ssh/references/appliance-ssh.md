# SSH on appliances and management planes

SSH on a router, firewall, NAS or switch is not a login prompt; it is the
device's administrative CLI. Reaching it from the internet is a management-plane
exposure before anyone authenticates, and a working credential is Critical
because one command reconfigures the network. That is also why this file is
strict: **one** documented default pair per host, under Stage B, and nothing
typed at the prompt afterwards.

## Identify the product before you think about credentials

Fingerprint from the banner, then corroborate with something else the host
serves (HTTPS admin UI title or certificate, SNMP `sysDescr` if already in hand,
reverse DNS). Banner strings below are commonly observed shapes, not guarantees;
firmware and administrators change them.

| Banner shape | Likely product | Notes |
|---|---|---|
| `SSH-2.0-Cisco-1.25` | Cisco IOS / IOS XE (verify per platform) | No factory SSH credential on enterprise IOS XE. |
| `SSH-2.0-ROSSSH` | MikroTik RouterOS | See the credential table and the three RouterOS rows in `ssh-cve-matrix.md` (CVE-2026-67279 and CVE-2026-86060 are KEV). Build number via `infra-network-devices`. |
| `SSH-2.0-Erlang/<ver>` | Erlang/OTP `ssh` app: Cisco ConfD/NSO and other OTP-based products | CVE-2025-32433 gate in `ssh-cve-matrix.md`. Embedding products often rewrite the banner. |
| `SSH-2.0-dropbear_<YYYY.NN>` | Embedded Linux: consumer and SOHO routers, IoT, some BMCs | Date-style version; Dropbear rows in the matrix. |
| `SSH-2.0-OpenSSH_<ver>` with no distro suffix | Many appliances (Junos, NAS firmware, hypervisors) and RHEL-family hosts | The banner alone cannot tell an appliance from a server. |
| Bare or custom string | Vendor stacks (firewalls, storage) | Identify via the HTTPS admin UI on the same address. |

## Documented factory credentials

Only use a pair the vendor documents for that exact product line. Never a
generic default-password list: that is spraying, and spraying is
`hunt-brute-force`'s territory with its own rules.

| Vendor / product | Documented default | Survives commissioning? | One attempt worth it? | Source |
|---|---|---|---|---|
| MikroTik RouterOS | User `admin`, password blank **or** the one printed on the device sticker | Blank survives on older units nobody configured | Blank only; sticker passwords are not guessable | MikroTik "First Time Configuration": <https://help.mikrotik.com/docs/spaces/ROS/pages/328151/First+Time+Configuration> |
| Fortinet FortiGate | User `admin`, no password; setting a password is mandatory and is forced at first login, after factory reset, and after a new image install | Only on a unit nobody has logged into | Low yield; allowed | FortiOS 7.0.1 Administration Guide, "Default administrator password": <https://docs.fortinet.com/document/fortigate/7.0.1/administration-guide/99980> |
| Juniper Junos | `root`, no password, on a factory-default device | No: a configuration will not commit without `root-authentication` | No, skip | Juniper "Root Password": <https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/user-access-root-password.html> |
| Ubiquiti UniFi | Before adoption: consoles `root`/`ui` (console SSH off by default); older devices `ubnt`/`ubnt` or `root`/`ubnt`. After adoption a random device password is set | Only on unadopted devices | Only if the device looks unadopted (verify against the vendor article) | Ubiquiti help article 204909374 (blocked automated fetch; verify): <https://help.ui.com/hc/en-us/articles/204909374> |
| Cisco Small Business / Catalyst 1200/1300 | `cisco`/`cisco` with a forced change at first login (third-party sources only; verify in the model's admin guide) | Only on an unconfigured unit | Low yield; allowed only after verifying in Cisco's own guide | Cisco admin guide for the exact model |
| Cisco enterprise IOS XE (Catalyst 9000 etc.) | No factory SSH credential; accounts are created at setup | n/a | No | Cisco configuration guides |
| QNAP QTS | QTS 4.4.1 and earlier: `admin`/`admin`. QTS 4.4.2 and later: `admin` with the first MAC address, uppercase, no separators | The MAC-based default does | No: the MAC is not knowable from outside. `admin`/`admin` only on a banner or UI proving QTS 4.4.1 or earlier | QNAP FAQ: <https://www.qnap.com/en/how-to/faq/article/what-is-the-default-username-and-password-of-the-qts-administrator-account> |
| Synology DSM | No factory credential; the administrator account is created during setup (verify) | n/a | No | Synology DSM documentation (verify) |

Procedure: B2 in the skill. One attempt, `-N`, operator-typed password, proof is
the `Authenticated to ... using "password"` (or `"keyboard-interactive"`) debug
line, `timeout` ends the connection. Then re-run the honeypot checks: Cowrie's
default user database accepts `root` with almost any password, and a "default
credential works" result on a decoy is the most common withdrawn SSH report.

Lockout awareness: appliances commonly lock the admin account or the source
address after a few failures. One attempt keeps you clear of any sane threshold;
a second attempt is how a pentest becomes an outage ticket.

## Grading management-plane SSH

| Situation | Grade |
|---|---|
| Documented default accepted on a router, firewall, switch, NAS or BMC | Critical, escalate the same day |
| Banner in range of a KEV-listed pre-auth CVE (Erlang CVE-2025-32433 on ConfD/NSO/RV routers) | High, unconfirmed; same-day notice. RV160/260/340/345 have no fix planned, so the remediation is "remove from the internet". |
| Management SSH reachable from the internet, password auth offered, no working credential | Low to Medium, as an exposure; many hardening baselines require management access restricted to a management network |
| Management SSH reachable, key-only auth | Low or Informational exposure note |

Related routing: SSL VPN gateways (`enterprise-vpn-attack`), vCenter and ESXi
(`vmware-vcenter-attack`), IPMI and other out-of-band protocols on the same BMC
(`hunt-exposed-services`, `references/management-interfaces.md` there).

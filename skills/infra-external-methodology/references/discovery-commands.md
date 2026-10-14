# Discovery commands

Every flag here was checked against the installed binaries: nmap (`--version` printed 7.991),
masscan 1.3.2, naabu 2.6.1 and rustscan 2.3.0. The nmap-services ranks come
from the file shipped with that nmap. Check again with `--help` if your version
differs. A flag that silently does nothing is worse than no flag.

**Preconditions for every block below.** Do not run a block until all four hold:

1. Every target is in `scope-ips.txt` (or `scope-ips6.txt`) and passed
   `SKILL.md` Step 2.
2. `exclude.txt` is passed to the scanner.
3. The rate is the RoE figure or this skill's default posture. Anything above
   the default posture for masscan, naabu or rustscan is Stage B, with the
   sign-off from `SKILL.md` Step 7.
4. The window is open and you are scanning from a declared source IP.

Run `mkdir -p out` once; nmap's `-oA` does not create the directory.

Output is always written by the tool's own output flag (`-oA`, `-oL`, `-o`) or
`tee`, so the command line and timestamps are kept with the result.

---

## 1. Ownership lookups

These go to registries and DNS, not to the target.

```bash
# RDAP: rdap.org redirects to the authoritative RIR (verified: 302 to rdap.arin.net for an ARIN address)
curl -sL "https://rdap.org/ip/192.0.2.10" | python3 -m json.tool | grep -E '"(name|handle|startAddress|endAddress)"'

# Origin ASN and BGP prefix (Team Cymru)
whois -h whois.cymru.com " -v 192.0.2.10"

# PTR, then forward-confirm the name it returns
dig +short -x 192.0.2.10
dig +short A host.target.example
```

A PTR that does not forward-confirm is a hint, not proof. Shared hosting
returns a PTR for the hoster, and stale PTRs survive address reassignment.

---

## 2. Shared-range classifier

The provider range files are public and third-party, so downloading them is not
target traffic. Fetch them once per test day, because they change.

| Provider | Source (verified field names) | Kind |
|---|---|---|
| AWS | `https://ip-ranges.amazonaws.com/ip-ranges.json`: `prefixes[].ip_prefix`, `ipv6_prefixes[].ipv6_prefix`, `service` | `CLOUDFRONT` is shared edge. `EC2` is a customer pool. Excludes BYOIP ranges. |
| Google Cloud | `https://www.gstatic.com/ipranges/cloud.json`: `prefixes[].ipv4Prefix` / `ipv6Prefix` | Customer pool. `goog.json` minus `cloud.json` is Google's own services. |
| Oracle Cloud | `https://docs.oracle.com/iaas/tools/public_ip_ranges.json` (redirects): `regions[].cidrs[].cidr`, `ipv6_cidrs` | Customer pool |
| Azure | Download Center item 56519, `ServiceTags_Public_<date>.json`, published weekly | `AzureFrontDoor.Frontend` is edge (verify the tag name in the current file); regional tags are pools |
| Cloudflare | `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6` | Edge |
| Fastly | `https://api.fastly.com/public-ip-list`: `addresses`, `ipv6_addresses` | Edge |
| Akamai | No public list verified (verify) | Edge. Identify by RDAP and ASN instead |

```bash
curl -s -o aws.json    https://ip-ranges.amazonaws.com/ip-ranges.json
curl -s -o gcp.json    https://www.gstatic.com/ipranges/cloud.json
curl -sL -o oci.json   https://docs.oracle.com/iaas/tools/public_ip_ranges.json
curl -s -o cf4.txt     https://www.cloudflare.com/ips-v4
curl -s -o cf6.txt     https://www.cloudflare.com/ips-v6
curl -s -o fastly.json https://api.fastly.com/public-ip-list

# One label per address. "not-in-published-shared-ranges" is the only result
# that makes an address a port-scan candidate on ownership evidence alone.
python3 -I - candidate-ips.txt <<'PY'
import ipaddress, json, sys
nets = []
def add(label, cidrs):
    nets.extend((ipaddress.ip_network(c), label) for c in cidrs)
aws = json.load(open("aws.json"))
for p in aws["prefixes"] + aws["ipv6_prefixes"]:
    add("aws:" + p["service"], [p.get("ip_prefix") or p["ipv6_prefix"]])
add("gcp-customer", [p.get("ipv4Prefix") or p["ipv6Prefix"] for p in json.load(open("gcp.json"))["prefixes"]])
add("oci", [c["cidr"] for r in json.load(open("oci.json"))["regions"] for c in r["cidrs"] + r.get("ipv6_cidrs", [])])
add("cloudflare-edge", open("cf4.txt").read().split() + open("cf6.txt").read().split())
fa = json.load(open("fastly.json"))
add("fastly-edge", fa["addresses"] + fa["ipv6_addresses"])
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    a = ipaddress.ip_address(line.strip())
    hits = sorted({l for n, l in nets if n.version == a.version and a in n} - {"aws:AMAZON"})
    print(a, ",".join(hits) or "not-in-published-shared-ranges")
PY
```

Tested output on sample addresses: a CloudFront address gives `aws:CLOUDFRONT`,
a Cloudflare v4 or v6 address gives `cloudflare-edge`, and an EC2 address gives
`aws:EC2,aws:S3`.

Reading the labels:

- `*-edge` and `aws:CLOUDFRONT` go into `exclude.txt`.
- `aws:EC2`, `gcp-customer` and `oci` stay out of `scope-ips.txt` until the
  client attests the address is theirs today.
- An unlabelled address still needs the RDAP check, because a small hoster
  publishes no file at all.

---

## 3. nmap passes

Default posture: `-T3 --max-rate 100 --max-retries 2` for TCP, `--max-rate 50
--max-retries 1` for UDP. `--max-rate` is global across the whole scan, not per
host. `-T3` is nmap's default; `-T4` caps the TCP scan delay at 10 ms and is for
networks you know are fast and robust. `-n` skips reverse DNS during the scan,
because Step 2 already did it.

```bash
# Precondition: scope-ips.txt verified (Step 2), exclude.txt applied, rate per RoE.
# Pass 1: TCP top 1000 (nmap's default port set), every host treated as up.
sudo nmap -sS -Pn -n -T3 --max-rate 100 --max-retries 2 --reason \
  -iL scope-ips.txt --excludefile exclude.txt -oA out/tcp-top1000

# Pass 2: full TCP on every verified host, not only those that answered pass 1.
sudo nmap -sS -Pn -n -T3 --max-rate 100 --max-retries 2 --reason -p- \
  -iL scope-ips.txt --excludefile exclude.txt -oA out/tcp-full
```

```bash
# Precondition: as above. UDP at half the TCP rate; targets rate-limit ICMP unreachables.
# Pass 3a: UDP top 100. Covers 53, 69, 123, 137, 161, 500, 623, 631, 1434, 1701,
# 1900, 2222, 4500, 5060, 5353 (all ranked inside 100).
sudo nmap -sU -Pn -n --top-ports 100 --max-rate 50 --max-retries 1 --reason \
  -iL scope-ips.txt --excludefile exclude.txt -oA out/udp-top100

# Pass 3b: targeted UDP that top-ports never reaches (rank in nmap-services):
# 389 (161), 3702 (343), 1194 (15246), 51820 (12250), 3478 (17277),
# 11211 (18973), 12346 (15179).
sudo nmap -sU -Pn -n -p 389,1194,3478,3702,11211,12346,51820 \
  --max-rate 50 --max-retries 1 --reason \
  -iL scope-ips.txt --excludefile exclude.txt -oA out/udp-targeted
```

The ICS UDP ports (47808 rank 515, 44818 rank 7792, 20000 rank 18440, 32100 not
ranked) are **not** in pass 3b. They are probed one port at a time, and only
under `hunt-exposed-services`' industrial rules.

```bash
# Precondition: as above. Only ports found open in pass 2 are fingerprinted, per host.
# Pass 4: -sV at default intensity plus the two orchestration scripts. No -sC, no -A.
grep -h '/open/' out/tcp-full.gnmap | while read -r line; do
  host=$(echo "$line" | awk '{print $2}')
  ports=$(echo "$line" | grep -oE '[0-9]+/open/tcp' | cut -d/ -f1 | paste -sd, -)
  sudo nmap -sS -sV -Pn -n --max-rate 100 --reason --script banner,ssl-cert \
    -p "$ports" "$host" -oA "out/svc-$host"
done
```

For UDP ports left `open|filtered`, run `-sU -sV` on those ports only. nmap sends
protocol payloads for the services it knows, which settles some of them. Any
port that is still `open|filtered` goes in the coverage statement, not in the
findings.

---

## 4. IPv6

**Precondition before anything else:** the scan host has working IPv6 egress.
nmap's man page says both the source and the target must be configured for
IPv6. Without it, every v6 port looks closed and the pass is a false negative.
Check it against a host you control, never a target.

Where external v6 addresses come from:

- AAAA records of in-scope names: `dnsx -l names.txt -aaaa -ro -silent`.
- AAAA records of the MX and NS hosts and of names taken from certificate SANs.
- The client's v6 allocation from RDAP, plus the client's own host list.

Where they do not come from:

- Sweeping a prefix. A single /64 is 2^64 addresses.
- Multicast, SLAAC or router-advertisement discovery. Those are link-local and
  excluded by `SECURITY.md`.
- Walking `ip6.arpa`. nmap's `dns-ip6-arpa-scan` is declared `intrusive`, so it
  is Stage B, and only against the client's own reverse zone.

```bash
# Precondition: scope-ips6.txt checked by hand against the signed scope
# (engine/scope.py does not match IPv6 CIDRs), exclude6.txt applied, rate per RoE.
sudo nmap -6 -sS -Pn -n -T3 --max-rate 100 --max-retries 2 --reason -p- \
  -iL scope-ips6.txt --excludefile exclude6.txt -oA out/tcp6-full
```

The v4/v6 delta is the headline IPv6 finding. `dualstack.txt` holds one
`<v4> <v6>` pair per dual-stack host:

```bash
open_ports() { grep -hF "Host: $1 " "$2" | grep -oE '[0-9]+/open/tcp' | cut -d/ -f1 | sort -u; }
while read -r v4 v6; do
  echo "== $v4 / $v6 (left column: v4 only, right column: v6 only)"
  comm -3 <(open_ports "$v4" out/tcp-full.gnmap) <(open_ports "$v6" out/tcp6-full.gnmap)
done < dualstack.txt
```

Tested on a synthetic pair: SSH and Redis open on both, and RDP open on v6
only. The output was one line, `3389`, in the v6 column.

---

## 5. masscan

Needs raw-socket privileges, because it sends from its own TCP/IP stack. It is stateless: its man
page notes that retries "are sent regardless if replies have already been
received". Treat its output as candidates for nmap to confirm. Do not use
`--banners`. masscan's own stack answers SYN-ACKs with RSTs, which breaks banner
grabbing unless you firewall a dedicated source port.

```bash
# Precondition: scope-ips.txt verified, exclude.txt applied, high-rate use allowed by the RoE.
# --rate 100 is masscan's own default. Anything higher is Stage B: written sign-off
# naming the packets-per-second figure, the target file hash and the window.
sudo masscan -iL scope-ips.txt --excludefile exclude.txt -p1-65535 --rate 100 \
  --wait 10 -oL out/masscan-tcp.lst

# UDP uses the U: prefix: -pU:53,U:161
```

Feed the open ports per host from `-oL` into nmap pass 4. Nothing masscan
reports is a finding until nmap has seen it.

---

## 6. naabu

Its defaults are `-rate 1000` packets per second, 25 workers, `-top-ports 100`,
connect scan (`-s c`), 3 retries, and **`-iv 4,6`**, which means a hostname's
AAAA records are scanned too. `-passive` reads Shodan InternetDB and sends
nothing to the target.

```bash
# Precondition: scope-ips.txt verified, exclude.txt applied, rate per RoE.
# Above -rate 100 is Stage B. -iv 4 until IPv6 ownership is verified by hand.
naabu -list scope-ips.txt -ef exclude.txt -tp full -rate 100 -c 10 -retries 1 \
  -iv 4 -silent -j -o out/naabu-tcp.jsonl

# Passive prior only (no packets to the target):
naabu -list scope-ips.txt -passive -silent -j -o out/naabu-passive.jsonl
```

`-ec` (`-exclude-cdn`) relies on naabu's own CDN detection and still scans 80
and 443. Use it as a second net, never instead of `exclude.txt`.

---

## 7. rustscan

A full-connect scanner with no packets-per-second flag. Speed is set by batch
size (default 4500 concurrent sockets) and timeout (default 1500 ms). Its help
text warns: "Do not use this program against sensitive infrastructure since the
specified server may not be able to handle this many socket connections at
once." Unless `-g` is given, it runs nmap on the results. The built-in call is
`nmap -vvv -p {{port}} -{{ipversion}} {{ip}}`, and the help says it adds `-Pn`.
Anything after `--` is passed through, which is how `-- -A` slips in.

```bash
# Precondition: scope-ips.txt verified, exclusions applied, RoE allows it.
# -g = ports only, no automatic nmap. Batch above 200 is Stage B.
rustscan -a scope-ips.txt -x "$(paste -sd, exclude.txt)" -r 1-65535 \
  -b 200 -t 2000 --tries 1 -g | tee out/rustscan-tcp.txt
```

`-a` accepts a newline-delimited file. `-x` documents only a comma-separated
list, hence `paste`.

---

## 8. Shun check during long scans

```bash
# Precondition: control host is an in-scope address with a port already confirmed open.
# Run between scan batches, not in a tight loop.
sudo nmap -sS -Pn -n --max-rate 100 -p 443 --reason 192.0.2.10 -oA "out/control-$(date +%H%M)"
```

If the control port goes `filtered` mid-scan, your source has probably been
shunned. Stop, record the time, and contact the client. Every result after that
point needs a re-scan, and until then it goes in the coverage statement as
untested.

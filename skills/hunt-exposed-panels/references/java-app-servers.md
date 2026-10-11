# Java application server consoles

JBoss AS / Red Hat EAP / WildFly, and the Apache Tomcat Manager application.
Both ship management surfaces that were designed for an administrator on the
same subnet, and both turn into remote code execution the moment they answer
from the internet with credentials an attacker can supply.

Scope note: AJP 8009 and Ghostcat (CVE-2020-1938) belong to
`hunt-exposed-services` (`references/remote-debug.md`). Spring Boot Actuator,
Jolokia and the H2 console belong to `hunt-springboot`. Jenkins, TeamCity and
every other build server belong to `hunt-cicd`. Gadget-chain construction and
payload generation belong to `hunt-deserialization`. This file covers only the
product-specific route: which path, which verb, which version.

Rate posture: serial, 2 s base delay plus 0-3 s jitter, one path at a time.

---

## JBoss AS / EAP / WildFly

### Fingerprint (Stage A)

Legacy JBoss deployments are recognised by their management paths rather than by
a banner. Probe them with `HEAD`-equivalent reads and record the status code
plus the first bytes of the body for each.

```bash
TARGET="target.example"

# Stage A — read-only. One GET per path, serial, no credentials sent.
for P in /jmx-console/ /web-console/ /web-console/ServerInfo.jsp /admin-console/ \
         /invoker/JMXInvokerServlet /invoker/EJBInvokerServlet \
         /invoker/readonly /management /status; do
  CODE=$(curl -s -m 15 -o /tmp/jb_body.txt -w '%{http_code}' "https://${TARGET}${P}")
  echo "$CODE  $P  $(head -c 120 /tmp/jb_body.txt | tr -d '\n')"
  sleep 3
done
```

Interpretation, and the trap that produces most false positives here: the
invoker servlets answer `GET` with a Java serialisation error or a raw
serialised object, **not** with HTML. A `200` carrying the bytes `\xac\xed`
(the Java serialisation stream magic) or a `ClassCastException` naming
`MarshalledInvocation` is a live invoker. A `200` carrying an HTML login page is
the application's error handler and proves nothing.

The paths above are the set a widely used public scanner probes, with the server
generations each was observed on: `/admin-console` (JBoss 5 and 6, default login
`admin`/`admin`), `/jmx-console` (4, 5, 6), `/web-console/Invoker` (4, 5, 6),
`/invoker/JMXInvokerServlet` (4, 5, 6)
([jexboss](https://github.com/joaomatosf/jexboss)). Modern WildFly has dropped
all of them and exposes `/management` on port 9990 instead; a WildFly box
answering on `/jmx-console` is a very old build or a misconfigured upgrade.

### Verified CVEs

| CVE | Mechanism | Affected (NVD) |
|---|---|---|
| CVE-2010-0738 | The JMX-Console web application performs access control **only for the `GET` and `POST` methods**, so a request with a different method reaches the `GET` handler unauthenticated. A verb-based authorisation bypass, not a parser bug. | JBoss EAP 4.2 before 4.2.0.CP09; 4.3 before 4.3.0.CP08 |
| CVE-2015-7501 | Arbitrary command execution via a crafted serialised Java object, through the Apache Commons Collections library. Reached in practice through the HTTP invoker servlets. Affects a long list of Red Hat products including EAP 6.x, 5.x and 4.3.x. | see NVD's product list |
| CVE-2017-12149 | `doFilter` in the HTTP Invoker's `ReadOnlyAccessFilter` does not restrict the classes it deserialises, so crafted serialised data executes code. | JBoss AS as shipped with Red Hat EAP 5.2 and the 5.x line |

CVE-2010-0738 is the one worth probing carefully, because it is a pure
authorisation flaw with a safe read-only test: the same URL that returns `401`
for `GET` returning console HTML for a different method **is** the finding. No
payload, no deserialisation, nothing executed.

```bash
# Stage A — authorisation-bypass detection. Read-only: this only asks the
# console to render its own index page.
curl -s -m 15 -o /tmp/jb_get.txt  -w 'GET   %{http_code}\n' \
  "https://${TARGET}/jmx-console/HtmlAdaptor?action=displayMBeans"
curl -s -m 15 -X HEAD -o /dev/null -w 'HEAD  %{http_code}\n' \
  "https://${TARGET}/jmx-console/HtmlAdaptor?action=displayMBeans"

# Finding ONLY if the restricted verb reaches the handler while GET is rejected.
```

Do not graduate this into an MBean invocation. `jboss.system:service=MainDeployer`
and the `DeploymentFileRepository` MBean both write WARs to disk, which is
deployment, not detection.

### Where the chain ends

The deserialisation CVEs above are confirmed-RCE primitives. Confirming the
exposure and the version is Stage A and is the finding. Sending a gadget chain
is Stage B under the SKILL.md Step 6 canary protocol, and the blast radius to
name is: code runs inside the live application server JVM as the server user, a
wrong gadget hangs or kills the application, and a deployed WAR is a persistent
artefact you must remove.

---

## Apache Tomcat Manager

### Fingerprint (Stage A)

The Manager application paths, exactly, from the vendor's own how-to
([manager-howto for 9.0](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html)):

| Path | Role required |
|---|---|
| `/manager/html` | `manager-gui` |
| `/manager/text/{command}?{parameters}` | `manager-script` |
| `/manager/status`, `/manager/status/all` | `manager-status` |
| `/manager/status?XML=true`, `?JSON=true` | `manager-status` |
| `/manager/jmxproxy/` | `manager-jmx` |
| `/host-manager/html` | `admin-gui` |

```bash
# Stage A — read-only, no credentials. A 401 with a Basic realm is the signal
# that the app is deployed and reachable; a 403 is usually a RemoteCIDRValve.
for P in /manager/html /manager/text/list /manager/status /host-manager/html; do
  curl -s -m 15 -o /dev/null -D - "https://${TARGET}${P}" 2>/dev/null \
    | grep -i -E '^(HTTP/|WWW-Authenticate)' | tr '\n' ' '
  echo " <- $P"
  sleep 3
done
```

Three distinct outcomes, three different findings:

- **`401` with `WWW-Authenticate: Basic realm="Tomcat Manager Application"`** —
  the app is deployed and internet-reachable. Reportable as exposure even if you
  never authenticate.
- **`403`** — the app is deployed but an address filter is rejecting you. The
  how-to's example filter is
  `<Valve className="org.apache.catalina.valves.RemoteCIDRValve" allow="127.0.0.0/8,::1/128" />`.
  This is a hardening item, not a finding, and it is worth checking whether the
  filter can be bypassed with an `X-Forwarded-For` header **only** if a proxy
  sits in front and `RemoteIpValve` is configured — otherwise the header is
  ignored and you are chasing nothing.
- **`200` with the deployed-application table** — unauthenticated Manager
  access. Critical, stop, report.

Important baseline fact for the report's "is this a default?" question: the
how-to states there is **no username in the default `conf/tomcat-users.xml`
assigned to the manager roles**, so Manager access is completely disabled in a
stock install. Anything you reach was configured by hand, which makes a weak
password a deliberate decision rather than a vendor default.

### Default credentials and the lockout you will trip

There is no vendor-shipped default pair, but `tomcat`/`tomcat`,
`admin`/`admin` and `admin`/`<empty>` are the pairs that appear in
deployment guides and container images. The relevant safety fact is
`LockOutRealm`, documented in
[the realm configuration reference](https://tomcat.apache.org/tomcat-9.0-doc/config/realm.html):

- `failureCount` default **5** consecutive failures.
- `lockOutTime` default **300 seconds**.
- `cacheSize` default **1000**, and failures are recorded **for usernames that
  do not exist**, so guessing usernames also fills the cache.
- Further failed attempts during a lockout **reset the timer**, extending it.
- Valid credentials presented during a lockout **do not succeed**.

That last pair of properties is why a spray here is actively harmful: you can
lock the real administrator out of their own console for as long as you keep
guessing, and the supplied engagement credentials will stop working with no
explanation. Two attempts maximum per host, then stop.

### CVE-2025-24813 — write-enabled default servlet

Path equivalence on an internal dot (`file.Name`) in the write-enabled default
servlet leads to information disclosure, injected content in uploaded files,
and under further conditions remote code execution. NVD's affected ranges:

- 11.0.0-M1 through before 11.0.3
- 10.1.0-M1 through before 10.1.35
- 9.0.0.M1 through before 9.0.99
- 8.5.0 through 8.5.100 (EOL at the time the CVE was created)

The advisory text lists the preconditions, and all of them must hold:

- writes enabled for the default servlet — **disabled by default**
- support for partial `PUT` — **enabled by default**
- a target URL for security-sensitive uploads that is a sub-directory of a
  target URL for public uploads
- the attacker knows the names of the sensitive files being uploaded

Because the first condition is off by default and the third is application
specific, a version match alone is weak. Prove that writes are enabled before
you write a word about it, and prove it with the smallest possible write:

```bash
# Stage B — this WRITES to the server. Requires written sign-off naming the
# host and the file. Blast radius: a file appears in the web root and must be
# removed; a mis-scoped PUT can overwrite an application file.
CANARY="PNL$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -s -m 15 -X PUT --data "$CANARY" \
  -o /dev/null -w 'PUT %{http_code}\n' \
  "https://${TARGET}/${CANARY}.txt"
# Confirmed write ONLY if a follow-up GET of /${CANARY}.txt returns exactly
# that canary string. Then delete the artefact and record the deletion.
```

A `403` or `405` here means writes are off and the CVE is not reachable. Say so
in the report; "version in range" plus "writes disabled" is an Informational
patch-hygiene item, not a High.

### Where the chain ends

A Manager session with `manager-script` is WAR deployment, which is remote code
execution by design. The deploy interface is documented as an HTTP `PUT` to
`/manager/text/deploy?path=/foo` to upload a WAR, with `GET` variants taking
`war=file:/path/to/bar.war`, `config=file:/path/context.xml` and `update=true`
(default `false`).

**Deploying a WAR is Stage B and is almost never necessary.** An authenticated
`GET /manager/text/list` proves the privilege level: it returns every deployed
context and its state, which is unambiguous evidence that you held deployment
rights. That listing plus the role names from the `401` realm is a complete
Critical finding. If sign-off for a deploy exists anyway, the blast radius to
name is: arbitrary code in the servlet container as the Tomcat user, a
persistent context you must undeploy, and an application outage if the context
path collides with a live one.

---

## Cross-references

- `hunt-exposed-services` — AJP 8009 and Ghostcat CVE-2020-1938, Java RMI 1099,
  JDWP.
- `hunt-springboot` — Actuator, Jolokia, the H2 console, Spring4Shell.
- `hunt-cicd` — Jenkins and every other build server with a script console.
- `hunt-deserialization` — gadget chains, payload generation, and the Java
  serialisation stream markers used above as a detection signal.
- `hunt-file-upload` — the upload-path mechanics behind CVE-2025-24813.
- `hunt-rce` — generic command-execution confirmation discipline.

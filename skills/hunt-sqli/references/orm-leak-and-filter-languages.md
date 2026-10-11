# ORM leaks and filter-language injection

A whole family of data-disclosure bugs sits one layer above SQL injection and is
invisible to every tool that looks for quote breaking. The query is built
correctly. The values are bound. No syntax error is reachable. The flaw is that
the client chose the **field names and the comparison operators**, so the
attacker writes a predicate against columns the API never returns.

elttam named the class **ORM leaks** and the cross-relation technique a
**relational filtering attack**. The confirmation signal is never a database
error; it is a row count, a response length, a pagination total or a latency
difference. That makes the false-positive discipline different from the rest of
this skill, and section "Proof and the stopping point" below is the part to read
before sending anything.

**Cadence for everything here.** Serial, 1.5s base plus up to 1.5s jitter. Caps
per endpoint: 25 Stage A differential requests, 150 oracle characters, 10 timing
trials. Every request is a `GET` or a read-only `POST` search. Nothing in this
file mutates data, and nothing in it should.

---

## Part 1 — ORM leaks

### The sink shape

Any handler that unpacks a request body straight into a filter call:

```python
# Django. The ** unpacking lets the client choose field names AND operators.
articles = Article.objects.filter(**request.data)
```

```javascript
// Prisma. The whole body becomes the query options.
const posts = await prisma.article.findMany(req.body.filter)
// Or just the predicate.
const posts = await prisma.article.findMany({ where: req.query.filter })
```

```go
// Beego. The client controls the first argument, which carries the operator.
qs := o.QueryTable("articles")
qs = qs.Filter(filterExpression, filterValue)
```

```ruby
# Ransack before 4.0.0. The whole q hash is the query.
@q = Post.ransack(params[:q])
```

### Django: lookup expressions as the attack language

Django's double-underscore lookups traverse relations and select operators in the
same string, so one query parameter reaches arbitrary joined columns:

```json
{"username": "admin", "password_startswith": "a"}
{"created_by__user__password__contains": "pbkdf2"}
{"created_by__departments__employees__user_startswith": "adm"}
```

Two relation paths are near universal because they exist in `AbstractUser`
itself, which means they work on an application that defined no interesting
relations of its own:

```text
created_by__user__groups__user__password
created_by__user__user_permissions__user__password
```

Guard bypass works the same way. A handler that thinks it is safe because it
pins a flag:

```python
Article.objects.filter(is_secret=False, **request.data)
```

is defeated by looping back through a many-to-many relation to the same table:
`categories__articles__id=2` makes `is_secret=False` apply to the *joined*
non-secret row while the attacker-chosen relation selects data belonging to a
secret one.

**The regex oracle, and why it is usually the wrong tool.** elttam's error-based
variant uses a catastrophically backtracking `__regex` value to force a timeout
and a 500 response when the prefix matches:

```json
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
```

Per the original research this depends on MySQL's regex timeout and is unlikely
to work on SQLite, PostgreSQL or MariaDB. It is also a CPU-exhaustion payload
against a production database. Use it only when no count, length or presence
oracle exists, cap it at 10 trials, and never run two concurrently.

### Django's raw escape hatches

Separate from the leak class, these are the sinks where real SQL injection still
lives in a Django codebase. Django's own documentation carries the warnings, so
quote them in the report:

| Sink | What the docs say |
|---|---|
| `Manager.raw(raw_query, params=(), translations=None)` | "**Do not use string formatting on raw queries or quote placeholders in your SQL strings!**" |
| `connection.cursor()` | "To protect against SQL injection, you must not include quotes around the `%s` placeholders in the SQL string." |
| `QuerySet.extra(select=, where=, params=)` | "You should be very careful whenever you use `extra()`. Every time you use it, you should escape any parameters that the user can control by using `params`" and "You also must not quote placeholders in the SQL string." The docs also mark it as "an old API that we aim to deprecate", no longer receiving bug fixes. |
| `RawSQL` in `annotate()` / `filter()` | Documented as the parameterised alternative to `extra()`; unparameterised fragments are the same hazard. |

A grep over a Django codebase for `.extra(`, `.raw(`, `RawSQL(` and
`cursor.execute(` with adjacent `%` or f-string formatting finds these quickly.

### Prisma: raw methods and type confusion

The raw API splits by safety, and the names say which is which:

| Method | Safety |
|---|---|
| `$queryRaw`, `$executeRaw` | Tagged-template parameterised |
| `$queryRawUnsafe`, `$executeRawUnsafe` | Raw string. The docs say the "Unsafe" methods "are at significant risk of making your code vulnerable to SQL injection" and recommend the non-unsafe variants "wherever possible". |
| `$runCommandRaw`, `<model>.findRaw`, `<model>.aggregateRaw` | MongoDB command passthrough |

The leak class, though, needs none of those. Prisma's `where` accepts either a
primitive or an operator object, so a handler that assumed a string gets a
predicate:

```ts
const user = await prisma.user.findFirstOrThrow({
    where: { resetToken: req.body.resetToken as string }
})
```

Coercion vectors, in the order they are worth testing:

- JSON body, the `express.json()` default: `{"resetToken":{"not":"E"}}` matches
  every user whose token is not `E`.
- URL-encoded body with `extended: true`: `resetToken[not]=E` becomes the same
  object.
- Query string with an extended parser: `?resetToken[contains]=argon2`.
- `cookie-parser` JSON cookies: `Cookie: resetToken=j:{"startsWith":"0x"}`.

Any equality check on a secret becomes a predicate that succeeds without knowing
the secret. `select` and `include` are the disclosure half of the same bug:
`{"include":{"createdBy":true}}` returns the joined user row wholesale, and
`{"select":{"createdBy":{"select":{"password":true}}}}` asks for exactly one
hidden column.

### Sequelize

Sequelize's two mechanisms differ in where the value is placed, and the
documentation states it plainly:

- `replacements` (`?` positional, `:name` named) are "escaped and inserted into
  the query by sequelize before the query is sent to the database". They are a
  client-side string operation.
- `bind` parameters (`$1` positional, `$name` named) are "sent to the database
  outside the SQL query text". They cannot be SQL keywords, table names or
  column names, and they are ignored inside quoted text.
- "A query can have either bind parameters or replacements", not both.

The practical consequence for a hunt: a `sequelize.query()` call whose SQL was
assembled with template-literal interpolation is injectable regardless of which
mechanism the remaining values use, and a column or table name can never be
bound, so `ORDER BY` and dynamic-column features are where to look.

### Beego and Harbor: validating only the first segment

Beego mirrors Django's `field__operator` DSL. Harbor tried to protect sensitive
fields by tagging them and validating only the first `__`-delimited segment:

```go
k := strings.SplitN(key, orm.ExprSep, 2)[0]
if _, ok := meta.Filterable(k); !ok { continue }
qs = qs.Filter(key, value)
```

Beego's internal `parseExprs` walks **every** segment, and when a segment is not
a relation it overwrites the target field with the next one. So
`email__password__startswith=foo` passes a check on `email` and executes as
`password__startswith=foo`. Harbor later limited keys to a single separator, but
its fuzzy-match builder appends the operator *after* validation
(`q=email__password=~abc` becomes `Filter("email__password__icontains", ...)`),
which reproduces the overwrite.

The generalisable audit question: **does validation happen on the same string
the ORM finally receives?** Any transformation between the check and the sink
reopens the bug.

### Strapi: unknown top-level keys forwarded to the query builder

A good example of ORM injection with no SQL injection anywhere. In
`@strapi/strapi` **4.0.0 through 5.36.1**, the public Content API validated
documented keys (`filters`, `sort`, `fields`, `populate`) and silently *kept*
unknown ones, which the query transformer then forwarded via `...rest` into the
internal query builder. A `where` tree therefore reached the database even though
`where` is not a documented Content API parameter:

```http
GET /api/<collection>?where[updatedBy][resetPasswordToken][$startsWith]=d
```

`updatedBy` joins the public collection to the admin users table,
`resetPasswordToken` never appears in the JSON response but still affects the
predicate, and `meta.pagination.total` reports whether the guessed prefix
matched. Tracked as [CVE-2026-27886](https://nvd.nist.gov/vuln/detail/CVE-2026-27886) /
[GHSA-rjg2-95x7-8qmx](https://github.com/advisories/GHSA-rjg2-95x7-8qmx),
"Strapi may leak sensitive data via relational filtering due to lack of query
sanitization", rated critical, affecting `@strapi/strapi` **>= 4.0.0, < 5.37.0**
and fixed in **5.37.0** by allow-listing valid query keys.

The non-destructive confirmation is an always-false predicate, which is the
pattern to reuse everywhere in this file:

```http
GET /api/<collection>                       # baseline
GET /api/<collection>?where[id][$lt]=-1     # always false
```

On a vulnerable target both return 200 but `meta.pagination.total` changes,
usually to 0. On a patched target the unknown key is stripped and the total is
unchanged. **That differential is the whole finding.** Do not continue into
token extraction; see the stopping point below.

### Entity Framework and reflection-based search helpers

A helper that enumerates every string property of an entity and ORs them into
`.Contains(term)` exposes passwords, tokens, salts and TOTP secrets to anyone who
can call the endpoint, because the predicate covers columns the projection never
returns. Directus is a real instance:
[CVE-2025-64748](https://nvd.nist.gov/vuln/detail/CVE-2025-64748) /
[GHSA-8jpw-gpr4-8cmh](https://github.com/advisories/GHSA-8jpw-gpr4-8cmh),
summarised as "a vulnerability allows authenticated users to search
concealed/sensitive fields when they have read permissions". Search on the users
collection reached `token`, `tfa_secret` and `password`, the values stayed masked
in the response, and match detection turned the result set into an enumeration
oracle. Rated moderate (CVSS 6.5). Fixed in `directus` **11.13.0** and
`@directus/api` **32.0.0** by refusing search on concealed fields regardless of
permissions.

### Collation decides whether the oracle works at all

String comparison inherits the database collation, so calibrate before brute
forcing:

- Default MySQL, MariaDB, SQLite and MSSQL collations are often
  case-insensitive, so `LIKE` and `=` cannot distinguish `a` from `A`. Use a
  case-sensitive operator when the secret's casing matters.
- Prisma and Entity Framework mirror the database ordering. MSSQL's
  `SQL_Latin1_General_CP1_CI_AS` orders punctuation before digits and letters, so
  a binary search must follow the collation, not raw ASCII.
- SQLite's `LIKE` is case-insensitive unless a custom collation is registered,
  so a Django or Beego leak may need `__regex` to recover case.

Calibrating first turns a 150-request budget into a usable oracle instead of a
wasted one.

---

## Part 2 — RSQL / FIQL

RSQL is a REST filter language compiled into a backend query. It is a superset of
FIQL (Feed Item Query Language, specified in the Internet-Draft
`draft-nottingham-atompub-fiql-00`), chosen because it is compact and
URI-friendly. The injection is the same ORM-leak shape: the client supplies the
field, the operator and the relation path.

```text
/products?filter=price>100;category==electronics
```

Operators, per the reference `rsql-parser` implementation:

| Operator | Meaning |
|---|---|
| `;` or `and` | Logical AND (binds tighter than OR) |
| `,` or `or` | Logical OR |
| `( )` | Override precedence |
| `==` | Equal to |
| `!=` | Not equal to |
| `=lt=` or `<` | Less than |
| `=le=` or `<=` | Less than or equal |
| `=gt=` or `>` | Greater than |
| `=ge=` or `>=` | Greater than or equal |
| `=in=` | In a list, `=in=(a,b)` |
| `=out=` | Not in a list, `=out=(a,b)` |

Implementations commonly add their own: `=q=` (search), `=like=`, `=notlike=`,
`=rng=(from,to)`. Custom FIQL-like operators such as `=all=` are an advertised
extension point, so enumerate rather than assume.

Relation traversal uses a dot, which is the equivalent of Django's double
underscore:

```text
director.lastName==Nolan;year=ge=2000;year=lt=2010
```

That dot is the leak primitive. A filter exposed on one resource reaches joined
resources, and a wildcard such as `actor==*Bale` turns an equality endpoint into
a prefix oracle.

**Surface signals.** `?filter=`, `?q=`, `?search=`, `filter[<resource>]=`,
`Accept: application/vnd.api+json` (JSON:API, where `filter[...]` is the
convention), and the companion parameters `include`, `sort`, `fields[<resource>]`,
`page[size]`, `page[number]`. The combination of a `filter[...]` parameter and a
`meta` block carrying a total is the ideal target, because the total is a
ready-made oracle.

**The highest-yield instance** is an endpoint built for one narrow check, such as
a registration form asking whether an email is already taken. Designed to return
a boolean, it returns the matched record once an RSQL filter reaches it:

```http
GET /api/registrations?email=<address>                             # intended
GET /api/registrations?filter[userAccounts]=email=='<address>'     # injected
```

A non-matching address returns an empty attributes block; a matching one returns
the user object, which is an unauthenticated account-enumeration and
information-disclosure finding on its own.

---

## Part 3 — OData `$filter`

OData is the same problem with a standardised grammar, and because ASP.NET OData
controllers return `IQueryable<T>`, the filter is compiled into SQL by Entity
Framework. A property exposed in the EDM is filterable even when the projection
hides it and even when string functions are disabled, because the comparison
operators alone are enough for a binary search.

Operators and functions, per the OASIS URL conventions specification:

- Comparison: `eq`, `ne`, `gt`, `ge`, `lt`, `le`. Operator names are
  case-insensitive in OData 4.01.
- Logical: `and`, `or`, `not`. Also `has` for enumeration flags and `in` for
  membership.
- String functions: `contains(string, substring)`,
  `startswith(string, prefix)`, `endswith(string, suffix)`,
  `substring(string, start[, length])`. Comparisons are case-sensitive; use
  `tolower` or `toupper` for case-insensitive matching.
- Navigation properties are traversed with `/`, which is the relation-pivot
  primitive.
- System query options: `$filter`, `$select`, `$expand`, `$top`, `$skip`,
  `$count`.

```text
GET /odata/Articles?$filter=CreatedBy/TfaSecret ge 'M'&$top=1
GET /odata/Articles?$filter=CreatedBy/TfaSecret lt 'M'&$top=1
```

Presence or absence of a result, or the `$count` value, answers one bit per
request. `$count` is the cleanest oracle because it needs no body comparison at
all. `$select` and `$expand` are the disclosure half: an EDM that exposes a
sensitive navigation property often returns it directly to `$expand`.

Signals: a `/odata/` path prefix, a `$metadata` document (fetch it, it lists
every filterable property and navigation path for free), `OData-Version` response
headers, or query parameters beginning with `$`.

---

## Proof and the stopping point

This is the part that keeps the finding ethical and the report credible.

1. **The always-false differential is the finding.** One baseline request and one
   request with a predicate that cannot be true (`where[id][$lt]=-1`,
   `$filter=Id lt -1`, `filter=id=lt=-1`, `{"id__lt": -1}`). A changed count,
   total or length proves the injected predicate reached the query. Save both
   bodies. Report at that point.
2. **A second request proves the relation pivot.** The same always-false
   predicate on a *joined* field that the response never contains
   (`where[updatedBy][id][$lt]=-1`). A differential here proves the attacker
   reaches columns outside the API contract, which is the severity argument.
3. **Prefix oracles run against your own test account only.** Seed a known value
   in a field you own and recover it character by character to demonstrate the
   oracle works. Within the 150-character cap, that is a complete proof.
4. **Never extract or use another user's secret.** Recovering a real
   `resetPasswordToken`, API key or TOTP seed and then exercising the reset flow
   is account takeover of a real person, not a proof of concept. Describe the
   chain in prose: "an oracle on `resetPasswordToken` plus the unauthenticated
   reset endpoint yields administrator takeover" is a critical finding and
   requires no real token.
5. **Never send a mutation.** No filter pointed at a delete or update endpoint,
   no `data` or `set` keys alongside the filter, and no `include`/`populate` that
   writes. The class is read-only by construction; keep it that way.
6. **Rule out the trivial explanation.** A changed count can also come from
   pagination defaults, caching, a soft-delete flag or a tenant scope. Re-run the
   baseline after the injected request and confirm it returns to its original
   value before claiming anything.

---

## Root causes

1. A request body or query string spread directly into a filter call, so the
   client owns the field names and the operators.
2. Validation applied to a transformed copy of the key rather than to the string
   the ORM receives, or applied before an operator suffix is appended.
3. Unknown parameters ignored instead of rejected, then preserved by an object
   spread on the way to the query builder.
4. Public entities carrying relations to internal or authentication tables
   (`updatedBy`, `createdBy`, `owner`, `user`, `admin`), with no per-property
   deny-list on the joined side.
5. A response that leaks an oracle for free: row presence, a count, pagination
   metadata or a latency difference.
6. A reflection-based search helper that treats "every string property" as
   searchable.

---

## Sources

- elttam: [Plormbing your Django ORM](https://www.elttam.com/blog/plormbing-your-django-orm/),
  [Plorming your Prisma ORM](https://www.elttam.com/blog/plorming-your-primsa-orm/),
  [ORM leaking more than you joined for](https://www.elttam.com/blog/leaking-more-than-you-joined-for/).
- Positive Security: [Ransack data exfiltration](https://positive.security/blog/ransack-data-exfiltration).
  Ransack **4.0.0** (released 2023-02-09) made explicit allow-listing of
  searchable attributes and associations a breaking change, so a version check
  comes before testing.
- Bishop Fox: [CVE-2026-27886, unauthenticated boolean-oracle exfiltration of administrator secrets in Strapi](https://bishopfox.com/blog/cve-2026-27886-unauthenticated-boolean-oracle-exfiltration-of-administrator-secrets-in-strapi).
- Advisories: [GHSA-rjg2-95x7-8qmx](https://github.com/advisories/GHSA-rjg2-95x7-8qmx)
  (Strapi), [GHSA-8jpw-gpr4-8cmh](https://github.com/advisories/GHSA-8jpw-gpr4-8cmh)
  and [CVE-2025-64748](https://nvd.nist.gov/vuln/detail/CVE-2025-64748) (Directus).
- Vendor documentation: [Django raw SQL](https://docs.djangoproject.com/en/stable/topics/db/sql/)
  and [`QuerySet.extra()`](https://docs.djangoproject.com/en/stable/ref/models/querysets/#extra),
  [Prisma raw queries](https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries),
  [Sequelize raw queries](https://sequelize.org/docs/v6/core-concepts/raw-queries/).
- Specifications: [`rsql-parser`](https://github.com/jirutka/rsql-parser) for the
  RSQL operator set and the FIQL relationship,
  [OData 4.01 URL conventions](https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html)
  for `$filter`.
- Coverage of the technique list was checked against the HackTricks
  `pentesting-web/orm-injection` and `pentesting-web/rsql-injection` pages
  (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a
  checklist only. All prose, the proof ladder, staging and safety guidance here
  is written against the primary sources listed above.

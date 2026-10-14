# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [Unreleased]

### Added
- **External infrastructure layer, 16 `infra-*` skills.** `infra-external-methodology`
  owns discovery and the port-to-skill routing table; per-service skills for SSH,
  FTP, mail, DNS, the Windows perimeter, VoIP/SIP, IKE and tunnel VPNs, network
  device management planes, RMM and remote support, backup and NAS, enterprise
  application servers (SAP, WebLogic, WebSphere, JBoss, ColdFusion, Atlassian),
  data platforms (Hadoop, Kafka, ZooKeeper, Solr, ClickHouse), AI/ML serving and
  agent builders (Ollama, Ray, Triton, MLflow, Langflow, MCP servers), DevOps
  control planes (Vault, Consul, Nomad, registries) and monitoring/logging
  ingest. Stage A is read-only; every write, login, job or tool call is Stage B
  with sign-off. CVE matrices carry CISA KEV status as of catalog 2026.10.13.
- **`hunt-cloud-backends`**: Firebase, Supabase, Cognito/Amplify, Appwrite,
  PocketBase, Hasura and Auth0 tenants tested from client-side config.
- **Mobile application pentest layer**: `hunt-mobile-android` and
  `hunt-mobile-ios` (MASVS v2 / MASTG v2 aligned test plans: storage, IPC and
  platform, biometrics and session, network and pinning, resilience, tooling)
  and `hunt-mobile-frameworks` (Flutter, React Native, Xamarin/MAUI, Unity,
  Cordova/Capacitor, Kotlin Multiplatform, bundle-to-backend routing, app-store
  recon). The two `*-redteam-pipeline` skills keep acquisition and extraction.
- **`hunt-cloud-misconfig` references** for storage by provider, instance
  metadata endpoints of every major and second-tier provider, serverless/PaaS
  and managed-service exposure; **`cloud-iam-deep` references** for second-tier
  provider tokens (DigitalOcean, Hetzner, OVH, Linode, Vultr, Scaleway, Alibaba,
  OCI, IBM, Cloudflare, Backblaze) and IaC/CI federation leaks.

### Changed
- **2025/2026 methodology refresh across the hunt and platform skills**: nuclei
  template paths, subfinder provider config, OWASP Agentic Top 10 (Dec 2025),
  subdomain-takeover provider status, Frida and Android 14+ CA paths, Burp
  single-packet attack wording, React2Shell and Livewire gates, SAML parser
  differentials, platform CVSS 4.0 policy dates, Redis probes reduced to `PING`.
- Plugin version 2.3.0; skill count 111 (70 `hunt-*`); `pyproject.toml`,
  `cbh.__version__` and the recon-manifest producer string now carry the same
  version.
- **Claude 5 model-switch guidance**: the README names the Opus 5 / Opus 5.5
  (to Opus 4.8) and Sonnet 5.5 (to Sonnet 5) fallbacks, that content the model
  reads can trigger them on its own, and the Cyber Verification Program status at
  launch; the safeguards paragraph no longer says "block by default".
- **Engine model default removed**: `engine/engine.py --model` and
  `engine/agent.py run_agent()` inherit the claude CLI's configured model instead
  of pinning `claude-sonnet-4-6`; `eval/` keeps its pins for reproducibility.
- **References Index moved to the top** of the 28 reference-heavy skills so it
  survives the post-compaction 5,000-token budget per loaded skill; sources and
  lab notes stay at the old position under `## Sources`.
- **Custom frontmatter keys under `metadata:`** (`sources`, `report_count`,
  `version`, `triggers`) so the files pass claude.ai uploads and the Skills API;
  `lint_skills.py` rejects any other top-level key; the installers'
  `--normalize-frontmatter` strips the block.
- An authorization frame line opens the 17 skills that had none; uppercase
  emphasis calmed in six skills (severity labels untouched).
- `bug-bounty` and `osint-methodology` descriptions trimmed to the 1,024-char
  limit; the lint grandfather list is gone, so the limit is an error everywhere.
- **Descriptions trimmed to a 600-char target** in 87 skills: the always-loaded
  budget drops from 82k to 55k chars (roughly 20k to 14k tokens). Trigger nouns
  and the `Use when` sentence stay, content inventories moved out. `lint_skills.py`
  warns above 600; the `cbh` description parser stops at hyphenated keys such as
  `user-invocable`.
- `hunt-idor`, `hunt-misc`, `hunt-oauth` and `hunt-rce` descriptions written out
  from their bodies (they were one-line stubs of about 117 chars).
- `hunt-dispatch` is `user-invocable: false`; credits and architecture agree on
  81 original, 22 community and 8 vendored skills.
- Docs: the throttle `PreToolUse` hook is wired by the plugin install only, with
  the `settings.json` block for copy installs; CI fails when `docs/skills.md` or
  `cbh/data/skill_index.json` is stale.

### Removed
- `bb-local-toolkit`: a byte-identical copy of `bug-bounty` (18.7k tokens, over
  the description limit).

### Added (earlier, unreleased)
- **A request ceiling and required headers, enforced in code** (`engine/throttle.py`,
  `hooks/throttle-guard.py`, `scripts/test_throttle_wire.py`,
  `docs/rate-limiting.md`). An engagement can state a request-per-second ceiling
  and a header every request to the target must carry, such as the bounty
  username an Intigriti programme requires, and both are held by code rather
  than asked for in a prompt. The counter lives in a state file taken under
  `fcntl.flock`, so the agent's `curl`, a background `nuclei`, four parallel
  `xargs` children and the engine's own recon all draw on one shared budget
  instead of one each.
  - **A sliding window, not a token bucket.** Refilling at 5/s with a burst of 5
    lets a one-second window hold ten requests. The wire test measured exactly
    that — 9 arrivals against a stated ceiling of 5 — so the limiter was changed
    rather than the assertion relaxed. Releases are also paced evenly over a
    window 10% longer than the stated one, because a ceiling is counted at the
    target's end where arrival jitter adds to any window; without the pacing, 6
    arrivals still landed in a window against a stated 5.
  - **Headers travel inside TLS**, added with each tool's own header flag, so
    there is no proxy and no intercepting CA. They reach in-scope hosts only: an
    out-of-scope target passes through unbudgeted and without them, so reading an
    NVD page neither spends the target's budget nor leaks the bounty username.
  - **A `PreToolUse` hook** refuses an unwrapped network tool, a command that
    unsets the proxy or engagement variables, `WebFetch` against an in-scope
    host, and any of 46 named network tools whose flags could not be verified on
    this machine — so an ungovernable tool is a visible refusal rather than a
    silent overrun. It is inert unless an engagement names a ceiling or headers,
    and fails closed inside one.
  - **Verified at the wire, not at the counter.** `scripts/test_throttle_wire.py`
    runs a receiver on loopback, drives 20 real `curl` processes through the
    wrapper four at a time, and asserts from the receiver's log that no window
    held more than the ceiling and that the header reached every in-scope
    request and none of the out-of-scope ones.
  - `docs/rate-limiting.md` lists all 19 ways traffic can leave and marks each:
    7 governed, 4 refused, 2 that are not target traffic, 5 not covered, 1
    unverified. The first count written here said nine governed; counting the
    rows said seven, because two of them are passive third-party sources that
    never touch the target. The earlier
    description of this as "no request can exceed the limit" was too strong and
    is corrected there.

- **Two skills adopted from community forks (90 → 92; `hunt-*` 65 → 66)**, each read
  file-by-file and re-verified rather than merged:
  - `hunt-healthcare-fhir` (from [@prithvee07](https://github.com/prithvee07)) —
    rebuilt around **authorization**, which is where FHIR bugs actually live: a
    token scoped to one patient reaching another's records through search
    chaining, `_has`, `_include`, `$everything`, or a compartment the server
    never enforces. Verified against `hl7.org/fhir` R4, SMART App Launch v1 and
    v2, and the HL7 bulk-data IG, with the R4-vs-current-build compartment
    deltas called out. PHI discipline is four paragraphs before the first
    heading: proof is an identifier you are not entitled to or a status
    differential, with bodies reduced to counts, and `_summary=count` is the
    preferred probe precisely because it proves the bug while moving zero
    records. No step writes.
  - `nuclei-template-forge` (from [@W1nt3rDay](https://github.com/W1nt3rDay)) —
    turns a finding confirmed once by hand into a repeatable estate-wide check.
    Re-authored against Nuclei Engine v3.8.0: the adopted draft named no
    severity values, matcher types or extractor types, gave rate limits as bare
    placeholders, and omitted that `matchers-condition` and `condition` both
    default to `or`. The template in Step 3 was validated by execution
    (`nuclei -validate`, v3.8.0, exit 0), and the Step 4 failure output is real
    measured error text.
- **Four further new skills (86 → 90; `hunt-*` 61 → 65)**, same sourcing bar — every
  CVE, path, port and version boundary re-verified against a primary source at
  authoring time rather than carried over from notes:
  - `hunt-exposed-panels` — internet-exposed **HTTP** admin panels and dashboards
    across 5 reference families (data/notebook tools, DevOps and orchestration,
    monitoring and dashboards, Java app servers, SaaS and proxy exposure): Tomcat,
    JBoss, Grafana, Zabbix, Jupyter, Artifactory, Portainer, Consul, Nomad, Flink,
    Spark, Airflow, Netdata, Prometheus. Splits cleanly from `hunt-exposed-services`,
    which keeps the raw-port half. Triage sequence routes a fingerprint to one
    reference; every probe is read-only by default and stops at
    "unauthenticated access confirmed".
  - `hunt-cms` — CMS and groupware platforms across 6 reference families (WordPress,
    Drupal, Joomla, Moodle, Adobe Experience Manager, and a grouped file for the
    thinner PrestaShop/Roundcube/Bolt surface), 33 verified CVEs. Fingerprint and
    version-match before touching anything; no exploit spraying. Two advisories
    with no locatable CVE are cited by vendor URL and labelled as such, and the
    products with no public version-verdict API give a live-check procedure instead
    of a guessed version.
  - `hunt-electron` — Electron and Chromium-wrapper desktop apps treated as a web
    surface, because an XSS inside one reaches the OS. `webPreferences` audit with
    the per-version default table (`nodeIntegration` off since Electron 5,
    `contextIsolation` on since 12, `enableRemoteModule` removed in 14,
    `sandbox` on since 20), preload-bridge abuse, deep-link and protocol handlers,
    `asar` unpacking.
  - `hunt-browser-extension` — browser extensions: `manifest.json` permission review,
    content-script to background message handlers, `externally_connectable`, CRX
    fetch and unpack, web-accessible resources. Commands were run against a real
    extension in a throwaway directory during authoring, which caught three broken
    checks in the draft before they shipped.
- **Three new skills (83 → 86; `hunt-*` 58 → 61)**, each grounded in primary sources
  verified at authoring time:
  - `hunt-payment-api` — payment and billing API defects in the merchant's wrapper
    code and in what it accepts back from the PSP: webhook signature forgery and
    raw-body mismatch, amount/currency and minor-unit confusion, checkout
    state-machine abuse, idempotency and double-spend, refund/payout/ledger
    asymmetry. 9 cited GHSA advisories. Money-moving steps are sandbox-or-sign-off
    only, with an explicit velocity posture (card-testing looks like a BIN attack
    to the acquirer).
  - `hunt-xs-leaks` — cross-site leaks and XS-Search: frame counting, connection-pool
    and event-loop timing, cache probing, error events, navigation detection, with
    COOP/COEP/CORP, `SameSite` and Fetch Metadata as the defences. Confirmation
    requires a blinded interleaved A/B oracle (≥20 runs, ≥95% accuracy, plus a state
    flip) and a pinned browser build — a missing header is a hardening note, not a
    finding. Noisy channels carry per-channel cost, cadence and cleanup gates.
  - `hunt-exposed-services` — internet-exposed non-HTTP services and management
    interfaces across 7 reference families (databases, management interfaces,
    remote-debug, brokers, printers/storage, industrial/IoT, legacy/info-leak):
    IPMI/BMC, SNMP, JDWP, Java RMI, Elasticsearch, MQTT, RTSP, VNC, ADB, PJL/IPP,
    Modbus/BACnet and more. Triage layer routes an open port to one reference.
    `nmap -sC`/`-A` are banned (the `default` category contains scripts that cross
    the auth boundary or relay to third parties); ICS and camera work is
    detection-only. Scope ends at "unauthenticated access confirmed"; SMB, MSSQL,
    FTP, RDP and Kerberos stay out per `SECURITY.md`.

### Fixed
- **`lint_skills.py` safety scan only read `SKILL.md`** — the client-identifier
  denylist and secret regexes never saw `references/*.md`, which is where
  reference-heavy skills keep most of their prose (e.g. `offensive-osint`, and
  ~1,550 lines of the new `hunt-exposed-services`). A planted AWS key in a
  reference file passed CI. The scan now walks every `.md` in the skill directory,
  including nested ones; structure and frontmatter checks remain `SKILL.md`-only.
  A `-----BEGIN ... PRIVATE KEY-----` header with no base64 body after it is
  treated as a documented detection pattern, not a leak, so the secret-catalog
  skills do not false-positive. New `scripts/test_lint_skills.py` (7 cases) guards
  the behaviour and runs in the `skill-lint` workflow; it fails on the pre-fix code.
- **`cbh/data/skill_index.json` was stale** — listed 82 skills and 24 reports
  (missing `hunt-fintech-graphql`). Regenerated: 86 skills, 36 reports.
- **`scripts/install.ps1` skill count** said 82.
- **Disclosed-report grounding, content-verified** — 28 `hunt-*` skills strengthened
  with cited public HackerOne disclosures. **433 distinct disclosed reports** are now
  individually cited across **36 pattern-library files** in `docs/disclosed-reports/`.
  New personal-research pipeline under `research/reports/` (`harvest_h1.py` metadata
  collector, `classify_reports.py` class router, `verify_citations.py` credibility gate).
  Every citation is **content-verified**: `verify_citations.py` fetches each report's
  public subject and confirms it corroborates the skill it's cited under — **433 reports,
  0 mismatch, 0 weak**. `report_count` convention is now explicit: *distinct cited
  disclosed-report URLs* (grep-auditable), documented in
  `docs/disclosed-reports/README.md`. Two-tier grounding — `report_count` counts
  disclosed reports only; deeper web/API technique is cited under `sources:`
  (research / CVE). The `681` headline stays the pattern-count; `433` is the
  now-auditable cited-report count. Some counts reconciled **down** where a prior number
  was asserted without a backing corpus (e.g. `hunt-source-leak` 31→7) — honesty, not a
  coverage loss: **every SKILL.md methodology body is unchanged**, the delta is purely
  additive grounding. Targets genericized (technique kept, victim dropped); leak-guard clean.
- **Native Windows install ** — every `.sh` installer now has a PowerShell
  counterpart: `scripts/install.ps1`, `scripts/install-community-skills.ps1`, `scripts/hunt.ps1`.
  Same behavior, same flags (hyphen-style: `-All`, `-Agents`, `-Hermes`, `-BurpMcp`, `-NoProfile`,
  `-Uninstall`), same manifest-driven uninstall. `hunt.ps1` is dot-sourced from the PowerShell
  `$PROFILE` (the Windows equivalent of the `.zshrc`/`.bashrc` `source` line). `.gitattributes`
  now pins `*.ps1` to LF alongside `*.sh`/`*.py`. Docs (README, INSTALL, USAGE, multi-harness,
  SECURITY, index, credits) updated to show both paths. macOS/Linux unchanged.
- **Skill library expanded 71 → 82** — 9 new hunt skills (`hunt-jwt-crypto`, `hunt-rag-vector`,
  `hunt-shadow-api`, `hunt-captcha-bypass`, `hunt-clickjacking`, `hunt-html-injection`,
  `hunt-forgot-password`, `hunt-exceptional-conditions`, `ios-redteam-pipeline`) plus `hunt-spa-api`
  and `recon-scope-triage`; 11 existing skills expanded with verified technique content. Hunt
  sub-stack 48 → 57. `hunt-ai-attacks` folded into `hunt-llm-ai` (was a frontmatter-less duplicate).
- **Claude Code plugin marketplace** — `.claude-plugin/marketplace.json` + `.claude-plugin/plugin.json`
  make the bundle installable natively: `/plugin marketplace add elementalsouls/Claude-BugHunter`
  then `/plugin install claude-bughunter@elementalsouls`. Skills load namespaced under
  `claude-bughunter:` and update on version bump. The `scripts/install.sh` copy method stays as a
  fallback. This is the convention used by Anthropic's own marketplaces and Trail of Bits.
- **Multi-harness install** — the 82 Agent Skills now run on **OpenCode, OpenAI Codex CLI, and
  Hermes Agent**, not just Claude Code. `scripts/install.sh` gains `--agents` (→ `~/.agents/skills/`,
  read by Codex + OpenCode), `--hermes` (→ `~/.hermes/skills/`), `--all`, and `--burp-mcp` (translates
  the existing Burp MCP into each harness's config via `scripts/setup_harness_mcp.py`; OpenCode JSON +
  Codex TOML + Hermes YAML written). Verified end-to-end on OpenCode, Codex, and Hermes
  (skills load + live Burp MCP connects). Slash commands, the plugin marketplace, and `hunt-dispatch`
  remain Claude-Code-only. New guide: `docs/multi-harness.md`.

### Fixed
- `hunt-clickjacking`, `hunt-html-injection`: quoted the `description` — an unquoted `: ` (`Targets:`,
  `surfaces:`) broke strict YAML / Codex. Also genericized lab/harness-specific language in the new
  skills for cross-harness portability.
- `hunt-ntlm-info`: quoted the `description` — it contained an unquoted `` `WWW-Authenticate: NTLM` ``
  (`: ` makes strict YAML parsers read a nested mapping). Claude/OpenCode/Hermes tolerated it; **Codex
  rejected it**. Surfaced by real multi-harness testing.

### Changed
- **Four engagement-derived false-positive guards** — hardening in `hunt-dispatch`,
  `triage-validation`, `hunt-source-leak`, and `hunt-ssrf`, each closing a specific way the
  toolkit produced or nearly produced a wrong finding on a real authorized test.
  `hunt-dispatch` gains a mandatory **`step 0` 404 baseline for all modes** — record status +
  byte length + body hash per host from two bogus paths, and treat no path as "found" until its
  response differs from that control; SPA/CDN estates return HTTP 200 with the app shell for
  everything, so `security.txt`, revalidate routes and framework dev endpoints all appear to
  exist when they don't. Previously `step 1` was red-team only, leaving WAPT runs with no
  fingerprinting phase at all. `hunt-dispatch` also gains **`subagent scope inheritance`**:
  scope is not inherited implicitly, so delegated prompts must carry the authorized host list
  verbatim as data, treat mid-run discoveries as report-only, apply an action-verb deny-list
  **before** any read-shaped allow-list (a path ending `/status` can still be a refund route),
  and spell "read-only" out as forbidden verbs — as an adjective it does not stop an agent
  POSTing `{}` to a `generate*` endpoint and creating a real record. `triage-validation` gains
  **THE LAYER-ORDERING TRAP** after Q7: a validation error does *not* prove auth was passed,
  because a sanitiser or body parser ahead of the auth middleware yields an identical response
  shape — re-test with a minimal well-formed body, and read input-shape errors as a parser vs
  domain-field errors as business logic. `hunt-source-leak` Phase 2 now requires resolving the
  **current** build hash before testing and before re-verifying; content-hashed bundles rotate
  on deploy, so a 404 at a recorded `.map` URL is a new build, not remediation. `hunt-ssrf`
  gains per-parameter callback attribution (Burp keys interactions by payload ID, not subdomain,
  so sub-tagging one payload is not distinguishable — use a fresh payload per candidate
  parameter, and record the negative controls) plus a **blind vs full-read** check, since a
  returned upstream body is what moves a finding off the never-submit list.
  The 7-Question Gate and never-submit list are deliberately unchanged — both worked, and
  rejecting DNS-only SSRF is what forced the check that established full-read.
- **Dispatch dedup (description-scoping only — bodies unchanged)** — `hunt-jwt-crypto` set as the
  JWT-crypto owner (`hunt-ato`/`hunt-auth-bypass`/`hunt-api-misconfig` defer to it); `bb-local-toolkit`
  differentiated from `bug-bounty` (had a byte-identical description); scoped `hunt-sqli`↔`hunt-nosqli`,
  `hunt-auth-bypass`↔`hunt-saml`, `hunt-cache-poison`↔`hunt-host-header`,
  `report-writing`/`security-arsenal`↔`triage-validation`, and `hunt-spa-api`↔`hunt-source-leak`/`hunt-shadow-api`.
- Metrics synced to **82 skills** across README, banner, catalog (regenerated), INSTALL, USAGE, and
  docs (architecture/credits/index/multi-harness + capability-map/architecture-overview diagrams).
- `install.sh --agents` **auto-truncates** descriptions > 1024 chars to ≤1024 in the `~/.agents/skills`
  (Codex) copy only — Codex hard-rejects longer ones; `~/.claude`/`~/.hermes` keep full descriptions.
  Affects the 3 aggregator router skills.
- `scripts/lint_skills.py` hardened: adds a YAML-safety check (catches unquoted-value-with-`: `, the
  `hunt-ntlm-info` bug class) and notes Codex's 1024 limit in the over-length message.

## [2.1] - 2026-06-05

### Added
- **20 new `hunt-*` skills** (community v3 expansion, #7 — thanks @muhsiindeniiz):
  `hunt-lfi`, `hunt-nosqli`, `hunt-deserialization`, `hunt-cors`, `hunt-host-header`,
  `hunt-open-redirect`, `hunt-brute-force`, `hunt-session`, `hunt-ldap`, `hunt-nextjs`,
  `hunt-nodejs`, `hunt-dom`, `hunt-websocket`, `hunt-grpc`, `hunt-laravel`,
  `hunt-springboot`, `hunt-k8s`, `hunt-cicd`, `hunt-source-leak`, `hunt-tls-network`.
  **51 → 71 skills**, 28 → 48 hunt modules.
- **CI skill-linter** (`scripts/lint_skills.py` + `.github/workflows/skill-lint.yml`) —
  validates every `SKILL.md` (frontmatter, `name`, description/body length per
  `CONTRIBUTING.md`) and scans for leaked secrets + client/engagement identifiers via a
  SHA-256 denylist (plaintext names never enter the repo).
- **Community infrastructure** — issue templates (bug / new-skill proposal / false-positive),
  PR template, `CODEOWNERS`, `FUNDING.yml`, `CHANGELOG.md`.
- **Docs site** — GitHub Pages site under `docs/` (just-the-docs + search), an
  auto-generated searchable [skill catalog](docs/skills.md) (`scripts/gen_skill_catalog.py`),
  and a README Quickstart.
- **Sponsor** — Atlas Cloud (theme-adaptive logo in README + `FUNDING.yml`).
- `hunt-auth-bypass`: new **Function-Level Access Control (Broken Authorization)** section.
  `hunt-subdomain`: Azure App Service takeover fingerprint.

### Fixed (security — closes #13)
- **Path traversal** in `cbh recon` and **arbitrary file write** via `cbh report --out` —
  both now enforce real path containment (ancestry check, not a bypassable prefix match).
- **Shell injection** in the `hunt.sh` engagement scaffold (an unquoted heredoc expanded
  `$target`) — neutralized via quoted heredocs + `printf`.
- **Q5 gate logic** — a finding labeled "duplicate" no longer wrongly passes the novelty gate.
- **TLS** — loud warning when `--proxy` disables certificate verification.

### Changed
- Skill descriptions scoped so dedicated skills own dispatch (`hunt-cors`, `hunt-k8s`,
  `hunt-cicd`) — descriptions only, bodies untouched (#12).
- Metrics synced across README, banner, and catalog to 71 skills / 48 hunt modules. The
  disclosed-report count is held at the curated **681** (not inflated by the new skills'
  uncited `report_count` values).
- `.gitignore` excludes the maintainer-only plaintext denylist override
  (`scripts/.identifier-denylist.local`).

## [2.0] - 2026-05-25

### Added
- Report-curation pass: 574 → **681 disclosed-report patterns** across 24 vulnerability classes.
- 5 previously-missing attack surfaces covered; 0 zero-report skills remaining.
- 29 A-to-B chain examples and `ENGAGEMENTS.md` scaffolding.
- Enterprise platform attack matrices (M365/Entra, Okta, SharePoint, vCenter, SSL-VPN, APK, supply-chain).

### Changed
- Top-3 trigger-match concentration rebalanced (81.2% → 68.4%) for better skill routing.

## [1.x]

- Initial public release: 51 skills + 15 slash commands, vendored foundation from
  `shuvonsec/claude-bug-bounty`, Burp MCP integration, recon pipeline.

[Unreleased]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.1...HEAD
[2.1]: https://github.com/elementalsouls/Claude-BugHunter/compare/v2.0...v2.1
[2.0]: https://github.com/elementalsouls/Claude-BugHunter/releases/tag/v2.0

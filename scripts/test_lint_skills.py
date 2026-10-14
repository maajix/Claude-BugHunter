#!/usr/bin/env python3
"""Self-check for lint_skills.py's safety scan. Stdlib only, no network, no git.

Run: python3 scripts/test_lint_skills.py   (exit 0 = pass)

Builds throwaway skill dirs in a temp tree and asserts the behaviors that the
secret scan exists for. The reference-file cases are the ones that regressed
silently before: the scan used to read SKILL.md only, so a key pasted into
references/ was invisible to CI.
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

FRONTMATTER = """---
name: {name}
description: "A throwaway skill used by test_lint_skills.py to exercise the safety scan."
metadata:
  sources: test_fixture
  report_count: 0
---

Body.
"""

# A real-looking key: BEGIN header followed by base64 body.
REAL_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAwJz8kQm3nR7vY2pLx9FbTgHcV6sNdQ4uZaEoI1rXyBmCfKjWl\n"
    "-----END RSA PRIVATE KEY-----\n"
)
# The same header as a documented detection pattern: no key material follows.
DOCUMENTED_KEY = "Detection regex: `-----BEGIN RSA PRIVATE KEY-----`\n"
AWS_KEY = "AKIA0000000000000000\n"


def load_module():
    path = os.path.join(HERE, "lint_skills.py")
    spec = importlib.util.spec_from_file_location("lint_skills", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_skill(root, name, skill_md_extra="", references=None):
    """Create <root>/<name>/SKILL.md (+ references/) and return the skill dir."""
    skill_dir = os.path.join(root, name)
    os.makedirs(skill_dir, exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
        fh.write(FRONTMATTER.format(name=name) + skill_md_extra)
    for fn, text in (references or {}).items():
        ref_dir = os.path.join(skill_dir, "references")
        os.makedirs(ref_dir, exist_ok=True)
        with open(os.path.join(ref_dir, fn), "w", encoding="utf-8") as fh:
            fh.write(text)
    return skill_dir


def main():
    mod = load_module()
    failures = []

    def check(label, skill_dir, want_errors):
        errors, _warnings = mod.lint_skill(skill_dir, denylist=set())
        got = len(errors)
        ok = (got > 0) if want_errors else (got == 0)
        if not ok:
            failures.append(
                f"{label}: expected {'>=1' if want_errors else '0'} error(s), got {got}"
                + (f" -> {errors}" if errors else "")
            )
        return errors

    with tempfile.TemporaryDirectory() as root:
        # 1. Clean skill passes.
        check("clean skill", make_skill(root, "clean"), want_errors=False)

        # 2. Real key in SKILL.md is caught (pre-existing behavior, must not regress).
        check("key in SKILL.md", make_skill(root, "key-in-skill", skill_md_extra=REAL_KEY),
              want_errors=True)

        # 3. Real key in references/ is caught. This is the gap this test guards.
        check("key in references/",
              make_skill(root, "key-in-ref", references={"notes.md": REAL_KEY}),
              want_errors=True)

        # 4. AWS key in references/ is caught.
        check("aws key in references/",
              make_skill(root, "aws-in-ref", references={"notes.md": AWS_KEY}),
              want_errors=True)

        # 5. A documented BEGIN header with no key body is NOT a leak. The
        #    secret-catalog skills list it as a detection pattern.
        check("documented key header",
              make_skill(root, "documented", references={"patterns.md": DOCUMENTED_KEY}),
              want_errors=False)

        # 6. Denylist shingles are matched in references/ too.
        import hashlib
        banned = {hashlib.sha256(b"acme analytics").hexdigest()}
        skill_dir = make_skill(root, "denylist-ref",
                               references={"notes.md": "Tested for Acme Analytics in Q3.\n"})
        errors, _ = mod.lint_skill(skill_dir, denylist=banned)
        if not any("CLIENT-IDENTIFIER MATCH" in e for e in errors):
            failures.append(f"denylist in references/: expected a match, got {errors}")

        # 7. Nested markdown under references/ is reached as well.
        skill_dir = make_skill(root, "nested")
        nested = os.path.join(skill_dir, "references", "deep")
        os.makedirs(nested, exist_ok=True)
        with open(os.path.join(nested, "buried.md"), "w", encoding="utf-8") as fh:
            fh.write(REAL_KEY)
        check("key in nested references/", skill_dir, want_errors=True)

        # 8. A custom key at top level is rejected: it belongs under metadata:.
        skill_dir = make_skill(root, "top-level-key")
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write(FRONTMATTER.format(name="top-level-key").replace(
                "metadata:\n  sources: test_fixture\n  report_count: 0", "sources: test_fixture\nreport_count: 0"))
        check("top-level custom key", skill_dir, want_errors=True)

        # 9. report_count under metadata: must be an integer for hunt-* skills.
        skill_dir = make_skill(root, "hunt-bad-count")
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write(FRONTMATTER.format(name="hunt-bad-count").replace("report_count: 0", "report_count: many"))
        check("non-integer report_count", skill_dir, want_errors=True)

    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        print(f"\ntest_lint_skills: {len(failures)} failure(s).")
        return 1
    print("test_lint_skills: 9 case(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""check_dispatch_coverage.py — every installed hunt-* skill must be reachable
from the /hunt orchestrator.

`/hunt` loads skills from the hard-coded lists in skills/hunt-dispatch/SKILL.md
(commands/hunt.md invokes hunt-dispatch, which names the set it loads). Nothing
checked those lists against what is on disk, so ten skills sat installed and
unreachable: hunt-jwt-crypto, hunt-forgot-password, hunt-shadow-api,
hunt-spa-api, hunt-fintech-graphql, hunt-rag-vector, hunt-captcha-bypass,
hunt-html-injection, hunt-clickjacking, hunt-exceptional-conditions. The skills
linted clean and skill_map.py routed them, because neither looks at dispatch.

Exit 0 = every hunt-* skill is named in the dispatch file, 1 = at least one is
not. Stdlib only.

Usage:
    python3 scripts/check_dispatch_coverage.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
DISPATCH = os.path.join(SKILLS_DIR, "hunt-dispatch", "SKILL.md")

# hunt-dispatch is the router itself: it cannot load itself.
EXEMPT = {"hunt-dispatch"}

SKILL_REF_RE = re.compile(r"hunt-[a-z0-9-]+")


def installed_hunt_skills():
    return {
        d for d in os.listdir(SKILLS_DIR)
        if d.startswith("hunt-")
        and os.path.isfile(os.path.join(SKILLS_DIR, d, "SKILL.md"))
    }


def main():
    if not os.path.isfile(DISPATCH):
        print(f"ERROR missing {os.path.relpath(DISPATCH, REPO)}")
        return 1

    installed = installed_hunt_skills() - EXEMPT
    with open(DISPATCH, encoding="utf-8") as fh:
        referenced = set(SKILL_REF_RE.findall(fh.read()))

    missing = sorted(installed - referenced)
    # A name in the dispatch file with no skill on disk is just as broken: /hunt
    # would try to load a skill that is not there.
    stale = sorted(ref for ref in referenced - EXEMPT
                   if ref not in installed and ref.startswith("hunt-")
                   and not os.path.isdir(os.path.join(SKILLS_DIR, ref)))

    gha = os.environ.get("GITHUB_ACTIONS")
    for name in missing:
        msg = (f"{name} is installed but never named in skills/hunt-dispatch/SKILL.md "
               f"— /hunt cannot reach it. Add it to the mode's load list.")
        print(f"::error:: {msg}" if gha else f"ERROR {msg}")
    for name in stale:
        msg = (f"{name} is named in skills/hunt-dispatch/SKILL.md but no such skill "
               f"is installed — /hunt would try to load a missing skill.")
        print(f"::error:: {msg}" if gha else f"ERROR {msg}")

    print(f"\ndispatch coverage: {len(installed)} hunt-* skill(s) installed, "
          f"{len(installed) - len(missing)} reachable, {len(missing)} unreachable, "
          f"{len(stale)} stale reference(s).")
    return 1 if (missing or stale) else 0


if __name__ == "__main__":
    sys.exit(main())

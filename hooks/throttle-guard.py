#!/usr/bin/env python3
"""Keep engagement traffic inside the request budget and carrying its headers.

A PreToolUse guard for `Bash` and `WebFetch`. It is inert unless an engagement
config names a `rate_limit` or `headers`, so installing this plugin changes
nothing for anyone who is not running an engagement.

While an engagement IS active it refuses:

  * a network tool run outside `engine/throttle.py exec --`, because the budget
    is shared between processes and a tool that does not take from it cannot be
    held to the ceiling;
  * a command that unsets the proxy or engagement variables;
  * `WebFetch` against an in-scope host, because it cannot carry the required
    header and its requests are invisible to the budget.

The decision lives in `engine/throttle.py`, which has the self-test. This file
is only the plumbing: read the payload, ask, exit 0 or 2.

Exit codes follow the hook contract: 0 allows, 2 blocks and shows stderr.

What this is NOT: a sandbox. It reads one command string, so a script that opens
its own socket is outside what it can see. It stops an agent following the
skills from overrunning a limit by accident, which is the failure that actually
happens. `docs/rate-limiting.md` lists every gap by name.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(os.path.dirname(HERE), "engine")
sys.path.insert(0, ENGINE)


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0                     # not a payload this guard understands
    tool = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()

    import throttle

    if tool == "WebFetch":
        url = tool_input.get("url") or ""
        if not isinstance(url, str) or not url:
            return 0
        lim = throttle.Limits.discover(cwd)
        if lim is None or not lim.scope.in_scope_host(url):
            return 0                 # documentation and research are not traffic
        print(f"WebFetch cannot carry the engagement's required header(s) "
              f"({', '.join(lim.headers) or 'none set'}) and its requests do "
              f"not take from the shared budget "
              f"({lim.requests:g} req / {lim.period:g}s), so it must not be "
              f"used against an "
              f"in-scope host.\n"
              f"Use the wrapper instead:\n"
              f"    python3 engine/throttle.py exec -- curl -s {url}",
              file=sys.stderr)
        return 2

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return 0
    why = throttle.check_command(command, cwd)
    if why:
        print(f"bughunter throttle: {why}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:        # noqa: BLE001 - the decision is below
        # Fail closed inside an engagement, open outside one. A guard that
        # crashes must not be the quiet reason a ceiling stopped applying, but
        # it must also not break a session that never asked for one.
        # An engagement named in the environment counts as active even when
        # the module will not import or the path is wrong: both are the
        # operator's intent to be governed, not an absence of one.
        active = bool(os.environ.get("BUGHUNTER_ENGAGEMENT"))
        try:
            sys.path.insert(0, ENGINE)
            import throttle
            active = active or throttle.find_engagement(os.getcwd()) is not None
        except Exception:           # noqa: BLE001
            pass
        if active:
            print(f"bughunter throttle: the request-budget guard failed "
                  f"({exc}), so no limit can be proven for this command. "
                  f"Fix the guard or clear rate_limit/headers from the "
                  f"engagement config before continuing.", file=sys.stderr)
            sys.exit(2)
        print(f"bughunter throttle: skipped ({exc})", file=sys.stderr)
        sys.exit(0)

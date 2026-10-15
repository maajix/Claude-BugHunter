#!/usr/bin/env python3
"""
throttle.py — one request budget and one set of required headers, enforced in code.

Two engagement rules that an instruction cannot keep:

  * a request-per-second ceiling the whole engagement must stay under, and
  * a header every request to the target must carry (an Intigriti programme may
    require the researcher's bounty username, for example).

Asking a skill to respect a ceiling does not keep it. A ceiling only holds if the
counter lives outside the process that sends the traffic, because the traffic
comes from many processes: the agent's own `curl`, a background `nuclei`, four
parallel `xargs` children, `engine/recon.py`. So the budget lives in a state
file and every process takes from it under `fcntl.flock`.

Use it as a prefix:

    python3 engine/throttle.py exec -- curl -s https://api.target.example/v1/me
    python3 engine/throttle.py exec -- nuclei -u https://target.example -t cves/

`exec` does five things, in this order:

  1. Reads the engagement config (the same JSON `scope.py` reads).
  2. Works out every target in the argv, list files included.
  3. For a target that is IN SCOPE: waits for room in the shared window, then
     adds the required headers with the tool's own header flag, so they travel
     inside TLS and need no proxy or intercepting CA.
     The ceiling is a hard cap over every window, not an average, and releases
     are spaced evenly rather than let go in a burst. `Window` says why.
  4. For a fan-out tool (one invocation, many requests) it also clamps the tool's
     own rate flag to the ceiling and holds an exclusive lock for the whole run,
     so two scans cannot each run at the ceiling. The kernel drops that lock when
     the process exits or is killed, so nothing has to clean up after a crash.
  5. Replaces itself with the tool via `os.execvp`, so signals, exit codes, pipes
     and stdin all behave exactly as they did unwrapped.

A target that is NOT in scope passes straight through: no budget, no headers.
That is deliberate. Reading an NVD page or a GitHub advisory is not engagement
traffic, must not spend the target's budget, and must never be sent the bounty
username. Every pass-through is still written to the audit log and announced on
stderr, so a mistyped target is visible rather than silent.

What this does NOT do, stated plainly because the gap matters:

  * It governs the tools in TOOLS. A script that opens its own socket is not
    covered. `hooks/throttle-guard.py` denies an unknown network tool while an
    engagement is active, so the gap shows up as a refusal and not as a silent
    overrun, but a determined bypass is still a bypass. This is a guard against
    an agent overrunning a limit by accident, not a sandbox.
  * It only sees what runs as a process. Another harness driving the same target
    has its own budget.

    python3 engine/throttle.py --selftest
"""
import functools
import json
import math
import os
import re
import shlex
import sys
import time
from urllib.parse import urlparse

try:
    import fcntl
except ImportError:         # native Windows: no flock, so no shared budget
    fcntl = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scope import Scope  # noqa: E402  (same directory, deliberate)

STATE_NAME = ".throttle-state.json"
AUDIT_NAME = "throttle-audit.jsonl"
FANOUT_NAME = ".throttle-fanout.lock"
ENV_ENGAGEMENT = "BUGHUNTER_ENGAGEMENT"

# Flag names are verified against the installed tool, never guessed. Anything
# whose flags could not be checked on this machine is absent on purpose: an
# unverified flag that silently does nothing is worse than a refusal.
#
#   header   — the tool's own header flag, repeated once per header.
#   rate     — the tool's own requests-per-second flag, clamped to the ceiling.
#   fanout   — one invocation sends many requests, so a rate flag governs it and
#              it takes the exclusive lock instead of a per-request slot.
#   targets  — argv flags whose value is a target, or a file of targets.
TOOLS = {
    # curl 8.22.0: -H/--header, -g/--globoff, --url, -K/--config, -L/--location
    # (curl --help all). Its URLs are positional, and which options take an
    # operand is read from `curl --help all` at run time (`_curl_value_flags`).
    "curl": {
        "header": "-H", "rate": None, "fanout": False,
        "targets": {"value": ["--url"], "file": [], "positional": True},
    },
    # nuclei v3.11.1: -H/-header, -rl/-rate-limit (default 150, per second),
    # -rld/-rate-limit-duration (the period -rl counts over, default 1s),
    # -u/-target, -l/-list   (nuclei -h)
    "nuclei": {
        "header": "-H", "rate": "-rl", "rate_period": "-rld", "fanout": True,
        "targets": {"value": ["-u", "-target"], "file": ["-l", "-list"]},
        # every long spelling of a flag this file acts on, so an alias or an
        # `=value` form cannot sit beside the clamped flag and override it
        "aliases": {"-header": "-H", "-rate-limit": "-rl",
                    "-rate-limit-duration": "-rld"},
    },
}


def _normalize(spec, argv):
    """Rewrite aliases to their canonical flag and split `-flag=value`, so the
    rest of build_argv has exactly one spelling to find and replace."""
    aliases = spec.get("aliases", {})
    known = set(aliases) | set(aliases.values())
    out = argv[:1]
    for a in argv[1:]:
        key, eq, val = a.partition("=")
        # Only the flags this file acts on. Anything else, `-dfoo=http://x`
        # included, is an operand and must reach the tool untouched.
        if key in known:
            out += [aliases.get(key, key), val] if eq else [aliases.get(key, key)]
        else:
            out.append(a)
    return out

# Network tools this file cannot govern, because their header and rate flags
# were not verifiable on this machine. They are named anyway so that running one
# during an engagement is a visible refusal and not a silent overrun: a gap you
# can see is a gap somebody fixes. To govern one, verify its flags against the
# installed binary and move it into TOOLS.
UNGOVERNED = {
    "ffuf", "wfuzz", "gobuster", "feroxbuster", "dirsearch", "dirb",
    "katana", "hakrawler", "gospider", "crawley",
    "subfinder", "amass", "dnsx", "shuffledns", "puredns",
    "sqlmap", "ghauri", "dalfox", "xsstrike", "commix", "tplmap",
    "nikto", "wpscan", "joomscan", "droopescan", "nuclei-templates",
    "nmap", "masscan", "naabu", "rustscan", "zmap",
    "arjun", "paramspider", "kiterunner", "crlfuzz", "smuggler",
    "testssl.sh", "sslscan", "sslyze", "whatweb", "wafw00f",
    "gau", "waybackurls", "hakip2host", "httpx", "httprobe",
}

# Words that turn the wrapper off from inside the command it wraps.
BYPASS = re.compile(
    r"(?:^|[\s;&|(])(?:unset\s+(?:\w+\s+)*(?:HTTPS?_PROXY|https?_proxy)"
    r"|env\s+(?:-\w+\s+)*-u\s*(?:HTTPS?_PROXY|https?_proxy|%s)"
    r"|(?:NO_PROXY|no_proxy)=\*?"
    r"|--noproxy\b"
    r"|--proxy(?:=|\s+)(?:''|\"\")"
    r"|%s=)" % (ENV_ENGAGEMENT, ENV_ENGAGEMENT))

URLISH = re.compile(r"^(?:https?://|//)?[A-Za-z0-9._~-]+(?::\d+)?(?:/|$)")


class ThrottleError(Exception):
    """A refusal with a reason the caller is meant to read."""


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

def find_engagement(start=None):
    """Locate the engagement JSON: the env var first, then upwards from cwd.

    An env var that names a file which is not there is a refusal, not an
    absence: a typo in the path must not quietly remove the ceiling.
    """
    env = os.environ.get(ENV_ENGAGEMENT)
    if env:
        if not os.path.isfile(env):
            raise ThrottleError(f"{ENV_ENGAGEMENT}={env} is not a readable "
                                f"file, so no limit can be enforced")
        return env
    d = os.path.abspath(start or os.getcwd())
    while True:
        for name in ("engagement.json", "engagement/engagement.json"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


class Limits:
    """The engagement's ceiling, required headers and scope.

    `active` is False when the engagement names no ceiling and no headers. The
    whole mechanism stays out of the way until an engagement asks for it.
    """

    def __init__(self, path, data):
        self.path = path
        rl = data.get("rate_limit") or {}
        # Two spellings, because programmes use both. "max 5 requests per
        # second" and "max 100 requests per minute" are the same mechanism.
        if rl.get("requests") is not None:
            self.requests = float(rl.get("requests") or 0)
            self.period = float(rl.get("per_seconds") or 1)
        else:
            self.requests = float(rl.get("requests_per_second") or 0)
            self.period = 1.0
        if 0 < self.requests < 1:
            # "0.5 per second" is "1 per 2 seconds". Never round a maximum up.
            self.period /= self.requests
            self.requests = 1.0
        self.headers = dict(data.get("headers") or {})
        self.scope = Scope(data.get("in_scope", []), data.get("out_of_scope", []),
                           data.get("seeds", []), data.get("name", "engagement"))
        self.active = bool(self.requests > 0 or self.headers)

    @property
    def per_second(self):
        return self.requests / self.period

    @classmethod
    def load(cls, path):
        """Parse the engagement file. A file that will not parse is a refusal,
        never a silent allow: a typo in the ceiling must not remove it."""
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ThrottleError(f"{path} will not parse, so no limit can be "
                                f"enforced: {exc}")
        if not isinstance(data, dict):
            raise ThrottleError(f"{path} is not a JSON object")
        lim = cls(path, data)
        if lim.requests < 0 or lim.period <= 0:
            raise ThrottleError("rate_limit must be a positive number of "
                                "requests over a positive number of seconds")
        return lim

    @classmethod
    def discover(cls, start=None):
        """Return the active Limits, or None when no engagement asks for one."""
        path = find_engagement(start)
        if not path:
            return None
        lim = cls.load(path)
        return lim if lim.active else None

    @property
    def state_dir(self):
        return os.path.dirname(os.path.abspath(self.path)) or "."


# --------------------------------------------------------------------------- #
# the shared budget
# --------------------------------------------------------------------------- #

def _flock(fd, shared=False):
    """flock, or a refusal on a platform without it. Never a silent allow."""
    if fcntl is None:
        raise ThrottleError("the shared request budget needs fcntl.flock, "
                            "which this platform lacks. Run the engagement "
                            "from Linux, macOS or WSL.")
    fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)


def _funlock(fd):
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class Window:
    """A hard cap: never more than `limit` requests in any `period` seconds.

    A token bucket is the obvious thing to reach for here and it is the wrong
    shape. Refilling at N per second with a burst of N lets a one-second window
    hold up to 2N requests: drain the full burst at once, then earn another N
    over the second. `scripts/test_throttle_wire.py` measured exactly that — 9
    arrivals in one second against a stated ceiling of 5 — which is not what a
    programme means by "5 requests per second".

    So the state is the arrival times themselves. A request is admitted only
    while fewer than `limit` of them fall inside the last `period`, which makes
    the guarantee hold over every window and not just on average.

    The state file is shared by every process under flock. The read-modify-write
    happens inside the lock and the waiting happens outside it, so a process
    waiting for room never blocks one that is finishing.
    """

    # A ceiling is counted at the target's end, so what matters is arrivals, and
    # this code only controls releases. The gap between the two is process
    # start-up and network latency, and it varies: with four senders running at
    # once, a request released just inside one second can arrive just inside the
    # next, which put 6 arrivals in a window against a stated 5 when this was
    # measured. Two things close that gap. Releases are spaced evenly instead of
    # let go in a burst, so jitter has to exceed a whole slot to reorder
    # anything; and the spacing is computed over a slightly longer period than
    # the stated one, which keeps a measured window under the number the
    # programme wrote down. The cost is that a short run is a little slower than
    # the ceiling would strictly allow. For an engagement that is the right side
    # to err on.
    JITTER_MARGIN = 0.10

    def __init__(self, path, limit, period=1.0):
        self.path = path
        self.limit = max(1, int(limit))
        self.period = float(period)
        self.spacing = self.period * (1 + self.JITTER_MARGIN) / self.limit

    def _attempt(self, n):
        """Admit n arrivals, or return how long to wait. Runs under the lock."""
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _flock(fd)
            raw = os.read(fd, 1 << 20).decode("utf-8") or "[]"
            try:
                stamps = [float(x) for x in json.loads(raw)]
            except (ValueError, TypeError):
                stamps = []
            now = time.monotonic()
            # CLOCK_MONOTONIC is shared between processes on the same boot, so
            # these are comparable. A file left by an earlier boot can still
            # hold stamps from the future; drop those rather than wait on them.
            keep = self.period * (1 + self.JITTER_MARGIN)
            stamps = [s for s in stamps if now - keep < s <= now]
            room = self.limit - len(stamps)
            # Two conditions, both of which must hold: room inside the window,
            # and a whole slot since the previous release.
            gap = self.spacing * n - (now - max(stamps)) if stamps else 0.0
            if room >= n and gap <= 0:
                stamps.extend([now] * n)
                wait = 0.0
            elif room < n:
                # The (n - room)-th oldest stamp has to leave the window first.
                stamps.sort()
                wait = max(gap, stamps[n - room - 1] + keep - now)
            else:
                wait = gap
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps([round(s, 6) for s in stamps]).encode())
            return wait
        finally:
            _funlock(fd)
            os.close(fd)

    def take(self, n=1, on_wait=None):
        """Admit n requests, sleeping until there is room. Never refuses."""
        n = max(1, int(n))
        if n > self.limit:
            raise ThrottleError(
                f"one invocation would send {n} requests, over the whole "
                f"ceiling of {self.limit} per {self.period:g}s. Split it so no "
                f"single command needs more than the ceiling allows.")
        waited = 0.0
        while True:
            wait = self._attempt(n)
            if wait <= 0:
                return waited
            if on_wait and waited == 0:
                on_wait(wait)
            time.sleep(min(wait, self.period))
            waited += min(wait, self.period)


def hold_fanout_lock(path, shared=False):
    """Take the engagement's fan-out lock and keep it across execvp.

    A fan-out tool takes it exclusively: it runs at the whole ceiling on its
    own rate flag, so nothing else may send meanwhile. A single request takes
    it shared: many of them run side by side under the window, and a scanner
    waits for them to finish. That is what makes the two kinds of traffic one
    budget instead of two that each fill the ceiling.

    flock lives on the open file description, so the lock survives `execvp` as
    long as the descriptor is not close-on-exec. Python marks every descriptor
    close-on-exec by default, so that has to be cleared explicitly. The kernel
    releases the lock when the process exits or dies, which is why no PostToolUse
    hook is needed to clean up after a background scan.

    ponytail: flock is unfair, so a scanner can wait behind a steady stream of
    single requests; and the requests in flight when the lock changes hands
    overlap the next holder by one window at most. A fair queue if either bites.
    """
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.set_inheritable(fd, True)
    _flock(fd, shared)
    return fd


# --------------------------------------------------------------------------- #
# reading the command
# --------------------------------------------------------------------------- #

def _host_looks_real(token):
    if "://" in token:
        return bool(urlparse(token).hostname)
    return bool(URLISH.match(token)) and "." in token.split("/")[0]


@functools.lru_cache(maxsize=None)
def _curl_value_flags():
    """The curl options that take an operand, read from `curl --help all`.

    Asked of the binary in front of you rather than copied from a man page, so
    `-o index.html` is consumed as an operand and never read as a host. When
    curl cannot be asked the set is empty, and a stray operand is then refused
    as an out-of-scope host rather than let through.
    """
    import subprocess
    try:
        out = subprocess.run(["curl", "--help", "all"], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    flags = set()
    for m in re.finditer(r"^\s*(?:(-\w), )?(--[\w-]+) <", out, re.M):
        flags.update(f for f in m.groups() if f)
    return frozenset(flags)


def _curl_argv(argv):
    """(targets, flags) for a curl argv.

    Targets are the positional URLs and `--url` operands; every other option's
    operand is consumed so it is never read as a URL. `flags` holds each option
    seen, short letters split out of their cluster (`-sL` is `-s` and `-L`), so
    a caller can ask for `-L` or `-g` without re-reading the argv.
    """
    takes = _curl_value_flags()
    targets, flags, i = [], set(), 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a.startswith("--"):
            key, eq, inline = a.partition("=")
            flags.add(key)
            # `--data=` is an empty operand, not a missing one: the next word
            # is a URL, and it has to be read as one
            val = inline if eq else nxt
            if key == "--url" and val:
                targets.append(val)
            i += 2 if (key in takes or key == "--url") and not eq else 1
            continue
        if a.startswith("-") and len(a) > 1:
            for k, ch in enumerate(a[1:]):
                flags.add("-" + ch)
                if "-" + ch in takes:
                    # the operand is the rest of the cluster, or the next word
                    if k == len(a) - 2:
                        i += 1
                    break
            i += 1
            continue
        if _host_looks_real(a):
            targets.append(a)
        i += 1
    return targets, flags


def targets_in(tool, argv):
    """Every target this invocation will touch, list files included."""
    spec = TOOLS[tool]["targets"]
    if tool == "curl":
        targets, flags = _curl_argv(argv)
        if flags & {"-K", "--config"}:
            # A config file carries its own url, header and location lines,
            # so nothing on the command line says what will be sent.
            raise ThrottleError("curl -K/--config hides the request's URL and "
                                "options from the budget. Pass them on the "
                                "command line instead.")
        return targets
    found, i = [], 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        key, _, inline = a.partition("=")
        if key in spec["value"]:
            val = inline if inline else nxt
            if val:
                found.extend(v for v in val.split(",") if v.strip())
            i += 1 if inline else 2
            continue
        if key in spec["file"]:
            val = inline if inline else nxt
            if val and os.path.isfile(val):
                try:
                    with open(val, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                found.append(line.split()[0])
                except OSError as exc:
                    raise ThrottleError(f"cannot read target list {val}: {exc}")
            elif val:
                raise ThrottleError(f"target list {val} does not exist, so its "
                                    f"hosts cannot be scope-checked")
            i += 1 if inline else 2
            continue
        i += 1
    return found


def request_estimate(tool, argv, n_targets):
    """How many requests one invocation of a counted tool should be charged.

    Deliberately an over-estimate where it cannot be exact. Charging one too
    many slows the engagement; charging one too few breaks the ceiling.
    """
    if tool != "curl":
        return max(1, n_targets)
    targets, flags = _curl_argv(argv)
    globbed = any(re.search(r"[\[{].*[\]}]", t) for t in targets)
    if globbed and not flags & {"-g", "--globoff"}:
        # A range like [1-100] is one argument and up to a hundred requests. The
        # count is not knowable from the string, so refuse and let the operator
        # expand it into requests that can be counted.
        raise ThrottleError(
            "curl URL globbing hides the request count from the budget. "
            "Expand the range into a list file and loop over it, so each "
            "request is counted, or pass -g to disable globbing.")
    return max(1, n_targets)


def refuse_redirects(tool, argv):
    """Refuse curl -L for in-scope traffic.

    curl re-sends every -H header to wherever a redirect points, so the bounty
    username would follow a 302 off-host, and each hop is a request the budget
    never saw. The wrapper execs the tool, so it cannot judge hops itself.
    """
    if tool == "curl" and _curl_argv(argv)[1] & {"-L", "--location",
                                                 "--location-trusted"}:
        raise ThrottleError(
            "curl -L would carry the engagement headers to wherever the "
            "redirect points and send hops the budget cannot count. Drop -L, "
            "read Location from -i, and request the next hop through the "
            "wrapper so it is scope-checked and counted on its own.")


# --------------------------------------------------------------------------- #
# exec
# --------------------------------------------------------------------------- #

def audit(lim, record):
    try:
        with open(os.path.join(lim.state_dir, AUDIT_NAME), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass        # the audit trail must never be the reason a request fails


def gate(url, start=None):
    """Wait for room in the engagement window; return the headers to add.

    For our own code that sends HTTP directly instead of launching a tool, so
    `engine/recon.py` spends the same budget as the agent's `curl` rather than
    running beside it. Returns an empty dict when no engagement asks for a
    limit or the URL is out of scope, so a caller can always merge the result
    without checking.

    A broken engagement config raises, for the same reason the wrapper refuses
    one: a typo in the ceiling must not quietly remove the ceiling.
    """
    lim = Limits.discover(start)
    if lim is None or not lim.scope.in_scope_host(url):
        return {}
    waited = 0.0
    if lim.requests > 0:
        # Shared slot: wait out any scanner that holds the ceiling, then take
        # from the window every single request shares.
        fd = hold_fanout_lock(os.path.join(lim.state_dir, FANOUT_NAME),
                              shared=True)
        try:
            waited = Window(os.path.join(lim.state_dir, STATE_NAME),
                            lim.requests, lim.period).take(1)
        finally:
            _funlock(fd)
            os.close(fd)
    audit(lim, {"t": time.time(), "tool": "engine", "targets": [url],
                "in_scope": True, "waited_s": round(waited, 3),
                "fanout_lock": False, "headers": sorted(lim.headers)})
    return dict(lim.headers)


def tool_supports(binary, flag):
    """True when `binary -h` advertises `flag`.

    For a tool this file cannot carry a verified flag table for, because it is
    not installed on the machine the table was written on. Asking the binary in
    front of you beats assuming a convention: ProjectDiscovery's own tools do
    not all spell the rate flag the same way. A tool that cannot be asked
    answers False, so the caller leaves the flag off rather than passing one the
    tool will reject.
    """
    import subprocess
    try:
        r = subprocess.run([binary, "-h"], capture_output=True, text=True,
                           timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])",
                     r.stdout + r.stderr) is not None


def wrap(argv, start=None):
    """Prefix a tool argv with this wrapper when an engagement asks for a limit.

    For our own code that launches a tool, so `engine/recon.py` spends the same
    budget the agent's `curl` does. Unchanged when no engagement applies.
    """
    argv = list(argv)
    if Limits.discover(start) is None:
        return argv
    return [sys.executable, "-I", os.path.abspath(__file__), "exec", "--"] + argv


class fanout:
    """Hold the engagement's fan-out slot, and report its per-second ceiling.

    For a crawler or scanner our own code launches: one invocation sends many
    requests, so the tool's own rate flag is what governs it. `ceiling` is the
    number to clamp that flag to, or None when nothing applies.

        with fanout() as f:
            if f.ceiling:
                argv = clamp(argv, f.ceiling)
            subprocess.run(argv, ...)
    """

    def __init__(self, start=None):
        self._lim = Limits.discover(start)
        self._fd = None
        # Floored, never rounded up: a per-second flag cannot say "30 per
        # minute", so a ceiling under one per second is a refusal in __enter__.
        self.ceiling = (int(self._lim.per_second)
                        if self._lim and self._lim.requests > 0 else None)
        # The required headers, read without charging a request. A fan-out tool
        # adds them once with its own flag for a whole run, so calling gate()
        # here would spend a slot the run does not use.
        self.headers = dict(self._lim.headers) if self._lim else {}

    def in_scope(self, target):
        """Whether this target is in the engagement's scope."""
        return bool(self._lim) and self._lim.scope.in_scope_host(target)

    def __enter__(self):
        if self.ceiling == 0:
            raise ThrottleError(
                f"the ceiling of {self._lim.requests:g} per "
                f"{self._lim.period:g}s is under one request per second, "
                f"which a per-second rate flag cannot express. Use the "
                f"per-request path for this engagement.")
        if self.ceiling:
            self._fd = hold_fanout_lock(
                os.path.join(self._lim.state_dir, FANOUT_NAME))
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            _funlock(self._fd)
            os.close(self._fd)
            self._fd = None
        return False


def build_argv(lim, tool, argv, in_scope):
    """Insert the required headers and clamp the tool's own rate flag."""
    spec = TOOLS[tool]
    out = _normalize(spec, list(argv))
    if in_scope and lim.headers and spec["header"]:
        add = []
        for k, v in lim.headers.items():
            if any(a == spec["header"] and i + 1 < len(out)
                   and out[i + 1].lower().startswith(k.lower() + ":")
                   for i, a in enumerate(out)):
                continue        # the caller already set it; leave theirs alone
            add += [spec["header"], f"{k}: {v}"]
        out = out[:1] + add + out[1:]
    if in_scope and spec["fanout"] and spec["rate"] and lim.requests > 0:
        flag, period_flag = spec["rate"], spec.get("rate_period")
        # Strip every rate and period the caller passed, remembering the last
        # value of each (the tool's own last-wins rule), and emit exactly one
        # pair. A second `-rl 99` or a `-rld 100ms` left beside the clamped
        # flag would otherwise override it.
        kept, theirs, pending = [], {}, None
        for a in out:
            if pending:
                theirs[pending], pending = a, None
            elif a in (flag, period_flag):
                pending = a
            else:
                kept.append(a)
        if not period_flag:
            raise ThrottleError(
                f"{tool} has no verified interval flag, so its burst shape "
                f"cannot be held to the ceiling. Add one to TOOLS.")
        # One request per interval, never N per second. nuclei's own limiter
        # is a token bucket: `-rl 5` measured 10 arrivals in a sliding second
        # at the wire (a burst of 5, then 5 more at the refill). One per
        # interval has no burst, and the interval carries the same margin
        # Window uses, which measured 6 in a second without it. This also
        # says "30 per minute" exactly, as one per 2.2 s, with nothing
        # rounded up. The caller's own rate stays only when it is plainly
        # lower: a number under the ceiling with no period of its own.
        rate = lim.per_second
        if period_flag not in theirs:
            try:
                mine = float(theirs.get(flag, rate))
                if 0 < mine < rate:
                    rate = mine
            except ValueError:
                pass
        interval = math.ceil(1000 * (1 + Window.JITTER_MARGIN) / rate)
        out = kept[:1] + [flag, "1", period_flag, f"{interval}ms"] + kept[1:]
    return out


def do_exec(argv, start=None):
    if not argv:
        raise ThrottleError("nothing to run after --")
    tool = os.path.basename(argv[0])
    lim = Limits.discover(start)
    if lim is None:
        os.execvp(argv[0], argv)        # no engagement asks for a limit
    if tool not in TOOLS:
        raise ThrottleError(
            f"{tool} is not in throttle.py's TOOLS table, so its requests "
            f"cannot be counted and its headers cannot be set. Add it with a "
            f"header flag and a rate flag verified against the installed "
            f"binary, or run it outside the engagement.")

    targets = targets_in(tool, argv[1:])
    if not targets:
        raise ThrottleError(
            f"no target found in: {shlex.join(argv)}\n"
            f"A request that cannot be attributed to a host cannot be "
            f"scope-checked or budgeted. Pass the target explicitly.")

    scoped = [t for t in targets if lim.scope.in_scope_host(t)]
    outside = [t for t in targets if t not in scoped]
    in_scope = bool(scoped)
    if outside:
        print(f"throttle: {len(outside)} target(s) outside the engagement scope "
              f"pass through unbudgeted and without the required headers: "
              f"{', '.join(outside[:3])}" + ("…" if len(outside) > 3 else ""),
              file=sys.stderr)
    if scoped and outside:
        raise ThrottleError(
            "this invocation mixes in-scope and out-of-scope targets, so the "
            "budget and the headers cannot be applied to only part of it. "
            "Split it into one command per scope.")

    if in_scope:
        refuse_redirects(tool, argv[1:])
    final = build_argv(lim, tool, argv, in_scope)
    spec = TOOLS[tool]
    waited, held = 0.0, False
    if in_scope and lim.requests > 0:
        lock = os.path.join(lim.state_dir, FANOUT_NAME)
        if spec["fanout"]:
            hold_fanout_lock(lock)
            held = True
        else:
            # Held shared across the exec, so a scanner cannot start while
            # this request is in flight, and this waits while one runs.
            n = request_estimate(tool, argv[1:], len(scoped))
            hold_fanout_lock(lock, shared=True)
            waited = Window(os.path.join(lim.state_dir, STATE_NAME),
                            lim.requests, lim.period).take(n)

    audit(lim, {"t": time.time(), "tool": tool, "targets": targets,
                "in_scope": in_scope, "waited_s": round(waited, 3),
                "fanout_lock": held,
                "headers": sorted(lim.headers) if in_scope else []})
    os.execvp(final[0], final)


# --------------------------------------------------------------------------- #
# check (used by the PreToolUse hook)
# --------------------------------------------------------------------------- #

# Characters that end one command and start the next. shlex glues adjacent
# operators into a single token, so `);` arrives as one word: anything made
# only of these characters is a separator, not a membership test against a list
# of the combinations somebody thought of.
SEPARATOR_CHARS = set(";|&()<>\n")
# Shell keywords: skip them, the command is the next word.
KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "for", "in",
            "done", "fi", "esac", "case", "!", "time", "select"}
# Commands that run another command taken from their own argv. A tool name
# anywhere in such a segment is an invocation, wherever it sits among the
# flags, which is what makes `xargs -P 4 -I{} curl …` a curl invocation.
RUNNERS = {"env", "sudo", "doas", "nohup", "nice", "stdbuf", "timeout",
           "xargs", "command", "eval", "exec", "parallel", "watch", "setsid",
           "ionice", "chrt", "unbuffer", "script"}
# Flags whose value is a command string, so it is worth looking inside.
NESTED = {"-c", "--command"}


def _tokens(command):
    """Tokenize a shell command, keeping the operators that start a new command.

    Returns None when the string will not tokenize (an unbalanced quote, say), so
    the caller can fail closed rather than read a half-parsed command.
    """
    lx = shlex.shlex(command, posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        return list(lx)
    except ValueError:
        return None


def _is_separator(tok):
    return bool(tok) and all(ch in SEPARATOR_CHARS for ch in tok)


def _segments(toks):
    """Split a token list at the operators that start a new command."""
    seg, out = [], []
    for t in toks:
        if _is_separator(t):
            if seg:
                out.append(seg)
            seg = []
        else:
            seg.append(t)
    if seg:
        out.append(seg)
    return out


def _scan_segment(seg, depth=0):
    """Tool invocations in one segment, as (tool, wrapped) pairs.

    Three shapes have to be told apart, because only the first is a refusal:

      curl https://x            an invocation           -> (curl, False)
      throttle.py exec -- curl  a wrapped invocation    -> (curl, True)
      grep curl notes.md        the name as an argument -> nothing
    """
    out, i, n = [], 0, len(seg)
    # The command is the first word that is not a keyword, a flag or VAR=value.
    while i < n:
        t = seg[i]
        base = os.path.basename(t)
        if base in KEYWORDS:
            i += 1
            continue
        if t.startswith("-") or re.match(r"^\w+=", t):
            i += 1
            continue
        break
    if i >= n:
        return out
    head = os.path.basename(seg[i])

    # the wrapper: <python> <path/throttle.py> exec [--] <the real command>
    if head == "throttle.py" and i + 1 < n and seg[i + 1] == "exec":
        j = i + 2
        if j < n and seg[j] == "--":
            j += 1
        if j < n:
            out.append((os.path.basename(seg[j]), True))
        return out
    if head.startswith("python") or head in ("py", "python3"):
        # `python3 engine/throttle.py exec -- curl …` and nothing else about
        # python is interesting here.
        return _scan_segment(seg[i + 1:], depth) if i + 1 < n else out

    rest = seg[i + 1:]
    if head in RUNNERS:
        # It runs something from its own argv, so look at every word of it.
        for k, t in enumerate(rest):
            b = os.path.basename(t)
            if b == "throttle.py" and rest[k + 1:k + 2] == ["exec"]:
                return out + _scan_segment(rest[k:], depth)
            if b in TOOLS or b in UNGOVERNED:
                out.append((b, False))
        return out
    # Every head is reported, not only a known tool, so the caller can tell a
    # governed tool from one it cannot govern from an ordinary command.
    out.append((head, False))

    # `bash -c "curl …"`, one level down only.
    if depth < 1:
        for k, t in enumerate(rest):
            if t in NESTED and k + 1 < len(rest):
                inner = invocations(rest[k + 1], depth + 1)
                if inner:
                    out.extend(inner)
    return out


def invocations(command, depth=0):
    """Every tool invocation in a shell command, as (tool, wrapped) pairs.

    Returns None when the string will not tokenize, so the caller can fail
    closed rather than read a half-parsed command.
    """
    toks = _tokens(command)
    if toks is None:
        return None
    out = []
    for seg in _segments(toks):
        out.extend(_scan_segment(seg, depth))
    return out


def check_command(command, start=None):
    """Return a refusal string for a shell command, or None to allow it.

    Called from the hook, so it must be fast and must never block.
    """
    lim = Limits.discover(start)
    if lim is None:
        return None
    if BYPASS.search(command):
        return ("This command turns off the engagement's request budget or its "
                "required headers. Both are set in "
                f"{os.path.basename(lim.path)} and are not optional while the "
                "engagement is active.")
    found = invocations(command)
    if found is None:
        # An unparseable command is not evidence of innocence. Refuse only when
        # a tool name appears in it at all, so ordinary quoting errors still
        # reach the shell and report themselves.
        if any(re.search(r"\b" + re.escape(t) + r"\b", command) for t in TOOLS):
            return ("This command does not tokenize, so it cannot be checked "
                    "against the engagement's request budget. Rewrite it as a "
                    "single tool invocation through "
                    "`python3 engine/throttle.py exec -- …`.")
        return None
    ungoverned = sorted({tool for tool, wrapped in found
                         if tool in UNGOVERNED})
    if ungoverned:
        return (f"{', '.join(ungoverned)} sends requests that "
                f"engine/throttle.py cannot count, because its header and rate "
                f"flags are not in the TOOLS table. While an engagement names a "
                f"ceiling, running it would leave the ceiling unproven.\n"
                f"Either add it to TOOLS with a header flag and a rate flag "
                f"checked against the installed binary, or run it in a session "
                f"with no engagement config.")
    problems = sorted({tool for tool, wrapped in found
                       if tool in TOOLS and not wrapped})
    if not problems:
        return None
    ceiling = (f"{lim.requests:g} req / {lim.period:g}s" if lim.requests
               else "no ceiling")
    hdrs = ", ".join(lim.headers) or "none"
    return (f"{', '.join(sorted(problems))} would send engagement traffic "
            f"outside the shared request budget ({ceiling}) and without the "
            f"required header(s) ({hdrs}).\n"
            f"Run it through the wrapper instead:\n"
            f"    python3 engine/throttle.py exec -- <the same command>\n"
            f"The wrapper counts the requests against a budget every process "
            f"shares, adds the headers with the tool's own flag, and leaves "
            f"out-of-scope hosts alone.")


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

def _selftest():
    import subprocess
    import tempfile

    here = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as d:
        eng = os.path.join(d, "engagement.json")
        with open(eng, "w", encoding="utf-8") as fh:
            json.dump({"name": "t", "in_scope": ["target.example"],
                       "out_of_scope": ["admin.target.example"],
                       "rate_limit": {"requests_per_second": 5},
                       "headers": {"X-Bug-Bounty": "tester"}}, fh)
        lim = Limits.load(eng)
        assert lim.active and lim.requests == 5 and lim.period == 1.0
        assert lim.headers == {"X-Bug-Bounty": "tester"}
        # the per-minute spelling programmes actually use
        perm = os.path.join(d, "perminute.json")
        with open(perm, "w", encoding="utf-8") as fh:
            json.dump({"in_scope": ["x.example"],
                       "rate_limit": {"requests": 100, "per_seconds": 60}}, fh)
        pl = Limits.load(perm)
        assert pl.requests == 100 and pl.period == 60 and pl.active
        # a ceiling under one per second keeps its pacing, never rounded up
        slow = os.path.join(d, "slow.json")
        with open(slow, "w", encoding="utf-8") as fh:
            json.dump({"in_scope": ["target.example"],
                       "rate_limit": {"requests": 30, "per_seconds": 60}}, fh)
        sl = Limits.load(slow)
        assert sl.per_second == 0.5
        half = os.path.join(d, "half.json")
        with open(half, "w", encoding="utf-8") as fh:
            json.dump({"in_scope": ["x.example"],
                       "rate_limit": {"requests_per_second": 0.5}}, fh)
        hl = Limits.load(half)
        assert hl.requests == 1 and hl.period == 2, (hl.requests, hl.period)
        s = build_argv(sl, "nuclei", ["nuclei", "-rl", "150", "-u",
                                       "https://target.example"], True)
        assert s[s.index("-rl") + 1] == "1" and s[s.index("-rld") + 1] == "2200ms", s
        assert s.count("-rl") == 1, s
        # an alias or =value form beside the clamped flag cannot override it
        s2 = build_argv(sl, "nuclei", ["nuclei", "-rl", "1", "-rate-limit-duration",
                                        "2s", "-rate-limit=99", "-u",
                                        "https://target.example"], True)
        assert s2[1:5] == ["-rl", "1", "-rld", "2200ms"], s2
        assert "-rate-limit-duration" not in s2 and "2s" not in s2 and "99" not in s2, s2
        n4 = build_argv(lim, "nuclei", ["nuclei", "-rate-limit=150", "-u",
                                        "https://target.example"], True)
        five = ["-rl", "1", "-rld", "220ms"]      # 5/s as one per 220 ms
        assert n4[1:5] == five and "-rate-limit=150" not in n4, n4
        # a second rate, or a period beside the rate, cannot slip past at 5/s
        n5 = build_argv(lim, "nuclei", ["nuclei", "-rl", "1", "-rl", "99", "-u",
                                        "https://target.example"], True)
        assert n5.count("-rl") == 1 and n5[1:5] == five, n5
        n6 = build_argv(lim, "nuclei", ["nuclei", "-rl", "5", "-rld", "100ms",
                                        "-u", "https://target.example"], True)
        assert n6.count("-rl") == 1 and n6.count("-rld") == 1 and "100ms" not in n6, n6
        assert n6[1:5] == five, n6
        # curl operands are never split on `=`: `-dfoo=http://x` is data
        c2 = build_argv(lim, "curl", ["curl", "-dfoo=http://outside.example/",
                                      "https://target.example/"], True)
        assert "-dfoo=http://outside.example/" in c2 and \
            "http://outside.example/" not in c2, c2
        try:
            with fanout(d):
                pass
            # 5/s in d/engagement.json is expressible; the slow one is not
            os.environ[ENV_ENGAGEMENT] = slow
            try:
                with fanout():
                    assert False, "0.5 req/s must refuse a per-second flag"
            except ThrottleError:
                pass
        finally:
            os.environ.pop(ENV_ENGAGEMENT, None)

        # an env var naming a missing file is a refusal, not an absence
        os.environ[ENV_ENGAGEMENT] = os.path.join(d, "typo.json")
        try:
            find_engagement(d)
            assert False, "a missing explicit engagement must refuse"
        except ThrottleError:
            pass
        finally:
            os.environ.pop(ENV_ENGAGEMENT, None)

        # inert when the engagement asks for nothing
        off = os.path.join(d, "off.json")
        with open(off, "w", encoding="utf-8") as fh:
            json.dump({"in_scope": ["x.example"]}, fh)
        assert Limits.load(off).active is False
        assert Limits.discover(d) is not None

        # a config that will not parse refuses; it never silently allows
        bad = os.path.join(d, "bad.json")
        open(bad, "w").write("{nope")
        try:
            Limits.load(bad)
            assert False, "a broken config must refuse"
        except ThrottleError:
            pass

        # headers go to in-scope targets only
        a = build_argv(lim, "curl", ["curl", "-s", "https://target.example/"], True)
        assert "-H" in a and "X-Bug-Bounty: tester" in a, a
        b = build_argv(lim, "curl", ["curl", "-s", "https://nvd.nist.gov/"], False)
        assert "X-Bug-Bounty: tester" not in b, b
        # a header the caller already set is left alone
        c = build_argv(lim, "curl", ["curl", "-H", "X-Bug-Bounty: other",
                                     "https://target.example/"], True)
        assert c.count("-H") == 1 and "X-Bug-Bounty: other" in c, c

        # the rate flag is clamped down, added when absent, left when lower
        n = build_argv(lim, "nuclei", ["nuclei", "-u", "https://target.example"], True)
        assert n[1:5] == five, n
        n2 = build_argv(lim, "nuclei", ["nuclei", "-rl", "150", "-u",
                                        "https://target.example"], True)
        assert n2[1:5] == five and "150" not in n2, n2
        n3 = build_argv(lim, "nuclei", ["nuclei", "-rl", "2", "-u",
                                        "https://target.example"], True)
        assert n3[1:5] == ["-rl", "1", "-rld", "550ms"], n3

        # targets are read out of argv and out of a list file
        lst = os.path.join(d, "hosts.txt")
        open(lst, "w").write("# comment\nhttps://a.target.example\nb.target.example\n")
        assert targets_in("nuclei", ["-l", lst]) == ["https://a.target.example",
                                                     "b.target.example"]
        assert targets_in("nuclei", ["-u", "a.example,b.example"]) == ["a.example",
                                                                      "b.example"]
        assert targets_in("curl", ["-s", "https://target.example/x"]) == \
            ["https://target.example/x"]
        assert targets_in("curl", ["-s", "-H", "A: b"]) == []
        # an operand is consumed, not read as a host: -o file, -sSo file,
        # -XPOST, -d json, --output=file, --url
        if _curl_value_flags():
            assert targets_in("curl", ["https://target.example/", "-o",
                                       "index.html"]) == ["https://target.example/"]
            assert targets_in("curl", ["-sSo", "index.html", "-XPOST", "-d",
                                       "a.b", "--output=x.html", "--url",
                                       "https://target.example/"]) == \
                ["https://target.example/"]
        # an empty inline operand does not swallow the URL after it
        assert targets_in("curl", ["--data=", "https://outside.example",
                                   "https://target.example"]) == \
            ["https://outside.example", "https://target.example"]
        try:
            targets_in("curl", ["-K", "curlrc", "https://target.example/"])
            assert False, "curl -K must refuse"
        except ThrottleError:
            pass
        # a list file that is not there must refuse, not scan unchecked
        try:
            targets_in("nuclei", ["-l", os.path.join(d, "nope.txt")])
            assert False, "a missing target list must refuse"
        except ThrottleError:
            pass

        # curl request estimate: globbing is judged on the URLs, not on -d
        assert request_estimate("curl", ["-s", "https://t.example/"], 1) == 1
        assert request_estimate("curl", ["-d", '{"a":[1]}',
                                         "https://t.example/"], 1) == 1
        try:
            request_estimate("curl", ["https://t.example/[1-100]"], 1)
            assert False, "URL globbing must refuse"
        except ThrottleError:
            pass
        assert request_estimate("curl", ["-g", "https://t.example/[1-100]"], 1) == 1
        assert request_estimate("curl", ["-sg", "https://t.example/[1-100]"], 1) == 1
        # -L would carry the header off-host and hide the hop count
        for bad in (["-L", "https://t.example/"], ["-sL", "https://t.example/"],
                    ["--location", "https://t.example/"]):
            try:
                refuse_redirects("curl", bad)
                assert False, bad
            except ThrottleError:
                pass
        refuse_redirects("curl", ["-s", "-H", "L: x", "https://t.example/"])

        # the budget is shared across processes, and it holds
        st = os.path.join(d, "shared.json")
        prog = ("import sys,json;sys.path.insert(0,%r);"
                "import throttle;"
                "b=throttle.Window(%r,5);"
                "print(json.dumps([b.take(1) for _ in range(4)]))" % (here, st))
        t0 = time.monotonic()
        procs = [subprocess.Popen([sys.executable, "-I", "-c", prog],
                                  stdout=subprocess.PIPE, text=True)
                 for _ in range(3)]
        for p in procs:
            p.wait()
        span = time.monotonic() - t0
        # 12 requests at a hard 5 per second: 5 now, 5 after a second, 2 after
        # two, so it cannot finish inside 2 s.
        assert span >= 1.9, f"12 requests at 5 req/s finished in {span:.2f}s"
        assert all(p.returncode == 0 for p in procs)
        # and the window itself never holds more than the cap
        w = Window(os.path.join(d, "hard.json"), 3)
        t1 = time.monotonic()
        for _ in range(7):
            w.take(1)
        assert time.monotonic() - t1 >= 1.9, "a hard cap of 3/s let 7 through fast"
        # an invocation bigger than the whole ceiling refuses rather than
        # quietly breaking it
        try:
            Window(os.path.join(d, "big.json"), 3).take(4)
            assert False, "a request burst over the ceiling must refuse"
        except ThrottleError:
            pass

        # the fan-out lock survives execvp, which is what makes it hold for a
        # background scan with no PostToolUse hook to clean up
        lk = os.path.join(d, "fan.lock")
        child = ("import sys,os,fcntl,time;sys.path.insert(0,%r);"
                 "import throttle;throttle.hold_fanout_lock(%r);"
                 "os.execvp('sleep',['sleep','1.5'])" % (here, lk))
        p = subprocess.Popen([sys.executable, "-I", "-c", child])
        time.sleep(0.6)
        fd = os.open(lk, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            got = True
        except OSError:
            got = False
        finally:
            os.close(fd)
        assert not got, "the fan-out lock did not survive execvp"
        # and a single request waits for the scanner, so the two share one
        # ceiling instead of each filling it
        t2 = time.monotonic()
        sfd = hold_fanout_lock(lk, shared=True)
        assert time.monotonic() - t2 >= 0.5, "a request ran beside a scanner"
        _funlock(sfd)
        os.close(sfd)
        p.wait()

        # the hook's check
        cwd = d
        assert check_command("ls -la", cwd) is None
        assert check_command("curl https://target.example/", cwd)
        assert check_command("echo hi | curl -d @- https://target.example/", cwd)
        assert check_command("python3 engine/throttle.py exec -- curl "
                             "https://target.example/", cwd) is None
        assert check_command("/usr/bin/curl https://target.example/", cwd)
        assert check_command("unset HTTPS_PROXY", cwd)
        assert check_command("curl --noproxy '*' https://target.example/", cwd)
        assert check_command("env -u BUGHUNTER_ENGAGEMENT curl https://t.example/",
                             cwd)
        # a word that merely contains a tool name is not that tool
        assert check_command("echo curlicue", cwd) is None
        assert check_command("ls nuclei-templates/", cwd) is None
        # the tool name as data, not as a command
        for ok in ("grep curl notes.md",
                   "echo 'curl is a tool'",
                   "awk '/curl/{print}' f",
                   "rg -n nuclei skills/",
                   "ls -la nuclei-templates/http/"):
            assert check_command(ok, cwd) is None, ok
        # every shape that really runs the tool, however it is dressed up.
        # Each of these was a false negative at some point while this was
        # written, which is why they are all here and not just the first.
        for bad in ("curl https://target.example/",
                    "for h in $(cat hosts); do curl -s \"$h\"; done",
                    "while read h; do curl -s \"$h\"; done < hosts",
                    "cat hosts | xargs -P8 curl -s",
                    "xargs -P 4 -I{} curl -s {}",
                    "bash -c \"curl -s https://target.example/\"",
                    "if curl -s https://target.example/; then echo ok; fi",
                    "timeout 30 nuclei -u https://target.example",
                    "nohup nuclei -u https://target.example &",
                    "env FOO=1 curl https://target.example/",
                    "(cd /tmp && curl https://target.example/)",
                    "./curl https://target.example/",
                    "nuclei -u https://target.example & curl https://t.example"):
            assert check_command(bad, cwd), bad
        # a network tool that cannot be governed is refused, not ignored
        for bad in ("ffuf -w w.txt -u https://target.example/FUZZ",
                    "nmap -sV target.example",
                    "sqlmap -u https://target.example/?id=1",
                    "subfinder -d target.example"):
            why = check_command(bad, cwd)
            assert why and "TOOLS table" in why, bad
        # and it is still only a word when it is data
        assert check_command("ls nmap-scripts/", cwd) is None
        assert check_command("grep ffuf notes.md", cwd) is None

        # wrapped, however it is dressed up
        for ok in ("python3 engine/throttle.py exec -- curl -s https://target.example/",
                   "cat hosts | xargs -P8 python3 engine/throttle.py exec -- curl -s",
                   "python3 /abs/engine/throttle.py exec curl https://target.example/",
                   "timeout 60 python3 engine/throttle.py exec -- nuclei -u https://t.example"):
            assert check_command(ok, cwd) is None, ok
        # inert where no engagement asks for a limit
        with tempfile.TemporaryDirectory() as empty:
            assert check_command("curl https://anything.example/", empty) is None

        # the hook itself, as Claude Code runs it: WebFetch in scope is a
        # refusal that names the ceiling; out of scope passes; a typo in
        # BUGHUNTER_ENGAGEMENT fails closed
        hook = os.path.join(os.path.dirname(here), "hooks", "throttle-guard.py")
        env = {k: v for k, v in os.environ.items() if k != ENV_ENGAGEMENT}

        def run_hook(payload, **extra):
            return subprocess.run([sys.executable, "-I", hook],
                                  input=json.dumps(payload), capture_output=True,
                                  text=True, env={**env, **extra})
        r = run_hook({"tool_name": "WebFetch", "cwd": d,
                      "tool_input": {"url": "https://target.example/x"}})
        assert r.returncode == 2 and "5 req / 1s" in r.stderr, r
        r = run_hook({"tool_name": "WebFetch", "cwd": d,
                      "tool_input": {"url": "https://nvd.nist.gov/"}})
        assert r.returncode == 0, r
        r = run_hook({"tool_name": "Bash", "cwd": d,
                      "tool_input": {"command": "curl https://target.example/"}},
                     **{ENV_ENGAGEMENT: os.path.join(d, "typo.json")})
        assert r.returncode == 2 and "not a readable file" in r.stderr, r

    print("throttle.py self-test: PASS")


def _main(argv=None):
    import argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "exec":
        rest = argv[1:]
        if rest and rest[0] == "--":
            rest = rest[1:]
        do_exec(rest)
        return 0

    ap = argparse.ArgumentParser(
        prog="throttle.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("exec", help="run a network tool under the engagement budget")
    c = sub.add_parser("check", help="judge a shell command the way the hook does")
    c.add_argument("command")
    sub.add_parser("show", help="print the active limits and remaining budget")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0
    if args.cmd == "check":
        why = check_command(args.command)
        if why:
            print(why)
            return 2
        print("allowed")
        return 0
    if args.cmd == "show":
        lim = Limits.discover()
        if lim is None:
            print("No engagement names a rate_limit or headers; throttle is inert.")
            return 0
        print(f"engagement: {lim.path}")
        print(f"ceiling:    {lim.requests:g} request(s) per {lim.period:g}s "
              f"(a hard cap over every window, not an average)")
        print(f"headers:    {lim.headers or 'none'}")
        print(f"in scope:   {', '.join(lim.scope.in_scope) or 'none'}")
        st = os.path.join(lim.state_dir, STATE_NAME)
        if os.path.isfile(st):
            with open(st, encoding="utf-8") as fh:
                try:
                    live = len(json.load(fh))
                except ValueError:
                    live = "?"
            print(f"in flight:  {live} request(s) still inside the window")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except ThrottleError as exc:
        print(f"throttle: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)

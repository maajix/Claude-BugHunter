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
import fcntl
import json
import os
import re
import shlex
import sys
import time
from urllib.parse import urlparse

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
    # curl 8.5.0: -H/--header, --rate, -g/--globoff, --url   (curl --help all)
    "curl": {
        "header": "-H", "rate": None, "fanout": False,
        "targets": {"value": ["--url"], "file": ["-K", "--config"]},
    },
    # nuclei v3.8.0: -H/-header, -rl/-rate-limit (default 150), -u/-target,
    # -l/-list   (nuclei -h)
    "nuclei": {
        "header": "-H", "rate": "-rl", "fanout": True,
        "targets": {"value": ["-u", "-target"], "file": ["-l", "-list"]},
    },
}

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
    """Locate the engagement JSON: the env var first, then upwards from cwd."""
    env = os.environ.get(ENV_ENGAGEMENT)
    if env:
        return env if os.path.isfile(env) else None
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
        self.headers = dict(data.get("headers") or {})
        self.scope = Scope(data.get("in_scope", []), data.get("out_of_scope", []),
                           data.get("seeds", []), data.get("name", "engagement"))
        self.active = bool(self.requests > 0 or self.headers)

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
            fcntl.flock(fd, fcntl.LOCK_EX)
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
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def take(self, n=1, on_wait=None):
        """Admit n requests, sleeping until there is room. Never refuses."""
        n = max(1, int(n))
        if n > self.limit:
            raise ThrottleError(
                f"one invocation would send {n} requests, over the whole "
                f"ceiling of {self.limit} per second. Split it so no single "
                f"command needs more than the ceiling allows.")
        waited = 0.0
        while True:
            wait = self._attempt(n)
            if wait <= 0:
                return waited
            if on_wait and waited == 0:
                on_wait(wait)
            time.sleep(min(wait, self.period))
            waited += min(wait, self.period)


def hold_fanout_lock(path):
    """Take the engagement's exclusive fan-out lock and keep it across execvp.

    flock lives on the open file description, so the lock survives `execvp` as
    long as the descriptor is not close-on-exec. Python marks every descriptor
    close-on-exec by default, so that has to be cleared explicitly. The kernel
    releases the lock when the process exits or dies, which is why no PostToolUse
    hook is needed to clean up after a background scan.
    """
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.set_inheritable(fd, True)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


# --------------------------------------------------------------------------- #
# reading the command
# --------------------------------------------------------------------------- #

def _host_looks_real(token):
    if "://" in token:
        return bool(urlparse(token).hostname)
    return bool(URLISH.match(token)) and "." in token.split("/")[0]


def targets_in(tool, argv):
    """Every target this invocation will touch, list files included."""
    spec = TOOLS[tool]["targets"]
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
        if not a.startswith("-") and _host_looks_real(a):
            found.append(a)
        i += 1
    return found


def request_estimate(tool, argv, n_targets):
    """How many requests one invocation of a counted tool should be charged.

    Deliberately an over-estimate where it cannot be exact. Charging one too
    many slows the engagement; charging one too few breaks the ceiling.
    """
    if tool != "curl":
        return max(1, n_targets)
    n = max(1, n_targets)
    globbed = any(not a.startswith("-") and re.search(r"[\[{].*[\]}]", a)
                  for a in argv)
    if globbed and not any(a in ("-g", "--globoff") for a in argv):
        # A range like [1-100] is one argument and up to a hundred requests. The
        # count is not knowable from the string, so refuse and let the operator
        # expand it into requests that can be counted.
        raise ThrottleError(
            "curl URL globbing hides the request count from the budget. "
            "Expand the range into a list file and loop over it, so each "
            "request is counted, or pass -g to disable globbing.")
    if any(a in ("-L", "--location") for a in argv):
        n += 1          # a redirect chain is at least one more request
    return n


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
        waited = Window(os.path.join(lim.state_dir, STATE_NAME),
                        lim.requests, lim.period).take(1)
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
        self.ceiling = (max(1, int(self._lim.requests / self._lim.period))
                        if self._lim and self._lim.requests > 0 else None)
        # The required headers, read without charging a request. A fan-out tool
        # adds them once with its own flag for a whole run, so calling gate()
        # here would spend a slot the run does not use.
        self.headers = dict(self._lim.headers) if self._lim else {}

    def in_scope(self, target):
        """Whether this target is in the engagement's scope."""
        return bool(self._lim) and self._lim.scope.in_scope_host(target)

    def __enter__(self):
        if self.ceiling:
            self._fd = hold_fanout_lock(
                os.path.join(self._lim.state_dir, FANOUT_NAME))
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None
        return False


def build_argv(lim, tool, argv, in_scope):
    """Insert the required headers and clamp the tool's own rate flag."""
    spec = TOOLS[tool]
    out = list(argv)
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
        # The tool's own flag is per second, so convert.
        ceiling = max(1, int(lim.requests / lim.period))
        flag = spec["rate"]
        for i, a in enumerate(out):
            if a == flag and i + 1 < len(out):
                try:
                    if int(out[i + 1]) > ceiling:
                        out[i + 1] = str(ceiling)
                except ValueError:
                    out[i + 1] = str(ceiling)
                return out
        out = out[:1] + [flag, str(ceiling)] + out[1:]
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

    final = build_argv(lim, tool, argv, in_scope)
    spec = TOOLS[tool]
    waited, held = 0.0, False
    if in_scope and lim.requests > 0:
        if spec["fanout"]:
            hold_fanout_lock(os.path.join(lim.state_dir, FANOUT_NAME))
            held = True
        else:
            n = request_estimate(tool, argv[1:], len(scoped))
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
        assert n[n.index("-rl") + 1] == "5", n
        n2 = build_argv(lim, "nuclei", ["nuclei", "-rl", "150", "-u",
                                        "https://target.example"], True)
        assert n2[n2.index("-rl") + 1] == "5", n2
        n3 = build_argv(lim, "nuclei", ["nuclei", "-rl", "2", "-u",
                                        "https://target.example"], True)
        assert n3[n3.index("-rl") + 1] == "2", n3

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
        # a list file that is not there must refuse, not scan unchecked
        try:
            targets_in("nuclei", ["-l", os.path.join(d, "nope.txt")])
            assert False, "a missing target list must refuse"
        except ThrottleError:
            pass

        # curl request estimate
        assert request_estimate("curl", ["-s", "https://t.example/"], 1) == 1
        assert request_estimate("curl", ["-sL", "https://t.example/"], 1) == 1
        assert request_estimate("curl", ["-s", "-L", "https://t.example/"], 1) == 2
        try:
            request_estimate("curl", ["https://t.example/[1-100]"], 1)
            assert False, "URL globbing must refuse"
        except ThrottleError:
            pass
        assert request_estimate("curl", ["-g", "https://t.example/[1-100]"], 1) == 1

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
        p.wait()
        assert not got, "the fan-out lock did not survive execvp"

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

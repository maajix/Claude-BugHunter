---
title: Rate limiting and required headers
nav_order: 4
description: A request ceiling and a required header, enforced in code rather than asked for in a prompt.
---

# Rate limiting and required headers

Two engagement rules that an instruction cannot keep:

- a **request ceiling** the whole engagement must stay under, and
- a **header every request to the target must carry** — an Intigriti programme
  may require the researcher's bounty username, and a request without it can be
  treated as unauthorised traffic.

Asking a skill to respect a ceiling does not keep it. The traffic comes from
many processes at once: the agent's own `curl`, a background `nuclei`, four
parallel `xargs` children, `engine/recon.py`. A counter inside any one of them
cannot see the others. So the counter lives in a state file and every process
takes from it under `fcntl.flock`.

The implementation is `engine/throttle.py`. The guard that stops traffic going
around it is `hooks/throttle-guard.py`.

## Turning it on

Add either block to the engagement JSON that `engine/scope.py` already reads.
Both are optional; naming neither leaves the whole mechanism inert.

```json
{
  "name": "acme-external",
  "in_scope": ["acme.example", "*.acme.example"],
  "out_of_scope": ["blog.acme.example"],
  "seeds": ["https://acme.example"],

  "rate_limit": {"requests_per_second": 5},
  "headers": {"X-Bug-Bounty": "your-platform-username"}
}
```

A programme that states a per-minute figure can be written as it is worded:

```json
"rate_limit": {"requests": 100, "per_seconds": 60}
```

The file is found by walking up from the working directory, or named outright:

```bash
export BUGHUNTER_ENGAGEMENT=/path/to/engagement.json
python3 engine/throttle.py show
```

### Where the guard runs

`hooks/throttle-guard.py` is a Claude Code `PreToolUse` hook. The plugin install
wires it through `hooks/hooks.json` on its own. The copy install
(`scripts/install.sh`, `scripts/install.ps1`) copies skills and commands only, so
add the hook to `~/.claude/settings.json` yourself, with the absolute path of your
clone in place of `${CLAUDE_PLUGIN_ROOT}`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$|^WebFetch$",
        "hooks": [
          {"type": "command", "command": "python3 -I /path/to/Claude-BugHunter/hooks/throttle-guard.py", "timeout": 10}
        ]
      }
    ]
  }
}
```

Without the hook, the ceiling still holds for every command run through
`engine/throttle.py exec`; only traffic that goes around it is unguarded.

## Using it

Prefix a network tool. That is the whole interface:

```bash
python3 engine/throttle.py exec -- curl -s https://acme.example/api/v1/me
python3 engine/throttle.py exec -- nuclei -u https://acme.example -t cves/
```

`exec` replaces itself with the tool, so pipes, exit codes, signals and stdin
behave exactly as they do unwrapped. In order it:

1. reads the engagement config;
2. works out every target in the argv, **including the hosts inside a `-l` list
   file**, so a list cannot smuggle a host past the scope check;
3. for an **in-scope** target, waits for room in the shared window and adds the
   required headers using the tool's own header flag;
4. for a **fan-out** tool — one invocation, many requests — clamps the tool's own
   rate flag to the ceiling and holds an exclusive lock for the whole run, so two
   scans cannot each run at the ceiling;
5. `execvp`s the tool.

An **out-of-scope** target passes straight through: no budget, no headers. That
is deliberate. Reading an NVD page is not engagement traffic, must not spend the
target's budget, and must never be sent the bounty username. Every pass-through
is written to `throttle-audit.jsonl` and announced on stderr, so a mistyped
target is visible rather than silent.

## Why a sliding window and not a token bucket

A token bucket is the obvious choice and it is the wrong shape. Refilling at 5
per second with a burst of 5 lets a one-second window hold **ten** requests:
drain the burst at once, then earn five more over the second.
`scripts/test_throttle_wire.py` measured that directly — **9 arrivals in one
second against a stated ceiling of 5** — which is not what a programme means by
"5 requests per second". So the state is the arrival times themselves, and a
request is admitted only while fewer than the ceiling fall inside the window.

Releases are also spaced **evenly** rather than let go in a burst, and the
spacing is computed over a window 10% longer than the stated one. The reason is
that a ceiling is counted at the target's end, so what matters is arrivals, while
this code only controls releases. With four senders running at once, a request
released just inside one second can arrive just inside the next: that put 6
arrivals in a window against a stated 5 before the pacing was added. The cost is
that a short run is slightly slower than the ceiling strictly allows. For an
engagement that is the right side to err on.

## What is enforced, and what is not

Counted honestly, because a gap you can see is a gap somebody fixes. Nineteen
ways traffic can leave: **7 governed, 4 refused outright, 2 that are not target
traffic at all, 5 not covered, and 1 unverified.**

| How traffic leaves | Status |
|---|---|
| `Bash` → `curl` | **Governed.** Counted, header added, and the hook refuses an unwrapped `curl`. Verified at the wire. |
| `Bash` → `nuclei` | **Governed.** Fan-out lock, `-rl` clamped to the ceiling, header added. Flags verified against the installed v3.8.0. |
| `engine/recon.py` own HTTP (`_get`, the API probe) | **Governed** via `throttle.gate()`. |
| `engine/recon.py` → `curl` | **Governed** via `throttle.wrap()`. |
| `engine/recon.py` → `katana` | **Governed.** Its existing `-rl` is clamped to the ceiling and it holds the fan-out lock. |
| `engine/osint.py` → `curl` host probe | **Governed** via `throttle.wrap()`. |
| `engine/osint.py` → `httpx-toolkit` | **Governed.** Fan-out lock; the rate and header flags are asked of the binary at run time rather than assumed. |
| `engine/osint.py` → `subfinder`, `assetfinder`, `crt.sh` | **Not target traffic.** Passive third-party sources, so no budget and no header. |
| `engine/recon.py` → `gau` | **Not target traffic.** Public archives. |
| `Bash` → any of the 46 other named network tools (`ffuf`, `sqlmap`, `nmap`, `subfinder`, `masscan`, …) | **Refused** while a ceiling is set, because their flags are not in the `TOOLS` table and their requests cannot be counted. Add one to `TOOLS` with flags checked against the installed binary to govern it. |
| A command that unsets the proxy or engagement variables | **Refused.** |
| `WebFetch` against an in-scope host | **Refused.** It cannot carry the header and its requests are invisible to the budget. |
| A command that will not tokenize and mentions a tool | **Refused**, because it cannot be checked. |
| A script that opens its own socket | **Not covered.** A Python or Node file the agent writes is outside what a command-string guard can see. |
| A network tool named in neither table | **Not covered.** The two tables are a list of what somebody thought of. |
| Burp MCP | **Not covered.** Burp has its own resource pools and Match/Replace rules; set the ceiling and the header there as well. |
| A browser MCP (Chrome, the built-in browser) | **Not covered.** |
| Another harness, or a second machine, driving the same target | **Not covered.** It has its own budget. `docs/multi-harness.md` ships the skills elsewhere; the hook is Claude Code's format. |
| `Bash` inside a **subagent** | **Unverified.** Whether a plugin `PreToolUse` hook fires for a subagent's tool calls was not confirmed on this build. To check: set a ceiling, have a subagent run `curl https://<in-scope-host>/`, and look for the refusal. If it does not fire, a subagent's `curl` is in the "not covered" row. |

**So the honest claim**: this stops an agent that is following the skills from
overrunning a ceiling or dropping a required header **by accident**, which is the
failure that actually happens on an engagement. It is **not a sandbox** against a
determined bypass, and an earlier description of it as "no request can exceed the
limit" was too strong.

If the uncovered scripted path matters for your engagement, the next step is TLS
interception with `mitmproxy` and an addon, which counts real requests inside the
tunnel. That is a dependency and a local CA, so it is a decision rather than a
default.

## Proving it

Three commands, in increasing strength:

```bash
python3 engine/throttle.py --selftest        # the logic, including the shell shapes
python3 scripts/test_throttle_wire.py        # the ceiling measured at a receiver
python3 engine/throttle.py show              # the active ceiling and what is in flight
```

The wire test is the one that decides it. It starts a receiver on loopback,
writes an engagement with `localhost` in scope and `127.0.0.1` out of it so both
names reach the same server and only the scope differs, drives 20 real `curl`
processes through the wrapper four at a time, and then asserts **from the
receiver's log**, not from the sender's counter:

- no one-second window ever held more than the ceiling;
- 20 requests at 5 per second did not finish faster than the ceiling allows;
- the required header reached every in-scope request and **none** of the
  out-of-scope ones.

Counting in the hook instead of the wrapper fails that last pair: `xargs -P 4`
is one command string and would be charged as one request.

## When the guard gets in the way

The guard is inert unless an engagement names a `rate_limit` or `headers`, so
nothing changes for a session that is not running one. Inside an engagement it
**fails closed**: a config that will not parse, or a guard that crashes, blocks
rather than quietly removing the ceiling. A typo in the ceiling must not be a way
to lose the ceiling.

To work without it, clear `rate_limit` and `headers` from the engagement file, or
work in a directory with no engagement config above it.

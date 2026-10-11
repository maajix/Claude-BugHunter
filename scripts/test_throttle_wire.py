#!/usr/bin/env python3
"""
test_throttle_wire.py — prove the request budget at the wire, not at the counter.

`engine/throttle.py --selftest` checks its own arithmetic. That is not the same
claim. A ceiling is only real if the requests that actually arrive stay under it,
counted by the receiver and not by the sender, with several processes sending at
once. So this test:

  1. starts a receiver on loopback that writes one JSON line per request, with
     the arrival time and every header it saw;
  2. writes an engagement that names a 5 req/s ceiling and one required header,
     with `localhost` in scope and `127.0.0.1` out of it, so both names reach the
     same receiver and only the scope differs;
  3. drives 20 real `curl` processes through the wrapper, four at a time, plus
     out-of-scope requests in the same run;
  4. asserts from the receiver's log that no one-second window ever held more
     than the burst, and that the required header reached the in-scope name and
     never the out-of-scope one.

Counting in the hook instead of the wrapper fails step 4: `xargs -P 4` is one
command string and would be charged one request.

    python3 scripts/test_throttle_wire.py

Exit 0 on pass, 1 on failure with the measured numbers.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THROTTLE = os.path.join(REPO, "engine", "throttle.py")

RPS = 5.0
BURST = 5          # with a hard window the cap IS the per-second ceiling
N_IN_SCOPE = 20
N_OUT_OF_SCOPE = 4
PARALLEL = 4
HEADER_NAME = "X-Bug-Bounty"
HEADER_VALUE = "tester-handle"


class Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"       # no keep-alive: one request, one arrival

    def do_GET(self):                   # noqa: N802 - the stdlib's spelling
        with self.server.lock:
            self.server.log.append({
                "t": time.monotonic(),
                "path": self.path,
                "host": self.headers.get("Host", ""),
                "bounty": self.headers.get(HEADER_NAME),
            })
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):          # keep the test output readable
        pass


def start_receiver():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    srv.log, srv.lock = [], threading.Lock()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def worst_window(stamps, window=1.0):
    """The most arrivals seen in any `window` seconds, over a sliding window."""
    stamps = sorted(stamps)
    worst, j = 0, 0
    for i, t in enumerate(stamps):
        while stamps[j] <= t - window:
            j += 1
        worst = max(worst, i - j + 1)
    return worst


def run_batch(urls, cwd, parallel):
    """Drive one wrapped curl per URL, `parallel` at a time, and wait for all."""
    running, failures = [], []
    for url in urls:
        while len(running) >= parallel:
            time.sleep(0.01)
            for p in list(running):
                if p.poll() is not None:
                    running.remove(p)
                    if p.returncode != 0:
                        failures.append((p.returncode, p.args[-1]))
        running.append(subprocess.Popen(
            [sys.executable, "-I", THROTTLE, "exec", "--",
             "curl", "-s", "-o", os.devnull, url],
            cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
    for p in running:
        p.wait()
        if p.returncode != 0:
            failures.append((p.returncode, p.args[-1]))
    return failures


def main():
    if not shutil.which("curl"):
        print("SKIP: curl is not installed, so nothing can be measured at the wire.")
        return 0

    srv, port = start_receiver()
    problems = []
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "engagement.json"), "w", encoding="utf-8") as fh:
            json.dump({
                "name": "wire-test",
                # Two names for the same loopback receiver. Only the scope
                # differs, so a header seen on the wrong one is a real leak and
                # not an artefact of talking to a different server.
                "in_scope": ["localhost"],
                "rate_limit": {"requests_per_second": RPS},
                "headers": {HEADER_NAME: HEADER_VALUE},
            }, fh)

        urls = ([f"http://localhost:{port}/target/{i}" for i in range(N_IN_SCOPE)] +
                [f"http://127.0.0.1:{port}/research/{i}" for i in range(N_OUT_OF_SCOPE)])
        t0 = time.monotonic()
        failures = run_batch(urls, d, PARALLEL)
        elapsed = time.monotonic() - t0

    time.sleep(0.2)
    srv.shutdown()
    with srv.lock:
        log = list(srv.log)

    if failures:
        problems.append(f"{len(failures)} wrapped curl(s) failed: {failures[:3]}")

    inside = [r for r in log if r["path"].startswith("/target/")]
    outside = [r for r in log if r["path"].startswith("/research/")]

    if len(inside) != N_IN_SCOPE:
        problems.append(f"{len(inside)} of {N_IN_SCOPE} in-scope requests arrived")
    if len(outside) != N_OUT_OF_SCOPE:
        problems.append(f"{len(outside)} of {N_OUT_OF_SCOPE} out-of-scope requests arrived")

    # The ceiling, measured at the receiver and not at the sender's counter.
    # This is the assertion that rejected a token bucket: refilling at 5/s with
    # a burst of 5 put 9 arrivals inside one second here, so the limiter was
    # changed to a hard sliding window rather than the assertion relaxed.
    worst = worst_window([r["t"] for r in inside])
    if worst > BURST:
        problems.append(f"{worst} in-scope requests arrived inside one second, "
                        f"over the stated ceiling of {BURST}")

    # 20 requests at a hard 5 per second cannot finish inside 3 seconds.
    floor = (N_IN_SCOPE - BURST) / RPS
    if elapsed < floor * 0.9:
        problems.append(f"{N_IN_SCOPE} requests at {RPS:g} req/s finished in "
                        f"{elapsed:.2f}s, under the {floor:.2f}s the ceiling implies")

    # The header reaches the target and nothing else.
    missing = [r["path"] for r in inside if r["bounty"] != HEADER_VALUE]
    if missing:
        problems.append(f"{len(missing)} in-scope request(s) arrived without "
                        f"{HEADER_NAME}: {missing[:3]}")
    leaked = [r["path"] for r in outside if r["bounty"] is not None]
    if leaked:
        problems.append(f"{HEADER_NAME} leaked to {len(leaked)} out-of-scope "
                        f"request(s): {leaked[:3]}")

    if problems:
        print("test_throttle_wire: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"test_throttle_wire: PASS — {len(inside)} in-scope requests in "
          f"{elapsed:.2f}s, worst second {worst}/{BURST}, header on all "
          f"{len(inside)} and on none of the {len(outside)} out-of-scope.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

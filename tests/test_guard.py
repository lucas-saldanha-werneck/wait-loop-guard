#!/usr/bin/env python3
"""Feed sample PreToolUse JSON to the hook and check allow/deny.

Run: python3 tests/test_guard.py
"""
import json
import os
import subprocess
import sys
import time
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks", "wait_loop_guard.py")


def run(payload):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    r = subprocess.run([sys.executable, "-I", HOOK], input=raw, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def denied(cmd):
    code, out = run(bash(cmd))
    assert code == 0, f"exit {code}"
    if not out.strip():
        return False
    d = json.loads(out)["hookSpecificOutput"]
    assert d["hookEventName"] == "PreToolUse"
    return d["permissionDecision"] == "deny"


BLOCKED = [
    "until [ -s out.log ]; do sleep 2; done",
    "while true; do curl -s http://localhost:8080 -o /dev/null && break; sleep 5; done",
    "while :; do sleep 1; done",
    "npm start & until curl -sf localhost:3000 -o /dev/null; do sleep 1; done",
    "until\n  [ -f ready ]\ndo\n  sleep 1\ndone",
    "bash -c 'until [ -f done ]; do sleep 1; done'",       # inside quotes (missed by the original)
    'sh -c "while ! pgrep app; do sleep 1; done"',
    "find . -maxdepth 1; while true; do sleep 1; done",    # lower-case "max" is not a deadline
    "while read -r l; do :; done < f; until [ -f x ]; do sleep 1; done",  # read loop + a wait loop
]

# Audit findings (0.1.1): each of these passed the 0.1.0 hook.
BLOCKED_AUDIT = [
    "until read -r x; do sleep 1; done < /dev/null",          # EOF keeps `until read` going
    "while read -r x || true; do sleep 1; done < /dev/null",  # `|| true` keeps it going
    "while read -r line; do until [ -f x ]; do sleep 1; done; done < files",  # nested right after do
    "while read -r x; do while true; do sleep 1; done; done < input.txt",
    "! while true; do sleep 1; done",                          # negated loop
    "bash <<EOF\nuntil [ -f ready ]; do sleep 1; done\nEOF",  # heredoc fed to a shell runs
]

# Round-2 review findings (0.1.2): each of these passed the 0.1.1 hook.
BLOCKED_REVIEW2 = [
    "cat <<EOF\n$(until false; do sleep 1; done)\nEOF",          # substitution in an unquoted heredoc runs
    "cat <<EOF\n`while true; do sleep 1; done`\nEOF",
    "cat <<EOF\nstart $(\nuntil false; do sleep 1; done\n) end\nEOF",  # substitution over several lines
    "env bash <<EOF\nuntil false; do sleep 1; done\nEOF",        # shell behind a wrapper
    "FOO=1 sudo -u app sh <<'EOF'\nwhile true; do sleep 1; done\nEOF",
    "cat <<'EOF' | bash\nwhile true; do sleep 1; done\nEOF",     # heredoc piped into a shell
    'x=1; while read -r line || [ -n "$x" ]; do sleep 1; done < /dev/null',  # tested variable is not the read one
    'while read -r a || [ -n "$b" ]; do :; done < f',
    "case x in x) while true; do sleep 1; done;; esac",             # loop in a case arm
    "case $1 in\n  start) until [ -f ready ]; do sleep 1; done ;;\nesac",
]

ALLOWED = [
    "timeout 120 sh -c 'until [ -s out.log ]; do sleep 2; done'",
    "/usr/bin/timeout 60 bash -c 'while true; do sleep 1; done'",
    "gtimeout 30 sh -c 'until [ -f x ]; do sleep 1; done'",
    "timeout -k 5 60 sh -c 'x'; until [ -f a ]; do sleep 1; done",
    "timeout --signal=KILL 60 sh -c 'until [ -f a ]; do sleep 1; done'",
    "i=0; until [ -s out.log ]; do i=$((i+1)); [ $i -gt 60 ] && break; sleep 2; done",
    "n=0; while true; do ((n++)); [ $n -ge 10 ] && break; sleep 1; done",
    "c=0; while true; do let c=c+1; [ $c -ge 10 ] && break; done",
    "end=$((SECONDS+120)); until [ -s out.log ] || [ $SECONDS -ge $end ]; do sleep 2; done",
    "start=$(date +%s); while [ $(( $(date +%s) - start )) -lt 60 ]; do sleep 1; done",
    "MAX_WAIT=30; until [ -f x ]; do sleep 1; done",
    "deadline=60; until [ -f x ]; do sleep 1; done",
    "while read -r line; do echo \"$line\"; done < file.txt",
    "cat list | while IFS= read -r f; do wc -l \"$f\"; done",
    "while IFS=, read -r a b; do echo $a; done < data.csv",
    "while IFS= read -r l || [ -n \"$l\" ]; do echo \"$l\"; done < f",  # last line without newline
    "until [ -f x ]; do sleep 1; done  # no-deadline-ok",
    "for i in 1 2 3; do echo $i; done",
    "python3 -c 'while True: pass'",
    "git status",
    "",
]

# Audit findings (0.1.1): each of these was denied by the 0.1.0 hook.
ALLOWED_AUDIT = [
    "cat <<EOF\nuntil [ -f ready ]; do sleep 1; done\nEOF",  # heredoc body is only text
    "cat > notes.md <<'EOF'\n```sh\nwhile true; do sleep 1; done\n```\nEOF\ngit add notes.md",
    "timeout -s KILL 60 sh -c 'while true; do sleep 1; done'",
    "timeout --signal KILL 60 sh -c 'until [ -f a ]; do sleep 1; done'",
]

# Round-2 review: keep these passing.
ALLOWED_REVIEW2 = [
    "cat <<'EOF'\n$(until false; do sleep 1; done)\nEOF",      # quoted heredoc: no substitution
    "cat <<EOF\nwhile true; do sleep 1; done\nbuilt on $(date)\nEOF",  # only the substitution runs
    'while IFS= read -r -d "" f || [ -n "$f" ]; do echo "$f"; done < list',
    "while read -r a b || [ -n \"$b\" ]; do echo $a; done < f",
    "while read || [ -n \"$REPLY\" ]; do echo \"$REPLY\"; done < f",
    "case $1 in start) echo go ;; esac",
]


class Guard(unittest.TestCase):
    def test_blocked(self):
        for cmd in BLOCKED:
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)

    def test_allowed(self):
        for cmd in ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertFalse(denied(cmd), cmd)

    def test_blocked_audit(self):
        for cmd in BLOCKED_AUDIT:
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)

    def test_allowed_audit(self):
        for cmd in ALLOWED_AUDIT:
            with self.subTest(cmd=cmd):
                self.assertFalse(denied(cmd), cmd)

    def test_blocked_review2(self):
        for cmd in BLOCKED_REVIEW2:
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)

    def test_allowed_review2(self):
        for cmd in ALLOWED_REVIEW2:
            with self.subTest(cmd=cmd):
                self.assertFalse(denied(cmd), cmd)

    def test_large_text_finishes_fast(self):
        # Review finding: 120 KB of repeated loop keywords took over 6 s, past the 5 s hook timeout.
        for cmd in ["echo " + "while x " * 15000,
                    "echo " + "; while x" * 15000 + "; do :; done",
                    "echo " + ";\n" * 60000 + "do"]:
            with self.subTest(size=len(cmd)):
                start = time.monotonic()
                run(bash(cmd))
                self.assertLess(time.monotonic() - start, 2.0)

    def test_message_examples_pass_the_guard(self):
        _, out = run(bash("until [ -s out.log ]; do sleep 2; done"))
        reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("timeout 120", reason)
        self.assertIn("no-deadline-ok", reason)
        examples = [l.strip()[2:] for l in reason.splitlines() if l.strip().startswith("- ")]
        self.assertEqual(len(examples), 3)
        for ex in examples:
            ex = ex.split(": ", 1)[1] if ex.startswith(("a counter", "elapsed")) else ex
            with self.subTest(example=ex):
                self.assertFalse(denied(ex), ex)

    def test_other_tools_and_bad_input_pass(self):
        self.assertEqual(run({"tool_name": "Read", "tool_input": {"file_path": "x"}}), (0, ""))
        self.assertEqual(run("not json"), (0, ""))
        self.assertEqual(run({"tool_name": "Bash"}), (0, ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)

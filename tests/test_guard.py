#!/usr/bin/env python3
"""Feed sample PreToolUse JSON to the hook and check allow/deny.

Run: python3 tests/test_guard.py
"""
import filecmp
import json
import os
import subprocess
import sys
import tempfile
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
    "timeout --signal=KILL 60 sh -c 'until [ -f a ]; do sleep 1; done'",
    "i=0; until [ -s out.log ]; do i=$((i+1)); [ $i -gt 60 ] && break; sleep 2; done",
    "n=0; while true; do ((n++)); [ $n -ge 10 ] && break; sleep 1; done",
    "c=0; while true; do let c=c+1; [ $c -ge 10 ] && break; done",
    "end=$((SECONDS+120)); until [ -s out.log ] || [ $SECONDS -ge $end ]; do sleep 2; done",
    "start=$(date +%s); while [ $(( $(date +%s) - start )) -lt 60 ]; do sleep 1; done",
    "MAX_WAIT=30; until [ -f x ]; do sleep 1; [ $SECONDS -gt $MAX_WAIT ] && break; done",
    "n=0; until [ -f x ] || [ $n -ge $max_tries ]; do sleep 1; done",
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

# Audit round 3 (0.2.4): each of these passed the 0.2.3 hook.
BLOCKED_AUDIT3 = [
    # WLG-01: a deadline word outside the loop no longer frees it
    "echo 'deadline soon'; until [ -f x ]; do sleep 1; done",
    "until psql -c 'select 1 LIMIT 1'; do sleep 1; done; echo MAX",
    "timeout 5 true; while true; do sleep 1; done",
    "while true; do sleep 1; done; timeout 5 true",
    "sh -c 'timeout 5 foo; while true; do sleep 1; done'",
    "MAX_WAIT=30; until [ -f x ]; do sleep 1; done",          # named but never used by the loop
    "timeout 60 cat log | while true; do sleep 1; done",
    # WLG-02: read must be the only command of the condition
    "while read -r x; true; do sleep 1; done < f",
    "while read -r x && true; do sleep 1; done < f",
    # WLG-03: <<WORD inside quotes is not a heredoc
    "echo 'see <<EOF'\nwhile true; do sleep 1; done",
    # WLG-04: a quoted shell name still runs the heredoc
    '"bash" <<EOF\nwhile true; do sleep 1; done\nEOF',
    "'/bin/sh' <<'EOF'\nuntil false; do sleep 1; done\nEOF",
    # WLG-05: no blank after the keyword
    "while((1)); do sleep 1; done",
    "until(false); do sleep 1; done",
    # WLG-06: a redirect in the condition reopens the input on every turn
    "while read -r x < file; do sleep 1; done",
    "while read -r x <<< \"$s\"; do sleep 1; done",
    "while read -r x < <(ls); do sleep 1; done",
    # WLG-07: arithmetic shift is not a heredoc
    "x=$((1<<4))\nwhile true; do sleep 1; done",
    "((x = 1<<4))\nwhile true; do sleep 1; done",
    # WLG-08: the escape word only counts as a comment
    "curl -o /tmp/no-deadline-ok.txt x; until [ -f x ]; do sleep 1; done",
    # WLG-10: prefixes before the keyword
    "time while true; do sleep 1; done",
    "time -p until false; do sleep 1; done",
]

ALLOWED_AUDIT3 = [
    # WLG-01: deadlines inside the loop or in a command that wraps it still count
    "timeout -k 5 60 sh -c 'until [ -f a ]; do sleep 1; done'",
    "bash -c \"timeout 5 sh -c 'until [ -f a ]; do sleep 1; done'\"",
    "timeout 60 bash -c '(while true; do sleep 1; done)'",
    "MAX_WAIT=30; n=0; until [ -f x ] || [ $n -ge $MAX_WAIT ]; do n=$((n+1)); sleep 1; done",
    "deadline=$((SECONDS+60)); until [ -f x ] || [ $SECONDS -ge $deadline ]; do sleep 1; done",
    "while read -r x <&3; do echo $x; done 3< f",                # fd duplicate, opened once
    "echo do; i=0; until [ -f x ]; do echo done; i=$((i+1)); [ $i -gt 9 ] && break; done",
    # WLG-11: loops that count down or shift end on their own
    "while [ $# -gt 0 ]; do case $1 in -v) v=1 ;; esac; shift; done",
    "n=10; while [ $n -gt 0 ]; do n=$((n-1)); done",
    "n=10; while (( n-- > 0 )); do echo $n; done",
    "n=10; until [ $n -eq 0 ]; do ((--n)); done",
    # WLG-07 / WLG-03: still fine
    "echo $((1<<4)); echo hi",
    "time sleep 1",
    "timeout 60 bash <<EOF\nwhile true; do sleep 1; done\nEOF",   # the shell running the heredoc has a limit
    "until [ -f x ]; do sleep 1; done # no-deadline-ok",
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

    def test_blocked_audit3(self):
        for cmd in BLOCKED_AUDIT3:
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)

    def test_allowed_audit3(self):
        for cmd in ALLOWED_AUDIT3:
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


LOOP = "until [ -s out.log ]; do sleep 2; done"


def loop_using(word):
    """A wait loop whose condition reads the variable `word`."""
    return "until [ -s out.log ] || [ $n -ge ${%s} ]; do sleep 2; done" % word


def run_with(cfg, cmd, env_var=False):
    """Run the hook with a settings file (in XDG_CONFIG_HOME, or named by WAIT_LOOP_GUARD_CONFIG)."""
    base = tempfile.mkdtemp()
    path = os.path.join(base, "wait-loop-guard", "config.json")
    os.makedirs(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg if isinstance(cfg, str) else json.dumps(cfg))
    env = dict(os.environ)
    env.pop("WAIT_LOOP_GUARD_CONFIG", None)
    env["HOME"] = env["USERPROFILE"] = tempfile.mkdtemp()
    if env_var:
        env["WAIT_LOOP_GUARD_CONFIG"] = path
        env.pop("XDG_CONFIG_HOME", None)
    else:
        env["XDG_CONFIG_HOME"] = base
    r = subprocess.run([sys.executable, "-I", HOOK], input=json.dumps(bash(cmd)), capture_output=True,
                       text=True, timeout=30, env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout.strip() else None


class TestSettings(unittest.TestCase):
    def test_escape_words(self):
        cfg = {"escape_words": ["# sem-prazo-ok"]}
        self.assertIsNone(run_with(cfg, LOOP + "  # sem-prazo-ok"))
        self.assertIsNotNone(run_with(cfg, LOOP))
        self.assertIsNone(run_with(cfg, LOOP + "  # no-deadline-ok"))  # the built-in word still works

    def test_deadline_words_whole_word_any_case(self):
        cfg = {"deadline_words": ["prazo"]}
        self.assertIsNone(run_with(cfg, loop_using("PRAZO")))
        self.assertIsNone(run_with(cfg, loop_using("prazo")))
        self.assertIsNotNone(run_with(cfg, loop_using("aprazovel")))
        self.assertIsNotNone(run_with({}, loop_using("prazo")))
        self.assertIsNotNone(run_with(cfg, "prazo=60; " + LOOP))  # only inside the loop (WLG-01)

    def test_deadline_patterns(self):
        cfg = {"deadline_patterns": [r"\bLIMITE\w*\b", "(unclosed"]}  # a bad regex is skipped
        self.assertIsNone(run_with(cfg, loop_using("LIMITE_SEG")))
        self.assertIsNotNone(run_with(cfg, loop_using("limite_seg")))  # patterns keep their case

    def test_tip_appended(self):
        reason = run_with({"tip": "Use /usr/bin/timeout, not gtimeout."}, LOOP)
        self.assertTrue(reason.endswith("\nUse /usr/bin/timeout, not gtimeout."))
        self.assertIn("timeout 120", reason)

    def test_config_env_var_path(self):
        self.assertIsNone(run_with({"escape_words": "# mine"}, LOOP + " # mine", env_var=True))

    def test_broken_or_odd_config_is_ignored(self):
        for cfg in ["{not json", "[1, 2]", json.dumps({"escape_words": [1, None], "tip": 5, "deadline_words": [""]})]:
            with self.subTest(cfg=cfg):
                self.assertIsNotNone(run_with(cfg, LOOP))
        self.assertIsNone(run_with("{not json", "echo hi"))

    def test_file_saved_with_a_bom_is_read(self):
        # Windows editors (Notepad before 2019, PowerShell 5 Out-File) put a BOM at the start.
        self.assertIsNone(run_with("﻿" + json.dumps({"escape_words": ["# mine"]}), LOOP + " # mine"))

    def test_escape_words_are_trimmed_like_deadline_words(self):
        self.assertIsNone(run_with({"escape_words": ["# mine "]}, LOOP + "  # mine"))

    def test_env_var_with_tilde_is_expanded(self):
        env = clean_env()
        path = os.path.join(env["HOME"], "dots", "wlg.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"escape_words": ["# mine"]}, f)
        env["WAIT_LOOP_GUARD_CONFIG"] = "~/dots/wlg.json"   # settings.json "env" does not expand ~
        self.assertEqual(decide(env, LOOP + " # mine"), "")

    def test_relative_paths_never_read_from_the_project(self):
        # A repo that ships .config/wait-loop-guard/config.json must not turn the guard off.
        cwd = tempfile.mkdtemp()
        path = os.path.join(cwd, ".config", "wait-loop-guard", "config.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"escape_words": ["until"]}, f)
        for env in (clean_env(xdg=".config"), clean_env(env_var=os.path.join(".config", "wait-loop-guard", "config.json"))):
            r = subprocess.run([sys.executable, "-I", os.path.abspath(HOOK)], input=json.dumps(bash(LOOP)),
                               capture_output=True, text=True, timeout=30, env=env, cwd=cwd)
            self.assertIn("deny", r.stdout)



# ---------------------------------------------------------------- first-run settings file

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
STARTER = os.path.join(ROOT, "config.example.json")
EVERY_CMD = (BLOCKED + BLOCKED_AUDIT + BLOCKED_REVIEW2 + BLOCKED_AUDIT3
             + ALLOWED + ALLOWED_AUDIT + ALLOWED_REVIEW2 + ALLOWED_AUDIT3)


def clean_env(xdg=None, env_var=None):
    """A fake HOME (USERPROFILE on Windows); XDG_CONFIG_HOME / WAIT_LOOP_GUARD_CONFIG only when given."""
    env = dict(os.environ)
    env["HOME"] = env["USERPROFILE"] = tempfile.mkdtemp()
    for k, v in (("XDG_CONFIG_HOME", xdg), ("WAIT_LOOP_GUARD_CONFIG", env_var)):
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    return env


def seed(env):
    r = subprocess.run([sys.executable, "-I", HOOK, "--seed"], input='{"hook_event_name":"SessionStart","source":"startup"}',
                       capture_output=True, text=True, timeout=30, env=env)
    return r.returncode, r.stdout + r.stderr


def decide(env, cmd):
    r = subprocess.run([sys.executable, "-I", HOOK], input=json.dumps(bash(cmd)), capture_output=True,
                       text=True, timeout=30, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class TestSeed(unittest.TestCase):
    def test_missing_file_is_created_from_the_starter(self):
        xdg = os.path.join(tempfile.mkdtemp(), "not-there-yet")
        self.assertEqual(seed(clean_env(xdg=xdg)), (0, ""))   # silent
        path = os.path.join(xdg, "wait-loop-guard", "config.json")
        self.assertEqual(read_bytes(path), read_bytes(STARTER))

    def test_default_location_is_under_home(self):
        env = clean_env()
        self.assertEqual(seed(env), (0, ""))
        path = os.path.join(env["HOME"], ".config", "wait-loop-guard", "config.json")
        self.assertEqual(read_bytes(path), read_bytes(STARTER))

    def test_env_var_path_is_respected(self):
        xdg = tempfile.mkdtemp()
        mine = os.path.join(tempfile.mkdtemp(), "sub", "mine.json")
        self.assertEqual(seed(clean_env(xdg=xdg, env_var=mine)), (0, ""))
        self.assertEqual(read_bytes(mine), read_bytes(STARTER))
        self.assertFalse(os.path.exists(os.path.join(xdg, "wait-loop-guard")))

    def test_existing_file_is_never_changed(self):
        for content in (b'{"tip": "mine"}\n', b"", b"{not json", b"\xff\xfe odd bytes\r\n"):
            with self.subTest(content=content):
                xdg = tempfile.mkdtemp()
                path = os.path.join(xdg, "wait-loop-guard", "config.json")
                os.makedirs(os.path.dirname(path))
                with open(path, "wb") as f:
                    f.write(content)
                copy = path + ".before"
                with open(copy, "wb") as f:
                    f.write(content)
                before = os.stat(path).st_mtime_ns
                self.assertEqual(seed(clean_env(xdg=xdg)), (0, ""))
                self.assertTrue(filecmp.cmp(path, copy, shallow=False))
                self.assertEqual(os.stat(path).st_mtime_ns, before)

    def test_cannot_create_folder_no_crash(self):
        blocker = os.path.join(tempfile.mkdtemp(), "a-file")
        with open(blocker, "w") as f:
            f.write("x")
        # the config folder would have to be inside a regular file: mkdir fails on every OS
        self.assertEqual(seed(clean_env(xdg=blocker)), (0, ""))
        self.assertEqual(seed(clean_env(env_var=os.path.join(blocker, "c.json"))), (0, ""))

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "read-only folders need POSIX permissions and a non-root user")
    def test_read_only_folder_no_crash(self):
        xdg = tempfile.mkdtemp()
        os.chmod(xdg, 0o500)
        try:
            self.assertEqual(seed(clean_env(xdg=xdg)), (0, ""))
            self.assertFalse(os.path.exists(os.path.join(xdg, "wait-loop-guard", "config.json")))
        finally:
            os.chmod(xdg, 0o700)

    def test_relative_path_is_skipped(self):
        cwd = tempfile.mkdtemp()
        env = clean_env(env_var="relative.json")
        r = subprocess.run([sys.executable, "-I", os.path.abspath(HOOK), "--seed"], input="", capture_output=True,
                           text=True, timeout=30, env=env, cwd=cwd)
        self.assertEqual((r.returncode, r.stdout + r.stderr), (0, ""))
        self.assertEqual(os.listdir(cwd), [])

    def test_seeded_defaults_behave_like_no_file(self):
        none = clean_env(xdg=tempfile.mkdtemp())          # no settings file at all
        seeded = clean_env(xdg=tempfile.mkdtemp())
        seed(seeded)
        self.assertTrue(os.path.isfile(os.path.join(seeded["XDG_CONFIG_HOME"], "wait-loop-guard", "config.json")))
        for cmd in EVERY_CMD + [LOOP + "  # sem-prazo-ok", loop_using("prazo"), loop_using("LIMITE")]:
            with self.subTest(cmd=cmd):
                self.assertEqual(decide(seeded, cmd), decide(none, cmd))

    def test_starter_has_every_key_documented(self):
        with open(STARTER, encoding="utf-8") as f:
            cfg = json.load(f)
        keys = {"escape_words", "deadline_words", "deadline_patterns", "tip"}
        self.assertEqual(set(cfg) - {"_doc"}, keys)
        self.assertTrue(keys <= set(cfg["_doc"]))

    def test_session_start_hook_runs_the_seed(self):
        with open(os.path.join(ROOT, "hooks", "hooks.json"), encoding="utf-8") as f:
            hooks = json.load(f)["hooks"]
        args = [h["args"] for g in hooks["SessionStart"] for h in g["hooks"]]
        self.assertIn(["-I", "${CLAUDE_PLUGIN_ROOT}/hooks/wait_loop_guard.py", "--seed"], args)

    def test_exact_hooks_json_command_runs(self):
        # WLG-09: run the hook the way Claude Code does (same program name, same args), so a
        # missing `python3` on some OS fails here instead of silently turning the guard off.
        import shutil
        with open(os.path.join(ROOT, "hooks", "hooks.json"), encoding="utf-8") as f:
            hooks = json.load(f)["hooks"]
        for h in (h for g in hooks["PreToolUse"] for h in g["hooks"]):
            exe = shutil.which(h["command"])
            self.assertIsNotNone(exe, f"{h['command']!r} from hooks.json is not on PATH")
            args = [a.replace("${CLAUDE_PLUGIN_ROOT}", os.path.abspath(ROOT)) for a in h["args"]]
            r = subprocess.run([exe] + args, input=json.dumps(bash(LOOP)), capture_output=True,
                               text=True, timeout=30, env=clean_env(xdg=tempfile.mkdtemp()))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('"deny"', r.stdout)

if __name__ == "__main__":
    unittest.main(verbosity=2)

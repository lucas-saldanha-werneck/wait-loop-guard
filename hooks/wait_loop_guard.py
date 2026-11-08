#!/usr/bin/env python3
"""PreToolUse(Bash): refuse `until`/`while` wait loops that have no deadline.

Why: a loop such as `until [ -s out.log ]; do sleep 2; done` waits forever when
the file never shows up, and the Bash call (or background task) hangs.

A command passes when it shows some deadline anywhere in it:
  timeout/gtimeout N, SECONDS, date +%s, a counter ((i++)) / ((i+=1)) /
  i=$((i+1)) / let, or the words deadline / max_tries / MAX* / LIMIT*.
`while read ...` loops also pass: they end when their input ends.
Deliberate escape: put the comment `# no-deadline-ok` in the command.
"""
import json
import re
import sys

ESCAPE = "no-deadline-ok"

# Shell loop: until/while <condition>; do   (Python "while x:" has no "do").
# Quotes are separators too, so loops inside `sh -c '...'` are seen.
LOOP = re.compile(
    r"(?:^|[;&|\n({`'\"]|\bthen|\bdo|\belse)\s*(until|while)\s+(.+?)(?:;|\n)\s*do\b",
    re.S,
)

DEADLINE = re.compile(
    r"\bg?timeout\s+(?:-\S+\s+(?:\d+\w*\s+)?)*\d"   # timeout [-k 5] [-s KILL] 60
    r"|\bSECONDS\b|date\s+\+%s"
    r"|\(\(\s*\w+\s*(?:\+\+|\+=)"                    # ((i++)) ((i+=1))
    r"|\w+=\$\(\(\s*\w+\s*\+\s*\d+\s*\)\)"           # i=$((i+1))
    r"|\blet\s+\w+"
    r"|(?i:\bdeadline\b|\bmax_?tries\b)"
    r"|\b(?:MAX|LIMIT)\w*\b",                        # MAX_WAIT, LIMIT ... (upper case)
)

READ_COND = re.compile(r"(?:IFS=\S*\s+)?read\b")


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command") or ""
    if ESCAPE in cmd:
        return

    bad = []
    for m in LOOP.finditer(cmd):
        cond = m.group(2).strip()
        if READ_COND.match(cond):
            continue  # while read: ends when the input ends
        bad.append(f"{m.group(1)} {cond[:60]}")

    if not bad or DEADLINE.search(cmd):
        return

    reason = (
        "wait-loop-guard: wait loop without a deadline (" + "; ".join(bad) + "). "
        "Give it a limit, for example:\n"
        "  - timeout 120 sh -c 'until [ -s out.log ]; do sleep 2; done'\n"
        "  - a counter: i=0; until [ -s out.log ]; do i=$((i+1)); "
        "[ $i -gt 60 ] && break; sleep 2; done\n"
        "  - elapsed seconds: end=$((SECONDS+120)); until [ -s out.log ] || "
        "[ $SECONDS -ge $end ]; do sleep 2; done\n"
        "Also check the exit code of the step you are waiting on before waiting "
        "for its result. If the loop really ends on its own, add the comment "
        f"`# {ESCAPE}`."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


if __name__ == "__main__":
    main()
    sys.exit(0)

#!/usr/bin/env python3
"""PreToolUse(Bash): refuse `until`/`while` wait loops that have no deadline.

Why: a loop such as `until [ -s out.log ]; do sleep 2; done` waits forever when
the file never shows up, and the Bash call (or background task) hangs.

A command passes when it shows some deadline anywhere in it:
  timeout/gtimeout N, SECONDS, date +%s, a counter ((i++)) / ((i+=1)) /
  i=$((i+1)) / let, or the words deadline / max_tries / MAX* / LIMIT*.
`while read ...` loops also pass (they end when their input ends), unless an
`||` keeps the condition true. Heredoc bodies are skipped unless they feed a shell.
Deliberate escape: put the comment `# no-deadline-ok` in the command.
"""
import json
import re
import sys

ESCAPE = "no-deadline-ok"

# Shell loop: until/while <condition>; do   (Python "while x:" has no "do").
# Only the keyword is consumed and the condition is a lookahead, so a loop that
# starts right after another loop's `do` is still found.
LOOP = re.compile(r"\b(until|while)\s+(?=(.+?)(?:;|\n)\s*do\b)", re.S)
# What may come right before the keyword. Quotes are separators too, so loops
# inside `sh -c '...'` are seen. `!` negates a loop: `! while true; do ...`.
LOOP_START = re.compile(r"(?:^|[;&|\n({`'\"]|\bthen|\bdo|\belse)\s*(?:!\s+)?$")

DEADLINE = re.compile(
    r"\bg?timeout\s+(?:(?:-[ks]|--kill-after|--signal)\s+\S+\s+|-\S+\s+)*\d"  # timeout [-k 5] [-s KILL] 60
    r"|\bSECONDS\b|date\s+\+%s"
    r"|\(\(\s*\w+\s*(?:\+\+|\+=)"                    # ((i++)) ((i+=1))
    r"|\w+=\$\(\(\s*\w+\s*\+\s*\d+\s*\)\)"           # i=$((i+1))
    r"|\blet\s+\w+"
    r"|(?i:\bdeadline\b|\bmax_?tries\b)"
    r"|\b(?:MAX|LIMIT)\w*\b",                        # MAX_WAIT, LIMIT ... (upper case)
)

# `while read ...` ends at end of input, unless `||` keeps the condition true.
# The one `||` allowed is the last-line idiom `|| [ -n "$line" ]`.
READ_COND = re.compile(r"(?:IFS=\S*\s+)?read\b")
READ_LAST_LINE = re.compile(r"\|\|\s*\[\[?\s+-n\s+\"?\$\{?\w+\}?\"?\s+\]\]?\s*$")

# Heredoc start: <<WORD, <<-WORD, <<'WORD', <<"WORD" (not the here-string <<<).
HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)(\w+)\2")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "ssh"}


def drop_heredoc_text(cmd):
    """Blank out heredoc bodies, which are data, unless they feed a shell."""
    out, lines, i = [], cmd.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC.finditer(line):
            words = re.split(r"[;&|(]", line[:m.start()])[-1].split()
            runs = bool(words) and words[0].rsplit("/", 1)[-1] in SHELLS
            while i < len(lines):
                body = lines[i]
                i += 1
                if (body.lstrip("\t") if m.group(1) else body) == m.group(3):
                    out.append(body)
                    break
                out.append(body if runs else "")
    return "\n".join(out)


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

    code = drop_heredoc_text(cmd)
    bad = []
    for m in LOOP.finditer(code):
        if not LOOP_START.search(code, 0, m.start()):
            continue
        kind, cond = m.group(1), m.group(2).strip()
        if kind == "while" and READ_COND.match(cond):
            rest = READ_LAST_LINE.sub("", cond)
            if "||" not in rest:
                continue  # while read: ends when the input ends
        bad.append(f"{kind} {cond[:60]}")

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

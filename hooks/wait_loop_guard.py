#!/usr/bin/env python3
"""PreToolUse(Bash): refuse `until`/`while` wait loops that have no deadline.

Why: a loop such as `until [ -s out.log ]; do sleep 2; done` waits forever when
the file never shows up, and the Bash call (or background task) hangs.

A command passes when it shows some deadline anywhere in it:
  timeout/gtimeout N, SECONDS, date +%s, a counter ((i++)) / ((i+=1)) /
  i=$((i+1)) / let, or the words deadline / max_tries / MAX* / LIMIT*.
`while read ...` loops also pass (they end when their input ends), unless an
`||` keeps the condition true. Heredoc bodies are skipped unless a shell may run
them; `$(...)` and backticks in an unquoted heredoc are still checked.
Deliberate escape: put the comment `# no-deadline-ok` in the command.

Your settings: $XDG_CONFIG_HOME/wait-loop-guard/config.json, or
~/.config/wait-loop-guard/config.json, or the file named by WAIT_LOOP_GUARD_CONFIG.
Plugin updates never touch it. Keys: escape_words, deadline_words, deadline_patterns, tip.
`--seed` (run at SessionStart) creates that file from config.example.json when it is missing.
"""
import bisect
import json
import os
import re
import sys

ESCAPE = "no-deadline-ok"
# Copied to your settings path on the first session when no file is there (see seed_config).
STARTER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.example.json")

# Loop keyword. The condition runs up to the first `;` or newline that is
# followed by `do` (Python "while x:" has no "do"). Only the keyword is matched
# here, so a loop that starts right after another loop's `do` is still found.
KEYWORD = re.compile(r"\b(until|while)\s+")
DO_WORD = re.compile(r"\bdo\b")
# What may come right before the keyword. Quotes are separators too, so loops
# inside `sh -c '...'` are seen; `)` ends a case pattern. `!` negates a loop.
SEP_CHARS = set(";&|\n({`'\")")
WORD_BEFORE = re.compile(r"\b(?:then|do|else)$")
MAX_COND = 1000  # a longer "condition" is not inspected, only refused

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
# The one `||` allowed is the last-line idiom `|| [ -n "$line" ]`, and only when
# `$line` is a variable that this `read` fills.
READ_COND = re.compile(r"(?:IFS=\S*\s+)?read\b")
READ_LAST_LINE = re.compile(r"\|\|\s*\[\[?\s+-n\s+\"?\$\{?(\w+)\}?\"?\s+\]\]?\s*$")
READ_OPT_WITH_ARG = re.compile(r"-[A-Za-z]*[adinNptu]")  # -d '', -rd '', -p prompt, -u 3 ...

# Heredoc start: <<WORD, <<-WORD, <<'WORD', <<"WORD" (not the here-string <<<).
HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)(\w+)\2")
# A heredoc may run as code when any of these words is on its line, before or
# after the `<<` (`env bash <<EOF`, `cat <<EOF | sh`, `ssh host <<EOF`).
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "ssh", "source", "eval"}


def substitutions_only(text):
    """Keep only `$(...)` and backtick parts of text; blank the rest (newlines stay)."""
    out, depth, tick, i, n = [], 0, False, 0, len(text)
    while i < n:
        c = text[i]
        if depth == 0 and not tick:
            if c == "$" and text.startswith("(", i + 1):
                depth = 1
                out.append("$(")
                i += 2
                continue
            if c == "`":
                tick = True
                out.append(c)
            else:
                out.append("\n" if c == "\n" else " ")
        else:
            out.append(c)
            if depth:
                depth += 1 if c == "(" else -1 if c == ")" else 0
            elif c == "`":
                tick = False
        i += 1
    return "".join(out)


def drop_heredoc_text(cmd):
    """Blank out heredoc bodies, which are data, unless a shell may run them."""
    out, lines, i = [], cmd.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC.finditer(line):
            words = re.split(r"[\s;&|()<>]+", line)
            runs = any(w.rsplit("/", 1)[-1] in SHELLS for w in words)
            body, end = [], None
            while i < len(lines):
                b = lines[i]
                i += 1
                if (b.lstrip("\t") if m.group(1) else b) == m.group(3):
                    end = b
                    break
                body.append(b)
            if runs:
                out.extend(body)
            elif not m.group(2):  # unquoted: $(...) and `...` inside still run
                out.extend(substitutions_only("\n".join(body)).split("\n") if body else [])
            else:
                out.extend("" for _ in body)
            if end is not None:
                out.append(end)
    return "\n".join(out)


def starts_command(code, i):
    """True when the keyword at i begins a command (not a word inside text)."""
    j = i
    while j > 0 and code[j - 1] in " \t":
        j -= 1
    if j > 0 and code[j - 1] == "!" and j < i:  # `! while ...`
        j -= 1
        while j > 0 and code[j - 1] in " \t":
            j -= 1
    if j == 0 or code[j - 1] in SEP_CHARS:
        return True
    return bool(WORD_BEFORE.search(code, max(0, j - 5), j))


def do_separators(code):
    """Sorted positions of each `;` or newline that is followed, after blanks, by `do`."""
    seps = []
    for m in DO_WORD.finditer(code):
        j = m.start()
        while j > 0 and code[j - 1].isspace():
            j -= 1
        nl = code.find("\n", j, m.start())
        if j > 0 and code[j - 1] == ";":
            seps.append(j - 1)
        elif nl != -1:
            seps.append(nl)
    return seps


def read_vars(cond):
    """Variables a `read` condition fills (REPLY when none is named)."""
    toks = cond.split("||", 1)[0].split()
    toks = toks[toks.index("read") + 1:] if "read" in toks else []
    names, skip = [], False
    for t in toks:
        if skip:
            skip = False
        elif t.startswith("-"):
            skip = bool(READ_OPT_WITH_ARG.fullmatch(t))
        elif re.fullmatch(r"[A-Za-z_]\w*", t):
            names.append(t)
    return names or ["REPLY"]


def find_bad_loops(code):
    seps = do_separators(code)
    bad = []
    for m in KEYWORD.finditer(code):
        if not starts_command(code, m.start()):
            continue
        k = bisect.bisect_left(seps, m.end() + 1)  # the condition has at least one character
        if k == len(seps):
            continue
        kind = m.group(1)
        if seps[k] - m.end() > MAX_COND:
            bad.append(f"{kind} {code[m.end():m.end() + 60].strip()}")
            continue
        cond = code[m.end():seps[k]].strip()
        if kind == "while" and READ_COND.match(cond):
            last = READ_LAST_LINE.search(cond)
            rest = cond[:last.start()] if last and last.group(1) in read_vars(cond) else cond
            if "||" not in rest:
                continue  # while read: ends when the input ends
        bad.append(f"{kind} {cond[:60]}")
    return bad


def config_path():
    """WAIT_LOOP_GUARD_CONFIG, else $XDG_CONFIG_HOME/..., else ~/.config/...; `~` is expanded and a
    relative path is ignored (it would be read from the project folder the session runs in)."""
    xdg = os.environ.get("XDG_CONFIG_HOME") or ""
    base = xdg if os.path.isabs(xdg) else os.path.join(os.path.expanduser("~"), ".config")
    mine = os.path.expanduser(os.environ.get("WAIT_LOOP_GUARD_CONFIG") or "")
    return mine if os.path.isabs(mine) else os.path.join(base, "wait-loop-guard", "config.json")


def load_config():
    """Your settings file as a dict; missing, broken or not an object means {}."""
    try:
        with open(config_path(), encoding="utf-8-sig") as f:  # -sig: a BOM from a Windows editor is fine
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def strings(cfg, key):
    v = cfg.get(key)
    v = [v] if isinstance(v, str) else v if isinstance(v, list) else []
    return [x for x in v if isinstance(x, str) and x.strip()]


def extra_deadlines(cfg):
    """Your deadline_words (whole words, any case) and deadline_patterns (regexes); bad ones skipped."""
    rxs = [re.compile(r"(?i)(?<!\w)" + re.escape(w.strip()) + r"(?!\w)") for w in strings(cfg, "deadline_words")]
    for p in strings(cfg, "deadline_patterns"):
        try:
            rxs.append(re.compile(p))
        except re.error:
            continue
    return rxs


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
    cfg = load_config()
    if any(w.strip() in cmd for w in strings(cfg, "escape_words")):
        return

    bad = find_bad_loops(drop_heredoc_text(cmd))
    if not bad or DEADLINE.search(cmd) or any(rx.search(cmd) for rx in extra_deadlines(cfg)):
        return

    reason = (
        "wait-loop-guard: wait loop without a deadline (" + "; ".join(bad[:5]) + "). "
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
    tip = cfg.get("tip")
    if isinstance(tip, str) and tip.strip():
        reason += "\n" + tip.strip()
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def seed_config():
    """SessionStart: create your settings file from config.example.json when it is missing.

    Never overwrites or changes a file that is there (not even an empty or broken one).
    Any error just leaves things as they are."""
    path = config_path()
    if os.path.lexists(path):
        return
    try:
        with open(STARTER, "rb") as f:
            data = f.read()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # O_EXCL: if the file shows up meanwhile, this fails instead of overwriting it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    except OSError:
        return
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError:
        try:
            os.remove(path)  # the half-written file is ours: remove it so the next run tries again
        except OSError:
            pass


if __name__ == "__main__":
    if sys.argv[1:] == ["--seed"]:
        try:
            seed_config()
        except Exception:
            pass  # never get in the way of starting a session
    else:
        main()
    sys.exit(0)

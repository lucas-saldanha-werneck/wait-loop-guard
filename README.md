# wait-loop-guard

A Claude Code hook that refuses Bash `until`/`while` wait loops with no deadline, so a
Bash call can't hang forever waiting for something that never happens.

Claude often waits like this:

```sh
until [ -s out.log ]; do sleep 2; done
```

If the step before it failed, `out.log` never appears and the loop never ends. The hook
blocks the command before it runs and tells Claude how to add a limit.

## What Claude sees

The command is not run. Claude gets this tool error instead (copied from a real session):

```
PreToolUse:Bash hook error: wait-loop-guard: wait loop without a deadline (until [ -s out.log ]). Give it a limit, for example:
  - timeout 120 sh -c 'until [ -s out.log ]; do sleep 2; done'
  - a counter: i=0; until [ -s out.log ]; do i=$((i+1)); [ $i -gt 60 ] && break; sleep 2; done
  - elapsed seconds: end=$((SECONDS+120)); until [ -s out.log ] || [ $SECONDS -ge $end ]; do sleep 2; done
Also check the exit code of the step you are waiting on before waiting for its result. If the loop really ends on its own, add the comment `# no-deadline-ok`.
```

All three suggested forms pass the hook.

## Examples

- `until [ -s out.log ]; do sleep 2; done` is refused, and Claude gets the three ways to add a limit (see above).
- `timeout 120 sh -c 'until [ -s out.log ]; do sleep 2; done'` passes, because it has a deadline.
- `until [ -f done ]; do sleep 1; done  # no-deadline-ok` passes, because of the opt-out comment, for a loop that really ends on its own.

## Install

In Claude Code:

```
/plugin marketplace add lucas-saldanha-werneck/lucas-tools
/plugin install wait-loop-guard@lucas-tools
```

Then run `/reload-plugins` or start a new session to load the hook.

## What passes

A command with an `until ... do` or `while ... do` loop passes if any of these appear
in the loop's own condition or body (a `timeout` may also be in the command that wraps the
loop, as in `timeout 60 sh -c '...'` or `timeout 60 bash <<EOF`):

| Kind | Examples |
|---|---|
| timeout | `timeout 60`, `gtimeout 60`, with options such as `-k 5`, `-s KILL` or `--signal=KILL` |
| clock | `SECONDS`, `date +%s` |
| counter | `((i++))`, `((i+=1))`, `i=$((i+1))`, `let c=c+1`, and counting down: `((n--))`, `n=$((n-1))`, `shift` |
| named limit | a variable named `deadline` or `max_tries` (any case), or an upper-case one starting with `MAX` or `LIMIT`, used as a variable: `$MAX_WAIT`, `${deadline}`, `max_tries=5`, `(( n < LIMIT ))`. The bare word (`psql -c '... LIMIT 1'`) does not count |

These also pass: `while read ...` loops (they stop when the input ends), `for` loops,
Python `while` loops, commands without a loop, and any command that contains the comment
`# no-deadline-ok` (as a comment, after `#`). A `while read` loop is still checked when
`read` is not the only command of its condition (`while read -r x; true`), when the condition
has its own redirect (`while read -r x < file`, `<<< text`, `< <(cmd)` reopen the input on
every turn; `<&3` is fine), or when `||` keeps its condition true, as in
`while read -r x || true`, except for the common last-line form
`while read -r x || [ -n "$x" ]`, and only when `$x` is a variable that the same `read`
fills. `until read` loops are always checked, because at the
end of the input they never stop.

Loops inside quotes, such as `bash -c 'until [ -f done ]; do sleep 1; done'`, are checked
too, and so are loops nested inside other loops, loops in `case` arms, and negated loops
(`! while ...`).

Heredoc bodies are treated as text and skipped, so writing a shell example to a file with
`cat <<EOF` passes. Two cases are still checked, because that text runs:

- A heredoc on a line that also names a shell (`bash`, `sh`, `zsh`, `dash`, `ksh`, `ash`,
  `ssh`, `source`, `eval`), before or after the `<<`. Examples: `env bash <<EOF`,
  `cat <<'EOF' | sh`.
- `$(...)` and backtick parts of an unquoted heredoc (`<<EOF`, not `<<'EOF'`), because the
  shell runs them before the command reads the text.

## Settings

Your own settings live outside the plugin, in a file that plugin updates never touch:

- `~/.config/wait-loop-guard/config.json` (or `$XDG_CONFIG_HOME/wait-loop-guard/config.json` when
  `XDG_CONFIG_HOME` is set; on Windows `~` is your user folder, `%USERPROFILE%`)
- or any file named by the environment variable `WAIT_LOOP_GUARD_CONFIG` (`~` is expanded; a
  relative path, here or in `XDG_CONFIG_HOME`, is ignored so a project folder can't supply one)

You don't have to create it: the first session after you install the plugin creates it for you,
a copy of [`config.example.json`](config.example.json) with every key at its default (so it
changes nothing until you edit it) and a `_doc` note on each key. If the file is already there,
it is never rewritten or changed, not even by an update.

Every key is optional, and each list may also be a single string. A missing or broken file, or a
value of the wrong type, means the defaults. The built-in rules above always apply; these keys
only add to them.

```json
{
  "escape_words": ["# sem-prazo-ok"],
  "deadline_words": ["prazo"],
  "deadline_patterns": ["\\bLIMITE\\w*\\b"],
  "tip": "On macOS use /usr/bin/timeout: Homebrew's gtimeout loses Full Disk Access under launchd."
}
```

| Key | Type | Effect |
| --- | --- | --- |
| `escape_words` | list of strings | extra escape comments. A command that contains any of them passes, like one with `# no-deadline-ok` (which keeps working) |
| `deadline_words` | list of strings | extra words that count as a deadline, for example in your language. Each matches as a whole word, in any case |
| `deadline_patterns` | list of Python regular expressions | extra deadline patterns, matched as written (case-sensitive unless you add `(?i)`). An invalid one is skipped |
| `tip` | string | a line added at the end of the message Claude sees when a loop is refused |

## Requirements

`python3` on your `PATH`. The hook uses only the standard library. `timeout` is only
suggested to Claude; the hook does not need it.

## How it works

`hooks/hooks.json` registers a `PreToolUse` hook on the `Bash` tool, and a `SessionStart` hook
that only creates your settings file when it is missing. The Python script
blanks out heredoc bodies that don't feed a shell, finds `until`/`while ... do` loops in
one pass over the command (fast enough for very long commands), skips `while read` loops, and
looks for a deadline pattern in each loop and in the commands that wrap it. If it finds a loop and no deadline, it
returns `permissionDecision: "deny"` with the message above. Input it can't parse, and calls
to other tools, pass through untouched.

To run the tests:

```
python3 tests/test_guard.py
```

## Uninstall

```
/plugin uninstall wait-loop-guard@lucas-tools
```

## Limits

- It is a pattern check, not a shell parser. The end of a loop is found by matching `do` and
  `done` words, and quotes are followed only roughly, so odd quoting can make it look at too much
  or too little text.
- It checks that a counter exists, not that the loop uses it to stop.
- A heredoc line that names a shell for another reason, such as `cat <<EOF > x; bash x`,
  has its body checked too.
- Text it can't tell apart from code still counts as code. A loop inside an `echo` string
  or a here-string (`<<<`) is checked, and can be refused, even though it never runs.
- Tested on macOS in the terminal CLI (Claude Code 2.1.319). The docs say desktop app
  local sessions load plugins too, but I have not tested it there, or on Linux or Windows.

## License

MIT. See [LICENSE](LICENSE).

Built with Claude Code

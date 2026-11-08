# wait-loop-guard

A Claude Code hook that refuses Bash `until`/`while` wait loops that have no deadline, so
Claude can't hang forever polling for something that never comes.

## Why

Claude often waits like this:

```sh
until [ -s out.log ]; do sleep 2; done
```

If the previous step failed, `out.log` never appears and the Bash call, or the background task,
waits forever. This hook stops the command before it runs and tells Claude how to add a limit.

## What Claude sees

```
wait-loop-guard: wait loop without a deadline (until [ -s out.log ]). Give it a limit, for example:
  - timeout 120 sh -c 'until [ -s out.log ]; do sleep 2; done'
  - a counter: i=0; until [ -s out.log ]; do i=$((i+1)); [ $i -gt 60 ] && break; sleep 2; done
  - elapsed seconds: end=$((SECONDS+120)); until [ -s out.log ] || [ $SECONDS -ge $end ]; do sleep 2; done
Also check the exit code of the step you are waiting on before waiting for its result. If the
loop really ends on its own, add the comment `# no-deadline-ok`.
```

## What passes

A command with an `until`/`while ... do` loop passes when it shows a deadline anywhere in it:

- `timeout N` / `gtimeout N` (options such as `-k 5` or `--signal=KILL` are fine)
- `SECONDS` or `date +%s`
- a counter: `((i++))`, `((i+=1))`, `i=$((i+1))`, `let ...`
- the words `deadline` or `max_tries`, or an upper-case `MAX...` / `LIMIT...` variable

Also allowed: `while read ...` loops (they end when their input ends), `for` loops, Python
`while` loops, and any command containing the comment `# no-deadline-ok`.

It's a pattern check, not a shell parser. A deadline anywhere in the command counts for every
loop in it.

## Install

In Claude Code:

```
/plugin marketplace add lucas-saldanha-werneck/wait-loop-guard
/plugin install wait-loop-guard@wait-loop-guard
```

Start a new session so it loads the hook.

## Configuration

None.

## Requirements

`python3` on your `PATH`. Nothing else; `timeout` is only suggested to Claude, not needed by
the hook.

## Test

```
python3 tests/test_guard.py
```

## Uninstall

```
/plugin uninstall wait-loop-guard@wait-loop-guard
```

## License

MIT. See [LICENSE](LICENSE).

Built with Claude Code

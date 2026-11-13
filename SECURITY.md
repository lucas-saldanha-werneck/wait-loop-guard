# Security policy

## Reporting a vulnerability

Please report security problems privately: open the **Security** tab of this repository and choose
**Report a vulnerability** (GitHub private vulnerability reporting). Please do not open a public issue
for a security problem. You will get an answer in the same thread.

## Supported versions

Only the latest release is supported. Fixes land in a new release; older versions are not patched.

## What this plugin accesses

- **What it does:** a PreToolUse hook on Bash that refuses (denies) a command containing an `until`/`while` wait loop with no deadline, and tells Claude why. Every other command passes unchanged.
- **What it reads:** the text of the Bash command Claude is about to run (passed to the hook by Claude Code) and its settings file `~/.config/wait-loop-guard/config.json` (or `$XDG_CONFIG_HOME/wait-loop-guard/`, or the path in `WAIT_LOOP_GUARD_CONFIG`).
- **Files it writes:** only that settings file, created once from `config.example.json` at session start when it is missing.
- **Network:** none. It is a local Python hook; it only reads the text of the command, it never runs it.
- **Secrets:** it does not read environment secrets. The command text it sees stays inside the hook process.

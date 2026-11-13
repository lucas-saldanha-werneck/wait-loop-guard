# Security policy

## Reporting a vulnerability

Please report security problems privately: open the **Security** tab of this repository and choose
**Report a vulnerability** (GitHub private vulnerability reporting). Please do not open a public issue
for a security problem. You will get an answer in the same thread.

## Supported versions

Only the latest release is supported. Fixes land in a new release; older versions are not patched.

## What this plugin accesses

- **Files it reads:** the Bash command Claude is about to run (passed to the hook by Claude Code) and its settings file `~/.config/wait-loop-guard/config.json`.
- **Files it writes:** only that settings file, created once from `config.example.json` when it is missing.
- **Network:** none. It is a local Python hook; it only reads the text of the command, it never runs it.
- **Secrets:** it does not read environment secrets. The command text it sees stays inside the hook process.

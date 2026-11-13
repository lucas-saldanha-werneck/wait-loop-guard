# Changelog

All notable changes to this plugin. Versions follow `.claude-plugin/plugin.json`.

## 0.2.5 (2026-11-13)

- Add an Examples section to the README; drop a literal U+FEFF from a test.

## 0.2.4 (2026-11-12)

- Check each loop's own deadline; tighten while-read, heredoc and keyword detection.

## 0.2.3 (2026-11-11)

- Point to the catalog repo's new name, `lucas-tools`.

## 0.2.2 (2026-11-11)

- Catalog renamed to `lucas-tools`.

## 0.2.1 (2026-11-09)

- One-line description, catalog install steps, heading names.

## 0.2.0 (2026-11-08)

- Settings file: escape words, deadline words and patterns, an extra tip.
- Create the settings file on the first session; read it with a BOM; expand `~` in `WAIT_LOOP_GUARD_CONFIG`; ignore relative paths.

## 0.1.2 (2026-11-08)

- Fix review findings: heredoc substitutions, `read` variable, `case` arms, speed.
- CI runs the tests on Linux, macOS and Windows.

## 0.1.1 (2026-11-08)

- Fix audit findings: `until read`, `|| true`, nested and negated loops, heredocs, `timeout -s KILL`.

## 0.1.0 (2026-11-08)

- First release: refuse Bash wait loops without a deadline.

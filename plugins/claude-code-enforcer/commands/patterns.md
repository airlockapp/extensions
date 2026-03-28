# /airlock:patterns

List all auto-approve patterns for the current workspace.

## What to do

Run:
```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" patterns
```

Shows each pattern on a separate line, or "(none)" if no patterns configured.

## Related

- **/airlock:approve** — add a pattern
- **/airlock:disapprove** — remove a pattern

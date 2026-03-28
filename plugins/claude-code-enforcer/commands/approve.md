# /airlock:approve

Add an auto-approve pattern. Shell commands matching any pattern bypass gateway approval.

## What to do

Run:
```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" approve "<pattern>"
```

## Pattern Formats

- **Substring** (case-insensitive): `git status` matches any command containing "git status"
- **Regex**: `/^git\s/i` matches commands starting with "git "

## Notes

- Patterns are per-workspace
- Only shell commands are matched — tool calls (Edit, Write, MCP) always go through gateway
- Use **/airlock:patterns** to list, **/airlock:disapprove** to remove

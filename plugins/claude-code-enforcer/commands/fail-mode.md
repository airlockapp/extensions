# Airlock: Fail Mode

Run this when the user invokes **/airlock:fail-mode**. Controls what happens when the daemon is unavailable.

## What to do

1. **Determine intent**: "open"/"fail open" → `open`, "closed"/"fail closed" → `closed`, just checking → no argument.

2. **Run**:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" fail-mode open
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" fail-mode closed
   ```

3. **Tell the user**: **open** = allow when daemon unavailable (low-risk only), **closed** (default) = block. `AIRLOCK_FAIL_MODE` env var overrides.

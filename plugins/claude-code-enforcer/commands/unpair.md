# Airlock: Unpair

Run this when the user invokes **/airlock:unpair**. Revokes pairing and clears local tokens.

## What to do

1. **Run**:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" unpair
   ```

2. **Tell the user**: This workspace is unpaired. Use **/airlock:pair** to pair again.

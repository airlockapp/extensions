# Airlock: Sign Out

Run this when the user invokes **/airlock:sign-out** or asks to sign out of Airlock.

## What to do

1. **Run**:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" sign-out
   ```

2. **Tell the user**: They are signed out. Use **/airlock:sign-in** and **/airlock:pair** to re-enable.

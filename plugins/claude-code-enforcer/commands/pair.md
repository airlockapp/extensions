# Airlock: Pair with mobile app

**Airlock Approver:** [App Store](https://apps.apple.com/us/app/airlock-approver/id6760250865) · [Google Play](https://play.google.com/store/apps/details?id=com.airlockapp.io)

When the user invokes **/airlock:pair**, run the pairing flow. The user must be signed in first.

## What to do

1. **Check sign-in**: If the user has not signed in yet, tell them to run **/airlock:sign-in** first.

2. **Ask for workspace name** (optional): Ask the user what they'd like to name this workspace. If they provide one, pass it as an argument. Otherwise, the daemon will prompt interactively (defaulting to the folder name).

3. **Run**:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" pair "workspace-name"
   ```
   Or without a custom name (will prompt interactively):
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" pair
   ```

4. **Tell the user**: Enter the 6-character code in the Airlock mobile app.

5. **Next step**: The daemon starts automatically after pairing.

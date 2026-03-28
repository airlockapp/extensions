# Airlock: Sign In

Run this when the user invokes **/airlock:sign-in**, asks to sign in to Airlock, or when tool use is blocked with "not signed in" or "runtime unavailable".

## What to do

1. **Run the sign-in script** in the terminal. On macOS/Linux/Windows:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login
   ```

2. **Optional gateway URL**: To use a specific gateway, pass it as an argument:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login https://localhost:7145
   ```
   If omitted, the daemon resolves the gateway automatically: saved config → `AIRLOCK_GATEWAY_URL` → local probe → default prod (`https://gw.airlocks.io`).

3. **Tell the user**: The script opens the sign-in URL in your default browser. Sign in there; the script waits and saves tokens when complete. If the browser did not open, use the URL printed in the terminal.

4. **Next step**: After sign-in, the user should run **/airlock:pair** to pair with the mobile app.

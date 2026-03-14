# Airlock: Prod Mode

Run this when the user invokes **/airlock:prod-mode** to switch to production mode with strict TLS.

## What to do

1. **Run**:
   ```bash
   ~/.config/airlock-enforcer/bin/airlock-enforcer prod-mode
   ```

2. **Tell the user**: Prod mode is on. Gateway is `https://gw.airlocks.io`. Use **/airlock:dev-mode** for local gateway.

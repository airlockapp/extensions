# Airlock: Dev Mode

Run this when the user invokes **/airlock:dev-mode** to use a local gateway with self-signed certificates.

## What to do

1. **Run**:
   ```bash
   ~/.config/airlock-enforcer/bin/airlock-enforcer dev-mode
   ```
   With custom URL: `~/.config/airlock-enforcer/bin/airlock-enforcer dev-mode https://localhost:7145`

2. **Tell the user**: Dev mode is on. Use **/airlock:prod-mode** to switch back.

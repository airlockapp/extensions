# Airlock: Pair with mobile app

When the user invokes **/airlock:pair**, run the pairing flow. The user must be signed in first.

## What to do

1. **Check sign-in**: If the user has not signed in yet, tell them to run **/airlock:sign-in** first.

2. **Run**:
   ```bash
   ~/.config/airlock-enforcer/bin/airlock-enforcer pair
   ```

3. **Tell the user**: Enter the 6-character code in the Airlock mobile app.

4. **Next step**: The daemon starts automatically after pairing.

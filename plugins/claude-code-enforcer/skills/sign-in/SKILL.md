# Airlock sign-in (Claude Code)

Use this skill when the user wants to **sign in to Airlock** for the Claude Code enforcer, or when tool use is blocked with "not signed in", "runtime unavailable", or "Not paired".

## Sign in and pair via the plugin (no daemon path needed)

The plugin exposes **commands** you can run for the user:

- **/airlock:sign-in** — Runs the sign-in flow. Gateway URL is resolved automatically if not provided (saved config → `AIRLOCK_GATEWAY_URL` → local probe → default prod `https://gw.airlocks.io`). The user opens the printed URL in a browser and enters the 6-char code.
- **/airlock:pair** — Runs the pairing flow (requires sign-in first). The user enters the 6-char pairing code in the Airlock mobile app.
- **/airlock:status** — Shows whether they are signed in and paired.

You do not need to tell the user where the daemon lives; invoke the command and, if needed, run the script from the plugin root (or use `CLAUDE_PLUGIN_ROOT` when set).

## Gateway URL resolution (same as Cursor)

When the user runs sign-in **without** a gateway URL, the daemon resolves it in this order:

1. **Saved** — Gateway URL already stored in credentials (from a previous login).
2. **Env** — `AIRLOCK_GATEWAY_URL`.
3. **Local probe** — HTTPS/HTTP on localhost (e.g. 7145, 5145, 7771) for dev.
4. **Default prod** — `https://gw.airlocks.io`.

So for production, the user can run **/airlock:sign-in** with no arguments. For local dev, set `AIRLOCK_GATEWAY_URL` or run a local gateway so the probe finds it.

## After sign-in and pair

To gate Claude Code tool use, the user must **start the daemon** from their project directory and leave it running: run **/airlock:status** or tell them to run `node scripts/run-airlock.js run` from the project (or set `AIRLOCK_WORKSPACE`).

## What to tell the user

- **"Not signed in" / "Runtime unavailable"**: Run **/airlock:sign-in**, then **/airlock:pair**, then start the daemon from the project directory.
- **"Not paired"**: Run **/airlock:pair** after sign-in.
- **Daemon not running**: They must run `node scripts/run-airlock.js run` from the project directory (or use **/airlock:status** for guidance).
- **Fail mode**: Run **/airlock:fail-mode open** to allow actions when the daemon is unavailable (use only in low-risk environments). Run **/airlock:fail-mode closed** to block (default). The `AIRLOCK_FAIL_MODE` env var overrides the stored setting.
- **Auto-approve**: Run **/airlock:approve** `<pattern>` to auto-approve specific shell commands without gateway approval. Run **/airlock:patterns** to list, **/airlock:disapprove** to remove. Patterns are per-workspace.

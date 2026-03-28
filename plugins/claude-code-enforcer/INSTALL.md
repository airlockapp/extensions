# Airlock Enforcer for Claude Code — Installation Guide

This guide walks you through installing and configuring the Airlock Claude Code plugin so that tool use (shell commands, file edits, etc.) is gated through the Airlock gateway and your mobile approval.

---

## Prerequisites

- **Claude Code** — [Install Claude Code](https://code.claude.com/) if you haven't already.
- **Node.js** — Version 18 or later (used to run the plugin's daemon and scripts).  
  Check with: `node --version`
- **Airlock Gateway** — You need access to an Airlock gateway (e.g. your organization's or the default `https://gw.airlocks.io`).
- **Airlock mobile app** — For approving or denying actions and for pairing.

---

## Step 1: Load the plugin

Claude Code can load plugins in two ways: from a **local directory** (e.g. a repo or unpacked folder) or from a **marketplace** after the plugin is published there.

### Option A: From the Airlock marketplace (recommended)

The plugin is published to the Airlock Claude Code marketplace hosted on GitHub. Add the marketplace and install the plugin by name:

1. Add the marketplace (one-time):
   ```bash
   /plugin marketplace add airlockapp/claude-plugins
   ```

2. Install the plugin:
   ```bash
   /plugin install airlock@airlock-claude-plugins
   ```

The plugin is automatically available in every Claude Code session after installation.

> **Important:** After installing or updating the plugin, **restart Claude Code** (close and reopen) so the daemon starts and presence goes online. A simple `/reload plugins` is not enough — the daemon is launched by the SessionStart hook, which only fires when Claude Code starts.

### Option B: Local directory (for development or one-off use)

Run Claude Code with the plugin directory path using **`--plugin-dir`**:

```bash
claude --plugin-dir /path/to/claude-code-enforcer
```

The plugin is loaded for that session only. To use it every time, install it from the marketplace (Option A) or create a shell alias.

You cannot use `claude plugin install /path/to/plugin` with a **file path** — that command expects a **plugin name** from a configured marketplace. Use `--plugin-dir` for a local path.

---

## Step 2 (recommended): Enable secure storage

Tokens and keys are stored so that only your user account can read them. For **stronger protection**, use the OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service).

From the **plugin root** (the folder that contains `daemon/`, `scripts/`, and this file):

```bash
cd /path/to/claude-code-enforcer
npm install
```

This installs the optional dependency used for secure storage. If this step is skipped, the daemon still works and stores data under `~/.config/airlock-enforcer/` with restricted file permissions (0600).

- **Linux:** You may need: `sudo apt-get install libsecret-1-dev` (Debian/Ubuntu) or the equivalent for your distro.

---

## Step 2b (optional): Dev mode for local gateway

If you use a **local gateway** (e.g. `https://localhost:7145`) with **self-signed certificates**, switch to dev mode first:

- **From Claude Code:** Run **/airlock:dev-mode** (or **/airlock:dev-mode https://localhost:7145** to set a custom URL).
- **From terminal:** `node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" dev-mode` or `node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" dev-mode https://localhost:YOUR_PORT`.

Dev mode sets the gateway URL to `https://localhost:7145` (or your URL) and allows self-signed certs. Switching modes automatically stops the running daemon so it restarts with the new gateway. Use **/airlock:prod-mode** to switch back to production (`https://gw.airlocks.io`).

---

## Step 3: Sign in

Sign in once per machine (or per config directory). You can do this from Claude Code or from a terminal. The plugin **always allows** its own sign-in, pair, status, dev-mode, and prod-mode commands (they are never gated by the daemon), so you can sign in from within Claude Code even when the daemon is not running.

### Option A: From Claude Code (easiest)

1. In Claude Code, run **/airlock:sign-in** (or ask Claude to sign you in to Airlock).
2. The sign-in flow opens the verification URL in your default browser (same as Cursor enforcer). Sign in there; if the browser did not open, use the URL printed in the terminal.
3. When sign-in succeeds, you'll see a short confirmation. No need to remember any paths.

For production, you don't need to specify a gateway URL; the plugin will use the default. For a custom or local gateway, set `AIRLOCK_GATEWAY_URL` in your environment or pass the URL when asked.

### Option B: From a terminal

From any directory (once the native shim is installed on first plugin load):

```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login
```

Or with an explicit gateway URL:

```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login https://your-gateway.example.com
```

The script opens the URL in your browser; sign in there.

---

## Step 4: Pair with the mobile app

After signing in, pair this machine with the Airlock mobile app so that approvals and denials are sent correctly.

### Option A: From Claude Code

1. Run **/airlock:pair** (or ask Claude to pair Airlock with your mobile app).
2. When you see the **6-character pairing code** (3 lines of output), open the Airlock mobile app and enter the code.
3. When pairing completes, the **daemon starts automatically** — you're ready to go.

### Option B: From a terminal

From any directory:

```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" pair
```

Enter the pairing code in the mobile app when prompted. The daemon starts automatically after pairing.

---

## That's it — you're ready!

After pairing, **the daemon is managed automatically**. You do not need to start or stop it manually:

- **SessionStart** hook: when Claude Code starts a new session (and you're signed in and paired), the daemon starts automatically.
- **SessionEnd** hook: when the session ends, the daemon stops.
- **Unpair / Sign out**: the daemon stops automatically.

The mobile app will show your workspace as online (with the workspace name), and you can approve or deny actions in real time.

---

## Where data is stored

| Data | With secure storage (after `npm install`) | Without secure storage |
|------|-------------------------------------------|-----------------------------|
| Sign-in tokens, gateway URL | OS keychain (e.g. Windows Credential Manager, macOS Keychain) | `~/.config/airlock-enforcer/credentials.json` (mode 0600) |
| Pairing (routing token, encryption key, paired keys) | OS keychain | `~/.config/airlock-enforcer/state.json` (mode 0600) |

Config directory (for non-sensitive or fallback data): `~/.config/airlock-enforcer/` or the path set in `AIRLOCK_CONFIG_DIR`.

---

## Check status

- **From Claude Code:** Run **/airlock:status** (or ask Claude for your Airlock status).
- **From a terminal:** From the plugin root, run:

  ```bash
  node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" status
  ```

This shows **mode** (dev/prod), **gateway URL**, whether you're signed in, and whether you're paired. In dev mode it also shows that self-signed certificates are allowed.

**Dev/Prod:** **/airlock:dev-mode** [URL] and **/airlock:prod-mode** switch between local gateway (self-signed certs OK) and production. **Sign out:** **/airlock:sign-out**. **Unpair:** **/airlock:unpair**.

---

## Troubleshooting

**"Not signed in" or "Runtime unavailable"**  
- Run **/airlock:sign-in**, then **/airlock:pair**. The daemon starts automatically after pairing.

**"Not paired"**  
- Run **/airlock:pair** after signing in.

**Tool use not gated / no approval prompt**  
- Make sure you are signed in and paired (**/airlock:status**).
- The daemon should start automatically. If it didn't, restart Claude Code to trigger the SessionStart hook, or run `node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" run` manually from your project directory.

**Workspace not showing in mobile app / Presence offline after install**  
- **Restart Claude Code** (close and reopen). The daemon starts on `SessionStart`, which only fires when Claude Code opens — not on `/reload plugins`. After restarting, your workspace should appear online in the mobile app. Check **/airlock:status** to confirm paired status.

**Custom or local gateway**  
- Run **/airlock:dev-mode** [URL] before sign-in, or set `AIRLOCK_GATEWAY_URL` to your gateway URL.

**Secure storage (keytar) build fails on Linux**  
- Install libsecret: e.g. `sudo apt-get install libsecret-1-dev` (Debian/Ubuntu). The daemon still works without keytar; credentials are then stored in the config directory with file mode 0600.

**Pairing or sign-in code is 8 characters instead of 6**  
- The plugin and gateway use **6-character** codes. There is **no cache to clear in the plugin**; the plugin does not cache codes.
- If you still see 8 characters, your **Airlock Gateway** (or auth backend) may be an older build. Redeploy the gateway so it uses 6-digit pairing and 6-digit sign-in (device verify) codes. The plugin will show and use only the first 6 characters.

---

## Uninstall

To completely remove the Airlock enforcer from your machine:

### 1. Unpair and sign out

From Claude Code:
```
/airlock:unpair
/airlock:sign-out
```

Or from a terminal:
```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" unpair
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" sign-out
```

This revokes the pairing on the gateway, clears stored credentials, and stops the daemon.

### 2. Remove the plugin

**If installed from the marketplace:**
```bash
claude plugin uninstall airlock@airlock-claude-plugins
```

**If used with `--plugin-dir`:** Simply stop using the `--plugin-dir` flag. No uninstall step is needed.

### 3. Remove config directory and native shim

**Linux / macOS:**
```bash
rm -rf ~/.config/airlock-enforcer
```

**Windows (PowerShell):**
```powershell
Remove-Item -Recurse -Force "$env:USERPROFILE\.config\airlock-enforcer"
```

This removes stored credentials (if not using the OS keychain), workspace state, the native shim binary, and all enforcer configuration.

### 4. Remove OS keychain entries (if you used secure storage)

If you ran `npm install` in the plugin directory to enable secure storage, keychain entries were created under the service name **"Airlock Enforcer"**. Remove them:

- **Windows:** Open **Credential Manager** → **Windows Credentials** → find and remove entries named `Airlock Enforcer`.
- **macOS:** Open **Keychain Access** → search for `Airlock Enforcer` → delete the entries.
- **Linux:** Use `secret-tool` or your desktop keyring manager to remove entries for `Airlock Enforcer`.

### 5. Remove workspace dotfiles (optional)

If you paired any workspace directories, a `.airlock` file was created in each (and added to `.gitignore`). You can safely delete these:

```bash
rm /path/to/your/project/.airlock
```

The `.gitignore` entry (`.airlock`) can be removed too, but it's harmless to leave it.

---

## Summary

1. Load the plugin: run `/plugin marketplace add airlockapp/claude-plugins` then `/plugin install airlock@airlock-claude-plugins` (or use `claude --plugin-dir /path/to/claude-code-enforcer` for local development).
2. (Recommended) Run `npm install` in the plugin directory for secure storage.
3. Sign in: **/airlock:sign-in** or `node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login`.
4. Pair: **/airlock:pair** or `node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" pair`.
5. Use Claude Code in your project — the daemon starts and stops automatically. Approve or deny actions in the mobile app.
6. (Optional) Set fail mode: **/airlock:fail-mode open** or **/airlock:fail-mode closed**.
7. (Optional) Auto-approve shell commands: **/airlock:approve** `<pattern>` to add, **/airlock:patterns** to list.

All per-workspace settings (pairing, auto-mode, fail-mode, auto-approve patterns) are scoped to your current workspace.

For more details (gateway resolution, fail-open/fail-close, plugin layout, hooks), see [README.md](README.md).

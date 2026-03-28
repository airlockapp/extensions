# Airlock Enforcer — Claude Code Plugin

Claude Code plugin that gates tool use (Bash, Edit, Write, Read, etc.) through the **Airlock** security gateway for human-in-the-loop approval (e.g. mobile app).

**The plugin works by itself.** It includes a **standalone daemon** for sign-in, pairing, token refresh, presence tracking, and gateway communication. You do not need Cursor or any other IDE.

**End users:** See **[INSTALL.md](INSTALL.md)** for a step-by-step installation guide (prerequisites, secure storage, sign-in, pair, troubleshooting).

Uses the [Claude Code plugin](https://code.claude.com/docs/en/plugins-reference) and [hooks](https://code.claude.com/docs/en/hooks) architecture. The plugin registers **SessionStart**, **SessionEnd**, and **PreToolUse** hooks. A **bootstrap script** sends each tool call to a local **pipe server** (the daemon). The daemon talks to the Airlock gateway and returns allow/deny.

## Features

- **Sign-in**: Browser-based sign-in (same as Cursor enforcer): device authorization via the gateway; the daemon opens the verification URL in your default browser. Tokens are stored securely (OS keychain if available, otherwise `~/.config/airlock-enforcer/` with restricted file permissions).
- **Sign-out**: Clear stored credentials and stop the daemon.
- **Pair / Unpair**: Pair with the mobile approver; unpair revokes on the gateway, clears local pairing state, and stops the daemon.
- **Automatic daemon management**: The daemon starts automatically after pairing and on each `SessionStart` hook (when already paired). It stops on `SessionEnd`, unpair, and sign-out. No manual daemon management needed.
- **Presence tracking**: The daemon maintains a persistent WebSocket connection to the gateway for real-time presence, so the mobile app shows the workspace as online and can deliver approvals instantly.
- **Per-workspace identity**: When you pair a workspace, a hidden `.airlock` dotfile is automatically created and added to your `.gitignore`. This ensures your workspace identity remains stable even if you rename your project folder or trigger tools from deeper subdirectories.
- **Per-workspace configuration**: Pairing, auto-mode, fail-mode, and auto-approve patterns are stored per workspace. Sign-in/sign-out and dev/prod mode are global.
- **Auto-approve patterns**: Define patterns (substring or `/regex/`) for shell commands that should be auto-approved without gateway approval. Only Bash commands are matched — tool calls (Edit, Write, MCP) always go through the gateway. Same matching as the Cursor enforcer.
- **Do Not Disturb (DND)**: If the gateway has DND policies configured, the daemon evaluates them before submitting artifacts — auto-approving or auto-denying actions based on the policy.
- **Gateway communication**: Daemon builds HARP envelopes, encrypts with the pairing key, submits to `POST /v1/artifacts`, long-polls `GET /v1/exchanges/{id}/wait`, and returns the decision.
- **Refresh token**: Daemon proactively refreshes the access token before expiry (60s ahead) with exponential backoff (30s–300s, up to 10 retries), and refreshes on 401.
- **Fail-open / fail-close**: If the daemon is unreachable (not running, connection timeout), the bootstrap applies **fail mode** (configurable via **/airlock:fail-mode**):
  - `failClosed` (default): block the action.
  - `failOpen`: allow the action.
  - The `AIRLOCK_FAIL_MODE` environment variable overrides the stored setting if set.

Approval **timeout** (no response from gateway within 2 minutes) always **denies** (no fail-open on timeout).

**Network:** The plugin and daemon communicate **only with the Airlock gateway** (sign-in, pairing, artifacts, exchanges, presence WebSocket). The bootstrap script does not make HTTP requests; it only talks to the local daemon via a named pipe. No localhost probing is performed — the default is the production gateway (`gw.airlocks.io`). Dev mode uses an explicit URL set via the dev-mode command. No direct Keycloak or other external URLs.

## Installation

### 1. Load the plugin

**From the Airlock marketplace** (recommended): Add the Airlock marketplace and install the plugin by name. The plugin is automatically kept up to date.

```bash
/plugin marketplace add airlockapp/claude-plugins
/plugin install airlock@airlock-claude-plugins
```

> **Note:** After installing or updating the plugin, **restart Claude Code** (close and reopen) so the daemon starts and presence goes online. A simple `/reload plugins` is not enough — the daemon is launched by the SessionStart hook, which only fires when Claude Code opens.

**From a local path** (e.g. for development): run Claude Code with the plugin directory. The plugin is active for that session only.

```bash
claude --plugin-dir /path/to/claude-code-enforcer
```

You cannot use `claude plugin install /path/...` with a file path — that command expects a plugin **name** from a configured marketplace.

### 2. Sign in and pair (one-time per machine) — via plugin

You can sign in and pair **without knowing the daemon path** by using the **airlock:\<command\>** plugin commands in Claude Code:

- **/airlock:sign-in** — Starts sign-in; opens the verification URL in your browser (same UX as Cursor). No gateway URL needed for production (see [Gateway URL resolution](#gateway-url-and-devprod-mode) below).
- **/airlock:sign-out** — Signs out; clears stored credentials and stops the daemon.
- **/airlock:dev-mode** [URL] — Use dev gateway (default `https://localhost:7145`). Self-signed certificates allowed. Pass URL to override.
- **/airlock:prod-mode** — Use prod gateway (default `https://gw.airlocks.io`). Strict TLS. Default mode.
- **/airlock:pair** — After sign-in, run this; it shows 3 lines with the **6-character pairing code**. Enter the code in the Airlock mobile app. The daemon starts automatically after pairing.
- **/airlock:unpair** — Unpair from the mobile approver; revokes on the gateway, clears local pairing state, and stops the daemon.
- **/airlock:status** — Shows **mode** (dev/prod), **gateway URL**, sign-in and pairing status.
- **/airlock:auto-on** — Enable auto-approve mode (skip gateway for all tool use).
- **/airlock:auto-off** — Disable auto-approve mode (resume gateway approval).
- **/airlock:fail-mode** \<open|closed\> — Set what happens when the daemon is unavailable: `open` allows actions, `closed` blocks. Run without argument to check current mode.
- **/airlock:approve** \<pattern\> — Add an auto-approve pattern (substring or `/regex/`). Matching shell commands skip gateway approval.
- **/airlock:disapprove** \<pattern\> — Remove an auto-approve pattern.
- **/airlock:patterns** — List current auto-approve patterns for this workspace.

All per-workspace commands (pair, unpair, auto-on/off, fail-mode, approve/disapprove/patterns) use `AIRLOCK_WORKSPACE` or the current working directory to determine the workspace.

Claude will run the daemon scripts for you when you invoke these commands. Credentials and pairing state are stored under `~/.config/airlock-enforcer/` (or `AIRLOCK_CONFIG_DIR`).

**Optional (terminal):** The plugin automatically generates a native shim executable the first time it loads. You can invoke it from any directory:

```bash
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" dev-mode [URL]   # default URL https://localhost:7145
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" prod-mode        # default https://gw.airlocks.io
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" login            # or sign-in; optional: add gateway URL as second arg
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" sign-out
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" pair
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" unpair
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" fail-mode open       # allow actions when daemon unavailable
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" fail-mode closed      # block actions when daemon unavailable (default)
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" approve 'git status'  # auto-approve commands matching pattern
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" disapprove 'git status' # remove auto-approve pattern
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" patterns              # list auto-approve patterns
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" status
```

### 3. Daemon lifecycle (automatic)

The daemon is managed automatically:

| Event | Action |
|-------|--------|
| **Pair** (first time) | Daemon starts automatically after successful pairing |
| **SessionStart** hook | Daemon starts if signed in and paired (and not already running) |
| **SessionEnd** hook | Daemon stops via shutdown message on the named pipe |
| **Unpair** | Daemon stops |
| **Sign out** | Daemon stops |

No manual daemon management is needed. The daemon runs as a detached background process — it is **not** a child process of Claude Code.

**Manual start (fallback):** If you need to start the daemon manually (e.g. debugging):

```bash
cd /path/to/your/project
node "${CLAUDE_PLUGIN_ROOT}/daemon/cli.js" run
```

### Gateway URL and dev/prod mode

- **Prod mode** (default): Gateway resolves in this order — saved URL in credentials → `AIRLOCK_GATEWAY_URL` → default `https://gw.airlocks.io`. Strict TLS.
- **Dev mode**: Gateway is `https://localhost:7145` (or a URL you set with **/airlock:dev-mode** [URL]). Self-signed certificates are allowed (`NODE_TLS_REJECT_UNAUTHORIZED=0`).

Switching modes (dev-mode / prod-mode) automatically stops the running daemon so it restarts with the new gateway on the next action.

Use **/airlock:dev-mode** before sign-in when using a local gateway. Use **/airlock:prod-mode** to switch back. **/airlock:status** shows the current mode and gateway URL.

### 4. Configure fail mode (optional)

Use **/airlock:fail-mode** to set what happens when the daemon is unavailable:

```bash
# From Claude Code:
/airlock:fail-mode open      # allow actions when daemon unavailable
/airlock:fail-mode closed    # block actions when daemon unavailable (default)

# Or via environment variable (overrides stored setting):
export AIRLOCK_FAIL_MODE=failClosed
export AIRLOCK_FAIL_MODE=failOpen
```

## Plugin layout

```
claude-code-enforcer/
├── .claude-plugin/
│   └── plugin.json          # Plugin manifest; hooks, skills, commands
├── commands/                # Plugin commands (no daemon path needed)
│   ├── sign-in.md           # /airlock:sign-in
│   ├── sign-out.md          # /airlock:sign-out
│   ├── dev-mode.md          # /airlock:dev-mode [URL]
│   ├── prod-mode.md         # /airlock:prod-mode
│   ├── pair.md              # /airlock:pair
│   ├── unpair.md            # /airlock:unpair
│   ├── status.md            # /airlock:status
│   ├── auto-on.md           # /airlock:auto-on
│   ├── auto-off.md          # /airlock:auto-off
│   ├── fail-mode.md         # /airlock:fail-mode <open|closed>
│   ├── approve.md           # /airlock:approve <pattern>
│   ├── disapprove.md        # /airlock:disapprove <pattern>
│   └── patterns.md          # /airlock:patterns
├── hooks/
│   └── hooks.json           # SessionStart, SessionEnd, PreToolUse hooks
├── scripts/
│   ├── airlock-bootstrap.js # Transport-only; stdin → pipe → stdout
│   └── airlock-session.js   # SessionStart/SessionEnd: spawn or stop daemon
├── daemon/                  # Standalone pipe server + auth + gateway
│   ├── cli.js               # login | pair | unpair | run | status | sign-out
│   ├── endpointResolver.js  # Gateway URL resolution (dev/prod, same as Cursor)
│   ├── config.js            # Config dir, credentials, per-workspace state, auto-approve patterns
│   ├── auth.js              # Device flow, refresh
│   ├── crypto.js            # X25519, AES-256-GCM
│   ├── pairing.js           # Pairing flow, per-workspace enforcer ID, store routing token + key
│   ├── gateway.js           # Submit artifact, wait for decision
│   ├── pipeServer.js        # Named pipe server
│   ├── presenceClient.js    # Persistent WebSocket for real-time presence tracking
│   └── dndClient.js         # Do Not Disturb policy evaluation
├── skills/
│   └── sign-in/
│       └── SKILL.md         # How to sign in and pair (references commands)
├── INSTALL.md
└── README.md
```

## Daemon commands

| Command   | Description |
|----------|-------------|
| `login [GATEWAY_URL]` | Sign in via device code; saves tokens to config dir. |
| `sign-out` | Sign out; clear credentials and stop daemon. |
| `pair`   | Pair with mobile app (requires sign-in); saves routing token and encryption key; starts daemon. |
| `unpair` | Unpair from mobile app; revoke on gateway, clear pairing state, stop daemon. |
| `run`    | Start the pipe server for the current workspace (or `AIRLOCK_WORKSPACE`). |
| `status` | Show sign-in, pairing, mode, fail mode, and auto-approve patterns. |
| `fail-mode <open\|closed>` | Set fail mode: `open` allows when daemon unavailable, `closed` blocks (default). |
| `approve <pattern>` | Add auto-approve pattern (substring or `/regex/`). Matching Bash commands skip gateway. |
| `disapprove <pattern>` | Remove an auto-approve pattern. |
| `patterns` | List auto-approve patterns for this workspace. |

Environment:

- `AIRLOCK_CONFIG_DIR` — Config directory (default: `~/.config/airlock-enforcer`).
- `AIRLOCK_GATEWAY_URL` — Gateway URL (used by `login` if not passed as argument).
- `AIRLOCK_WORKSPACE` — Workspace path for `run` (default: current working directory).
- `AIRLOCK_FAIL_MODE` — Override fail mode (takes precedence over stored config).

## Hook behavior

Three hooks are registered in `hooks/hooks.json`:

| Hook | Purpose |
|------|---------|
| **SessionStart** | Spawn the daemon (if signed in and paired, and not already running) |
| **SessionEnd** | Send shutdown message to daemon via named pipe |
| **PreToolUse** | Forward tool call to daemon pipe; return allow/deny |

- **PreToolUse matcher**: `*` (all tools). You can narrow in `hooks/hooks.json` (e.g. `"Bash"` or `"Edit|Write"`).
- **Command**: `node "${CLAUDE_PLUGIN_ROOT}/scripts/airlock-bootstrap.js"`.
- **Input**: Claude Code PreToolUse JSON on stdin.
- **Output**: Bootstrap writes JSON to stdout with `hookSpecificOutput.permissionDecision` (allow/deny).

Pipe name is derived from the workspace path (same algorithm as Cursor):  
Windows `\\.\pipe\airlock-ws-<hash>`, Unix `/tmp/airlock-ws-<hash>.sock`.

## Security

- The bootstrap script contains **no secrets**. It only forwards the hook payload to the pipe and returns the decision.
- All token handling, refresh, pairing, and gateway calls happen in the **daemon**. Credentials and pairing state are stored under `AIRLOCK_CONFIG_DIR` with restrictive file permissions.
- The daemon runs as a **detached OS process**, not a child of Claude Code. It survives if the hook runner exits.

## Development / worktree

This plugin was developed on branch `feature/claude-code-enforcer-plugin`. To create a worktree (from repo root, with hook approved or from a shell without the hook):

```bash
git worktree add -b feature/claude-code-enforcer-plugin ../airlock-claude-enforcer
```

Or run `scripts/create-claude-enforcer-worktree.cmd` from the repo root.

## References

- [Claude Code — Plugins reference](https://code.claude.com/docs/en/plugins-reference)
- [Claude Code — Hooks reference](https://code.claude.com/docs/en/hooks)
- [Claude Code — Automate workflows with hooks](https://code.claude.com/docs/en/hooks-guide)
- Cursor enforcer: `src/extensions/airlock-cursor-enforcer/` (same gateway protocol; daemon reuses the same concepts).

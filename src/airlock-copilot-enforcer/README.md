# Airlock Copilot Enforcer

**Human-in-the-loop control for GitHub Copilot agents.** Every tool call made by the Copilot agent (bash, file edits, MCP calls, etc.) requires an explicit allow or deny decision from your paired Airlock mobile approver before it executes.

> ⚠️ **Preview Feature:** GitHub Copilot agent hooks (`preToolUse`) are currently in preview. You need **VS Code 1.99 or later** and **GitHub Copilot Chat extension**. Ensure you are on the latest VS Code and Copilot Chat releases.

---

## How It Works

```
Copilot Agent → wants to use a tool → .github/hooks/airlock.json
                                               ↓
                                     Airlock Gate Script
                                               ↓
                                      Airlock Gateway
                                               ↓
                                     📱 Mobile Approver
                                               ↓
                                     Allow / Deny decision
                                               ↓
                              Tool executes  OR  Agent is blocked
```

## Quick Start

1. **Install** this extension in VS Code
2. **Configure endpoint** — open the Command Palette (`Ctrl+Shift+P`) → `Airlock: Configure Endpoint` → enter your Gateway URL (e.g. `http://localhost:5145`)
3. **Sign in** — `Airlock: Sign In`
4. **Pair mobile device** — `Airlock: Start Mobile Pairing` → scan QR code with the Airlock app
5. **Enable auto mode** — `Airlock: Enable Auto Mode`

The extension writes `.github/hooks/airlock.json` to your workspace. Commit this file to your repository's **default branch** for the Copilot Coding Agent to pick it up automatically.

The status bar shows the current state: `$(shield) Airlock ✓` when active.

## Requirements

| Requirement | Minimum version |
|---|---|
| VS Code | **1.99 or later** |
| GitHub Copilot Chat extension | **Latest** (hooks are a preview feature) |
| Node.js | **18 or later** (for the gate script) |

> ⚠️ GitHub Copilot agent hooks are a **preview** feature. Enable them via VS Code settings if not yet active.

## How Copilot Hooks Work

The extension installs `.github/hooks/airlock.json` (Copilot format):

```json
{
  "hooks": {
    "PreToolUse": [{
      "type": "command",
      "command": ".github/hooks/airlock-gate.cmd",
      "timeout": 60
    }]
  }
}
```

The gate script outputs a JSON decision:
- **Allow:** `{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow" } }`
- **Deny:** `{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..." } }`

The extension also installs `.github/rules/airlock.md` — a project rule that instructs the agent to cooperate with the hook and never bypass it.

## Files Created in Your Repository

| File | Purpose |
|---|---|
| `.github/hooks/airlock.json` | Copilot hooks configuration |
| `.github/hooks/airlock-gate.sh` | Unix gate wrapper |
| `.github/hooks/airlock-gate.cmd` | Windows CMD gate wrapper |
| `.github/hooks/airlock-hooks.log` | Diagnostic log (not committed) |
| `.github/rules/airlock.md` | Copilot behavioral rules |

> **Note:** Commit `airlock.json` and the gate scripts to your default branch. The `.log` file can be added to `.gitignore`.

## Commands

| Command | Description |
|---------|-------------|
| `Airlock: Enable Auto Mode` | Start automatic approval gating |
| `Airlock: Disable Auto Mode` | Stop gating |
| `Airlock: Configure Endpoint` | Set the Gateway URL |
| `Airlock: Start Mobile Pairing` | Pair with the Airlock mobile app (QR code) |
| `Airlock: Unpair Mobile Approver` | Remove paired device |
| `Airlock: Show Status` | Show current endpoint, enforcer ID, pairing state |
| `Airlock: Sign In` | Authenticate with the Gateway |
| `Airlock: Sign Out` | Clear authentication |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `airlock.diagnosticMode` | `false` | Enable verbose diagnostic logging. Default is off for production. |
| `airlock.autoApprovePatterns` | `[]` | Commands matching these patterns are auto-approved without Gateway. Supports literal substrings and `/regex/` patterns. |
| `airlock.approvalEndpoint` | `""` | Gateway URL (empty = auto-discover) |
| `airlock.approvalTimeoutSeconds` | `60` | Seconds to wait for mobile decision |
| `airlock.allowSelfSignedCerts` | `false` | Allow self-signed TLS certificates. Enable only for local Aspire dev. |

## Security

- **End-to-end encryption** — AES-256-GCM with X25519 ECDH key exchange
- **Signature verification** — Ed25519 for pairing integrity
- **Tamper-resistant gate** — Gate scripts and hooks config are set read-only; commands targeting them are auto-denied
- **Copilot rules** — `.github/rules/airlock.md` instructs the agent to cooperate with the hook and never bypass it
- **Timeout enforcement** — Configurable; default 60 seconds

## Platform Support

Windows ✅ · macOS ✅ · Linux ✅

---

*Published by Out Of Band Systems · [airlockapp.io](https://airlockapp.io) · Built on the [HARP Specification](https://harp-protocol.github.io)*

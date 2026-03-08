# Airlock Windsurf Enforcer

**Human-in-the-loop control for Windsurf Cascade AI agents.** Every terminal command and MCP tool call made by the Cascade agent requires an explicit allow or deny decision from your paired Airlock mobile approver before it executes.

> ⚠️ **Required Windsurf Setting:** Set Windsurf's terminal auto-execution mode to **"Auto Mode"** (recommended) for full approve/reject control. Turbo Mode fires the hook but does not enforce rejections. See [Required Windsurf Run Mode](#required-windsurf-run-mode) below.

---

## How It Works

```
Cascade Agent → wants to run command → Airlock Gate Script
                                               ↓
                                      Airlock Gateway
                                               ↓
                                     📱 Mobile Approver
                                               ↓
                                     Allow / Deny decision
                                               ↓
                              Command runs  OR  Agent is blocked
```

## Quick Start

1. **Install** this extension in Windsurf
2. **Configure endpoint** — open the Command Palette (`Ctrl+Shift+P`) → `Airlock: Configure Endpoint` → enter your Gateway URL (e.g. `http://localhost:5145`)
3. **Pair mobile device** — `Airlock: Start Mobile Pairing` → scan QR code with the Airlock app
4. **Enable auto mode** — `Airlock: Enable Auto Mode`

The status bar shows the current state: `$(shield) Airlock ✓` when active.

## Required Windsurf Run Mode

Windsurf's hooks mechanism only fires when the terminal auto-execution mode allows Cascade to run commands automatically.

**How to set it:** Windsurf Settings (gear icon, bottom-left) → Cascade → set **"Terminal command auto-execution"** to **"Auto Mode"** or **"Turbo Mode"**

| Run Mode | Hook behavior |
|---|---|
| **Auto Mode** ✅ | **Recommended.** Hook fires for Cascade-initiated commands. Both mobile approvals and rejections are fully enforced. |
| **Turbo Mode** ⚠️ | Hook fires for all commands; however, Windsurf does not enforce rejections in this mode. Approved commands proceed normally, but denied commands may still execute. Use Auto Mode for full approve/reject control. |
| **Allowlist Only** ⚠️ | Hook fires only for allowlisted commands. Non-listed commands bypass Airlock until added once via Windsurf's UI. |
| **Disabled** ❌ | Hooks are not invoked. Airlock cannot intercept anything. |

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
- **Tamper-resistant gate** — Gate script and hooks config are set read-only; commands targeting them are auto-denied
- **Windsurf rule** — `.windsurf/rules/airlock.md` instructs Cascade to cooperate with the hook and never bypass it
- **Circuit breaker** — 5 consecutive errors → auto-mode disables
- **Timeout enforcement** — Configurable; default 60 seconds

## Platform Support

Windows ✅ · macOS ✅ · Linux ✅

---

*Published by Out Of Band Systems · [airlockapp.io](https://airlockapp.io) · Built on the [HARP Specification](https://harp-protocol.github.io)*

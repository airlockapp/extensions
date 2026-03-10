# Airlock Cursor Enforcer

**Human-in-the-loop control for Cursor AI agents.** Every terminal command and MCP tool call made by the Cursor agent requires an explicit allow or deny decision from your paired Airlock mobile approver before it executes.

> ⚠️ **Required Cursor Setting:** To approve or reject commands from the Airlock mobile app, set Cursor's terminal run mode to **"Run Everything as Agent"** (Yolo mode). See [Required Cursor Run Mode](#required-cursor-run-mode) below.

---

## How It Works

```
Cursor Agent → wants to run command → Airlock Gate Script
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

1. **Install** this extension in Cursor
2. **Configure endpoint** — open the Command Palette (`Ctrl+Shift+P`) → `Airlock: Configure Endpoint` → enter your Gateway URL (e.g. `http://localhost:5145`)
3. **Pair mobile device** — `Airlock: Start Mobile Pairing` → scan QR code with the Airlock app
4. **Enable auto mode** — `Airlock: Enable Auto Mode`

The status bar shows the current state: `$(shield) Airlock ✓` when active.

> 💡 **After pairing**, click **"Reload Window"** in the notification that appears to activate hooks immediately without restarting Cursor.

## Required Cursor Run Mode

Cursor's hooks mechanism only fully respects the hook decision when run mode is set to **"Run Everything as Agent"**.

**How to set it:** Cursor Settings → Features → Agent / Terminal → set **Auto-run mode** to **"Run Everything as Agent"**

| Run Mode | Hook behavior |
|---|---|
| **Run Everything as Agent** ✅ | Hook fires for every command. Mobile approve/reject works reliably. |
| **Use Allowlist** ⚠️ | Hook fires only for allowlisted commands. Others bypass Airlock until added to the allowlist once via Cursor's UI. |
| **Ask / Manual** | Cursor's own dialog intercepts first; hook may not be invoked. |

## Commands

| Command | Description |
|---------|-------------|
| `Airlock: Enable Auto Mode` | Start automatic approval gating |
| `Airlock: Disable Auto Mode` | Stop gating |
| `Airlock: Configure Endpoint` | Set the Gateway URL |
| `Airlock: Start Mobile Pairing` | Pair with the Airlock mobile app (QR code) |
| `Airlock: Unpair Mobile Approver` | Remove paired device and notify the Gateway |
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
| `airlock.hookBeforeSubmitPrompt` | `false` | Enable the `beforeSubmitPrompt` hook — gates every prompt submission. Disabled by default (Cursor support is unreliable). |
| `airlock.hookStop` | `false` | Enable the `stop` hook for informational stop events. Disabled by default. |

## Security

- **End-to-end encryption** — AES-256-GCM with X25519 ECDH key exchange
- **Signature verification** — Ed25519 for pairing integrity
- **Tamper-resistant gate** — Gate script and hooks config are set read-only; commands targeting them are auto-denied
- **Fail-closed by default** — Gateway errors, timeouts, and unexpected payloads block the command
- **Fail-open for missing config** — If `AIRLOCK_GATEWAY_URL` or `AIRLOCK_ROUTING_TOKEN` are unset, commands are allowed (extension not yet configured)
- **Pairing revocation** — When you remove a pairing from the mobile app, the Gateway immediately invalidates the routing token and pushes a `pairing.revoked` event to this extension. Hooks go offline instantly with no IDE restart required.
- **Presence gating** — The extension only registers as "online" in the mobile app after pairing is complete. Unpaired workspaces are never visible.
- **Strict TLS by default** — Self-signed certificate bypass is disabled unless explicitly enabled via `airlock.allowSelfSignedCerts` (global setting).
- **Circuit breaker** — 3 consecutive errors → auto-mode disables
- **Timeout enforcement** — Configurable; default 60 seconds

## Changelog

### v0.3.0
- **Security hardening** — Verbose approval logs gated behind `diagnosticMode`; routing tokens masked in logs
- **TLS fix** — All HTTP clients now respect `allowSelfSignedCerts` setting
- **Diagnostic mode** — Approval request details only logged when `airlock.diagnosticMode` is enabled

## Platform Support

Windows ✅ · macOS ✅ · Linux ✅

---

*Published by Out Of Band Systems · [airlockapp.io](https://airlockapp.io) · Built on the [HARP Specification](https://harp-protocol.github.io)*

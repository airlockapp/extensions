# Airlock Antigravity Enforcer

**Human-in-the-loop control for Antigravity AI agents.** Every agent step requires an explicit allow or deny decision from your paired Airlock mobile approver before it executes.

---

## How It Works

The Antigravity Enforcer connects to the Antigravity IDE webview via the Chrome DevTools Protocol (CDP), detects pending agent approval prompts ("Accept Step?"), and routes them through the Airlock Gateway for mobile approval — automatically clicking Accept or Reject based on the mobile decision.

```
Antigravity Agent → "Accept Step?" prompt → CDP Handler
                                                 ↓
                                        Airlock Gateway
                                                 ↓
                                       📱 Mobile Approver
                                                 ↓
                                       Allow / Deny decision
                                                 ↓
                                 Accept clicked  OR  Reject clicked
```

## Prerequisites — Enable CDP (Remote Debugging Port)

The enforcer connects to Antigravity's webview via the Chrome DevTools Protocol. This requires the IDE to be launched with the `--remote-debugging-port` flag.

### Automatic Setup (Recommended)

On first activation the extension will **auto-relaunch** Antigravity with CDP enabled — no manual steps required. If the auto-relaunch is unsuccessful, a prompt will appear with the option to retry.

You can also trigger this manually via Command Palette → **`Airlock: Relaunch with CDP`**.

### Manual Setup

If the auto-relaunch doesn't work on your system, you can add the flag to your launch shortcut manually:

**Windows**
1. Right-click your **Antigravity** shortcut → **Properties**
2. In the **Target** field, append ` --remote-debugging-port=9000` after the `.exe"` path
3. Example: `"C:\Users\...\Antigravity.exe" --remote-debugging-port=9000`
4. Click **OK** and relaunch from this shortcut

**macOS**
1. Open **Terminal** and run:
   ```bash
   open -a "Antigravity" --args --remote-debugging-port=9000
   ```
2. Or create a wrapper script at `~/.local/bin/antigravity-cdp`:
   ```bash
   #!/bin/bash
   open -a "/Applications/Antigravity.app" --args --remote-debugging-port=9000 "$@"
   ```

**Linux**
1. Edit your `.desktop` file (usually `~/.local/share/applications/antigravity.desktop`)
2. Append `--remote-debugging-port=9000` to the `Exec=` line
3. Example: `Exec=/usr/bin/antigravity --remote-debugging-port=9000 %F`

> **Port conflicts:** If port 9000 is occupied, change the port in both the shortcut/launch command and the extension settings (`airlock.cdpPortStart`). The extension scans ports 9000–9030 by default.

## Quick Start

1. **Ensure CDP is enabled** — see [Prerequisites](#prerequisites--enable-cdp-remote-debugging-port) above (usually automatic)
2. **Configure endpoint** — Command Palette → `Airlock: Configure Endpoint` → enter your Gateway URL (e.g. `http://localhost:5145`)
3. **Pair mobile device** — `Airlock: Start Mobile Pairing` → scan QR code with the Airlock app
4. **Enable auto mode** — `Airlock: Enable Auto Mode`

The status bar shows the current state: `$(shield) Airlock ✓` when active.

## Commands

| Command | Description |
|---------|-------------|
| `Airlock: Enable Auto Mode` | Start automatic approval gating |
| `Airlock: Disable Auto Mode` | Stop gating |
| `Airlock: Relaunch with CDP` | Restart Antigravity with `--remote-debugging-port` enabled |
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
| `airlock.allowSelfSignedCerts` | `false` | Allow self-signed TLS certificates. Enable only for local Aspire dev. |
| `airlock.autoApprovePatterns` | `[]` | Commands matching these patterns are auto-approved without Gateway. Supports literal substrings and `/regex/` patterns. |
| `airlock.approvalEndpoint` | `""` | Gateway URL (empty = auto-discover) |
| `airlock.approvalTimeoutSeconds` | `60` | Seconds to wait for mobile decision |
| `airlock.pollInterval` | `500` | CDP detection polling interval (ms) |
| `airlock.cdpPortStart` | `9000` | Start of CDP port scan range |
| `airlock.cdpPortEnd` | `9030` | End of CDP port scan range |

## Security

- **End-to-end encryption** — AES-256-GCM with X25519 ECDH key exchange
- **Signature verification** — Ed25519 for pairing integrity
- **Circuit breaker** — 3 consecutive errors → auto-mode disables
- **Timeout enforcement** — Configurable; default 60 seconds
- **Delivery acknowledgment** — After receiving a decision, the extension sends a fire-and-forget `POST /v1/acks` to confirm delivery to the gateway

## Changelog

### v0.3.0
- **Security hardening** — Routing tokens no longer logged in plaintext; verbose approval logs gated behind `diagnosticMode`
- **TLS fix** — All HTTP clients now respect `allowSelfSignedCerts` setting (previously some were hardcoded to accept self-signed certs)
- **Diagnostic mode** — Approval request details (requestId, commandText, routing info) only logged when `airlock.diagnosticMode` is enabled

## Platform Support

Windows ✅ · macOS ✅ · Linux ✅

---

*Published by Out Of Band Systems · [airlockapp.io](https://airlockapp.io) · Built on the [HARP Specification](https://harp-protocol.github.io)*

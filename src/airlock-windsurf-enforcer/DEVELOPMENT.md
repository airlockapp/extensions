# Airlock Windsurf Enforcer — Developer Reference

> **Engine requirement:** `^1.85.0` — compatible with Windsurf and standard VS Code.

## Architecture

The Windsurf Enforcer uses **Windsurf Cascade Hooks** (`pre_run_command`, `pre_mcp_tool_use`) to intercept agent actions before they execute. A standalone Node.js gate script handles the approval flow independent of the extension runtime.

```
Cascade Agent ─── wants to run command ──→ hooks.json
                                               │
                                      spawns gate script
                                               │
                                     ┌─────────┴──────────┐
                                     │  hooksGateScript.js │
                                     │  (reads stdin JSON) │
                                     └─────────┬──────────┘
                                               │
                                    POST /v1/artifacts
                                               │
                                       Airlock Gateway
                                               │
                                     Long-poll for decision
                                               │
                                     ┌─────────┴──────────┐
                                   allow                 deny
                                     │                     │
                               exit code 0           exit code 2
                                     │                     │
                              Cascade executes       Cascade blocks +
                               the command           shows message to LLM
```

## Gate Script Protocol

The gate script (`hooksGateScript.js`) receives a JSON payload from Windsurf via **stdin** and exits with a code:

**Input** (stdin from Windsurf — `pre_run_command`):
```json
{
  "agent_action_name": "pre_run_command",
  "tool_info": { "command_line": "npm install", "cwd": "/path/to/project" }
}
```

**Input** (stdin from Windsurf — `pre_mcp_tool_use`):
```json
{
  "agent_action_name": "pre_mcp_tool_use",
  "tool_info": { "mcp_server_name": "github", "mcp_tool_name": "create_issue", "mcp_tool_arguments": {} }
}
```

**Exit codes:**
- `0` — allow the action
- `2` — block the action (Cascade will show the `agent_message` to the LLM)

## Platform Wrappers

Environment variables are injected into the gate script via platform-specific wrappers:

| Platform | Wrapper | Mechanism |
|----------|---------|-----------| 
| **Windows** | `airlock-gate.cmd` | `@echo off` + `set VAR=val` + `node gate.js` |
| **Linux/macOS** | `airlock-gate.sh` | `#!/bin/sh` + `export VAR='val'` + `exec node gate.js` |

Both wrappers are written as **read-only** files to prevent agent tampering.

## Environment Variables (Gate Script)

| Variable | Source | Purpose |
|----------|--------|---------|
| `AIRLOCK_GATEWAY_URL` | Endpoint resolver | Gateway HTTP endpoint |
| `AIRLOCK_ROUTING_TOKEN` | Pairing flow | Routes approval to correct mobile approver |
| `AIRLOCK_AUTO_APPROVE` | `airlock.autoApprovePatterns` | Pipe-separated patterns for auto-approval bypass |
| `AIRLOCK_ENFORCER_ID` | Auto-generated UUID | Identifies this enforcer instance |
| `AIRLOCK_TIMEOUT_SECONDS` | `airlock.approvalTimeoutSeconds` | Max wait for mobile approval |
| `AIRLOCK_WORKSPACE_NAME` | VS Code workspace | Displayed in mobile approval UI |
| `AIRLOCK_LOG_FILE` | Computed | Path for gate script diagnostic logs |

## Routing Token Lifecycle

1. **Pairing initiated** — Extension calls `POST /v1/pairing/initiate` → Gateway returns `pairingNonce` + `pairingCode`
2. **QR code displayed** — User scans QR code with Airlock mobile app
3. **Mobile completes pairing** — App sends Ed25519 public key + X25519 key exchange to Gateway
4. **Gateway returns routing token** — Extension polls `GET /v1/pairing/{nonce}/status` → `PairingStatus.routingToken`
5. **Token stored** — `storeRoutingToken()` saves to VS Code `workspaceState` (per-workspace)
6. **Token injected** — `hooksStrategy.ts` reads via `getRoutingToken()`, sets `AIRLOCK_ROUTING_TOKEN` env var
7. **Token used** — Gate script includes it in `POST /v1/artifacts` requests

The token is **opaque** — the extension never interprets its contents.

## Project Structure

```
airlock-windsurf-enforcer/src/
├── extension.ts         # Main entry, command registration, lifecycle
├── hooksStrategy.ts     # Windsurf hooks installation & management
├── hooksGateScript.js   # Standalone gate script (reads Windsurf stdin JSON)
├── approvalClient.ts    # HARP artifact submission & polling
├── crypto.ts            # AES-256-GCM encryption, X25519 ECDH, Ed25519 verify
├── pairingClient.ts     # Pairing session HTTP client
├── pairingPanel.ts      # QR code webview panel for mobile pairing
├── deviceAuth.ts        # OAuth2 device authorization flow
├── presenceClient.ts    # WebSocket presence tracking
├── autoMode.ts          # Auto-mode polling, debounce, circuit breaker
├── endpointResolver.ts  # Gateway URL discovery
├── statusBar.ts         # Status bar indicators
└── detectionStrategy.ts # Detection strategy interface
```

## Build & Development

```bash
cd src/airlock-windsurf-enforcer
npm install
npm run compile    # TypeScript → out/ + copies hooksGateScript.js
npm run watch      # Watch mode for development
npm run lint       # ESLint
```

### Packaging

```bash
npx @vscode/vsce package --allow-missing-repository
```

Or use the project-level build scripts:

```powershell
# Build all enforcers (dev + prod VSIX packages)
.\build-extensions.ps1 -Mode all

# Build only prod
.\build-enforcers.ps1 -Mode prod
```

Dev packages are named with `-dev` suffix (e.g., `airlock-windsurf-enforcer-dev-0.1.0.vsix`) and placed in `extensions_dist/dev/`. Prod packages go to `extensions_dist/prod/`.

### Dependencies

**Runtime:** `ws` (WebSocket), `qrcode` (QR code generation)  
**Dev:** TypeScript, ESLint, VS Code test framework

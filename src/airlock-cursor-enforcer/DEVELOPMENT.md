# Airlock Cursor Enforcer — Developer Reference

> **Engine requirement:** `^1.85.0` — compatible with Cursor and standard VS Code.

## Architecture

The Cursor Enforcer uses **Cursor Hooks** (`beforeShellExecution`, `beforeMCPExecution`) to intercept agent actions before they execute. A standalone Node.js gate script handles the approval flow independent of the extension runtime.

```
Cursor Agent ─── wants to run command ──→ hooks.json
                                              │
                                     spawns gate script
                                              │
                                    ┌─────────┴──────────┐
                                    │  hooksGateScript.js │
                                    │  (reads stdin JSON) │
                                    └─────────┬──────────┘
                                              │
                                   POST /v1/approve/submit
                                              │
                                      Airlock Gateway
                                              │
                                    Long-poll for decision
                                              │
                                    ┌─────────┴──────────┐
                                  allow                 deny
                                    │                     │
                            stdout: JSON              stdout: JSON
                          permission:"allow"        permission:"deny"
                                    │                     │
                             Cursor executes       Cursor blocks + shows
                              the command           agent_message to LLM
```

## Gate Script Protocol

The gate script (`hooksGateScript.js`) communicates with Cursor via **stdin/stdout JSON**:

**Input** (stdin from Cursor):
```json
{
  "command": "npm install",
  "cwd": "/path/to/project"
}
```

**Output** (stdout to Cursor):
```json
{
  "continue": true,
  "permission": "allow|deny|ask",
  "user_message": "Optional message shown to user",
  "agent_message": "Optional message injected into agent context"
}
```

- `continue: true` — **required** in every response per Cursor hooks spec
- `permission: "allow"` — let the command execute
- `permission: "deny"` — block the command
- `permission: "ask"` — show the user a confirmation dialog
- Exit code `0` — use JSON output; exit code `2` — force deny; other — fail-open

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
7. **Token used** — Gate script includes it in `POST /v1/approve/submit` requests

The token is **opaque** — the extension never interprets its contents.

## Project Structure

```
airlock-cursor-enforcer/src/
├── extension.ts         # Main entry, command registration, lifecycle
├── hooksStrategy.ts     # Cursor hooks installation & management
├── hooksGateScript.js   # Standalone gate script (stdin/stdout JSON)
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
cd src/airlock-cursor-enforcer
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

Dev packages are named with `-dev` suffix (e.g., `airlock-cursor-enforcer-dev-0.1.0.vsix`) and placed in `extensions_dist/dev/`. Prod packages go to `extensions_dist/prod/`.

### Dependencies

**Runtime:** `ws` (WebSocket), `qrcode` (QR code generation)  
**Dev:** TypeScript, ESLint, VS Code test framework

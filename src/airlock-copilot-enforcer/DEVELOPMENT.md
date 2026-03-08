# Airlock Copilot Enforcer — Developer Reference

> **Engine requirement:** `^1.99.0` — requires VS Code 1.99+ for Copilot agent hooks support.

## Architecture

The Copilot Enforcer uses **GitHub Copilot Agent Hooks** (`PreToolUse`) to intercept tool calls before they execute. A standalone Node.js gate script handles the approval flow independent of the extension runtime.

```
Copilot Agent ─── wants to use a tool ──→ .github/hooks/airlock.json
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
                              JSON output to stdout   stderr + exit 2
                           permissionDecision:"allow"
                                      │                     │
                               Copilot executes       Copilot blocks +
                                the tool call         shows reason to LLM
```

## Gate Script Protocol

The gate script (`hooksGateScript.js`) communicates with Copilot via **stdin/stdout JSON**, following the [VS Code Agent Hooks specification](https://code.visualstudio.com/docs/copilot/customization/hooks).

**Input** (stdin from Copilot — `PreToolUse`):
```json
{
  "hookEventName": "PreToolUse",
  "tool_name": "bash",
  "tool_input": { "command": "npm install", "cwd": "/path/to/project" },
  "tool_use_id": "tool-123",
  "cwd": "/path/to/workspace",
  "sessionId": "session-identifier",
  "timestamp": "2026-02-09T10:30:00.000Z",
  "transcript_path": "/path/to/transcript.json"
}
```

**Output — Approve** (stdout to Copilot):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow"
  }
}
```

**Output — Deny**: Exit code 2 + rejection message written to stderr. No JSON on stdout.

**How tool types are distinguished:**
Copilot uses `tool_name` to identify the tool being called. Common values include:
- `bash` — terminal/shell commands (`tool_input.command` has the command line)
- `editFiles` — file editing (`tool_input.file_path` or `tool_input.files`)
- `readFile` — file reading
- `listFiles`, `searchFiles` — file search/listing

The `tool_input` format varies by tool. For `bash`, it's `{ command, cwd }`. For file tools, it's `{ file_path, ... }`.

## Hook File Location

Copilot hooks live in the **repository**, not the user config directory:

| File | Purpose |
|---|---|
| `.github/hooks/airlock.json` | Copilot hooks configuration |
| `.github/hooks/airlock-gate.sh` | Unix gate wrapper |
| `.github/hooks/airlock-gate.cmd` | Windows CMD gate wrapper |
| `.github/hooks/airlock-hooks.log` | Diagnostic log (not committed) |
| `.github/rules/airlock.md` | Copilot behavioral rules — instructs agent to cooperate |

> **Commit `airlock.json`, gate scripts, and `airlock.md`** to the default branch for the Copilot Coding Agent to pick up automatically.

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
| `AIRLOCK_PIPE_NAME` | Named pipe proxy | IPC pipe for Gateway communication |
| `AIRLOCK_LOCAL_SECRET` | Per-session random | Authenticates gate script to named pipe proxy |
| `AIRLOCK_ROUTING_TOKEN` | Pairing flow | Routes approval to correct mobile approver |
| `AIRLOCK_AUTO_APPROVE` | `airlock.autoApprovePatterns` | Pipe-separated patterns for auto-approval bypass |
| `AIRLOCK_ENFORCER_ID` | Auto-generated UUID | Identifies this enforcer instance |
| `AIRLOCK_TIMEOUT_SECONDS` | `airlock.approvalTimeoutSeconds` | Max wait for mobile approval |
| `AIRLOCK_WORKSPACE_NAME` | VS Code workspace | Displayed in mobile approval UI |
| `AIRLOCK_LOG_FILE` | Computed | Path for gate script diagnostic logs |

## Named Pipe Proxy

Unlike direct HTTP to the Gateway, the gate script communicates through a **named pipe proxy** running inside the extension host:

1. Extension starts a named pipe server (`\\.\pipe\airlock-<uuid>` on Windows, `/tmp/airlock-<uuid>.sock` on Unix)
2. Gate script connects to the pipe and sends HTTP-like requests
3. Proxy forwards to the Gateway with the user's auth token (not available to the gate script)
4. Responses flow back through the pipe

This design keeps auth tokens inside the extension process and out of environment variables.

## Self-Protection

The gate script blocks any tool calls that target Airlock hook files:
- `airlock.json`, `hooks.json`, `airlock-gate.cmd`, `airlock-gate.sh`, `hooksGateScript.js`, `airlock-hooks.log`, `airlock.md`

Any command, file path, or tool input referencing these patterns is auto-denied with exit code 2.

## Routing Token Lifecycle

1. **Pairing initiated** — Extension calls `POST /v1/pairing/initiate` → Gateway returns `pairingNonce` + `pairingCode`
2. **QR code displayed** — User scans QR code with Airlock mobile app
3. **Mobile completes pairing** — App sends Ed25519 public key + X25519 key exchange to Gateway
4. **Gateway returns routing token** — Extension polls `GET /v1/pairing/{nonce}/status` → `PairingStatus.routingToken`
5. **Token stored** — `storeRoutingToken()` saves to VS Code `workspaceState` (per-workspace)
6. **Token injected** — `hooksStrategy.ts` reads via `getRoutingToken()`, sets `AIRLOCK_ROUTING_TOKEN` env var in wrapper
7. **Token used** — Gate script sends it in `POST /v1/artifacts` metadata

The token is **opaque** — the extension never interprets its contents.

## Fail Behavior

| Scenario | Behavior | Rationale |
|---|---|---|
| Pipe name not set | **Fail open** (allow) | Extension not configured yet |
| Local secret not set | **Fail open** (allow) | Extension not configured yet |
| Pipe connection error | **Fail open** (allow) | Gateway not running |
| 503 from proxy | **Fail open** (allow) | User not signed in |
| 401 from proxy | **Fail closed** (deny) | Wrong secret — security boundary |
| 403 (quota) | **Fail open** (allow) | Plan limit only, not security |
| 403 (other) | **Fail closed** (deny) | Pairing revoked or security error |
| Timeout | **Fail closed** (deny) | No approver responded |
| stdin parse error | **Fail closed** (deny) | Unknown payload format |

## Project Structure

```
airlock-copilot-enforcer/src/
├── extension.ts         # Main entry, command registration, lifecycle
├── hooksStrategy.ts     # Copilot hooks installation & management
├── hooksGateScript.js   # Standalone gate script (stdin/stdout JSON, Copilot protocol)
├── namedPipeProxy.ts    # Named pipe IPC server for gate script ↔ Gateway
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
cd src/extensions/airlock-copilot-enforcer
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

Dev packages are named with `-dev` suffix (e.g., `airlock-copilot-enforcer-dev-0.1.0.vsix`) and placed in `extensions_dist/dev/`. Prod packages go to `extensions_dist/prod/`.

### Dependencies

**Runtime:** `ws` (WebSocket), `qrcode` (QR code generation)  
**Dev:** TypeScript, ESLint, VS Code test framework

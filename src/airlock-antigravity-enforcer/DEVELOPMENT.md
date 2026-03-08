# Airlock Antigravity Enforcer — Developer Reference

> **Engine requirement:** `^1.107.0` — matches Antigravity's current VS Code engine version.

## Architecture

The Antigravity Enforcer connects to the Antigravity IDE webview via the **Chrome DevTools Protocol (CDP)**, detects pending agent approval prompts, and intercepts them by routing through the Airlock Gateway for mobile approval.

Unlike the Cursor, Windsurf, and Copilot enforcers — which use native IDE hooks — Antigravity does not provide a hooks API. Instead, the extension:
1. Launches Antigravity with `--remote-debugging-port`
2. Connects to the webview via CDP WebSocket
3. Injects a DOM observer script to detect approval buttons
4. Routes detected approvals through the Gateway
5. Programmatically clicks Accept/Reject based on mobile decision

```
Antigravity Agent ─── "Accept Step?" prompt ──→ CDP Handler (cdpHandler.ts)
                                                      │
                                               detects pending button
                                                      │
                                              Auto Mode Controller
                                                      │
                                           POST /v1/approve/submit
                                                      │
                                              Airlock Gateway
                                                      │
                                            ┌─────────┴──────────┐
                                          allow                 deny
                                            │                     │
                                    executeApproval()      executeRejection()
                                    (clicks Accept)        (clicks Reject)
```

## CDP Detection

The extension connects to Antigravity's Electron webview via CDP, injects JavaScript to detect accept/reject buttons, and programmatically clicks them on approval.

**How it works:**
1. Scans ports `9000–9030` for CDP endpoints (`GET /json`)
2. Matches the correct VS Code window by walking the process tree (`PID → PPID` chain)
3. Connects via WebSocket to the agent webview page
4. Injects `cdpScript.js` — monitors DOM for pending approval buttons
5. Reports detected buttons via `Runtime.evaluate` polling
6. On approval: evaluates `window.__airlock_clickAccept()` to click the Accept button
7. On rejection: evaluates `window.__airlock_clickReject()` to click Reject/Cancel/Skip

**Platform support for port-to-PID mapping:**
- **Windows:** `netstat -ano` for port mapping, `wmic` for process tree walking
- **macOS/Linux:** `lsof` for port mapping, `ps` for process tree walking

**Requirement:** Antigravity must be launched with `--remote-debugging-port=<port>`. The extension can relaunch with this flag via the `airlock.relaunch` command.

## Key Differences from Hooks-Based Enforcers

| Aspect | Cursor / Windsurf / Copilot | Antigravity |
|---|---|---|
| **Interception** | Native IDE hooks (stdin/stdout JSON or exit codes) | CDP DOM observer (injected JavaScript) |
| **Gate Script** | Standalone `hooksGateScript.js` process | Not used — approval goes through in-process `approvalClient.ts` |
| **Button Clicks** | IDE executes command automatically | Extension clicks DOM buttons via `Runtime.evaluate` |
| **Port Requirement** | None | Must launch with `--remote-debugging-port` |
| **Session Isolation** | Per-hook-invocation (environment variables) | Per-CDP-session (PID + session ID matching) |
| **Auto-approve** | Gate script checks `AIRLOCK_AUTO_APPROVE` env var | `approvalClient.ts` checks `autoApprovePatterns` setting |

## Approval Flow

1. **CDP script** detects a pending button → fires `onPendingDetected` event
2. **AutoModeController** receives the event → calls `requestApproval()` in `approvalClient.ts`
3. **approvalClient.ts** builds a HARP `artifact.submit` envelope → `POST /v1/artifacts` to the Gateway
4. **Long-poll** on `GET /v1/exchanges/{requestId}/wait` for mobile decision
5. On **approve** → `strategy.executeApproval(pending)` → CDP clicks the Accept button
6. On **reject** → `strategy.executeRejection(pending)` → CDP clicks the Reject button

## Fail Behavior

| Scenario | Behavior | Rationale |
|---|---|---|
| CDP not available | **Prompt relaunch** | User must restart with `--remote-debugging-port` |
| No endpoint | **Pause** | Gateway URL not configured |
| Gateway error (3xx) | **Retry** (up to 5) | Transient network issue |
| Quota exceeded (403/429) | **Fail open** (auto-approve) | Plan limit only, not security |
| Pairing revoked (403) | **Fail closed** (deny) | Security boundary |
| 5 consecutive errors | **Auto-disable** | Circuit breaker — check endpoint |
| Approval timeout | **Block** | No approver responded |

## Routing Token Lifecycle

1. **Gateway generates** `AIRLOCK_ROUTING_TOKEN` during the pairing completion response
2. **Stored** in VS Code `workspaceState` (per-workspace, survives restarts)
3. **Retrieved** by `approvalClient.ts` and included in every approval submission request
4. **Opaque** — routes the approval decision back to the correct paired mobile device

## TLS Configuration

`allowSelfSignedCerts` setting controls `NODE_TLS_REJECT_UNAUTHORIZED`:
- **Default (`false`):** Standard certificate validation — connections to Aspire dev certs will fail
- **Enabled (`true`):** Bypasses certificate validation — **only for local development**

> **Note:** `endpointResolver.ts` and `pairingClient.ts` always use `rejectUnauthorized: false` for local endpoint probing. This is intentional — probing is local-only and never carries auth tokens.

## Project Structure

```
airlock-antigravity-enforcer/src/
├── extension.ts          # Main entry, commands, CDP wiring, lifecycle
├── detectionStrategy.ts  # DetectionStrategy interface + PendingApproval type
├── cdpHandler.ts         # CDP: WebSocket, JS injection, button detection, process tree
├── cdpScript.js          # Injected JS: DOM observer for accept/reject buttons
├── relauncher.ts         # Relaunch Antigravity with --remote-debugging-port
├── approvalClient.ts     # HARP artifact submission & polling
├── crypto.ts             # AES-256-GCM encryption, X25519 ECDH, Ed25519 verify
├── pairingClient.ts      # Pairing session HTTP client
├── pairingPanel.ts       # QR code webview panel for mobile pairing
├── deviceAuth.ts         # OAuth2 device authorization flow
├── presenceClient.ts     # WebSocket presence tracking
├── autoMode.ts           # Auto-mode controller: event routing, circuit breaker
├── endpointResolver.ts   # Gateway URL discovery
└── statusBar.ts          # Status bar indicators
```

## Build & Development

```bash
cd src/extensions/airlock-antigravity-enforcer
npm install
npm run compile    # TypeScript → out/ + copies cdpScript.js
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

Dev packages are named with `-dev` suffix (e.g., `airlock-antigravity-enforcer-dev-0.1.0.vsix`) and placed in `extensions_dist/dev/`. Prod packages go to `extensions_dist/prod/`.

### Dependencies

**Runtime:** `ws` (WebSocket for CDP + presence), `qrcode` (QR code generation)  
**Dev:** TypeScript, ESLint, VS Code test framework

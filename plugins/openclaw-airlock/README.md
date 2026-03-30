# Airlock Plugin for OpenClaw

Enforces human-in-the-loop approval for risky AI tool actions via the [Airlock Gateway](https://airlockapp.io).

**Airlock Approver** (mobile app): [App Store](https://apps.apple.com/us/app/airlock-approver/id6760250865) · [Google Play](https://play.google.com/store/apps/details?id=com.airlockapp.io)

## Features

- **Tool-based approval** — AI calls `airlock_request_approval` for explicit approval
- **Hook-based enforcement** — Automatically intercepts protected tool executions
- **Polling-based decisions** — Long-polls the gateway for approver decisions
- **Pre-generated pairing** — X25519 ECDH key exchange with mobile approver app
- **Decision signature verification** — Ed25519 signatures prevent forgery
- **DND (Do Not Disturb)** — Auto-approves when DND policies are active
- **Presence heartbeat** — Mobile app shows enforcer online/offline status
- **State persistence** — Pairing state survives restarts (`.airlock/pairing-state.json`)
- **Fail modes** — Configurable fail-open or fail-closed on timeout/errors

---

## Installation

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **OpenClaw** | An OpenClaw-compatible AI agent runtime |
| **Node.js** | Version 18 or later (`node --version`) |
| **Airlock Gateway** | Access to an Airlock Integrations Gateway (default: `igw.airlocks.io`) |
| **Airlock Mobile App** | For approving/denying actions and generating pairing codes |
| **Airlock Developer Account** | Required to create an Enforcer App and get API credentials (see below) |
| **Personal Access Token (PAT)** | Created from the Platform or Mobile App (Settings → Access Tokens) |

### Step 1 — Join the Airlock Developer Programme

Before you can create an enforcer app, you must register as a developer.

1. **Sign in** to the [Airlock Platform](https://platform.airlocks.io) with your Airlock account.
2. Navigate to **Developer Programme** in the sidebar.
3. Fill in the application form.
4. **Submit** your application. An Airlock administrator will review it.
5. Once **Approved**, you can create enforcer apps.

> For the full walkthrough with field descriptions and application states, see the [Airlock Developer Guide](https://airlockapp.io/docs/developer-guide/).

### Step 2 — Create an Enforcer App

Once approved, create an app from **Developer Programme → My Apps** in the Platform web UI.

| Field | Value |
|-------|-------|
| **Name** | Your app name (e.g. "My OpenClaw Enforcer"). Must be unique. Max 128 characters. |
| **Kind** | Select **Agent** (confidential client — authenticates via Client ID + Client Secret) |
| **Is Open Source** | Whether your enforcer source code is public |
| **Description** | What your app does (max 2000 chars) |

On creation, you receive:

| Credential | Description |
|------------|-------------|
| **App ID** | Human-readable identifier (format: `ABC-1234567`) |
| **Client ID** | 20-character alphanumeric string (used in plugin config) |
| **Client Secret** | 40-character secret (**shown only once** — copy and save it!) |

> ⚠️ **Save the Client Secret immediately.** You cannot retrieve it later. You can rotate it from the Platform UI, but the old secret is invalidated.

### Step 3 — Create a Personal Access Token (PAT)

The plugin authenticates as a user via a **Personal Access Token**.

1. In the **Airlock Platform App** (Settings → Access Tokens) or the **Mobile Approver** app, create a new token.
2. Set an appropriate expiry (max 1 year).
3. Copy the token (prefixed with `airpat_`).

The token identifies which user the enforcer acts on behalf of.

### Step 4 — Generate a Pre-Generated Pairing Code

The OpenClaw plugin uses **pre-generated pairing codes** (approver-initiated) instead of interactive pairing. This means the approver creates the code first, and you paste it into the plugin config.

**From the Mobile Approver app:**

1. Open the **Airlock** mobile app on your phone.
2. Tap the **"+"** button or go to **Workspaces → Add Workspace**.
3. Select **"Generate Code"** (pre-generated pairing).
4. The app shows a **6-character pairing code** (e.g. `A3K9X2`).
5. Copy or note this code — you'll paste it into your plugin config.

> ⏱️ **Time limit**: Pre-generated codes expire after **30 minutes**. Complete plugin setup within this window.

The code is in **Pending** state until an enforcer claims it. You can see its status in the mobile app.

### Step 5 — Install the Plugin

```bash
# From your OpenClaw workspace
openclaw plugins install ./openclaw-airlock
```

Or, if developing locally:

```bash
# Build from source
cd src/extensions/plugins/openclaw-airlock
npm install
npm run build
```

### Step 6 — Configure the Plugin

Add to your OpenClaw plugin config:

```json
{
  "plugins": {
    "entries": {
      "airlock": {
        "enabled": true,
        "config": {
          "gatewayUrl": "https://igw.airlocks.io",
          "enforcerId": "my-enforcer-001",
          "pat": "airpat_your_token_here",
          "clientId": "ABCDEFGHJKLMNPRSTUVWXYZabc",
          "clientSecret": "abcdEFGH1234567890abcdEFGH1234567890abcd",
          "pairingCode": "A3K9X2",
          "workspaceName": "My AI Workspace",
          "failMode": "closed",
          "protectedTools": ["shell.exec", "deploy.run"],
          "timeoutMs": 300000,
          "executionMode": "poll"
        }
      }
    }
  }
}
```

### Config Reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `gatewayUrl` | ✓ | — | Airlock Integrations Gateway URL (use `https://igw.airlocks.io` for production) |
| `enforcerId` | ✓ | — | Unique enforcer instance identifier (your choice, e.g. `oc-prod-001`) |
| `pat` | ✓* | — | Personal Access Token (`airpat_...`) |
| `clientId` | ✓* | — | Enforcer App Client ID (from Step 2) |
| `clientSecret` | ✓* | — | Enforcer App Client Secret (from Step 2) |
| `pairingCode` | — | — | Pre-generated pairing code from mobile app (from Step 4) |
| `workspaceName` | — | "OpenClaw Workspace" | Human-readable workspace name shown in mobile app |
| `timeoutMs` | — | 300000 | Approval timeout in ms (default: 5 min) |
| `pollIntervalMs` | — | 3000 | Decision poll interval in ms (min 1000) |
| `failMode` | — | "closed" | `"open"` = allow on timeout, `"closed"` = block |
| `protectedTools` | — | [] | Tool names requiring approval (empty = none) |
| `executionMode` | — | "poll" | `"poll"` (only mode available) |

> *`pat` is required for user identity. At least `clientId` **or** `pat` is required for authentication.

### Step 7 — Pair and Verify

Once configured, run the setup and pairing commands:

```bash
# Validate config and test gateway connectivity
openclaw airlock setup

# Claim the pre-generated pairing code (X25519 ECDH key exchange)
openclaw airlock pair

# Check everything is connected
/airlock-status
```

The `airlock pair` command:
1. Generates an X25519 keypair for end-to-end encryption
2. Claims the pre-generated code with the gateway
3. Polls until the mobile app completes the pairing
4. Derives the shared AES-256-GCM encryption key via ECDH + HKDF-SHA256
5. Stores the approver's Ed25519 public key for decision verification
6. Persists all state to `.airlock/pairing-state.json`

> 🔒 The `.airlock/` directory is automatically gitignored. It contains secrets (encryption key, routing token) that must not be committed.

### Step 8 — You're Ready!

After pairing, the plugin is fully operational:

- **Protected tools** are automatically intercepted and require mobile approval
- **Presence heartbeat** keeps the mobile app showing your workspace as online
- **State persists** across restarts — no need to re-pair

---

## Usage

### Automatic Enforcement (Hook)

Configure `protectedTools` to automatically intercept tool executions:

```json
{
  "protectedTools": ["shell.exec", "deploy.run", "database.query"]
}
```

Any tool matching these names will require mobile approval before executing. Supports glob patterns (e.g. `shell.*` matches `shell.exec`, `shell.run`).

When a DND (Do Not Disturb) policy is active, protected tools are auto-approved silently.

### Explicit Approval (Tool)

The AI agent can explicitly request approval using the `airlock_request_approval` tool:

```
Action: deploy to production
Reason: User requested deployment of v2.1.0
```

This tool also respects DND policies.

### Status Check (Tool)

Check the status of a previous approval request using `airlock_check_status`:

```
Request ID: req-abc123
```

### Slash Command

Use `/airlock-status` in chat to see the current status including:
- Gateway connectivity
- Pairing status and state file info
- Encryption key availability
- Protected tools list

---

## Fail Modes

| Scenario | `failMode: "closed"` | `failMode: "open"` |
|----------|----------------------|---------------------|
| Approval timeout | ✗ Block | ✓ Allow |
| Gateway unreachable | ✗ Block | ✓ Allow |
| Network error | ✗ Block | ✓ Allow |
| Pairing revoked | ✗ Block (always) | ✗ Block (always) |
| No approver (stale) | ✗ Block (always) | ✗ Block (always) |
| Quota exceeded | ✗ Block (always) | ✗ Block (always) |

---

## Security

### End-to-End Encryption

All approval requests are encrypted using AES-256-GCM. The encryption key is derived via:
1. X25519 ECDH key exchange during pairing
2. HKDF-SHA256 key derivation with info `"HARP-E2E-AES256GCM"`

The gateway never sees the plaintext — it only routes encrypted artifacts.

### Decision Signature Verification

Approver decisions are signed with Ed25519. The plugin verifies signatures using the approver's public key stored during pairing. Canonical format: `${artifactHash}|${decision}|${nonce}`. Unsigned decisions are accepted; decisions with invalid signatures are rejected.

### State Storage

| Data | Location |
|------|----------|
| Routing token | `.airlock/pairing-state.json` |
| Encryption key (AES-256-GCM) | `.airlock/pairing-state.json` |
| Approver public keys | `.airlock/pairing-state.json` |
| Pairing timestamp | `.airlock/pairing-state.json` |

> ⚠️ **Security**: The `.airlock/` directory is gitignored by default. If you move or copy the project, ensure the state file is protected and not committed to version control.

---

## Troubleshooting

### "Not paired — run 'airlock pair' first"
- Make sure `pairingCode` is set in config.
- Generate a new code if the previous one expired (30-min TTL).
- Run `openclaw airlock pair`.

### "No approver available — pairing may be stale"
- The pairing was revoked from the mobile app.
- Generate a new pre-generated code and run pair again.

### "Access denied: pairing_revoked"
- The mobile app user revoked the pairing.
- The plugin automatically clears stale pairing state.
- Generate a new code and run `openclaw airlock pair`.

### "Approval timed out"
- The approver didn't respond within the timeout period.
- Increase `timeoutMs` if needed, or check if the approver's mobile app is reachable.

### Plugin not intercepting tools
- Check that `protectedTools` includes the tool names you want to gate.
- An empty `protectedTools` array means no automatic enforcement (opt-in model).
- Use the `airlock_request_approval` tool for explicit control.

### Gateway unreachable
- Verify the `gatewayUrl` is correct (`https://igw.airlocks.io` for production).
- Run `openclaw airlock setup` to test connectivity.
- Check network/firewall settings.

---

## Development

```bash
npm install
npm run build        # Compile TypeScript
npm run dev          # Watch mode
npm run typecheck    # Type-check without emitting
```

### Project Structure

```
src/extensions/plugins/openclaw-airlock/
  openclaw.plugin.json          # OpenClaw manifest + config schema
  package.json                  # NPM package with SDK dependency
  tsconfig.json                 # TypeScript ESM config
  .gitignore                    # Excludes .airlock/, dist/, node_modules/

  src/
    index.ts                    # Plugin entry — registers all capabilities
    config.ts                   # Config parsing, validation, defaults
    client.ts                   # Gateway SDK wrapper: approval, pairing, heartbeat, DND
    crypto.ts                   # X25519 ECDH key exchange + Ed25519 signature verification
    state.ts                    # Pairing state persistence (.airlock/pairing-state.json)

    tools/
      requestApproval.ts        # AI-callable tool: explicit approval request
      checkStatus.ts            # AI-callable tool: check exchange status

    hooks/
      beforeTool.ts             # Automatic tool interception hook (+ DND check)

    commands/
      airlockStatus.ts          # /airlock-status diagnostic command

    cli/
      setup.ts                  # `airlock setup` — validate config + connectivity
      pair.ts                   # `airlock pair` — claim pre-generated code
```

---

## Architecture

```
┌───────────────────┐    HTTPS     ┌──────────────────────────┐
│  OpenClaw Agent    │ ──────────→ │  Integrations Gateway     │
│  + Airlock Plugin  │ ←────────── │  (igw.airlocks.io)        │
└───────────────────┘              └────────────┬─────────────┘
                                                │
                                     Internal routing
                                                │
                                   ┌────────────▼─────────────┐
                                   │  Airlock Platform Backend │
                                   └────────────┬─────────────┘
                                                │
                                     Push notification
                                                │
                                   ┌────────────▼─────────────┐
                                   │  Mobile Approver App      │
                                   │  (approve / deny)         │
                                   └──────────────────────────┘
```

Key components:

- **@airlockapp/gateway-sdk** — TypeScript SDK for the Airlock Integrations Gateway API
- **X25519 ECDH** — Key exchange for end-to-end encryption (AES-256-GCM)
- **Ed25519** — Decision signature verification
- **PAT + Client Credentials** — Dual authentication (user identity + app identity)
- **Pre-generated pairing codes** — Config-driven pairing (no interactive browser login)
- **Long-polling** — Server-side 25s timeout for efficient decision waiting
- **Presence heartbeat** — 45s interval for online/offline status in mobile app
- **DND policy check** — Auto-approval when Do Not Disturb is active

---

## Further Reading

- [Airlock Developer Guide](https://airlockapp.io/docs/developer-guide/) — Developer programme, enforcer lifecycle, API reference
- [Gateway Client SDKs](https://airlockapp.io/docs/sdk/) — Published SDK packages and documentation
- [HARP Specification](../../harp-spec/) — Human-Approvable Request Protocol specification
- [Claude Code Enforcer](../claude-code-enforcer/README.md) — Reference enforcer implementation for Claude Code

---

## License

MIT

# Airlock Extensions

IDE enforcer extensions and CLI for **Airlock** — the cryptographically enforced approval gateway for AI agents.

These extensions intercept AI agent actions before execution and route them through a mobile approval flow, ensuring no sensitive or high-impact action runs without an explicitly signed human decision.

---

## HARP (Human Authorization & Review Protocol)

Airlock implements **[HARP](https://harp-protocol.github.io/)** — the Human Authorization & Review Protocol — a standards-grade, cryptographically verifiable authorization layer for AI agents.

### What HARP provides

- **Binding** — Approvals are cryptographically bound to the exact artifact (e.g. command or prompt) that was reviewed.
- **Verifiable decisions** — Ed25519-signed decisions; replay and substitution are rejected.
- **E2E encryption** — Artifact payloads can be encrypted (AES-256-GCM) so gateways stay zero-knowledge.
- **Interoperability** — Open schemas, test vectors, and conformance criteria for cross-vendor use.

### HARP specs in this repo

This repository includes a **HARP specification draft suite** (v0.2) under `samples/harp/`:

| Area                 | Location                                    | Description                                                             |
| -------------------- | ------------------------------------------- | ----------------------------------------------------------------------- |
| **Core**             | `samples/harp/src/spec/core/`               | Artifact canonicalization, hashing, decision signing, replay protection |
| **Gateway**          | `samples/harp/src/spec/gateway/`            | HTTP binding, artifact submit, decision wait, schemas                   |
| **Prompt / Session** | `samples/harp/src/spec/prompt/`, `session/` | Prompt and session message types                                        |
| **Infrastructure**   | `samples/harp/src/spec/infrastructure/`     | KEYMGMT, THREATMODEL, TRANSPORT, COMPLIANCE                             |
| **Governance**       | `samples/harp/src/spec/governance/`         | Governance and lifecycle                                                |

Enforcers and the CLI align with HARP-CORE (artifact hash, decision verification, E2E encryption), the Gateway HTTP binding, and HARP key/encryption practices. See [samples/harp/src/spec/README.md](samples/harp/src/spec/README.md) for the full spec layout.

---

## Extensions

| Extension                                                             | IDE                          | Interception Method                                                                                |
| --------------------------------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| **[Airlock Cursor Enforcer](src/airlock-cursor-enforcer/)**           | Cursor                       | Hooks (pre-tool-use gate)                                                                          |
| **[Airlock Windsurf Enforcer](src/airlock-windsurf-enforcer/)**       | Windsurf                     | Hooks (pre-tool-use gate)                                                                          |
| **[Airlock Copilot Enforcer](src/airlock-copilot-enforcer/)**         | VS Code (GitHub Copilot)     | Hooks (pre-tool-use gate)                                                                          |
| **[Airlock Antigravity Enforcer](src/airlock-antigravity-enforcer/)** | VS Code (Google Antigravity) | CDP (Chrome DevTools Protocol)                                                                     |
| **[Airlock CLI](src/airlock-cli/)**                                   | Any shell                    | CLI (`sign-in`, `pair`, `approve`) — use with [shell plugins](src/shells/) (Bash, Zsh, PowerShell) |

### Shared Capabilities

All enforcers provide:

- 🔒 **AI action interception** before execution
- 🔐 **AES-256-GCM** artifact encryption (ECDH key exchange during pairing)
- ✍️ **Ed25519 signature verification** of mobile approver decisions
- 📱 **Workspace pairing** with mobile approver (QR code + text code)
- 📊 **Quota monitoring** via Gateway (subscription status)
- 🔗 **Presence tracking** via WebSocket
- 🔄 **Token refresh** for long-running sessions

### Claude Code Plugin

The Claude Code enforcer plugin has moved to its own dedicated repository:

👉 **[airlockapp/claude-plugins](https://github.com/airlockapp/claude-plugins)** — install via `/plugin marketplace add airlockapp/claude-plugins`

---

## Repository Structure

```
airlock-extensions/
├── src/
│   ├── airlock-cursor-enforcer/        # Cursor IDE enforcer
│   ├── airlock-windsurf-enforcer/      # Windsurf IDE enforcer
│   ├── airlock-copilot-enforcer/       # VS Code Copilot enforcer
│   ├── airlock-antigravity-enforcer/   # VS Code Antigravity enforcer
│   ├── airlock-cli/                    # CLI enforcer (sign-in, pair, approve)
│   ├── shells/                         # Shell plugins (Bash, Zsh, PowerShell)
│   ├── build-enforcers.ps1             # Build single mode (dev/prod)
│   └── build-extensions.ps1            # Build all modes (wrapper)
├── samples/
│   └── harp/                           # HARP spec drafts + reference implementations
└── README.md
```

---

## Building

### Prerequisites

- **Node.js** 18+ and **npm**
- **PowerShell** 7+ (or Windows PowerShell 5.1)

### Build All (Dev + Prod)

```powershell
.\src\build-extensions.ps1
```

### Build Specific Mode

```powershell
.\src\build-extensions.ps1 -Mode dev    # Dev builds only
.\src\build-extensions.ps1 -Mode prod   # Prod builds only
```

### Build Output

VSIX packages are placed in:

| Mode     | Output Directory | Naming                              |
| -------- | ---------------- | ----------------------------------- |
| **dev**  | `dist/dev/`      | `airlock-*-enforcer-dev-0.3.0.vsix` |
| **prod** | `dist/prod/`     | `airlock-*-enforcer-0.3.0.vsix`     |

### Install a Built Extension

```bash
# VS Code / Cursor / Windsurf
code --install-extension dist/prod/airlock-cursor-enforcer-0.3.0.vsix
```

Or: **Extensions** → **⋯** → **Install from VSIX…** → select the `.vsix` file.

---

## Development

Each extension is a standalone TypeScript VS Code extension. To develop individually:

```bash
cd src/airlock-cursor-enforcer
npm install
npm run compile
```

Then press **F5** in your IDE to launch the Extension Development Host.

See the `DEVELOPMENT.md` file in each extension folder for extension-specific notes.

---

## Related

- **[HARP Protocol](https://harp-protocol.github.io/)** — Human Authorization & Review Protocol (underlying spec); draft suite and samples live in [samples/harp/](samples/harp/)

---

## License

This project is licensed under the [MIT License](LICENSE).

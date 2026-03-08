# Airlock Extensions

IDE enforcer extensions for **[Airlock](https://github.com/airlockapp/airlock)** — the cryptographically enforced approval gateway for AI agents.

These extensions intercept AI agent actions before execution and route them through a mobile approval flow, ensuring no sensitive or high-impact action runs without an explicitly signed human decision.

---

## Extensions

| Extension | IDE | Interception Method |
|-----------|-----|---------------------|
| **[Airlock Cursor Enforcer](src/airlock-cursor-enforcer/)** | Cursor | Hooks (pre-tool-use gate) |
| **[Airlock Windsurf Enforcer](src/airlock-windsurf-enforcer/)** | Windsurf | Hooks (pre-tool-use gate) |
| **[Airlock Copilot Enforcer](src/airlock-copilot-enforcer/)** | VS Code (GitHub Copilot) | Hooks (pre-tool-use gate) |
| **[Airlock Antigravity Enforcer](src/airlock-antigravity-enforcer/)** | VS Code (Google Antigravity) | CDP (Chrome DevTools Protocol) |

### Shared Capabilities

All enforcers provide:

- 🔒 **AI action interception** before execution
- 🔐 **AES-256-GCM** artifact encryption (ECDH key exchange during pairing)
- ✍️ **Ed25519 signature verification** of mobile approver decisions
- 📱 **Workspace pairing** with mobile approver (QR code + text code)
- 📊 **Quota monitoring** via Gateway (subscription status)
- 🔗 **Presence tracking** via WebSocket
- 🔄 **Token refresh** for long-running sessions

---

## Repository Structure

```
airlock-extensions/
├── src/
│   ├── airlock-cursor-enforcer/        # Cursor IDE enforcer
│   ├── airlock-windsurf-enforcer/      # Windsurf IDE enforcer
│   ├── airlock-copilot-enforcer/       # VS Code Copilot enforcer
│   ├── airlock-antigravity-enforcer/   # VS Code Antigravity enforcer
│   ├── build-enforcers.ps1             # Build single mode (dev/prod)
│   └── build-extensions.ps1            # Build all modes (wrapper)
├── dist/                               # Built VSIX packages (gitignored)
│   ├── dev/                            # Dev builds (-dev suffix)
│   └── prod/                           # Production builds
├── samples/                            # HARP protocol samples
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

| Mode | Output Directory | Naming |
|------|-----------------|--------|
| **dev** | `dist/dev/` | `airlock-*-enforcer-dev-0.1.0.vsix` |
| **prod** | `dist/prod/` | `airlock-*-enforcer-0.1.0.vsix` |

### Install a Built Extension

```bash
# VS Code / Cursor / Windsurf
code --install-extension dist/prod/airlock-cursor-enforcer-0.1.0.vsix
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

- **[Airlock](https://github.com/airlockapp/airlock)** — Main platform (Gateway, Backend, Admin, Mobile Approver)
- **[HARP Protocol](https://harp-protocol.github.io/)** — The underlying protocol specification

---

## License

(To be defined)

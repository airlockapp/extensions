# airlock-cli

**Airlock CLI enforcer** — a non–hook-based enforcer that gates shell commands through the Airlock gateway. Sign in and pair once; then use `airlock-cli approve` to request human approval before running sensitive commands (e.g. `git push`, production deploys).

---

## Table of contents

- [Features](#features)
- [Contract (detailed)](#contract-detailed)
- [Build](#build)
- [Release binaries (production)](#release-binaries-production)
- [Testing](#testing)
- [Configuration](#configuration)
- [Usage](#usage)

---

## Features

- **Sign in / Sign out** — OAuth2 device authorization (same flow as the IDE extensions); tokens stored under your config dir.
- **Secure token storage** — Access and refresh tokens (and pairing secrets) in `~/.config/airlock/` (or `%APPDATA%\airlock` on Windows) with restricted permissions.
- **Token refresh** — The CLI refreshes the access token automatically when it is close to expiry.
- **Pairing** — Pair with the Airlock mobile app to get an encryption key and routing token; required for submitting artifacts.
- **Approve** — Submit a command for approval, long-poll the gateway, verify the Ed25519 signature, and exit with a well-defined status code.
- **DND-aware approvals** — Before submitting an artifact, the CLI checks **Do Not Disturb (DND)** policies via the same control plane as the IDE enforcers. When a matching DND rule exists, the CLI auto-approves / auto-denies locally and emits a short-lived **DND audit artifact** to `POST /v1/artifacts` (with `metadata.dndAudit = "true"`) so the mobile app shows a non-interactive history entry for the action.

---

## Contract (detailed)

The **approve** command is the main integration point. Call it from your shell wrapper or CI; it blocks until the gateway delivers a decision or the timeout is reached.

### Command line

```text
airlock-cli approve [flags]
```

### Required flags

| Flag        | Type   | Description |
| ----------- | ------ | ----------- |
| `--command` | string | **Required.** The exact command line to be approved (e.g. `git push origin main`). This is what the human sees on the mobile app and approves or denies. |

### Optional flags (approve)

| Flag          | Type   | Default | Description |
| ------------- | ------ | ------- | ----------- |
| `--shell`     | string | `""`    | Shell name (e.g. `zsh`, `bash`, `pwsh`). Informs the approver which shell would run the command. |
| `--cwd`       | string | `""`    | Current working directory for the command. Shown to the approver. |
| `--session-id`| string | `""`    | Opaque session identifier (e.g. terminal session ID). Used for correlation and audit. |
| `--shell-pid` | string | `""`    | Process ID of the shell. Used for correlation and audit. |
| `--host`      | string | `""`    | Host name of the machine (e.g. `mbp-01`, `ci-runner-42`). Shown to the approver. |
| `--timeout`   | int    | `300`   | Maximum seconds to wait for a decision. After this, the CLI exits with code 3. |

### Global flags (all commands)

| Flag           | Type   | Description |
| -------------- | ------ | ----------- |
| `--gateway`    | string | Gateway base URL (e.g. `https://gateway.example.com`). Overrides config and env. |
| `--diagnostic` | bool   | Enable diagnostic output: print exit code before exit, and extra debug lines (e.g. gateway, requestId, submit/poll) for `approve`. Useful for debugging and shell integration. |

### Exit codes (approve)

| Code | Meaning |
| ---- | ------- |
| `0`  | **Approved** — The approver allowed the action. The caller should proceed to run the command. |
| `1`  | **Denied** — The approver explicitly rejected the action. |
| `2`  | **Verification failed** — The decision could not be verified (e.g. invalid or unknown Ed25519 signature, artifactHash mismatch). The caller must not run the command. |
| `3`  | **Timeout** — No decision was received within `--timeout` seconds. The caller should not assume approval. |

Non-zero exit from any other failure (e.g. not signed in, not paired, network error) is reported to stderr and exits with code 1.

### Example (full contract)

```bash
airlock-cli approve \
  --shell zsh \
  --cwd "/work/project" \
  --command "git push origin main" \
  --session-id "pts-1" \
  --shell-pid "12345" \
  --host "mbp-01" \
  --timeout 600
```

### Behavioral guarantees

- **Stdin** — Not read; safe to use in pipelines or with interactive shells.
- **Stdout** — No normal output; only progress or errors may go to **stderr**.
- **Idempotency** — Each call uses a new `requestId`; no client-side idempotency key is exposed.
- **Gateway flow** — Same as IDE enforcers: build encrypted artifact (AES-256-GCM), submit to `POST /v1/artifacts`, long-poll `GET /v1/exchanges/{requestId}/wait`, verify decision (Ed25519) with paired keys, then exit. If an applicable DND policy exists (from the mobile app), the CLI first queries `GET /v1/policy/dnd/effective` and may auto-approve/auto-reject without an interactive decision, while still emitting a short‑lived DND audit artifact to `POST /v1/artifacts` for history.

---

## Build

**Requirements:** Go 1.23 or later.

```bash
cd src/airlock-cli
go build -o airlock-cli ./cmd/airlock-cli
```

**Clean and rebuild** (use this if you changed code but still see old behaviour — ensures you run a fresh binary):

```bash
cd src/airlock-cli
go clean -cache
go build -o airlock-cli ./cmd/airlock-cli
```

On Windows you may need to remove any running `airlock-cli.exe` from the current directory first. If you installed the binary elsewhere (e.g. `~/.airlock/bin/`), run the new build from the project dir and copy the new binary over the old one.

**Where the executable is output:**

- **Default build** — The executable is written to the **current directory** (the `src/airlock-cli` folder):
  - Linux/macOS: `src/airlock-cli/airlock-cli`
  - Windows (when building for Windows): `src/airlock-cli/airlock-cli.exe`
- To put it elsewhere, pass a path to `-o`, e.g. `go build -o "$HOME/.airlock/bin/airlock-cli" ./cmd/airlock-cli`.
- **Release build** (`make release` or the one-liners below) — Binaries are written to the **`dist/`** directory inside `src/airlock-cli`, with names like `airlock-cli-windows-amd64.exe`, `airlock-cli-linux-amd64`, etc.

---

## Release binaries (production)

Build production binaries for all supported platforms and architectures from a single machine (or CI) using Go’s cross-compilation.

### Supported targets

| OS      | Architectures |
| ------- | ------------- |
| Windows | amd64, 386    |
| Linux   | amd64, 386, arm, arm64 |
| macOS   | amd64, arm64  |

### One-liner (all targets)

From `src/airlock-cli`:

```bash
# Optional: set a version for the binary (e.g. for embedding or dist folder name)
VERSION=${VERSION:-"0.1.0"}
mkdir -p dist

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/airlock-cli-windows-amd64.exe ./cmd/airlock-cli
GOOS=windows GOARCH=386   go build -ldflags="-s -w" -o dist/airlock-cli-windows-386.exe   ./cmd/airlock-cli

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/airlock-cli-linux-amd64   ./cmd/airlock-cli
GOOS=linux GOARCH=386   go build -ldflags="-s -w" -o dist/airlock-cli-linux-386     ./cmd/airlock-cli
GOOS=linux GOARCH=arm   go build -ldflags="-s -w" -o dist/airlock-cli-linux-arm     ./cmd/airlock-cli
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/airlock-cli-linux-arm64    ./cmd/airlock-cli

# macOS (darwin)
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/airlock-cli-darwin-amd64  ./cmd/airlock-cli
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/airlock-cli-darwin-arm64  ./cmd/airlock-cli
```

`-ldflags="-s -w"` strips debug info and reduces binary size.

### Using a Makefile (optional)

Create `src/airlock-cli/Makefile`:

```makefile
VERSION ?= 0.1.0
DIST    := dist

.PHONY: build release clean

build:
	go build -o airlock-cli ./cmd/airlock-cli

release: clean
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-windows-amd64.exe ./cmd/airlock-cli
	GOOS=windows GOARCH=386   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-windows-386.exe   ./cmd/airlock-cli
	GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-amd64     ./cmd/airlock-cli
	GOOS=linux   GOARCH=386   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-386       ./cmd/airlock-cli
	GOOS=linux   GOARCH=arm   go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-arm       ./cmd/airlock-cli
	GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-linux-arm64    ./cmd/airlock-cli
	GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-darwin-amd64    ./cmd/airlock-cli
	GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST)/airlock-cli-darwin-arm64    ./cmd/airlock-cli

clean:
	rm -rf $(DIST) airlock-cli airlock-cli.exe
```

Then:

```bash
make release
```

Artifacts will be in `dist/`. On Windows, if you don't have `make`, use the [one-liner commands](#one-liner-all-targets) above in PowerShell or Git Bash, or run the same `GOOS=... GOARCH=... go build ...` lines manually.

### Naming convention

- **Windows:** `airlock-cli-windows-<arch>.exe`
- **Linux:**   `airlock-cli-linux-<arch>` (no extension)
- **macOS:**   `airlock-cli-darwin-<arch>` (no extension)

---

## Testing

### Prerequisites

- A running Airlock stack (Gateway + Backend + Keycloak); see the main repo README.
- Optional: Airlock mobile app for pairing tests.

### 1. Unit / local build check

```bash
cd src/airlock-cli
go build ./...
go build -o airlock-cli ./cmd/airlock-cli
./airlock-cli --help
./airlock-cli approve --help
```

### 2. Sign-in (device flow)

```bash
./airlock-cli sign-in --gateway https://localhost:7145
```

- Browser should open; sign in with a Keycloak user.
- After success, tokens and gateway URL are stored; `airlock-cli status` should show “Signed in: true”.

### 3. Pairing

```bash
./airlock-cli pair --gateway https://localhost:7145
```

- Enter the shown code in the Airlock mobile app and complete pairing.
- After success, `airlock-cli status` should show “Paired: true”.

### 4. Approve (happy path)

```bash
./airlock-cli approve \
  --gateway https://localhost:7145 \
  --command "echo test" \
  --host "$(hostname)"
```

- Approve on the mobile app within the timeout.
- CLI should exit 0; stderr may show “Approved” or reason.

### 5. Approve (rejected)

- Run the same `approve` command and **reject** on the mobile app.
- Notice it exits with status `1`.

### 6. Approve (timeout)

```bash
./airlock-cli approve --command "sleep 1" --timeout 5
```

- Do **not** approve on the mobile app.
- After ~5 seconds, CLI should exit 3.

### 7. Exit code check (script)

```bash
./airlock-cli approve --command "echo ok" --timeout 2
echo "Exit code: $?"
# If timeout: expect 3
```

### 8. Not signed in / not paired

```bash
./airlock-cli sign-out
./airlock-cli approve --command "echo ok"
# Expect error and non-zero exit (e.g. "not signed in" or "not paired")
```

---

## Configuration

- **Gateway URL** — Set via `--gateway`, config (after sign-in), or env `AIRLOCK_GATEWAY_URL`.
- **Config directory**
  - Linux/macOS: `~/.config/airlock/`
  - Windows: `%APPDATA%\airlock`
- **Files**
  - `config.json` — Gateway URL, enforcer ID (non-sensitive).
  - `secrets.json` — Access/refresh tokens, encryption key, routing token, paired keys. **Keep private** (permissions are set to 0600 where supported).

---

## Usage

### Commands overview

| Command     | Description |
| ----------- | ----------- |
| `sign-in`   | Start device authorization; store tokens and gateway URL. |
| `sign-out`  | Clear tokens and pairing data. |
| `pair`      | Pair with the mobile app (show code, poll until complete). |
| `approve`   | Request approval for a command; exit 0/1/2/3 per contract. |
| `status`    | Show gateway URL, enforcer ID, sign-in and pairing status. |

### Minimal workflow

```bash
airlock-cli sign-in
airlock-cli pair
# ... then in your wrapper:
airlock-cli approve --command "git push origin main"
if [ $? -eq 0 ]; then
  git push origin main
fi
```

For end-user–oriented steps and troubleshooting, see **[USER_GUIDE.md](USER_GUIDE.md)**.

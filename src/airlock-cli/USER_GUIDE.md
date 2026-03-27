# Airlock CLI — User Guide

This guide helps you install, set up, and use the **Airlock CLI** so you can require approval from your phone before sensitive commands (like `git push` or production deploys) run on your machine.

---

## What is the Airlock CLI?

The Airlock CLI is a small program that:

1. **Asks for approval** — Before a command runs, it sends a request to the Airlock gateway. You see the request on the **Airlock mobile app** and tap **Approve** or **Deny**.
2. **Blocks until you decide** — The terminal waits until you approve, reject, or until a timeout. It then exits with a clear result so your shell or script can allow or block the command.
3. **Stays secure** — You sign in once (with your normal account) and pair the CLI with your phone once. After that, approvals are cryptographically verified so only your decision counts.

You typically **don’t run the CLI by hand** for every command. Instead, you (or your team) set up a **wrapper** that runs the CLI first; if it exits “approved,” the wrapper runs the real command.

---

## Before you start

You need:

- **Airlock gateway** — Your organization or project will give you a URL (e.g. `https://gateway.mycompany.com`). If you’re trying Airlock yourself, use the URL from your dev setup (e.g. `https://localhost:7145`).
- **An account** — Same account you use for the Airlock web app or IDE extension (Keycloak/SSO).
- **Airlock mobile app** — Installed on your phone, signed in with that account. Used to approve or reject requests and to **pair** the CLI.

---

## Step 1: Install the CLI

### Option A: Download a release

1. Get the right binary for your system from your team or the releases page:
   - **Windows (64-bit):** `airlock-cli-windows-amd64.exe`
   - **Windows (32-bit):** `airlock-cli-windows-386.exe`
   - **Linux (64-bit):** `airlock-cli-linux-amd64`
   - **Linux (32-bit):** `airlock-cli-linux-386`
   - **Linux (ARM, 32-bit):** `airlock-cli-linux-arm`
   - **Linux (ARM, 64-bit):** `airlock-cli-linux-arm64`
   - **macOS (Intel):** `airlock-cli-darwin-amd64`
   - **macOS (Apple Silicon):** `airlock-cli-darwin-arm64`

2. Rename it to `airlock-cli` (or `airlock-cli.exe` on Windows) and put it somewhere in your PATH, or use the full path when you run it.

3. Make it executable (Linux/macOS):
   ```bash
   chmod +x airlock-cli
   ```

### Option B: Build from source

If you have Go installed:

```bash
cd src/airlock-cli
go build -o airlock-cli ./cmd/airlock-cli
```

Use `airlock-cli.exe` on Windows if your environment expects that.

---

## Step 2: Sign in

Sign in once so the CLI can talk to the gateway with your identity.

1. Run:
   ```bash
   airlock-cli sign-in
   ```
   If your gateway is not the default, add the URL:
   ```bash
   airlock-cli sign-in --gateway https://your-gateway.example.com
   ```

2. Your browser will open to a login page. Sign in with your normal Airlock/Keycloak account.

3. When the page says you’re logged in, you can close it. The CLI will detect the login and print something like “Signed in successfully.”

4. Check that it worked:
   ```bash
   airlock-cli status
   ```
   You should see “Signed in: true” and the gateway URL.

---

## Step 3: Pair with your phone

Pairing links this CLI installation to your phone so that:

- Approval requests from this CLI show up on **your** Airlock app.
- The CLI can verify that an “approve” really came from your device.

Do this once per machine (or per config directory).

1. Run:
   ```bash
   airlock-cli pair
   ```
   (Add `--gateway https://...` if needed.)

2. The CLI will show a **pairing code** (a short string like `AB12CD`).

3. Open the **Airlock mobile app**, go to the pairing / add agent section, and enter that code. Complete the steps in the app.

4. When pairing succeeds, the CLI will say “Pairing complete. You can now use ‘airlock-cli approve’.”

5. Check:
   ```bash
   airlock-cli status
   ```
   You should see “Paired: true.”

---

## Step 4: Use the approve command

After sign-in and pairing, you can request approval for a command.

### Basic usage

```bash
airlock-cli approve --command "git push origin main"
```

- The CLI sends the command to the gateway; you get a notification on your phone.
- You **Approve** or **Reject** in the app.
- The CLI then exits:
  - **Exit 0** — Approved → safe for your script to run the command.
  - **Exit 1** — Denied.
  - **Exit 2** — Verification failed (don’t run the command).
  - **Exit 3** — Timeout (no answer in time; don’t assume approval).

### With more context (recommended)

Giving the CLI a bit of context helps you recognize the request on your phone:

```bash
airlock-cli approve \
  --command "git push origin main" \
  --cwd "/home/me/my-project" \
  --shell "bash" \
  --host "my-laptop"
```

You can also use `--session-id` and `--shell-pid` if your wrapper supplies them.

### Timeout

By default the CLI waits up to 5 minutes. To change it (e.g. 2 minutes):

```bash
airlock-cli approve --command "git push" --timeout 120
```

---

### How DND (Do Not Disturb) affects approve

If you have enabled **workspace or command-level DND** in the Airlock mobile app, the CLI:

- Looks up effective DND policies from the gateway using the same control plane as the IDE extensions:
  - `GET /v1/policy/dnd/effective?enforcerId=...&workspaceId=...&sessionId=...`
- If a matching rule says “auto-approve” or “auto-deny” for this command:
  - The CLI **does not send a normal interactive approval request**.
  - Instead, it auto-approves / auto-denies **locally**, then:
    - Sends a short‑lived **DND audit artifact** to `POST /v1/artifacts` (marked with `dndAudit = "true"`), so you still see the command in the mobile app’s history.
  - The exit codes are the same:
    - `0` if the DND rule approves the command.
    - `1` if the DND rule denies the command.

If no DND rule applies, the normal interactive approval flow runs as described above.

---

## Using the CLI from a script or wrapper

The idea is: **run the CLI first; only run the real command if the CLI exits 0.**

### Example (Bash)

```bash
#!/bin/bash
# Wrap a command so it only runs after approval.
airlock-cli approve \
  --command "$*" \
  --cwd "$(pwd)" \
  --shell "$SHELL" \
  --host "$(hostname)"
if [ $? -eq 0 ]; then
  "$@"
else
  echo "Command not approved or failed."
  exit 1
fi
```

### Example (PowerShell)

```powershell
# Wrap a command so it only runs after approval.
param([string]$Command)
& airlock-cli approve --command $Command --cwd (Get-Location).Path --host $env:COMPUTERNAME
if ($LASTEXITCODE -eq 0) {
  Invoke-Expression $Command
} else {
  Write-Host "Command not approved or failed."
  exit 1
}
```

You can then alias or wrap specific commands (e.g. `git push`, `kubectl apply`, deploy scripts) so they always go through the CLI.

---

## Where are my data and settings stored?

- **Config and secrets** are stored in a single folder:
  - **Linux / macOS:** `~/.config/airlock/`
  - **Windows:** `%APPDATA%\airlock`

- **config.json** — Gateway URL and enforcer ID (not secret).
- **secrets.json** — Tokens and pairing keys. This file is sensitive; the CLI sets strict permissions where possible. Don’t share it or commit it.

---

## Signing out and unpairing

To clear all stored credentials and pairing:

```bash
airlock-cli sign-out
```

After this you must **sign in** and **pair** again before using `approve`.

---

## Troubleshooting

### “Not signed in” or “run airlock-cli sign-in”

- Run `airlock-cli sign-in` (and complete the browser login).
- If you use a custom gateway, use `--gateway https://...` or set `AIRLOCK_GATEWAY_URL`.

### “Not paired” or “run airlock-cli pair”

- Run `airlock-cli pair` and enter the code in the Airlock mobile app.
- Make sure you’re signed in on the **same account** in both the CLI and the app.

### “Approval timeout” (exit code 3)

- You didn’t approve or reject in time. Increase `--timeout` if needed, or approve faster next time.
- Check that the mobile app has notifications enabled and can reach the gateway (e.g. same network or VPN).

### Browser doesn’t open when I run sign-in

- The CLI will still print the URL and code. Open the URL manually in your browser and sign in; the CLI will detect when login completes.

### Wrong gateway URL

- Use `airlock-cli sign-in --gateway https://correct-url` to sign in again with the right URL, or set `AIRLOCK_GATEWAY_URL` and run `sign-in` again.
- You can also edit `~/.config/airlock/config.json` (or `%APPDATA%\airlock\config.json`) and set `gateway_url` there.

### I want to use a different gateway for one command

- Use the global flag:  
  `airlock-cli --gateway https://other-gateway.example.com approve --command "..."`

---

## Quick reference

| Task           | Command |
| -------------- | ------- |
| Sign in        | `airlock-cli sign-in` |
| Pair phone     | `airlock-cli pair` |
| Request approval | `airlock-cli approve --command "your command"` |
| Check status   | `airlock-cli status` |
| Sign out       | `airlock-cli sign-out` |

**Exit codes for `approve`:**  
`0` = approved, `1` = denied, `2` = verification failed, `3` = timeout.

For full flag details and build instructions, see **[README.md](README.md)**.

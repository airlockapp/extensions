# Airlock PowerShell profile — User guide

This guide walks you through installing and using the Airlock PowerShell integration so that **every command you type** in PowerShell can require approval on your phone before it runs.

---

## What this does

When the profile is loaded and you press **Enter** on a command:

1. The command is sent to **Airlock** (via `airlock-cli`).
2. A notification appears on your **Airlock mobile app**.
3. You tap **Approve** or **Reject**.
4. If you approve, the command runs in PowerShell. If you reject (or don’t respond in time), it does not run.

So you get a second check before risky commands (e.g. `git push`, production deploys) actually execute.

---

## Before you start

You need:

1. **airlock-cli** — Installed for Windows (e.g. `airlock-cli.exe`) and on your `PATH` or in a known folder.
2. **Signed in** — Run `airlock-cli sign-in` once and complete the browser login.
3. **Paired** — Run `airlock-cli pair` once and enter the code in the Airlock mobile app.
4. **PowerShell** — You’re using PowerShell 5 or PowerShell Core (pwsh) on Windows. PSReadLine should be available (it usually is by default).

---

## Step 1: Install airlock-cli

If you haven’t already:

- Download or build `airlock-cli` for Windows (see the main [airlock-cli README](../../airlock-cli/README.md)).
- Put it in a folder on your `PATH`, or in a folder you’ll reference below (e.g. `$HOME\.airlock\bin\`).

Example (after downloading or building):

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\.airlock\bin"
Copy-Item ".\airlock-cli-windows-amd64.exe" "$HOME\.airlock\bin\airlock-cli.exe"
# Optional: add to PATH for current session
$env:Path = "$HOME\.airlock\bin;" + $env:Path
```

---

## Step 2: Sign in and pair

In PowerShell:

```powershell
airlock-cli sign-in
# Complete login in the browser when it opens.

airlock-cli pair
# Enter the code shown in the Airlock mobile app.
```

When both succeed, `airlock-cli status` should show “Signed in: true” and “Paired: true”.

---

## Step 3: Install the profile script

1. Copy the profile script into a stable location, for example:

   ```powershell
   New-Item -ItemType Directory -Force -Path "$HOME\.airlock\shell"
   Copy-Item "path\to\airlock\src\shells\posh\airlock.profile.ps1" "$HOME\.airlock\shell\"
   ```

   Replace `path\to\airlock` with the path to your Airlock repo or install.

2. Open your PowerShell profile (create it if it doesn’t exist):

   ```powershell
   if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
   notepad $PROFILE
   ```

3. Add these lines at the end (adjust paths if you put the CLI or script elsewhere):

   ```powershell
   $env:AIRLOCK_CLI = "$HOME\.airlock\bin\airlock-cli.exe"
   $env:AIRLOCK_ENABLED = "1"
   $env:AIRLOCK_FAIL_MODE = "open"
   . "$HOME\.airlock\shell\airlock.profile.ps1"
   ```

4. Reload your profile:

   ```powershell
   . $PROFILE
   ```

   Or close and reopen PowerShell.

---

## Step 4: Try it

1. Open a **new** PowerShell window.
2. Type a command, for example: `Write-Host hello`
3. Press **Enter**.

The command will run (no approval message). On your phone, you should see the approval request in the Airlock app.

- If you **reject** in the app, the command will not run and you’ll see “[Airlock] Denied” in red.
- If you don’t approve in time, with default `AIRLOCK_FAIL_MODE=open` the command still runs and you’ll see “Unavailable, continuing” in yellow.

---

## Turning the profile off temporarily

Set `AIRLOCK_ENABLED=0` and reload, or comment out the dot-source line in your profile:

```powershell
# $env:AIRLOCK_ENABLED = "0"
# . "$HOME\.airlock\shell\airlock.profile.ps1"
```

Then run `. $PROFILE`. Commands will run without going through Airlock until you re-enable it.

---

## If the CLI is unavailable

The profile respects **fail mode**:

- **`AIRLOCK_FAIL_MODE=open`** (default) — If the CLI fails or times out, the command **still runs** and you see “Unavailable, continuing” in yellow.
- **`AIRLOCK_FAIL_MODE=closed`** — If the CLI fails or times out, the command **does not run** and you see “Unavailable, blocked” in red.

Set it before dot-sourcing the profile in your `$PROFILE`:

```powershell
$env:AIRLOCK_FAIL_MODE = "closed"
. "$HOME\.airlock\shell\airlock.profile.ps1"
```

---

## Troubleshooting

- **“airlock-cli is not recognized”**  
  Install the CLI and either add it to your `PATH` or set `$env:AIRLOCK_CLI` to the full path of `airlock-cli.exe` before dot-sourcing the profile.

- **“Not signed in” / “Not paired”**  
  Run `airlock-cli sign-in` and `airlock-cli pair` in PowerShell and complete the steps. Then try again.

- **Nothing happens when I press Enter**  
  Make sure you’re in an **interactive** session and that you’ve run `. $PROFILE` (or opened a new window) after adding the profile. If you see a warning about PSReadLine, install or enable PSReadLine (it’s usually present by default).

- **“[Airlock] PSReadLine not found”**  
  The profile requires PSReadLine for Enter interception. Install it if missing (e.g. `Install-Module PSReadLine`) and ensure it’s not disabled elsewhere in your profile.

---

## Quick reference

| What you want | What to do |
| -------------- | ---------- |
| Use Airlock on every command | Keep `AIRLOCK_ENABLED=1` and dot-source the profile in `$PROFILE`. |
| Run without approval for a while | Set `$env:AIRLOCK_ENABLED = "0"` and run `. $PROFILE`. |
| Block commands when CLI fails | Set `$env:AIRLOCK_FAIL_MODE = "closed"` before dot-sourcing the profile. |
| Point to a different CLI | Set `$env:AIRLOCK_CLI = "C:\path\to\airlock-cli.exe"` before dot-sourcing the profile. |

For more details (environment variables, behavior, testing), see [README.md](README.md).

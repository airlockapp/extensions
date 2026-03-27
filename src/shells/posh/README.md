# Airlock PowerShell profile

Opt-in PowerShell integration that intercepts **Enter** in an interactive session, calls `airlock-cli approve` with the current command, and only accepts the line (executes the command) when the CLI exits with code `0` (approved).

## Requirements

- **PowerShell 5+** or **PowerShell Core** (pwsh)
- **PSReadLine** — Usually included by default; required for key handling
- **airlock-cli** — Built for Windows and on your `PATH`, or set `AIRLOCK_CLI` to its path (e.g. `airlock-cli.exe`)
- Signed in and paired: run `airlock-cli sign-in` and `airlock-cli pair` before using the profile

## Installation

### 1. Install airlock-cli

Build or download `airlock-cli` for Windows (e.g. `airlock-cli-windows-amd64.exe`) and place it in a directory on your `PATH`, or in `%USERPROFILE%\.airlock\bin\`:

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\.airlock\bin"
# Copy airlock-cli.exe to $HOME\.airlock\bin\
```

### 2. Install the profile script

Copy the profile script into your shell directory:

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\.airlock\shell"
Copy-Item "path\to\airlock\src\shells\posh\airlock.profile.ps1" "$HOME\.airlock\shell\"
```

### 3. Load the profile in your PowerShell profile

Open (or create) your PowerShell profile:

```powershell
if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
notepad $PROFILE
```

Add these lines at the end (adjust paths if needed):

```powershell
$env:AIRLOCK_CLI = "$HOME\.airlock\bin\airlock-cli.exe"
$env:AIRLOCK_ENABLED = "1"
$env:AIRLOCK_FAIL_MODE = "open"
. "$HOME\.airlock\shell\airlock.profile.ps1"
```

Then start a new PowerShell session or run `. $PROFILE`.

## Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `AIRLOCK_CLI` | `airlock-cli.exe` | Path to the `airlock-cli` executable. |
| `AIRLOCK_ENABLED` | `1` | Set to `0` to disable interception (commands run without approval). |
| `AIRLOCK_FAIL_MODE` | `open` | When the CLI is unavailable or returns an error: `open` = allow command; `closed` = block command. |
| `AIRLOCK_SESSION_ID` | (auto) | Session identifier. Set only if you need a fixed value; otherwise generated once per session. |

## Behavior

- **Enter** / **Ctrl+J** — Current line is sent to `airlock-cli approve` with:
  - `--shell powershell`
  - `--cwd` (current location path)
  - `--command` (current buffer)
  - `--session-id` (stable per session)
  - `--shell-pid` (current PowerShell PID)
  - `--host` (from `$env:COMPUTERNAME` or `[System.Net.Dns]::GetHostName()` or `unknown-host`)

- **Exit 0** — Approved: line is accepted and runs (no message).
- **Exit 1** — Denied: line is reverted (not executed); “[Airlock] Denied” in red.
- **Exit 2** — Verification failed: line is reverted; “[Airlock] Verification failed, blocked” in red.
- **Other exit** — Unavailable/error: if `AIRLOCK_FAIL_MODE=open`, line is accepted and “Unavailable, continuing” in yellow; if `closed`, line is reverted and “Unavailable, blocked” in red.

Empty or whitespace-only lines are not sent to the CLI; they are accepted normally.

If **PSReadLine** is not available, the profile prints a warning and does not install key handlers; Enter will behave as default.

## Testing with a fake CLI

Use the provided **batch file** to test the profile without a real gateway:

```powershell
# Reject all commands (exit code 1)
$env:AIRLOCK_CLI = "C:\path\to\shells\posh\fake-airlock-cli.bat"
$env:FAKE_AIRLOCK_EXIT = "1"
. $PROFILE
# Type a command and press Enter → it is blocked

# Approve all commands (exit code 0)
$env:FAKE_AIRLOCK_EXIT = "0"
# Type a command and press Enter → it runs
```

Replace `C:\path\to\shells\posh` with the actual path to the `posh` folder. You can also use `fake-airlock-cli.ps1` if you invoke it in a way that passes the exit code (e.g. a wrapper that runs the script and exits with `$env:FAKE_AIRLOCK_EXIT`).

## Limitations

- **Interactive only** — Non-interactive script execution is not intercepted.
- **PSReadLine required** — Key handling uses PSReadLine; if it’s missing or overridden, the profile may not intercept Enter.
- **Windows-focused** — The profile is written for Windows PowerShell / PowerShell Core on Windows; paths and `.exe` naming assume Windows.
- **Opt-in** — This is a workflow aid, not a hardened security boundary; users can disable the profile or use another shell.

## File layout (recommended)

```text
%USERPROFILE%\.airlock\
  bin\
    airlock-cli.exe
  shell\
    airlock.profile.ps1
```

## See also

- [USER_GUIDE.md](USER_GUIDE.md) — Step-by-step user guide.
- [airlock-powershell-interceptor-implementation.md](airlock-powershell-interceptor-implementation.md) — Implementation plan and acceptance criteria.
- Main **airlock-cli** [README](../../airlock-cli/README.md) and [USER_GUIDE](../../airlock-cli/USER_GUIDE.md) for sign-in, pairing, and CLI usage.

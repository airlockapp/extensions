# Airlock PowerShell Interceptor — AI-Friendly Implementation Plan

## Purpose

Implement an opt-in PowerShell interceptor that captures an interactive command before execution, calls `airlock-cli approve`, and only proceeds when the CLI exits with code `0`.

This document is designed for an AI coding agent. The target is a native Windows-friendly integration using the PowerShell profile and PSReadLine.

## CLI Contract

The integration must call the CLI in this shape:

```powershell
airlock-cli approve `
  --shell powershell `
  --cwd "C:\work\project" `
  --command "git push origin main" `
  --session-id "..." `
  --shell-pid "12345" `
  --host "mbp-01"
```

Rules:

- exit code `0` => approved
- exit code `2` => denied
- any other exit code => unavailable/error
- `--command` must be the exact interactive line as typed by the user

## Scope

This implementation covers:

- interactive PowerShell sessions
- profile-based installation
- PSReadLine Enter interception
- forwarding metadata to `airlock-cli`
- allow/deny behavior
- configurable fail-open / fail-closed mode

This implementation does **not** cover:

- non-interactive script execution
- processes started outside PowerShell
- global Windows process interception
- policy-enforced hard security

## Recommended Design

Use the PowerShell profile plus PSReadLine key handlers.

Preferred flow:

- load code from `$PROFILE`
- override Enter using `Set-PSReadLineKeyHandler`
- read the current command buffer
- call `airlock-cli approve`
- on approval, submit the line
- on denial, block submission and revert the line

Why this design:

- native Windows UX
- best opt-in developer experience on Windows
- preserves a common contract with Bash and Zsh
- does not require WSL

## Required Inputs

The profile must derive and send:

- `--shell`: literal string `powershell`
- `--cwd`: current location path
- `--command`: current line buffer
- `--session-id`: stable PowerShell session identifier
- `--shell-pid`: current PowerShell PID
- `--host`: computer hostname

## Session ID Requirements

Generate one session ID per PowerShell session if `AIRLOCK_SESSION_ID` is absent.

Recommended format:

```text
<unix-seconds>-<pid>-<short-guid>
```

## Host Resolution

Resolve host in this order:

1. `$env:COMPUTERNAME`
2. `[System.Net.Dns]::GetHostName()`
3. fallback `unknown-host`

## Decision Handling Policy

Support:

- `AIRLOCK_FAIL_MODE=open`
- `AIRLOCK_FAIL_MODE=closed`

Recommended default for opt-in mode:

```powershell
$env:AIRLOCK_FAIL_MODE = "open"
```

## UX Requirements

Use simple terminal feedback only:

- Approved: no message (line just runs)
- `[Airlock] Denied: ...`
- `[Airlock] Unavailable, continuing`
- `[Airlock] Unavailable, blocked: ...`

No GUI dialogs.

## Installation Model

Recommended layout:

```text
%USERPROFILE%\.airlock\bin\airlock-cli.exe
%USERPROFILE%\.airlock\shell\airlock.profile.ps1
```

Recommended profile bootstrap:

```powershell
$env:AIRLOCK_CLI = "$HOME\.airlock\bin\airlock-cli.exe"
$env:AIRLOCK_ENABLED = "1"
$env:AIRLOCK_FAIL_MODE = "open"
. "$HOME\.airlock\shell\airlock.profile.ps1"
```

## Implementation Steps

### Step 1 — Create profile script

Create `airlock.profile.ps1`.

### Step 2 — Define environment defaults

Support:

- `AIRLOCK_CLI`
- `AIRLOCK_ENABLED`
- `AIRLOCK_FAIL_MODE`

### Step 3 — Initialize session ID

If missing, create and store in `AIRLOCK_SESSION_ID`.

### Step 4 — Implement helper functions

Create:

- `Get-AirlockHost`
- `Invoke-AirlockApproval`
- `Invoke-AirlockAcceptLine`

### Step 5 — Bind Enter with PSReadLine

Use:

```powershell
Set-PSReadLineKeyHandler -Key Enter -ScriptBlock { Invoke-AirlockAcceptLine }
```

Also optionally support `Ctrl+j`.

### Step 6 — Decision flow

Pseudo-flow:

1. read command buffer from PSReadLine
2. if empty => accept line
3. if disabled => accept line
4. call `airlock-cli`
5. inspect `$LASTEXITCODE`
6. on `0` => accept line
7. on `2` => deny and revert line
8. on other codes => apply fail mode

## Reference Implementation Skeleton

```powershell
# airlock.profile.ps1

$env:AIRLOCK_CLI = if ($env:AIRLOCK_CLI) { $env:AIRLOCK_CLI } else { "airlock-cli.exe" }
$env:AIRLOCK_ENABLED = if ($env:AIRLOCK_ENABLED) { $env:AIRLOCK_ENABLED } else { "1" }
$env:AIRLOCK_FAIL_MODE = if ($env:AIRLOCK_FAIL_MODE) { $env:AIRLOCK_FAIL_MODE } else { "open" }

if (-not $env:AIRLOCK_SESSION_ID) {
    $env:AIRLOCK_SESSION_ID = "{0}-{1}-{2}" -f [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $PID, ([Guid]::NewGuid().ToString("N").Substring(0, 8))
}

function Get-AirlockHost {
    if ($env:COMPUTERNAME) { return $env:COMPUTERNAME }

    try {
        return [System.Net.Dns]::GetHostName()
    }
    catch {
        return "unknown-host"
    }
}

function Invoke-AirlockApproval {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    & $env:AIRLOCK_CLI approve `
        --shell powershell `
        --cwd (Get-Location).Path `
        --command $Command `
        --session-id $env:AIRLOCK_SESSION_ID `
        --shell-pid $PID `
        --host (Get-AirlockHost)

    return $LASTEXITCODE
}

function Invoke-AirlockAcceptLine {
    if ($env:AIRLOCK_ENABLED -ne "1") {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        return
    }

    $buffer = $null
    $cursor = 0
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$buffer, [ref]$cursor)

    if ([string]::IsNullOrWhiteSpace($buffer)) {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        return
    }

    $rc = Invoke-AirlockApproval -Command $buffer

    switch ($rc) {
        0 {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        }
        2 {
            Write-Host ""
            Write-Host "[Airlock] Denied: $buffer" -ForegroundColor Red
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
        }
        default {
            if ($env:AIRLOCK_FAIL_MODE -eq "closed") {
                Write-Host ""
                Write-Host "[Airlock] Unavailable, blocked: $buffer" -ForegroundColor Red
                [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            }
            else {
                Write-Host ""
                Write-Host "[Airlock] Unavailable, continuing" -ForegroundColor Yellow
                [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            }
        }
    }
}

Import-Module PSReadLine -ErrorAction SilentlyContinue
Set-PSReadLineKeyHandler -Key Enter -ScriptBlock { Invoke-AirlockAcceptLine }
Set-PSReadLineKeyHandler -Chord Ctrl+j -ScriptBlock { Invoke-AirlockAcceptLine }
```

## Acceptance Criteria

The implementation is complete when all of the following are true:

1. pressing Enter in interactive PowerShell invokes Airlock logic
2. CLI exit `0` allows the command
3. CLI exit `2` blocks the command
4. `--command` matches the exact typed line
5. `--cwd` equals current PowerShell location
6. `--session-id` remains stable for the session
7. `--shell-pid` equals the PowerShell PID
8. `--host` is non-empty
9. fail-open and fail-closed both work
10. profile loading does not break ordinary interactive startup

## Test Plan

### Manual tests

Test 1:

- fake CLI returns `0`
- command: `echo hello`
- expected: command executes

Test 2:

- fake CLI returns `2`
- command: `git push origin main`
- expected: command blocked

Test 3:

- fake CLI returns `7`
- fail-open
- expected: command executes

Test 4:

- fake CLI returns `7`
- fail-closed
- expected: command blocked

Test 5:

- empty line
- expected: normal shell behavior

## Risks and Edge Cases

- PSReadLine must be present for the key interception approach
- some host environments may customize Enter behavior already
- multiline input may need refinement later
- this is an opt-in shell workflow, not a security product boundary
- commands started outside PowerShell are out of scope

## Recommended V1 Boundaries

Do not add in v1:

- Windows service integration
- process creation hooks
- encryption in the profile
- HTTP from the profile
- GUI prompts
- background daemons

Keep the PowerShell profile thin and let `airlock-cli` own policy, transport, and crypto.

## Deliverables

The coding agent should produce:

1. `airlock.profile.ps1`
2. example `$PROFILE` bootstrap snippet
3. fake CLI test helper
4. short README section with installation and usage

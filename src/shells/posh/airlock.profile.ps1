# Airlock PowerShell profile — intercept Enter, call airlock-cli approve, allow/deny execution.
# Requires airlock-cli to be installed and signed in + paired.
# Requires PSReadLine (default in PowerShell 5+ and PowerShell Core).

if (-not $env:AIRLOCK_CLI) { $env:AIRLOCK_CLI = "airlock-cli.exe" }
if (-not $env:AIRLOCK_ENABLED) { $env:AIRLOCK_ENABLED = "1" }
if (-not $env:AIRLOCK_FAIL_MODE) { $env:AIRLOCK_FAIL_MODE = "open" }

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
        1 {
            Write-Host ""
            Write-Host "[Airlock] Denied: $buffer" -ForegroundColor Red
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
        }
        2 {
            Write-Host ""
            Write-Host "[Airlock] Verification failed, blocked: $buffer" -ForegroundColor Red
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

# PSReadLine is required for key handling
if (Get-Module -ListAvailable -Name PSReadLine) {
    Import-Module PSReadLine -ErrorAction SilentlyContinue
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock { Invoke-AirlockAcceptLine }
    Set-PSReadLineKeyHandler -Chord Ctrl+j -ScriptBlock { Invoke-AirlockAcceptLine }
}
else {
    Write-Warning "[Airlock] PSReadLine not found. Airlock key handlers were not installed. Install PSReadLine for Enter interception."
}

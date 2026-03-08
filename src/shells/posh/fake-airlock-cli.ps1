# Fake airlock-cli for testing the PowerShell profile.
# Usage: $env:AIRLOCK_CLI = "path\to\fake-airlock-cli.ps1"
#        $env:FAKE_AIRLOCK_EXIT = "0"  # or 1, 2, 5
# Then . $PROFILE and press Enter on a command.
# Note: For .ps1 you must invoke via powershell -File or wrap in a .exe; easier to use a .bat that calls powershell with -Command "exit %FAKE_AIRLOCK_EXIT%"

param(
    [string]$Command,
    [string]$Shell,
    [string]$Cwd,
    [string]$SessionId,
    [string]$ShellPid,
    [string]$HostName
)

$exitCode = [int](if ($env:FAKE_AIRLOCK_EXIT -match '^\d+$') { $env:FAKE_AIRLOCK_EXIT } else { 0 })
exit $exitCode

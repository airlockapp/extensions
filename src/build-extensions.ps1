<#
.SYNOPSIS
    Builds all Airlock enforcer extensions for both dev and prod modes.

.DESCRIPTION
    Wrapper script that calls build-enforcers.ps1 twice — once for dev and
    once for prod — producing two sets of VSIX packages in dist/.

    Dev packages have "-dev" appended to the extension name:
      airlock-cursor-enforcer-dev-0.1.0.vsix
      airlock-windsurf-enforcer-dev-0.1.0.vsix
      ...

    Prod packages use standard naming:
      airlock-cursor-enforcer-0.1.0.vsix
      airlock-windsurf-enforcer-0.1.0.vsix
      ...

.PARAMETER Mode
    Which mode(s) to build: "dev", "prod", or "all" (default: "all").

.EXAMPLE
    .\build-extensions.ps1              # Builds both dev and prod
    .\build-extensions.ps1 -Mode dev    # Builds only dev
    .\build-extensions.ps1 -Mode prod   # Builds only prod
#>

param(
    [ValidateSet("dev", "prod", "all")]
    [string]$Mode = "all"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildScript = Join-Path $scriptDir "build-enforcers.ps1"

if (-not (Test-Path $buildScript)) {
    Write-Host "ERROR: build-enforcers.ps1 not found at $buildScript" -ForegroundColor Red
    exit 1
}

$modes = switch ($Mode) {
    "all" { @("dev", "prod") }
    default { @($Mode) }
}

$overallFailed = $false

foreach ($m in $modes) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host "  Building $($m.ToUpper()) extensions" -ForegroundColor Magenta
    Write-Host "================================================================" -ForegroundColor Magenta

    & $buildScript -Mode $m
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: $m build failed!" -ForegroundColor Red
        $overallFailed = $true
    }
}

# Final summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host "  Build Complete" -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Magenta

$repoRoot = Split-Path $scriptDir -Parent
$distDir = Join-Path $repoRoot "dist"

Write-Host ""
Write-Host "All VSIX files in: $distDir" -ForegroundColor Cyan
foreach ($subDir in @("dev", "prod")) {
    $subPath = Join-Path $distDir $subDir
    if (Test-Path $subPath) {
        Write-Host "  [$($subDir.ToUpper())]" -ForegroundColor $(if ($subDir -eq "dev") { "Yellow" } else { "Green" })
        Get-ChildItem $subPath -Filter "*.vsix" | Sort-Object Name | ForEach-Object {
            Write-Host "    $($_.Name)  ($([math]::Round($_.Length / 1MB, 2)) MB)" -ForegroundColor White
        }
    }
}

if ($overallFailed) {
    Write-Host ""
    Write-Host "Some builds failed -- check output above." -ForegroundColor Red
    exit 1
}

<#
.SYNOPSIS
    Compiles, packages (with all dependencies), and copies all Airlock enforcer
    extension VSIX files to the dist folder.

.DESCRIPTION
    Iterates over each enforcer extension folder, runs npm install, compiles
    TypeScript, packages with vsce (--allow-missing-repository), and copies
    the resulting .vsix file to dist/.

    In dev mode, the package name is temporarily suffixed with "-dev" so VSIX
    files are distinctly named (e.g., airlock-cursor-enforcer-dev-0.1.0.vsix).

.PARAMETER Mode
    Build mode: "dev" or "prod" (default: "prod").
    - dev:  Patches package.json name with -dev suffix before packaging, restores after.
    - prod: Builds as-is with standard naming.

.EXAMPLE
    .\build-enforcers.ps1
    .\build-enforcers.ps1 -Mode dev
#>

param(
    [ValidateSet("dev", "prod")]
    [string]$Mode = "prod"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path $scriptDir -Parent
$distDir = Join-Path $repoRoot "dist"
$modeDistDir = Join-Path $distDir $Mode

# Ensure dist folder exists
if (-not (Test-Path $modeDistDir)) {
    New-Item -ItemType Directory -Path $modeDistDir -Force | Out-Null
    Write-Host "Created $modeDistDir" -ForegroundColor Cyan
}

$enforcers = @(
    "airlock-cursor-enforcer",
    "airlock-windsurf-enforcer",
    "airlock-copilot-enforcer",
    "airlock-antigravity-enforcer"
)

$failed = @()

Write-Host ""
Write-Host "Building enforcers in $($Mode.ToUpper()) mode" -ForegroundColor Cyan
Write-Host ""

foreach ($name in $enforcers) {
    $extDir = Join-Path $scriptDir $name
    if (-not (Test-Path $extDir)) {
        Write-Host "[SKIP] $name -- folder not found" -ForegroundColor Yellow
        continue
    }

    Write-Host ""
    Write-Host "=== Building $name ($Mode) ===" -ForegroundColor Green

    Push-Location $extDir
    $patchedPackageJson = $false
    $originalContent = $null
    try {
        # 1. Install dependencies
        Write-Host "  [1/3] npm install..." -ForegroundColor DarkGray
        npm install --silent 2>&1 | Out-Null

        # 2. Compile TypeScript
        Write-Host "  [2/3] Compiling..." -ForegroundColor DarkGray
        npm run compile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] Compile failed for $name" -ForegroundColor Red
            $failed += $name
            continue
        }

        # 3. In dev mode, patch package.json name with -dev suffix
        if ($Mode -eq "dev") {
            $pkgPath = Join-Path $extDir "package.json"
            $originalContent = [System.IO.File]::ReadAllText($pkgPath)
            $pkg = $originalContent | ConvertFrom-Json
            $pkg.name = "$($pkg.name)-dev"
            $pkg.displayName = "$($pkg.displayName) (Dev)"
            # Write without BOM — vsce can't parse UTF-8 with BOM
            $patchedJson = $pkg | ConvertTo-Json -Depth 20
            [System.IO.File]::WriteAllText($pkgPath, $patchedJson, [System.Text.UTF8Encoding]::new($false))
            $patchedPackageJson = $true
            Write-Host "  [DEV] Patched name -> $($pkg.name)" -ForegroundColor Yellow
        }

        # 4. Package VSIX with all dependencies included
        Write-Host "  [3/3] Packaging VSIX..." -ForegroundColor DarkGray
        npx @vscode/vsce package --allow-missing-repository --skip-license 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] Package failed for $name" -ForegroundColor Red
            $failed += $name
            continue
        }

        # 5. Copy .vsix to dist
        $vsix = Get-ChildItem -Path $extDir -Filter "*.vsix" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($vsix) {
            Copy-Item $vsix.FullName -Destination $modeDistDir -Force
            Write-Host "  [OK] Copied $($vsix.Name) -> dist/$Mode/" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARN] No .vsix file found after packaging" -ForegroundColor Yellow
            $failed += $name
        }
    }
    finally {
        # Restore original package.json if patched
        if ($patchedPackageJson -and $originalContent) {
            # Write without BOM — restore exact original content
            [System.IO.File]::WriteAllText((Join-Path $extDir "package.json"), $originalContent, [System.Text.UTF8Encoding]::new($false))
            Write-Host "  [DEV] Restored original package.json" -ForegroundColor Yellow
        }
        Pop-Location
    }
}

Write-Host ""
Write-Host "=== Summary ($Mode) ===" -ForegroundColor Cyan
$successCount = $enforcers.Count - $failed.Count
if ($failed.Count -eq 0) {
    Write-Host "  $successCount / $($enforcers.Count) extensions built successfully" -ForegroundColor Green
}
else {
    Write-Host "  $successCount / $($enforcers.Count) extensions built successfully" -ForegroundColor Yellow
}

if ($failed.Count -gt 0) {
    Write-Host "  Failed: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "VSIX files in: $modeDistDir" -ForegroundColor Cyan
Get-ChildItem $modeDistDir -Filter "*.vsix" | ForEach-Object {
    Write-Host "  - $($_.Name)  ($([math]::Round($_.Length / 1MB, 2)) MB)" -ForegroundColor White
}

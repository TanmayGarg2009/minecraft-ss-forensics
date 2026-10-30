<#
.SYNOPSIS
    Automated build, test, and single-file publishing script for Minecraft SS Forensics.
.DESCRIPTION
    1. Verifies .NET 8.0 SDK availability.
    2. Restores all NuGet package dependencies.
    3. Compiles the master solution in Release mode.
    4. Executes the automated test suite (79 tests).
    5. Publishes standalone, self-contained single-file win-x64 executables.
    6. Generates SHA-256 checksum manifests.
.PARAMETER OutputDirectory
    Directory where release binaries and checksums are placed. Defaults to 'release/win-x64'.
.PARAMETER SkipTests
    Skips test execution if set.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "release/win-x64",
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Minecraft SS Forensics — Reproducible Build Pipeline" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check or locate .NET 8.0 SDK
Write-Host "[1/6] Checking .NET SDK environment..." -ForegroundColor Yellow
if ($env:DOTNET_ROOT -and (Test-Path $env:DOTNET_ROOT)) {
    $env:PATH = "$env:DOTNET_ROOT;$env:PATH"
} elseif (Test-Path "$env:USERPROFILE\.dotnet") {
    $env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"
    $env:PATH = "$env:DOTNET_ROOT;$env:PATH"
}

try {
    $dotnetVersion = dotnet --version
    Write-Host "      Detected .NET SDK Version: $dotnetVersion" -ForegroundColor Green
    if (-not $dotnetVersion.StartsWith("8.")) {
        Write-Warning "Recommended SDK is .NET 8.0 LTS. Detected: $dotnetVersion"
    }
} catch {
    Write-Error "CRITICAL: .NET SDK not found. Install .NET 8.0 SDK from https://dotnet.microsoft.com/download/dotnet/8.0"
    exit 1
}

# Resolve paths relative to script root
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Get-Location }
$solutionPath = Join-Path $scriptRoot "backend\MinecraftSsForensics.sln"
$scannerAppProj = Join-Path $scriptRoot "backend\src\MinecraftSsForensics.Scanner.App\MinecraftSsForensics.Scanner.App.csproj"
$viewerAppProj = Join-Path $scriptRoot "backend\src\MinecraftSsForensics.Viewer.App\MinecraftSsForensics.Viewer.App.csproj"

$resolvedOutputDir = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot $OutputDirectory))

# 2. Restore NuGet Packages
Write-Host "[2/6] Restoring package dependencies..." -ForegroundColor Yellow
dotnet restore "$solutionPath"
if ($LASTEXITCODE -ne 0) { Write-Error "Package restore failed!"; exit $LASTEXITCODE }

# 3. Build Solution in Release Configuration
Write-Host "[3/6] Compiling solution in Release configuration..." -ForegroundColor Yellow
dotnet build "$solutionPath" -c Release --no-restore
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed!"; exit $LASTEXITCODE }

# 4. Run Automated Test Suite
if (-not $SkipTests) {
    Write-Host "[4/6] Running automated test suite..." -ForegroundColor Yellow
    dotnet test "$solutionPath" -c Release --no-build --logger "console;verbosity=normal"
    if ($LASTEXITCODE -ne 0) { Write-Error "Test suite failed!"; exit $LASTEXITCODE }
    Write-Host "      All automated verification tests passed!" -ForegroundColor Green
} else {
    Write-Host "[4/6] Skipping test execution (-SkipTests specified)." -ForegroundColor Gray
}

# 5. Publish Self-Contained Standalone Executables
Write-Host "[5/6] Publishing self-contained single-file win-x64 binaries..." -ForegroundColor Yellow

if (-not (Test-Path $resolvedOutputDir)) {
    New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
}

Write-Host "      Publishing Scanner App (MinecraftSsForensics.exe)..." -ForegroundColor Gray
dotnet publish "$scannerAppProj" `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o "$resolvedOutputDir"
if ($LASTEXITCODE -ne 0) { Write-Error "Scanner publish failed!"; exit $LASTEXITCODE }

Write-Host "      Publishing Staff Viewer App (MinecraftSsForensics.Viewer.exe)..." -ForegroundColor Gray
dotnet publish "$viewerAppProj" `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o "$resolvedOutputDir"
if ($LASTEXITCODE -ne 0) { Write-Error "Viewer publish failed!"; exit $LASTEXITCODE }

# 6. Generate Cryptographic SHA-256 Checksum Manifest
Write-Host "[6/6] Generating cryptographic SHA-256 checksums..." -ForegroundColor Yellow
$manifestPath = Join-Path $resolvedOutputDir "checksums.sha256"
$checksumLines = @()

Get-ChildItem -Path $resolvedOutputDir -Filter "*.exe" | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = $_.Name
    $line = "$hash  $name"
    $checksumLines += $line
    Set-Content -Path (Join-Path $resolvedOutputDir "$name.sha256") -Value $line -Encoding utf8
    Write-Host "      $name -> $hash" -ForegroundColor White
}

$checksumLines | Out-File -FilePath $manifestPath -Encoding utf8
Write-Host "      Checksum manifest saved to: $manifestPath" -ForegroundColor Green

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Build & Publishing Completed Successfully!" -ForegroundColor Green
Write-Host " Output Directory: $resolvedOutputDir" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

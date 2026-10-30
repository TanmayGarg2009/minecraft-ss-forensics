<#
.SYNOPSIS
    Secure, verified launcher for Minecraft SS Forensics Standalone Scanner.
.DESCRIPTION
    Downloads the official release binary and its cryptographic SHA-256 manifest,
    verifies checksum authenticity before execution, and launches the scanner.
    NEVER pipes unverified remote code directly into the shell (No irm | iex).
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = "minecraft-ss-forensics/minecraft-ss-forensics"
$releaseUrl = "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe"
$checksumUrl = "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe.sha256"

$targetDir = Join-Path $env:TEMP "MinecraftForensics"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$exePath = Join-Path $targetDir "MinecraftSsForensics.exe"
$shaPath = Join-Path $targetDir "MinecraftSsForensics.exe.sha256"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Minecraft SS Forensics - Verified Launcher" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    Write-Host "[1/4] Downloading official binary..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $releaseUrl -OutFile $exePath -UseBasicParsing

    Write-Host "[2/4] Downloading cryptographic SHA-256 manifest..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $checksumUrl -OutFile $shaPath -UseBasicParsing

    Write-Host "[3/4] Verifying cryptographic integrity..." -ForegroundColor Gray
    $expectedHash = (Get-Content $shaPath -Raw).Trim().Split(" `t`r`n")[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($actualHash -ne $expectedHash) {
        Write-Host "SECURITY ERROR: SHA-256 verification failed!" -ForegroundColor Red
        Write-Host "Expected: $expectedHash" -ForegroundColor Yellow
        Write-Host "Actual:   $actualHash" -ForegroundColor Red
        Remove-Item $exePath -Force -ErrorAction SilentlyContinue
        exit 1
    }

    Write-Host "[4/4] Cryptographic seal verified authentic: $actualHash" -ForegroundColor Green
    Write-Host "Launching Minecraft SS Forensics..." -ForegroundColor Green
    Start-Process -FilePath $exePath
}
catch {
    Write-Host "Launcher error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

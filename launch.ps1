<#
.SYNOPSIS
    Secure, verified launcher for Minecraft SS Forensics Standalone Scanner.
.DESCRIPTION
    Downloads the official release binary and its cryptographic SHA-256 manifest,
    displays live progress percentage, download speed (MB/s), and estimated time (ETA),
    verifies checksum authenticity before execution, and launches the scanner.
    NEVER pipes unverified remote code directly into the shell (No irm | iex).
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = "TanmayGarg2009/minecraft-ss-forensics"
$exeUrl = "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe"
$shaUrl = "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe.sha256"

$targetDir = Join-Path $env:TEMP "MinecraftForensics"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$exePath = Join-Path $targetDir "MinecraftSsForensics.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Minecraft SS Forensics - Verified Launcher" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    Write-Host "[1/4] Fetching cryptographic integrity manifest..." -ForegroundColor Cyan
    $wc = New-Object System.Net.WebClient
    $manifestContent = $wc.DownloadString($shaUrl)
    $expectedHash = ([regex]'[0-9a-fA-F]{64}').Match($manifestContent).Value.ToLowerInvariant()

    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        throw "Could not extract valid 64-character SHA-256 hash from release manifest."
    }
    Write-Host "      Expected SHA-256: $expectedHash" -ForegroundColor Gray

    Write-Host "[2/4] Downloading official binary with live progress..." -ForegroundColor Cyan
    $req = [System.Net.HttpWebRequest]::Create($exeUrl)
    $res = $req.GetResponse()
    $total = $res.ContentLength
    $stream = $res.GetResponseStream()
    $fs = [System.IO.File]::Create($exePath)
    $buffer = New-Object byte[] 131072
    $downloaded = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lastUpdate = 0

    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $fs.Write($buffer, 0, $read)
        $downloaded += $read

        if ($sw.ElapsedMilliseconds - $lastUpdate -gt 250) {
            $lastUpdate = $sw.ElapsedMilliseconds
            $pct = [math]::Round(($downloaded / $total) * 100, 1)
            $speed = if ($sw.Elapsed.TotalSeconds -gt 0) { ($downloaded / 1MB) / $sw.Elapsed.TotalSeconds } else { 0 }
            $eta = if ($speed -gt 0) { [math]::Round((($total - $downloaded) / 1MB) / $speed) } else { 0 }
            $curMb = [math]::Round($downloaded / 1MB, 1)
            $totMb = [math]::Round($total / 1MB, 1)
            $spdMb = [math]::Round($speed, 1)
            Write-Progress -Activity "Downloading Minecraft SS Forensics ($totMb MB)" -Status "$pct% ($curMb MB / $totMb MB) at $spdMb MB/s - ETA: ${eta}s" -PercentComplete $pct
        }
    }
    $fs.Close()
    $stream.Close()
    $res.Close()
    Write-Progress -Activity "Downloading Minecraft SS Forensics" -Completed
    Write-Host "      Download completed successfully." -ForegroundColor Green

    Write-Host "[3/4] Verifying cryptographic integrity..." -ForegroundColor Cyan
    $actualHash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "      Actual SHA-256:   $actualHash" -ForegroundColor Gray

    if ($actualHash -ne $expectedHash) {
        Write-Host "SECURITY ERROR: SHA-256 verification failed!" -ForegroundColor Red
        Write-Host "Expected: $expectedHash" -ForegroundColor Yellow
        Write-Host "Actual:   $actualHash" -ForegroundColor Red
        Remove-Item $exePath -Force -ErrorAction SilentlyContinue
        exit 1
    }

    Write-Host "[4/4] Cryptographic seal verified authentic!" -ForegroundColor Green
    Write-Host "Launching Minecraft SS Forensics..." -ForegroundColor Green
    Start-Process -FilePath $exePath
}
catch {
    Write-Host "Launcher error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

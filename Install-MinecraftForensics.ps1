<#
.SYNOPSIS
    Installs and launches the Minecraft SS Forensics Standalone Scanner & Staff Viewer.

.DESCRIPTION
    Downloads the verified, self-contained single-file Windows executable (MinecraftSsForensics.exe)
    from GitHub Releases, verifies its cryptographic SHA-256 hash against published release checksums,
    and launches the application.

.PARAMETER Repository
    The GitHub repository in 'owner/repo' format. Defaults to 'minecraft-ss-forensics/minecraft-ss-forensics'.

.PARAMETER TargetDirectory
    The destination directory on the local machine. Defaults to '$env:LOCALAPPDATA\MinecraftSsForensics'.

.PARAMETER SkipLaunch
    Downloads and verifies the binary without launching it.

.EXAMPLE
    .\launch.ps1
    Or run via secure one-line download-and-verify command.
#>

[CmdletBinding()]
param(
    [string]$Repository = "TanmayGarg2009/minecraft-ss-forensics",
    [string]$TargetDirectory = "$env:LOCALAPPDATA\MinecraftSsForensics",
    [switch]$SkipLaunch
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Minecraft SS Forensics - Standalone Installer & Verifier" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Prepare target directory
if (-not (Test-Path $TargetDirectory)) {
    New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
}

$ExePath = Join-Path $TargetDirectory "MinecraftSsForensics.exe"
$ChecksumPath = Join-Path $TargetDirectory "MinecraftSsForensics.exe.sha256"

# 2. Query GitHub Releases API for latest asset
Write-Host "[*] Checking latest release from GitHub ($Repository)..." -ForegroundColor Yellow
$ApiUrl = "https://api.github.com/repos/$Repository/releases/latest"

try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "MinecraftForensics-Installer" }
    $TagName = $Release.tag_name
    Write-Host "[+] Found latest release: $TagName" -ForegroundColor Green

    $ExeAsset = $Release.assets | Where-Object { $_.name -like "*MinecraftSsForensics*.exe" -or $_.name -like "*.exe" } | Select-Object -First 1
    $ShaAsset = $Release.assets | Where-Object { $_.name -like "*.sha256" -or $_.name -like "*checksums.txt*" } | Select-Object -First 1

    if ($ExeAsset) {
        $DownloadUrl = $ExeAsset.browser_download_url
        Write-Host "[*] Downloading executable: $($ExeAsset.name) ($([math]::Round($ExeAsset.size / 1MB, 2)) MB)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ExePath -UseBasicParsing

        # 3. Cryptographic hash verification if checksum asset is published
        if ($ShaAsset) {
            Write-Host "[*] Downloading cryptographic SHA-256 release seal..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $ShaAsset.browser_download_url -OutFile $ChecksumPath -UseBasicParsing
            $PublishedChecksum = (Get-Content $ChecksumPath | Select-String -Pattern "([a-fA-F0-9]{64})").Matches.Value

            if ($PublishedChecksum) {
                Write-Host "[*] Computing local SHA-256 digest..." -ForegroundColor Yellow
                $LocalHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
                $ExpectedHash = $PublishedChecksum.Trim().ToLowerInvariant()

                if ($LocalHash -eq $ExpectedHash) {
                    Write-Host "[+] Cryptographic verification PASSED: SHA-256 seal matches ($LocalHash)." -ForegroundColor Green
                } else {
                    Write-Error "SECURITY TAMPER ALERT! Downloaded binary hash ($LocalHash) does not match published release seal ($ExpectedHash)."
                    Remove-Item $ExePath -Force -ErrorAction SilentlyContinue
                    return
                }
            }
        } else {
            Write-Host "[i] No published checksum asset found; computing local SHA-256: $((Get-FileHash $ExePath -Algorithm SHA256).Hash)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "[!] No compiled release binary found in latest release assets." -ForegroundColor Red
        Write-Host "    If running from local source, run: .\run-scanner.bat" -ForegroundColor Yellow
        return
    }
}
catch {
    Write-Host "[!] Could not fetch from GitHub Releases: $_" -ForegroundColor Yellow
    Write-Host "[*] Attempting local build check if running inside repository..." -ForegroundColor Yellow
    $LocalReleaseExe = Join-Path $PSScriptRoot "release\win-x64\MinecraftSsForensics.Scanner.App.exe"
    if (Test-Path $LocalReleaseExe) {
        Copy-Item -Path $LocalReleaseExe -Destination $ExePath -Force
        Write-Host "[+] Copied local compiled binary to $ExePath" -ForegroundColor Green
    } else {
        Write-Host "[-] Please build using 'dotnet publish' or run '.\run-scanner.bat'." -ForegroundColor Red
        return
    }
}

# 4. Launch executable
if (-not $SkipLaunch -and (Test-Path $ExePath)) {
    Write-Host "[*] Launching Minecraft SS Forensics Scanner & Staff Viewer..." -ForegroundColor Cyan
    Start-Process -FilePath $ExePath
}

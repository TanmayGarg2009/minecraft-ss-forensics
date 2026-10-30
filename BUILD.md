# Build & Developer Packaging Guide

This document describes how to build, test, and publish **Minecraft SS Forensics** from source.

---

## 1. Prerequisites

- **SDK**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (Version 8.0.400 or later).
- **OS**: Windows 10 or Windows 11 (x64).
- **Tools**: Git, PowerShell 5.1 or PowerShell 7+.

---

## 2. Restoring & Building the Solution

Clone the repository and set your .NET environment path:

```powershell
# Set path if using user-local .NET SDK install
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"

# Restore NuGet dependencies
dotnet restore backend/MinecraftSsForensics.sln

# Build solution in Release configuration
dotnet build backend/MinecraftSsForensics.sln -c Release
```

---

## 3. Running Automated Tests

The test suite contains 79 automated xUnit tests validating all forensic collectors, tamper resistance, and security controls:

```powershell
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"

dotnet test backend/MinecraftSsForensics.sln -c Release --logger "console;verbosity=normal"
```

Expected result:
```
Passed! - Failed: 0, Passed: 79, Skipped: 0, Total: 79
```

---

## 4. Publishing Single-File Release Binaries

To produce standalone, self-contained single-file executables with zero runtime dependencies:

```powershell
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"

# 1. Publish Scanner Executable
dotnet publish backend/src/MinecraftSsForensics.Scanner.App/MinecraftSsForensics.Scanner.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o release/win-x64

# 2. Publish Staff Viewer Executable
dotnet publish backend/src/MinecraftSsForensics.Viewer.App/MinecraftSsForensics.Viewer.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o release/win-x64
```

### Generating SHA-256 Checksums
```powershell
Get-FileHash release/win-x64/*.exe -Algorithm SHA256 |
  ForEach-Object { "$($_.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($_.Path))" } |
  Out-File -FilePath release/win-x64/checksums.sha256 -Encoding utf8
```

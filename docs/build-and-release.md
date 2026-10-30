# Developer Build & Release Guide

This document describes how to compile, test, package, and publish the Minecraft SS Forensics Standalone Windows application.

---

## 1. Prerequisites

- **Operating System**: Windows 10 (version 1809+) or Windows 11 (x64)
- **.NET SDK**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+

---

## 2. Repository Layout

```
ssing tool/
├── backend/
│   ├── MinecraftSsForensics.sln             # Master standalone solution
│   ├── src/
│   │   ├── MinecraftSsForensics.Scanner/     # Core forensic engine, collectors, integrity
│   │   ├── MinecraftSsForensics.Scanner.App/ # Player scan WPF GUI
│   │   └── MinecraftSsForensics.Viewer.App/  # Dedicated Staff Report Viewer WPF GUI
│   └── tests/
│       └── MinecraftSsForensics.Scanner.Tests/ # 56 automated verification tests
├── docs/                                     # Guides and architectural specs
├── launch.ps1                                # Verified PowerShell launcher script
├── run-scanner.bat                           # Local development scanner launcher
├── run-viewer.bat                            # Local development viewer launcher
└── .github/workflows/release.yml             # GitHub release CI/CD workflow
```

---

## 3. Local Compilation & Testing

### Build Entire Solution
```powershell
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"
dotnet build backend/MinecraftSsForensics.sln
```

### Run Automated Forensic Test Suite
```powershell
dotnet test backend/MinecraftSsForensics.sln --verbosity normal
```
*Executes all 56 verification tests covering renamed mods, lookalikes, policy violations (possession vs execution), static bytecode capabilities, JNA provenance checks, corrupt seal tampering, and backward compatibility.*

### Launch in Development Mode
- Scanner: Double-click `run-scanner.bat` or run:
  ```powershell
  dotnet run --project backend/src/MinecraftSsForensics.Scanner.App/MinecraftSsForensics.Scanner.App.csproj
  ```
- Viewer: Double-click `run-viewer.bat` or run:
  ```powershell
  dotnet run --project backend/src/MinecraftSsForensics.Viewer.App/MinecraftSsForensics.Viewer.App.csproj
  ```

---

## 4. Publishing Self-Contained Standalone Binaries

To produce single-file executables (`MinecraftSsForensics.exe` and `MinecraftSsForensics.Viewer.exe`) that run on any Windows machine without requiring a pre-installed .NET runtime:

```powershell
# 1. Publish Player Scanner
dotnet publish backend/src/MinecraftSsForensics.Scanner.App/MinecraftSsForensics.Scanner.App.csproj `
  --configuration Release --runtime win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  --output release/win-x64

# 2. Publish Staff Viewer
dotnet publish backend/src/MinecraftSsForensics.Viewer.App/MinecraftSsForensics.Viewer.App.csproj `
  --configuration Release --runtime win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  --output release/win-x64
```

Rename `release/win-x64/MinecraftSsForensics.Scanner.App.exe` to `MinecraftSsForensics.exe`.
Rename `release/win-x64/MinecraftSsForensics.Viewer.App.exe` to `MinecraftSsForensics.Viewer.exe`.

### Calculate Cryptographic SHA-256 Checksums
```powershell
Get-FileHash release/win-x64/MinecraftSsForensics.exe -Algorithm SHA256
Get-FileHash release/win-x64/MinecraftSsForensics.Viewer.exe -Algorithm SHA256
```

---

## 5. Automated CI/CD GitHub Releases

The project includes an automated GitHub Actions workflow in `.github/workflows/release.yml`:
1. Push a git release tag (e.g., `git tag v2.0.0 && git push origin v2.0.0`).
2. The workflow executes all 50 unit and integration tests on `windows-latest`.
3. If all tests pass, it packages the self-contained executable, generates `MinecraftSsForensics.exe.sha256`, and attaches both artifacts to a new GitHub Release.

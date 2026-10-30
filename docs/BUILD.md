# Developer Build & Publishing Guide — Minecraft Forensic Scanner

**Target Framework:** .NET 8.0 LTS (`net8.0-windows`)  
**Operating System:** Windows 10 / Windows 11 (x64)  
**Dependencies:** Self-Contained / Zero Server Dependencies

---

## 1. Prerequisites

- Microsoft Windows 10 (Build 19041+) or Windows 11 (x64)
- .NET 8.0 SDK (v8.0.400 or higher)
- PowerShell 5.1 or PowerShell 7+

---

## 2. Building from Source

### Quick Build (Solution-Wide)
```powershell
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"
dotnet build backend/MinecraftSsForensics.sln -c Release
```

### Running Automated Test Suite (79 Tests)
```powershell
$env:DOTNET_ROOT = "$env:USERPROFILE\.dotnet"; $env:PATH = "$env:DOTNET_ROOT;$env:PATH"
dotnet test backend/MinecraftSsForensics.sln -c Release --logger "console;verbosity=normal"
```

---

## 3. Publishing Standalone Single-File Binaries

The application is engineered to compile into self-contained, single-file Windows executables that require no pre-installed .NET runtime on the player's or staff's computer.

### Step 1: Publish Player Scanner (`MinecraftSsForensics.exe`)
```powershell
dotnet publish backend/src/MinecraftSsForensics.Scanner.App/MinecraftSsForensics.Scanner.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o release/win-x64
```

### Step 2: Publish Staff Report Viewer (`MinecraftSsForensics.Viewer.exe`)
```powershell
dotnet publish backend/src/MinecraftSsForensics.Viewer.App/MinecraftSsForensics.Viewer.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o release/win-x64
```

### Step 3: Compute Cryptographic SHA-256 Checksums
```powershell
Get-FileHash -Path release\win-x64\MinecraftSsForensics.exe -Algorithm SHA256 | Format-List
Get-FileHash -Path release\win-x64\MinecraftSsForensics.Viewer.exe -Algorithm SHA256 | Format-List
```

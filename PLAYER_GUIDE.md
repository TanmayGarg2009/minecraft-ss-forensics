# Player Guide — Running a Forensic Scan

Welcome to the **Minecraft SS Forensics** player guide. This document explains how to download, review, run, and export your forensic report when requested by server staff or tournament referees.

---

## 1. Prerequisites

- **Operating System**: Windows 10 or Windows 11 (64-bit).
- **Permissions**: Standard User (No administrator privileges required for basic scans; elevated privileges enable full system prefetch and driver audits).
- **Network**: Internet connection is completely optional (offline scans are fully supported).

---

## 2. Launching the Scanner

You can run the scanner using either the pre-compiled executable or the verified PowerShell one-line launcher.

### Option A: Direct Executable Launch
1. Download `MinecraftSsForensics.exe` from the official release page.
2. Double-click `MinecraftSsForensics.exe` to launch.
3. If Windows SmartScreen displays an *Unrecognized App* banner:
   - Click **More info**.
   - Click **Run anyway**.
   *(This occurs because community open-source releases do not hold costly commercial EV code-signing certificates).*

### Option B: Verified PowerShell One-Line Launcher
Open Windows PowerShell (Run as Administrator recommended for full prefetch access) and paste:

```powershell
& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $repo = "TanmayGarg2009/minecraft-ss-forensics"; $dir = "$env:TEMP\MinecraftForensics"; New-Item -ItemType Directory -Path $dir -Force | Out-Null; $exe = "$dir\MinecraftSsForensics.exe"; Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe" -OutFile $exe; $expected = ((Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/MinecraftSsForensics.exe.sha256").Content -split '\s+')[0].ToLowerInvariant(); if ((Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expected) { Start-Process -FilePath $exe } else { Write-Error "SHA-256 verification failed!" } }
```

> [!NOTE]
> This command verifies the SHA-256 cryptographic hash of the downloaded binary before launching it. It never executes unverified remote code.

---

## 3. Configuring the Scan & Privacy Consent

When the scanner opens, you will see the **Forensic Consent & Scope Gate**:

1. **Review Scopes**:
   - `Filesystem Scanning`: Scans standard Minecraft folders (`.minecraft/mods`), common launchers (Prism, Lunar, Badlion), Downloads, and Recycle Bin.
   - `Running Processes`: Checks active `javaw.exe` instances and loaded modules.
   - `Historical Execution`: Audits Windows Prefetch and BAM/DAM records for execution timestamps.
   - `USB History`: Audits USB storage device connection records.
   - `Sensitive Browser Audit`: **Unchecked by default**. If enabled, scans only for specific cheat domains (`vape.gg`, `drip.gg`, etc.). General browsing history, passwords, and personal web traffic are never collected.
2. **Select Policy Mode**:
   - Choose the ruleset specified by your server (e.g., *Competitive PvP*, *Strict HCF*, or *Casual*).
3. **Click Start Forensic Scan**.

---

## 4. Reviewing Results & Exporting Reports

Once the scan finishes:
1. Review the executive summary cards:
   - **Verdict**: Overall compliance with the selected policy.
   - **Verified Mods**: Legitimately matched mods from Modrinth/CurseForge.
   - **Unverified Artifacts**: Custom or modified JAR files requiring manual staff review.
   - **Correlated Violations**: Any detected prohibited cheats or macro tools.
2. Click **Export Report**:
   - Choose **Save Portable JSON (`.json`)** to save the raw sealed forensic payload.
   - Choose **Save Interactive HTML (`.html`)** to generate a local self-contained browser report.
3. Save the file to your Desktop or Documents folder.
4. Provide the exported `.json` or `.html` file to the staff member or tournament referee via Discord or your ticket system.

> [!TIP]
> The exported `.json` file contains a cryptographic seal (`SHA256-CANONICAL-V2`). Do not open or modify the file in text editors, as altering any character will break the seal and flag the report as tampered.

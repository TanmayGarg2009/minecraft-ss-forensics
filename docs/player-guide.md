# Player Guide: Running a Minecraft Screenshare Forensic Audit

If server staff or competitive anti-cheat moderators request a screenshare (SS) investigation, you can complete the audit quickly, safely, and transparently using this open-source tool.

---

## 1. Fast Download & Launch

You have two convenient options to run the scanner:

### Option A: One-Line PowerShell Command (Recommended)
Open **PowerShell** on your Windows PC and paste:
```powershell
irm https://raw.githubusercontent.com/minecraft-ss-forensics/minecraft-ss-forensics/main/Install-MinecraftForensics.ps1 | iex
```
*This downloads the official, signed release binary, verifies its SHA-256 cryptographic checksum, and opens the application.*

### Option B: Download Standalone Executable Directly
1. Download `MinecraftSsForensics.exe` from the official repository Releases page.
2. Double-click to launch (no installer, .NET runtime, or background service required).

---

## 2. Reviewing Consent & Scope

When the tool opens, you are in **Player Scan Mode**:

1. **Verify Collection Scope**:
   - By default, standard forensic checks are selected (Active Minecraft Mods, Java Process Memory, Execution Artifacts, Registry Traces, Connected USB Storage).
   - **Sensitive Browser History**: This category is **explicitly unchecked by default**. If staff requests domain-level cheat verification, you can choose whether to check this box.
   - The scanner **never** inspects passwords, cookies, session tokens, search queries, or personal web traffic.
2. **Select Gamemode Policy**: Choose the policy matching the server you play on (e.g., `Crystal PvP`, `Sword PvP`, or `SMP`).
3. **Choose Scan Mode**:
   - `Quick Scan`: Audits active Minecraft installations and loaded game memory (typically completes in 5–15 seconds).
   - `Full Scan`: Performs deep inspection of historical execution artifacts and filesystem staging areas (15–45 seconds).
4. **Click "I Consent & Start Forensic Audit"**.

---

## 3. Reviewing Your Results Locally

When the scan finishes, you retain complete control over your data:

- **Executive Verdict**: Shows whether any cheat software, prohibited mods, or suspicious traces were detected.
- **Categorized Findings**: Displays all detected items with explanations of what is proven and what is not proven.
- **Local Review Before Sharing**: Nothing is transmitted over the internet or uploaded to any server. You can review the entire report locally on your screen before deciding to share it.

---

## 4. Saving & Submitting Your Report

Click the export buttons at the bottom of the scan results:

1. **Save JSON Report (`.json`)**:
   - Saves the structured forensic file to your preferred folder (e.g. `Desktop\ForensicReport.json`).
   - Give this file to server staff so they can inspect it inside the Staff Viewer.
2. **Save Interactive HTML Report (`.html`)**:
   - Generates a standalone, interactive report you can double-click and open in Chrome, Edge, or Firefox.
   - Requires no internet connection and includes full styling, search, and category filters.
3. **Save Markdown Summary (`.md`)**:
   - Formats the report for text sharing or AI-assisted second-stage reviews.

---

## 5. Privacy & Security Guarantees

- **100% Read-Only**: The tool cannot delete your files, alter your registry, or modify your Minecraft installation.
- **Zero Cloud Uploads**: There is no backend server, database, or hosted web API. Your report exists only on your computer until you personally send the file.
- **Open-Source & Auditable**: The entire source code is public and open for inspection.

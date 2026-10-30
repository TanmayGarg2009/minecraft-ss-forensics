# Evidence Sources Reference Manual — Minecraft Forensic Scanner

**Version:** 2.1.0-standalone  
**Scope:** Technical specification of all 18 evidence collection sources

---

## Technical Evidence Source Matrix

| Evidence Source | Windows Artifact Queried | Acquisition Method | Retention & Limits | Permissions Required | Potential False Positives & Legitimate Explanations |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **1. Mod JAR Inventory** | `.minecraft/mods/*.jar` | File stream / SHA-256 | Indefinite until deleted | User | Old, disabled, or unselected mods in inactive profile directories. |
| **2. Mod Metadata** | `mcmod.info`, `fabric.mod.json`, `mods.toml` | SafeArchiveInspector ZIP read | Indefinite | User | Mod developers testing private builds or unofficial forks. |
| **3. Bytecode Structure** | JVM Class Files & Constant Pools | Constant pool & method table parser | Indefinite | User | Utility mods utilizing reflection or LWJGL for legitimate optimization/UI. |
| **4. Active Processes** | Windows Process Table | `Process.GetProcesses()` | Real-time only | User (Self) / Admin (Elevated) | Background developer tools, IDEs, or local Java servers. |
| **5. JVM Arguments** | WMI `Win32_Process` | WMI query (`CommandLine`) | Process lifetime | User (Self) / Admin (System) | Custom launcher optimization flags or memory allocations. |
| **6. Loaded Modules (DLLs)** | Process PEB Loader List | `Process.Modules` | Process lifetime | User (Self) / Admin (Elevated) | Discord overlay, OBS Game Capture, graphics drivers, RivaTuner. |
| **7. Authenticode Trust** | PE Authenticode Signatures | `WinVerifyTrust` (wintrust.dll) | Indefinite | User | Open-source utilities signed with self-signed test certificates. |
| **8. Windows Prefetch** | `C:\Windows\Prefetch\*.pf` | `PrefetchParser` (MAM decompress) | Up to 1024 entries / 8 timestamps | **Administrator** | Renamed executables or launcher wrapper scripts. |
| **9. BAM / DAM** | `HKLM\SYSTEM\...\bam\State\UserSettings` | Registry query + `QueryDosDevice` | Rolling OS cache (~few weeks) | **Administrator** | Antivirus scanners executing files in sandbox. |
| **10. UserAssist** | `HKCU\...\UserAssist\{GUID}\Count` | Registry query + ROT13 + 72-byte binary | Indefinite until profile wipe | User | Files launched months ago prior to server registration. |
| **11. PCA (Compatibility)** | `HKCU\...\AppCompatFlags\Compatibility Assistant` | Registry query | Indefinite | User | Applications prompted for compatibility by Windows. |
| **12. Run / RunOnce** | `HKCU`/`HKLM` Run keys | Registry query | Indefinite until removed | User / Admin | Auto-updating mouse or keyboard macro software. |
| **13. RecentDocs MRU** | `HKCU\...\RecentDocs\.jar` | Registry binary MRU decoding | Last 20-30 opened files | User | Downloading mods for friend, singleplayer, or server testing. |
| **14. USB Storage (USBSTOR)**| `HKLM\...\Enum\USBSTOR` & SetupAPI | Registry query + `setupapi.dev.log` | Indefinite | User | Backup flash drives, school USBs, phone charging connections. |
| **15. PowerShell History** | `ConsoleHost_history.txt` | Text stream (FileShare.ReadWrite) | Last 4096 commands | User | Development scripts, IT admin commands, git operations. |
| **16. Chromium History** | `History` SQLite database (Opt-In) | Read-only SQLite query | Rolling browser history | User (Opt-In) | Researching anti-cheat articles, Reddit threads, YouTube reviews. |
| **17. Services & Drivers** | `HKLM\...\Services` & Event 7045 | Registry + System Event Log | Rolling log (~weeks) | User / Admin | Anti-cheat drivers (EasyAntiCheat, Vanguard, BattlEye), GPU tools. |
| **18. Recycle Bin ($Recycle.Bin)**| `$I` index files on all fixed volumes | Binary `$I` parser + `$R` hash | Until emptied | User | Cleaning up old mods or test files weeks prior to match. |

# Forensic Accuracy Audit — Minecraft Forensic Scanner

**Date of Audit:** October 30, 2026  
**Auditor:** Senior Windows Forensics Engineer  
**Scope:** Rigorous forensic evaluation of all 18 evidence collection sources in `backend/src/MinecraftSsForensics.Scanner`.

---

## 1. Overview of Forensic Accuracy & Evidentiary Standards

In forensic screensharing (SS) for competitive gaming, false positives can wrongfully ruin a player's reputation and result in permanent bans, while false negatives allow sophisticated ghost clients, injectors, and self-destructing bypasses to remain undetected. 

Every forensic artifact must meet four fundamental evidentiary criteria:
1. **Provenance:** Clear, unmanipulated artifact origin directly attributable to the target executable or user.
2. **Temporal Integrity:** Accurate, verifiable timestamps (UTC) that reflect actual execution or file system activity without fabrication.
3. **Resilience to Anti-Forensics:** Defense against artifact cleaning, string encryption, file locking, and process masquerading.
4. **Contextual Correlation:** Evidence must distinguish between possession of an inactive file vs active in-game execution.

---

## 2. 10-Question Evaluation of All 18 Forensic Evidence Sources

---

### Source 1: Running Processes
- **1. Artifact Queried:** Active Windows processes via `Process.GetProcesses()`.
- **2. Acquisition Method:** Standard .NET Process API + Win32 `OpenProcess`/`QueryFullProcessImageName`.
- **3. Permissions / UAC:** Non-elevated processes can inspect standard user processes. Fails with `Win32Exception` (Access Denied) when inspecting elevated processes or anti-cheat protected games without Admin.
- **4. File Locks / In-Use:** Handled gracefully; processes remain open.
- **5. Timestamps:** `StartTime` is queried and parsed correctly to UTC.
- **6. Anti-Forensic Evasion:** Process hollowing, process renaming, or injection into explorer/svchost will mask the true executable name.
- **7. False Positive Risks:** Low. Process name matching (`javaw.exe`, `lunarclient.exe`) is standard.
- **8. False Negative Risks:** Medium. Injected cheats that run inside `javaw.exe` memory do not appear as separate processes.
- **9. Forensic Integrity:** High. Read-only query; no process memory modified.
- **10. Industry Comparison:** Basic. Lacks parent-process ID (PPID) tree tracking found in Paladin or EchoSS.

---

### Source 2: Loaded Modules (DLLs)
- **1. Artifact Queried:** Dynamic link libraries mapped into process memory space via `process.Modules`.
- **2. Acquisition Method:** `ProcessModuleCollection` enumeration.
- **3. Permissions / UAC:** Access Denied if target process is running at higher integrity level.
- **4. File Locks / In-Use:** Mapped DLLs cannot be deleted while process lives.
- **5. Timestamps:** File write/creation times queried from disk.
- **6. Anti-Forensic Evasion:** Manual DLL mapping (reflective DLL injection) bypasses PEB module list (`InLoadOrderModuleList`), leaving no module entry.
- **7. False Positive Risks:** High due to [BUG-P0-02]: Unsigned module alerts rely on flawed Authenticode checks.
- **8. False Negative Risks:** High. Cannot detect unlinked or reflectively loaded cheats.
- **9. Forensic Integrity:** High. Read-only PEB query.
- **10. Industry Comparison:** Primitive. Commercial SS tools use kernel drivers or VAD (Virtual Address Descriptor) memory walking to detect unmapped executable code pages (`PAGE_EXECUTE_READWRITE`).

---

### Source 3: JNA Native Extraction Cache
- **1. Artifact Queried:** Temporary native DLLs unpacked by Java Native Access in `%LOCALAPPDATA%\Temp\jna-*\`.
- **2. Acquisition Method:** Directory enumeration of `jna-*` folders.
- **3. Permissions / UAC:** User-level access; no elevation required.
- **4. File Locks / In-Use:** Flawed. Locked DLLs trigger `IOException` and are skipped ([BUG-P1-05]).
- **5. Timestamps:** File creation and write timestamps recorded.
- **6. Anti-Forensic Evasion:** Cheats can configure JNA to unpack to custom memory locations or delete on unload.
- **7. False Positive Risks:** Low. Matches hashes/strings against known JNA cheat hooks.
- **8. False Negative Risks:** High if cheat holds an exclusive lock or uses custom native loaders.
- **9. Forensic Integrity:** High. Read-only file inspection.
- **10. Industry Comparison:** Novel heuristic, but fragile implementation compared to memory-based JNA inspection.

---

### Source 4: Process Command Lines & JVM Arguments
- **1. Artifact Queried:** Process command line strings via WMI `Win32_Process`.
- **2. Acquisition Method:** WMI query: `SELECT ProcessId, CommandLine FROM Win32_Process`.
- **3. Permissions / UAC:** Requires admin to inspect command lines of elevated processes on modern Windows 10/11.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Correlated with process start time.
- **6. Anti-Forensic Evasion:** PEB spoofing (`RTL_USER_PROCESS_PARAMETERS`) can overwrite command-line memory in seconds.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** Medium. Cheats injected after launch or via internal class injection don't alter startup command lines.
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Matches industry standard for launcher/JVM argument auditing (checking `-javaagent`, `--add-opens`, etc.).

---

### Source 5: Windows Prefetch
- **1. Artifact Queried:** `C:\Windows\Prefetch\*.pf`.
- **2. Acquisition Method:** File enumeration.
- **3. Permissions / UAC:** Requires Administrator privileges to read `C:\Windows\Prefetch`. Non-admin scans fail silently.
- **4. File Locks / In-Use:** Handled.
- **5. Timestamps:** Reads file write time; fails to parse the 8 embedded execution timestamps inside the SCCA structure ([BUG-P1-03]).
- **6. Anti-Forensic Evasion:** Modern Windows compresses Prefetch with `MAM` compression. The scanner does not decompress `MAM`, missing internal execution counts and loaded files.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** Very High. Renamed cheat executables are missed because embedded DLL and file path references are not read.
- **9. Forensic Integrity:** High (read-only).
- **10. Industry Comparison:** Significantly below industry standard (EchoSS and Paladin fully parse Win10/11 MAM-compressed Prefetch files).

---

### Source 6: Background Activity Moderator (BAM / DAM)
- **1. Artifact Queried:** `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` and `dam`.
- **2. Acquisition Method:** Windows Registry query.
- **3. Permissions / UAC:** Requires elevated Administrator privileges.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Parses 64-bit `FILETIME` binary registry data accurately.
- **6. Anti-Forensic Evasion:** Device path formatting (`\Device\HarddiskVolumeX`) is mishandled for secondary volumes ([BUG-P1-04]).
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** Medium. Unmapped drive letters lead to missed file correlations.
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Good foundation; requires proper device-to-DOS-drive translation.

---

### Source 7: UserAssist Registry Keys
- **1. Artifact Queried:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
- **2. Acquisition Method:** Windows Registry query + ROT13 decoding.
- **3. Permissions / UAC:** User level; no elevation required.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Flawed. Fails to parse the 72-byte binary value, leaving timestamps and run counts empty ([BUG-P2-03]).
- **6. Anti-Forensic Evasion:** Trivial to wipe or disable via registry cleaning tools.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** High if cleaned; incomplete forensic data when present.
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Incomplete. Standard tools parse run counts and focus times.

---

### Source 8: Program Compatibility Assistant (PcaSvc)
- **1. Artifact Queried:** `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store` and `Persisted`.
- **2. Acquisition Method:** Registry key enumeration.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Extracted from PcaSvc binary value headers.
- **6. Anti-Forensic Evasion:** Clearing PcaSvc requires stopping the service, which is flagged by event logs.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** Low for standalone executable cheats.
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Solid implementation.

---

### Source 9: Run / RunOnce Autostart Keys
- **1. Artifact Queried:** `HKCU` and `HKLM` `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`.
- **2. Acquisition Method:** Registry enumeration.
- **3. Permissions / UAC:** Mixed (HKCU is user; HKLM is system).
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** None provided by Windows for individual registry values.
- **6. Anti-Forensic Evasion:** Cheats rarely configure autostart persistence; mostly relevant for macro tools.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** N/A (Not primary cheat persistence vector).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Standard.

---

### Source 10: RecentDocs Registry MRU
- **1. Artifact Queried:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`.
- **2. Acquisition Method:** Registry value name query.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Missing.
- **6. Anti-Forensic Evasion:** Does not parse binary MRU list order or binary payload; only collects key names ([BUG-P3-04]).
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** High (empty artifact names).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Poor.

---

### Source 11: USB Storage Device History (USBSTOR)
- **1. Artifact Queried:** `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`.
- **2. Acquisition Method:** Registry subkey traversal.
- **3. Permissions / UAC:** Read-accessible by standard user.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Missing. Leaves `LastConnectedTime` as null ([BUG-P2-03]).
- **6. Anti-Forensic Evasion:** USB serial number and friendly name are preserved by the OS.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** High (cannot prove USB was plugged in during match).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Incomplete. Professional tools parse `setupapi.dev.log` to establish exact USB connection and disconnection timestamps.

---

### Source 12: PowerShell Readline Command History
- **1. Artifact Queried:** `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.
- **2. Acquisition Method:** File read with sharing flags.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** Shared read.
- **5. Timestamps:** None recorded by PSReadLine file format natively.
- **6. Anti-Forensic Evasion:** `Clear-History` or deleting the txt file.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** High (easily deleted).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Standard.

---

### Source 13: Chromium Browser History
- **1. Artifact Queried:** `History` SQLite file in Chrome, Edge, Brave, Opera, Vivaldi.
- **2. Acquisition Method:** Raw byte copy and UTF-8 string search.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** Handled via temp copy.
- **5. Timestamps:** **CRITICAL DEFECT: Fabricates `DateTimeOffset.UtcNow`** ([BUG-P0-03]).
- **6. Anti-Forensic Evasion:** Browser history clearing or incognito browsing.
- **7. False Positive Risks:** **Extremely High** (substring matches in Google searches or Reddit threads).
- **8. False Negative Risks:** Medium.
- **9. Forensic Integrity:** **UNACCEPTABLE** (Fabricates timestamps).
- **10. Industry Comparison:** Far below industry standard.

---

### Source 14: Service & Kernel Driver Installations (Event ID 7045 & HKLM Services)
- **1. Artifact Queried:** Windows System Event Log (Event ID 7045) & `HKLM\SYSTEM\CurrentControlSet\Services`.
- **2. Acquisition Method:** `System.Diagnostics.EventLog` + Registry.
- **3. Permissions / UAC:** Read-only admin access for full event logs.
- **4. File Locks / In-Use:** N/A.
- **5. Timestamps:** Accurate generation timestamps from Event Log records.
- **6. Anti-Forensic Evasion:** Flawed Authenticode validation bypass ([BUG-P0-02]).
- **7. False Positive Risks:** High (falsely marks drivers as signed when cert is unvalidated).
- **8. False Negative Risks:** Event truncation due to 50-item limit ([BUG-P2-04]).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Good concept, broken verification.

---

### Source 15: SetupAPI Device Installation Logs (`setupapi.dev.log`)
- **1. Artifact Queried:** `C:\Windows\inf\setupapi.dev.log`.
- **2. Acquisition Method:** Text parsing of section headers.
- **3. Permissions / UAC:** Read-only access by standard users.
- **4. File Locks / In-Use:** Shared read.
- **5. Timestamps:** Parses `start:` and `end:` log timestamps.
- **6. Anti-Forensic Evasion:** Highly durable; difficult to modify without system integrity compromise.
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** Low.
- **9. Forensic Integrity:** Excellent.
- **10. Industry Comparison:** Solid implementation.

---

### Source 16: File System Discovery (Downloads, Desktop, Temp)
- **1. Artifact Queried:** User folders: Downloads, Desktop, `%TEMP%`.
- **2. Acquisition Method:** `DirectoryInfo.GetFiles()`.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** Handled.
- **5. Timestamps:** Accurate NTFS creation and modification times.
- **6. Anti-Forensic Evasion:** Subdirectories are never scanned ([BUG-P2-01]).
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** High (placing files in a subfolder evades discovery).
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Incomplete directory recursion.

---

### Source 17: Recycle Bin ($Recycle.Bin)
- **1. Artifact Queried:** `C:\$Recycle.Bin`.
- **2. Acquisition Method:** Directory enumeration of raw recycle bin directories.
- **3. Permissions / UAC:** Standard user can read their own user SID subfolder in `$Recycle.Bin`.
- **4. File Locks / In-Use:** Handled.
- **5. Timestamps:** File system write time.
- **6. Anti-Forensic Evasion:** Fails completely to parse `$I` metadata files ([BUG-P1-02]).
- **7. False Positive Risks:** Low.
- **8. False Negative Risks:** **100% False Negative** for files deleted to the Recycle Bin.
- **9. Forensic Integrity:** High.
- **10. Industry Comparison:** Broken. Professional tools always parse `$I` headers.

---

### Source 18: Mod JAR Bytecode / Constant Pool Inspection
- **1. Artifact Queried:** Minecraft mod `.jar` files (ZIP archives containing `.class` files).
- **2. Acquisition Method:** Safe ZIP extraction + class constant pool parsing.
- **3. Permissions / UAC:** User-level access.
- **4. File Locks / In-Use:** Handled via memory streams.
- **5. Timestamps:** ZIP entry timestamps.
- **6. Anti-Forensic Evasion:** Fails against string obfuscators ([BUG-P2-02]).
- **7. False Positive Risks:** Medium (keyword collisions).
- **8. False Negative Risks:** High against obfuscated clients.
- **9. Forensic Integrity:** High (safe ZIP traversal prevents zip-slip).
- **10. Industry Comparison:** Moderate.

---

## 3. Summary Scorecard

| Forensic Metric | Score (out of 10) | Evaluation |
| :--- | :---: | :--- |
| **Tamper Resistance** | **2 / 10** | Cryptographic report seal excludes evidence collections ([BUG-P0-01]). |
| **Timestamp Fidelity** | **4 / 10** | Browser history fabricates timestamps ([BUG-P0-03]); USB/UserAssist timestamps omitted. |
| **False Positive Rate** | **5 / 10** | Execution policy triggers bans for background game sessions ([BUG-P1-01]). |
| **Detection Coverage** | **6 / 10** | Good coverage across 18 sources, but Recycle Bin and subdirectories are non-functional. |
| **Anti-Forensic Defense**| **3 / 10** | Obfuscated bytecode, compressed Prefetch, and self-signed certs bypass detection. |

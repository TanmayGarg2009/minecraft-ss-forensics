# Feature Gap Analysis — Minecraft Forensic Scanner

**Date of Audit:** October 30, 2026  
**Auditor:** QA Architect & Forensics Engineer  
**Scope:** Complete feature inventory, implementation verification, and competitive capability comparison.

---

## 1. Feature Status Classification

Every feature in the repository is evaluated against five rigorous implementation states:
- `IMPLEMENTED_AND_VERIFIED`: Feature is fully implemented, functions correctly on Windows, has real logic, and meets forensic standards.
- `PARTIALLY_IMPLEMENTED`: Logic exists but contains major omissions (e.g., missing subfolders, unparsed metadata, lack of decompression).
- `BROKEN`: Feature exists in code but fails completely due to fundamental logic defects or API misuse.
- `STUBBED_OR_MOCKED`: Empty methods, hardcoded returns, or unexecuted prototypes.
- `NOT_IMPLEMENTED`: Desirable or industry-standard capability absent from the codebase.

---

## 2. Feature Inventory & Current Status

| Feature / Capability | Subsystem | Status | Notes / Limitations |
| :--- | :--- | :---: | :--- |
| **Standalone Offline Execution** | Core / WPF | `IMPLEMENTED_AND_VERIFIED` | Zero reliance on web server, database, or network connectivity. Runs completely offline. |
| **User Consent & Audit Scope Selection** | Scanner App | `IMPLEMENTED_AND_VERIFIED` | Explicit consent screen, scan mode toggle (Standard vs Full Deep Scan). |
| **Local JSON Report Export** | Scanner App | `IMPLEMENTED_AND_VERIFIED` | Exports full report to user-chosen path via `SaveFileDialog`. |
| **Interactive Staff Report Viewer** | Viewer App | `IMPLEMENTED_AND_VERIFIED` | Tabbed UI, search/filtering, statistics summary, and assessment breakdown. |
| **Self-Contained HTML Exporter** | Viewer App | `IMPLEMENTED_AND_VERIFIED` | Generates zero-dependency standalone HTML files with embedded styling. |
| **Mod Inventory & Hash Verification** | Mod Scanner | `IMPLEMENTED_AND_VERIFIED` | Computes SHA-1/SHA-256 hashes, extracts `mcmod.info` and `fabric.mod.json`. |
| **Mod Policy Engine (Allowed/Prohibited)** | Policy Engine | `IMPLEMENTED_AND_VERIFIED` | Evaluates server rules: `PROHIBITED_POSSESSION`, `PROHIBITED_EXECUTION`, `ALLOWED`. |
| **Process Enumeration & Start Time** | Process Scanner | `IMPLEMENTED_AND_VERIFIED` | Enumerates active processes, PIDs, and process start timestamps. |
| **WMI Command Line Inspection** | Process Scanner | `IMPLEMENTED_AND_VERIFIED` | Extracts full JVM startup flags (`-javaagent`, `-Xmx`, etc.). |
| **SetupAPI Device Installation Parsing** | SetupAPI Scanner | `IMPLEMENTED_AND_VERIFIED` | Parses `setupapi.dev.log` device connection headers. |
| **PowerShell History Collection** | Historical Scanner | `IMPLEMENTED_AND_VERIFIED` | Reads `ConsoleHost_history.txt` with safe file-share access. |
| **PcaSvc Program Compatibility History** | Registry Scanner | `IMPLEMENTED_AND_VERIFIED` | Reads Compatibility Assistant registry execution logs. |
| **Cryptographic Report Seal** | Security / Engine | `BROKEN` | Excludes evidence payload from hash. Easily bypassed ([BUG-P0-01]). |
| **Authenticode Signature Verification** | Process / Service | `BROKEN` | Uses `X509Certificate.CreateFromSignedFile`; ignores chain & validity ([BUG-P0-02]). |
| **Browser History Extraction** | Browser Scanner | `BROKEN` | Fabricates `UtcNow` visit timestamps and raw string searches SQLite ([BUG-P0-03]). |
| **Recycle Bin Deleted File Discovery** | File Scanner | `BROKEN` | Fails to parse Windows `$I` index files; 100% false negative ([BUG-P1-02]). |
| **Execution Policy Violation Correlation** | Correlation Engine | `BROKEN` | False positive bans when any Java game is running ([BUG-P1-01]). |
| **Windows Prefetch Execution Analysis** | Historical Scanner | `PARTIALLY_IMPLEMENTED` | Fails to decompress Win10/11 `MAM` headers; reads file write time only ([BUG-P1-03]). |
| **BAM / DAM Execution History** | Historical Scanner | `PARTIALLY_IMPLEMENTED` | Parses binary `FILETIME`, but mishandles secondary volume paths ([BUG-P1-04]). |
| **UserAssist Registry Analysis** | Registry Scanner | `PARTIALLY_IMPLEMENTED` | Decodes ROT13 names, but ignores 72-byte execution count & timestamp ([BUG-P2-03]). |
| **USBSTOR Device History** | USB Scanner | `PARTIALLY_IMPLEMENTED` | Extracts device IDs, but leaves `LastConnectedTime` as null ([BUG-P2-03]). |
| **Directory File System Discovery** | File Scanner | `PARTIALLY_IMPLEMENTED` | `maxDepth` is ignored; subdirectories are never scanned ([BUG-P2-01]). |
| **Bytecode / Class Analysis** | Static Analyzer | `PARTIALLY_IMPLEMENTED` | Constant pool strings only; opcodes & instructions not parsed ([BUG-P2-02]). |
| **Event Log Service Installation (7045)** | Service Scanner | `PARTIALLY_IMPLEMENTED` | Arbitrary 50-event truncation limit; synchronous query ([BUG-P2-04]). |
| **RecentDocs MRU Analysis** | Registry Scanner | `PARTIALLY_IMPLEMENTED` | Reads registry value keys, but ignores binary MRU filename targets ([BUG-P3-04]). |
| **NTFS USN Journal Parsing** | Forensics | `NOT_IMPLEMENTED` | Does not parse `$UsnJrnl` for deleted, moved, or wiped files. |
| **NTFS Master File Table ($MFT) Parsing** | Forensics | `NOT_IMPLEMENTED` | Does not inspect MFT records for wiped file traces. |
| **Shimcache / AppCompatCache Parsing** | Forensics | `NOT_IMPLEMENTED` | Missing primary Windows execution cache in registry. |
| **Amcache.hve Registry Hive Parsing** | Forensics | `NOT_IMPLEMENTED` | Missing SHA-1 execution database for uninstalled/deleted programs. |
| **DNS Client Cache Inspection** | Forensics | `NOT_IMPLEMENTED` | Does not inspect resolved IP/domain cache for cheat host connections. |
| **JVM Memory & Injected DLL Inspection** | Forensics | `NOT_IMPLEMENTED` | No VAD walking or memory scanning for unlinked injected cheats. |
| **Screen Recording / Streaming Detection** | Forensics | `NOT_IMPLEMENTED` | Does not detect active recording hooks (OBS, Discord overlay, GameBar). |
| **Self-Destruct Wiper Script Detection** | Forensics | `NOT_IMPLEMENTED` | Does not detect batch scripts or commands used to wipe forensic trails. |

---

## 3. Competitive Feature Gap Analysis

### Comparison: Minecraft Forensic Scanner vs Industry Standard SS Tools (Paladin, EchoSS, Ocean)

```mermaid
radar-chart
    title Forensic Capabilities Comparison
    axes
        "Offline Report Sharing" : 90
        "Consent & Transparency" : 95
        "Mod Inventory / Hashes" : 85
        "Execution History (Prefetch/BAM)" : 50
        "Deleted File Recovery (Recycle/USN)" : 20
        "Memory & Injection Detection" : 15
        "Registry Forensics" : 55
        "Anti-Tamper & Security" : 30
```

### Key Competitive Gaps:

1. **NTFS USN Change Journal ($UsnJrnl):**
   - *Industry Standard:* Modern screenshare tools rely heavily on the NTFS USN Journal. Even if a player permanently deletes a cheat (`Shift+Delete`) or runs a wiper script, the USN Journal records the exact timestamp, original filename, and file deletion reason (`FILE_DELETE`).
   - *Current Implementation:* Completely absent. The scanner relies solely on the user directory scans and the broken Recycle Bin scanner.

2. **AppCompatCache (Shimcache) & Amcache.hve:**
   - *Industry Standard:* Shimcache (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`) and Amcache (`C:\Windows\appcompat\Programs\Amcache.hve`) maintain permanent records of executable paths, file sizes, last modification dates, and SHA-1 hashes of executables run on Windows.
   - *Current Implementation:* Absent. The scanner only inspects UserAssist and BAM.

3. **In-Memory Injection & Virtual Address Descriptor (VAD) Walking:**
   - *Industry Standard:* Leading tools scan memory allocations in `javaw.exe` looking for non-image-backed executable memory pages (`MEM_COMMIT` + `PAGE_EXECUTE_READWRITE`), detecting ghost clients like Vape v4 even after the injector self-destructs.
   - *Current Implementation:* Relies solely on standard .NET `process.Modules` (which only shows DLLs registered in the PEB loader list).

4. **Cryptographic Anti-Tamper Sealing:**
   - *Industry Standard:* Reports are digitally signed with an embedded private key or HMAC computed over the full JSON payload, preventing player alterations.
   - *Current Implementation:* The existing seal hashes only 15 scalar fields ([BUG-P0-01]), allowing players to freely edit findings.

---

## 4. Priority Assessment for Feature Completion

1. **Fix Broken Features First:**
   - Repair Report Integrity Seal (P0).
   - Fix Authenticode signature verification (P0).
   - Implement real SQLite parsing for browser history (P0).
   - Repair $Recycle.Bin parsing with $I parser (P1).
   - Correct game execution policy correlation (P1).

2. **Complete Partially Implemented Collectors:**
   - Decompress Windows 10/11 Prefetch `MAM` headers.
   - Add directory recursion to File Discovery.
   - Parse UserAssist binary run counts and timestamps.
   - Parse BAM device volume names to DOS drive letters.

3. **High-Value New Implementations:**
   - Add Shimcache (`AppCompatCache`) parser.
   - Add basic USN Journal query via `FSCTL_READ_USN_JOURNAL`.

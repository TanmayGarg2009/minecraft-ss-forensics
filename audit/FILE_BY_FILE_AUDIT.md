# File-by-File Audit — Minecraft Forensic Scanner

**Date of Audit:** October 30, 2026  
**Auditor:** Senior Software Auditor & QA Engineer  
**Scope:** Exhaustive audit across all 64 source files in the repository.

---

## 1. Project: `MinecraftSsForensics.Scanner` (Core Library)

### Directory: `Engine/`

#### 1. `Engine/StandaloneScannerEngine.cs`
- **Lines:** 651
- **Quality Rating:** B+
- **Status:** Active / Production Core
- **Role:** Main scanning orchestrator for the standalone application suite. Coordinates all 18 evidence collectors, policy evaluation, and summary aggregation.
- **Identified Issues:**
  - Does not accept or propagate a `CancellationToken` ([BUG-P3-02]).
  - Calls synchronous I/O routines within async methods without explicit background offloading.
  - Hardcodes execution mode defaults.

#### 2. `Engine/ScannerEngine.cs`
- **Lines:** 720
- **Quality Rating:** F (Dead Code)
- **Status:** Unreferenced / Obsolete Stage 1 Legacy Code
- **Role:** Legacy scanner engine leftover from the ASP.NET client-server architecture.
- **Identified Issues:**
  - Produces obsolete `SubmitReportRequest` DTOs.
  - Never invoked by `MinecraftSsForensics.Scanner.App` or `Viewer.App`.
  - Duplicates scanning logic across 720 lines ([BUG-P2-05]).
  - **Action:** Delete file.

#### 3. `Engine/EvidenceCorrelationEngine.cs`
- **Lines:** 220
- **Quality Rating:** C
- **Status:** Active / High-Severity Defect
- **Role:** Correlates discovered mods, files, and registry entries with active processes and historical logs to evaluate game policy violations.
- **Identified Issues:**
  - **[BUG-P1-01]:** Marks all discovered mods as executed if *any* process named `java` or `javaw` is running, causing catastrophic false positive bans for players running vanilla Minecraft.
  - Lacks JVM classpath verification.

#### 4. `Engine/ReportIntegrityValidator.cs`
- **Lines:** 115
- **Quality Rating:** F (Critical Security Bypass)
- **Status:** Active / Broken Security
- **Role:** Computes and verifies SHA-256 report seal for tamper detection.
- **Identified Issues:**
  - **[BUG-P0-01]:** Computes seal over 15 scalar metadata fields only. All actual evidence collections (`Findings`, `ModInventory`, etc.) are omitted, allowing anyone to modify findings in JSON with zero integrity failure.
  - Verification test suite has zero negative tamper tests.

#### 5. `Engine/CheatDetectionDatabase.cs`
- **Lines:** 380
- **Quality Rating:** A-
- **Status:** Active / Production
- **Role:** Built-in signature database of known Minecraft cheat clients, injectors, autoclickers, DLL hooks, and suspicious domains.
- **Identified Issues:**
  - Relies primarily on filename and hash lookups; lacks fuzzy matching for obfuscated file variants.

---

### Directory: `Scanners/`

#### 6. `Scanners/HistoricalEvidenceScanner.cs`
- **Lines:** 210
- **Quality Rating:** C+
- **Status:** Active / Incomplete
- **Role:** Collects Windows Prefetch, BAM/DAM, and PowerShell readline history.
- **Identified Issues:**
  - **[BUG-P1-03]:** Does not decompress Windows 10/11 `MAM` Prefetch files; reads file timestamps only.
  - **[BUG-P1-04]:** Fails to map BAM `\Device\HarddiskVolumeX` device paths to DOS drive letters.
  - Hardcodes `C:\Windows\Prefetch` ([BUG-P3-01]).

#### 7. `Scanners/ProcessScanner.cs`
- **Lines:** 265
- **Quality Rating:** D+
- **Status:** Active / Critical Flaw
- **Role:** Enumerates running processes, mapped modules, JVM arguments, and JNA cache directories.
- **Identified Issues:**
  - **[BUG-P0-02]:** Uses `X509Certificate.CreateFromSignedFile`, bypassing Authenticode signature validation (marks self-signed or invalid certs as valid).
  - **[BUG-P1-05]:** JNA cache inspection fails on active file locks due to exclusive sharing mode.

#### 8. `Scanners/ServiceAndDriverScanner.cs`
- **Lines:** 185
- **Quality Rating:** C
- **Status:** Active / Flawed
- **Role:** Audits Windows Services, kernel drivers, Event ID 7045, and `setupapi.dev.log`.
- **Identified Issues:**
  - **[BUG-P0-02]:** Driver signature validation bypass via `X509Certificate.CreateFromSignedFile`.
  - **[BUG-P2-04]:** Event ID 7045 query arbitrarily limits results to 50 items and runs synchronously.

#### 9. `Scanners/RegistryScanner.cs`
- **Lines:** 160
- **Quality Rating:** C
- **Status:** Active / Partial
- **Role:** Inspects UserAssist, PcaSvc, Run/RunOnce, and RecentDocs registry keys.
- **Identified Issues:**
  - **[BUG-P2-03]:** Decodes UserAssist names but ignores the 72-byte binary payload containing run counts and execution timestamps.
  - **[BUG-P3-04]:** Reads RecentDocs value names without decoding binary MRU filename targets.
  - Unhandled permission exceptions in protected subkeys ([BUG-P3-03]).

#### 10. `Scanners/UsbHistoryScanner.cs`
- **Lines:** 85
- **Quality Rating:** C-
- **Status:** Active / Partial
- **Role:** Enumerate USBSTOR registry keys to track connected external storage devices.
- **Identified Issues:**
  - **[BUG-P2-03]:** Leaves `LastConnectedTime` as null; does not correlate with setupapi logs or registry write times.

#### 11. `Scanners/BrowserHistoryScanner.cs`
- **Lines:** 120
- **Quality Rating:** F (Fabricated Data)
- **Status:** Active / Critical Flaw
- **Role:** Inspects Chromium browser history for visits to known cheat distribution domains.
- **Identified Issues:**
  - **[BUG-P0-03]:** Does not parse SQLite binary format; decodes database as raw UTF-8 string and searches substrings.
  - **Fabricates `VisitTime = DateTimeOffset.UtcNow`**, falsely telling server staff the player visited cheat sites at the moment of the scan.

#### 12. `Scanners/FileDiscoveryScanner.cs`
- **Lines:** 195
- **Quality Rating:** D
- **Status:** Active / High-Severity Defect
- **Role:** Scans Downloads, Desktop, Temp, and $Recycle.Bin for cheat files.
- **Identified Issues:**
  - **[BUG-P1-02]:** Fails to parse Windows Recycle Bin `$I` index files; 100% false negative rate for deleted cheats.
  - **[BUG-P2-01]:** `maxDepth = 2` parameter is ignored; never recurses into subdirectories.
  - Hardcodes `C:\$Recycle.Bin` ([BUG-P3-01]).

#### 13. `Scanners/SafeArchiveInspector.cs`
- **Lines:** 140
- **Quality Rating:** A
- **Status:** Active / Secure
- **Role:** Safely opens and extracts ZIP/JAR files, enforcing file count, uncompressed size limits, and path traversal (Zip Slip) protections.
- **Identified Issues:** None. Well-architected with defensive boundaries.

#### 14. `Scanners/StaticBytecodeAnalyzer.cs`
- **Lines:** 190
- **Quality Rating:** C+
- **Status:** Active / Partial
- **Role:** Parses Java `.class` files to detect cheat strings and injection hooks.
- **Identified Issues:**
  - **[BUG-P2-02]:** Only parses constant pool `CONSTANT_Utf8` strings. Does not parse JVM opcodes or bytecode instructions, easily defeated by standard string obfuscators.

#### 15. `Scanners/ModScanner.cs`
- **Lines:** 175
- **Quality Rating:** A-
- **Status:** Active / Production
- **Role:** Discovers `.minecraft` directory, scans `mods/` folders, parses `mcmod.info` and `fabric.mod.json`, and calculates SHA-1 / SHA-256 hashes.
- **Identified Issues:** None of critical severity.

---

### Directory: `Policy/` & `Export/` & `Models/`

#### 16. `Policy/ModPolicyEngine.cs`
- **Lines:** 215
- **Quality Rating:** B+
- **Status:** Active / Production
- **Role:** Evaluates server rules (`PROHIBITED_POSSESSION`, `PROHIBITED_EXECUTION`, `ALLOWED`).
- **Identified Issues:**
  - Path comparison lacks normalization with `Path.GetFullPath()` ([BUG-P2-06]).

#### 17. `Export/StandaloneHtmlExporter.cs`
- **Lines:** 490
- **Quality Rating:** A-
- **Status:** Active / Production
- **Role:** Generates self-contained, standalone HTML forensic reports with embedded dark/light CSS and vanilla JS interactive filtering.
- **Identified Issues:** Minor CSS edge cases in deep mobile views; excellent desktop rendering.

#### 18. `Export/ReportExporter.cs`
- **Lines:** 705
- **Quality Rating:** F (Dead Code)
- **Status:** Unreferenced / Obsolete Stage 1
- **Role:** Legacy HTML exporter for obsolete `SubmitReportRequest` models.
- **Identified Issues:** 705 lines of duplicate, unused code ([BUG-P2-05]).
- **Action:** Delete file.

#### 19. `Models/StandaloneReport.cs`
- **Lines:** 285
- **Quality Rating:** A
- **Status:** Active / Core Contract
- **Role:** Primary DTO modeling the complete standalone forensic report, summary counts, system info, and all 18 evidence collections.

#### 20. `Models/LegacyModels.cs`
- **Lines:** 110
- **Quality Rating:** F (Dead Code)
- **Status:** Unreferenced / Obsolete Stage 1
- **Role:** Holds `SubmitReportRequest` and related DTOs.
- **Action:** Delete file.

---

## 2. Project: `MinecraftSsForensics.Scanner.App` (WPF Scanner)

#### 21. `MainWindow.xaml` & `MainWindow.xaml.cs`
- **Lines:** 380 (XAML: 190, CS: 190)
- **Quality Rating:** B+
- **Status:** Active / Desktop App
- **Role:** Player-facing UI wizard managing consent, progress reporting, results summary, and report saving.
- **Identified Issues:**
  - Consent checkbox lacks granular collector toggles.
  - Missing cancel button during active scan execution.

---

## 3. Project: `MinecraftSsForensics.Viewer.App` (WPF Viewer)

#### 22. `MainWindow.xaml` & `MainWindow.xaml.cs`
- **Lines:** 540 (XAML: 260, CS: 280)
- **Quality Rating:** B+
- **Status:** Active / Desktop App
- **Role:** Staff-facing UI for opening `.json` reports, verifying report seals, searching findings, and exporting standalone HTML files.
- **Identified Issues:**
  - UI displays green "Cryptographic integrity verified" badge even when evidence collections have been tampered with, due to [BUG-P0-01].

---

## 4. Project: `MinecraftSsForensics.Scanner.Tests` (Test Suite)

#### 23–30. Test Classes (8 files, 56 tests total)
- `CheatDetectionDatabaseTests.cs` (8 tests) — B+
- `ModPolicyEngineTests.cs` (10 tests) — B+
- `EvidenceCorrelationEngineTests.cs` (8 tests) — C (Masks Bug P1-01)
- `ReportIntegrityValidatorTests.cs` (6 tests) — F (Zero negative tamper tests; masks Bug P0-01)
- `SafeArchiveInspectorTests.cs` (6 tests) — A
- `StaticBytecodeAnalyzerTests.cs` (6 tests) — B
- `StandaloneHtmlExporterTests.cs` (6 tests) — A
- `FileDiscoveryScannerTests.cs` (6 tests) — C (Masks Bugs P1-02 and P2-01)

---

## 5. Root Launch Scripts & Documentation

#### 31. `launch.ps1` & `run-scanner.bat`
- **Quality Rating:** A
- **Status:** Active
- **Role:** PowerShell and batch convenience wrappers to launch the standalone scanner and viewer without manual CLI commands.
- **Identified Issues:** Well-written with environment detection and error handling.

#### 32. `docs/STANDALONE_FORENSIC_SUITE.md`
- **Quality Rating:** B+
- **Status:** Active Documentation
- **Role:** Architecture overview and user guide.
- **Identified Issues:** Documents the report seal as providing absolute tamper protection, unaware of [BUG-P0-01].

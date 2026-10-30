# Remediation Roadmap — Minecraft Forensic Scanner

**Date of Audit:** October 30, 2026  
**Auditor:** Senior Software Architect & Windows Forensics Engineer  
**Objective:** A phased, actionable engineering roadmap to remediate all verified vulnerabilities, forensic inaccuracies, dead code, and test gaps identified in the October 2026 audit.

---

## Roadmap Overview & Gantt Progression

```mermaid
flowchart TD
    subgraph Phase 1: Critical Security & Integrity [Urgent / Days 1-2]
        P1_1["Fix Report Seal Merkle/Payload Hashing (P0-01)"]
        P1_2["Implement Real Authenticode WinVerifyTrust (P0-02)"]
        P1_3["Replace Browser UTF-8 with SQLite Parser (P0-03)"]
        P1_4["Implement Negative Tamper Test Suite"]
    end

    subgraph Phase 2: Forensic Accuracy & False Positives [High / Days 3-5]
        P2_1["Decouple Policy Execution from Background Java (P1-01)"]
        P2_2["Implement Windows Recycle Bin $I Parser (P1-02)"]
        P2_3["Implement Win10/11 Prefetch MAM Decompression (P1-03)"]
        P2_4["Fix BAM Device to DOS Drive Mapping (P1-04)"]
        P2_5["Add Shared File Access to JNA Inspector (P1-05)"]
    end

    subgraph Phase 3: Architectural Cleanup & Quality [Medium / Days 6-7]
        P3_1["Delete Dead Legacy ScannerEngine & Exporter (P2-05)"]
        P3_2["Fix Directory Recursion in File Discovery (P2-01)"]
        P3_3["Parse UserAssist & USB Timestamps/Counts (P2-03)"]
        P3_4["Refactor EventLog 7045 with XPath Query (P2-04)"]
        P3_5["Enhance Bytecode Opcode Inspection (P2-02)"]
    end

    subgraph Phase 4: Hardening & Enterprise Features [Enhancements / Days 8-10]
        P4_1["Implement Granular Privacy & Consent UI"]
        P4_2["Add Shimcache (AppCompatCache) Parser"]
        P4_3["Add NTFS USN Change Journal Collector"]
        P4_4["Add CancellationToken Propagation Across Scanners"]
    end

    Phase 1 --> Phase 2
    Phase 2 --> Phase 3
    Phase 3 --> Phase 4
```

---

# Phase 1: Critical Security & Integrity Fixes (Days 1–2)

### Task 1.1: Fix Cryptographic Report Seal Bypass ([BUG-P0-01])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Engine/ReportIntegrityValidator.cs`
- **Actions:**
  1. Remove the scalar-only string concatenation in `ComputeReportSeal`.
  2. Implement canonical, deterministic JSON serialization of the `StandaloneReport` object with `ReportSeal` set to `null` or empty string.
  3. Sort dictionary keys and ensure invariant culture formatting across all timestamps.
  4. Compute SHA-256 over the canonical serialized payload.
  5. In `VerifyReportIntegrity`, strip the incoming seal, serialize the report using the identical canonical formatter, compute the SHA-256 hash, and perform a constant-time comparison (`CryptographicOperations.FixedTimeEquals`).
- **Success Criteria:** Mutating any string, path, or classification inside `Findings` or `ModInventory` causes `VerifyReportIntegrity` to return `IsValid = false`.

### Task 1.2: Implement Authentic WinVerifyTrust Signature Verification ([BUG-P0-02])
- **Files:**
  - `backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs`
  - `backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs`
- **Actions:**
  1. Remove `X509Certificate.CreateFromSignedFile(path)` for trust validation.
  2. P/Invoke `WinVerifyTrust` from `wintrust.dll` using `WINTRUST_ACTION_GENERIC_VERIFY_V2` (`{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}`).
  3. Pass flags: `WTD_REVOKE_NONE` (or `WTD_REVOKE_WHOLECHAIN` if online) and `WTD_CHOICE_FILE`.
  4. Only mark `record.IsSigned = true` when `WinVerifyTrust` returns `0` (`ERROR_SUCCESS`).
  5. Log signature errors (`TRUST_E_NOSIGNATURE`, `CERT_E_UNTRUSTEDROOT`, `CERT_E_EXPIRED`).
- **Success Criteria:** Self-signed, invalidly hashed, or forged driver/module certificates are flagged as unsigned/untrusted.

### Task 1.3: Replace Browser Raw UTF-8 Scraping with SQLite Driver ([BUG-P0-03])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/BrowserHistoryScanner.cs`
- **Actions:**
  1. Add `Microsoft.Data.Sqlite` dependency.
  2. Copy the browser `History` file to a unique temp file to avoid locks.
  3. Open SQLite connection with `Mode=ReadOnly`.
  4. Query table:
     ```sql
     SELECT url, title, visit_count, last_visit_time FROM urls WHERE url LIKE @pattern
     ```
  5. Convert WebKit timestamp (`(last_visit_time / 1000000) - 11644473600`) to authentic UTC `DateTimeOffset`.
  6. **Never** assign `DateTimeOffset.UtcNow` to historical web visits.
- **Success Criteria:** Browser history reports authentic historical visit times and zero false positives on Reddit/Google search queries.

---

# Phase 2: Forensic Accuracy & False Positive Elimination (Days 3–5)

### Task 2.1: Eliminate Policy False Positives from Background Java Sessions ([BUG-P1-01])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Engine/EvidenceCorrelationEngine.cs`
- **Actions:**
  1. Remove `bool hasRunningGame = report.RunningProcesses.Any(...)` as a global execution flag for all mods.
  2. Correlate mod execution specifically with:
     - The process command-line arguments of active Java instances (checking whether the mod jar is on the `-classpath` or `-javaagent`).
     - Prefetch entries matching the specific loader or mod filename.
     - BAM/DAM records specifically matching the game launcher instance that loaded that profile.
  3. If a mod was not loaded by the running process, evaluate policy under `PROHIBITED_POSSESSION` only, leaving `PROHIBITED_EXECUTION` as unviolated.
- **Success Criteria:** Running vanilla Minecraft with a restricted mod present in an inactive folder does not trigger an execution policy ban.

### Task 2.2: Implement Windows Recycle Bin $I File Format Parser ([BUG-P1-02])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs`
- **Actions:**
  1. Detect `$I` index files in `C:\$Recycle.Bin\<SID>\`.
  2. Parse the binary format:
     - Header: 8-byte version (1 for Win7/8, 2 for Win10/11).
     - File size: 8-byte int64.
     - Deletion timestamp: 8-byte `FILETIME` (convert to `DateTimeOffset`).
     - Original file path: UTF-16LE null-terminated string at offset 24 (or 28).
  3. Pair each `$I` file with its corresponding `$R` data file.
  4. Run `CheatDetectionDatabase.MatchFileName()` against the recovered original filename.
- **Success Criteria:** Deleted cheat files sent to Recycle Bin are accurately identified with their original names and exact deletion times.

### Task 2.3: Implement Windows 10/11 Prefetch MAM Decompression ([BUG-P1-03])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs`
- **Actions:**
  1. Inspect first 4 bytes of `.pf` files for `MAM\x04` magic header.
  2. If `MAM`, call native `ntdll.dll` API `RtlDecompressBufferEx` with compression engine `COMPRESSION_FORMAT_XPRESS_HUFF`.
  3. Parse the standard decompressed SCCA header (version 30 for Win10/11).
  4. Extract run count, all 8 execution timestamps, and the list of loaded file paths and DLLs.
- **Success Criteria:** Renamed cheat executables that load Java native injection libraries are exposed via internal Prefetch dependency lists.

### Task 2.4: Fix BAM Volume Device Mapping ([BUG-P1-04])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs`
- **Actions:**
  1. Implement a volume cache mapping `\Device\HarddiskVolumeX` to DOS drive letters (`C:`, `D:`) via P/Invoke `QueryDosDevice`.
  2. Replace device prefixes before evaluating file paths and cheat rules.

### Task 2.5: Safe Shared Access for JNA Inspection ([BUG-P1-05])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs`
- **Actions:**
  1. Open file streams using `FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)`.
  2. Handle transient extraction locks gracefully without aborting the scan.

---

# Phase 3: Architectural Cleanup & Quality (Days 6–7)

### Task 3.1: Purge Dead Stage 1 Code ([BUG-P2-05])
- **Files to Delete:**
  - `backend/src/MinecraftSsForensics.Scanner/Engine/ScannerEngine.cs`
  - `backend/src/MinecraftSsForensics.Scanner/Export/ReportExporter.cs`
  - `backend/src/MinecraftSsForensics.Scanner/Models/LegacyModels.cs`
- **Actions:**
  1. Remove these 3 files from the project.
  2. Verify all 4 solution projects build with 0 errors.

### Task 3.2: Implement Directory Recursion in File Discovery ([BUG-P2-01])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs`
- **Actions:**
  1. Refactor `ScanDirectory` to iterate subdirectories recursively up to `maxDepth`.
  2. Guard against circular symlinks / junction points by checking `FileAttributes.ReparsePoint`.

### Task 3.3: Parse UserAssist & USB Timestamps ([BUG-P2-03])
- **Files:**
  - `backend/src/MinecraftSsForensics.Scanner/Scanners/RegistryScanner.cs`
  - `backend/src/MinecraftSsForensics.Scanner/Scanners/UsbHistoryScanner.cs`
- **Actions:**
  1. Read 72-byte binary payload from UserAssist; parse run count at offset 4 and `FILETIME` at offset 60.
  2. Query `setupapi.dev.log` for USB hardware IDs to populate `LastConnectedTime`.

### Task 3.4: Optimize Event Log Query 7045 ([BUG-P2-04])
- **File:** `backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs`
- **Actions:**
  1. Replace `System.Diagnostics.EventLog` with `System.Diagnostics.Eventing.Reader.EventLogReader`.
  2. Use XPath filter `*[System[(EventID=7045)]]` to stream events in reverse order without arbitrary 50-item cutoff.

---

# Phase 4: Hardening & Enterprise Features (Days 8–10)

1. **Granular Consent UI:** Add individual checkboxes in `MinecraftSsForensics.Scanner.App/MainWindow.xaml` allowing players to opt-in/opt-out of sensitive collectors.
2. **Path Anonymization:** Sanitize `C:\Users\<Name>\` to `%USERPROFILE%\` across all JSON output.
3. **Shimcache (`AppCompatCache`) Parser:** Parse `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` to discover historically executed programs even if Prefetch was purged.
4. **Cancellation Support:** Pass `CancellationToken` from WPF UI through `StandaloneScannerEngine.RunScanAsync` down to all individual collectors.

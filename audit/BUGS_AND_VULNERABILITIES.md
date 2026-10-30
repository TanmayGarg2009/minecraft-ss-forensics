# Bugs and Vulnerabilities Inventory â€” Minecraft Forensic Scanner

**Date of Audit:** October 30, 2026  
**Repository:** Minecraft Screenshare (SS) Forensics / Standalone Windows Scanner  
**Status:** AUDIT ONLY (No code modified)

---

## Severity Summary

| Severity | Count | Criteria |
| :--- | :---: | :--- |
| **P0 (Critical)** | **3** | Cryptographic integrity bypass, falsified forensic evidence, or critical security vulnerabilities. |
| **P1 (High)** | **5** | High-risk false positive bans, silent collection failures, or anti-forensic evasion vectors. |
| **P2 (Medium)** | **6** | Incomplete forensic parsing, dead legacy code, superficial string inspection. |
| **P3 (Low)** | **4** | Edge case failures, missing cancellation tokens, hardcoded system assumptions. |
| **Total** | **18** | |

---

# 1. P0 (Critical Vulnerabilities & Forensic Defects)

---

### [BUG-P0-01] Cryptographic Report Seal Excludes Evidence Payloads
- **Severity:** P0 (Critical Security)
- **Category:** Cryptographic Verification / Tamper Protection
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Engine/ReportIntegrityValidator.cs:33-47`](backend/src/MinecraftSsForensics.Scanner/Engine/ReportIntegrityValidator.cs#L33-L47)
- **Description & Root Cause:**
  `ComputeReportSeal` claims to compute a cryptographic SHA-256 seal guaranteeing the integrity of the scan report. However, the string hashed by the algorithm only contains scalar metadata:
  ```csharp
  var payload = string.Join("|",
      report.ReportId,
      report.SchemaVersion,
      report.ScannerVersion,
      report.CreatedAt.ToUnixTimeSeconds(),
      report.ScanStartedAt.ToUnixTimeSeconds(),
      report.ScanCompletedAt.ToUnixTimeSeconds(),
      report.ScanMode,
      findingsCount,
      evidenceCount,
      modsCount,
      diagnosticsCount,
      report.SummaryCounts.VerifiedMods,
      report.SummaryCounts.SuspiciousArtifacts,
      report.SummaryCounts.DuplicateFiles,
      report.SummaryCounts.ScanErrors,
      report.SummaryCounts.PolicyViolations
  );
  ```
  **The actual forensic evidence collections (`report.Findings`, `report.ModInventory`, `report.EvidenceItems`, `report.ServicesAndDrivers`, `report.CorrelatedAssessments`, `report.FileDiscoveries`, `report.ExecutionHistory`, `report.LoadedModules`, `report.RegistryEvidence`, `report.UsbEvidence`, and `report.BrowserEvidence`) are completely excluded from the payload.**
- **Exploitation / Failure Mode:**
  A player caught with cheats can open their generated `report.json` file in a text editor. They can:
  1. Rename `"Vape v4"` in `Findings` to `"OptiFine"`.
  2. Change classification from `CHEAT_DETECTED` to `OFFICIAL_MOD`.
  3. Replace file paths pointing to illegal `.jar` or `.dll` files with innocent paths.
  4. Keep the array lengths and `SummaryCounts` unchanged.
  When server staff opens the modified report in `MinecraftSsForensics.Viewer.App`, the viewer runs `ReportIntegrityValidator.VerifyReportIntegrity()` and displays:
  > *"Cryptographic integrity verified: Report data has not been modified since initial generation."* (Green Badge)
- **Remediation:**
  Serialize the complete normalized report structure (excluding the seal field itself) into deterministic, key-ordered canonical JSON (or hash every evidence collection individually into a Merkle root) and sign/hash the complete payload.

---

### [BUG-P0-02] Authenticode Signature Verification Bypass
- **Severity:** P0 (Critical Security)
- **Category:** Code Signing / Driver & DLL Integrity
- **Location:**
  - [`backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs:139`](backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs#L139)
  - [`backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs:139`](backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs#L139)
- **Description & Root Cause:**
  The scanner attempts to determine if running modules and kernel drivers are legitimately signed using .NET's `X509Certificate.CreateFromSignedFile(path)`:
  ```csharp
  var cert = X509Certificate.CreateFromSignedFile(path);
  if (cert != null)
  {
      record.IsSigned = true;
      record.SignerSubject = cert.Subject;
      record.SignerIssuer = cert.Issuer;
  }
  ```
  In Windows and .NET, `X509Certificate.CreateFromSignedFile()` only reads the embedded PKCS#7 / Authenticode certificate blob from the PE header. It does **NOT** invoke `WinVerifyTrust` (`wintrust.dll`). It performs **no cryptographic hash verification** between the certificate and the file content, **no chain validation**, **no root CA trust check**, and **no expiration or revocation check**.
- **Exploitation / Failure Mode:**
  An adversary, cheat injector, or vulnerable kernel driver can be signed with any self-signed, expired, or forged certificate (e.g., self-signed with CN="Microsoft Corporation"). The scanner will record `IsSigned = true`, exempting the malicious binary from unsigned-module and unsigned-driver alerts.
- **Remediation:**
  Call the native Windows Win32 API `WinVerifyTrust` via P/Invoke with `WINTRUST_ACTION_GENERIC_VERIFY_V2` to ensure cryptographic integrity, root authority trust, and valid timestamping.

---

### [BUG-P0-03] Browser History Timestamp Fabrication
- **Severity:** P0 (Critical Forensic Inaccuracy / Ethics)
- **Category:** Forensic Evidence Collection
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/BrowserHistoryScanner.cs:74-88`](backend/src/MinecraftSsForensics.Scanner/Scanners/BrowserHistoryScanner.cs#L74-L88)
- **Description & Root Cause:**
  Chromium browser history (`History` file) is a SQLite 3 database. The scanner attempts to read it without a SQLite driver by copying the file and decoding the raw binary bytes as a UTF-8 string:
  ```csharp
  var rawContent = Encoding.UTF8.GetString(bytes);
  foreach (var domain in SuspiciousDomains)
  {
      if (rawContent.Contains(domain, StringComparison.OrdinalIgnoreCase))
      {
          results.Add(new BrowserHistoryRecord
          {
              BrowserName = browserName,
              Url = $"https://{domain}/ (Domain match in history database)",
              Title = "Known cheat distribution / resource site",
              VisitTime = DateTimeOffset.UtcNow, // <--- FABRICATED TIMESTAMP
              VisitCount = 1
          });
      }
  }
  ```
- **Exploitation / Failure Mode:**
  1. **Fabricated Timestamp:** The scanner injects `DateTimeOffset.UtcNow` (the exact second the forensic scan is running) as the `VisitTime`. Staff reviewing the report are presented with evidence claiming the player visited a cheat website *during or immediately prior to the screenshare*, even if the visit was months ago or never occurred.
  2. **False Positives on Raw Text:** Because `rawContent` contains the entire SQLite file (including cached URLs, search engine query strings, referrer URLs, and cached page titles), any search for a news article, Reddit post, or YouTube video mentioning `vape.gg` will match `Contains("vape.gg")`.
- **Remediation:**
  Use `Microsoft.Data.Sqlite` to query the SQLite `urls` and `visits` tables properly, parsing the WebKit timestamp (`(last_visit_time / 1000000) - 11644473600`) to retrieve the authentic visit date and time. If SQLite cannot be loaded, report an unparsed raw match without fabricating a visit timestamp.

---

# 2. P1 (High-Severity Forensic & Accuracy Defects)

---

### [BUG-P1-01] False Positive Execution Policy Violations via Game Session Overlap
- **Severity:** P1 (High Forensic Inaccuracy)
- **Category:** Policy Engine / Correlation
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Engine/EvidenceCorrelationEngine.cs:88-115`](backend/src/MinecraftSsForensics.Scanner/Engine/EvidenceCorrelationEngine.cs#L88-L115)
- **Description & Root Cause:**
  When evaluating whether a mod was executed under a `PROHIBITED_EXECUTION` rule, the engine checks:
  ```csharp
  bool hasRunningGame = report.RunningProcesses.Any(p => p.ProcessName.Contains("java", StringComparison.OrdinalIgnoreCase));
  bool executed = executionRecords.Any(...) || hasRunningGame;
  ```
  If ANY process named `java` or `javaw` is running, `executed` is evaluated as `true` for **all discovered mods across all profiles**.
- **Exploitation / Failure Mode:**
  A player playing completely vanilla Minecraft on `javaw.exe` who has an unverified, experimental, or server-restricted mod sitting in an old, unselected directory will have that mod flagged as:
  > *"VIOLATION (EXECUTION BANNED): Server policy prohibits execution of 'X', and game session was running"*
  The player receives an automated policy violation and server ban for a mod that was never loaded into memory.
- **Remediation:**
  Verify execution against actual JVM process command lines (`-Djava.class.path`), loaded JAR handles in the specific Minecraft process, or verified Prefetch/BAM records matching the mod or loader.

---

### [BUG-P1-02] $Recycle.Bin File Name Matching Failure
- **Severity:** P1 (High Forensic Inaccuracy)
- **Category:** Deleted Artifact Detection
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs:132-140`](backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs#L132-L140)
- **Description & Root Cause:**
  The scanner enumerates files in `C:\$Recycle.Bin` and matches filenames using:
  ```csharp
  var match = CheatDetectionDatabase.MatchFileName(file.Name);
  ```
  When Windows deletes a file to the Recycle Bin, it renames the data file to `$R<6 random characters>.<original extension>` and creates an index file named `$I<6 random characters>.<original extension>`. The original filename is stored inside the binary `$I` file.
- **Exploitation / Failure Mode:**
  A deleted cheat named `vape-loader.exe` becomes `$R1A2B3C.exe`. The scanner checks if `$R1A2B3C.exe` matches known cheat patterns and fails to detect it. The cheat is completely ignored.
- **Remediation:**
  Implement the standard Windows Recycle Bin `$I` file format parser. Read byte offset 24 (or offset 28 in Windows 10/11) of every `$I` file to extract the true deleted filename and original deletion timestamp.

---

### [BUG-P1-03] Prefetch Parser Format Incompatibility on Modern Windows
- **Severity:** P1 (High Forensic Inaccuracy)
- **Category:** Execution History
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs:51-70`](backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs#L51-L70)
- **Description & Root Cause:**
  The Prefetch scanner inspects `.pf` files in `C:\Windows\Prefetch`. On Windows 10 and 11, Prefetch files are compressed using the proprietary Microsoft XPRESS Huffman algorithm (starting with the magic bytes `MAM\x04`). The current implementation does not decompress `MAM` headers, instead only reading file metadata (creation/write times) and searching for cheat names in raw filenames (`file.Name`).
- **Exploitation / Failure Mode:**
  Cheats executed via generic wrappers, renamed executables, or launcher scripts cannot be identified through their internal referenced DLLs, run counts, or execution timestamps stored inside the compressed Prefetch payload.
- **Remediation:**
  Incorporate native `RtlDecompressBufferEx` (using `COMPRESSION_FORMAT_XPRESS_HUFF`) to decompress `.pf` files and parse the standard SCCA header, execution counter, and referenced file tables.

---

### [BUG-P1-04] BAM/DAM Registry Path Extraction Logic Flaw
- **Severity:** P1 (High Forensic Inaccuracy)
- **Category:** Execution History
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs:98-125`](backend/src/MinecraftSsForensics.Scanner/Scanners/HistoricalEvidenceScanner.cs#L98-L125)
- **Description & Root Cause:**
  In Windows Background Activity Moderator (`BAM`), the registry key values contain paths in the format `\Device\HarddiskVolumeX\path\to\file.exe`. The scanner splits strings by backslashes without translating volume device paths to drive letters, and assumes the last component is always the executable name without verifying file existence or resolving device prefixes.
- **Exploitation / Failure Mode:**
  Execution records on secondary drives (`D:`, `E:`) or USB drives fail path normalization, resulting in unlinked or missing correlation entries.
- **Remediation:**
  Use `QueryDosDevice` via P/Invoke to map `\Device\HarddiskVolumeX` to standard logical drive letters (`C:`, `D:`) before performing forensic correlation.

---

### [BUG-P1-05] JNA Extraction Cache Scanning Race Condition
- **Severity:** P1 (High Forensic Inaccuracy)
- **Category:** Process & Memory Inspection
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs:189-215`](backend/src/MinecraftSsForensics.Scanner/Scanners/ProcessScanner.cs#L189-L215)
- **Description & Root Cause:**
  The scanner attempts to detect in-memory cheat injection by looking for JNA (Java Native Access) temp folders in `%TEMP%\jna-*\`. It reads DLLs extracted by JNA and checks if they match cheat signatures. However, JNA cleans up these files upon JVM termination, and concurrent file locking prevents read access while the JVM has the DLL mapped.
- **Exploitation / Failure Mode:**
  Active cheats locking their JNA DLLs cause unhandled `IOException` (file locked by another process), which is caught by a broad exception handler, silently skipping the analysis of the injected module.
- **Remediation:**
  Open file streams with `FileShare.ReadWrite | FileShare.Delete` sharing flags to inspect files even when locked by running Java processes.

---

# 3. P2 (Medium-Severity Deficiencies & Code Quality)

---

### [BUG-P2-01] Fake Directory Recursion in File Discovery
- **Severity:** P2 (Medium)
- **Category:** File System Discovery
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs:49, 67`](backend/src/MinecraftSsForensics.Scanner/Scanners/FileDiscoveryScanner.cs#L49)
- **Description & Root Cause:**
  `ScanDirectory` defines a parameter `int maxDepth = 2`:
  ```csharp
  private void ScanDirectory(string rootPath, string category, List<FileDiscoveryRecord> results, int maxDepth = 2)
  ```
  However, inside the method:
  ```csharp
  var dirInfo = new DirectoryInfo(rootPath);
  var files = dirInfo.GetFiles("*.*", SearchOption.TopDirectoryOnly);
  ```
  The method never queries child directories (`GetDirectories()`) and never recurses.
- **Exploitation / Failure Mode:**
  Any cheat downloaded into subdirectories of `Downloads` (e.g., `Downloads\Minecraft Cheats\`) or folders on the `Desktop` is completely ignored.
- **Remediation:**
  Implement genuine breadth-first or depth-first recursion bounded by `maxDepth`.

---

### [BUG-P2-02] Bytecode Analyzer Inspects Constant Pool Strings Only
- **Severity:** P2 (Medium)
- **Category:** Static Analysis
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/StaticBytecodeAnalyzer.cs:104-180`](backend/src/MinecraftSsForensics.Scanner/Scanners/StaticBytecodeAnalyzer.cs#L104-L180)
- **Description & Root Cause:**
  `AnalyzeClassFile` parses the class file constant pool and extracts `CONSTANT_Utf8` entries. It searches these raw strings for keywords like `"autoclicker"`, `"aimassist"`, `"reach"`. It does not parse JVM bytecode instructions, method attributes, opcodes (`invokevirtual`, `getfield`), or ASM structures.
- **Exploitation / Failure Mode:**
  1. Standard string obfuscators (ProGuard, Allatori, Stringer) encrypt or hide constant pool strings, resulting in 100% false negatives against real cheat clients.
  2. Legitimate mods containing benign strings or log messages mentioning these words trigger false positives.
- **Remediation:**
  Incorporate a lightweight class parser or ASM visitor to inspect actual method invocations, reflection patterns, and network packet hooks rather than raw strings.

---

### [BUG-P2-03] Missing Timestamps in USB History & Unparsed UserAssist Data
- **Severity:** P2 (Medium)
- **Category:** Registry Forensics
- **Location:**
  - [`backend/src/MinecraftSsForensics.Scanner/Scanners/UsbHistoryScanner.cs:36-43`](backend/src/MinecraftSsForensics.Scanner/Scanners/UsbHistoryScanner.cs#L36-L43)
  - [`backend/src/MinecraftSsForensics.Scanner/Scanners/RegistryScanner.cs:54-70`](backend/src/MinecraftSsForensics.Scanner/Scanners/RegistryScanner.cs#L54-L70)
- **Description & Root Cause:**
  1. `UsbHistoryScanner` reads device names from `SYSTEM\CurrentControlSet\Enum\USBSTOR` but leaves `LastConnectedTime` as `null` because it does not read the registry key's last write time or setupapi installation logs.
  2. `RegistryScanner` reads UserAssist ROT13-encoded value names, but ignores the 72-byte binary payload (where byte offset 4 stores execution count and offset 60 stores the last execution 64-bit `FILETIME`).
- **Impact:**
  Staff cannot determine when a USB device was connected or when an application was executed via UserAssist.

---

### [BUG-P2-04] Incomplete Event Log Query & Truncation
- **Severity:** P2 (Medium)
- **Category:** Event Log Forensics
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs:82-105`](backend/src/MinecraftSsForensics.Scanner/Scanners/ServiceAndDriverScanner.cs#L82-L105)
- **Description & Root Cause:**
  The query for Event ID 7045 (Service/Driver Installed) reads entries synchronously from `System.Diagnostics.EventLog` without filtering at the log reader level, capping results arbitrarily at 50 entries. If a machine has had more than 50 service installations, recent driver installations may be truncated.
- **Remediation:**
  Use `EventLogReader` with an XPath query (`*[System[(EventID=7045)]]`) to query the event provider directly and order by reverse chronological timestamp.

---

### [BUG-P2-05] Dead Legacy Code Duplication
- **Severity:** P2 (Medium)
- **Category:** Code Maintainability
- **Location:**
  - `backend/src/MinecraftSsForensics.Scanner/Engine/ScannerEngine.cs` (720 lines)
  - `backend/src/MinecraftSsForensics.Scanner/Export/ReportExporter.cs` (705 lines)
  - `backend/src/MinecraftSsForensics.Scanner/Models/LegacyModels.cs` (110 lines)
- **Description:**
  Over 1,535 lines of dead Stage 1 code remain in the core scanner library, duplicating logic and increasing maintenance burden.

---

### [BUG-P2-06] Mod Policy Engine File Path Normalization Inconsistencies
- **Severity:** P2 (Medium)
- **Category:** Policy Evaluation
- **Location:** [`backend/src/MinecraftSsForensics.Scanner/Policy/ModPolicyEngine.cs:78-95`](backend/src/MinecraftSsForensics.Scanner/Policy/ModPolicyEngine.cs#L78-L95)
- **Description:**
  Path comparisons in policy matching use mixed forward slashes and backslashes without calling `Path.GetFullPath()`, causing rules targeted at specific relative or absolute mod paths to fail to match depending on how the launcher launched the game.

---

# 4. P3 (Low-Severity Defects & Edge Cases)

---

### [BUG-P3-01] Hardcoded C: Drive Letter
- **Severity:** P3 (Low)
- **Location:** `FileDiscoveryScanner.cs:122`, `HistoricalEvidenceScanner.cs:41`
- **Description:** The scanner hardcodes paths to `C:\$Recycle.Bin` and `C:\Windows\Prefetch`. If Windows is installed on another partition (e.g. `D:\`), these scanners fail silently.

### [BUG-P3-02] Missing Cancellation Token Propagation
- **Severity:** P3 (Low)
- **Location:** `StandaloneScannerEngine.cs:38`
- **Description:** `RunScanAsync` does not take a `CancellationToken`, making it impossible to abort a hung or slow scan gracefully.

### [BUG-P3-03] Unhandled UnauthorizedAccessException in Registry Key Traversal
- **Severity:** P3 (Low)
- **Location:** `RegistryScanner.cs:31`
- **Description:** Certain registry keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags` have strict ACLs. Opening them without checking rights can throw `SecurityException` if not elevated.

### [BUG-P3-04] RecentDocs MRU Binary Data Ignored
- **Severity:** P3 (Low)
- **Location:** `RegistryScanner.cs:78-90`
- **Description:** RecentDocs reads value names ("0", "1") without parsing the binary MRU filename structure, yielding empty file targets.


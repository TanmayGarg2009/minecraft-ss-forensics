# Changelog

All notable changes to the **Minecraft SS Forensics** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-10-30

### Complete Remediation, Production Hardening & Feature Completion
This release resolves all 18 findings identified during the full repository audit (BUG-P0-01 through BUG-P3-04), implements native Win32 P/Invoke subsystem inspection, expands automated test coverage to 79 tests (0 failures), and refines the offline forensic architecture.

#### 1. Security & Integrity Fixes (P0)
- **Full Recursive Report Sealing [BUG-P0-01]**: Replaced metadata-only hashing with `SHA256-CANONICAL-V2` recursive canonical JSON normalization covering all findings, telemetry items, discovered mods, and diagnostic counters. Implemented constant-time verification (`CryptographicOperations.FixedTimeEquals`).
- **Real Authenticode Trust Provider [BUG-P0-02]**: Replaced superficial `X509Certificate` inspection with native Win32 `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) P/Invoke. Accurately verifies embedded PKCS#7 signatures and catalog-signed Windows system binaries while extracting publisher identity.
- **Sandboxed SQLite Chromium History [BUG-P0-03]**: Eliminated regex scanning on locked browser databases. Implemented safe file copying of `History` with `.wal`/`.shm` companions to isolated temporary files, parameterized SQL queries on `urls`, authentic WebKit epoch microsecond conversion, and eliminated synthetic timestamp fabrication.

#### 2. Forensic Accuracy & Detection Logic (P1)
- **Decoupled Minecraft Execution Correlation [BUG-P1-01]**: Fixed logic that previously marked all discovered mods executed if `javaw.exe` was running. Mods are now verified as executed only if explicitly referenced in the running Java command line (`SanitizedCommandLine`) or active profile directory.
- **Multi-Volume & Recycle Bin Recovery [BUG-P1-02]**: Extended filesystem scanning to all ready fixed drives (`DriveInfo.GetDrives()`). Implemented direct binary parsing for Windows Recycle Bin `$I` index files (Version 1 for Vista/7/8 and Version 2 for 10/11), recovering original file paths, deletion timestamps, and hashing paired `$R` payloads.
- **Native Prefetch MAM Decompression [BUG-P1-03]**: Added native `RtlDecompressBufferEx` (`XPRESS_HUFF`) P/Invoke to decompress Windows 10/11 MAM-compressed prefetch files. Parses SCCA format headers to extract run counts, all 8 execution timestamps, and loaded DLL modules.
- **BAM/DAM NT Device Path Translation [BUG-P1-04]**: Integrated `kernel32.dll!QueryDosDevice` to translate kernel device paths (`\Device\HarddiskVolumeX`) into standard DOS drive letters (`C:\`, `D:\`).
- **Non-Locking Shared Process Streams [BUG-P1-05]**: Updated process and file scanners to use `FileShare.ReadWrite | FileShare.Delete` with defensive error handling to prevent file lock crashes during active gaming sessions.

#### 3. Deep System Forensics & Engine Optimization (P2)
- **Deep Directory Recursion [BUG-P2-01]**: Replaced single-level lookups in user staging folders with depth-bounded recursive scanning (up to 3 levels) to discover cheats hidden in nested subdirectories.
- **Static Bytecode Method Invocation Analysis [BUG-P2-02]**: Upgraded `StaticBytecodeAnalyzer` to resolve constant pool `Methodref` and `InterfaceMethodref` entries into fully-qualified invoked methods (`invokevirtual`, `invokestatic`, `invokeinterface`) and mapped Fabric/Forge `@Mixin` annotations.
- **UserAssist 72-Byte Payload & USB Corroboration [BUG-P2-03]**: Parsed UserAssist 72-byte binary payloads to extract execution counts (offset 4) and `FILETIME` timestamps (offset 60). Correlated USB device hardware IDs with `setupapi.dev.log` to establish device connection timestamps.
- **Event Log Streaming & Driver Audits [BUG-P2-04]**: Configured `EventLogQuery` with `ReverseDirection = true` to stream newest Event ID 7045 entries first, avoiding full-log scans. Integrated Authenticode validation across service binaries.
- **Dead Code Elimination [BUG-P2-05]**: Completely purged obsolete, duplicate, and legacy classes (`ScannerEngine.cs`, `ReportExporter.cs`, `LegacyModels.cs`, and corresponding legacy tests).

#### 4. Architecture, Stability & UI (P3)
- **Symlink & Loop Protection [BUG-P3-01]**: Added path canonicalization and visited-directory tracking to prevent infinite recursion across NTFS reparse points.
- **Responsive Cancellation Handling [BUG-P3-02]**: Integrated `CancellationToken` checks across all forensic collection phases to ensure instantaneous scan cancellation.
- **RecentDocs UTF-16LE Decoding [BUG-P3-03]**: Implemented binary parsing of `RecentDocs` MRU payloads to correctly extract null-terminated UTF-16LE file paths.
- **Registry Access Resilience [BUG-P3-04]**: Added defensive `UnauthorizedAccessException` handlers to gracefully skip protected registry keys without terminating scans.

#### 5. Quality Assurance & Documentation
- **79 Passing Automated Tests**: Comprehensive xUnit test suite with 0 failures, 0 skipped, covering all collectors, negative tamper tests, Zip Slip security, HTML escaping, and roundtrip JSON integrity.
- **Complete Documentation Suite**: Published 14 comprehensive guides (`README.md`, `ARCHITECTURE.md`, `PLAYER_GUIDE.md`, `STAFF_GUIDE.md`, `EVIDENCE_SOURCES.md`, `EVIDENCE_CONFIDENCE.md`, `POLICY_PACKS.md`, `REPORT_SCHEMA.md`, `PRIVACY.md`, `SECURITY.md`, `LIMITATIONS.md`, `BUILD.md`, `TROUBLESHOOTING.md`, `CHANGELOG.md`).

---

## [2.0.0-standalone] - 2026-10-30

### Major Architectural Rebuild
* **100% Offline-First Architecture**: Completely eliminated all dependencies on ASP.NET backend APIs, SQLite databases, cloud report hosting, user accounts, and hosted frontend dashboards.
* **Dual Standalone Workflows**:
  * **Player Workflow**: Download and run the standalone scanner (`MinecraftSsForensics.exe`), complete a consented forensic audit, save portable reports (`.json`, `.html`, `.md`), and send directly to server staff.
  * **Staff Workflow**: Inspect reports locally using the dedicated `MinecraftSsForensics.Viewer.exe` desktop tool or by opening the self-contained interactive `.html` report in any standard browser.
* **Verified One-Line PowerShell Launcher**: Provided `launch.ps1` and a secure one-line launch command that enforces TLS 1.2, downloads binaries from GitHub releases, validates SHA-256 checksums against published manifests, and executes safely without unsafe `irm | iex` piping.

---

## [1.0.0] - 2026-10-29
* Initial multi-tier client-server prototype (deprecated in favor of standalone architecture).

# Changelog

All notable changes to the **Minecraft SS Forensics** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0-standalone] - 2026-10-30

### Major Architectural Rebuild
* **100% Offline-First Architecture**: Completely eliminated all dependencies on ASP.NET backend APIs, SQLite databases, cloud report hosting, user accounts, and hosted frontend dashboards.
* **Dual Standalone Workflows**:
  * **Player Workflow**: Download and run the standalone scanner (`MinecraftSsForensics.exe`), complete a consented forensic audit, save portable reports (`.json`, `.html`, `.md`), and send directly to server staff.
  * **Staff Workflow**: Inspect reports locally using the dedicated `MinecraftSsForensics.Viewer.exe` desktop tool or by opening the self-contained interactive `.html` report in any standard browser.
* **Verified One-Line PowerShell Launcher**: Provided `launch.ps1` and a secure one-line launch command that enforces TLS 1.2, downloads binaries from GitHub releases, validates SHA-256 checksums against published manifests, and executes safely without unsafe `irm | iex` piping.

### Evidentiary & Forensic Engine Enhancements
* **6 Correlated Software States**: Implemented `EvidenceCorrelationEngine`, strictly distinguishing:
  1. `SoftwarePresent` (File exists on disk in staging directories).
  2. `SoftwareInstalled` (File located in active Minecraft profile mods folder).
  3. `SoftwareExecuted` (Recorded in Windows Prefetch, BAM/DAM, or PCA execution history).
  4. `SoftwareActiveDuringSession` (Co-existing concurrently with running `javaw.exe`).
  5. `SoftwareInteractingWithMinecraft` (Mapped directly into game process address space).
  6. `ProhibitedFunctionalityUsed` (Corroborated by in-game packet/session telemetry).
* **9 Evidence States**: Standardized evidentiary classifications across all checks: `CONFIRMED`, `STRONG_INDICATOR`, `WEAK_INDICATOR`, `INCONCLUSIVE`, `NOT_CONFIGURED`, `NOT_AVAILABLE`, `DATA_EXPIRED_OR_OVERWRITTEN`, `COLLECTION_FAILED`, and `NOT_COLLECTED_BY_USER_CHOICE`.
* **Possession vs Execution Policy Rules**: Policy engine now supports distinct enforcement standards:
  * `PROHIBITED_POSSESSION`: Confirmed file presence or installation is sufficient for a policy violation.
  * `PROHIBITED_EXECUTION`: Requires verified execution traces before flagging a violation.
  * `PROHIBITED_GAMEPLAY_USE`: Requires runtime packet or match session evidence.
* **Static Bytecode Constant Pool Analyzer**: Added `StaticBytecodeAnalyzer` to safely parse Java `.class` constant pools in memory without execution, detecting structural capabilities including:
  * Crystal placement and breaking automation (`EndCrystalEntity`, `autoCrystal`, `crystalPlace`).
  * Combat automation and reach modifications (`killAura`, `triggerBot`, `extendedReach`).
  * Packet manipulation and spoofing (`PlayerMoveC2SPacket`, `C03PacketPlayer`, `sendPacket`).
  * Synthetic input simulation (`java/awt/Robot`, `setKeyBindState`, `glfwSetCursorPos`).
  * Native library loading and mixin targets.
* **Services & Third-Party Driver Scanner**: Added `ServiceAndDriverScanner` auditing:
  * `HKLM\SYSTEM\CurrentControlSet\Services` for non-standard services and kernel drivers.
  * Binaries executing from user-writable paths (`%TEMP%`, `%APPDATA%`, `%USERPROFILE%`).
  * Authenticode digital signature status and signer certificates.
  * Windows System Event Log Event ID 7045 (Service installed).
  * SetupAPI device installation log (`setupapi.dev.log`).
  * Transparent architectural disclosure regarding user-mode limitations and kernel rootkits.
* **Historical Execution Traces**: Upgraded BAM/DAM registry scanner to decode 8-byte `FILETIME` timestamps across all user security identifiers (SIDs).
* **Distributable Policy Packs**: Implemented versioned JSON `PolicyPack` format with SHA-256 seal calculation, schema validation, and conversion to active `ServerGamemodePolicy`.
* **Reference Gamemode Policies**: Bundled 6 reference competitive rulesets: `Crystal PvP`, `Sword PvP`, `Axe PvP`, `UHC`, `Pot PvP`, and `SMP`, with clear disclosure that they serve as example templates.

### Reporting & Exporters
* **Interactive Self-Contained HTML Exporter**: Generates single-file HTML reports (`StandaloneHtmlExporter`) featuring zero CDN/network dependencies, dark-mode design, 7 key metric counters, search/filter controls, and strict `WebUtility.HtmlEncode` escaping for all evidentiary inputs.
* **AI-Friendly Markdown Exporter**: Generates structured Markdown reports (`MarkdownExporter`) formatted for second-stage analysis with LLMs (ChatGPT, Claude, Gemini).
* **Cryptographic Report Sealing**: Every report features an embedded SHA-256 digest (`ReportIntegrityValidator`) computed over its findings, counts, and inventory to verify data has not been modified after generation.

### Testing & Quality Assurance
* **56 Passing Tests**: Comprehensive xUnit test suite covering all 22 forensic scenarios, including possession-based bans, execution-based policies, bytecode automation analysis, policy pack validation, and seal verification.

---

## [1.0.0] - 2026-10-29
* Initial multi-tier client-server prototype (deprecated in favor of standalone architecture).

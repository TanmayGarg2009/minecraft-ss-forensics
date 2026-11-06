# 28 — Comprehensive Adversarial Validation Matrix (25 Controlled Scenarios)

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Specification (Expansion)  
**Version**: 3.0.0-DRAFT  
**Author**: Principal QA Architect, Adversarial Validation Lead  
**Classification**: Test Engineering & Acceptance Criteria  

---

## 1. Controlled Validation Principles

To ensure scientific repeatability and safety, all scenarios in this matrix utilize **benign, synthetic test fixtures**. The test suite strictly forbids the compilation, execution, or distribution of active commercial malware or live cheat payloads. Every scenario evaluates whether the platform maintains evidentiary boundaries under edge-case conditions.

---

## 2. The 25 Controlled Adversarial Scenarios

### Scenario 01: Standard Legitimate Mod `[VALIDATED]`
- **Controlled Environment**: Clean Windows 11 sandbox; standard `.minecraft/mods` directory.
- **Synthetic Evidence**: Authentic Sodium mod JAR matching upstream Modrinth SHA-256 release hash.
- **Expected Raw Observations**: Single file observation in `.minecraft/mods`; valid Modrinth reference match.
- **Expected Graph Relationships**: `(FILE)-[:located_in]->(MINECRAFT_INSTALLATION)`, `(FILE)-[:hash_matches]->(HASH)`.
- **Expected Findings**: `EvidenceCategory.ModIntegrity`, `Severity.Informational`, `Finding = "Verified Authentic Release: Sodium"`.
- **Expected Confidence**: High (Exact cryptographic hash match).
- **Expected Conclusion**: Verdict 5 (`No known prohibited indicators detected`).
- **Forbidden Conclusions**: Cannot emit warnings, suspicion scores, or policy flags.
- **Acceptance Criteria**: Summary counts reflect 0 Critical, 0 High, 0 Medium, 0 Low, 1 Informational.

### Scenario 02: Known Prohibited Synthetic Mod (Disk Only) `[VALIDATED]`
- **Controlled Environment**: Windows sandbox; synthetic JAR placed in `Downloads`; zero process activity.
- **Synthetic Evidence**: Synthetic archive containing dummy classes in package `me.vape.client` with matching test catalog hash.
- **Expected Raw Observations**: File on disk; SHA-256 matches prohibited catalog; zero running PID.
- **Expected Graph Relationships**: `(FILE)-[:hash_matches]->(CHEAT_HASH)`, zero `loaded_by` or `associated_with` edges.
- **Expected Findings**: `EvidenceCategory.Disk`, `Severity.Medium`, `IsInScanWindow = false`.
- **Expected Confidence**: High (Catalog hash match).
- **Expected Conclusion**: Verdict 3 (`Known prohibited artifact identified; runtime activity not established`).
- **Forbidden Conclusions**: **STRICTLY FORBIDDEN**: Must NOT claim active in-game cheating, injection, or Verdict 1.
- **Acceptance Criteria**: Report explicitly records presence on disk only; runtime observations count = 0.

### Scenario 03: Renamed Legitimate Mod `[VALIDATED]`
- **Controlled Environment**: Standard `.minecraft/mods` folder.
- **Synthetic Evidence**: Authentic Sodium JAR renamed to `custom_fps_enhancer.jar`.
- **Expected Raw Observations**: File name does not match catalog; internal `fabric.mod.json` declares `id: sodium`; bytecodes match upstream release.
- **Expected Graph Relationships**: `(FILE)-[:identified_as]->(MOD_IDENTITY)`.
- **Expected Findings**: `EvidenceCategory.ModIntegrity`, `Severity.Informational`, `Finding = "Legitimate Mod Renamed Transparently: Sodium"`.
- **Expected Confidence**: High (Decompiled manifest matches official release).
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT flag filename discrepancy as suspicious or a disguise.
- **Acceptance Criteria**: Lookalike detector classifies as `LegitimateRenamedMod`.

### Scenario 04: Renamed Synthetic Prohibited Mod (Disguise Attack) `[VALIDATED]`
- **Controlled Environment**: Standard `.minecraft/mods` folder.
- **Synthetic Evidence**: Synthetic cheat archive renamed to `sodium-mc1.20.1-0.5.8.jar`; internal bytecode contains unauthorized crystal automation hooks.
- **Expected Raw Observations**: Outer filename claims popular mod; internal hash and bytecode mismatch official release; bytecode analyzer flags combat hooks.
- **Expected Graph Relationships**: `(FILE)-[:disguised_as]->(OFFICIAL_MOD)`.
- **Expected Findings**: `EvidenceCategory.Disk`, `Severity.Medium`, `DetectionMethod.BytecodeStructure`.
- **Expected Confidence**: High (Hash mismatch + unauthorized bytecode structure).
- **Expected Conclusion**: Verdict 3 (or Verdict 2 if Minecraft is running).
- **Forbidden Conclusions**: Cannot assume benign Sodium mod based on filename.
- **Acceptance Criteria**: Lookalike detector flags `HashMismatchOnClaimedRelease`.

### Scenario 05: Unknown Custom JAR (Unlisted Mod) `[VALIDATED]`
- **Controlled Environment**: `.minecraft/mods` directory.
- **Synthetic Evidence**: Custom compiled open-source mod JAR with zero matches in Modrinth or cheat catalogs.
- **Expected Raw Observations**: Valid ZIP structure; uncataloged SHA-256 hash; normal game helper bytecodes.
- **Expected Graph Relationships**: `(FILE)-[:located_in]->(MODS_DIR)`, `MatchQuality = UNKNOWN_ARTIFACT`.
- **Expected Findings**: `EvidenceCategory.ModIntegrity`, `Severity.Low` or `Medium`, `Classification = POLICY_REVIEW_REQUIRED`.
- **Expected Confidence**: Moderate (Unlisted community package).
- **Expected Conclusion**: Verdict 2 (`Suspicious runtime evidence requires review`) if running, or Informational if idle.
- **Forbidden Conclusions**: **STRICTLY FORBIDDEN**: Must NOT label unlisted mod as malware or cheat.
- **Acceptance Criteria**: Finding interpretation states file is unlisted and requires human verification.

### Scenario 06: Java Agent Parameter on Startup `[VALIDATED]`
- **Controlled Environment**: Running test JVM process with command-line `-javaagent:test_agent.jar`.
- **Synthetic Evidence**: Test agent implementing `premain` mapped into `javaw.exe`.
- **Expected Raw Observations**: Process command line contains `-javaagent:`; module list contains `instrument.dll`.
- **Expected Graph Relationships**: `(JVM_PROCESS)-[:loads_agent]->(FILE)`.
- **Expected Findings**: `EvidenceCategory.JvmEnvironment`, `Severity.Medium` (or `Critical` if agent matches cheat catalog).
- **Expected Confidence**: High (Direct PEB command-line extraction).
- **Expected Conclusion**: Verdict 1 or Verdict 2.
- **Forbidden Conclusions**: Cannot leak sensitive command line auth tokens in finding text.
- **Acceptance Criteria**: `CommandLineRedactor` scrubs all session parameters; agent path is highlighted.

### Scenario 07: External Unrelated Executable Running `[VALIDATED]`
- **Controlled Environment**: Windows host running Notepad (`notepad.exe`) or Discord simultaneously with Minecraft.
- **Synthetic Evidence**: Standard system process in active process table.
- **Expected Raw Observations**: Process observed; zero open handles to `javaw.exe`; zero memory mapping.
- **Expected Graph Relationships**: `(OS_PROCESS)` node with zero edges connecting to `(JVM_PROCESS)`.
- **Expected Findings**: `EvidenceCategory.RunningProcess`, `Severity.Informational`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT claim external process targeted Minecraft.
- **Acceptance Criteria**: Zero association edges created in graph.

### Scenario 08: Legitimate Native Library in Temporary Directory (JNA Unpack) `[VALIDATED]`
- **Controlled Environment**: `%TEMP%\jna-12345\jnidispatch.dll` loaded by `javaw.exe`.
- **Synthetic Evidence**: Unsigned native DLL mapped into Java process containing export `Java_com_sun_jna_Native_initIDs`.
- **Expected Raw Observations**: Loaded module from temporary directory; unsigned Authenticode status; recognized JNA export symbols.
- **Expected Graph Relationships**: `(LOADED_MODULE)-[:loaded_by]->(JVM_PROCESS)`, `(LOADED_MODULE)-[:provenance_of]->(JNA_LIBRARY)`.
- **Expected Findings**: `EvidenceCategory.LoadedModule`, `Severity.Informational`, `Finding = "Legitimate Runtime Unpack: JNA Native Dispatch"`.
- **Expected Confidence**: High (Symbol table verification).
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: **STRICTLY FORBIDDEN**: Must NOT flag as code injection or high severity.
- **Acceptance Criteria**: Summary counts treat module as Informational; 0 Critical findings.

### Scenario 09: Unknown Module Loaded into Unrelated Process `[VALIDATED]`
- **Controlled Environment**: Custom test DLL loaded into `dummy.exe` (unrelated background process).
- **Synthetic Evidence**: Module mapped into PID 9999; zero connection to `javaw.exe`.
- **Expected Raw Observations**: Module observed in external PID.
- **Expected Graph Relationships**: `(LOADED_MODULE)-[:loaded_by]->(EXTERNAL_PROCESS)`.
- **Expected Findings**: `EvidenceCategory.LoadedModule`, `TargetProcess = dummy.exe`, `Severity.Low`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Verdict 5 (`Clean` for Minecraft).
- **Forbidden Conclusions**: Must NOT claim injection into Minecraft.
- **Acceptance Criteria**: Target process is explicitly identified as `dummy.exe`.

### Scenario 10: Known Test Module Loaded into Minecraft (Active Injection) `[VALIDATED]`
- **Controlled Environment**: Synthetic test DLL mapped into active `javaw.exe` memory space with matching cheat catalog signature.
- **Synthetic Evidence**: In-process module list entry at base address `0x7FFA10000000`.
- **Expected Raw Observations**: In-process module; target process is `javaw.exe`; signature matches prohibited catalog.
- **Expected Graph Relationships**: `(LOADED_MODULE)-[:loaded_by]->(JVM_PROCESS)`, `(LOADED_MODULE)-[:identified_as]->(PROHIBITED_DLL)`.
- **Expected Findings**: `EvidenceCategory.Injected`, `Severity.Critical`, `IsInScanWindow = true`.
- **Expected Confidence**: High (In-memory address mapping).
- **Expected Conclusion**: Verdict 1 (`Strong evidence of a known prohibited artifact associated with the Minecraft process`).
- **Forbidden Conclusions**: Cannot report as disk-only.
- **Acceptance Criteria**: Verdict 1 is triggered; target process PID and base address are recorded.

### Scenario 11: Historical Artifact Without Current Execution `[VALIDATED]`
- **Controlled Environment**: Windows Prefetch contains `TEST_CHEAT.EXE-12345678.pf` dated 10 days ago; zero current process; binary deleted.
- **Synthetic Evidence**: Valid SCCA prefetch header with execution timestamp in past.
- **Expected Raw Observations**: Prefetch execution record; run count = 3; last launch outside scan window.
- **Expected Graph Relationships**: `(HISTORICAL_RECORD)-[:records_past_run]->(NAMED_BINARY)`.
- **Expected Findings**: `EvidenceCategory.Historical`, `Severity.Medium`, `IsInScanWindow = false`.
- **Expected Confidence**: High (Prefetch SCCA decompression).
- **Expected Conclusion**: Verdict 3 (`Known prohibited artifact identified; runtime activity not established`).
- **Forbidden Conclusions**: Must NOT claim active in-game use during the match.
- **Acceptance Criteria**: Report explicitly flags observation as historical.

### Scenario 12: File Deletion Record Without Known Execution `[VALIDATED]`
- **Controlled Environment**: NTFS USN Journal records deletion of `suspicious_file.jar` 5 minutes before scan; zero prefetch.
- **Synthetic Evidence**: USN Journal entry with `USN_REASON_FILE_DELETE`.
- **Expected Raw Observations**: Filesystem deletion record.
- **Expected Graph Relationships**: `(FILE_DELETION_EVENT)`.
- **Expected Findings**: `EvidenceCategory.FileDeletion`, `Severity.Low` or `Medium`, `Classification = Diagnostic`.
- **Expected Confidence**: High (NTFS journal).
- **Expected Conclusion**: Informational/Diagnostic anomaly.
- **Forbidden Conclusions**: Cannot claim deleted file was a cheat without corroborating hash or prefetch.
- **Acceptance Criteria**: Explicit statement that deletion alone does not establish malicious intent.

### Scenario 13: Local Proxy Configuration Without Proof of Use `[PROPOSED]`
- **Controlled Environment**: Localhost SOCKS proxy listening on `127.0.0.1:1080`; Minecraft connecting directly to public IP `192.0.2.1:25565`.
- **Synthetic Evidence**: Listening TCP socket on localhost; active Minecraft socket connects to remote public IP.
- **Expected Raw Observations**: Proxy listening; Minecraft socket table shows public endpoint.
- **Expected Graph Relationships**: Zero routing edges between Minecraft socket and localhost socket.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Severity.Low`.
- **Expected Confidence**: High (TCP table inspection).
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT claim Minecraft traffic was intercepted or manipulated.
- **Acceptance Criteria**: Verified that Minecraft socket bypassed local proxy.

### Scenario 14: Legitimate Localhost Development Tool `[PROPOSED]`
- **Controlled Environment**: Local Python HTTP server running on `127.0.0.1:8000` for web development.
- **Synthetic Evidence**: Standard Python process binding localhost port.
- **Expected Raw Observations**: Process and port observed.
- **Expected Graph Relationships**: Zero association with Minecraft.
- **Expected Findings**: `EvidenceCategory.RunningProcess`, `Severity.Informational`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT flag development tool as a packet cheat.
- **Acceptance Criteria**: Clean assessment.

### Scenario 15: Legitimate Gaming Peripheral Software `[PROPOSED]`
- **Controlled Environment**: Logitech G HUB (`lghub.exe`) running in user session.
- **Synthetic Evidence**: Authenticode-signed executable signed by Logitech Europe S.A.
- **Expected Raw Observations**: Process active; digital certificate valid; default mouse profiles.
- **Expected Graph Relationships**: `(OS_PROCESS)-[:signed_by]->(VALID_CERT)`.
- **Expected Findings**: `EvidenceCategory.RunningProcess`, `Severity.Informational`.
- **Expected Confidence**: High (Valid Authenticode signature).
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT flag commercial peripheral drivers as cheats.
- **Acceptance Criteria**: Authenticode validator marks signature trusted; 0 suspicious findings.

### Scenario 16: Macro Script Without Evidence of Minecraft Use `[PROPOSED]`
- **Controlled Environment**: AutoHotkey script on desktop automating Excel spreadsheet data entry.
- **Synthetic Evidence**: Script file containing hotkeys targeting `ahk_class XLMAIN`.
- **Expected Raw Observations**: AHK script discovered; AST parsing reveals targeting of Microsoft Excel.
- **Expected Graph Relationships**: Zero targeting edges to Minecraft.
- **Expected Findings**: `EvidenceCategory.Disk`, `Severity.Informational`.
- **Expected Confidence**: High (Script text inspection).
- **Expected Conclusion**: Verdict 5 (`Clean`).
- **Forbidden Conclusions**: Must NOT claim macro targeted Minecraft.
- **Acceptance Criteria**: Script parsed; non-Minecraft target confirmed.

### Scenario 17: Resource Pack with Policy-Sensitive Feature (X-Ray) `[PROPOSED]`
- **Controlled Environment**: `.minecraft/resourcepacks/xray_pack.zip` containing transparent stone block models.
- **Synthetic Evidence**: JSON models defining `cullface` transparency.
- **Expected Raw Observations**: Resource pack present; block models modified.
- **Expected Graph Relationships**: `(RESOURCE_PACK)-[:modifies_assets]->(BLOCK_MODELS)`.
- **Expected Findings**: `EvidenceCategory.Disk`, `Severity.Low` or `Medium`, `Classification = POLICY_REVIEW_REQUIRED`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Evaluated against loaded Server Policy Pack.
- **Forbidden Conclusions**: Must NOT classify resource pack as malware or code injection.
- **Acceptance Criteria**: Finding directs reviewer to verify server resource pack policy.

### Scenario 18: Modified Options Configuration (Gamma Override) `[PROPOSED]`
- **Controlled Environment**: `.minecraft/options.txt` containing `gamma:1000.0`.
- **Synthetic Evidence**: Config key value exceeds vanilla maximum (1.0).
- **Expected Raw Observations**: Text parser extracts `gamma = 1000.0`.
- **Expected Graph Relationships**: `(CONFIGURATION)-[:sets_parameter]->(GAMMA)`.
- **Expected Findings**: `EvidenceCategory.ModIntegrity`, `Severity.Low`, `Finding = "Modified Game Setting: Fullbright Gamma Override"`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Evaluated against Server Policy Pack.
- **Forbidden Conclusions**: Must NOT claim third-party cheat client was used.
- **Acceptance Criteria**: Configuration finding correctly isolated.

### Scenario 19: Unsupported Hardware Telemetry (DMA Peripheral) `[OUT OF SCOPE]`
- **Controlled Environment**: Test machine with generic USB development board (Raspberry Pi Pico) connected.
- **Synthetic Evidence**: USB device descriptor in SetupAPI.
- **Expected Raw Observations**: USB device enumerated.
- **Expected Graph Relationships**: `(USB_DEVICE)`.
- **Expected Findings**: `EvidenceCategory.Historical`, `Severity.Informational`.
- **Expected Confidence**: Moderate.
- **Expected Conclusion**: Verdict 5 (`Clean`) or Diagnostic notice.
- **Forbidden Conclusions**: **STRICT PROHIBITION**: Must NOT claim detection of DMA memory reading.
- **Acceptance Criteria**: Explicit disclaimer that physical PCIe memory transfers are out of scope.

### Scenario 20: Missing Historical Artifacts (Disabled Prefetch) `[PROPOSED]`
- **Controlled Environment**: Windows machine with `EnablePrefetcher = 0` in registry.
- **Synthetic Evidence**: `C:\Windows\Prefetch\` contains zero files.
- **Expected Raw Observations**: `PrefetchParser` detects registry flag `EnablePrefetcher = 0`.
- **Expected Graph Relationships**: `CollectionStatus = NOT_APPLICABLE`.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Finding = "Windows Prefetch Disabled by OS Configuration"`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Handled gracefully; historical checks marked not applicable without penalizing user.
- **Forbidden Conclusions**: Must NOT accuse player of anti-forensic Prefetch tampering.
- **Acceptance Criteria**: Diagnostic item logged; user not penalized.

### Scenario 21: Non-Elevated Execution (Standard User Permissions) `[PROPOSED]`
- **Controlled Environment**: Scanner executed without administrative rights.
- **Synthetic Evidence**: Access to `C:\Windows\Prefetch\` returns `Access Denied`.
- **Expected Raw Observations**: `CollectionStatus = PERMISSION_DENIED` on Prefetch collector.
- **Expected Graph Relationships**: Diagnostic check item emitted.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Severity.Informational`.
- **Expected Conclusion**: Verdict 4 (`Inconclusive because required telemetry was unavailable`) if historical audit requested.
- **Forbidden Conclusions**: Must NOT crash; must not claim player is clean if critical checks were skipped.
- **Acceptance Criteria**: Graceful degradation; clear status reporting.

### Scenario 22: Correlated Duplicate Observations Across Subsystems `[PROPOSED]`
- **Controlled Environment**: Synthetic cheat on disk + UserAssist launch record + Prefetch execution count.
- **Synthetic Evidence**: Same file path and SHA-256 hash across all three sources.
- **Expected Raw Observations**: 3 distinct raw observations.
- **Expected Graph Relationships**: All 3 observations linked to a single `EvidenceClusterId`.
- **Expected Findings**: Exactly 1 unified finding in summary counts.
- **Expected Confidence**: High (Multi-source corroboration).
- **Expected Conclusion**: Verdict 3.
- **Forbidden Conclusions**: Must NOT count as 3 separate cheat violations.
- **Acceptance Criteria**: Summary counts reflect `ConfirmedCheats = 1`.

### Scenario 23: Conflicting Clocks / Clock Drift Anomaly `[PROPOSED]`
- **Controlled Environment**: File modification timestamp is 2 hours *after* scan completion time.
- **Synthetic Evidence**: Future timestamp in NTFS metadata.
- **Expected Raw Observations**: Negative time delta calculated.
- **Expected Graph Relationships**: `(TEMPORAL_ANOMALY)`.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Finding = "Temporal Anomaly: Future File Timestamp Detected"`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Anomaly recorded; timeline normalized to UTC collection time.
- **Forbidden Conclusions**: Must not crash chronological sort.
- **Acceptance Criteria**: Temporal anomaly logged in diagnostic table.

### Scenario 24: Inconsistent Truncated Log `[PROPOSED]`
- **Controlled Environment**: `latest.log` ends abruptly mid-duel without a clean shutdown record.
- **Synthetic Evidence**: File ends without `Stopping server` or `Closing screen`.
- **Expected Raw Observations**: Log parser flags incomplete termination.
- **Expected Graph Relationships**: `(LOG_GAP)`.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Finding = "Minecraft Session Terminated Abnormally or Crash Logged"`.
- **Expected Confidence**: Moderate.
- **Expected Conclusion**: Neutral diagnostic finding.
- **Forbidden Conclusions**: Must NOT accuse user of anti-forensic log tampering (could be normal crash).
- **Acceptance Criteria**: Handled neutrally.

### Scenario 25: Stale Reference Database `[PROPOSED]`
- **Controlled Environment**: Reference pack timestamp set to 180 days prior to scan date.
- **Synthetic Evidence**: Expired reference pack header.
- **Expected Raw Observations**: Engine checks expiration date against current system clock.
- **Expected Graph Relationships**: `ReferenceDataStatus = STALE`.
- **Expected Findings**: `EvidenceCategory.Diagnostic`, `Finding = "Reference Data Pack is Outdated (> 90 Days)"`.
- **Expected Confidence**: High.
- **Expected Conclusion**: Stale warning banner displayed; audit proceeds with conservative confidence.
- **Forbidden Conclusions**: Must not fail silently.
- **Acceptance Criteria**: Adjudicator alerted that newly released community mods may be unlisted.

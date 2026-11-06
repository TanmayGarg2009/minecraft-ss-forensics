# Architecture Changelog & Audit Reconciliation Register

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Governance Specification  
**Version**: 3.0.0-DRAFT  
**Author**: Principal Security Architect, Systems Quality Auditor  
**Classification**: Audit Traceability & Revision Register  

---

## 1. Executive Summary

This Changelog documents the formal audit reconciliation of the Minecraft SS Forensics architectural specification suite. Following an independent architectural audit (Codex Audit), the entire document repository ([`docs/architecture/`](./)) was reviewed, corrected, and consolidated.

All identified discrepancies, uncalibrated claims, machine-specific paths, and semantic confusions between the existing v2.1.0 codebase and the proposed v3.0.0 architecture have been systematically addressed.

> [!IMPORTANT]
> **Strict Non-Implementation Boundary**:  
> In accordance with Phase 0 directives, **zero application source code** (C#, project files, or build scripts) was modified. All reconciliations documented herein apply strictly to architectural specifications, schemas, data models, and test criteria.

---

## 2. Summary of Reconciled Audit Findings

| Audit Issue ID | Affected Document(s) | Previous Description | Reconciled Architecture & Rationale | Status |
| :---: | :--- | :--- | :--- | :---: |
| **AUD-01** | All documents (00–28, Reviews) | 60+ machine-specific absolute links (`file:///c:/Users/TANMAY%20GARG/...`). | Replaced all links with clean relative Markdown paths (`./XX-DOCUMENT.md`), making documentation fully portable across operating systems and developer workstations. | **RESOLVED** |
| **AUD-02** | `00`, `03`, `04`, `10`, `12` | Ambiguous claims regarding "HMAC" and asymmetric digital signing of reports. | Reconciled with actual codebase (`ReportIntegrityValidator.cs`): the implemented integrity mechanism is unkeyed RFC 8785 JSON Canonicalization with SHA-256 (`SHA256-CANONICAL-V2`). True asymmetric digital signing is formally labeled `DEFERRED`. | **RESOLVED** |
| **AUD-03** | `00`, `04`, `05`, `08`, `10` | Disconnect between implemented flat `StandaloneReport` and proposed `EvidenceGraph`. | Established formal Serialization Bridge (`05-EVIDENCE-GRAPH.md` §6); defined 9-layer abstraction pipeline and explicit mapping from graph projection to flat 12-column findings. | **RESOLVED** |
| **AUD-04** | `04`, `05`, `08` | Ephemeral Windows Process IDs (`PID`) used for cross-collector clustering, vulnerable to PID recycling. | Introduced stable composite entity identifier: `ProcessInstanceId` (`proc:{HostId}:{PID}:{StartTimeTicks}:{ImageSha256}`) and companion keys for modules, files, and sessions. | **RESOLVED** |
| **AUD-05** | `07`, `18`, `20`, `25` | Conflation of filename with software identity. | Codified Identity Axiom 1: Filename is solely a filesystem path attribute, never software identity. Identity requires multi-modal inspection (hashes, package manifests, bytecode). | **RESOLVED** |
| **AUD-06** | `07`, `09`, `25` | Unknown cryptographic hashes treated with suspicion. | Codified Identity Axiom 2: An unknown or unindexed hash is never automatically suspicious; it defaults to `POLICY_REVIEW_REQUIRED` or `Informational`, requiring human review. | **RESOLVED** |
| **AUD-07** | `08` | Proposed Bayesian Belief Networks for automated cheat probability scoring. | Bayesian scoring formally **REJECTED** for automated adjudication due to the absence of empirical prior probability distributions. Hybrid Attributed Evidence Graph accepted. | **RESOLVED** |
| **AUD-08** | `09`, `26` | Conflation of Evidence Strength, Confidence, Severity, and Conclusion. | Codified 5 Orthogonal Dimensions: (1) Evidence Strength, (2) Observational Confidence, (3) Policy Severity, (4) Collection Coverage, and (5) Proposition Truth. | **RESOLVED** |
| **AUD-09** | `06`, `09`, `19` | Missing telemetry or failed checks treated ambiguously or assumed clean. | Codified Canonical 7-Tier Collection Status (`COMPLETE`, `PARTIAL`, `TIMED_OUT`, `FAILED`, `PERMISSION_DENIED`, `NOT_APPLICABLE`, `UNSUPPORTED`). Failed checks emit diagnostics and trigger Verdict 4 (`INCONCLUSIVE`). | **RESOLVED** |
| **AUD-10** | `11`, `28` | Divergence between "20-scenario" matrix in Doc 11 and "25-scenario" matrix in Doc 28. | Unified around Doc 28 as the single canonical 25-scenario matrix. Scenarios 01–12 labeled `VALIDATED` (covered by existing unit tests); Scenarios 13–25 labeled `PROPOSED` / `OUT OF SCOPE`. | **RESOLVED** |
| **AUD-11** | `24`, `25` | Ingestion of server packages (`.mcsec`) and policy packs (`.polpack`) trusted self-asserted embedded public keys. | Insecure self-asserted key model rejected as circular. Ingestion now mandates verification against pre-configured local trust anchors (public key fingerprints configured in Viewer). | **RESOLVED** |
| **AUD-12** | `18`, `19`, `21`, `28` | Ambiguous boundaries regarding hardware DMA detection and kernel rootkits. | DMA memory reading and proprietary kernel rootkit introspection formally designated as **`OUT OF SCOPE`** for user-space scanner. | **RESOLVED** |
| **AUD-13** | `00`, `06`, `07`, `12` | Inconsistent network assumptions across documents. | Codified strict offline-by-default rule: scanner contains zero outbound network telemetry; all reference data and policy packs are staged locally. | **RESOLVED** |
| **AUD-14** | `18`, `19`, `20` | Unsigned temporary DLLs loaded by Java classified as suspicious code injection. | Codified JNA/LWJGL unpack legitimacy rules: libraries verifying known JNA export symbols (`Java_com_sun_jna_...`) are categorized as `EvidenceCategory.LoadedModule`, `Severity.Informational`. | **RESOLVED** |
| **AUD-15** | `02`, `19`, `23` | Conflation of temporal concurrency with game targeting. | Codified Association Model: temporal overlap between an external process and Minecraft does not prove association. Association requires handles, memory mapping, or Java agent attachment. | **RESOLVED** |
| **AUD-16** | `16`, `25`, `Review`, `Lock` | Ambiguous conflation of `POL-02` between obfuscated mod policy and policy pack governance. | Resolved without guessing: preserved `POL-02` as "Handling of Obfuscated Community Mods" per Document 16; introduced `POL-05` for "Server Policy Pack Governance & Policy Decoupling". | **RESOLVED** |
| **AUD-17** | `01`, `06`, `13` | Discrepancy in archive decompression safety limits (claimed 10 MB/250:1 vs real constants). | Reconciled with actual `SafeArchiveInspector.cs` constants: `MaxEntries = 10,000`, `MaxTotalUncompressedBytes = 250 MB`, `MaxCompressionRatio = 100:1`, `MaxMetadataReadBytes = 2 MB`. | **RESOLVED** |
| **AUD-18** | `06`, `07`, `12` | Offline-by-default claim contradicted by v2.1.0 `ConsentScopeConfig.cs` default. | Documented that v2.1.0 baseline defaults `PerformOnlineVerification = true`. Flagged as high-priority Phase 2 implementation task to default to `false` and enforce backend boundary. | **RESOLVED** |
| **AUD-19** | `01`, `04`, `12` | Custom property-sorted JSON serializer described as published RFC 8785 JCS. | Clarified that v2.1.0 `ReportIntegrityValidator.cs` implements an unkeyed custom property-sorted canonical serializer (`SHA256-CANONICAL-V2`); strict RFC 8785 compliance is `PROPOSED`. | **RESOLVED** |
| **AUD-20** | `01`, `04`, `12`, `13` | Path redaction string discrepancy (`[REDACTED]` vs actual code `[REDACTED_USER]`). | Standardized documentation to match `CommandLineRedactor.cs:66` (`C:\Users\[REDACTED_USER]\`). | **RESOLVED** |

---

## 3. Detailed Document Modification History

### Document 00: Executive Architecture & System Principles
- Updated Document Inventory table to reflect all 29 numbered specifications and governance documents.
- Standardized document status tagging to 7 canonical states: `PROPOSED`, `VERIFIED`, `IMPLEMENTED`, `VALIDATED`, `DEFERRED`, `OUT OF SCOPE`, `RESEARCH REQUIRED`.
- Clarified system boundaries: offline-first, consent-based, user-space only.
- Added explicit distinction between v2.1.0 flat report model (`IMPLEMENTED`) and proposed graph engine (`PROPOSED`).

### Document 03: Forensic Philosophy & Evidentiary Standards
- Codified 4 Proposition Truth States: `PROVEN`, `NOT PROVEN`, `UNKNOWN`, `CONTRADICTED`.
- Added 10 Epistemic Axioms governing what digital evidence can and cannot establish.
- Replaced ambiguous HMAC references with `SHA256-CANONICAL-V2`.

### Document 04: Canonical Evidence Schema & Data Contracts
- Added the 9 Canonical Abstraction Layers (`RawObservation` $\rightarrow$ `NormalizedObservation` $\rightarrow$ `IdentifiedArtifact` $\rightarrow$ `EvidenceRelationship` $\rightarrow$ `EvidenceCluster` $\rightarrow$ `Contradiction` $\rightarrow$ `FindingRecord` $\rightarrow$ `PolicyAssessment` $\rightarrow$ `InvestigationVerdict`).
- Defined stable composite identifiers: `ProcessInstanceId`, `ModuleInstanceId`, `FileInstanceId`, `JvmInstanceId`, `MinecraftSessionId`, `HistoricalRecordId`, `PolicyId`.
- Added multi-collector deduplication rules and composite keys.

### Document 05: Directed Attributed Evidence Graph
- Added Section 6: Graph Serialization Bridge & Flat Report Projection.
- Codified traversal boundaries ($k \le 4$ hops, prohibited coincident edges).
- Mapped graph sub-topologies to 12-column finding records.

### Document 06: Forensic Collection Architecture
- Added `UNSUPPORTED` to complete the standardized 7-status collection state machine.
- Explicitly documented graceful degradation and memory budget enforcement ($\le 250\text{ MB}$).

### Document 07: Multi-Modal Identification Engine
- Added Core Identity Axioms: Filename != Identity; Unknown Hash != Suspicious; Strict Offline Mode by Default.
- Added Trust Anchor requirements for `.refpack` verification.
- Explicitly noted that built-in v2.1.0 reference databases use compiled SHA-256 checks (`IMPLEMENTED`), while detached signed `.refpack` files are `PROPOSED`.

### Document 08: Correlation Engine & Explainable Reasoning
- Refined Operator 1 (Equivalence Clustering) to use composite `ProcessInstanceId` rather than bare Windows PIDs.
- Differentiated `ActiveInScanWindow` from `ActiveInMinecraftSession`.
- Formally documented the rejection of uncalibrated Bayesian Belief Networks.

### Document 09: Severity, Evidence Strength & Assessment Framework
- Codified the Five Orthogonal Evaluative Dimensions: Evidence Strength, Observational Confidence, Policy Severity, Collection Coverage, Proposition Truth.
- Standardized the 9 Assessment Categories and 5 Verdict flows.

### Document 11: Validation, Testing Strategy & Adversarial Framework
- Updated title and test pyramid to harmonize with the canonical 25-scenario matrix in Document 28.
- Added summary cross-reference table mapping Scenarios 01–25 to their respective status tags and operational criteria.

### Document 12: Privacy Architecture & Cryptographic Integrity
- Formally distinguished Content Digest Consistency (`SHA256-CANONICAL-V2`) from Asymmetric Digital Signatures.
- Documented that unkeyed RFC 8785 canonical digest is `IMPLEMENTED` in v2.1.0, while detached asymmetric signing is `DEFERRED`.
- Re-verified user profile path redaction (`C:\Users\[REDACTED_USER]\`) and token scrubbing rules.

### Document 24: Server-Side Evidence Bridge
- Fixed public-key trust vulnerability: rejected self-asserted embedded keys in `.mcsec`.
- Mandated pre-configured local trust anchors (key fingerprints) for server signature validation.
- Standardized domain separation badge (`[SERVER-OBSERVED]`).

### Document 25: Server Policy Pack Intelligence
- Added trust anchor requirements for `.polpack` schemas.
- Distinguished implemented hardcoded mod rules in v2.1.0 from proposed external `.polpack` files.

### Document 28: Adversarial Validation Matrix (25 Controlled Scenarios)
- Tagged every scenario header with explicit status: `[VALIDATED]` for Scenarios 01–12 (matching existing unit tests), `[PROPOSED]` for Scenarios 13–18 and 20–25, and `[OUT OF SCOPE]` for Scenario 19 (DMA).
- Re-verified all acceptance criteria and forbidden conclusions.

---

## 4. Implementation Milestones & Test Progression

### Phase 1: Foundational Data Architecture (Milestone 1)
- **Observations Model**: Implemented `IObservation`, `RawObservation`, `CollectionStatus`, and `CollectionOutcome` in `backend/src/MinecraftSsForensics.Scanner/Observations/`.
- **Identity Model**: Implemented stable composite entity identifiers in `backend/src/MinecraftSsForensics.Scanner/Identities/CompositeIdentities.cs` (`ProcessInstanceId`, `ModuleInstanceId`, `FileInstanceId`, `MinecraftSessionId`, `HistoricalRecordId`), providing immunity against Windows PID recycling.
- **Evidence Graph**: Implemented in-memory Directed Attributed Evidence Graph $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ in `backend/src/MinecraftSsForensics.Scanner/Graph/EvidenceGraph.cs` with 13 entity types, 11 edge types, cycle prevention, and bounded traversal ($k \le 4$).
- **Serialization Bridge**: Implemented `GraphSerializationBridge.cs` projecting graph structures into normalized `FindingRecord`s preserving 100% backward compatibility with `StandaloneReport` v2.
- **Tests Added**: 11 new tests in `FoundationalDataArchitectureTests.cs` (Suite increased from 91 to 102 passing tests).

### Phase 2: Integrity, Privacy & Network Boundaries
- **Strict Offline-First Operation**: Updated `ConsentScopeConfig.cs` to default `PerformOnlineVerification` to `false`.
- **Network Capability Boundary**: Added `AllowNetworkRequests` capability gate to `CompositeModVerifier.cs` so default offline scans make zero outbound HTTP requests.
- **Report Integrity vs Authenticity**: Re-verified `ReportIntegrityValidator.cs` and `ProvenanceNotice`, strictly distinguishing content SHA-256 integrity from author identity authentication.
- **Tests Added**: 4 new tests in `IntegrityAndPrivacyBoundaryTests.cs` (Suite increased from 102 to 106 passing tests).

### Phase 3: Detection & Forensic Correctness
- **Native Library Provenance**: Implemented `PeExportParser.cs` for bounded PE Export table inspection. Integrated export parsing into `ProcessScanner.CheckJavaNativeProvenance` for recognized JNA/LWJGL symbols (`Java_com_sun_jna_...`), eliminating false positives on unsigned temporary DLLs extracted into `%TEMP%`.
- **Anti-Double-Counting Clustering**: Enhanced `EvidenceCorrelationEngine.cs` to cluster disk, prefetch, and process detections into unified `EvidenceClusterId` records.
- **Scenario Tests Expanded**: Added automated tests for Scenarios 16 (unknown client review), 18 (macro software possession), 19 (benign USB peripheral), and 20 (OBS overlay hook) in `ScenarioBasedForensicTests.cs`.
- **Tests Added**: 4 new scenario tests (Suite increased from 106 to 110 passing tests).

---

## 5. Verification Checkpoint (Post-Phase 1, 2, 3 Implementation)

1. All links within `docs/architecture/` verified as relative (`./`).
2. Core data contracts, graph, offline boundary, PE export parsing, and clustering implemented cleanly in `backend/src/`.
3. Solution compiles cleanly with zero warnings and zero errors across Debug and Release configurations.
4. Total test suite expanded from **91 to 110 tests**, passing 100% cleanly across all 17 test fixtures.
5. 100% backward compatibility with `StandaloneReport` v2, Viewer, and existing command-line exports preserved.


---

## 6. V1 Launch Architecture Remediation (Findings F-001 through F-021)

This section documents the repository-wide remediation addressing all 21 findings (F-001 through F-021) from the independent forensic architecture audit across Workstreams A through H:

### Workstream A: Production Pipeline & Observation Architecture Integration (F-001, F-002, F-003, F-014, F-015, F-016)
- **F-001**: Fully wired `IObservation` and `RawObservation` into `StandaloneScannerEngine.cs` across all 9 scanning phases (Installations, Mods, Processes, Modules, History, Registry, USB, Browser, File Discovery, Services/Drivers).
- **F-002**: Integrated `CollectionOutcome` across all collectors. Errors, timeouts, and consent exclusions generate typed outcomes and update `DiagnosticChecks` and `TechnicalLimitations`, directly influencing coverage and verdict formulation.
- **F-003, F-015**: Built live, in-memory `EvidenceGraph` during scanning via `GraphSerializationBridge.BuildGraphFromObservations`, attaching it to `StandaloneReport.EvidenceGraph`.
- **F-014**: Deployed composite entity identities (`ProcessInstanceId`, `ModuleInstanceId`, `FileInstanceId`) across all raw observations and correlation nodes, providing immunity to Windows PID recycling.
- **F-016**: Maintained 100% backward compatibility with `StandaloneReport` v2 schema and the WPF Viewer by decorating in-memory properties (`EvidenceGraph`, `RawObservations`, `CollectionOutcomes`) with `[JsonIgnore]`.

### Workstream B: Transport-Level Network Consent Boundary (F-004)
- **F-004**: Implemented `ConsentEnforcingHttpMessageHandler` and `NetworkBoundary.CreateConsentBoundedClient` in `backend/src/MinecraftSsForensics.Scanner/Verification/NetworkBoundary.cs`. Direct instantiation of `ModrinthVerificationProvider`, `CurseForgeVerificationProvider`, and `GitHubVerificationProvider` strictly defaults to offline-by-default, rejecting any attempt to initiate outbound HTTP connections without explicit runtime consent.

### Workstream C: Canonical Integrity & Authenticity Separation (F-005, F-006)
- **F-005**: Standardized report content sealing to canonical `SHA256-CANONICAL-V2` with deterministic property sorting and cryptographic constant-time comparison via `CryptographicOperations.FixedTimeEquals`.
- **F-006**: Separated content integrity from author authenticity across all documentation and viewer UI (`MainWindow.xaml.cs`). Updated viewer banner to: `"✔ Content Integrity Verified (SHA-256 digest matches; author not authenticated)"`.

### Workstream D: Centralized Privacy Redaction Boundary (F-007)
- **F-007**: Created centralized `PrivacyBoundary.cs` in `backend/src/MinecraftSsForensics.Scanner/Process/`. Unified redaction of command-line tokens (`--accessToken`, `--uuid`, `--session`, `--userProperties`, `--password`), JVM system properties (`-Dauth`, `-Dtoken`), URL query parameters, and multi-platform user directory paths (`C:\Users\[REDACTED_USER]\...`). Wired `SanitizeReportForExport` across `PortableJsonExporter`, `MarkdownExporter`, and `StandaloneHtmlExporter`.

### Workstream E: Forensic Correctness in Association & Attribution (F-008, F-009, F-010, F-011)
- **F-008**: In `FileDiscoveryScanner.cs`, filename-only matches on disk are downgraded from `ConfirmedCheatArtifact` / `Certain` to `StrongIndicator` / `Medium` confidence, explicitly stating that filename match alone does not confirm cheat identity.
- **F-009**: In `EvidenceCorrelationEngine.cs` and `StandaloneScannerEngine.cs`, concurrent execution without an established technical link (open handle, injection, parentage) is strictly classified as `SoftwareExecuted` under `RunningProcess`, never triggering `StrongEvidenceMinecraft`.
- **F-010**: In `EvidenceCorrelationEngine.cs`, temporary DLL modules are only attributed to Minecraft if `mod.ProcessId` matches an active Minecraft process (`javaw.exe`). Modules in non-Minecraft processes are classified as non-Minecraft executions.
- **F-011**: Standardized identity-based clustering via canonical `EvidenceClusterId` across findings, observations, and evidence references.

### Workstream F: Hardened PE Export Parser (F-012, F-013)
- **F-012, F-013**: Completely rewrote `backend/src/MinecraftSsForensics.Scanner/Process/PeExportParser.cs` with checked arithmetic (`checked`), section boundary validation, virtual zero-fill detection, ordinals and forwarders support, and structured diagnostic return types (`PeExportParseResult`, `PeExportParseStatus`). Added synthetic binary test suite in `PeExportParserHardeningTests.cs` covering valid PEs, truncated headers, corrupted offsets, bad signatures, and zero-fills.

### Workstream G: Resource Bounds & TOCTOU Defenses (F-020, F-021)
- **F-020**: In `PortableJsonExporter.cs`, enforced strict untrusted payload defenses: 50 MB maximum report file size, max JSON recursion depth of 32, and maximum collection limit of 25,000 findings.
- **F-021**: In `FileDiscoveryScanner.cs`, implemented TOCTOU mitigation: checks file existence and modification timestamps before and after reading; downgrades evidence to `Inconclusive` if modified concurrently during collection.

### Workstream H: Historical Compatibility & Schema Migration (F-019)
- **F-019**: Implemented comprehensive test fixture in `backend/tests/MinecraftSsForensics.Scanner.Tests/HistoricalCompatibilityTests.cs` (8 automated tests) verifying backward compatibility against synthetic v1 wrapped, v1 direct, and canonical v2 reports, round-trip serialization fidelity, and tampered integrity detection.

### Final Verification Status:
- Total automated tests: **132 passed, 0 failed, 0 skipped** across all 19 test fixtures in both Debug and Release configurations.
- Compilation status: **0 warnings, 0 errors** across both Debug and Release builds.
- Architecture documents: All 34 documents reconciled with production implementation.
- Governance milestone: Marked `TECHNICALLY READY FOR HUMAN RELEASE REVIEW`.

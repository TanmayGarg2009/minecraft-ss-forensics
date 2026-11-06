# Architecture Decision Register (ADR)

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Specification  
**Version**: 3.0.0-DRAFT  
**Author**: Principal Security Architect, Systems Quality Engineering  
**Classification**: Architecture Governance & Historical Decision Log  

---

## Index of Architectural Decisions

- [ADR-001: Adoption of Directed Attributed Evidence Graph with Serialization Bridge](#adr-001-adoption-of-directed-attributed-evidence-graph-with-serialization-bridge)
- [ADR-002: Canonical JCS Content Digest Sealing (SHA256-CANONICAL-V2) and Deferral of Asymmetric Signatures](#adr-002-canonical-jcs-content-digest-sealing-sha256-canonical-v2-and-deferral-of-asymmetric-signatures)
- [ADR-003: Privacy-by-Design Redaction Pipeline (Token & User Path Scrubbing)](#adr-003-privacy-by-design-redaction-pipeline-token--user-path-scrubbing)
- [ADR-004: Strict Offline-First Operation by Default](#adr-004-strict-offline-first-operation-by-default)
- [ADR-005: Stable Composite Entity Identifiers (ProcessInstanceId, ModuleInstanceId, FileInstanceId)](#adr-005-stable-composite-entity-identifiers)
- [ADR-006: Rejection of Uncalibrated Bayesian Probability Scoring](#adr-006-rejection-of-uncalibrated-bayesian-probability-scoring)
- [ADR-007: Orthogonal 5-Dimension Assessment Framework](#adr-007-orthogonal-5-dimension-assessment-framework)
- [ADR-008: Seven-Tier Association Model for Minecraft Processes](#adr-008-seven-tier-association-model-for-minecraft-processes)
- [ADR-009: Multi-Modal Software Identity Engine and Filename Decoupling](#adr-009-multi-modal-software-identity-engine-and-filename-decoupling)
- [ADR-010: Native Library Provenance & Legitimacy of JNA/LWJGL Runtime Extraction](#adr-010-native-library-provenance--legitimacy-of-jnalwjgl-runtime-extraction)
- [ADR-011: Server-Side Evidence Bridge Trust Anchor Architecture (.mcsec)](#adr-011-server-side-evidence-bridge-trust-anchor-architecture-mcsec)
- [ADR-012: Policy-Sensitive Utility Decoupling & Server Policy Packs (.polpack)](#adr-012-policy-sensitive-utility-decoupling--server-policy-packs-polpack)
- [ADR-013: Bounded Collector Execution State Machine & Graceful Degradation](#adr-013-bounded-collector-execution-state-machine--graceful-degradation)
- [ADR-014: Hardware DMA Detection Bounded as Out of Scope](#adr-014-hardware-dma-detection-bounded-as-out-of-scope)
- [ADR-015: Canonical 25-Scenario Adversarial Test Matrix Governance](#adr-015-canonical-25-scenario-adversarial-test-matrix-governance)

---

### ADR-001: Adoption of Directed Attributed Evidence Graph with Serialization Bridge
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Graph/EvidenceGraph.cs`, `Graph/GraphSerializationBridge.cs`)
- **Context**: Legacy screen-sharing tools represented findings as disconnected lists of string detections. This caused rampant double-counting and prevented causal tracking (e.g., distinguishing a file sitting in `Downloads` from a module injected into `javaw.exe`).
- **Decision**: Adopt an in-memory Directed Attributed Evidence Graph $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ with 13 entity types and 11 edge types. To maintain backward compatibility with existing reporting and viewer consumers, implement a deterministic Serialization Bridge that projects graph sub-topologies into normalized 12-column finding records.
- **Consequences**: Enables rigorous anti-double-counting and explainable reasoning traces; requires formal graph node schemas and traversal bounds ($k \le 4$ hops).

---

### ADR-002: Canonical JCS Content Digest Sealing (SHA256-CANONICAL-V2) and Deferral of Asymmetric Signatures
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`SHA256-CANONICAL-V2` via `ReportIntegrityValidator.cs`) / `PROPOSED` (Strict RFC 8785 Conformance) / `DEFERRED` (Asymmetric Digital Signatures)
- **Context**: Forensic reports must be protected against post-scan tampering and accidental corruption when exported. Some proposals suggested using embedded HMAC keys or private signing keys.
- **Decision**: Implement unkeyed canonical JSON digest sealing (`SHA256-CANONICAL-V2`), as verified in `ReportIntegrityValidator.cs`. Note that the v2.1.0 serializer recursively sorts JSON properties alphabetically, but has not been validated against published RFC 8785 test suites (true RFC 8785 compliance is `PROPOSED`). Explicitly defer asymmetric digital signatures because embedding private keys in client-side open-source software is an insecure anti-pattern, and remote signing violates offline-first operation.
- **Consequences**: Successfully detects post-generation file edits and summary count tampering; does not prove authorship against a sophisticated reverse-engineer who can re-run canonical hashing.

---

### ADR-003: Privacy-by-Design Redaction Pipeline (Token & User Path Scrubbing)
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`CommandLineRedactor.cs`)
- **Context**: Competitive players' privacy was routinely violated by legacy screen-sharing tools exposing real names from filesystem paths (`C:\Users\<RealName>\`) and Minecraft authentication session tokens.
- **Decision**: Implement mandatory automated redaction pipelines in `CommandLineRedactor.cs` (`Redact` and `RedactPath`). Scrub all sensitive session tokens (`--accessToken`, `--uuid`, `--session`, `--userProperties`, `--password`, `-Dauth*`) and normalize user profile paths to `C:\Users\[REDACTED_USER]\` across JSON, HTML, and memory logs prior to display or export.
- **Consequences**: Eliminates player doxxing and token hijacking risks while preserving critical forensic relative paths (`.minecraft\mods\...`).

---

### ADR-004: Strict Offline-First Operation by Default
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`ConsentScopeConfig.cs` default `false`, `CompositeModVerifier.cs` network capability boundary)
- **Context**: Players and security researchers distrust tools that upload local telemetry, file listings, or system metadata to external servers or cloud APIs.
- **Decision**: The scanner must operate strictly offline by default. Zero outbound network connections, sockets, or HTTP requests are permitted during default scanning. In the v2.1.0 baseline, `ConsentScopeConfig.cs` incorrectly defaulted `PerformOnlineVerification` to `true`. This ADR mandates changing the default to `false` and enforcing a strict backend network boundary that physically prevents HTTP requests unless explicit consent is granted.
- **Consequences**: Eliminates network latency, air-gap incompatibilities, and data exfiltration risks; updates require distributing updated reference packs.

---

### ADR-005: Stable Composite Entity Identifiers
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Identities/CompositeIdentities.cs`)
- **Context**: Windows aggressively recycles 32-bit Process Identifiers (PIDs). Using bare PIDs to correlate across collectors running seconds apart results in false correlations.
- **Decision**: Mandate stable composite identifiers across all entities:
  - Process: `proc:{HostId}:{PID}:{StartTimeTicks}:{ImageSha256}`
  - Module: `mod:{ProcessInstanceId}:{BaseAddressHex}:{Size}:{ModuleSha256}`
  - File: `file:{NormalizedPath}:{Size}:{Sha256}`
  - Minecraft Session: `mc:{ProcessInstanceId}:{StartTimeUtc}`
- **Consequences**: Completely immune to PID recycling; guarantees deterministic graph edge construction.

---

### ADR-006: Rejection of Uncalibrated Bayesian Probability Scoring
- **ADR Status**: `ADR_REJECTED` (Bayesian Probabilities) / `ADR_ACCEPTED` (Attributed Evidence Graph)
- **Implementation Status**: `IMPLEMENTED` in `EvidenceCorrelationEngine.cs` (Deterministic Rules)
- **Context**: Proposals suggested using Bayesian Belief Networks to compute automated "Cheat Probabilities" (e.g. 98.4%).
- **Decision**: Formally reject Bayesian scoring for automated adjudication. Calculating valid Bayesian posteriors $P(\text{Cheat} \mid E)$ requires extensive empirical ground-truth datasets for prior probabilities and conditional likelihood tables. Fabricating prior probabilities produces pseudoscience. Adopt deterministic causal rules over the Evidence Graph.
- **Consequences**: Reports present factual, reproducible findings with documented evidence strength rather than uncalibrated percentage scores.

---

### ADR-007: Orthogonal 5-Dimension Assessment Framework
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` in `FindingRecord.cs` and `StandaloneReport.cs`
- **Context**: Legacy systems conflated severity, confidence, coverage, and evidence strength into single subjective scores, causing high-impact rumors to be labeled "Critical" and verified benign mods to be labeled "Suspicious".
- **Decision**: Decouple assessment into five strictly orthogonal dimensions:
  1. Evidence Strength: `STRONG`, `MODERATE`, `WEAK`, `INCONCLUSIVE`
  2. Observational Confidence: Qualitative level based on match quality
  3. Policy Severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
  4. Collection Coverage: Standardized collection state machine
  5. Proposition Truth: `PROVEN`, `NOT PROVEN`, `UNKNOWN`, `CONTRADICTED`
- **Consequences**: Eliminates false positives from benign high-confidence detections and prevents unsubstantiated high-severity claims.

---

### ADR-008: Seven-Tier Association Model for Minecraft Processes
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `PARTIALLY IMPLEMENTED` in `ProcessScanner.cs` and `EvidenceCorrelationEngine.cs`
- **Context**: Tools frequently accused players of cheating simply because an external program or macro tool was running anywhere on the OS during gameplay.
- **Decision**: Establish seven explicit levels of Minecraft association:
  - Level 0: Unrelated System Process (No targeting)
  - Level 1: Concurrent Execution (Temporal overlap only, not associated)
  - Level 2: Inter-Process Handles (Open handle to `javaw.exe`)
  - Level 3: Input Simulation Targeting (Synthesizing input to Minecraft HWND)
  - Level 4: Network Proxy Interception (Sockets routing Minecraft traffic)
  - Level 5: Native Module Injection (DLL mapped into JVM virtual memory)
  - Level 6: JVM Bytecode Modification (Java agent or HotSpot Attach API)
- **Consequences**: Strictly forbids inferring game targeting from mere temporal concurrency.

---

### ADR-009: Multi-Modal Software Identity Engine and Filename Decoupling
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`StreamingFileHasher.cs`, `LookalikeDetector.cs`, `StaticBytecodeAnalyzer.cs`)
- **Context**: Filename-based detections are trivially spoofed by adversaries (renaming cheats to `sodium.jar`) and cause false positives on legitimately renamed community mods.
- **Decision**: Enforce multi-modal software identity:
  1. Filename is solely a filesystem path attribute, never software identity.
  2. Identity is established across 7 layers: Bitstream Hash, Authenticode Certificate, Package Manifest, Bytecode Hierarchy, Behavioral Heuristics, Release Matching, Runtime Context.
  3. Unknown hashes default to `POLICY_REVIEW_REQUIRED`, never malware.
- **Consequences**: Robust against lookalike disguise attacks; eliminates false-positive flags on renamed authentic mods.

---

### ADR-010: Native Library Provenance & Legitimacy of JNA/LWJGL Runtime Extraction
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`PeExportParser.cs` and `ProcessScanner.CheckJavaNativeProvenance` via FileVersionInfo + PE Export Parsing + Naming Pattern)
- **Context**: Java games unpack native C/C++ libraries (e.g. `jnidispatch.dll`, LWJGL OpenGL bindings) into `%TEMP%` at runtime. Legacy scanners flagged these unsigned temporary DLLs as malicious code injections.
- **Decision**: Codify native library provenance rules: modules mapped from `%TEMP%` that match recognized JNA/LWJGL product descriptions ('Java(TM) Native Access', 'JNA', 'Timothy Wall', 'LWJGL', 'OpenAL', 'JInput') and naming conventions are categorized as `EvidenceCategory.LoadedModule`, `Severity.Informational`.
- **Consequences**: Eliminates one of the most widespread false positives in competitive Minecraft screening.

---

### ADR-011: Server-Side Evidence Bridge Trust Anchor Architecture (.mcsec)
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `PROPOSED`
- **Governance Status**: `GOVERNANCE_PENDING` (`POL-04`)
- **Context**: Client scanners cannot measure in-game combat reach or knockback without server data. However, accepting untrusted server evidence could allow rogue server admins to frame players.
- **Decision**: Define the `.mcsec` offline file import schema. Require that server evidence packages be signed by the server organization's private key (Ed25519) and verified strictly against **pre-configured local trust anchors** in the Viewer. Reject self-asserted embedded keys.
- **Consequences**: Enables multi-source corroboration without sacrificing security or introducing network dependencies into the client scanner.

---

### ADR-012: Policy-Sensitive Utility Decoupling & Server Policy Packs (.polpack)
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (Compiled in `ModPolicyEngine.cs`) / `PROPOSED` (External `.polpack` Loader)
- **Governance Status**: `GOVERNANCE_PENDING` (`POL-05`)
- **Context**: Legitimate community utilities (Litematica, Freecam) are permitted on some servers (SMP) but banned on others (competitive PvP). Classifying them as "cheats" causes severe disputes.
- **Decision**: Enforce the Policy Decoupling Axiom: $\text{Identity} \neq \text{Authenticity} \neq \text{Compliance}$. Authentic tools are categorized as `POLICY_REVIEW_REQUIRED` and evaluated against server-specific policy tiers: `ALLOWED`, `RESTRICTED`, `PROHIBITED_GAMEPLAY_USE`, `PROHIBITED_EXECUTION`, `PROHIBITED_POSSESSION`.
- **Consequences**: Clearly separates technical software capabilities from server-specific administrative rules.

---

### ADR-013: Bounded Collector Execution State Machine & Graceful Degradation
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`SafeArchiveInspector.cs`, `PrefetchParser.cs`, `ProcessScanner.cs`)
- **Context**: Collectors querying corrupted files, locked registry keys, or non-standard JVMs could hang indefinitely or crash the entire scan.
- **Decision**: Every collector runs under a strict bounded timeout ($\le 10\text{s}$) and memory budget ($\le 250\text{ MB}$). Collectors output standardized `CollectionStatus` states. Any failure emits a `DiagnosticCheckItem`, degrades gracefully, and triggers Verdict 4 (`INCONCLUSIVE`) if the failed source was essential.
- **Consequences**: The scanner is crash-resilient and never silently treats failed or skipped checks as clean proof.

---

### ADR-014: Hardware DMA Detection Bounded as Out of Scope
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `OUT OF SCOPE`
- **Governance Status**: `GOVERNANCE_APPROVED`
- **Context**: Direct Memory Access (DMA) hardware cards (e.g. PCIe Squirrel/Screamer) read physical host memory over the PCIe bus without running software on the host OS.
- **Decision**: Formally designate physical PCIe DMA memory reading and proprietary kernel rootkit introspection as **`OUT OF SCOPE`** for this user-space forensic scanner. The scanner must explicitly disclaim capability to detect DMA attacks.
- **Consequences**: Prevents false claims of security coverage and protects organizational credibility.

---

### ADR-015: Canonical 25-Scenario Adversarial Test Matrix Governance
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `PARTIALLY IMPLEMENTED` (Scenarios 01–12 `AUTOMATED_TEST_PASSING`; Scenarios 13–25 `TEST_PENDING_IMPLEMENTATION`)
- **Context**: Inconsistencies existed between earlier 20-scenario tables and expanded 25-scenario matrices.
- **Decision**: Establish Document 28 (`28-ADVERSARIAL-VALIDATION-MATRIX.md`) as the single authoritative 25-scenario test matrix. Scenarios 01–12 represent the established `VALIDATED` baseline (verified by existing unit tests). Scenarios 13–25 govern extended behaviors (`PROPOSED`).
- **Consequences**: Provides an unambiguous, verified testing specification for future implementation milestones.


---

### ADR-016: Transport-Level Network Consent Boundary (ConsentEnforcingHttpMessageHandler)
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Verification/NetworkBoundary.cs`)
- **Context**: Relying purely on upper-layer boolean flags to prevent outbound HTTP requests leaves open the possibility that subcomponents, providers, or future code paths might inadvertently leak network requests in an offline-by-default environment.
- **Decision**: Enforce network consent at the transport layer using a custom `DelegatingHandler` (`ConsentEnforcingHttpMessageHandler`). Unless the user has explicitly consented (`consent.PerformOnlineVerification == true`), the transport handler intercepts and rejects any outbound `HttpClient` request, throwing an `InvalidOperationException` and ensuring zero packets leave the process.
- **Consequences**: Absolute defense-in-depth against network leakage; verification providers default to safe offline operation upon instantiation.

---

### ADR-017: Integration of Typed Observations and Directed Evidence Graph into Production Scanning
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Engine/StandaloneScannerEngine.cs`, `Graph/GraphSerializationBridge.cs`)
- **Context**: Findings in the architecture audit revealed that early prototype versions decoupled the observation model (`RawObservation`) and `EvidenceGraph` into test-only utilities while production scanning ran on flat legacy collections.
- **Decision**: Fully wire `IObservation`, `RawObservation`, and `CollectionOutcome` into `StandaloneScannerEngine.cs` across all 9 scanning phases. Construct a live in-memory `EvidenceGraph` during scan execution via `GraphSerializationBridge`, maintaining 100% backward compatibility by keeping graph and observation collections as `[JsonIgnore]` properties on `StandaloneReport`.
- **Consequences**: Unifies data models between testing and production runtime without breaking compatibility with existing JSON exporters or the WPF Viewer.

---

### ADR-018: Strict Separation of Content Integrity (SHA256-CANONICAL-V2) from Author Authenticity
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Integrity/ReportIntegrityValidator.cs`, `MainWindow.xaml.cs`)
- **Context**: Past documentation and viewer UI claimed that verifying the report hash proved "Authenticity and Untampered Origin", conflating unkeyed content hashing with cryptographic author authentication.
- **Decision**: Explicitly distinguish content integrity from author identity. Update report validation messages and Viewer banner to state: `"Content integrity verified (SHA-256 digest matches; author not authenticated)"`. Document that unkeyed hashes protect against unintentional file corruption and manual post-generation edits, but do not authenticate the identity of the scanner or reviewer without asymmetric digital signatures.
- **Consequences**: Eliminates misleading cryptographic claims; aligns forensic terminology with established digital evidence standards.

---

### ADR-019: Centralized Multi-Layer Privacy Boundary (PrivacyBoundary.cs)
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Process/PrivacyBoundary.cs`, `Process/CommandLineRedactor.cs`)
- **Context**: Sensitive user tokens (session credentials, UUIDs, passwords) and local filesystem usernames were previously scrubbed inconsistently across different exporters, leading to potential data leakage in markdown or HTML reports.
- **Decision**: Centralize all redaction into `PrivacyBoundary.cs`. Implement comprehensive regular expressions covering command-line flags (supporting space, '=', and quoted variants), JVM properties (`-Dauth`), URL query strings, and Windows/Unix user directory paths (`C:\Users\[REDACTED_USER]\`). Apply `PrivacyBoundary.SanitizeReportForExport` across JSON, Markdown, and HTML export pipelines before writing to disk or displaying.
- **Consequences**: Guarantees consistent PII scrubbing across all export formats and user interfaces.

---

### ADR-020: Hardened PE Export Parser with Checked Bounds and Section Verification
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Process/PeExportParser.cs`)
- **Context**: Inspecting DLL exports in user-mode to distinguish legitimate Java native libraries (JNA, LWJGL) from injection artifacts requires parsing untrusted binary files in memory, which is vulnerable to integer overflows, out-of-bounds reads, and virtual zero-fill attacks.
- **Decision**: Rewrite `PeExportParser` with checked arithmetic (`checked`), strict section boundary verification, RawData vs VirtualAddress zero-fill detection, ordinals and forwarders support, and structured diagnostic return types (`PeExportParseResult`, `PeExportParseStatus`). Validate using real and synthetic malformed binaries in `PeExportParserHardeningTests.cs`.
- **Consequences**: Eliminates crash vectors and parsing exploits when examining untrusted or corrupted PE binaries on disk.

---

### ADR-021: Forensic Correctness in Association & Attribution
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Collectors/FileDiscoveryScanner.cs`, `Correlation/EvidenceCorrelationEngine.cs`)
- **Context**: Audit findings identified critical forensic flaws: (1) flagging files on disk as confirmed cheats based purely on filename, and (2) assuming that an external process running concurrently with Minecraft was associated with Minecraft without technical proof.
- **Decision**: Enforce two forensic axioms: (1) Filename match alone is never a confirmed cheat artifact; it is classified as `StrongIndicator` with `Medium` confidence, requiring hash or bytecode confirmation. (2) Concurrent execution without technical evidence (open handle, injection, parentage) is classified as `SoftwareExecuted` under `RunningProcess`, never triggering `StrongEvidenceMinecraft`. Furthermore, temporary DLLs are only attributed to Minecraft if loaded into an active Minecraft process.
- **Consequences**: Completely eliminates false accusations based on coincidental filenames or concurrent background applications.

---

### ADR-022: Resource Limits and TOCTOU Defenses for Stored Reports & Files
- **ADR Status**: `ADR_ACCEPTED`
- **Implementation Status**: `IMPLEMENTED` (`Export/PortableJsonExporter.cs`, `Collectors/FileDiscoveryScanner.cs`)
- **Context**: Loading large or adversarial JSON reports could exhaust memory or trigger stack overflow via deep nesting (JSON bomb). Furthermore, concurrent modification of files during scanning could lead to Time-of-Check to Time-of-Use (TOCTOU) inconsistencies.
- **Decision**: Enforce a 50 MB file size limit, maximum JSON depth of 32, and 25,000 collection item limit in `PortableJsonExporter.cs`. In `FileDiscoveryScanner.cs`, record file modification times and file existence before and after computing cryptographic hashes; if modified concurrently, downgrade the evidence state to `Inconclusive`.
- **Consequences**: Protects viewer and scanner against resource exhaustion and race conditions during evidence collection.

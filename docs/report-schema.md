# Forensic Report Schema Specification (v1.0.0)

## Overview
This document specifies the canonical schema format for Minecraft screenshare (SS) forensic diagnostic reports. All client scanners (including the future Stage 2 Windows native scanner) must submit reports matching this format.

The schema is strictly versioned (`schemaVersion: "1.0.0"`). Unknown or deprecated schema versions are rejected during ingestion.

---

## Root Object (`SubmitReportRequest`)

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schemaVersion` | `string` | **Yes** | Must be `"1.0.0"`. |
| `scannerVersion` | `string` | **Yes** | Client build/version identifier (e.g. `"1.0.0-rc1"`). Max 64 chars. |
| `scanMode` | `string` | **Yes** | Scan intensity: `"QUICK"` or `"FULL"`. |
| `osName` | `string` | **Yes** | OS Name (e.g. `"Windows 11 Pro"`). Max 64 chars. |
| `osVersion` | `string` | **Yes** | Windows Build / Version (e.g. `"10.0.22631"`). Max 64 chars. |
| `osArchitecture` | `string` | No | Architecture: `"x64"`, `"x86"`, or `"arm64"`. Default: `"x64"`. |
| `scanStartedAt` | `ISO-8601` | No | Timestamp when local scan began on client. |
| `scanCompletedAt` | `ISO-8601` | No | Timestamp when local scan finished. |
| `detectedMinecraftVersions` | `string[]` | No | Array of detected Minecraft versions (e.g. `["1.8.9"]`). |
| `detectedLoaders` | `string[]` | No | Array of active loaders (e.g. `["Forge 11.15.1.2318", "Lunar Client"]`). |
| `consentConfirmation` | `Object` | **Yes** | Mandatory explicit player consent record. |
| `collectionCoverage` | `Object` | No | Summary of checks executed, passed, and unavailable. |
| `retentionDays` | `integer` | No | Retention lifetime in days (1 - 30). Default: `7`. |
| `findings` | `Finding[]` | No | List of suspicious or verified forensic findings (max 1,000). |
| `evidenceItems` | `Evidence[]` | No | Raw and structured evidence collections (max 500). |
| `timelineEvents` | `Timeline[]` | No | Chronological events observed or inferred (max 5,000). |
| `diagnosticItems` | `Diagnostic[]`| No | Audit trail of skipped or failed check modules. |

---

## 1. Consent Confirmation (`consentConfirmation`)

Consent is mandatory. Ingestion strictly enforces `consentGiven: true`.

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `consentGiven` | `boolean` | **Yes** | Must be `true`. If `false`, API rejects submission. |
| `collectionScopeVersion` | `string` | **Yes** | Disclosed scope version presented to player (e.g. `"1.0"`). |
| `consentTimestamp` | `ISO-8601` | **Yes** | Exact UTC timestamp when player consented in the UI. |

---

## 2. Findings Model (`findings[]`)

Each finding records an individual forensic observation or anomaly.

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `ruleId` | `string` | **Yes** | Stable rule identifier (e.g. `"WIN-PREF-001"`, `"NTFS-USN-004"`). |
| `title` | `string` | **Yes** | Short human-readable title. Max 200 chars. |
| `category` | `string` | **Yes** | Finding category enum (see Enums below). |
| `severity` | `string` | **Yes** | Severity enum (`Critical`, `High`, `Medium`, `Low`, `Informational`). |
| `confidence` | `string` | **Yes** | Confidence enum (`Certain`, `High`, `Medium`, `Low`). |
| `explanation` | `string` | **Yes** | Technical narrative of what was observed. |
| `observedEvidence` | `Object` | No | Structured key-value details specific to the detection rule. |
| `filePath` | `string` | No | Path on the scanned client related to the finding. |
| `fileSizeBytes` | `integer` | No | Size in bytes. |
| `fileSha256` | `string` | No | Lowercase 64-character hexadecimal SHA-256 digest. |
| `fileCreatedTime` | `ISO-8601` | No | Creation timestamp from filesystem metadata. |
| `fileModifiedTime` | `ISO-8601` | No | Last modification timestamp. |
| `fileLastAccessTime` | `ISO-8601` | No | Last access timestamp. |
| `processId` | `integer` | No | PID of process if runtime finding. |
| `processName` | `string` | No | Name of process (e.g. `"javaw.exe"`). |
| `processCommandLine` | `string` | No | Execution command line. |
| `firstObservedAt` | `ISO-8601` | No | Earliest relevant timestamp for this indicator. |
| `lastObservedAt` | `ISO-8601` | No | Latest relevant timestamp for this indicator. |
| `evidenceSource` | `string` | **Yes** | Subsystem source enum (e.g. `"Prefetch"`, `"UsnJournal"`). |
| `detectionRuleVersion` | `string` | No | Version of rule engine. Default: `"1.0.0"`. |
| `limitationsAndFalsePositives` | `string` | **Yes** | Explicit technical caveats and conditions where finding could be benign. |

---

## 3. Evidence Items (`evidenceItems[]`)

Large or detailed evidence artifacts referenced by findings.

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `publicEvidenceId` | `string` | **Yes** | Identifier unique within report (e.g. `"ev_pref_001"`). |
| `type` | `string` | **Yes** | Evidence type enum (`WindowsArtifact`, `JvmArguments`, `ModInventory`, etc.). |
| `title` | `string` | **Yes** | Title of evidence collection. Max 200 chars. |
| `description` | `string` | No | Description of what this artifact represents. |
| `rawContent` | `string` | No | Raw textual content (saved to abstract raw storage). |
| `structuredPayload` | `Object` | No | Parsed JSON representation (stored in database). |
| `sha256Hash` | `string` | No | SHA-256 digest of the artifact. |
| `isAvailable` | `boolean` | No | Whether collection succeeded. Default: `true`. |
| `diagnosticMessage` | `string` | No | Reason if unavailable (e.g. `"Access Denied"`). |
| `capturedAt` | `ISO-8601` | No | Collection timestamp. |

---

## 4. Timeline Events (`timelineEvents[]`)

Events plotted on the report viewer chronological timeline.

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `timestamp` | `ISO-8601` | **Yes** | Event timestamp. |
| `isInferred` | `boolean` | **Yes** | `false` if explicitly recorded by Windows/game; `true` if calculated by forensic correlation. |
| `category` | `string` | **Yes** | Category (e.g. `"Execution"`, `"FileDeletion"`, `"Launch"`). |
| `description` | `string` | **Yes** | Description of the event. |
| `source` | `string` | **Yes** | Originating log or artifact (e.g. `"Windows Prefetch"`). |
| `confidence` | `string` | No | Confidence in event timing (`Certain`, `High`, `Medium`, `Low`). |
| `correlationGroup` | `string` | No | Correlated chain tag (e.g. `"CORR-CLICKER"`). |

---

## 5. Enumeration Dictionaries

### `Severity`
- `Critical` — Definitive binary injection into active Java process, active bytecode patch bypass, or known cheat driver.
- `High` — Clear evidence of standalone clicker execution within 30 minutes of investigation, Shift+Del USN record of cheat JAR.
- `Medium` — Historical execution or deletion artifacts without direct proof of in-game duel correlation.
- `Low` — Unverified or unsigned custom utilities outside known catalogs.
- `Informational` — Configuration details, launcher parameters, or benign system metrics.

### `ConfidenceLevel`
- `Certain` — Directly verified cryptographic hash match or observed system log.
- `High` — High-probability heuristic match with multi-source artifact agreement.
- `Medium` — Single-source artifact with plausible alternative explanations.
- `Low` — Speculative or low-resolution indicator requiring human investigation.

### `FindingCategory`
- `ModIntegrity`
- `ProcessInjection`
- `ExecutionArtifacts`
- `JvmEnvironment`
- `FileDeletion`
- `NetworkAnomaly`
- `Other`

### `EvidenceSource`
- `ModFolder`
- `Prefetch`
- `UsnJournal`
- `BamDam`
- `JvmArgs`
- `EventLogs`
- `ProcessMemoryMetadata`
- `ShimCache`
- `Amcache`
- `Other`

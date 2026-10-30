# Forensic Report Schema Specification (v2.0.0)

## Overview
This document specifies the canonical schema for standalone Minecraft screenshare (SS) forensic reports (`.json`). The report structure is self-contained, offline-portable, and cryptographically sealed with SHA-256 anti-tamper verification.

The standalone report loader (`PortableJsonExporter`) also provides 100% backward compatibility for legacy v1.0 reports.

---

## Root Object (`StandaloneReport`)

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schemaVersion` | `string` | **Yes** | Schema version: `"2.0.0"`. |
| `scannerVersion` | `string` | **Yes** | Client build/version identifier (e.g. `"2.0.0"`). |
| `reportId` | `string` | **Yes** | Unique report identifier (e.g. `"SS-20261030-ABCDEF"`). |
| `reportIntegrityHash` | `string` | **Yes** | Cryptographic SHA-256 seal computed over normalized telemetry. |
| `scanMode` | `string` | **Yes** | `"QUICK"` or `"FULL"`. |
| `scanStartedAt` | `ISO-8601` | **Yes** | UTC timestamp when scan initiated. |
| `scanCompletedAt` | `ISO-8601` | **Yes** | UTC timestamp when scan concluded. |
| `scanDurationMs` | `integer` | **Yes** | Duration of audit in milliseconds. |
| `consent` | `Object` | **Yes** | Detailed player consent configuration and scope selections. |
| `policyEvaluation` | `Object` | **Yes** | Active server policy, gamemode name, version, and rules URL. |
| `targetSystem` | `Object` | **Yes** | OS name, build version, architecture, and current user. |
| `javaRuntime` | `Object` | No | Active Java executable path, version, and sanitized JVM flags. |
| `verdict` | `Object` | **Yes** | Executive verdict, recommendation, and key takeaways. |
| `summaryCounts` | `Object` | **Yes** | Recomputed counters for confirmed cheats, warnings, and checks. |
| `findings` | `FindingRecord[]` | **Yes** | List of forensic findings with evidentiary backing. |
| `modInventory` | `DiscoveredModItem[]` | No | Installed mod JAR inventory with authenticity and policy states. |
| `runningProcesses` | `ProcessTelemetryItem[]`| No | Audited game processes with sanitized command lines. |
| `loadedModules` | `LoadedModuleItem[]` | No | Mapped DLL modules with JNA provenance assessments. |
| `executionHistory` | `ExecutionHistoryItem[]`| No | Windows Prefetch, BAM, and PCA execution records. |
| `registryEvidence` | `RegistryArtifactItem[]`| No | UserAssist (ROT13) and Run key artifacts. |
| `usbEvidence` | `UsbStorageItem[]` | No | Historically connected USB storage devices. |
| `browserEvidence` | `BrowserHistoryItem[]` | No | Known cheat domains matched from local browser history. |
| `fileDiscoveries` | `DiscoveredFileItem[]` | No | Discovered files in user staging directories and $Recycle.Bin. |
| `diagnosticChecks` | `DiagnosticCheckItem[]`| **Yes** | Audit trail of completed, passed, skipped, or failed checks. |

---

## 1. Consent Scope Configuration (`consent`)

Records the exact permissions granted by the player:

| Field | Type | Description |
| :--- | :--- | :--- |
| `consentGiven` | `boolean` | Must be `true` for a valid audit. |
| `consentTimestamp` | `ISO-8601` | Timestamp when consent was affirmatively given. |
| `inspectMinecraftMods` | `boolean` | Permission to inspect active mod folders. |
| `performOnlineVerification` | `boolean` | Permission to query Modrinth / CurseForge / GitHub. |
| `inspectProcessesAndModules` | `boolean` | Permission to audit `javaw.exe` and loaded DLLs. |
| `inspectExecutionArtifacts` | `boolean` | Permission to audit Windows Prefetch / BAM. |
| `inspectRegistryArtifacts` | `boolean` | Permission to audit UserAssist / Run keys. |
| `inspectUsbHistory` | `boolean` | Permission to enumerate USB storage devices. |
| `inspectBrowserHistory` | `boolean` | **Explicitly optional** cheat domain browser audit. |
| `inspectFileDiscovery` | `boolean` | Permission to audit Downloads, Desktop, and Recycle Bin. |

---

## 2. Findings Model (`findings[]`)

Every finding adheres to a strict evidentiary standard:

| Field | Type | Description |
| :--- | :--- | :--- |
| `findingId` | `string` | Unique finding ID (e.g. `FND-0001`). |
| `ruleId` | `string` | Detection rule identifier (e.g. `CHEAT-JAR-FILENAME`). |
| `detectionName` | `string` | Human-readable title of the finding. |
| `classification` | `string` | 7-tier scale: `ConfirmedCheatArtifact`, `StrongIndicator`, `Suspicious`, `NeedsReview`, `Informational`, `NoEvidenceFound`, `Unavailable`. |
| `category` | `string` | `CheatArtifact`, `ModIntegrity`, `ProcessInjection`, `ExecutionHistory`, `RegistryArtifact`, `UsbStorage`, `BrowserHistory`, `FileDiscovery`. |
| `severity` | `string` | `Critical`, `High`, `Medium`, `Low`, `Informational`. |
| `confidence` | `string` | `Certain`, `High`, `Medium`, `Low`. |
| `technicalExplanation` | `string` | Directly observed technical facts. |
| `whyItMatters` | `string` | Anti-cheat and security significance. |
| `alternativeLegitimateExplanations` | `string` | Plausible benign explanations. |
| `whatIsProven` | `string` | Strictly what the evidence demonstrates. |
| `whatIsNotProven` | `string` | Boundaries of what cannot be assumed. |

---

## 3. Cryptographic Integrity Seal (`reportIntegrityHash`)

The integrity seal is computed as:
$$\text{Seal} = \text{SHA-256}(\text{Canonical Normalized JSON Payload})$$
The normalized payload excludes the `reportIntegrityHash` property itself and orders keys consistently. When imported into the Staff Viewer, recalculating this seal guarantees that no finding, count, or path has been tampered with offline.

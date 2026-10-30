# Forensic Report Schema Specification (v2.1.0)

**Format:** Self-Contained Portable JSON (`StandaloneReport`)  
**Integrity Digest Algorithm:** `SHA256-CANONICAL-V2`

---

## 1. Schema Overview

The standalone forensic report is serialized as a deterministic, portable JSON object that encapsulates all 18 evidence streams, system info, mod authenticity results, and policy decisions into a single file.

```json
{
  "reportId": "rep_102207582d794cf6",
  "schemaVersion": "2.1.0",
  "createdAt": "2026-10-30T18:00:00Z",
  "reportIntegrityHash": "8f3b2a1c0d4e5f6a...",
  "scannerVersion": "2.1.0-standalone",
  "scannerBuild": "Standalone-Win-x64-Release",
  "targetSystem": {
    "osName": "Microsoft Windows 11 Pro",
    "osVersion": "10.0.22631",
    "architecture": "X64",
    "machineIdentifier": "DESKTOP-ABC123",
    "userIdentifier": "Player"
  },
  "scanStartedAt": "2026-10-30T17:59:45Z",
  "scanCompletedAt": "2026-10-30T18:00:00Z",
  "scanDurationMs": 15000,
  "scanMode": "QUICK",
  "consent": {
    "consentGiven": true,
    "inspectMinecraftMods": true,
    "performOnlineVerification": true,
    "inspectProcessesAndModules": true,
    "inspectExecutionArtifacts": true,
    "inspectRegistryArtifacts": true,
    "inspectUsbHistory": true,
    "inspectFileDiscovery": true,
    "inspectBrowserHistory": false
  },
  "minecraftInstallations": [],
  "modInventory": [],
  "authenticityVerifications": [],
  "policyEvaluation": {},
  "cheatDetections": [],
  "runningProcesses": [],
  "loadedModules": [],
  "executionHistory": [],
  "registryEvidence": [],
  "usbEvidence": [],
  "browserEvidence": [],
  "fileDiscoveries": [],
  "servicesAndDrivers": [],
  "correlatedAssessments": [],
  "findings": [],
  "timelineEvents": [],
  "evidenceItems": [],
  "summaryCounts": {},
  "diagnosticChecks": [],
  "technicalLimitations": [],
  "verdict": {}
}
```

---

## 2. Cryptographic Integrity: `SHA256-CANONICAL-V2`

To guarantee tamper resistance:
1. The report is serialized into canonical JSON using recursive key sorting in ordinal string order.
2. The `reportIntegrityHash` property is omitted during digest computation.
3. Every evidence collection (`findings`, `modInventory`, `evidenceItems`, etc.) is fully represented in the hash payload.
4. Any alteration to finding names, classifications, file paths, hashes, or timestamps will result in an immediate integrity mismatch when opened in the Staff Viewer.

# REST API Specification (v1)

Base URL: `http://localhost:5000/api/v1` (or your configured production HTTPS host)  
OpenAPI / Swagger UI: `http://localhost:5000/swagger`

---

## 1. System Health Check

### `GET /api/v1/health`
Returns service availability, uptime, and database connectivity.

#### Response `200 OK`
```json
{
  "status": "Healthy",
  "timestamp": "2026-10-30T00:00:00.0000000Z",
  "uptime": "01:24:12.3456789",
  "database": "Connected",
  "version": "1.0.0",
  "service": "Minecraft SS Forensics Ingestion & Viewer API"
}
```

---

## 2. Ingest Forensic Report

### `POST /api/v1/reports`
Accepts a structured, validated forensic report submitted by the Windows scanner or diagnostic tool.

- **Rate Limit**: 30 requests / minute per IP.
- **Request Size Limit**: 15 MB max.

#### Request Headers
| Header | Value | Description |
| :--- | :--- | :--- |
| `Content-Type` | `application/json` | Required |
| `Accept` | `application/json` | Required |

#### Request Body
```json
{
  "schemaVersion": "1.0.0",
  "scannerVersion": "1.0.0-rc1",
  "scanMode": "FULL",
  "osName": "Windows 11 Pro",
  "osVersion": "10.0.22631",
  "osArchitecture": "x64",
  "scanStartedAt": "2026-10-30T00:15:00Z",
  "scanCompletedAt": "2026-10-30T00:18:24Z",
  "detectedMinecraftVersions": ["1.8.9"],
  "detectedLoaders": ["Forge 11.15.1.2318"],
  "consentConfirmation": {
    "consentGiven": true,
    "collectionScopeVersion": "1.0",
    "consentTimestamp": "2026-10-30T00:14:50Z"
  },
  "collectionCoverage": {
    "totalChecks": 42,
    "passedChecks": 40,
    "flaggedChecks": 2,
    "unavailableChecks": 0
  },
  "retentionDays": 7,
  "findings": [
    {
      "ruleId": "WIN-PREF-001",
      "title": "Unregistered Clicker Executable in Prefetch",
      "category": "ExecutionArtifacts",
      "severity": "High",
      "confidence": "High",
      "explanation": "Prefetch file AUTOCLICKER.EXE-A1B2C3D4.pf indicates execution 12 minutes prior to investigation.",
      "observedEvidence": {
        "runCount": 3,
        "lastRun": "2026-10-30T00:06:00Z"
      },
      "filePath": "C:\\Users\\User\\Downloads\\autoclicker.exe",
      "fileSizeBytes": 412000,
      "fileSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "firstObservedAt": "2026-10-30T00:06:00Z",
      "lastObservedAt": "2026-10-30T00:06:00Z",
      "evidenceSource": "Prefetch",
      "detectionRuleVersion": "1.2.0",
      "limitationsAndFalsePositives": "Prefetch confirms execution only, not injection into game memory."
    }
  ],
  "evidenceItems": [
    {
      "publicEvidenceId": "ev_pref_001",
      "type": "WindowsArtifact",
      "title": "Prefetch Header Dump",
      "description": "Extracted prefetch run records.",
      "rawContent": "[RAW PREFETCH LOG DUMP...]",
      "sha256Hash": "a1b2c3d4e5f6...",
      "isAvailable": true
    }
  ],
  "timelineEvents": [
    {
      "timestamp": "2026-10-30T00:06:00Z",
      "isInferred": false,
      "category": "Execution",
      "description": "autoclicker.exe executed (Prefetch timestamp)",
      "source": "Windows Prefetch",
      "confidence": "High"
    }
  ],
  "diagnosticItems": [
    {
      "checkName": "NTFS USN Journal Parsing",
      "source": "Volume C:",
      "status": "Completed",
      "reason": "Scanned 1200 records."
    }
  ]
}
```

#### Response `201 Created`
- **Header**: `Location: /api/v1/reports/mc_G23Yx38ebR86Otk4vl`
```json
{
  "publicId": "mc_G23Yx38ebR86Otk4vl",
  "shareUrl": "http://localhost:5000/report/mc_G23Yx38ebR86Otk4vl",
  "deletionKey": "del_a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "expiresAt": "2026-11-06T00:18:24Z",
  "processingStatus": "Completed",
  "findingsCount": 1,
  "message": "Report successfully ingested. Keep your DeletionKey safe; it will not be shown again."
}
```

#### Error Responses
- `400 Bad Request`: Payload validation failed (e.g. `ConsentGiven: false`, invalid schema version, prohibited script tokens, malformed JSON).
```json
{
  "message": "Report submission validation failed.",
  "errors": [
    {
      "field": "ConsentConfirmation.ConsentGiven",
      "error": "Explicit player consent is strictly required for report ingestion."
    }
  ]
}
```
- `429 Too Many Requests`: Client exceeded rate limiting quota.

---

## 3. Retrieve Public Report

### `GET /api/v1/reports/{publicId}`
Retrieves a public forensic report using its unguessable public identifier.

- **Authentication**: None required (bearer-link model).
- **Headers Returned**: `Cache-Control: no-store, no-cache, must-revalidate`

#### Response `200 OK`
```json
{
  "publicId": "mc_G23Yx38ebR86Otk4vl",
  "schemaVersion": "1.0.0",
  "scannerVersion": "1.0.0-rc1",
  "createdAt": "2026-10-30T00:18:24Z",
  "uploadedAt": "2026-10-30T00:18:24Z",
  "scanStartedAt": "2026-10-30T00:15:00Z",
  "scanCompletedAt": "2026-10-30T00:18:24Z",
  "scanMode": "FULL",
  "osName": "Windows 11 Pro",
  "osVersion": "10.0.22631",
  "osArchitecture": "x64",
  "detectedMinecraftVersions": ["1.8.9"],
  "detectedLoaders": ["Forge 11.15.1.2318"],
  "consent": {
    "consentGiven": true,
    "collectionScopeVersion": "1.0",
    "consentTimestamp": "2026-10-30T00:14:50Z"
  },
  "processingStatus": "Completed",
  "expiresAt": "2026-11-06T00:18:24Z",
  "coverage": {
    "totalChecks": 42,
    "passedChecks": 40,
    "flaggedChecks": 1,
    "unavailableChecks": 0
  },
  "severitySummary": {
    "High": 1
  },
  "findings": [...],
  "evidenceItems": [...],
  "timelineEvents": [...],
  "diagnosticItems": [...],
  "privacyNotice": "This report is accessible via this unguessable link without authentication. Please share only with trusted server staff."
}
```

> **Security Note**: `deletionKey` or `deletionKeyHash` are **NEVER** present in the GET response.

#### Error Responses
- `404 Not Found`: Report does not exist, has already been deleted, or has passed its expiration date.

---

## 4. Retrieve Specific Evidence Item

### `GET /api/v1/reports/{publicId}/evidence/{evidenceId}`
Retrieves an individual evidence item and its associated raw content.

#### Response `200 OK`
```json
{
  "publicEvidenceId": "ev_pref_001",
  "type": "WindowsArtifact",
  "title": "Prefetch Header Dump",
  "description": "Extracted prefetch run records.",
  "sha256Hash": "a1b2c3d4e5f6...",
  "isAvailable": true,
  "diagnosticMessage": null,
  "capturedAt": "2026-10-30T00:18:24Z",
  "hasRawContent": true,
  "rawContent": "[RAW PREFETCH LOG DUMP...]",
  "structuredPayload": null
}
```

#### Error Responses
- `404 Not Found`: Either the report or the requested evidence ID does not exist or has expired.

---

## 5. Delete Report

### `DELETE /api/v1/reports/{publicId}`
Permanently purges a report and all its associated raw evidence from the database and storage. Requires the secret `DeletionKey`.

#### Authorization Credentials
The key may be passed either:
1. In the `X-Deletion-Key` HTTP header: `X-Deletion-Key: del_...`
2. Or in the JSON request body:
```json
{
  "deletionKey": "del_a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
}
```

#### Response `200 OK`
```json
{
  "success": true,
  "message": "Report mc_G23Yx38ebR86Otk4vl and all associated forensic evidence have been permanently deleted."
}
```

#### Error Responses
- `400 Bad Request`: Deletion key was not provided.
- `401 Unauthorized`: Deletion key is invalid or does not match the stored hash.
- `404 Not Found`: Report does not exist or has already been deleted.

---

## 6. Maintenance Cleanup

### `POST /api/v1/reports/cleanup`
Manually triggers the expiration cleaner (also run periodically every hour by `ReportCleanupBackgroundService`).

#### Response `200 OK`
```json
{
  "message": "Cleanup completed. Removed 3 expired report(s)."
}
```

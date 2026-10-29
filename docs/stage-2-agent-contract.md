# Stage 2 Windows Native Scanner — Agent Integration Contract

## 1. Purpose & Architecture Overview
This document specifies the exact technical contract that the Stage 2 Windows Native Scanner executable (EXE) must implement to communicate with the Stage 1 backend.

The Stage 2 scanner is responsible for:
1. Presenting a transparent consent dialog to the player explaining collection scope.
2. Collecting local forensic artifacts (Windows Prefetch, NTFS USN Journal, process memory metadata for javaw.exe, mod inventories, and launch arguments).
3. Serializing findings into the standardized `1.0.0` JSON schema.
4. Uploading the payload to `POST /api/v1/reports`.
5. Saving the returned `DeletionKey` locally and displaying the `ShareUrl` to the player to share with server staff.

---

## 2. Ingestion Endpoint Specification

- **Target Route**: `POST /api/v1/reports`
- **Method**: `POST`
- **Content-Type**: `application/json; charset=utf-8`
- **Payload Max Size**: 15 MB
- **Timeout Recommendation**: 30 seconds

### Required Headers
```http
POST /api/v1/reports HTTP/1.1
Host: <backend-host>
Content-Type: application/json; charset=utf-8
Accept: application/json
User-Agent: MinecraftSsScanner/1.0.0 (Windows NT 10.0; Win64; x64)
```

---

## 3. Mandatory Consent Contract

Before initiating any local scan routines, the EXE **must** obtain explicit user consent.

```json
"consentConfirmation": {
  "consentGiven": true,
  "collectionScopeVersion": "1.0",
  "consentTimestamp": "2026-10-30T10:14:02.123Z"
}
```

> [!CRITICAL]
> If `consentGiven` is `false`, the backend will reject the report with `HTTP 400 Bad Request`. The scanner must never bypass this user confirmation.

The consent dialog in the EXE must disclose:
- Scanned paths: `.minecraft/mods`, temporary directories, Windows Prefetch, and NTFS Journal metadata.
- Process inspection: PID and memory space of `javaw.exe` / `java.exe` only.
- Retention window: Scanned report will automatically expire in 7 days.
- Deletion rights: The player will receive a secret deletion key to wipe the report at any time.

---

## 4. Expected API Response

Upon successful validation and ingestion, the backend returns:

```http
HTTP/1.1 201 Created
Location: /api/v1/reports/mc_7ckiaTA61QwRTtEebT
Content-Type: application/json; charset=utf-8

{
  "publicId": "mc_7ckiaTA61QwRTtEebT",
  "shareUrl": "https://ss.example.org/report/mc_7ckiaTA61QwRTtEebT",
  "deletionKey": "del_8fa21b7c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "expiresAt": "2026-11-06T10:14:02Z",
  "processingStatus": "Completed",
  "findingsCount": 2,
  "message": "Report successfully ingested. Keep your DeletionKey safe; it will not be shown again."
}
```

### Client EXE Post-Ingestion Responsibilities
1. **Copyable Share URL**: Present `shareUrl` prominently with a "Copy Link for Staff" button.
2. **Secure Deletion Key Storage**: Display `deletionKey` with a "Delete Report" button in the EXE UI so the player can immediately wipe their report if the screenshare concludes.
3. **Save Token Locally**: Store `deletionKey` in local memory or `%TEMP%\minecraft_ss_session.dat` during the active session.

---

## 5. Deletion Flow Contract

If the player requests report deletion from the EXE:

```http
DELETE /api/v1/reports/mc_7ckiaTA61QwRTtEebT HTTP/1.1
Host: <backend-host>
X-Deletion-Key: del_8fa21b7c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0
Content-Type: application/json

{
  "deletionKey": "del_8fa21b7c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
}
```

Expected Response:
```http
HTTP/1.1 200 OK

{
  "success": true,
  "message": "Report mc_7ckiaTA61QwRTtEebT and all associated forensic evidence have been permanently deleted."
}
```

---

## 6. HTTP Status Code Handling & Retry Policy

| Status Code | Meaning | Scanner EXE Action |
| :--- | :--- | :--- |
| `201 Created` | Successful upload. | Display `shareUrl` and `deletionKey` to player. |
| `400 Bad Request` | Validation failure (XSS tokens, unsupported schema, missing consent). | Display validation error message to player. Do NOT retry automatically. |
| `413 Payload Too Large`| Payload exceeds 15 MB limit. | Truncate raw logs / debug dumps and resubmit. |
| `429 Too Many Requests`| Rate limit reached (>30 req/min). | Back off exponentially (`2^attempt * 1000ms`) and retry up to 3 times. |
| `500 Internal Error` | Unexpected backend error. | Retry once after 2 seconds; if it persists, prompt user to check network. |
| `503 Service Unavailable`| Backend database connecting/offline. | Display backend maintenance message to player. |

---

## 7. Payload Generation Rules

1. **Schema Version**: Must always be `"1.0.0"`.
2. **Scan Mode**: Must be `"QUICK"` or `"FULL"`.
3. **No Executable Code**: Do not submit binary executable files in base64. Use text dumps or structured JSON attributes.
4. **Hashes**: All computed hashes should be lowercase 64-character SHA-256 strings.
5. **Caveats Mandatory**: Every finding must include `limitationsAndFalsePositives` so server staff are never misled.

---

## 8. Reference Implementation (Stage 2 Completed)

The reference implementation for Stage 2 is provided in the repository:
- `backend/src/MinecraftSsForensics.Scanner`: Core testable scanner library containing:
  - `StreamingFileHasher`: SHA-256, SHA-512, Murmur2 with mutation detection.
  - `SafeArchiveInspector`: Zip-bomb and traversal-safe JAR metadata parser (`fabric.mod.json`, `mods.toml`, `quilt.mod.json`, `MANIFEST.MF`).
  - `CompositeModVerifier`: Provider chain (Modrinth, CurseForge, GitHub) with 9 verification states and TTL caching.
  - `LookalikeDetector`: Anomaly detection for disguised mods, mismatched metadata, duplicate mod IDs, and agent hooks.
  - `ProcessScanner` & `CommandLineRedactor`: Scoped `javaw.exe` / `java.exe` process auditing with credential redaction.
  - `HistoricalEvidenceScanner`: Read-only Prefetch, BAM/DAM, and Temp artifact inspection with transparent user-mode limitation diagnostics.
  - `BackendApiClient`: Typed client for report submission and instant player-controlled deletion.
- `backend/src/MinecraftSsForensics.Scanner.App`: Native Windows WPF desktop application providing a 5-panel state machine (Consent & Scope Disclosure -> Progress & Cancellation -> Pre-upload Review -> Submission -> Shareable URL & Deletion Key Result).
- `backend/tests/MinecraftSsForensics.Scanner.Tests`: 24 unit and end-to-end integration tests verifying every component and the full submission lifecycle.

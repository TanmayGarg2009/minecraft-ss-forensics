# Security & Privacy Model

## 1. Threat Model & Scope

Minecraft SS Forensics is designed for consent-based investigations between players and server staff. The architecture explicitly balances forensic diagnostic utility with privacy, anonymity, and anti-abuse protections.

### In-Scope Security Objectives
1. **Report Isolation**: A viewer possessing link `mc_A` must never be able to discover, enumerate, or guess link `mc_B`.
2. **Access Revocation**: The player who uploaded the report can immediately delete it at any time using their unguessable `DeletionKey`.
3. **Automatic Data Lifecycle**: Reports do not persist indefinitely; retention expires after a set window (default 7 days, max 30 days), after which the database records and raw files are destroyed.
4. **Injection Defense**: Malicious players or scanners cannot execute stored Cross-Site Scripting (XSS), SQL injection, or server filesystem path traversal.
5. **No Stealth or Remote Execution**: The platform never sends commands to the player's computer, executes remote code, or captures personal credentials/unrelated browser data.

---

## 2. Bearer-Link Access Model

### How It Works
Anyone with the complete URL (`https://<domain>/report/{publicId}`) can view the forensic report. This intentionally replaces complex staff login infrastructure, preventing staff credential database compromises and enabling rapid sharing during live screenshare sessions.

### Mathematical Security of Identifiers
- **Entropy Source**: Cryptographically secure random bytes generated via `System.Security.Cryptography.RandomNumberGenerator`.
- **Length**: 18 random bytes (144 bits of entropy) encoded into a 24-character Base62 string prefixed with `mc_` (e.g. `mc_fddy1tJ6mEK4IxfFRv`).
- **Brute-Force Resistance**: With 144 bits of entropy ($2^{144} \approx 2.23 \times 10^{43}$ possibilities), an attacker submitting 10,000 guesses per second would require over $7 \times 10^{31}$ years to encounter a collision by chance.
- **Enumeration Prevention**: Public IDs are completely decoupled from database sequential primary keys (internal GUIDs).

---

## 3. Cryptographic Deletion Credentials

### Secret Generation & Storage
- When a report is created, a 256-bit cryptographic token is generated: `del_<64 hex chars>`.
- The plaintext deletion key is delivered **only once** to the uploader in the `POST /api/v1/reports` JSON response.
- The server computes an HMAC-SHA256 hash using a server-side secret salt (`Security:HashSalt`):
  $$\text{Hash} = \text{HMAC-SHA256}(\text{DeletionKey}, \text{Salt})$$
- The database stores **only** the computed hash (`DeletionKeyHash`).
- If the database is compromised, attackers cannot derive the plaintext deletion keys to delete other players' reports.

### Timing Attack Mitigation
When a deletion request is evaluated, `CryptographicOperations.FixedTimeEquals` is utilized to compare byte arrays in constant time, preventing timing-based side-channel analysis.

---

## 4. Stored XSS & Output Sanitization

Forensic reports display user-originating filenames, process arguments, and rule titles:
1. **Server Validation Gate**: The `ReportSubmissionValidator` scans all text fields for script tags (`<script>`, `javascript:`, `onerror=`, `onload=`, `<iframe>`). Payloads containing these tokens are rejected with HTTP 400.
2. **Client React Output Escaping**: React escapes all JSX text by default. No `dangerouslySetInnerHTML` is used in any component.
3. **Content Security Policy (CSP)**:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
   ```
4. **Security Headers**:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

## 5. Storage Security & Path Traversal

Raw evidence files are handled by `LocalEvidenceStorageService`:
- File and report IDs are strictly sanitized using `Path.GetInvalidFileNameChars()`.
- The target path is verified against the canonical root directory using `Path.GetFullPath()`. If the computed path does not start with the configured storage root directory, an `InvalidOperationException` is thrown, blocking `../` directory traversal attempts.

---

## 6. Retention & Cleanup Engine

1. Reports define an `ExpiresAt` UTC timestamp upon ingestion (`UtcNow.AddDays(retentionDays)`).
2. The `ReportCleanupBackgroundService` runs hourly in the background:
   - Queries all reports where `ExpiresAt <= DateTimeOffset.UtcNow`.
   - Calls `IStorageService.DeleteReportEvidenceAsync(report.PublicId)` to purge disk artifacts.
   - Cascades deletion to all database entities (`Findings`, `EvidenceItems`, `TimelineEvents`, `DiagnosticItems`).
3. If an expired report is queried prior to background purge, `ReportService` checks `ExpiresAt` and immediately returns `404 Not Found`.

---

## 7. Operational Limitations & Privacy Notice

- **Bearer Link Sensitivity**: Because anyone with the URL can view the report, players must only provide the link to verified server staff.
- **Local Artifacts Only**: The scanner only collects diagnostic information disclosed in `collectionScopeVersion`. Private personal documents, browser history, passwords, and private chats are outside the collection scope and strictly rejected by the data model.

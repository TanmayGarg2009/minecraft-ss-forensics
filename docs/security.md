# Security Architecture & Hardening Model

**Minecraft SS Forensics** enforces robust defensive security controls to protect both the player executing the scan and the staff member inspecting the resulting evidence.

---

## 1. Threat Model & Defensive Controls

| Threat Scenario | Vulnerability / Attack Vector | Defensive Hardening Control |
| :--- | :--- | :--- |
| **Tampered Report File** | Player modifies JSON finding to hide detected cheat client. | `SHA256-CANONICAL-V2` cryptographic seal over the recursive payload. Viewer flags hash mismatch and alerts staff. |
| **Malicious Archive / Zip Bomb** | Crafted JAR designed to exhaust scanner memory or trigger denial of service. | `SafeArchiveInspector` enforces maximum 10,000 entries, 250 MB total decompressed size, and 100:1 compression ratio limit. |
| **Path Traversal / Zip Slip** | Crafted JAR with `../` entries attempting to overwrite system files. | Strict path validation strips relative separators and rejects archive entries outside the safe extraction target. |
| **Malicious HTML / XSS Injection** | Player names a cheat `"><script>alert(1)</script>.jar` to exploit staff viewer. | `StandaloneHtmlExporter` sanitizes all dynamic fields with `WebUtility.HtmlEncode()` and strips executable protocol schemes. |
| **Insecure Launch / Code Injection** | Malicious PowerShell scripts piped via `iex`. | One-line launcher validates the SHA-256 binary hash against published release manifests before executing `MinecraftSsForensics.exe`. |
| **Spoofed Windows System Binaries** | Malware masquerading as `cmd.exe` or `svchost.exe`. | `AuthenticodeTrustValidator` calls native Win32 `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`. |
| **Locked File Exceptions** | Active game processes locking mod JARs or logs. | All file streams use `FileShare.ReadWrite | FileShare.Delete` and defensive try/catch handlers to avoid crash states. |

---

## 2. Authenticode Trust Verification (`WinVerifyTrust`)

The scanner does not rely on filenames or file extensions to verify binary legitimacy. It integrates directly with the Windows Cryptographic Trust Provider API:

```csharp
var actionGuid = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
var trustData = new WINTRUST_FILE_INFO { ... };
int result = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref trustData);
```

- Returns `Trusted` only when the binary matches an intact digital signature from a trusted root CA.
- Correctly identifies catalog-signed and embedded PKCS#7 signatures.
- Extracts publisher subject name and signature timestamp.

---

## 3. Sandboxed Browser History Reading

To prevent locking active browser sessions or exposing SQL injection surfaces:
1. SQLite history databases are copied to isolated temporary files with their `.wal` and `.shm` journaling companions.
2. Queries are strictly parameterized with exact domain matches:
   ```sql
   SELECT url, title, visit_count, last_visit_time FROM urls WHERE url LIKE @Pattern
   ```
3. WebKit microsecond timestamps are converted accurately to UTC `DateTimeOffset` without timestamp fabrication.

---

## 4. Responsible Disclosure

If you discover a security vulnerability or bypass technique in **Minecraft SS Forensics**, please open a security advisory on GitHub or report it directly to the maintainers.

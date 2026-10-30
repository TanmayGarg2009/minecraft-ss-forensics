# Security & Privacy Model

## 1. Threat Model & Privacy Principles

Minecraft SS Forensics is designed for consent-based forensic investigations between Minecraft players and server anti-cheat staff. The architecture is engineered to provide rigorous diagnostic clarity while maintaining uncompromising standards of user privacy, data isolation, and non-invasive execution.

### Core Security Objectives
1. **Zero-Server Exposure**: No telemetry, evidence, or personal data is transmitted to central servers, cloud buckets, or third-party databases.
2. **Read-Only Non-Invasive Safety**: The application operates in user mode without kernel drivers, background services, code injection, or system modifications.
3. **Explicit Player Consent**: Forensic categories require affirmative opt-in. Sensitive categories (specifically browser history) are strictly opt-in and off by default.
4. **Offline Cryptographic Seals**: Every report is sealed with a deterministic SHA-256 digest so staff can immediately detect offline tampering or falsification.
5. **Strict Secret Redaction**: JVM launch arguments, environment tokens, and authentication parameters are automatically redacted in memory before display or export.

---

## 2. Privacy & Data Protection Controls

### A. Browser History Auditing (Sensitive Category)
- **Problem**: Traditional screensharing tools dump entire browser histories, exposing search queries, personal interests, private purchases, and personal bookmarks.
- **Our Architecture**:
  - The browser history auditor is **explicitly optional and unchecked by default**.
  - If enabled by the player, it strictly filters Chromium SQLite history files **only** for known cheat distribution domains (`vape.gg`, `doomsdayclient.com`, `drip.gg`).
  - Search queries, URL paths, form data, passwords, session tokens, and unrelated web domains are completely ignored and never read into memory.

### B. Secret Redaction (`CommandLineRedactor`)
- Scans `javaw.exe` process arguments for known authentication tokens:
  - `--accessToken <token>` $\rightarrow$ `--accessToken [REDACTED]`
  - `--uuid <uuid>` $\rightarrow$ `--uuid [REDACTED]`
  - `--session <session>` $\rightarrow$ `--session [REDACTED]`
  - `--password <pass>` $\rightarrow$ `--password [REDACTED]`
- Guarantees that sensitive Mojang / Microsoft session tokens cannot be leaked in exported reports or shared screens.

### C. Safe Archive Extraction (`SafeArchiveInspector`)
- Inspects user `.jar` files in memory without extracting arbitrary files to the filesystem.
- Enforces strict Zip-Bomb guards:
  - Maximum archive entries: 10,000
  - Maximum uncompressed total size: 250 MB
  - Maximum compression ratio threshold: 100:1
  - Traversal defense: Discards any entry containing `../` or root paths.

---

## 3. Cryptographic Integrity Seal Verification

To prevent players from hand-editing report JSON files to erase detected cheats:
1. When a scan completes, the engine serializes a canonical normalized JSON payload of all findings, mods, diagnostic items, and summary counters.
2. It computes the SHA-256 digest:
   $$\text{Seal} = \text{SHA-256}(\text{Canonical Normalized Telemetry})$$
3. When staff opens the `.json` report in the Standalone Staff Viewer, the seal is recomputed from the payload and compared.
4. If a player modifies a single character (e.g. changing `"ConfirmedCheatArtifact"` to `"Informational"`), the viewer flags the mismatch: `TAMPER DETECTED: Expected digest mismatch`.

---

## 4. XSS & Offline HTML Escaping

The Standalone HTML Exporter (`StandaloneHtmlExporter`) generates self-contained `.html` reports that can be viewed in standard web browsers:
- All dynamic strings (mod names, filenames, command lines, detection explanations) are strictly passed through `WebUtility.HtmlEncode()`.
- JavaScript event attributes (`onerror=`, `onload=`, `javascript:`) are escaped.
- Inline styles and scripts are completely self-contained with no external CDN requests or remote tracker calls.

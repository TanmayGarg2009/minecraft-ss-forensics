# Privacy & Consent Policy — Minecraft Forensic Scanner

**Version:** 2.1.0-standalone  
**Status:** Mandatory Evidentiary Standard

---

## 1. Core Principles: Local-First & Consent-Bound

The Minecraft Forensic Scanner is designed specifically for transparent, consent-based competitive screensharing. It is fundamentally an **offline forensic tool, NOT spyware, monitoring software, or a background telemetry agent**.

### Key Privacy Guarantees:
1. **100% Offline & Local**: The application has zero network upload capabilities. Reports are saved exclusively to the local file system at a path chosen by the player via a standard Windows `SaveFileDialog`.
2. **Read-Only Inspection**: The scanner never modifies, deletes, quarantines, or tampers with any file, process, or registry key on the host computer.
3. **Strict Credential Protection**: The scanner strictly NEVER extracts passwords, Minecraft session tokens (`access_token`), Microsoft / Xbox account credentials, browser cookies, autofill data, or personal documents.
4. **Transparent Audit Scope**: Every audit category is clearly disclosed before execution. Players can see every finding on the Self-Audit screen before sharing a report with server staff.
5. **No Background Persistence**: The scanner does not install Windows services, kernel drivers, scheduled tasks, autostart registry entries, or background workers. When closed, zero components remain running.

---

## 2. Sensitive Categories & Explicit Consent

### Web Browser History Auditing (Strictly Opt-In)
- **Status:** Disabled by default (`InspectBrowserHistory = false`).
- **Audit Method:** When explicitly enabled by the player, the scanner opens local Chromium `History` databases (Chrome, Edge, Brave, Opera) in read-only mode using a dedicated SQLite parser.
- **Strict Query Scope:** The scanner executes parameterized queries specifically matching known Minecraft cheat distribution domains (e.g., `vape.gg`, `doomsdayclient.com`).
- **Privacy Protections:**
  - Query parameters (such as search tokens, tracking IDs, or personal URLs) are automatically redacted (`[QUERY-REDACTED]`).
  - Personal web browsing, bank websites, social media, and unrelated searches are never read or stored.
  - Authentic WebKit timestamps (`last_visit_time`) are extracted; the scanner never fabricates visit times.

### Terminal & PowerShell History Auditing
- Scans `ConsoleHost_history.txt` strictly for command-line entries referencing known cheat loaders, kernel wiper utilities, or journal wipe commands (`fsutil usn deletejournal`, `wevtutil cl`).
- Does not publish general command lines unrelated to anti-cheat verification.

---

## 3. Data Retention & Sharing

1. **Player Ownership:** The generated `.json` report file is owned entirely by the player.
2. **Volunteer Staff Review:** If a player chooses to share their report with Minecraft server staff, the staff can inspect the cryptographic integrity digest (`SHA256-CANONICAL-V2`) using the dedicated Staff Viewer (`MinecraftSsForensics.Viewer.exe`).
3. **No Centralized Storage:** Because there are no backend APIs, databases, or cloud servers, no third party retains, analyzes, or aggregates player forensic data.

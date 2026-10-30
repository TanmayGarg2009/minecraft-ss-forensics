# Privacy Policy & Consent Architecture

**Minecraft SS Forensics** is built on the principle of minimal, necessary, and strictly consented forensic data collection.

---

## 1. Absolute Privacy Guarantees

1. **Zero External Communication**:
   - The application does not contain telemetry, tracking, analytics, or crash-reporting libraries.
   - It will never connect to external servers unless you enable online mod verification (which queries public Modrinth/CurseForge APIs for file hashes).
2. **Local Control**:
   - All reports are saved locally to files of your choice (`.json`, `.html`, `.md`).
   - You control when and to whom the report file is sent.
3. **Non-Invasive Read-Only Execution**:
   - The scanner does not install drivers, services, or registry run keys.
   - It reads files using shared, non-locking handles and does not modify, delete, or quarantine any files on your system.

---

## 2. What Is Collected

When you execute a scan with standard consent, the scanner inspects:
- **Minecraft Configurations**: Installed mods in `.minecraft` and supported launchers (Prism, Lunar, Badlion, Feather).
- **File Metadata & Hashes**: Size, timestamps, and SHA-256 hashes of `.jar` and `.exe` files in gaming and staging directories (Downloads, Desktop, Recycle Bin).
- **Active Processes**: Running process names, PIDs, memory usage, and loaded DLL modules of active `javaw.exe` instances.
- **Historical Execution Logs**: Windows Prefetch run records, BAM/DAM execution timestamps, UserAssist run counts, and RecentDocs file references.
- **USB Device History**: Connected USB storage device vendor/product IDs and connection timestamps.
- **System Services & Drivers**: Registered system services and active kernel drivers to detect unsigned third-party software.

---

## 3. What Is Explicitly Excluded

The scanner **never** collects:
- Personal documents, photos, videos, or desktop files unrelated to Minecraft.
- Passwords, credentials, browser cookies, or saved autofill data.
- Chat logs from Discord, Telegram, WhatsApp, or browser messaging.
- Keystrokes, screen recordings, microphone audio, or webcam feeds.
- Private encryption keys or personal certificates.

---

## 4. Credential & Secret Redaction

The scanner automatically filters and redacts command-line launch arguments before storing or exporting them. Any occurrences of:
- `--accessToken <token>` $\rightarrow$ `--accessToken [REDACTED]`
- `--uuid <uuid>` $\rightarrow$ `--uuid [REDACTED]`
- `--session <session>` $\rightarrow$ `--session [REDACTED]`
- `--password <pass>` $\rightarrow$ `--password [REDACTED]`

are purged in memory to prevent session token hijacking.

---

## 5. Opt-In Browser History Auditing

Browser history auditing is **unchecked by default**:
- If you opt in, the scanner copies your Chromium browser history database (`Chrome`, `Edge`, `Brave`, `Opera`) to a temporary read-only location.
- It executes a strictly filtered SQL query looking **only** for known cheat distribution domains (`vape.gg`, `drip.gg`, `doomsdayclient.com`).
- No search queries, banking domains, social media URLs, or personal visits are recorded or retained in the report.

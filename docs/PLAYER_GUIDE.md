# Player Guide — Running a Minecraft Forensic Scan

**Audience:** Minecraft Players under Screenshare (SS) Investigation  
**Application:** `MinecraftSsForensics.exe`

---

## 1. Quick Start

1. **Download & Run**: Download `MinecraftSsForensics.exe` from official tournament/server links.
2. **Review Consent**: The application launches directly to the **Audit Scope & Legal Consent** screen.
3. **Choose Categories**:
   - Check the categories you consent to audit (Minecraft Mods, Processes, Execution Artifacts).
   - *Optional Sensitive Audit*: Web browser history is **disabled by default**. Only check this if explicitly requested and agreed upon with the referee.
4. **Select Ruleset**: Choose the gamemode ruleset applicable to the match (e.g. *Crystal PvP*, *Sword PvP*, *General Competitive*).
5. **Start Scan**: Click **Start System Scan**. The scan typically completes in 10 to 30 seconds.
6. **Review Findings (Self-Audit)**: Before sharing anything, you are presented with the complete scan results. Inspect every finding, check, and verified mod.
7. **Save Report**: Click **Save Report (.json)** and choose your destination folder. You can also export a readable HTML report.
8. **Send to Staff**: Send the saved `.json` file to the referee or staff member via Discord or ticket.

---

## 2. Frequently Asked Questions

### Does this application send data to the internet?
**No.** The application is 100% offline-first. It does not contain any web upload endpoints or cloud databases.

### Does it read my passwords or personal photos?
**No.** The application strictly restricts its file searches to game directories, user staging folders (`Downloads`, `Desktop`, `$Recycle.Bin`), and execution logs. It never collects passwords, session tokens, or personal documents.

### What if I want to cancel the scan?
You can click the **Cancel** button on the progress screen at any time to abort the audit immediately.

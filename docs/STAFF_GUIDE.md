# Staff Guide — Forensic Investigation & Report Review

**Audience:** Minecraft Server Staff, Tournament Referees, Anti-Cheat Teams  
**Application:** `MinecraftSsForensics.Viewer.exe`

---

## 1. Opening a Player Report

1. Launch `MinecraftSsForensics.Viewer.exe`.
2. Click **Open Report File (.json)** and select the `.json` file provided by the player.
3. **Verify Integrity Seal Badge**:
   - **Green Badge ("Cryptographic Integrity Verified")**: Confirms that every finding, mod, path, and timestamp matches the `SHA256-CANONICAL-V2` digest generated at scan time.
   - **Red Badge ("Integrity Mismatch / Tampered")**: Indicates that the report file was modified, edited in a text editor, or corrupted after generation. **Do not trust tampered reports.**

---

## 2. Navigating the Investigation Workstation

### 1. Executive Summary & Verdict
- Answers the three fundamental questions within 5 seconds:
  1. *Was anything suspicious found?*
  2. *What was found?*
  3. *What is the strength of the evidence?*

### 2. Mod Inventory & Authenticity
- Inspects every installed JAR.
- Displays Modrinth / CurseForge verification state, official project URLs, and SHA-256 hashes.
- Separates authenticity from gameplay policy: a verified official mod can still be prohibited by server rules.

### 3. Correlated Assessments (The 8 Software States)
- Review whether software was merely `Present` in Downloads, `Installed` in mods, or actively `Loaded in Game Session`.
- Remember: Under `PROHIBITED_EXECUTION` rules, mere file presence without execution proof is NOT a violation. Under `PROHIBITED_POSSESSION` rules, presence alone constitutes a breach.

### 4. Interactive HTML Export
- Click **Export Standalone HTML Report** to generate a single-file, zero-dependency HTML report suitable for archiving, staff ticket logs, or automated second-stage AI analysis.

# Forensic Detection Categories & Evidence Methodology

Minecraft SS Forensics is a 100% standalone, offline-first forensic audit suite engineered for Minecraft server staff, anti-cheat teams, and competitive leagues.

This document outlines the 7-tier classification hierarchy, evidence categories, false-positive mitigation controls, and operational limitations.

---

## 1. The 7-Tier Classification Hierarchy

Rather than producing binary "banned/clean" flags, the tool provides evidence-backed classifications that separate **directly observed technical facts** from **inferences and context**:

| Classification | Meaning | Evidentiary Standard | Example Findings |
|---|---|---|---|
| **CONFIRMED CHEAT ARTIFACT** | Definite evidence of cheat software or prohibited game modification. | Exact cryptographic match against known cheat binary, internal cheat bytecode class, or strictly prohibited mod under active ruleset. | `net.ccbluex.liquidbounce.LiquidBounce` inside JAR, `meteor-client.jar`, `vape.exe` execution trace. |
| **STRONG INDICATOR** | Strong circumstantial evidence of cheat utility or injection framework. | Execution artifacts in BAM/Prefetch matching known ghost client loaders or hook libraries. | Historical execution trace of known ghost client loader executable from USB drive. |
| **SUSPICIOUS** | Anomalous behavior or unverified artifacts requiring scrutiny. | Unsigned dynamic link library mapped into `javaw.exe` from temporary folder without recognized Java native extraction provenance. | Unrecognized DLL `hooker64.dll` mapped from `%TEMP%` into Minecraft JVM. |
| **NEEDS REVIEW** | Unrecognized or modified files where intent cannot be determined automatically. | Unknown mod JAR not cataloged in Modrinth or CurseForge with no known malicious signatures. | Private custom mod created for local utility or clan PvP without public release signature. |
| **INFORMATIONAL** | Normal user behavior, configuration notes, or verified modifications without malicious intent. | Renamed authentic mod where cryptographic hash matches an official release. | `sodium.jar` renamed to `my-sodium-1.20.jar` with exact Modrinth hash match (`INFO-RENAMED-MOD`). |
| **NO EVIDENCE FOUND** | An inspected subsystem showed no indicators of tampering or unauthorized modification. | Complete inspection of a category yielding clean results. | Active process memory contains only signed Windows and official Java runtime binaries. |
| **UNAVAILABLE** | Check could not be completed due to missing permissions, disabled features, or system limitations. | Windows Prefetch disabled on SSD, or non-admin execution preventing low-level memory read. | `CHK-PREFETCH` skipped because Prefetch service `SysMain` is stopped or running on non-admin token. |

---

## 2. Audited Evidence Categories

### A. Minecraft Installation & Mod JAR Inspection
- **Directory Discovery**: Identifies vanilla `.minecraft`, Prism Launcher, Modrinth App, CurseForge, Feather Client, and Lunar Client instances.
- **Safe Archive Parsing**: Inspects ZIP directory structures using strict zip-bomb protection (max entry count, maximum uncompressed expansion ratio, directory traversal guards).
- **Metadata Extraction**: Reads `fabric.mod.json`, `mcmod.info`, `quilt.mod.json`, and `META-INF/MANIFEST.MF`.
- **Bytecode Class Analysis**: Scans internal `.class` filenames against known cheat client package signatures (e.g., Doomsday, Prestige, LiquidBounce, Aristois, Meteor, Vape wrapper).
- **Cryptographic Hashes**: Computes SHA-256, SHA-512, SHA-1, and CurseForge Murmur2 fingerprints using non-locking file streams.

### B. Mod Policy Engine (Authenticity vs Gameplay Permissibility)
- **Multi-Signal Evaluation**: Separates artifact authenticity (official release verification) from gameplay permissibility.
- **Gamemode Profiles**:
  - `Crystal PvP`: Prohibits Freecam, MiniHUD coordinate overlays, automated crystal macros, and hitboxes.
  - `Sword PvP / Vanilla`: Prohibits reach modifiers, autoclickers, and toggle-sprint modifications that alter packets.
  - `UHC`: Prohibits x-ray, entity radar, cave finders, and coordinate helpers.
  - `SMP / Casual`: Permissive default allowing aesthetic and client-side utility mods.
- **Conflict Detection**: Alerts staff if a filename mimics an allowed mod (e.g. `sodium.jar`) but contains prohibited bytecode or internal mod IDs.

### C. Process Memory & Module Provenance
- **Process Target**: Audits active `javaw.exe` and launcher parent/child process relationships.
- **Java Native Provenance Check**:
  - **Problem**: Legitimate Java frameworks (JNA, LWJGL, OpenAL, JInput) legitimately unpack native DLLs into `%LOCALAPPDATA%\Temp\` at runtime.
  - **Mitigation**: Scans temporary DLLs against strict JNA naming patterns (`jna[0-9]+.dll`, `lwjgl.dll`, `OpenAL32.dll`), cross-referencing disk artifacts and signatures rather than applying blind whitelists.
  - **Suspicious Injection Detection**: Unsigned, non-Java DLLs mapped from temporary or user staging directories are flagged as `SUSPICIOUS` with full disclosure of alternative legitimate causes (e.g., screen recording hooks, Discord overlay).

### D. Execution History & Forensic Traces
- **Windows Prefetch (`C:\Windows\Prefetch\*.pf`)**: Analyzes application run history, launch count, and last execution timestamps.
- **Background Activity Moderator (BAM)**: Queries `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\` for persistent execution records even if executables were deleted.
- **Program Compatibility Assistant (PCA)**: Inspects `PcaSvc` registry keys tracking compatibility store records for standalone executables.

### E. Windows Registry Artifacts
- **UserAssist**: Decodes ROT13-encoded execution keys under `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` tracking GUI program executions.
- **Run & RunOnce Keys**: Checks autorun persistence locations for unauthorized background services.
- **RecentDocs**: Audits recently opened documents and archive paths.

### F. Removable Storage Device History
- **USBSTOR Forensics**: Enumerates historically connected USB drives, flash devices, and portable storage from `SYSTEM\CurrentControlSet\Enum\USBSTOR`.
- **Timestamp Correlation**: Helps staff determine if unauthorized cheat executables were executed from removable USB drives immediately prior to a match or screenshare.

### G. Browser History (Sensitive Category — Explicitly Opt-In)
- **Strict Privacy Scope**: Requires explicit player opt-in before inspection.
- **Domain-Only Matching**: Audits local Chromium (Chrome / Edge) SQLite history files **strictly** for known Minecraft cheat distribution domains (`vape.gg`, `doomsdayclient.com`, `drip.gg`).
- **Privacy Protections**: Completely ignores search queries, URLs outside the cheat catalog, form data, passwords, cookies, session tokens, and personal web history.

### H. Filesystem Staging & Recycle Bin
- **Staging Areas**: Audits user `Downloads`, `Desktop`, and `%TEMP%` for cheat filenames or hidden archives.
- **Recycle Bin Forensics**: Inspects `$Recycle.Bin` for recently deleted executable or mod files matching cheat signatures.

---

## 3. Cryptographic Seals & Anti-Tampering

Every generated report (`.json` and `.html`) includes an embedded SHA-256 integrity seal calculated over normalized report telemetry.

When staff loads a report file into the Standalone Staff Viewer:
1. The viewer strips the seal property.
2. The viewer computes the SHA-256 digest of the remaining structured data.
3. If any field, finding, mod hash, or count was altered, the viewer displays a prominent red warning: `TAMPER DETECTED: Cryptographic seal mismatch`.

---

## 4. Known Technical Limitations & Operational Ethics

- **Non-Invasive Architecture**: The tool operates strictly read-only and will never delete, modify, or inject code into player systems.
- **No Blanket Whitelisting**: The tool mitigates false positives through contextual evidence correlation rather than insecure hardcoded hash bypasses.
- **Administrative Rights**: Full execution history (Prefetch) requires running as Administrator. If run as a standard user, prefetch checks are marked `UNAVAILABLE` without crashing.
- **Separation of Evidence**: A file detected on disk does not inherently prove it was executed during an active competitive match without corroborating timestamp and session evidence.

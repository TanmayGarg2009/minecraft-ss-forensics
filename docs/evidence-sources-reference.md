# Evidence Sources & Forensic Artifact Reference

This document provides a technical reference for all evidentiary sources audited by the **Minecraft SS Forensics** scanner on Windows 10 and Windows 11 systems.

Every evidence source is collected in a strictly read-only, non-invasive manner. The scanner never modifies registry hives, deletes files, alters system timestamps, or injects kernel drivers.

---

## 1. Forensic Evidence Source Matrix

| Evidence Source | What Is Recorded | Proves Execution? | Proves Game Interaction? | Typical Retention | Permissions Required | Known False Positives | Evidentiary Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Active Process Memory (`javaw.exe`)** | PIDs, command lines, memory-mapped modules (`.dll`), base addresses. | **Yes** (Active) | **Yes** (Direct memory mapping) | Volatile (Process runtime only) | Standard User | Screen recorders (OBS/Bandicam), Discord Overlay, audio drivers, graphics hooks (RivaTuner, GeForce). | Only audits modules currently mapped into memory. Does not persist after game process terminates. |
| **JNA / LWJGL Native Libraries** | Temporary extracted DLLs (`jnidispatch.dll`, `lwjgl.dll`) in `%TEMP%`. | **Yes** | **Yes** | Duration of session | Standard User | Legitimate Java native libraries extracted dynamically by Fabric/Forge/Vanilla launcher. | Automatically filtered by the scanner's Java Native Library Provenance engine. |
| **Windows Prefetch (`C:\Windows\Prefetch\*.pf`)** | Executable filename, hash, execution count, last 8 execution timestamps (Win 10/11), referenced DLLs and files. | **Yes** | **No** (Proves process execution, not in-game interaction) | Rolling cache (~1,024 files on Win 10/11) | Standard User / Administrator (Reading `.pf` files) | Renamed files matching cheat names, benchmark utilities, false positive file signatures. | Prefetch may be disabled on some SSD systems. Timestamps can roll off on high-usage systems. |
| **Background Activity Moderator (BAM / DAM)** | Full executable path, 8-byte `FILETIME` timestamp of last execution. | **Yes** | **No** | Persistent across reboots until overwritten or cleaned | Administrator / Registry Read | Portable utilities, external installers, development test binaries. | Stored per-user SID under `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`. Does not record execution count. |
| **Program Compatibility Assistant (PCA)** | Executable path, compatibility flags, execution failure/success timestamps. | **Yes** | **No** | Persistent in registry (`AppCompatCache`, `PcaAppLaunchDic`) | Standard User / Registry Read | Windows compatibility troubleshooting runs, legacy tools. | Only records applications that triggered compatibility monitoring. |
| **UserAssist Registry (`NTUSER.DAT`)** | ROT13 encoded GUID subkeys, run counts, focus time, last execution timestamp. | **Yes** (for GUI apps launched via Explorer) | **No** | Persistent across user profile lifetime | Standard User (Current User Hive) | Double-clicking joke files, test files, developer shortcuts. | Console/CLI utilities launched via PowerShell or batch scripts do not populate UserAssist. |
| **Services & Drivers (`HKLM Services`)** | Service name, display name, binary image path, service type (Kernel vs User), start type. | **Yes** (if service started) | **No** (unless driver hooks game) | Persistent in SYSTEM hive | Standard User / Local Machine Read | Anti-cheat drivers (Vanguard, BattlEye, EasyAntiCheat), virtual audio drivers, emulator drivers. | User-mode scan cannot guarantee detection of active rootkits using Direct Kernel Object Manipulation (DKOM). |
| **System Event Log (Event ID 7045)** | Service/driver installation events, service name, image path, installer account, timestamp. | **Yes** (Installation) | **No** | Rolling event log (typically weeks to months) | Standard User / Event Log Read | Legitimate software installs, peripheral driver updates. | Log can be cleared by administrator (`wevtutil cl System`), which is flagged by the scanner as an integrity anomaly. |
| **SetupAPI Logs (`setupapi.dev.log`)** | Driver device installations, PnP device enumeration, timestamps. | **Yes** (Device install) | **No** | Persistent text log in `%SystemRoot%\inf` | Standard User Read | USB mouse, keyboard, or flash drive plug-in events. | Plain text file that can theoretically be truncated by local administrators. |
| **USB Storage History (`USBSTOR`)** | Vendor, product ID, device serial number, volume names, connection timestamps. | **No** (Proves device connection only) | **No** | Persistent in SYSTEM and SOFTWARE hives | Standard User Read | Legitimate thumb drives, portable SSDs, external backup drives. | Connection proves a USB device was inserted; does not prove cheat files were executed from it without Prefetch correlation. |
| **Filesystem Staging ($Recycle.Bin, Downloads, Desktop)** | Filenames, file sizes, creation/modification timestamps, SHA-256 hashes, MFT records. | **No** (Proves possession/presence only) | **No** | Until user deletion or Recycle Bin emptying | Standard User Read | Old unused downloads, joke files, prank files sent over Discord. | File presence proves possession; does not prove execution or in-game use unless governed by a `PROHIBITED_POSSESSION` policy. |
| **Java Class Bytecode Constant Pool** | Class names, package references, method calls (`interactBlock`, `autoCrystal`, `killAura`, `sendPacket`). | **No** (Proves capability/structure) | **No** (Without runtime packet verification) | Static within `.jar` file | Standard User Read | Complex utility mods, optimization mods using mixins, client-side diagnostics. | Identifies structural capabilities; does not prove a toggle was active during a specific match. |
| **Browser History (Opt-In Category Only)** | Domain name, URL path, timestamp, visit count matching curated cheat domains. | **No** (Proves website visit only) | **No** | Browser cache lifetime (days to months) | Standard User Read (Requires explicit consent) | Researching cheats, anti-cheat staff research, curiosity. | Strictly optional! Never accesses passwords, session cookies, or unrelated search queries. |

---

## 2. Evidentiary Boundary Rules

When reviewing reports, staff must observe these five fundamental boundaries:

1. **Possession vs. Execution vs. Gameplay Use**:
   - `PROHIBITED_POSSESSION`: Policy prohibits possessing the software anywhere on the system. Proved by filesystem presence or mod directory discovery.
   - `PROHIBITED_EXECUTION`: Policy prohibits running the software. Proved by Prefetch, BAM, PCA, or active process telemetry.
   - `PROHIBITED_GAMEPLAY_USE`: Policy prohibits using features in a match. Requires in-game server telemetry, combat logs, or packet capture.

2. **User-Mode vs. Kernel-Mode Scanning**:
   - This scanner runs in Windows user-mode. It does not install kernel hooks or ring-0 drivers.
   - While it detects non-standard services, unverified drivers, Event ID 7045, and SetupAPI records, it cannot detect kernel rootkits using Direct Kernel Object Manipulation (DKOM).

3. **Cryptographic Release Verification**:
   - Verification against Modrinth, CurseForge, and GitHub confirms that a JAR file matches an official release bit-for-bit.
   - However, an authentic official mod can still be prohibited under specific competitive rulesets (e.g., Freecam, Mini-maps, Auto-Clickers).

4. **Temporal Scope**:
   - Artifacts reflect historical activity. A Prefetch execution timestamp from two weeks ago proves the binary was executed then, but does not prove it was running during a match played today.

5. **Consent Integrity**:
   - The player controls collection scope. Any omitted categories are recorded in the report as `NOT_COLLECTED_BY_USER_CHOICE` and never assumed to be malicious.

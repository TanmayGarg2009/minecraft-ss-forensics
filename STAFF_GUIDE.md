# Staff Guide — Forensic Investigation & Report Review

This guide outlines the methodology for server staff, referees, and anti-cheat reviewers using **`MinecraftSsForensics.Viewer.exe`** to verify player reports, evaluate evidence, and render defensible disciplinary decisions.

---

## 1. Opening a Player Report

1. Launch `MinecraftSsForensics.Viewer.exe` on your workstation.
2. Click **Open Report File (.json)**.
3. Select the `.json` report provided by the player.
4. **Immediate Seal Check**:
   - The viewer automatically computes the `SHA256-CANONICAL-V2` digest of the payload.
   - If the seal matches, a green banner appears: `✓ SEAL VALID: Authentic Unmodified Report`.
   - If any finding, count, or metadata field was edited, a red banner appears: `⚠ TAMPER DETECTED: Report payload does not match cryptographic seal`. Reject tampered reports immediately.

---

## 2. Navigating the Investigation Interface

The viewer provides an intuitive multi-tab interface:

### 2.1 Overview & Executive Summary
- Displays overall verdict (`CLEAN`, `SUSPICIOUS`, or `VIOLATION_CONFIRMED`).
- Highlights critical counts: Prohibited Possession, Prohibited Execution, Unverified Mods, and Duplicate Files.
- Displays player environment: OS version, system architecture, scan duration, and execution privileges (Standard vs Administrator).

### 2.2 Finding Records & Evidence Chains
Click any finding to inspect its multi-layer evidentiary corroboration:
- **Rule Violated**: Policy rule triggered (e.g., `RULE-METEOR: Meteor Client`).
- **Software State**: Strict classification among the 8 software states:
  - `SoftwarePresent`: File located on disk or in Recycle Bin.
  - `SoftwareInstalled`: Placed in active launcher profile `mods/` folder.
  - `SoftwareExecuted`: Recorded in Prefetch, BAM/DAM, or PCA.
  - `SoftwareActiveDuringSession`: Executed concurrently with Minecraft.
  - `SoftwareInteractingWithMinecraft`: Injected or mapped into `javaw.exe`.
  - `ProhibitedFunctionalityUsed`: Corroborated combat or movement automation.
- **Evidence Confidence**: High (1.00), Medium (0.75), or Low (0.50). Corroborated when multiple distinct sources agree.

### 2.3 Bytecode & Static Analysis
Review decompiled structural findings:
- Invoked APIs (`java/awt/Robot`, `glfwSetCursorPos`, `sendPacket`).
- Mixin targets hooking into Minecraft rendering or player movement.
- Known cheat strings or package signatures detected in memory.

### 2.4 Historical Traces
- **Prefetch Entries**: View execution counts, first/last execution timestamps, and loaded DLL modules.
- **Recycle Bin Artifacts**: Inspect deleted files recovered from `$I`/`$R` pairs, including deletion timestamps and original filenames.
- **BAM / DAM**: Review registry execution timestamps with translated DOS drive letters.
- **USB Storage History**: Review connected flash drives correlated with `setupapi.dev.log` device connection timestamps.

---

## 3. Rendering a Defensible Verdict

Staff must evaluate evidence according to the server's published policy:

| Finding Scenario | Policy Standard | Recommended Staff Action |
| :--- | :--- | :--- |
| **Hacked Client in Downloads** | `PROHIBITED_POSSESSION` | Confirmed violation under possession rules. |
| **Hacked Client in Downloads** | `PROHIBITED_EXECUTION` | Not a violation unless Prefetch / BAM confirms execution. |
| **Modified / Repackaged Mod** | `NEEDS_REVIEW` | Inspect bytecode capabilities tab; verify if modifications are harmless performance optimizations or disguised cheats. |
| **Deleted Cheat in Recycle Bin** | `PROHIBITED_POSSESSION` | Confirmed possession; note deletion timestamp relative to match start time. |
| **Unsigned DLL Mapped into Java** | `PROHIBITED_EXECUTION` | Critical indicator of active injection or hook. |

---

## 4. Exporting Summaries

To attach evidence to ban appeals or tournament logs:
- Click **Export HTML Report** to save a self-contained, offline-viewable summary.
- Click **Export AI Markdown** to generate a structured text document optimized for automated second-stage LLM review.

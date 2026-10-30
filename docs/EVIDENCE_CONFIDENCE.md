# Evidence Confidence & Correlation Methodology

**Version:** 2.1.0-standalone  
**Standard:** Minecraft Competitive Screensharing Evidentiary Framework

---

## 1. The 8 Correlated Software States

Forensic screensharing must never collapse findings into a simplistic "cheating detected" or "clean" binary. Instead, the application correlates evidence into **8 distinct, non-interchangeable software states**:

| State # | Software Evidence State | Evidentiary Standard & Meaning |
| :---: | :--- | :--- |
| **1** | `SoftwarePresent` | The software binary or archive is located in user staging folders (`Downloads`, `Desktop`, `$Recycle.Bin`, `%TEMP%`). Possession is established, but installation and execution remain unproven. |
| **2** | `SoftwareInstalled` | The mod archive is placed in an active Minecraft profile `mods/` directory. Software is staged to load, but execution is not yet proven. |
| **3** | `SoftwareExecuted` | The software has verified historical execution traces recorded in Windows Prefetch, BAM/DAM, UserAssist, or PCA. |
| **4** | `SoftwareActiveDuringSession` | The mod was verified loaded into an active `javaw.exe` instance (via JVM `-classpath`, `-javaagent`, or matching active profile directory). |
| **5** | `SoftwareInteractingWithMinecraft` | A native library, unsigned DLL, or external tool is actively mapped into the Minecraft process memory space or holding open handles. |
| **6** | `SoftwareContainsProhibitedCapabilities` | Static bytecode analysis verifies prohibited capabilities (e.g., auto-crystal detonation, reach multipliers, packet spoofing) regardless of whether executed. |
| **7** | `ProhibitedFunctionalityUsed` | Corroborating evidence (in-game match logs, server combat telemetry, packet logs) establishes that an unfair advantage feature was actively toggled during match play. |
| **8** | `IsPolicyViolation` | Evaluated against the server's gamemode ruleset: determines whether the verified state breaches `PROHIBITED_POSSESSION`, `PROHIBITED_EXECUTION`, or `PROHIBITED_GAMEPLAY_USE`. |

---

## 2. Policy Enforcement Standards

Different Minecraft servers and tournament leagues enforce different rulebooks:

1. **`PROHIBITED_POSSESSION`**: Confirmed presence or installation is sufficient for a policy violation (e.g. hacked client JAR or known cheat utility on disk).
2. **`PROHIBITED_EXECUTION`**: Requires verified execution traces (Prefetch, BAM, UserAssist) or active process loading before flagging a violation. Mere presence of an unexecuted, inactive file does not violate an execution-based rule.
3. **`PROHIBITED_GAMEPLAY_USE`**: Requires corroborating in-game match session telemetry or packet manipulation proof.
4. **`ALLOWED`**, **`RESTRICTED`**, **`NEEDS_REVIEW`**, **`UNKNOWN`**: Transparent categorizations that separate mod authenticity from gameplay policy.

---

## 3. Explicit Evidence States & Confidence Tiers

Every individual piece of evidence is assigned an explicit state:
- `CONFIRMED`: Mathematical certainty (cryptographic hash match, authentic timestamp, or verified signature).
- `STRONG_INDICATOR`: Corroborated trace (e.g. Prefetch execution or UserAssist record).
- `WEAK_INDICATOR`: Uncorroborated single-source signal.
- `INCONCLUSIVE`: Ambiguous finding with multiple alternative legitimate explanations.
- `NOT_CONFIGURED`: Telemetry source was disabled on Windows.
- `NOT_AVAILABLE`: Windows edition or permissions prevented collection.
- `DATA_EXPIRED_OR_OVERWRITTEN`: Rolling log (such as Event Log or Prefetch) rotated historical entries.
- `COLLECTION_FAILED`: Reader error occurred.
- `NOT_COLLECTED_BY_USER_CHOICE`: Player opted out in consent dialog (e.g. browser history).

**Critical Rule:** Missing telemetry is NEVER automatically interpreted as evidence of tampering.

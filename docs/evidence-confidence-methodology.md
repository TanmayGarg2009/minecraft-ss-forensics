# Evidence Confidence & Correlation Methodology

This document outlines the evidentiary principles, confidence grading scale, and multi-source correlation engine implemented in **Minecraft SS Forensics**.

---

## 1. The 6 Correlated Software States

Forensic investigation often suffers from binary oversimplification: flagging a player as "cheating" simply because a file with a suspicious name was found on their hard drive.

Minecraft SS Forensics introduces a strict 6-stage Software State hierarchy. Every finding is assigned an explicit software state that reflects exactly what the collected evidence proves:

```
[1. Software Present] ───────► [2. Software Installed] ───────► [3. Software Executed]
       │                                                                │
       ▼                                                                ▼
 (File on Disk)              (In Active Profile Mods)         (Prefetch / BAM / PCA)
                                                                        │
                                                                        ▼
[6. Prohibited Used]  ◄────── [5. Software Interacting] ◄────── [4. Active in Session]
       │                               │                                │
 (In-Game Packet/Logs)       (DLL Injected in javaw)         (javaw.exe Running Same Time)
```

### Definitions:

1. **`SoftwarePresent`**: The executable, JAR, or script exists somewhere on the physical storage device (e.g. in `Downloads`, `Desktop`, or `$Recycle.Bin`).
   * *What is proven:* The user downloaded, received, or stored the file.
   * *What is NOT proven:* Installation into Minecraft, execution, or gameplay use.

2. **`SoftwareInstalled`**: The artifact is located inside an active Minecraft installation directory (e.g., `.minecraft/mods/`).
   * *What is proven:* The file is configured to be loaded when the game launches.
   * *What is NOT proven:* In-game feature activation or gameplay toggling during competition.

3. **`SoftwareExecuted`**: The executable has a verifiable execution record in Windows Prefetch, BAM/DAM, PCA, or UserAssist.
   * *What is proven:* The binary ran as an active process on the machine at the recorded timestamp.
   * *What is NOT proven:* That it was running simultaneously with Minecraft, or that it hooked the game process.

4. **`SoftwareActiveDuringSession`**: Evidence confirms the software was running concurrently with an active `javaw.exe` Minecraft process.
   * *What is proven:* Temporal co-existence during gameplay.
   * *What is NOT proven:* Direct memory manipulation or packet modification.

5. **`SoftwareInteractingWithMinecraft`**: The software is actively mapped into `javaw.exe` memory address space (e.g., injected unsigned DLL, JNI hook, or reflective load).
   * *What is proven:* Memory interaction and direct process access.
   * *What is NOT proven:* Malicious intent if the module is an unlisted recording utility or overlay.

6. **`ProhibitedFunctionalityUsed`**: Corroborated evidence (such as server packet telemetry, combat hitboxes, or synchronized event logs) confirms a prohibited advantage was activated in-game.
   * *What is proven:* Active unfair advantage during a competitive match.

---

## 2. Policy Violation Scopes

Server policies evaluate these software states against their specific rule definitions:

* **`PROHIBITED_POSSESSION`**:
  * *Standard:* Possession of the software anywhere on the system (State 1 or State 2) constitutes a full policy violation.
  * *Evidence required:* Cryptographic SHA-256 match, verified filename match, or bytecode signature in files or mods.
  * *Evidentiary note:* Execution proof is *not* required under this policy rule.

* **`PROHIBITED_EXECUTION`**:
  * *Standard:* Running the software on the computer constitutes a violation, regardless of whether in-game advantage is proven.
  * *Evidence required:* Execution records (State 3, 4, or 5).
  * *Evidentiary note:* If the file is only present on disk (State 1) without execution records, it is classified as `NEEDS_REVIEW`, not a violation.

* **`PROHIBITED_GAMEPLAY_USE`**:
  * *Standard:* Prohibits in-game feature activation.
  * *Evidence required:* State 6 (packet logs, combat telemetry, or runtime toggle proof).
  * *Evidentiary note:* Mere installation or execution of a multi-purpose tool is not alone sufficient for a competitive ban without corroborating session telemetry.

---

## 3. The 9 Evidence States

Every diagnostic check and finding is qualified by one of nine discrete evidence states:

| State | Definition | Example |
| :--- | :--- | :--- |
| **`CONFIRMED`** | Deterministic cryptographic or structural fact. | Exact SHA-256 hash match against Modrinth official release, or exact match against known cheat binary. |
| **`STRONG_INDICATOR`** | Reliable evidentiary trace pointing to specific behavior, with minimal alternative explanations. | Windows BAM registry record showing execution of a known cheat tool path 10 minutes prior to match. |
| **`WEAK_INDICATOR`** | Circumstantial observation with plausible legitimate alternatives. | Unsigned DLL in `%TEMP%` loaded by `javaw.exe`, which may be an unlisted screen recorder. |
| **`INCONCLUSIVE`** | Conflicting or insufficient data to draw a defensible conclusion. | File timestamp indicates modification, but MFT records are incomplete. |
| **`NOT_CONFIGURED`** | Feature or policy rule is not configured for the active server gamemode. | No policy rules specified for a custom mod ID. |
| **`NOT_AVAILABLE`** | System artifact could not be accessed due to OS architecture or disabled OS features. | Windows Prefetch is disabled on the player's SSD drive. |
| **`DATA_EXPIRED_OR_OVERWRITTEN`** | Historical data existed but has rolled off due to buffer limits. | Event log rolled over due to standard Windows event log capacity limits. |
| **`COLLECTION_FAILED`** | Technical exception occurred during read-only collection. | Access denied when reading locked system file. |
| **`NOT_COLLECTED_BY_USER_CHOICE`** | Player explicitly opted out of this collection category during consent scoping. | Player unchecked Browser History in the scan consent interface. |

---

## 4. Confidence Levels

Findings are assigned a four-tier confidence rating:

1. **`Certain`**: Cryptographically sealed, byte-exact, or kernel-level recorded facts. Zero likelihood of machine misidentification.
2. **`High`**: Strong corroborating evidence across multiple artifacts (e.g. Prefetch execution timestamp matching BAM registry and file discovery).
3. **`Medium`**: Strong single-source evidence that warrants staff review, but carries potential legitimate alternative hypotheses.
4. **`Low`**: Weak heuristic signal (e.g. keyword match in a text document or generic script name). Must never be used alone to justify sanctions.

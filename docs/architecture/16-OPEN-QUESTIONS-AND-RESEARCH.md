# 16 — Open Technical Questions & Forensic Research Roadmap

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Specification  
**Version**: 3.0.0-DRAFT  
**Author**: Principal Security Architect, Research Team Lead  
**Classification**: Research Agenda & Open Inquiries  

---

## 1. Executive Summary: Areas of Technical Uncertainty

A defensible architecture explicitly documents what is unknown or unverified rather than assuming theoretical techniques will function reliably in adversarial practice. This document catalogs active research questions, external dependencies, and strategic policy decisions requiring human adjudicator approval.

---

## 2. Technical Research Inquiries

### Research Area 1: Non-Invasive Detection of Dynamic HotSpot Attach Injections
- **Classification**: `[UNKNOWN]`
- **The Challenge**: A player can start Minecraft cleanly without `-javaagent:` arguments, enter a tournament match, and subsequently use a secondary process to invoke `com.sun.tools.attach.VirtualMachine.attach(jvmPid).loadAgent(cheatJar)`.
- **Active Research Questions**:
  1. *Socket Probing*: Does inspecting the Windows named pipe or temporary IPC socket (`%TEMP%\.java_pid<pid>`) reliably reveal dynamic agent attachment without attaching to the JVM or altering its state?
  2. *Security Manager & Access Controls*: Does querying HotSpot attach state require administrative elevation or debug privileges (`SeDebugPrivilege`) on Windows 11 with Core Isolation / Memory Integrity (HVCI) enabled?
- **Action Item**: Develop a dedicated synthetic research harness measuring Windows 10/11 IPC socket behavior under standard user privileges.

### Research Area 2: Memory-Mapped Native Injection without PEB Registration
- **Classification**: `[UNKNOWN]`
- **The Challenge**: Sophisticated native cheats bypass `LoadLibrary` by using manual PE mapping (reflective DLL injection), allocating memory via `VirtualAllocEx` and manually resolving imports. Because the DLL is not loaded via standard Win32 loaders, it does not appear in `EnumProcessModulesEx` or `InLoadOrderModuleList`.
- **Active Research Questions**:
  1. *VirtualQueryEx Scanning*: Can user-space `VirtualQueryEx` reliably scan `PAGE_EXECUTE_READWRITE` and `PAGE_EXECUTE_READ` memory regions in `javaw.exe` to detect unbacked executable pages without triggering anti-cheat watchdog hooks or degrading game performance?
  2. *Performance Overhead*: What is the scanning latency of iterating the virtual address space of a 64-bit Java process configured with a 16 GB heap?
- **Action Item**: Benchmark memory page enumeration latency across varying Java heap sizes.

### Research Area 3: Windows 11 24H2 / Next-Gen OS Artifact Evolution
- **Classification**: `[INFERRED]`
- **The Challenge**: Microsoft regularly modifies internal structures of AppCompatCache, BAM, and Prefetch between major Windows releases (e.g. changes between Windows 10 build 19041 and Windows 11 build 26100).
- **Active Research Questions**:
  1. Does Windows 11 24H2 alter the SCCA header structure (version 31) in `C:\Windows\Prefetch\`?
  2. Are BAM/DAM registry key paths relocated under future security updates?
- **Action Item**: Integrate CI build matrix testing against preview builds of Windows 11 to track telemetry format changes before public release.

### Research Area 4: Passive Observability Limits of PCIe DMA Hardware
- **Classification**: `[UNKNOWN]`
- **The Challenge**: Direct Memory Access (DMA) cards read host physical RAM directly across the PCIe bus without invoking CPU instructions or OS APIs.
- **Active Research Questions**:
  1. Can user-space software differentiate an unmasked generic FPGA PCIe device descriptor from legitimate development hardware without false positives?
  2. Are secondary USB microcontroller HID emulators (Arduino/Teensy) distinguishable from legitimate custom mechanical keyboards via USB endpoint descriptor polling?
- **Action Item**: Research USB descriptor tree enumeration patterns in `SetupAPI` to establish baseline hardware boundaries.

### Research Area 5: Empirical Calibration Requirements for Probabilistic Correlation
- **Classification**: `[PROPOSED]`
- **The Challenge**: Proposing a Bayesian or probabilistic scoring model requires empirically verified prior probabilities ($P(\text{Cheat})$) and likelihood ratios.
- **Active Research Questions**:
  1. What is the minimum sample size of independently labeled, representative clean and cheat system states required to calibrate a Bayesian network without introducing statistical bias?
  2. How can ground-truth datasets be gathered across diverse gaming demographics without violating privacy?
- **Action Item**: Retain deterministic graph traversal and clustering until an independently audited calibration dataset of at least 10,000 verified host states is compiled.

---

## 3. Decisions Requiring Human Adjudicator Approval

The following strategic policy decisions cannot be resolved purely through software engineering; they require explicit policy governance from server administration:

| Policy Decision ID | Governance Question | Trade-Off Analysis | Recommended Default |
| :--- | :--- | :--- | :--- |
| **POL-01** | **Possession vs Execution Policy Enforcement** | Should the presence of a cheat file in `Downloads` trigger an automatic match forfeiture, or should staff only penalize confirmed in-game execution? | Default to **Strict Separation**: Report as `Known prohibited artifact identified; runtime activity not established` (Verdict 3), leaving sanction decisions to server rulebook. |
| **POL-02** | **Handling of Obfuscated Community Mods** | Many legitimate small community mods use free obfuscators to protect custom assets. Should an unknown obfuscated mod be permitted or flagged? | Default to **`POLICY_REVIEW_REQUIRED`**: Classify as `NeedsReview`, provide constant pool analysis, and instruct human staff to inspect mod source or author. |
| **POL-03** | **Opt-In Web History Inspection** | Should browser history auditing be removed entirely to maximize player privacy, or retained as an explicit opt-in diagnostic? | Default to **Retain with Strict Opt-In**: Disabled by default; requires explicit player checkbox before reading local SQLite databases. |
| **POL-04** | **Server-Side Anti-Cheat Telemetry Bridge** | Should tournament staff be permitted to import server-side anti-cheat flags (`.mcsec`) into local reports to cross-correlate with client evidence? | Default to **Permit with Strict Separation**: Allow offline manual import; enforce that server flags are visually badged and never mutate local host observations. |
| **POL-05** | **Server Policy Pack Governance & Decoupling** | Should tournament rulebooks (`.polpack`) be allowed to restrict authentic community utilities (Litematica, Freecam) without labeling them malware? | Default to **Strict Policy Decoupling**: Software identity and authenticity remain distinct from rule compliance. Prohibited gameplay use is evaluated against active policy pack. |

# Detection Coverage and Known Limitations

SSing Tool is a Windows user-mode evidence collection and correlation application. It is not an anti-cheat driver, malware verdict engine, or universal injector detector. A suspicious finding is not a finding of guilt.

## Supported methods

- Process inspection using Windows process APIs and WMI where available. Captures a targeted set of processes, not a complete system inventory. Minecraft classification requires a known game/client process name or recognized Minecraft/loader launch marker on Java command lines; other launchers or obfuscated/custom launch configurations may be missed.
- Loaded module enumeration through .NET process module APIs. Collection can be denied, partial, or unavailable across bitness/protected-process boundaries. Hashing and file metadata are best-effort. A module present in a process is not proof of malicious intent.
- Optional bounded read-only scanning of private executable virtual-memory regions for `MZ` PE headers. It can miss manual mapping that removes/relocates headers, may encounter access limitations, and does not inspect or dump arbitrary memory. It does not establish what code did.
- Java agent and launch-argument observation. Startup arguments do not prove the agent file existed, loaded successfully, or changed game behavior. Dynamically attached agents may have no startup argument.
- Mod metadata and static archive/class constant-pool inspection. This can identify loader metadata and known strings/classes, but obfuscation causes misses and benign references can cause false positives. A mod installed in a profile is not proof it loaded in a match.
- Windows Prefetch/BAM/PCA/registry and service/driver collection where implemented and accessible. These sources are incomplete, configuration-dependent, and may be absent, malformed, permission-limited, stale, or ambiguous. Their absence does not prove deletion or non-execution.
- Recycle Bin `$I` metadata and paired `$R` payload inspection where accessible. It does not cover Shift+Delete, secure wiping, purged records, or inaccessible volumes.
- Optional Chromium history matching only known domains. A domain match is not evidence of downloading, running, possession, or Minecraft use.
- SHA-256 canonical report sealing and local verification. A digest detects changes after sealing only if the seal itself is trusted; it is not a digital signature and does not authenticate author or chain of custody.

## Not supported or not established

- Universal cheat, malware, injector, rootkit, kernel, hypervisor, hidden-process, or manually mapped code detection.
- Proof that a feature was toggled or used during a match from a file, mod, string, hash, parent process, Java agent argument, unsigned module, browser visit, or historical OS record alone.
- Comprehensive class-level JVM telemetry, runtime method tracing, server-side game evidence, network packet capture, loaded-JAR verification, or dynamic attach-agent detection.
- Complete NTFS USN/MFT/ADS forensic parsing or comprehensive Amcache/PCA/BAM coverage across all Windows versions.
- HID/macro device identification or attribution of USB storage use to a specific application.
- Online verification in CLI mode. GUI online verification is opt-in and limited to configured mod hash providers.
- Guaranteed removal of temporary files after abrupt process termination or system failure.

## Verdict interpretation

`No known prohibited indicators detected within tested coverage` is a bounded statement, not proof of a clean system. If required collection is skipped, failed, partial, denied, unsupported, or otherwise incomplete, results should be inconclusive and should not be shown as a green clean verdict. A filename/hash/string match alone never proves execution. Evidence of module loading proves an observed mapping to a process instance; it does not alone prove intent or competitive advantage.

The application must never be used as the sole basis for punitive decisions without human review, corroboration, and an opportunity for the affected user to respond.

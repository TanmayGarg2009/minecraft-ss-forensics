# 17 — Comprehensive Architecture & Forensic Glossary

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Specification  
**Version**: 3.0.0-DRAFT  
**Author**: Principal Security Architect, Technical Documentation Lead  
**Classification**: Reference Lexicon & Terminology Standard  

---

## 1. Forensic & Evidentiary Terminology

- **Artifact**: Any physical, logical, or temporal data structure existing on a host operating system that records historical or active state (e.g., a file, registry key, prefetch record, memory segment, or log event).
- **Attributed Evidence Graph**: A directed graph data structure $\mathcal{G} = (\mathcal{V}, \mathcal{E})$ where vertices represent forensic entities (processes, files, modules) and edges represent verified relationships (loaded_by, launched_by), annotated with confidence and provenance metadata.
- **Authenticode**: Microsoft's digital signing standard based on PKCS#7 cryptographic envelopes and X.509 certificates, allowing the verification of the identity of software publishers and the integrity of binary code.
- **Corroboration**: The presence of independent, mutually confirming telemetry from separate operating system subsystems supporting the same factual hypothesis (e.g., Prefetch and UserAssist both recording an execution).
- **De-duplication**: The process of identifying multiple observations that describe the same underlying software artifact and grouping them under a unified `EvidenceClusterId` without multiplying severity totals.
- **Evidence Cluster**: A logical grouping of multiple raw observations across different OS layers that all originate from a single physical or logical software component.
- **Evidentiary Strength**: The degree of factual certainty and cryptographic/observational robustness supporting a finding (`Strong`, `Moderate`, `Weak`, `Inconclusive`), independent of its policy impact.
- **Historical Telemetry**: Data recording past system activity that occurred prior to the initiation of the active inspection window (e.g., Prefetch records from days ago).
- **Inconclusive**: A formal forensic status indicating that necessary evidence could not be acquired (due to permission barriers, file corruption, or disabled OS logging), preventing a definitive clean or violation determination.
- **Observation**: An immutable, atomic record of environmental telemetry collected at a specific point in time by a forensic collector.
- **Provenance**: The verifiable origin, lineage, and custody chain of an artifact, including creation source, signing entity, extraction parent, and directory context.
- **Severity**: The potential policy or security impact of a finding assuming its factual claims are true (`Critical`, `High`, `Medium`, `Low`, `Informational`), independent of its evidentiary strength.
- **Timestomping**: The anti-forensic act of deliberately modifying file metadata timestamps (`$STANDARD_INFORMATION`) to match legitimate system files in order to mislead chronological audits.

---

## 2. Windows Operating System Internals

- **AppCompatCache (ShimCache)**: A Windows registry/kernel cache (`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`) used by the Application Compatibility engine to track executable file paths, sizes, and last modification times to determine if compatibility shims are needed.
- **Background Activity Moderator (BAM/DAM)**: A Windows service (`SYSTEM\CurrentControlSet\Services\bam`) that tracks desktop application execution paths and timestamps for power management and process throttling.
- **MAM Compression**: A proprietary Microsoft compression format based on the `XPRESS_HUFF` algorithm used to compress Windows 10 and 11 Prefetch files on disk. Decompressed via `ntdll!RtlDecompressBufferEx`.
- **PEB (Process Environment Block)**: A user-mode data structure allocated by the Windows kernel for every running process, containing the list of loaded modules (`InLoadOrderModuleList`), process startup arguments, and environment variables.
- **Program Compatibility Assistant (PCA)**: A Windows subsystem that monitors applications for compatibility failures, storing execution records and configuration settings in registry hives and `%SystemRoot%\AppCompat\Programs`.
- **UserAssist**: A set of ROT13-encoded registry keys located at `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` that record execution counts and last launch timestamps for GUI applications launched via Windows Explorer.
- **USN Journal ($UsnJrnl)**: The NTFS Update Sequence Number Journal, an internal file system log that records changes to files and directories on an NTFS volume, including creation, renaming, and deletion events.
- **Amcache (`Amcache.hve`)**: A Windows registry hive file that tracks application execution, installation inventory, file paths, SHA-1 hashes, and PE header compilation timestamps for application compatibility.
- **Bring Your Own Vulnerable Driver (BYOVD)**: An attack technique where a signed, legitimate, but known-vulnerable kernel driver is installed on the host to bypass driver signature enforcement and read/write physical kernel memory.
- **Direct Kernel Object Manipulation (DKOM)**: A technique used by kernel-mode rootkits to directly modify executive kernel structures (such as unlinking an `EPROCESS` block) to hide processes from standard enumeration APIs.
- **Direct Memory Access (DMA) PCIe Card**: A physical hardware expansion card containing an FPGA that interfaces directly with physical system RAM over the PCIe bus, bypassing the host CPU, OS kernel, and running software.
- **Reflective DLL Injection**: A library injection technique that copies a native PE binary into a target process's memory and manually resolves imports and base relocations without calling the standard Win32 `LoadLibrary` API, bypassing the PEB module list.
- **SetupAPI Log (`setupapi.dev.log`)**: A Windows diagnostic log that records device driver installations, hardware plug-and-play events, and USB device enumerations.
- **System Resource Usage Monitor (SRUM)**: A Windows diagnostic subsystem storing historical per-application resource utilization (network bytes transferred, foreground CPU time) in an ESE database (`SRUDB.dat`) in 60-minute windows.

---

## 3. Java Virtual Machine (JVM) & Minecraft Internals

- **ClassFileTransformer**: An interface in the `java.lang.instrument` package allowing a Java agent to intercept and modify class bytecode before it is defined by a class loader in the JVM.
- **Constant Pool**: A table of variable-length structures located inside every Java `.class` file that describes symbolic references, string literals, class names, method names, and descriptors used by the bytecode instructions.
- **Fabric Loader**: A modern, lightweight, modular Minecraft modding framework that transforms bytecode at runtime using the Spoon engine and Mixin mappings.
- **Forge / NeoForge**: A comprehensive Minecraft mod loader and API providing standardized hooks, item registries, and event pipelines for complex mods.
- **HotSpot Attach API**: A JVM management interface (`com.sun.tools.attach.VirtualMachine`) allowing an external process to dynamically connect to a running JVM instance and load an instrumentation agent into memory post-startup.
- **Java Agent**: A specialized `.jar` archive containing a `premain` (startup) or `agentmain` (dynamic attach) method that leverages the Java Instrumentation API to inspect or modify bytecode.
- **Java Native Access (JNA)**: A community library that provides Java programs easy access to native shared libraries without writing boilerplate JNI code. Frequently unpacks temporary `.dll` files into `%TEMP%` at runtime.
- **JVMTI (JVM Tool Interface)**: A native C/C++ programming interface provided by the JVM for profiling, debugging, and inspecting virtual machine state, thread execution, and object memory.
- **Lookalike Disguise**: An adversarial evasion technique where an unauthorized software archive is renamed to match the filename of a popular legitimate mod (e.g., `sodium-1.20.1.jar`) while containing unverified internal code.
- **Mixin**: A bytecode manipulation framework developed by SpongePowered and utilized by Fabric allowing mods to inject code into target classes at runtime without replacing entire class files.
- **Modrinth / CurseForge**: Standardized community repositories and package registries hosting verified Minecraft mods, texture packs, and modpacks with authoritative cryptographic hashes and metadata.
- **Netty Pipeline ChannelHandler**: An event-driven network handler in the Netty networking framework utilized by Minecraft; can be hooked to intercept, delay, or modify protocol packets before transmission.
- **RFC 8785 (JCS)**: JSON Canonicalization Scheme; an international standard for deterministic serialization of JSON data ensuring identical SHA-256 digests across disparate platforms.
- **Server Policy Pack (`.polpack`)**: A versioned, decoupled configuration specification defining permitted, restricted, and prohibited software and capabilities for a specific Minecraft server or tournament.
- **Server-Side Evidence Bridge (`.mcsec`)**: An optional offline evidence file format allowing tournament adjudicators to import server-side anti-cheat flags and combat anomalies for multi-source correlation with client findings.
- **Zip-Slip**: A directory traversal vulnerability occurring when unzipping an archive that contains filenames with path traversal characters (e.g. `../../evil.bat`), allowing files to be written outside the intended destination directory.

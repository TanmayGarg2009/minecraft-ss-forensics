# System Architecture — Standalone Windows Forensic Suite

## 1. System Overview

**Minecraft SS Forensics** is an offline-first, standalone forensic investigation suite designed for Windows 10 and Windows 11. It eliminates all reliance on remote servers, web APIs, cloud report hosting, or user accounts.

```mermaid
flowchart TD
    subgraph HostSystem["Player Windows PC"]
        App["MinecraftSsForensics.exe"]
        ConsentUI["Consent Scope Gate (Sensitive Categories Opt-In)"]

        subgraph CoreEngine["Forensic Collection Engine"]
            Locator["Installation Locator (Vanilla, Prism, Modrinth, Lunar)"]
            Hasher["Streaming File Hasher (SHA-256, SHA-512, Murmur2)"]
            Archive["Safe Archive Inspector (ZipBomb Guard + Bytecode)"]
            Verifier["Multi-Platform Mod Verifier (Modrinth, Curse, GitHub)"]
            Policy["Mod Policy Engine (Authenticity vs Gameplay Policy)"]
            ProcScan["Process Scanner (javaw.exe, Modules, Authenticode)"]
            HistScan["Historical Evidence (Prefetch SCCA/MAM, BAM/DAM, PCA)"]
            RegScan["Registry Forensics (UserAssist 72-Byte FILETIME, RecentDocs UTF-16LE)"]
            UsbScan["USBSTOR Flash Device Enumeration + SetupAPI Log Correlation"]
            BrowserScan["Sensitive Cheat Domain Auditor (Opt-In SQLite WebKit Epoch)"]
            FileScan["Filesystem Staging (Multi-Volume $Recycle.Bin, Downloads, Temp)"]
        end

        subgraph OutputLayer["Sealed Export Subsystem"]
            Seal["SHA256-CANONICAL-V2 Cryptographic Report Seal"]
            JsonOut["Portable Forensic JSON (.json)"]
            HtmlOut["Self-Contained Interactive HTML (.html)"]
            MdOut["AI Diagnostic Markdown (.md)"]
        end
    end

    subgraph StaffReview["Staff Review Workflow"]
        StaffApp["MinecraftSsForensics.Viewer.exe (Staff Viewer)"]
        Browser["Standard Web Browser (Offline HTML)"]
    end

    App --> ConsentUI
    ConsentUI --> CoreEngine
    Locator --> CoreEngine
    Hasher --> Verifier
    Archive --> Verifier
    Verifier --> Policy
    ProcScan --> CoreEngine
    HistScan --> CoreEngine
    RegScan --> CoreEngine
    UsbScan --> CoreEngine
    BrowserScan --> CoreEngine
    FileScan --> CoreEngine

    CoreEngine --> Seal
    Seal --> JsonOut
    Seal --> HtmlOut
    Seal --> MdOut

    JsonOut -->|File Transfer via Discord / Ticket| StaffApp
    HtmlOut -->|Direct Double-Click| Browser
    StaffApp -->|Verify SHA-256 Seal & Inspect Evidence| StaffApp
```

---

## 2. Forensic Subsystems & Win32 Integration

1. **Authenticode Verification (`WinVerifyTrust`)**: Uses native P/Invoke with `WINTRUST_ACTION_GENERIC_VERIFY_V2` to check embedded PKCS#7 and catalog signatures, extracting subject names.
2. **Prefetch MAM Decompression (`RtlDecompressBufferEx`)**: Decompresses Windows 10/11 compressed prefetch files (`XPRESS_HUFF`), parsing SCCA format headers to extract run counts, execution timestamps, and loaded DLL modules.
3. **BAM/DAM Volume Path Translation (`QueryDosDevice`)**: Maps NT device paths (`\Device\HarddiskVolumeX`) to DOS drive letters (`C:\`, `D:\`).
4. **Recycle Bin Reconstruction**: Parses Version 1 and Version 2 `$I` index files across all fixed drives, recovering deleted filenames, deletion timestamps, and hashing paired `$R` payloads.
5. **Static Bytecode Constant Pool Parsing**: Analyzes Java class file constant pools in memory without execution, resolving method references (`Robot`, `cursor`, `packet`, `autoCrystal`) and `@Mixin` targets.
6. **Report Sealing (`SHA256-CANONICAL-V2`)**: Canonicalizes recursive JSON properties ordinally and computes a SHA-256 digest verified via constant-time comparison.

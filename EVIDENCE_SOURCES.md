# Evidence Sources Reference

This document provides a comprehensive technical reference for every forensic artifact source inspected by **Minecraft SS Forensics**.

---

## Evidence Sources Matrix

| Source | Target Path / Subsystem | Collection Method | Information Extracted | Confidence Impact | Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Active Processes** | Windows Process Subsystem (`Process.GetProcesses()`) | Shared read handles via Win32 APIs | Process Name, PID, Start Time, Parent PID, Authenticode Trust status, Working Set Memory, Redacted Command-Line | High (`0.90 - 1.00`) | Process may terminate prior to scan execution. |
| **Process Modules** | `javaw.exe` Virtual Memory Mappings | Win32 Toolhelp32 / `Process.Modules` | Loaded DLL paths, Base Addresses, Authenticode Signatures, Signer Certificates | High (`0.95 - 1.00`) | 32-bit to 64-bit inspection restrictions; requires elevation for protected system processes. |
| **Filesystem Mods** | Standard & Launcher Folders (`.minecraft`, Prism, Lunar, Badlion, Feather) | Multi-volume recursive directory walk | File size, Creation/Modification timestamps, SHA-256, SHA-512, Murmur2 hashes | High (`0.95 - 1.00`) | Symlinks and junction points are handled with bounded recursion depth. |
| **Recycle Bin** | `\$Recycle.Bin\{SID}\$I*` & `$R*` on all fixed drives | Direct binary parsing of Version 1 (Vista/7/8) and Version 2 (10/11) `$I` indexes | Original file path, original file size, precise deletion timestamp (`FILETIME`), SHA-256 hash of paired `$R` data | High (`0.90 - 1.00`) | Purged Recycle Bin or Shift+Delete bypasses `$I`/`$R` allocation. |
| **Windows Prefetch** | `C:\Windows\Prefetch\*.pf` | Binary SCCA parsing & `RtlDecompressBufferEx` (`XPRESS_HUFF`) | Execution count, up to 8 execution timestamps, executable hash, loaded DLLs | High (`0.95 - 1.00`) | Requires elevated privileges to read; disabled on some SSD optimizations or Windows Server. |
| **Background Activity Moderator (BAM/DAM)** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` | Registry key enumeration with `QueryDosDevice` volume path translation | Executable path, 8-byte `FILETIME` timestamp of last execution | High (`0.85 - 0.95`) | Records only the single latest execution timestamp per path. |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | Registry enumeration, ROT13 decryption, 72-byte binary payload parsing | Execution count (offset 4), Last execution timestamp (`FILETIME` at offset 60) | High (`0.85 - 0.95`) | Only records GUI executions launched via Windows Explorer. |
| **RecentDocs (MRU)** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Registry enumeration, UTF-16LE binary payload decoding | Recently accessed file paths, file extensions, access order | Medium (`0.70 - 0.85`) | User can manually clear Recent files history. |
| **USB History** | `SYSTEM\CurrentControlSet\Enum\USBSTOR` & `setupapi.dev.log` | Registry enumeration correlated with SetupAPI device log timestamps | Vendor ID, Product ID, Device Serial Number, Friendly Name, Last Connected Timestamp | High (`0.80 - 0.95`) | Logs device connection; cannot prove specific files executed from USB without prefetch correlation. |
| **Services & Drivers** | `SYSTEM\CurrentControlSet\Services`, Windows Event ID 7045 | Registry service enumeration + Event Log reverse stream | Service name, ImagePath, DisplayName, StartType, Event 7045 install time, Authenticode trust | High (`0.85 - 0.95`) | Hidden kernel-level drivers bypassing standard Service Manager require kernel inspection. |
| **Browser History** | Chromium SQLite `History` databases (Chrome, Edge, Brave, Opera) | Read-only copy of `History` + WAL/SHM to `%TEMP%`, parameterized SQLite query | Visited URL, Page Title, WebKit epoch timestamp (`FILETIME / 10`), visit count | High (`0.85 - 0.95`) | Strictly opt-in; filtered only for known cheat domains. Incognito browsing is not recorded. |
| **Static Bytecode** | JAR archives in mods or staging directories | In-memory ZIP stream reading & constant pool binary parsing | Method invocations (`Robot`, `Cursor`, `sendPacket`), Mixin targets, manifest attributes | High (`0.90 - 1.00`) | Advanced custom obfuscation or native JNI payloads require specialized decompilation. |

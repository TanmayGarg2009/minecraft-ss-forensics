# Technical Limitations & Evidentiary Boundaries

**Version:** 2.1.0-standalone  
**Standard:** Realistic Windows Forensic Disclosure

---

## 1. Fundamental Principle: No Guaranteed Detection

No software operating in Windows user mode can provide guaranteed 100% detection of advanced cheating, kernel-level tampering, or sophisticated anti-forensics. 

Server staff, referees, and players must understand what this application can prove, what it cannot prove, and the technical boundaries of user-mode investigation.

---

## 2. Technical Boundaries of User-Mode Scanning

### 1. Kernel-Level Bypasses & Rootkits (Ring 0 vs Ring 3)
- The scanner runs entirely in user mode (`Ring 3`).
- Cheats utilizing Bring Your Own Vulnerable Driver (BYOVD) or custom kernel drivers (`Ring 0`) can hide processes, unhook memory pages, or manipulate Direct Memory Access (DMA) beneath the visibility of user-mode Win32 and WMI APIs.
- The scanner audits registered services, driver signatures via `WinVerifyTrust`, and Event ID 7045, but cannot detect active rootkits that intercept kernel SSDT/IRP tables.

### 2. Physical Memory & Unmapped Code Execution
- The scanner inspects PEB loader tables (`Process.Modules`).
- Reflective DLL injection, manual PE mapping, or shellcode execution within `PAGE_EXECUTE_READWRITE` memory regions inside `javaw.exe` does not appear as a named DLL module in standard Windows APIs without kernel memory dumping or invasive thread suspension.

### 3. File System Anti-Forensics & Wiping
- If a player executes a low-level disk wiper, runs SDelete, or zeros unallocated clusters, historical file recovery is mathematically impossible.
- The scanner audits Windows Prefetch, BAM/DAM, UserAssist, and Recycle Bin indexes, but if these artifacts were deliberately purged prior to the match, the absence of an artifact cannot be treated as positive proof of cheating.

### 4. Non-Elevated (Standard User) Execution
- When run as a standard Windows user (without Administrator privileges):
  - Access to `C:\Windows\Prefetch` is restricted by Windows security permissions.
  - Access to `HKLM\SYSTEM\CurrentControlSet\Services\bam` may be restricted.
  - Command lines of processes running under other user accounts or elevated privileges cannot be read.
- The scanner transparently flags these checks as `UNAVAILABLE` or `SKIPPED` in `DiagnosticChecks`, rather than failing or inventing false evidence.

### 5. Multi-User & Shared Machines
- An artifact located in `Downloads` or `Desktop` proves possession on that user profile, but does not prove who was sitting at the keyboard or which family member downloaded the file.
- Staff must evaluate findings holistically alongside player statements and match timestamps.

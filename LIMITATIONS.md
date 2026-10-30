# Forensic Scope & Technical Limitations

Transparency is essential in forensic investigations. While **Minecraft SS Forensics** is comprehensive, certain evasion techniques and environmental conditions fall outside the capability of user-mode scanning.

---

## 1. User-Mode vs Kernel-Mode Boundaries

The scanner operates purely in **Windows User Mode** (Ring 3) without requiring kernel drivers (Ring 0):
- **Kernel-Level Hiding**: Advanced rootkits or Ring 0 hypervisors that hook Windows SSDT, direct kernel object manipulation (DKOM), or hidden process tables cannot be detected by user-mode APIs.
- **Direct Memory Injection**: If a cheat injected directly into memory and subsequently erased all disk traces, Prefetch records, and terminated prior to the scan, user-mode process enumeration cannot reconstruct the historical memory map.

---

## 2. Windows Environment Variations

1. **Prefetch Availability**:
   - Windows 10/11 typically enables Prefetch on standard installations.
   - On certain enterprise configurations, Windows Server editions, or systems where users manually set `EnablePrefetcher = 0` in the registry, prefetch history will be marked `NOT_AVAILABLE`.
2. **Elevated Privileges**:
   - When executed as a **Standard User**, the scanner cannot decompress files in `C:\Windows\Prefetch` or read low-level device configuration logs.
   - For complete prefetch and driver audits, running as **Administrator** is recommended.

---

## 3. Anti-Forensic Evasion Techniques

1. **Shift + Delete / Secure File Wiping**:
   - Files deleted using `Shift+Delete` or specialized shredding utilities bypass the Windows Recycle Bin and do not produce `$I` index records.
2. **Encrypted / Virtual Disks**:
   - Cheats stored inside unmounted VeraCrypt containers, BitLocker VHDs, or RAM disks that were unmounted prior to the scan cannot be inspected.
3. **Private In-House Obfuscation**:
   - The Static Bytecode Analyzer detects standard patterns (`Robot`, `glfwSetCursorPos`, `autoCrystal`, `sendPacket`).
   - Highly novel, custom JNI/native-loader cheats that decrypt bytecode purely at runtime cannot be fully classified by static constant-pool inspection alone.

---

## 4. Privacy Opt-Outs

- If a player exercises their right to uncheck **Sensitive Browser Audit**, web domain activity will not be present in the report and will be documented in the audit trail as `NOT_COLLECTED_BY_USER_CHOICE`. Staff must not treat opted-out categories as automatic evidence of guilt.

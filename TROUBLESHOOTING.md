# Troubleshooting & Frequently Asked Questions

This guide addresses common issues encountered by players running scans and staff reviewing reports.

---

## 1. Player Troubleshooting

### Q: Windows Defender / SmartScreen warns "Windows protected your PC"
**Reason**: The scanner is open-source software built by community developers and does not hold an expensive commercial EV (Extended Validation) code-signing certificate from Microsoft.  
**Resolution**:
1. Click **More info** on the SmartScreen dialog.
2. Click **Run anyway**.
3. You can verify the executable's SHA-256 hash against the release checksums published on GitHub before running.

### Q: Prefetch or Driver Audit is marked `NOT_AVAILABLE`
**Reason**: Windows restricts access to `C:\Windows\Prefetch` and low-level system event logs to administrative users.  
**Resolution**:
- Close the scanner.
- Right-click `MinecraftSsForensics.exe` and select **Run as Administrator**.
- Rerun the scan.

### Q: The scan hangs or takes a very long time
**Reason**: Deep directory scanning across multiple secondary or network drives with millions of files.  
**Resolution**:
- Ensure external network/backup drives are disconnected during the scan.
- Cancel the scan and select **Quick Scan Mode** for a focused audit of standard Minecraft directories.

---

## 2. Staff Troubleshooting

### Q: Viewer displays `⚠ TAMPER DETECTED: Report payload does not match cryptographic seal`
**Reason**: The report JSON file has been altered after it was generated. This happens when:
1. A player manually edited fields in the JSON to hide a detected cheat.
2. A text editor reformatted lines or modified timestamp precision.
3. The file was partially truncated or corrupted during transfer.  
**Action**: **Do not accept tampered reports**. Request that the player rerun the scan and send the unaltered file directly.

### Q: BAM shows device paths like `\Device\HarddiskVolume3\...`
**Reason**: Background Activity Moderator records volume identifiers rather than DOS drive letters.  
**Resolution**: The scanner automatically translates these paths to `C:\`, `D:\`, etc. via `QueryDosDevice`. If an unmapped volume appears, it indicates a removable drive or partition that has since been unmounted.

### Q: Mod is marked `UNKNOWN` but player claims it is legitimate
**Reason**: The mod was compiled locally, downloaded from an unofficial mirror, or represents a private guild build.  
**Action**:
- Check the **Bytecode Capabilities** tab in the viewer.
- If it contains no suspicious APIs (`Robot`, `cursor`, `packet`, `autoCrystal`), mark as approved for casual play or request the player provide the original source link.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

/// <summary>
/// Audits USB storage device connection history via USBSTOR registry and SetupAPI device installation logs.
/// Associates devices with their authentic connection timestamps and serial numbers.
/// </summary>
public class UsbHistoryScanner
{
    private static readonly Regex SetupApiSectionRegex = new(
        @"^>>>\s+\[Device Install .*? - (.*?)\]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SetupApiTimeRegex = new(
        @"^>>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public List<UsbDeviceItem> ScanUsbStorageDevices(out List<FindingRecord> findings)
    {
        var devices = new List<UsbDeviceItem>();
        findings = new List<FindingRecord>();

        if (!OperatingSystem.IsWindows())
            return devices;

        // Parse setupapi.dev.log timestamps first for fast correlation
        var setupApiTimestamps = ParseSetupApiLog();

        try
        {
            using var usbstor = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (usbstor == null) return devices;

            foreach (string deviceSubKey in usbstor.GetSubKeyNames())
            {
                using var devKey = usbstor.OpenSubKey(deviceSubKey);
                if (devKey == null) continue;

                foreach (string instanceKey in devKey.GetSubKeyNames())
                {
                    using var inst = devKey.OpenSubKey(instanceKey);
                    if (inst == null) continue;

                    string friendlyName = inst.GetValue("FriendlyName")?.ToString() ?? deviceSubKey;
                    string hardwareId = inst.GetValue("HardwareID") is string[] hids && hids.Length > 0 ? hids[0] : string.Empty;

                    // Correlate with SetupAPI log
                    DateTimeOffset? lastConnected = null;
                    foreach (var kvp in setupApiTimestamps)
                    {
                        if (kvp.Key.Contains(instanceKey, StringComparison.OrdinalIgnoreCase) ||
                            (!string.IsNullOrEmpty(hardwareId) && kvp.Key.Contains(hardwareId, StringComparison.OrdinalIgnoreCase)))
                        {
                            lastConnected = kvp.Value;
                            break;
                        }
                    }

                    var item = new UsbDeviceItem
                    {
                        DeviceName = friendlyName,
                        SerialNumber = instanceKey,
                        MountLocation = hardwareId,
                        LastConnectedTime = lastConnected
                    };

                    devices.Add(item);
                }
            }

            if (devices.Count > 0)
            {
                findings.Add(new FindingRecord
                {
                    RuleId = "INFO-USBSTOR-DEVICES",
                    DetectionName = $"USB Storage Devices Identified ({devices.Count} found)",
                    FindingTitle = $"USB Storage Devices Identified ({devices.Count} found)",
                    Category = FindingCategory.UsbArtifact,
                    EvidenceCategory = EvidenceCategory.Historical,
                    Classification = FindingClassification.Informational,
                    Severity = Severity.Informational,
                    EvidenceStrength = EvidenceStrength.Strong,
                    Confidence = ConfidenceLevel.Certain,
                    DetectionMethod = DetectionMethod.HistoricalArtifact,
                    EvidenceSource = "Registry (USBSTOR) & SetupAPI",
                    IsInScanWindow = false,
                    EvidenceClusterId = "CLUSTER-USB-HISTORY",
                    Interpretation = $"Enumerated {devices.Count} historically connected USB storage device(s) via Windows USBSTOR registry and SetupAPI logs.",
                    TechnicalExplanation = $"Enumerated {devices.Count} historically connected USB storage device(s) via Windows USBSTOR registry and SetupAPI logs.",
                    WhyItMatters = "In competitive screensharing, flash drives may be used to execute cheat programs without leaving permanent files on the main drive.",
                    AlternativeLegitimateExplanations = "Standard personal USB flash drives, backup drives, or external storage peripherals.",
                    WhatIsProven = "The enumerated USB storage devices were physically connected to this computer.",
                    WhatIsNotProven = "Does not prove a cheat was executed from the USB device without correlated Prefetch, BAM, or USN journal entries.",
                    Limitations = "Historical hardware connection records only. Does not prove software execution from USB.",
                    RecommendedReview = "Check drive letters and Prefetch records for executables launched from removable media."
                });
            }
        }
        catch { /* Fallback */ }

        return devices;
    }

    private static Dictionary<string, DateTimeOffset> ParseSetupApiLog()
    {
        var timestamps = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);

        try
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string logPath = Path.Combine(winDir, @"inf\setupapi.dev.log");

            if (!File.Exists(logPath)) return timestamps;

            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);

            string? currentDevice = null;
            string? line;

            while ((line = reader.ReadLine()) != null)
            {
                var matchSection = SetupApiSectionRegex.Match(line);
                if (matchSection.Success)
                {
                    currentDevice = matchSection.Groups[1].Value.Trim();
                    continue;
                }

                if (currentDevice != null)
                {
                    var matchTime = SetupApiTimeRegex.Match(line);
                    if (matchTime.Success && DateTimeOffset.TryParse(matchTime.Groups[1].Value, out var dt))
                    {
                        timestamps[currentDevice] = dt;
                        currentDevice = null;
                    }
                }
            }
        }
        catch { /* Non-fatal */ }

        return timestamps;
    }
}

using System;
using System.Collections.Generic;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

public class UsbHistoryScanner
{
    public List<UsbDeviceItem> ScanUsbStorageDevices(out List<FindingRecord> findings)
    {
        var devices = new List<UsbDeviceItem>();
        findings = new List<FindingRecord>();

        if (!OperatingSystem.IsWindows())
            return devices;

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

                    var item = new UsbDeviceItem
                    {
                        DeviceName = friendlyName,
                        SerialNumber = instanceKey,
                        MountLocation = hardwareId
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
                    Category = FindingCategory.UsbArtifact,
                    Classification = FindingClassification.Informational,
                    Severity = Severity.Informational,
                    Confidence = ConfidenceLevel.Certain,
                    EvidenceSource = "Registry (USBSTOR)",
                    TechnicalExplanation = $"Enumerated {devices.Count} historically connected USB storage device(s) via Windows USBSTOR registry.",
                    WhyItMatters = "In competitive screensharing, flash drives may be used to execute cheat programs without leaving permanent files on the main drive.",
                    AlternativeLegitimateExplanations = "Standard personal USB flash drives, backup drives, or external storage peripherals.",
                    WhatIsProven = "These USB storage hardware profiles were mounted to this system.",
                    WhatIsNotProven = "Does not prove a flash drive contained cheat software or was connected during Minecraft play.",
                    EvidenceStrengtheningFinding = "Prefetch or USN journal entries showing .exe execution directly from removable drive letters (E:, F:, etc.).",
                    EvidenceWeakeningFinding = "Drive has not been connected for weeks or months."
                });
            }
        }
        catch { /* Non-fatal access denial on restricted keys */ }

        return devices;
    }
}

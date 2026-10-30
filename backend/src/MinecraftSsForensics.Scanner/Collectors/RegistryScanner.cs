using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

public class RegistryScanner
{
    public List<RegistryEvidenceItem> ScanRegistryArtifacts(out List<FindingRecord> findings)
    {
        var records = new List<RegistryEvidenceItem>();
        findings = new List<FindingRecord>();

        if (!OperatingSystem.IsWindows())
            return records;

        try
        {
            ScanUserAssist(records, findings);
            ScanPcaStore(records, findings);
            ScanRunKeys(records, findings);
            ScanRecentDocs(records);
        }
        catch (Exception ex)
        {
            records.Add(new RegistryEvidenceItem
            {
                KeyPath = "RegistryScanError",
                ValueName = "Exception",
                ValueData = ex.Message,
                Significance = "Registry inspection encountered an error."
            });
        }

        return records;
    }

    private void ScanUserAssist(List<RegistryEvidenceItem> records, List<FindingRecord> findings)
    {
        try
        {
            using var userAssist = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (userAssist == null) return;

            foreach (string subKeyName in userAssist.GetSubKeyNames())
            {
                using var countKey = userAssist.OpenSubKey($@"{subKeyName}\Count");
                if (countKey == null) continue;

                foreach (string valName in countKey.GetValueNames())
                {
                    string decodedName = Rot13(valName);
                    string lower = decodedName.ToLowerInvariant();

                    var sig = CheatDetectionDatabase.MatchFileName(decodedName);
                    bool isCheatMatch = sig != null;

                    if (isCheatMatch || lower.Contains("minecraft") || lower.Contains("javaw") || lower.Contains("cheat") || lower.Contains("clicker"))
                    {
                        records.Add(new RegistryEvidenceItem
                        {
                            KeyPath = $@"HKCU\...\UserAssist\{subKeyName}\Count",
                            ValueName = decodedName,
                            ValueData = "GUI Execution Record",
                            Significance = isCheatMatch ? $"UserAssist trace matching known cheat tool: {sig!.Name}" : "Standard GUI execution trace"
                        });

                        if (isCheatMatch)
                        {
                            findings.Add(new FindingRecord
                            {
                                RuleId = "REG-USERASSIST-CHEAT",
                                DetectionName = $"UserAssist Execution Record: {sig!.Name}",
                                Category = FindingCategory.RegistryArtifact,
                                Classification = FindingClassification.StrongIndicator,
                                Severity = Severity.High,
                                Confidence = ConfidenceLevel.High,
                                EvidenceSource = "Registry (UserAssist)",
                                FilePath = decodedName,
                                TechnicalExplanation = $"Decoded UserAssist ROT13 registry entry '{decodedName}' matches known cheat identifier '{sig.Name}'. UserAssist tracks GUI application execution through Windows Explorer.",
                                WhyItMatters = "Proves this executable was launched on this Windows user account via the graphical desktop interface.",
                                AlternativeLegitimateExplanations = "Does not prove execution during the competitive Minecraft match session unless correlated with session timestamps.",
                                WhatIsProven = "The application was executed via Windows Explorer interface on this machine.",
                                WhatIsNotProven = "Does not prove the cheat was active during the specific Minecraft match under investigation.",
                                EvidenceStrengtheningFinding = "Prefetch (.pf) or BAM entry with timestamp matching Minecraft gameplay.",
                                EvidenceWeakeningFinding = "File creation/execution timestamp is months old with zero recent activity."
                            });
                        }
                    }
                }
            }
        }
        catch { /* Non-fatal registry read restriction */ }
    }

    private void ScanPcaStore(List<RegistryEvidenceItem> records, List<FindingRecord> findings)
    {
        try
        {
            using var pcaKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store");
            if (pcaKey == null) return;

            foreach (string valName in pcaKey.GetValueNames())
            {
                var sig = CheatDetectionDatabase.MatchFileName(valName);
                if (sig != null)
                {
                    records.Add(new RegistryEvidenceItem
                    {
                        KeyPath = @"HKCU\...\AppCompatFlags\Compatibility Assistant\Store",
                        ValueName = valName,
                        ValueData = "PCA Interaction Trace",
                        Significance = $"Program Compatibility Assistant record matching {sig.Name}"
                    });

                    findings.Add(new FindingRecord
                    {
                        RuleId = "REG-PCA-CHEAT",
                        DetectionName = $"PCA Execution Artifact: {sig.Name}",
                        Category = FindingCategory.RegistryArtifact,
                        Classification = FindingClassification.StrongIndicator,
                        Severity = Severity.High,
                        Confidence = ConfidenceLevel.High,
                        EvidenceSource = "Registry (PcaSvc Store)",
                        FilePath = valName,
                        TechnicalExplanation = $"Windows Program Compatibility Assistant (PcaSvc) logged execution telemetry for '{valName}'. PcaSvc records executables that run on the system.",
                        WhyItMatters = "Confirms historical execution of an executable recognized in the cheat detection database.",
                        AlternativeLegitimateExplanations = "User may have downloaded and tested the tool in singleplayer or outside the competition window.",
                        WhatIsProven = "The program was executed on this Windows installation.",
                        WhatIsNotProven = "Does not prove injection into javaw.exe during match play.",
                        EvidenceStrengtheningFinding = "USN Journal deletion record immediately following match conclusion.",
                        EvidenceWeakeningFinding = "Execution occurred outside match timeframe."
                    });
                }
            }
        }
        catch { /* Non-fatal */ }
    }

    private void ScanRunKeys(List<RegistryEvidenceItem> records, List<FindingRecord> findings)
    {
        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                foreach (string valName in runKey.GetValueNames())
                {
                    string data = runKey.GetValue(valName)?.ToString() ?? string.Empty;
                    records.Add(new RegistryEvidenceItem
                    {
                        KeyPath = @"HKCU\...\Windows\CurrentVersion\Run",
                        ValueName = valName,
                        ValueData = data,
                        Significance = "Current user autostart entry"
                    });
                }
            }
        }
        catch { /* Non-fatal */ }
    }

    private void ScanRecentDocs(List<RegistryEvidenceItem> records)
    {
        try
        {
            using var recentKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.jar");
            if (recentKey != null)
            {
                foreach (string valName in recentKey.GetValueNames())
                {
                    if (valName != "MRUListEx")
                    {
                        records.Add(new RegistryEvidenceItem
                        {
                            KeyPath = @"HKCU\...\Explorer\RecentDocs\.jar",
                            ValueName = valName,
                            ValueData = "Recent JAR Document Access",
                            Significance = "Recent JAR file interaction"
                        });
                    }
                }
            }
        }
        catch { /* Non-fatal */ }
    }

    private static string Rot13(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
        }
        return new string(chars);
    }
}

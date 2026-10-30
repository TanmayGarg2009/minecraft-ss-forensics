using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

/// <summary>
/// Scans critical Windows Registry execution hives:
/// UserAssist (ROT13-decoded GUI execution records with execution count and last run timestamp),
/// Program Compatibility Assistant (PcaSvc), Run/RunOnce autostart keys, and RecentDocs MRU lists.
/// </summary>
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
            ScanPcaSvc(records, findings);
            ScanRunKeys(records);
            ScanRecentDocs(records);
        }
        catch { /* Fallback */ }

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
                try
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
                            int runCount = 0;
                            DateTimeOffset? lastExecution = null;

                            // In Windows 7/8/10/11: UserAssist Count value is a 72-byte binary structure
                            if (countKey.GetValue(valName) is byte[] bytes && bytes.Length >= 68)
                            {
                                runCount = BitConverter.ToInt32(bytes, 4);
                                long fileTime = BitConverter.ToInt64(bytes, 60);
                                if (fileTime > 0)
                                {
                                    try { lastExecution = DateTimeOffset.FromFileTime(fileTime); } catch { }
                                }
                            }

                            string valDataDesc = $"Run Count: {runCount}" + (lastExecution.HasValue ? $", Last Executed: {lastExecution:yyyy-MM-dd HH:mm:ss} UTC" : "");

                            records.Add(new RegistryEvidenceItem
                            {
                                KeyPath = $@"HKCU\...\UserAssist\{subKeyName}\Count",
                                ValueName = decodedName,
                                ValueData = valDataDesc,
                                Significance = isCheatMatch ? $"UserAssist trace matching known cheat tool: {sig!.Name}" : "Standard GUI execution trace"
                            });

                            if (isCheatMatch)
                            {
                                string clusterId = "CLUSTER-" + sig!.Name.ToLowerInvariant().Replace(" ", "-");
                                findings.Add(new FindingRecord
                                {
                                    RuleId = "REG-USERASSIST-CHEAT",
                                    DetectionName = $"UserAssist Execution Record: {sig.Name}",
                                    FindingTitle = $"UserAssist Execution Record: {sig.Name}",
                                    Category = FindingCategory.RegistryArtifact,
                                    EvidenceCategory = EvidenceCategory.Historical,
                                    Classification = FindingClassification.StrongIndicator,
                                    Severity = Severity.Medium,
                                    EvidenceStrength = EvidenceStrength.Strong,
                                    Confidence = ConfidenceLevel.High,
                                    DetectionMethod = DetectionMethod.HistoricalArtifact,
                                    SoftwareState = SoftwareEvidenceState.SoftwareExecuted,
                                    SoftwareStateDescription = $"GUI execution artifact recorded in UserAssist (Run count: {runCount}).",
                                    EvidenceSource = "Registry (UserAssist)",
                                    FilePath = decodedName,
                                    ObservedTimestamp = lastExecution,
                                    IsInScanWindow = false,
                                    EvidenceClusterId = clusterId,
                                    Interpretation = $"Decoded UserAssist ROT13 registry entry '{decodedName}' proves GUI launch of '{sig.Name}'. Run Count: {runCount}." + (lastExecution.HasValue ? $" Last Executed: {lastExecution:yyyy-MM-dd HH:mm:ss} UTC." : ""),
                                    TechnicalExplanation = $"Decoded UserAssist ROT13 registry entry '{decodedName}' matches known cheat identifier '{sig.Name}'. " +
                                        $"Recorded Run Count: {runCount}. " + (lastExecution.HasValue ? $"Last Executed: {lastExecution:yyyy-MM-dd HH:mm:ss} UTC." : ""),
                                    WhyItMatters = "Proves this executable was launched on this Windows user account via the graphical desktop interface.",
                                    AlternativeLegitimateExplanations = "Does not prove execution during the competitive Minecraft match session unless correlated with session timestamps.",
                                    WhatIsProven = "The application was executed via Windows Explorer interface on this machine.",
                                    WhatIsNotProven = "Does not prove the cheat was active during the specific Minecraft match under investigation.",
                                    Limitations = "Historical execution record. Proves past launch on Windows; does not prove current session execution.",
                                    RecommendedReview = "Cross-reference execution timestamp with server match logs and game process start time.",
                                    EvidenceStrengtheningFinding = "Prefetch (.pf) or BAM entry with timestamp matching Minecraft gameplay.",
                                    EvidenceWeakeningFinding = "File creation/execution timestamp is months old with zero recent activity."
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { /* Restricted subkey */ }
                catch (Exception) { /* Skip subkey */ }
            }
        }
        catch { /* Fallback */ }
    }

    private void ScanPcaSvc(List<RegistryEvidenceItem> records, List<FindingRecord> findings)
    {
        try
        {
            string[] pcaPaths =
            {
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
            };

            foreach (var path in pcaPaths)
            {
                using var key = Registry.CurrentUser.OpenSubKey(path);
                if (key == null) continue;

                foreach (string valName in key.GetValueNames())
                {
                    string lower = valName.ToLowerInvariant();
                    var sig = CheatDetectionDatabase.MatchFileName(valName);

                    if (sig != null || lower.Contains("cheat") || lower.Contains("autoclicker") || lower.Contains("doomsday") || lower.Contains("vape"))
                    {
                        records.Add(new RegistryEvidenceItem
                        {
                            KeyPath = $@"HKCU\{path}",
                            ValueName = valName,
                            ValueData = "Program Compatibility Assistant Execution Record",
                            Significance = sig != null ? $"PCA trace matching cheat: {sig.Name}" : "Suspicious executable PCA trace"
                        });

                        if (sig != null)
                        {
                            string clusterId = "CLUSTER-" + sig.Name.ToLowerInvariant().Replace(" ", "-");
                            findings.Add(new FindingRecord
                            {
                                RuleId = "REG-PCA-CHEAT",
                                DetectionName = $"Program Compatibility Record: {sig.Name}",
                                FindingTitle = $"Program Compatibility Record: {sig.Name}",
                                Category = FindingCategory.RegistryArtifact,
                                EvidenceCategory = EvidenceCategory.Historical,
                                Classification = FindingClassification.StrongIndicator,
                                Severity = Severity.Medium,
                                EvidenceStrength = EvidenceStrength.Strong,
                                Confidence = ConfidenceLevel.High,
                                DetectionMethod = DetectionMethod.HistoricalArtifact,
                                SoftwareState = SoftwareEvidenceState.SoftwareExecuted,
                                SoftwareStateDescription = "Recorded in Program Compatibility Assistant execution hive.",
                                EvidenceSource = "Registry (PcaSvc)",
                                FilePath = valName,
                                IsInScanWindow = false,
                                EvidenceClusterId = clusterId,
                                Interpretation = $"Program Compatibility Assistant recorded historical execution of known cheat '{sig.Name}' at '{valName}'.",
                                TechnicalExplanation = $"Program Compatibility Assistant recorded execution of known cheat '{sig.Name}' at '{valName}'.",
                                WhyItMatters = "PCA persists execution tracking even if files are deleted or moved.",
                                AlternativeLegitimateExplanations = "Historical artifact prior to server registration.",
                                Limitations = "PCA proves historical execution on the operating system. Does not prove execution in the active session.",
                                RecommendedReview = "Cross-reference with BAM/DAM and Prefetch timestamps."
                            });
                        }
                    }
                }
            }
        }
        catch { /* Fallback */ }
    }

    private void ScanRunKeys(List<RegistryEvidenceItem> records)
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
                        string fileName = valName;
                        if (recentKey.GetValue(valName) is byte[] bytes && bytes.Length > 2)
                        {
                            // In RecentDocs, the binary data begins with a UTF-16LE null-terminated filename
                            string decoded = Encoding.Unicode.GetString(bytes);
                            int nullIdx = decoded.IndexOf('\0');
                            if (nullIdx > 0)
                            {
                                fileName = decoded[..nullIdx];
                            }
                        }

                        records.Add(new RegistryEvidenceItem
                        {
                            KeyPath = @"HKCU\...\Explorer\RecentDocs\.jar",
                            ValueName = valName,
                            ValueData = fileName,
                            Significance = $"Recent JAR file interaction: {fileName}"
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

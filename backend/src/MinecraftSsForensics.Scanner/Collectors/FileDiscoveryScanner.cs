using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

/// <summary>
/// Fast file discovery auditor inspecting common download and staging directories
/// (Downloads, Desktop, %TEMP%, and $Recycle.Bin) for cheat binaries and renamed JARs.
/// </summary>
public class FileDiscoveryScanner
{
    private readonly IFileHasher _hasher;

    public FileDiscoveryScanner(IFileHasher? hasher = null)
    {
        _hasher = hasher ?? new StreamingFileHasher();
    }

    public List<DiscoveredFileItem> DiscoverFiles(out List<FindingRecord> findings)
    {
        var items = new List<DiscoveredFileItem>();
        findings = new List<FindingRecord>();

        var targetFolders = new List<string>();

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(userProfile))
        {
            string downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) targetFolders.Add(downloads);

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop)) targetFolders.Add(desktop);
        }

        string temp = Path.GetTempPath();
        if (Directory.Exists(temp)) targetFolders.Add(temp);

        foreach (var folder in targetFolders)
        {
            try
            {
                ScanDirectory(folder, items, findings, maxDepth: 2);
            }
            catch { /* Permission boundaries */ }
        }

        // Check Recycle Bin
        ScanRecycleBin(items, findings);

        return items;
    }

    private void ScanDirectory(string dirPath, List<DiscoveredFileItem> items, List<FindingRecord> findings, int maxDepth)
    {
        if (maxDepth < 0 || !Directory.Exists(dirPath)) return;

        try
        {
            var dirInfo = new DirectoryInfo(dirPath);
            foreach (var file in dirInfo.GetFiles("*.*", SearchOption.TopDirectoryOnly))
            {
                string ext = file.Extension.ToLowerInvariant();
                if (ext != ".jar" && ext != ".exe" && ext != ".dll") continue;

                var sig = CheatDetectionDatabase.MatchFileName(file.Name);
                if (sig != null)
                {
                    string sha256 = string.Empty;
                    try
                    {
                        using var stream = File.OpenRead(file.FullName);
                        byte[] hashBytes = SHA256.HashData(stream);
                        sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
                    }
                    catch { /* Inaccessible file */ }

                    var item = new DiscoveredFileItem
                    {
                        FileName = file.Name,
                        FilePath = file.FullName,
                        FileSizeBytes = file.Length,
                        Sha256 = sha256,
                        LastModified = file.LastWriteTimeUtc,
                        SuspicionReason = $"Matched known cheat file pattern: {sig.Name}"
                    };
                    items.Add(item);

                    findings.Add(new FindingRecord
                    {
                        RuleId = "FILE-CHEAT-NAME-MATCH",
                        DetectionName = $"Known Cheat Artifact on Disk: {sig.Name}",
                        Category = FindingCategory.CheatArtifact,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.High,
                        Confidence = ConfidenceLevel.High,
                        EvidenceSource = "Filesystem Discovery",
                        FilePath = file.FullName,
                        FileSha256 = sha256,
                        FileSizeBytes = file.Length,
                        ObservedTimestamp = file.LastWriteTimeUtc,
                        TechnicalExplanation = $"File '{file.Name}' in directory '{dirPath}' directly matches known cheat signature '{sig.Name}'. SHA-256: {sha256}.",
                        WhyItMatters = "Presence of known cheat executables on the player's computer indicates possession and potential unauthorized use.",
                        AlternativeLegitimateExplanations = "File may have been downloaded for review, testing, or unused on another game server.",
                        WhatIsProven = "The file is physically present in the player's file system.",
                        WhatIsNotProven = "Does not prove the cheat was active or running during the competitive match without process or execution logs.",
                        EvidenceStrengtheningFinding = "Prefetch or BAM execution timestamp during the match timeframe.",
                        EvidenceWeakeningFinding = "File has never been executed (no Prefetch / BAM records) and last modified date is months old."
                    });
                }
            }
        }
        catch { /* Non-fatal */ }
    }

    private void ScanRecycleBin(List<DiscoveredFileItem> items, List<FindingRecord> findings)
    {
        try
        {
            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            string recycleBinPath = Path.Combine(systemDrive, "$Recycle.Bin");

            if (Directory.Exists(recycleBinPath))
            {
                var dirInfo = new DirectoryInfo(recycleBinPath);
                foreach (var file in dirInfo.GetFiles("*.*", SearchOption.AllDirectories))
                {
                    string ext = file.Extension.ToLowerInvariant();
                    if (ext == ".jar" || ext == ".exe")
                    {
                        var sig = CheatDetectionDatabase.MatchFileName(file.Name);
                        if (sig != null)
                        {
                            var item = new DiscoveredFileItem
                            {
                                FileName = file.Name,
                                FilePath = file.FullName,
                                FileSizeBytes = file.Length,
                                LastModified = file.LastWriteTimeUtc,
                                SuspicionReason = $"Deleted cheat artifact discovered in Recycle Bin: {sig.Name}"
                            };
                            items.Add(item);

                            findings.Add(new FindingRecord
                            {
                                RuleId = "RECYCLE-BIN-CHEAT-DELETED",
                                DetectionName = $"Cheat Artifact Found in Recycle Bin: {sig.Name}",
                                Category = FindingCategory.FileDeletion,
                                Classification = FindingClassification.ConfirmedCheatArtifact,
                                Severity = Severity.High,
                                Confidence = ConfidenceLevel.Certain,
                                EvidenceSource = "Recycle Bin ($Recycle.Bin)",
                                FilePath = file.FullName,
                                ObservedTimestamp = file.LastWriteTimeUtc,
                                TechnicalExplanation = $"Discovered deleted file '{file.Name}' in $Recycle.Bin matching known cheat signature '{sig.Name}'.",
                                WhyItMatters = "Players often delete cheat files immediately before or during an investigation to hide evidence.",
                                AlternativeLegitimateExplanations = "Player may have cleaned up old files days or weeks prior.",
                                WhatIsProven = "The cheat file was moved to the Recycle Bin on this computer.",
                                WhatIsNotProven = "Does not prove exact time of deletion unless correlated with USN Journal or Recycle Bin metadata.",
                                EvidenceStrengtheningFinding = "USN Journal entry showing file deletion within minutes of match conclusion or screenshare request.",
                                EvidenceWeakeningFinding = "Deletion occurred well before the match session."
                            });
                        }
                    }
                }
            }
        }
        catch { /* Non-fatal */ }
    }
}

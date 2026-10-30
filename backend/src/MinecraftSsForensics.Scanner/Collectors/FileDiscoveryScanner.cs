using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Collectors;

public class RecycleBinMetadata
{
    public long OriginalSize { get; set; }
    public DateTimeOffset DeletionTimestamp { get; set; }
    public string OriginalFilePath { get; set; } = string.Empty;
    public string OriginalFileName => Path.GetFileName(OriginalFilePath);
    public string DataFilePath { get; set; } = string.Empty;
    public string MetadataFilePath { get; set; } = string.Empty;
}

/// <summary>
/// Fast file discovery auditor inspecting common download and staging directories
/// (Downloads, Desktop, %TEMP%, and multi-volume $Recycle.Bin) for cheat binaries and renamed JARs.
/// Performs genuine directory recursion up to maxDepth and parses Windows $I/$R Recycle Bin metadata.
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
                ScanDirectoryRecursive(folder, items, findings, currentDepth: 0, maxDepth: 2);
            }
            catch { /* Permission boundaries */ }
        }

        // Check Recycle Bin across all fixed drives
        ScanRecycleBin(items, findings);

        return items;
    }

    private void ScanDirectoryRecursive(string currentDir, List<DiscoveredFileItem> items, List<FindingRecord> findings, int currentDepth, int maxDepth)
    {
        if (currentDepth > maxDepth || !Directory.Exists(currentDir)) return;

        try
        {
            var dirInfo = new DirectoryInfo(currentDir);
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
                        using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
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

                    string clusterId = "CLUSTER-" + (!string.IsNullOrEmpty(sha256) ? sha256[..Math.Min(12, sha256.Length)] : sig.Name.ToLowerInvariant().Replace(" ", "-"));

                    findings.Add(new FindingRecord
                    {
                        RuleId = "FILE-CHEAT-NAME-MATCH",
                        DetectionName = $"Known Cheat Artifact on Disk: {sig.Name}",
                        FindingTitle = $"Known Cheat Artifact on Disk: {sig.Name}",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.Disk,
                        Classification = FindingClassification.ConfirmedCheatArtifact,
                        Severity = Severity.Medium,
                        EvidenceStrength = EvidenceStrength.Strong,
                        Confidence = ConfidenceLevel.Certain,
                        DetectionMethod = DetectionMethod.ExactSignature,
                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                        SoftwareStateDescription = $"Physical file present on disk in '{dirInfo.FullName}'.",
                        EvidenceSource = $"File System ({dirInfo.Name})",
                        FilePath = file.FullName,
                        FileSha256 = sha256,
                        FileSizeBytes = file.Length,
                        ObservedTimestamp = file.LastWriteTimeUtc,
                        IsInScanWindow = false,
                        EvidenceClusterId = clusterId,
                        Interpretation = $"A file matching known cheat signature '{sig.Name}' is physically stored on disk in '{dirInfo.FullName}'.",
                        TechnicalExplanation = $"File '{file.Name}' in '{dirInfo.FullName}' matches known cheat signature '{sig.Name}'. Description: {sig.Description}",
                        WhyItMatters = "Known cheat executables and modified client loaders indicate possession of prohibited advantage software.",
                        AlternativeLegitimateExplanations = "File may have been downloaded for review, testing, joke, or unused on another game server.",
                        WhatIsProven = "The file is physically present in the player's file system.",
                        WhatIsNotProven = "Does not prove the cheat was installed into Minecraft, launched, or active during the competitive match without process or execution logs.",
                        Limitations = "File presence on disk establishes physical possession only. It does NOT establish that the software executed or interacted with Minecraft.",
                        RecommendedReview = "Review running processes, loaded modules, and historical execution artifacts (Prefetch/BAM) to establish whether runtime activity occurred.",
                        EvidenceStrengtheningFinding = "Prefetch or BAM execution timestamp during the match timeframe.",
                        EvidenceWeakeningFinding = "File has never been executed (no Prefetch / BAM records) and last modified date is old."
                    });
                }
            }

            if (currentDepth < maxDepth)
            {
                foreach (var subDir in dirInfo.GetDirectories())
                {
                    // Avoid infinite symlink recursion
                    if ((subDir.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    ScanDirectoryRecursive(subDir.FullName, items, findings, currentDepth + 1, maxDepth);
                }
            }
        }
        catch { /* Non-fatal directory access restriction */ }
    }

    private void ScanRecycleBin(List<DiscoveredFileItem> items, List<FindingRecord> findings)
    {
        IEnumerable<DriveInfo> drives;
        try
        {
            drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
        }
        catch
        {
            drives = new[] { new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\") };
        }

        foreach (var drive in drives)
        {
            try
            {
                string recycleBinPath = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                if (!Directory.Exists(recycleBinPath)) continue;

                var binDir = new DirectoryInfo(recycleBinPath);
                foreach (var userDir in binDir.GetDirectories())
                {
                    try
                    {
                        foreach (var iFile in userDir.GetFiles("$I*", SearchOption.AllDirectories))
                        {
                            var meta = ParseIndexFile(iFile.FullName);
                            if (meta == null || string.IsNullOrWhiteSpace(meta.OriginalFileName)) continue;

                            string ext = Path.GetExtension(meta.OriginalFileName).ToLowerInvariant();
                            if (ext != ".jar" && ext != ".exe" && ext != ".dll") continue;

                            var sig = CheatDetectionDatabase.MatchFileName(meta.OriginalFileName);
                            if (sig != null)
                            {
                                string sha256 = string.Empty;
                                long fileSize = meta.OriginalSize;

                                if (File.Exists(meta.DataFilePath))
                                {
                                    try
                                    {
                                        using var stream = new FileStream(meta.DataFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                                        byte[] hashBytes = SHA256.HashData(stream);
                                        sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
                                        fileSize = stream.Length;
                                    }
                                    catch { /* Best effort file read */ }
                                }

                                var item = new DiscoveredFileItem
                                {
                                    FileName = meta.OriginalFileName,
                                    FilePath = meta.OriginalFilePath,
                                    FileSizeBytes = fileSize,
                                    Sha256 = sha256,
                                    LastModified = meta.DeletionTimestamp,
                                    SuspicionReason = $"Deleted cheat artifact recovered from Recycle Bin: {sig.Name}"
                                };
                                items.Add(item);

                                string recycleClusterId = "CLUSTER-" + (!string.IsNullOrEmpty(sha256) ? sha256[..Math.Min(12, sha256.Length)] : sig.Name.ToLowerInvariant().Replace(" ", "-"));

                                findings.Add(new FindingRecord
                                {
                                    RuleId = "RECYCLE-BIN-CHEAT-DELETED",
                                    DetectionName = $"Cheat Artifact Recovered from Recycle Bin: {sig.Name}",
                                    FindingTitle = $"Cheat Artifact Recovered from Recycle Bin: {sig.Name}",
                                    Category = FindingCategory.FileDeletion,
                                    EvidenceCategory = EvidenceCategory.Disk,
                                    Classification = FindingClassification.ConfirmedCheatArtifact,
                                    Severity = Severity.Medium,
                                    EvidenceStrength = EvidenceStrength.Strong,
                                    Confidence = ConfidenceLevel.Certain,
                                    DetectionMethod = DetectionMethod.ExactSignature,
                                    SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                                    SoftwareStateDescription = "Deleted cheat file metadata recovered from $Recycle.Bin.",
                                    EvidenceSource = $"Recycle Bin ({drive.Name.TrimEnd('\\')})",
                                    FilePath = meta.OriginalFilePath,
                                    FileSha256 = sha256,
                                    FileSizeBytes = fileSize,
                                    ObservedTimestamp = meta.DeletionTimestamp,
                                    IsInScanWindow = false,
                                    EvidenceClusterId = recycleClusterId,
                                    Interpretation = $"A deleted file matching known cheat signature '{sig.Name}' was discovered in $Recycle.Bin on drive {drive.Name.TrimEnd('\\')}.",
                                    TechnicalExplanation = $"Recovered deleted cheat artifact from $Recycle.Bin metadata index '{iFile.Name}'. " +
                                        $"Original Path: '{meta.OriginalFilePath}'. Exact Deletion Timestamp: {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC. " +
                                        (File.Exists(meta.DataFilePath) ? "Content payload ($R file) is preserved on disk." : "Data payload was purged."),
                                    WhyItMatters = "Players often delete cheat files immediately before or during an investigation to hide evidence.",
                                    AlternativeLegitimateExplanations = "Player may have cleaned up old files days or weeks prior.",
                                    WhatIsProven = $"The file '{meta.OriginalFileName}' was deleted to the Recycle Bin on volume {drive.Name.TrimEnd('\\')} at {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC.",
                                    WhatIsNotProven = "Does not prove the cheat was active during the match unless deletion timestamp closely correlates with the match timeframe.",
                                    Limitations = "Presence in Recycle Bin confirms deletion of the file on disk. Does not establish runtime injection into Minecraft without active process or session memory evidence.",
                                    RecommendedReview = "Review Prefetch and BAM execution records to check if execution occurred prior to deletion.",
                                    EvidenceStrengtheningFinding = "Prefetch or BAM execution timestamp shortly before deletion.",
                                    EvidenceWeakeningFinding = "Deletion occurred well before the match session."
                                });
                            }
                        }
                    }
                    catch { /* Restricted user SID directory */ }
                }
            }
            catch { /* Non-fatal volume error */ }
        }
    }

    /// <summary>
    /// Parses a Windows $I Recycle Bin metadata index file.
    /// Supports both Version 1 (Windows Vista/7/8) and Version 2 (Windows 10/11) formats.
    /// </summary>
    public static RecycleBinMetadata? ParseIndexFile(string iFilePath)
    {
        if (string.IsNullOrWhiteSpace(iFilePath) || !File.Exists(iFilePath)) return null;

        try
        {
            byte[] bytes = File.ReadAllBytes(iFilePath);
            if (bytes.Length < 28) return null;

            long version = BitConverter.ToInt64(bytes, 0);
            long originalSize = BitConverter.ToInt64(bytes, 8);
            long fileTime = BitConverter.ToInt64(bytes, 16);

            DateTimeOffset deletionTime;
            try
            {
                deletionTime = fileTime > 0 ? DateTimeOffset.FromFileTime(fileTime) : DateTimeOffset.MinValue;
            }
            catch
            {
                deletionTime = DateTimeOffset.MinValue;
            }

            string originalPath;
            if (version == 2 && bytes.Length >= 28)
            {
                // Windows 10/11: Offset 24 is character count (int32), followed by UTF-16LE characters
                int charCount = BitConverter.ToInt32(bytes, 24);
                int byteLength = charCount * 2;
                if (28 + byteLength <= bytes.Length)
                {
                    originalPath = Encoding.Unicode.GetString(bytes, 28, byteLength).TrimEnd('\0');
                }
                else
                {
                    originalPath = Encoding.Unicode.GetString(bytes, 28, bytes.Length - 28).TrimEnd('\0');
                }
            }
            else
            {
                // Windows Vista/7/8: Offset 24 contains fixed 520 bytes (260 WCHARs)
                originalPath = Encoding.Unicode.GetString(bytes, 24, Math.Min(520, bytes.Length - 24)).TrimEnd('\0');
            }

            int nullIdx = originalPath.IndexOf('\0');
            if (nullIdx >= 0) originalPath = originalPath[..nullIdx];

            string dir = Path.GetDirectoryName(iFilePath) ?? string.Empty;
            string fileName = Path.GetFileName(iFilePath);
            string dataFileName = "$R" + fileName[2..];
            string dataFilePath = Path.Combine(dir, dataFileName);

            return new RecycleBinMetadata
            {
                MetadataFilePath = iFilePath,
                DataFilePath = dataFilePath,
                OriginalSize = originalSize,
                DeletionTimestamp = deletionTime,
                OriginalFilePath = originalPath
            };
        }
        catch
        {
            return null;
        }
    }
}

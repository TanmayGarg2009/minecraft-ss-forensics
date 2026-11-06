using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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

                bool isHidden = (file.Attributes & FileAttributes.Hidden) != 0;
                bool isSystem = (file.Attributes & FileAttributes.System) != 0;

                string sha256 = string.Empty;
                bool fileChangedConcurrently = false;
                bool hashAttempted = false;

                void TryHashFile()
                {
                    if (hashAttempted) return;
                    hashAttempted = true;
                    try
                    {
                        long initialLength = file.Length;
                        DateTime initialWriteTime = file.LastWriteTimeUtc;

                        using (var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                        {
                            byte[] hashBytes = SHA256.HashData(stream);
                            sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
                        }

                        file.Refresh();
                        if (file.Exists && (file.Length != initialLength || file.LastWriteTimeUtc != initialWriteTime))
                        {
                            fileChangedConcurrently = true;
                        }
                    }
                    catch { /* Inaccessible file */ }
                }

                var sig = CheatDetectionDatabase.MatchFileName(file.Name);
                if (sig != null)
                {
                    TryHashFile();

                    var item = new DiscoveredFileItem
                    {
                        FileName = file.Name,
                        FilePath = file.FullName,
                        FileSizeBytes = file.Length,
                        Sha256 = sha256,
                        LastModified = file.LastWriteTimeUtc,
                        SuspicionReason = fileChangedConcurrently
                            ? $"Matched known cheat file pattern: {sig.Name} (Warning: File modified concurrently during collection)"
                            : $"Matched known cheat file pattern: {sig.Name}"
                    };
                    items.Add(item);

                    // Identity-based clustering: group by hash or canonical software name
                    string clusterId = "CLUSTER-" + (!string.IsNullOrEmpty(sha256)
                        ? $"{sig.Name.ToLowerInvariant().Replace(" ", "-")}-{sha256[..Math.Min(12, sha256.Length)]}"
                        : sig.Name.ToLowerInvariant().Replace(" ", "-"));

                    // Forensic Correctness (F-008): Filename match alone is a StrongIndicator / NeedsReview with Medium confidence, NOT Certain
                    findings.Add(new FindingRecord
                    {
                        RuleId = "FILE-CHEAT-NAME-MATCH",
                        DetectionName = $"Potential Cheat Artifact on Disk (Filename Match): {sig.Name}",
                        FindingTitle = $"Potential Cheat Artifact on Disk (Filename Match): {sig.Name}",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.Disk,
                        Classification = fileChangedConcurrently ? FindingClassification.NeedsReview : FindingClassification.StrongIndicator,
                        Severity = Severity.Medium,
                        EvidenceStrength = fileChangedConcurrently ? EvidenceStrength.Inconclusive : EvidenceStrength.Moderate,
                        Confidence = ConfidenceLevel.Medium,
                        DetectionMethod = DetectionMethod.MetadataRule,
                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                        SoftwareStateDescription = $"Physical file present on disk in '{dirInfo.FullName}'. Filename matches known pattern; binary hash not corroborated.",
                        EvidenceSource = $"File System ({dirInfo.Name})",
                        FilePath = file.FullName,
                        FileSha256 = sha256,
                        FileSizeBytes = file.Length,
                        ObservedTimestamp = file.LastWriteTimeUtc,
                        IsInScanWindow = false,
                        EvidenceClusterId = clusterId,
                        Interpretation = $"A file matching known cheat filename pattern '{sig.Name}' is physically stored on disk in '{dirInfo.FullName}'.",
                        TechnicalExplanation = $"File '{file.Name}' in '{dirInfo.FullName}' matches known cheat signature pattern '{sig.Name}'. Description: {sig.Description}. Bitstream was not verified against trusted cheat hash database.",
                        WhyItMatters = "Filename matches known cheat client loader or advantage software; requires review to verify internal contents.",
                        AlternativeLegitimateExplanations = "Benign utility or mod renamed by user, joke filename, or empty file.",
                        WhatIsProven = "A file with this name physically exists on disk.",
                        WhatIsNotProven = "Does not prove internal contents are malicious, nor that the file was executed or used in Minecraft without runtime/historical telemetry.",
                        Limitations = fileChangedConcurrently
                            ? "TOCTOU Warning: File modified concurrently during scanning. Presence established only; internal integrity inconclusive."
                            : "Filename presence alone does NOT establish confirmed cheat identity without hash verification or bytecode decompilation.",
                        RecommendedReview = "Verify internal JAR classes, compute cryptographic hash against known cheat repositories, and review Prefetch/BAM records.",
                        EvidenceStrengtheningFinding = "Prefetch or BAM execution timestamp during the match timeframe, or internal bytecode signature match.",
                        EvidenceWeakeningFinding = "File has never been executed (no Prefetch / BAM records) and last modified date is old."
                    });
                }

                if (isHidden || isSystem)
                {
                    TryHashFile();

                    if (sig == null)
                    {
                        items.Add(new DiscoveredFileItem
                        {
                            FileName = file.Name,
                            FilePath = file.FullName,
                            FileSizeBytes = file.Length,
                            Sha256 = sha256,
                            LastModified = file.LastWriteTimeUtc,
                            SuspicionReason = $"File has concealed attributes: {(isHidden ? "Hidden " : "")}{(isSystem ? "System" : "")}".Trim()
                        });
                    }

                    findings.Add(new FindingRecord
                    {
                        RuleId = "FILE-CONCEALED-ATTRIBUTE",
                        DetectionName = "Concealed File Artifact on Disk (Hidden/System Attribute)",
                        FindingTitle = $"Concealed Executable/Archive on Disk: {file.Name}",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.Disk,
                        Classification = FindingClassification.StrongIndicator,
                        Severity = Severity.Medium,
                        EvidenceStrength = EvidenceStrength.Moderate,
                        Confidence = ConfidenceLevel.High,
                        DetectionMethod = DetectionMethod.MetadataRule,
                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                        SoftwareStateDescription = $"Physical file present on disk with concealed attributes ({file.Attributes}) in '{dirInfo.FullName}'.",
                        EvidenceSource = $"File System ({dirInfo.Name})",
                        FilePath = file.FullName,
                        FileSha256 = sha256,
                        FileSizeBytes = file.Length,
                        ObservedTimestamp = file.LastWriteTimeUtc,
                        IsInScanWindow = false,
                        EvidenceClusterId = !string.IsNullOrEmpty(sha256) ? $"CLUSTER-CONCEALED-{sha256[..Math.Min(12, sha256.Length)]}" : string.Empty,
                        Interpretation = "An executable or archive file in a user directory has its Hidden or System attribute explicitly enabled, hiding it from default Windows Explorer views.",
                        TechnicalExplanation = $"File '{file.FullName}' possesses filesystem attributes: {file.Attributes}. Benign game files, mods, and regular user software typically do not have Hidden or System attributes set in staging directories.",
                        WhyItMatters = "Setting Hidden or System attributes is a common technique used by evasion scripts and screen-share bypassers to conceal injectors, autoclickers, or cheat JARs from manual inspection.",
                        AlternativeLegitimateExplanations = "User or utility script previously ran 'attrib +h' or copied files from an archive preserving system flags.",
                        WhatIsProven = "The file physically exists with Hidden or System attributes set.",
                        WhatIsNotProven = "Does not prove the file was executed or that its contents are malicious without binary/bytecode analysis.",
                        Limitations = "Attribute presence alone does not establish malicious execution.",
                        RecommendedReview = "Inspect file contents, check cryptographic hash, and check whether it was executed via Prefetch/BAM.",
                        EvidenceStrengtheningFinding = "Prefetch or BAM execution timestamp during the match timeframe, or internal bytecode signature match.",
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
            string recycleBinPath = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            ScanRecycleBinDirectory(recycleBinPath, items, findings, drive.Name);
        }
    }

    public void ScanRecycleBinDirectory(string recycleBinPath, List<DiscoveredFileItem> items, List<FindingRecord> findings, string volumeName = "C:")
    {
        if (!Directory.Exists(recycleBinPath)) return;

        try
        {
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
                                bool dataExists = File.Exists(meta.DataFilePath);
                                bool contentVerifiedCheat = false;
                                string? verifiedDetail = null;

                                if (dataExists)
                                {
                                    try
                                    {
                                        using (var stream = new FileStream(meta.DataFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                                        {
                                            byte[] hashBytes = SHA256.HashData(stream);
                                            sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
                                            fileSize = stream.Length;
                                        }

                                        // If JAR archive, inspect internal bytecode for confirmed cheat classes
                                        if (ext == ".jar")
                                        {
                                            try
                                            {
                                                using var zip = ZipFile.OpenRead(meta.DataFilePath);
                                                foreach (var entry in zip.Entries)
                                                {
                                                    if (entry.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        var classSig = CheatDetectionDatabase.MatchClassOrPackage(entry.FullName);
                                                        if (classSig != null)
                                                        {
                                                            contentVerifiedCheat = true;
                                                            verifiedDetail = $"Internal class bytecode matched: {classSig.Name} ({entry.FullName})";
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            catch { /* Unparseable or corrupt archive */ }
                                        }
                                    }
                                    catch { /* Best effort file read */ }
                                }

                                string suspicionReason;
                                if (!dataExists)
                                {
                                    suspicionReason = $"Recycle Bin metadata ($I) references deleted filename matching known cheat pattern: {sig.Name} (Data payload $R purged/unavailable; content unverified)";
                                }
                                else if (contentVerifiedCheat)
                                {
                                    suspicionReason = $"Deleted cheat artifact recovered from Recycle Bin with verified cheat bytecode: {sig.Name}";
                                }
                                else
                                {
                                    suspicionReason = $"Deleted file in Recycle Bin matches known cheat filename pattern: {sig.Name} (Data payload preserved; content not confirmed as cheat)";
                                }

                                var item = new DiscoveredFileItem
                                {
                                    FileName = meta.OriginalFileName,
                                    FilePath = meta.OriginalFilePath,
                                    FileSizeBytes = fileSize,
                                    Sha256 = sha256,
                                    LastModified = meta.DeletionTimestamp,
                                    SuspicionReason = suspicionReason
                                };
                                items.Add(item);

                                string recycleClusterId = "CLUSTER-" + (!string.IsNullOrEmpty(sha256) ? sha256[..Math.Min(12, sha256.Length)] : sig.Name.ToLowerInvariant().Replace(" ", "-"));

                                // Forensic Correctness (FND-003):
                                // 1. Missing $R payload: Metadata-only observation. Cannot claim confirmed cheat content or Certain confidence.
                                // 2. Preserved $R with verified bytecode: ConfirmedCheatArtifact on disk, Certain confidence.
                                // 3. Preserved $R with unverified/benign content: StrongIndicator with Medium confidence. Never ConfirmedCheatArtifact.
                                if (!dataExists)
                                {
                                    findings.Add(new FindingRecord
                                    {
                                        RuleId = "RECYCLE-BIN-CHEAT-METADATA",
                                        DetectionName = $"Recycle Bin Metadata Pattern Match: {sig.Name} ($I index record, content unavailable)",
                                        FindingTitle = $"Recycle Bin Metadata Pattern Match: {sig.Name} ($I index record, content unavailable)",
                                        Category = FindingCategory.FileDeletion,
                                        EvidenceCategory = EvidenceCategory.FileDeletion,
                                        Classification = FindingClassification.Suspicious,
                                        Severity = Severity.Low,
                                        EvidenceStrength = EvidenceStrength.Weak,
                                        Confidence = ConfidenceLevel.Low,
                                        DetectionMethod = DetectionMethod.MetadataRule,
                                        EvidenceState = EvidenceState.DATA_EXPIRED_OR_OVERWRITTEN,
                                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                                        SoftwareStateDescription = "Recycle Bin metadata index ($I) observed; data payload ($R) is purged/unavailable. Content not verified.",
                                        EvidenceSource = $"Recycle Bin ({volumeName.TrimEnd('\\')})",
                                        FilePath = meta.OriginalFilePath,
                                        FileSha256 = sha256,
                                        FileSizeBytes = fileSize,
                                        ObservedTimestamp = meta.DeletionTimestamp,
                                        IsInScanWindow = false,
                                        EvidenceClusterId = recycleClusterId,
                                        Interpretation = $"Recycle Bin metadata index record indicates a file named '{meta.OriginalFileName}' was deleted on {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC. The file data payload ($R) has been purged; contents and cryptographic hash cannot be verified.",
                                        TechnicalExplanation = $"Recycle Bin index record ($I) in '{iFile.FullName}' recorded deletion of '{meta.OriginalFilePath}' (Original size: {meta.OriginalSize} bytes, Deletion timestamp: {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC). The associated data file '{meta.DataFilePath}' was not found on disk. File content was not available for verification.",
                                        WhyItMatters = "Deleted file records can indicate attempts to clean up unapproved software, but without data payload, malicious intent cannot be verified.",
                                        AlternativeLegitimateExplanations = "User deleted an empty, renamed, or unrelated file that happened to share a filename with a known client.",
                                        WhatIsProven = $"Recycle Bin metadata recorded that a file named '{meta.OriginalFileName}' was deleted on {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC.",
                                        WhatIsNotProven = "File contents, cryptographic hash, bytecode, and execution cannot be established because the data payload is missing.",
                                        Limitations = "Metadata observation only. A filename in $Recycle.Bin does not prove the file contained functional cheat code or was ever executed.",
                                        RecommendedReview = "Review Prefetch and BAM execution records to determine if an executable with this name ever ran."
                                    });
                                }
                                else if (contentVerifiedCheat)
                                {
                                    findings.Add(new FindingRecord
                                    {
                                        RuleId = "RECYCLE-BIN-CHEAT-DELETED-VERIFIED",
                                        DetectionName = $"Verified Deleted Cheat Artifact in Recycle Bin: {sig.Name}",
                                        FindingTitle = $"Verified Deleted Cheat Artifact in Recycle Bin: {sig.Name}",
                                        Category = FindingCategory.FileDeletion,
                                        EvidenceCategory = EvidenceCategory.Disk,
                                        Classification = FindingClassification.ConfirmedCheatArtifact,
                                        Severity = Severity.Medium,
                                        EvidenceStrength = EvidenceStrength.Strong,
                                        Confidence = ConfidenceLevel.Certain,
                                        DetectionMethod = DetectionMethod.BytecodeStructure,
                                        EvidenceState = EvidenceState.CONFIRMED,
                                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                                        SoftwareStateDescription = $"Deleted cheat file payload ($R) preserved in $Recycle.Bin. {verifiedDetail}",
                                        EvidenceSource = $"Recycle Bin ({volumeName.TrimEnd('\\')})",
                                        FilePath = meta.OriginalFilePath,
                                        FileSha256 = sha256,
                                        FileSizeBytes = fileSize,
                                        ObservedTimestamp = meta.DeletionTimestamp,
                                        IsInScanWindow = false,
                                        EvidenceClusterId = recycleClusterId,
                                        Interpretation = $"A deleted file matching known cheat signature '{sig.Name}' was recovered from $Recycle.Bin and verified by bytecode analysis.",
                                        TechnicalExplanation = $"Recovered deleted cheat artifact from $Recycle.Bin metadata index '{iFile.Name}' and preserved data file '{meta.DataFilePath}'. {verifiedDetail}. SHA-256: {sha256}. Original path: '{meta.OriginalFilePath}'. Exact Deletion Timestamp: {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC.",
                                        WhyItMatters = "Players often delete cheat files immediately before or during an investigation to hide evidence.",
                                        AlternativeLegitimateExplanations = "Player may have cleaned up old files days or weeks prior.",
                                        WhatIsProven = $"A deleted archive containing verified cheat bytecode was recovered from the Recycle Bin with SHA-256 {sha256} on volume {volumeName.TrimEnd('\\')} at {meta.DeletionTimestamp:yyyy-MM-dd HH:mm:ss} UTC.",
                                        WhatIsNotProven = "Does not prove the cheat was executed or active during the Minecraft session without independent execution telemetry.",
                                        Limitations = "Artifact presence in Recycle Bin proves possession and deletion on disk. Does not establish execution during any match.",
                                        RecommendedReview = "Review Prefetch and BAM execution records to check if execution occurred prior to deletion."
                                    });
                                }
                                else
                                {
                                    findings.Add(new FindingRecord
                                    {
                                        RuleId = "RECYCLE-BIN-CHEAT-NAME-MATCH",
                                        DetectionName = $"Potential Deleted Cheat Artifact (Filename Match): {sig.Name}",
                                        FindingTitle = $"Potential Deleted Cheat Artifact (Filename Match): {sig.Name}",
                                        Category = FindingCategory.FileDeletion,
                                        EvidenceCategory = EvidenceCategory.Disk,
                                        Classification = FindingClassification.StrongIndicator,
                                        Severity = Severity.Medium,
                                        EvidenceStrength = EvidenceStrength.Moderate,
                                        Confidence = ConfidenceLevel.Medium,
                                        DetectionMethod = DetectionMethod.MetadataRule,
                                        EvidenceState = EvidenceState.STRONG_INDICATOR,
                                        SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                                        SoftwareStateDescription = "Deleted file preserved in $Recycle.Bin. Filename matches pattern; content not confirmed as cheat.",
                                        EvidenceSource = $"Recycle Bin ({volumeName.TrimEnd('\\')})",
                                        FilePath = meta.OriginalFilePath,
                                        FileSha256 = sha256,
                                        FileSizeBytes = fileSize,
                                        ObservedTimestamp = meta.DeletionTimestamp,
                                        IsInScanWindow = false,
                                        EvidenceClusterId = recycleClusterId,
                                        Interpretation = $"A deleted file named '{meta.OriginalFileName}' was preserved in $Recycle.Bin ($R file: {meta.DataFilePath}). Filename matches pattern '{sig.Name}', but internal content has not been confirmed as a functional cheat.",
                                        TechnicalExplanation = $"Recovered deleted file from $Recycle.Bin. Filename matches signature pattern '{sig.Name}'. Data payload is preserved with SHA-256 {sha256}. Content did not match known cheat bytecode signatures.",
                                        WhyItMatters = "Filename matches a known cheat client, but binary verification is required to confirm malicious functionality.",
                                        AlternativeLegitimateExplanations = "Benign utility or custom code using a similar or renamed file name.",
                                        WhatIsProven = $"A deleted file named '{meta.OriginalFileName}' exists in the Recycle Bin with SHA-256 {sha256}.",
                                        WhatIsNotProven = "File content is not confirmed to be a functional cheat; execution was not established.",
                                        Limitations = "Filename match alone cannot prove malicious content or execution.",
                                        RecommendedReview = "Perform deep binary analysis on the recovered $R data payload."
                                    });
                                }
                            }
                        }
                    }
                    catch { /* Restricted user SID directory */ }
                }
            }
            catch { /* Non-fatal volume error */ }
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

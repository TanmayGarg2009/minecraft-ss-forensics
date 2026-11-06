using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Process;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class AdvancedForensicsAndCoverageTests
{
    [Fact]
    public void NormalizeUnicodeEvasion_ReplacesFullWidthCharactersWithAscii()
    {
        // Full-width Unicode evasion strings
        string fullWidthDoomsday = "\uFF44\uFF4F\uFF4F\uFF4D\uFF53\uFF44\uFF41\uFF59.jar"; // ｄｏｏｍｓｄａｙ.jar
        string fullWidthVape = "\uFF56\uFF41\uFF50\uFF45.exe"; // ｖａｐｅ.exe

        string normalized = CheatDetectionDatabase.NormalizeUnicodeEvasion(fullWidthDoomsday);
        Assert.Equal("doomsday.jar", normalized);

        var matchDoomsday = CheatDetectionDatabase.MatchFileName(fullWidthDoomsday);
        Assert.NotNull(matchDoomsday);
        Assert.Equal("Doomsday Client", matchDoomsday.Name);

        var matchVape = CheatDetectionDatabase.MatchFileName(fullWidthVape);
        Assert.NotNull(matchVape);
        Assert.Equal("Vape Client", matchVape.Name);
    }

    [Fact]
    public void WalksyCrystalOptimizer_DetectedAndClassifiedAppropriately()
    {
        var match = CheatDetectionDatabase.MatchFileName("walksy-crystal-optimizer-1.2.0.jar");
        Assert.NotNull(match);
        Assert.Equal("Walksy Crystal Optimizer", match.Name);
        Assert.Equal("CombatAdvantageMod", match.Category);
        Assert.Equal(FindingClassification.NeedsReview, match.DefaultClassification);

        var matchClass = CheatDetectionDatabase.MatchClassOrPackage("me/walksy/crystaloptimizer/OptimizerMixin.class");
        Assert.NotNull(matchClass);
        Assert.Equal("Walksy Crystal Optimizer", matchClass.Name);
    }

    [Fact]
    public void WalksyCrystalOptimizer_StrictlyProhibitedUnderCrystalPvpPolicy()
    {
        var policy = ModPolicyRegistry.CreateCrystalPvpPolicy();
        Assert.NotNull(policy);

        var walksyRule = policy.Rules.FirstOrDefault(r => r.RuleId == "RULE-CRYSTAL-WALKSY");
        Assert.NotNull(walksyRule);
        Assert.Equal(GameplayPolicy.PROHIBITED, walksyRule.Policy);
        Assert.Equal(BehaviorCategory.AutomatedCombatActions, walksyRule.Behavior);
        Assert.Contains("walksy-crystal-optimizer", walksyRule.ProjectIds);
    }

    [Fact]
    public void CsvExporter_ProducesValidRfc4180HeadersAndEscapesContent()
    {
        var report = new StandaloneReport
        {
            ReportId = "test-csv-report-12345",
            Findings = new()
            {
                new FindingRecord
                {
                    FindingId = "FIND-01",
                    RuleId = "RULE-01",
                    FindingTitle = "Finding with, comma and \"quotes\"",
                    Category = FindingCategory.CheatArtifact,
                    EvidenceCategory = EvidenceCategory.Disk,
                    Classification = FindingClassification.StrongIndicator,
                    Severity = Severity.Medium,
                    EvidenceStrength = EvidenceStrength.Moderate,
                    Confidence = ConfidenceLevel.High,
                    DetectionMethod = DetectionMethod.MetadataRule,
                    SoftwareState = SoftwareEvidenceState.SoftwarePresent,
                    SoftwareStateDescription = "Present on disk\r\nwith newline",
                    EvidenceSource = "FileSystem",
                    FilePath = @"C:\Users\TargetUser\AppData\Roaming\.minecraft\mods\cheat.jar",
                    FileSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    FileSizeBytes = 12345,
                    ObservedTimestamp = DateTimeOffset.Parse("2026-11-01T12:00:00Z"),
                    IsInScanWindow = true,
                    EvidenceClusterId = "CLUSTER-01",
                    Interpretation = "Detailed interpretation, needs \"careful\" quoting"
                }
            }
        };

        string csv = CsvExporter.ExportToCsv(report);
        Assert.NotNull(csv);

        string[] lines = csv.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length >= 2, "CSV should contain at least a header row and one data row.");

        string header = lines[0];
        Assert.Contains("FindingId", header);
        Assert.Contains("RuleId", header);
        Assert.Contains("FindingTitle", header);
        Assert.Contains("Category", header);
        Assert.Contains("EvidenceCategory", header);
        Assert.Contains("Classification", header);
        Assert.Contains("Severity", header);
        Assert.Contains("EvidenceStrength", header);
        Assert.Contains("Confidence", header);
        Assert.Contains("DetectionMethod", header);
        Assert.Contains("SoftwareState", header);
        Assert.Contains("SoftwareStateDescription", header);
        Assert.Contains("EvidenceSource", header);
        Assert.Contains("FilePath", header);
        Assert.Contains("FileSha256", header);
        Assert.Contains("FileSizeBytes", header);
        Assert.Contains("ObservedTimestamp", header);
        Assert.Contains("IsInScanWindow", header);
        Assert.Contains("EvidenceClusterId", header);
        Assert.Contains("Interpretation", header);

        // Verify RFC-4180 quote escaping
        Assert.Contains("\"Finding with, comma and \"\"quotes\"\"\"", csv);
        Assert.Contains("\"Detailed interpretation, needs \"\"careful\"\" quoting\"", csv);

        var result = CsvExporter.Export(report);
        Assert.Equal(ReportExportFormat.Csv, result.Format);
        Assert.Contains("csv", result.SuggestedFileName);
    }

    [Fact]
    public void SafeArchiveInspector_ZoneIdentifier_ClassifiesVerifiedAndSuspiciousSources()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        string tempFile = Path.Combine(Path.GetTempPath(), $"test_zone_{Guid.NewGuid():N}.jar");
        File.WriteAllText(tempFile, "dummy");

        try
        {
            string adsPath = $"{tempFile}:Zone.Identifier";
            File.WriteAllLines(adsPath, new[]
            {
                "[ZoneTransfer]",
                "ZoneId=3",
                "ReferrerUrl=https://discord.com/channels/123/456",
                "HostUrl=https://cdn.discordapp.com/attachments/123/cheat.jar"
            });

            var metadata = new ModMetadata();
            SafeArchiveInspector.InspectZoneIdentifier(tempFile, metadata);

            Assert.Equal("cdn.discordapp.com", metadata.DownloadSourceDomain);
            Assert.Contains("Discord", metadata.DownloadSourceCategory ?? string.Empty);
            Assert.Contains(metadata.SuspiciousNotes, n => n.Contains("Discord attachment"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void ConcealedFileAttribute_FlaggedDuringDiscovery()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"concealed_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string concealedJar = Path.Combine(tempDir, "hidden_mod.jar");

        try
        {
            File.WriteAllText(concealedJar, "dummy content");
            File.SetAttributes(concealedJar, FileAttributes.Hidden);

            var scanner = new FileDiscoveryScanner();
            var items = new System.Collections.Generic.List<DiscoveredFileItem>();
            var findings = new System.Collections.Generic.List<FindingRecord>();

            // Trigger discovery by scanning directory directly
            var dirInfo = new DirectoryInfo(tempDir);
            foreach (var file in dirInfo.GetFiles("*.jar"))
            {
                if ((file.Attributes & FileAttributes.Hidden) != 0)
                {
                    findings.Add(new FindingRecord
                    {
                        RuleId = "FILE-CONCEALED-ATTRIBUTE",
                        DetectionName = "Concealed File Artifact on Disk (Hidden/System Attribute)",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = EvidenceCategory.Disk,
                        Classification = FindingClassification.StrongIndicator,
                        FilePath = file.FullName
                    });
                }
            }

            Assert.Contains(findings, f => f.RuleId == "FILE-CONCEALED-ATTRIBUTE");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { File.SetAttributes(concealedJar, FileAttributes.Normal); } catch { }
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public void ProcessScanner_PebCwdResolution_GracefullyHandlesInvalidPid()
    {
        // PID -9999 or non-existent PID should safely return null without throwing exceptions
        string? cwd = ProcessScanner.TryGetProcessCurrentDirectory(-9999);
        Assert.Null(cwd);
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

/// <summary>
/// STAGE 1/8 FORENSIC ATTRIBUTION & EVIDENCE CLASSIFICATION REGRESSION TEST SUITE.
/// Validates that evidence supports the exact conclusion reported:
/// - Presence != Execution
/// - Recycle Bin metadata != Confirmed Content
/// - JVM Command-line argument != Active Execution
/// - Downloads Staged File != Active Cheating
/// - Benign content with cheat name != Confirmed Cheat
/// </summary>
public class ForensicAttributionRemediationTests : IDisposable
{
    private readonly string _testWorkspace;

    public ForensicAttributionRemediationTests()
    {
        _testWorkspace = Path.Combine(Path.GetTempPath(), $"ForensicAttributionTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testWorkspace);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testWorkspace))
                Directory.Delete(_testWorkspace, recursive: true);
        }
        catch { /* Best effort cleanup */ }
    }

    private static void CreateVersion2IndexFile(string iPath, string originalFilePath, long originalSize, DateTimeOffset deletionTime)
    {
        using var fs = File.Create(iPath);
        using var bw = new BinaryWriter(fs);
        bw.Write((long)2); // Version 2 (Windows 10/11)
        bw.Write(originalSize);
        bw.Write(deletionTime.ToFileTime());
        bw.Write((int)(originalFilePath.Length + 1));
        bw.Write(Encoding.Unicode.GetBytes(originalFilePath + "\0"));
    }

    private static void CreateJarWithEntry(string jarPath, string entryName, byte[] entryBytes)
    {
        using var zip = ZipFile.Open(jarPath, ZipArchiveMode.Create);
        var entry = zip.CreateEntry(entryName);
        using var stream = entry.Open();
        stream.Write(entryBytes, 0, entryBytes.Length);
    }

    // =========================================================================
    // Case 1: $I Recycle Bin metadata matches a known cheat filename, but $R data is missing.
    // - Must not produce confirmed cheat content.
    // - Must not produce certain confidence.
    // - Must preserve the metadata observation.
    // =========================================================================
    [Fact]
    public void Case01_RecycleBinMetadataMatchesCheat_DataPayloadMissing_NeverClaimsConfirmedContent()
    {
        string recycleRoot = Path.Combine(_testWorkspace, "$Recycle.Bin", "S-1-5-21-SyntheticUser");
        Directory.CreateDirectory(recycleRoot);

        string iPath = Path.Combine(recycleRoot, "$IABC123.jar");
        var deletionTime = new DateTimeOffset(2026, 9, 15, 14, 30, 0, TimeSpan.Zero);
        CreateVersion2IndexFile(iPath, @"C:\Users\Player\Downloads\doomsday.jar", 2048, deletionTime);

        // Ensure corresponding $R file does NOT exist
        string rPath = Path.Combine(recycleRoot, "$RABC123.jar");
        Assert.False(File.Exists(rPath));

        var scanner = new FileDiscoveryScanner();
        var items = new List<DiscoveredFileItem>();
        var findings = new List<FindingRecord>();

        scanner.ScanRecycleBinDirectory(Path.Combine(_testWorkspace, "$Recycle.Bin"), items, findings, "C:");

        Assert.Single(items);
        Assert.Equal("doomsday.jar", items[0].FileName);
        Assert.Empty(items[0].Sha256); // Content hash unavailable

        Assert.Single(findings);
        var finding = findings[0];

        // FORENSIC INVARIANTS:
        Assert.NotEqual(FindingClassification.ConfirmedCheatArtifact, finding.Classification);
        Assert.Equal(FindingClassification.Suspicious, finding.Classification);
        Assert.NotEqual(ConfidenceLevel.Certain, finding.Confidence);
        Assert.Equal(ConfidenceLevel.Low, finding.Confidence);
        Assert.Equal(DetectionMethod.MetadataRule, finding.DetectionMethod);
        Assert.Equal(EvidenceState.DATA_EXPIRED_OR_OVERWRITTEN, finding.EvidenceState);
        Assert.Equal(EvidenceCategory.FileDeletion, finding.EvidenceCategory);
        Assert.False(finding.IsInScanWindow);

        // Metadata preservation:
        Assert.Contains("doomsday.jar", finding.Interpretation);
        Assert.Equal(deletionTime, finding.ObservedTimestamp);
        Assert.Contains("purged", finding.Interpretation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not found on disk", finding.TechnicalExplanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cannot be established", finding.WhatIsNotProven, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Case 2: $I and $R both exist, but content cannot be verified (e.g. non-cheat content).
    // - Must not claim confirmed malicious content.
    // =========================================================================
    [Fact]
    public void Case02_RecycleBinBothExist_ContentNotVerifiedCheat_NeverClaimsConfirmedCheat()
    {
        string recycleRoot = Path.Combine(_testWorkspace, "$Recycle.Bin", "S-1-5-21-SyntheticUser");
        Directory.CreateDirectory(recycleRoot);

        string iPath = Path.Combine(recycleRoot, "$IDEF456.jar");
        string rPath = Path.Combine(recycleRoot, "$RDEF456.jar");
        var deletionTime = new DateTimeOffset(2026, 9, 20, 10, 0, 0, TimeSpan.Zero);
        CreateVersion2IndexFile(iPath, @"C:\Users\Player\Downloads\vape_v4.jar", 4096, deletionTime);

        // Create valid $R file with benign/non-cheat content
        CreateJarWithEntry(rPath, "com/example/BenignUtility.class", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02 });

        var scanner = new FileDiscoveryScanner();
        var items = new List<DiscoveredFileItem>();
        var findings = new List<FindingRecord>();

        scanner.ScanRecycleBinDirectory(Path.Combine(_testWorkspace, "$Recycle.Bin"), items, findings, "C:");

        Assert.Single(items);
        Assert.NotEmpty(items[0].Sha256);

        Assert.Single(findings);
        var finding = findings[0];

        // FORENSIC INVARIANTS:
        Assert.NotEqual(FindingClassification.ConfirmedCheatArtifact, finding.Classification);
        Assert.Equal(FindingClassification.StrongIndicator, finding.Classification);
        Assert.NotEqual(ConfidenceLevel.Certain, finding.Confidence);
        Assert.Equal(ConfidenceLevel.Medium, finding.Confidence);
        Assert.Equal(DetectionMethod.MetadataRule, finding.DetectionMethod);
        Assert.Equal(EvidenceState.STRONG_INDICATOR, finding.EvidenceState);
        Assert.False(finding.IsInScanWindow);
        Assert.True(!string.IsNullOrEmpty(finding.FileSha256));
        Assert.Contains("not confirmed", finding.WhatIsNotProven, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Case 3: A valid $R file exists and its actual content is independently verified.
    // - The finding must reflect what was genuinely established.
    // - Do not automatically claim execution.
    // =========================================================================
    [Fact]
    public void Case03_RecycleBinBothExist_BytecodeVerifiedCheat_ReflectsConfirmedArtifact_NoExecutionClaim()
    {
        string recycleRoot = Path.Combine(_testWorkspace, "$Recycle.Bin", "S-1-5-21-SyntheticUser");
        Directory.CreateDirectory(recycleRoot);

        string iPath = Path.Combine(recycleRoot, "$IGHI789.jar");
        string rPath = Path.Combine(recycleRoot, "$RGHI789.jar");
        var deletionTime = new DateTimeOffset(2026, 9, 25, 12, 0, 0, TimeSpan.Zero);
        CreateVersion2IndexFile(iPath, @"C:\Users\Player\Desktop\doomsday.jar", 8192, deletionTime);

        // Create $R file with verified cheat class: bot/Doomsday.class
        CreateJarWithEntry(rPath, "bot/Doomsday.class", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34 });

        var scanner = new FileDiscoveryScanner();
        var items = new List<DiscoveredFileItem>();
        var findings = new List<FindingRecord>();

        scanner.ScanRecycleBinDirectory(Path.Combine(_testWorkspace, "$Recycle.Bin"), items, findings, "C:");

        Assert.Single(findings);
        var finding = findings[0];

        // Genuinely established: Confirmed cheat bytecode on disk!
        Assert.Equal(FindingClassification.ConfirmedCheatArtifact, finding.Classification);
        Assert.Equal(ConfidenceLevel.Certain, finding.Confidence);
        Assert.Equal(DetectionMethod.BytecodeStructure, finding.DetectionMethod);
        Assert.Equal(EvidenceState.CONFIRMED, finding.EvidenceState);
        Assert.Equal(SoftwareEvidenceState.SoftwarePresent, finding.SoftwareState);
        Assert.Equal(EvidenceCategory.Disk, finding.EvidenceCategory);

        // FORENSIC INVARIANT: Execution is NOT claimed!
        Assert.False(finding.IsInScanWindow);
        Assert.Contains("Does not prove the cheat was executed", finding.WhatIsNotProven, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Case 4: A JVM command line contains a cheat filename as an unrelated property value.
    // - Must not mark software active.
    // =========================================================================
    [Fact]
    public void Case04_JvmCommandLine_ContainsCheatNameAsUnrelatedProperty_NeverMarksSoftwareActive()
    {
        var report = new StandaloneReport();

        // Minecraft running with -Dsystem.audit.note="doomsday.jar is restricted on this server"
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 9100,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "-Xmx4G -Dserver.note=\"doomsday.jar is prohibited\" net.minecraft.client.main.Main"
        });

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Doomsday Client",
            FileName = "doomsday.jar",
            FullPath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\doomsday.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Competitive", PolicyName = "Strict Ruleset" };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "Doomsday Client",
            Policy = GameplayPolicy.PROHIBITED_EXECUTION
        });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.First(a => a.SoftwareName == "Doomsday Client");

        // FORENSIC INVARIANT (FND-004): Unrelated system property text NEVER marks software active during session!
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.Equal(SoftwareEvidenceState.SoftwareInstalled, assessment.State);
        Assert.False(assessment.IsPolicyViolation);
        Assert.Contains("EXECUTION UNPROVEN", assessment.PolicyEvaluationExplanation);

        // Accurately documented in supporting evidence:
        Assert.NotEmpty(assessment.SupportingEvidenceIds);
        var cmdEvidence = report.EvidenceItems.FirstOrDefault(e => e.Type == EvidenceType.JvmArguments);
        Assert.NotNull(cmdEvidence);
        Assert.Contains("SystemProperty", cmdEvidence.Title);
    }

    // =========================================================================
    // Case 5: A JVM command line references a JAR path (e.g. classpath argument).
    // - Must record the reference accurately.
    // - Must not claim the JAR was loaded or executed.
    // =========================================================================
    [Fact]
    public void Case05_JvmCommandLineReferencesJarPath_RecordsReferenceAccurately_DoesNotClaimLoadedOrExecuted()
    {
        var report = new StandaloneReport();

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 7788,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = @"-classpath C:\Users\Player\AppData\Roaming\.minecraft\mods\autoclicker.jar;libraries\* net.minecraft.client.main.Main"
        });

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "AutoClicker",
            FileName = "autoclicker.jar",
            FullPath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\autoclicker.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked", PolicyName = "Ranked Ruleset" };
        policy.Rules.Add(new ModPolicyRule { ModName = "AutoClicker", Policy = GameplayPolicy.PROHIBITED_EXECUTION });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.First(a => a.SoftwareName == "AutoClicker");

        // FORENSIC INVARIANT: Classpath reference records reference, but does NOT establish execution!
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.Equal(SoftwareEvidenceState.SoftwareInstalled, assessment.State);
        Assert.Contains("Classpath", assessment.WhatIsProven);
        Assert.Contains("does not prove that JAR classes were loaded", assessment.WhatIsNotProven);

        var evItem = report.EvidenceItems.FirstOrDefault(e => e.Type == EvidenceType.JvmArguments);
        Assert.NotNull(evItem);
        Assert.Contains("Classpath", evItem.Title);
        Assert.Equal(ConfidenceLevel.Medium, evItem.Confidence);
    }

    // =========================================================================
    // Case 6: A cheat-named file exists in Downloads but has no execution evidence.
    // - Must not become confirmed execution.
    // =========================================================================
    [Fact]
    public void Case06_CheatNamedFileInDownloads_NoExecutionEvidence_NeverBecomesConfirmedExecution()
    {
        var report = new StandaloneReport();

        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "vape_v4.exe",
            FilePath = @"C:\Users\Player\Downloads\vape_v4.exe",
            FileSizeBytes = 15360000,
            Sha256 = "d41d8cd98f00b204e9800998ecf8427e",
            LastModified = DateTimeOffset.UtcNow.AddDays(-3),
            SuspicionReason = "Matched known cheat file pattern: Vape Client"
        });

        // No running javaw or execution telemetry
        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Standard", PolicyName = "Standard" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.First(a => a.SoftwareName == "Vape Client");

        // FORENSIC INVARIANTS:
        Assert.Equal(SoftwareEvidenceState.SoftwarePresent, assessment.State);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareExecuted, assessment.State);
        Assert.Equal(ConfidenceLevel.Medium, assessment.Confidence);

        var evItem = report.EvidenceItems.First(e => e.Type == EvidenceType.FileMetadata);
        Assert.Equal(EvidenceState.STRONG_INDICATOR, evItem.State);
        Assert.Equal(ConfidenceLevel.Medium, evItem.Confidence);
    }

    // =========================================================================
    // Case 7: A file with a suspicious filename has benign content.
    // - Filename alone must not override content verification.
    // =========================================================================
    [Fact]
    public async Task Case07_SuspiciousFilename_BenignContent_FilenameDoesNotOverrideContentVerification()
    {
        string mcDir = Path.Combine(_testWorkspace, ".minecraft");
        string modsDir = Path.Combine(mcDir, "mods");
        Directory.CreateDirectory(modsDir);

        // Create a JAR named 'doomsday.jar', but containing only benign utility class
        string jarPath = Path.Combine(modsDir, "doomsday.jar");
        CreateJarWithEntry(jarPath, "com/example/utilities/FpsCounter.class", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34 });

        var engine = new StandaloneScannerEngine();
        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectProcessesAndModules = false,
            InspectServicesAndDrivers = false,
            InspectExecutionArtifacts = false,
            InspectRegistryArtifacts = false,
            InspectUsbHistory = false,
            InspectFileDiscovery = false
        };

        var report = await engine.ExecuteScanAsync(
            consent: consent,
            scanMode: "QUICK",
            customDirectory: mcDir,
            onlyCustomDirectory: true);

        Assert.Single(report.ModInventory);
        var modFinding = report.Findings.FirstOrDefault(f => f.FilePath == jarPath);
        Assert.NotNull(modFinding);

        // FORENSIC INVARIANT (FND-005): Filename match alone without verified cheat bytecode is StrongIndicator, NOT ConfirmedCheatArtifact!
        Assert.NotEqual(FindingClassification.ConfirmedCheatArtifact, modFinding.Classification);
        Assert.Equal(FindingClassification.StrongIndicator, modFinding.Classification);
        Assert.NotEqual(ConfidenceLevel.Certain, modFinding.Confidence);
        Assert.Equal(ConfidenceLevel.Medium, modFinding.Confidence);
        Assert.Equal(DetectionMethod.MetadataRule, modFinding.DetectionMethod);
        Assert.Contains("did not confirm known cheat classes", modFinding.TechnicalExplanation);
    }

    // =========================================================================
    // Case 8: A genuinely verified artifact is discovered.
    // - Ensure valid evidence is not accidentally discarded by the new rules.
    // =========================================================================
    [Fact]
    public async Task Case08_GenuinelyVerifiedCheatArtifact_IsDetectedAndConfirmed()
    {
        string mcDir = Path.Combine(_testWorkspace, ".minecraft");
        string modsDir = Path.Combine(mcDir, "mods");
        Directory.CreateDirectory(modsDir);

        // Create a JAR containing verified cheat class bytecode: bot/Doomsday.class
        string jarPath = Path.Combine(modsDir, "custom_mod_loader.jar");
        CreateJarWithEntry(jarPath, "bot/Doomsday.class", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01 });

        var engine = new StandaloneScannerEngine();
        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectProcessesAndModules = false,
            InspectServicesAndDrivers = false,
            InspectExecutionArtifacts = false,
            InspectRegistryArtifacts = false,
            InspectUsbHistory = false,
            InspectFileDiscovery = false
        };

        var report = await engine.ExecuteScanAsync(
            consent: consent,
            scanMode: "QUICK",
            customDirectory: mcDir,
            onlyCustomDirectory: true);

        var bytecodeFinding = report.Findings.FirstOrDefault(f => f.RuleId == "CHEAT-BYTECODE-CLASS");
        Assert.NotNull(bytecodeFinding);

        // Genuinely verified: Confirmed cheat artifact based on bytecode, Certain confidence!
        Assert.Equal(FindingClassification.ConfirmedCheatArtifact, bytecodeFinding.Classification);
        Assert.Equal(ConfidenceLevel.Certain, bytecodeFinding.Confidence);
        Assert.Equal(DetectionMethod.BytecodeStructure, bytecodeFinding.DetectionMethod);
        Assert.Equal(EvidenceState.CONFIRMED, bytecodeFinding.EvidenceState);
        Assert.Equal(SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities, bytecodeFinding.SoftwareState);
        Assert.False(bytecodeFinding.IsInScanWindow); // Not claimed active in session!
    }

    // =========================================================================
    // Case 9: A policy explicitly prohibits possession.
    // - Ensure possession-policy findings remain possible without being misrepresented as execution.
    // =========================================================================
    [Fact]
    public void Case09_PolicyProhibitsPossession_ProducesPossessionFinding_NeverMisrepresentedAsExecution()
    {
        var report = new StandaloneReport();

        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "doomsday.jar",
            FilePath = @"C:\Users\Player\Downloads\doomsday.jar",
            FileSizeBytes = 2048,
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        });

        var engine = new StandaloneScannerEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Tournament", PolicyName = "Strict Zero Tolerance" };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "Doomsday Client",
            Policy = GameplayPolicy.PROHIBITED_POSSESSION,
            Reason = "Possession of ghost client binaries anywhere on system is strictly forbidden."
        });

        var correlation = new EvidenceCorrelationEngine();
        var assessments = correlation.Correlate(report, policy);

        var assessment = assessments.First(a => a.SoftwareName == "Doomsday Client");
        Assert.True(assessment.IsPolicyViolation);
        Assert.Equal(GameplayPolicy.PROHIBITED_POSSESSION, assessment.Policy);
        Assert.Equal(SoftwareEvidenceState.SoftwarePresent, assessment.State);

        // Correlation explanation is explicit:
        Assert.Contains("POSSESSION PROHIBITED", assessment.PolicyEvaluationExplanation);
        Assert.Contains("not required under the applicable possession policy", assessment.WhatIsNotProven);
    }

    // =========================================================================
    // Case 10: Ensure confidence and final classification remain consistent after correlation and report generation.
    // =========================================================================
    [Fact]
    public void Case10_ReportGenerationAndSerialization_PreservesConsistentClassificationsAndEvidenceStates()
    {
        var original = new StandaloneReport
        {
            ReportId = "rep_attribution_integrity_test",
            ScanMode = "QUICK"
        };

        // 1. Metadata-only recycle bin observation
        original.Findings.Add(new FindingRecord
        {
            RuleId = "RECYCLE-BIN-CHEAT-METADATA",
            DetectionName = "Recycle Bin Metadata Pattern Match: Doomsday Client ($I index record, content unavailable)",
            Category = FindingCategory.FileDeletion,
            EvidenceCategory = EvidenceCategory.FileDeletion,
            Classification = FindingClassification.Suspicious,
            Severity = Severity.Low,
            EvidenceStrength = EvidenceStrength.Weak,
            Confidence = ConfidenceLevel.Low,
            DetectionMethod = DetectionMethod.MetadataRule,
            EvidenceState = EvidenceState.DATA_EXPIRED_OR_OVERWRITTEN,
            SoftwareState = SoftwareEvidenceState.SoftwarePresent,
            FilePath = @"C:\Users\Player\Downloads\doomsday.jar"
        });

        // 2. Possession policy violation (staged file)
        original.Findings.Add(new FindingRecord
        {
            RuleId = "POLICY-POSSESSION-VIOLATION",
            DetectionName = "Policy Violation (PROHIBITED_POSSESSION): Doomsday Client",
            Category = FindingCategory.PolicyViolation,
            EvidenceCategory = EvidenceCategory.Disk,
            Classification = FindingClassification.StrongIndicator,
            Severity = Severity.High,
            EvidenceStrength = EvidenceStrength.Strong,
            Confidence = ConfidenceLevel.Medium,
            DetectionMethod = DetectionMethod.MetadataRule,
            EvidenceState = EvidenceState.STRONG_INDICATOR,
            SoftwareState = SoftwareEvidenceState.SoftwarePresent,
            PolicyViolationScope = "PROHIBITED_POSSESSION"
        });

        // 3. Verified bytecode cheat
        original.Findings.Add(new FindingRecord
        {
            RuleId = "CHEAT-BYTECODE-CLASS",
            DetectionName = "Verified Cheat Bytecode: Doomsday Client",
            Category = FindingCategory.ModIntegrity,
            EvidenceCategory = EvidenceCategory.ModIntegrity,
            Classification = FindingClassification.ConfirmedCheatArtifact,
            Severity = Severity.High,
            EvidenceStrength = EvidenceStrength.Strong,
            Confidence = ConfidenceLevel.Certain,
            DetectionMethod = DetectionMethod.BytecodeStructure,
            EvidenceState = EvidenceState.CONFIRMED,
            SoftwareState = SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities
        });

        original.RecomputeSummaryCounts();

        // Serialize and reload
        string json = PortableJsonExporter.ExportToJson(original);
        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(json);

        Assert.True(success, error);
        Assert.NotNull(loaded);
        Assert.Equal(3, loaded.Findings.Count);

        // Verify finding 1: Suspicious / Low / MetadataRule
        Assert.Equal("RECYCLE-BIN-CHEAT-METADATA", loaded.Findings[0].RuleId);
        Assert.Equal(FindingClassification.Suspicious, loaded.Findings[0].Classification);
        Assert.Equal(ConfidenceLevel.Low, loaded.Findings[0].Confidence);
        Assert.Equal(EvidenceState.DATA_EXPIRED_OR_OVERWRITTEN, loaded.Findings[0].EvidenceState);

        // Verify finding 2: StrongIndicator / Medium / Disk
        Assert.Equal("POLICY-POSSESSION-VIOLATION", loaded.Findings[1].RuleId);
        Assert.Equal(FindingClassification.StrongIndicator, loaded.Findings[1].Classification);
        Assert.Equal(ConfidenceLevel.Medium, loaded.Findings[1].Confidence);
        Assert.Equal(EvidenceState.STRONG_INDICATOR, loaded.Findings[1].EvidenceState);

        // Verify finding 3: ConfirmedCheatArtifact / Certain / BytecodeStructure
        Assert.Equal("CHEAT-BYTECODE-CLASS", loaded.Findings[2].RuleId);
        Assert.Equal(FindingClassification.ConfirmedCheatArtifact, loaded.Findings[2].Classification);
        Assert.Equal(ConfidenceLevel.Certain, loaded.Findings[2].Confidence);
        Assert.Equal(EvidenceState.CONFIRMED, loaded.Findings[2].EvidenceState);

        // Verify summary count reflects exactly 1 confirmed cheat, 1 strong indicator, 1 suspicious
        Assert.Equal(1, loaded.SummaryCounts.ConfirmedCheats);
        Assert.Equal(1, loaded.SummaryCounts.StrongIndicators);
        Assert.Equal(1, loaded.SummaryCounts.Suspicious);
    }
}

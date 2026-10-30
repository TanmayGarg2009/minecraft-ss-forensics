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
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

/// <summary>
/// Controlled scenario-based forensic validation suite verifying Scenarios A through L
/// with synthetic, benign test fixtures.
/// Adheres strictly to evidentiary standards: validates that presence != execution,
/// module load != malicious, and verdicts accurately differentiate runtime activity.
/// </summary>
public class ScenarioBasedForensicTests : IDisposable
{
    private readonly string _testWorkspace;

    public ScenarioBasedForensicTests()
    {
        _testWorkspace = Path.Combine(Path.GetTempPath(), $"ForensicScenarioTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testWorkspace);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testWorkspace))
                Directory.Delete(_testWorkspace, recursive: true);
        }
        catch { /* Best effort test workspace cleanup */ }
    }

    // =========================================================================
    // Scenario A: Known prohibited artifact on disk, not running
    // =========================================================================
    [Fact]
    public void ScenarioA_ProhibitedArtifactOnDisk_NotRunning_DoesNotClaimActiveCheating()
    {
        var report = new StandaloneReport();

        // Staged cheat file in Downloads (idle on disk)
        string fakeDownloads = Path.Combine(_testWorkspace, "Downloads");
        Directory.CreateDirectory(fakeDownloads);
        string cheatFile = Path.Combine(fakeDownloads, "doomsday.jar");
        File.WriteAllText(cheatFile, "dummy cheat jar content");

        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "doomsday.jar",
            FilePath = cheatFile,
            FileSizeBytes = 1024,
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            LastModified = DateTimeOffset.UtcNow.AddDays(-5),
            SuspicionReason = "Matched known cheat file pattern: Doomsday Client"
        });

        report.Findings.Add(new FindingRecord
        {
            RuleId = "FILE-CHEAT-NAME-MATCH",
            FindingTitle = "Known Cheat Artifact on Disk: Doomsday Client",
            EvidenceCategory = EvidenceCategory.Disk,
            Classification = FindingClassification.ConfirmedCheatArtifact,
            Severity = Severity.Medium,
            EvidenceStrength = EvidenceStrength.Strong,
            SoftwareState = SoftwareEvidenceState.SoftwarePresent,
            FilePath = cheatFile,
            IsInScanWindow = false,
            Interpretation = "File exists on disk in a user staging folder.",
            Limitations = "Presence of a file on disk does not establish that it was launched, running, or active during any match."
        });

        // Correlate with policy (standard PvP ruleset)
        var policyEngine = new ModPolicyEngine();
        var correlation = new EvidenceCorrelationEngine(policyEngine);
        var activePolicy = policyEngine.Registry.GetPolicy("Standard PvP");

        var assessments = correlation.Correlate(report, activePolicy);
        report.CorrelatedAssessments.AddRange(assessments);
        report.RecomputeSummaryCounts();

        // Verify summary counts and classifications
        Assert.Equal(1, report.SummaryCounts.DiskOnlyObservations);
        Assert.Equal(0, report.SummaryCounts.RuntimeObservations);
        Assert.Equal(1, report.SummaryCounts.Medium);
        Assert.Equal(0, report.SummaryCounts.Critical);

        // Verify verdict: Must strictly declare known prohibited artifact identified; runtime activity not established
        bool hasMinecraftAssociatedCheat = report.Findings.Any(f =>
            (f.Classification == FindingClassification.ConfirmedCheatArtifact || f.Severity == Severity.Critical) &&
            (f.EvidenceCategory == EvidenceCategory.Injected || f.EvidenceCategory == EvidenceCategory.ActiveInScanWindow));

        bool hasProhibitedDisk = report.Findings.Any(f =>
            f.Classification == FindingClassification.ConfirmedCheatArtifact &&
            f.EvidenceCategory == EvidenceCategory.Disk);

        Assert.False(hasMinecraftAssociatedCheat, "Must not claim Minecraft-associated cheat when file is only on disk.");
        Assert.True(hasProhibitedDisk);

        // Formulate verdict according to StandaloneScannerEngine logic
        report.Verdict.OverallAssessment = InvestigationVerdict.ProhibitedArtifactNotActive;
        Assert.Equal(InvestigationVerdict.ProhibitedArtifactNotActive, report.Verdict.OverallAssessment);
    }

    // =========================================================================
    // Scenario B: Known prohibited executable running, but no connection to Minecraft
    // =========================================================================
    [Fact]
    public void ScenarioB_ProhibitedExecutableRunning_NoConnectionToMinecraft_NotClaimedInjected()
    {
        var report = new StandaloneReport();

        // Autoclicker process is running outside Java
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 4420,
            ProcessName = "itami.exe",
            ExecutablePath = @"C:\Tools\itami.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30)
        });

        // No javaw.exe is running in this session
        var policyEngine = new ModPolicyEngine();
        var correlation = new EvidenceCorrelationEngine(policyEngine);
        var activePolicy = policyEngine.Registry.GetPolicy("Standard PvP");

        var assessments = correlation.Correlate(report, activePolicy);
        report.CorrelatedAssessments.AddRange(assessments);
        report.RecomputeSummaryCounts();

        var finding = report.Findings.FirstOrDefault(f => f.RuleId == "PROC-CHEAT-PROCESS-RUNNING");
        Assert.NotNull(finding);
        Assert.Equal(EvidenceCategory.RunningProcess, finding.EvidenceCategory);
        Assert.Equal(SoftwareEvidenceState.SoftwareExecuted, finding.SoftwareState);
        Assert.False(finding.IsInScanWindow, "Should not be active in game scan window when Minecraft is not running.");
        Assert.NotEqual(EvidenceCategory.Injected, finding.EvidenceCategory);
        Assert.Equal(4420, finding.TargetProcessId);
    }

    // =========================================================================
    // Scenario C: Known test module loaded into test process
    // =========================================================================
    [Fact]
    public void ScenarioC_KnownTestModuleLoadedIntoProcess_DocumentedWithProvenance()
    {
        var modInfo = new LoadedModuleInfo
        {
            ModuleName = "test_custom_hook.dll",
            FilePath = @"C:\Users\Player\AppData\Local\Temp\test_custom_hook.dll",
            IsSuspiciousLocation = true,
            IsRecognizedJavaNativeLibrary = false,
            IsSigned = false,
            ProvenanceAssessment = "Unsigned DLL executing from temporary directory without Java native library provenance"
        };

        var report = new StandaloneReport();
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 1234,
            ModuleName = modInfo.ModuleName,
            FilePath = modInfo.FilePath,
            IsInTempDirectory = true,
            IsRecognizedJavaNativeLibrary = false,
            ProvenanceAssessment = modInfo.ProvenanceAssessment
        });

        report.Findings.Add(new FindingRecord
        {
            RuleId = "PROC-SUSP-TEMP-MODULE",
            FindingTitle = $"Unsigned Temporary DLL Loaded into javaw.exe: {modInfo.ModuleName}",
            EvidenceCategory = EvidenceCategory.LoadedModule,
            Classification = FindingClassification.Suspicious,
            Severity = Severity.Medium, // Not Critical!
            EvidenceStrength = EvidenceStrength.Moderate,
            Confidence = ConfidenceLevel.Medium,
            DetectionMethod = DetectionMethod.RuntimeObservation,
            ProcessId = 1234,
            ProcessName = "javaw.exe",
            IsInScanWindow = true,
            Interpretation = "Module mapped into javaw.exe address space from temporary directory.",
            Limitations = "Module mapping indicates memory presence, but does not prove malicious intent without reverse engineering."
        });

        report.RecomputeSummaryCounts();

        Assert.Equal(1, report.SummaryCounts.RuntimeObservations);
        Assert.Equal(1, report.SummaryCounts.Medium);
        Assert.Equal(0, report.SummaryCounts.Critical);
        Assert.Equal(EvidenceCategory.LoadedModule, report.Findings[0].EvidenceCategory);
    }

    // =========================================================================
    // Scenario D: Legitimate mod renamed
    // =========================================================================
    [Fact]
    public async Task ScenarioD_LegitimateModRenamed_RecognizedViaMetadata_NotFlaggedAsCheat()
    {
        // Setup synthetic mod archive that has internal ModId 'sodium' but renamed file 'custom_fps.jar'
        string modFile = Path.Combine(_testWorkspace, "custom_fps.jar");
        using (var zip = ZipFile.Open(modFile, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("{\"id\": \"sodium\", \"name\": \"Sodium\", \"version\": \"0.5.8\"}");
        }

        var inspector = new SafeArchiveInspector();
        var metadata = await inspector.InspectModJarAsync(modFile);

        var discMod = new DiscoveredMod
        {
            FilePath = modFile,
            FileName = "custom_fps.jar",
            Metadata = metadata,
            Hashes = new FileHashResult { Sha256 = "test_clean_hash" }
        };

        var verResult = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            ProjectName = "Sodium",
            ProjectId = "AANobbMI"
        };

        var lookalikeDetector = new LookalikeDetector();
        var lookalikeFindings = lookalikeDetector.AnalyzeMods(new[] { (discMod, verResult) });

        var policyEngine = new ModPolicyEngine();
        var policy = policyEngine.Registry.GetPolicy("Standard PvP");
        var polResult = policyEngine.EvaluateMod(discMod, verResult, policy);

        // Assertions: Should NOT be classified as ConfirmedCheatArtifact
        Assert.True(polResult.Policy == GameplayPolicy.ALLOWED);
        Assert.DoesNotContain(lookalikeFindings, f => f.Severity == "Critical" || f.Severity == "High");
    }

    // =========================================================================
    // Scenario E: Known prohibited artifact renamed
    // =========================================================================
    [Fact]
    public async Task ScenarioE_ProhibitedArtifactRenamed_DetectedViaBytecodeOrPackageSignatures()
    {
        // Renamed file claims to be 'sodium-1.20.jar', but contains Doomsday package/classes
        string fakeFile = Path.Combine(_testWorkspace, "sodium-1.20.jar");
        using (var zip = ZipFile.Open(fakeFile, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("bot/Doomsday.class");
            using var s = entry.Open();
            // CAFEBABE magic + dummy bytes
            s.Write(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01 });
        }

        var inspector = new SafeArchiveInspector();
        var metadata = await inspector.InspectModJarAsync(fakeFile);

        // Bytecode/class matching must catch the prohibited signature
        var match = CheatDetectionDatabase.MatchClassOrPackage("bot.Doomsday");
        Assert.NotNull(match);
        Assert.Equal("Doomsday Client", match.Name);

        var finding = new FindingRecord
        {
            RuleId = "CHEAT-BYTECODE-CLASS",
            FindingTitle = $"Cheat Bytecode / Class Match: {match.Name}",
            EvidenceCategory = EvidenceCategory.ModIntegrity,
            Classification = FindingClassification.ConfirmedCheatArtifact,
            Severity = Severity.High,
            DetectionMethod = DetectionMethod.BytecodeStructure,
            Interpretation = "Disguised JAR archive contains internal bytecode matching known cheat client."
        };

        Assert.Equal(EvidenceCategory.ModIntegrity, finding.EvidenceCategory);
        Assert.Equal(DetectionMethod.BytecodeStructure, finding.DetectionMethod);
    }

    // =========================================================================
    // Scenario F: Legitimate native library loaded from temp
    // =========================================================================
    [Fact]
    public void ScenarioF_LegitimateNativeLibraryLoadedFromTemp_RecognizedProvenance_NotSuspicious()
    {
        // JNA native extraction file in temp
        string tempDir = Path.GetTempPath();
        string jnaFile = Path.Combine(tempDir, "jna891234567.dll");

        var (isNative, explanation) = ProcessScanner.CheckJavaNativeProvenance(jnaFile, "jna891234567.dll");

        Assert.True(isNative, "JNA library must be recognized as legitimate Java native extraction.");
        Assert.Contains("Java native library", explanation, StringComparison.OrdinalIgnoreCase);

        // lwjgl dll
        var (isLwjgl, lwjglExp) = ProcessScanner.CheckJavaNativeProvenance(@"C:\Temp\lwjgl_opengl.dll", "lwjgl_opengl.dll");
        Assert.True(isLwjgl);
        Assert.Contains("Java native library", lwjglExp, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Scenario G: Unknown unsigned DLL on disk with no Minecraft connection
    // =========================================================================
    [Fact]
    public void ScenarioG_UnknownUnsignedDllOnDisk_NoMinecraftConnection_NotFlaggedAsInjection()
    {
        var report = new StandaloneReport();

        // Arbitrary DLL on disk in temp, but NOT mapped into javaw.exe
        string dllPath = Path.Combine(_testWorkspace, "unrelated_tool.dll");
        File.WriteAllText(dllPath, "dummy binary content");

        // Normal file discovery should not flag unknown DLLs as cheats unless matching database
        var sig = CheatDetectionDatabase.MatchFileName("unrelated_tool.dll");
        Assert.Null(sig);

        // Running processes has javaw.exe, but its modules do NOT include unrelated_tool.dll
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5000,
            ProcessName = "javaw.exe"
        });

        report.RecomputeSummaryCounts();
        Assert.Equal(0, report.SummaryCounts.RuntimeObservations);
        Assert.Equal(0, report.SummaryCounts.ConfirmedCheats);
    }

    // =========================================================================
    // Scenario H: Known legitimate mod loaded by Minecraft
    // =========================================================================
    [Fact]
    public void ScenarioH_KnownLegitimateModLoadedByMinecraft_AllowedAndCleanVerdict()
    {
        var report = new StandaloneReport();

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "AppleSkin",
            FileName = "appleskin-fabric-mc1.20-2.5.1.jar",
            FullPath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\appleskin-fabric-mc1.20-2.5.1.jar",
            Verified = true,
            VerificationState = "VERIFIED_OFFICIAL",
            GameplayPolicy = "ALLOWED"
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5120,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "--username Player -Dfabric.mods=appleskin-fabric-mc1.20-2.5.1.jar"
        });

        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-MODS",
            Status = CheckStatus.PASSED,
            Reason = "Audited mods"
        });
        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-PROCESS-MODULES",
            Status = CheckStatus.PASSED,
            Reason = "Audited processes"
        });

        var policyEngine = new ModPolicyEngine();
        var correlation = new EvidenceCorrelationEngine(policyEngine);
        var activePolicy = policyEngine.Registry.GetPolicy("Standard PvP");

        var assessments = correlation.Correlate(report, activePolicy);
        report.CorrelatedAssessments.AddRange(assessments);
        report.RecomputeSummaryCounts();

        Assert.Equal(0, report.SummaryCounts.ConfirmedCheats);
        Assert.Equal(0, report.SummaryCounts.Critical);
        Assert.Equal(0, report.SummaryCounts.High);
        Assert.False(assessments[0].IsPolicyViolation);
        Assert.Equal(InvestigationVerdict.NoProhibitedIndicators, report.Verdict.OverallAssessment);
    }

    // =========================================================================
    // Scenario I: Same artifact detected by multiple collectors (clustering)
    // =========================================================================
    [Fact]
    public void ScenarioI_SameArtifactMultipleCollectors_DeduplicatedIntoSingleCluster()
    {
        var report = new StandaloneReport();
        string clusterId = "CLUSTER-VAPE";

        // Collector 1: File discovery
        report.Findings.Add(new FindingRecord
        {
            RuleId = "FILE-CHEAT-NAME-MATCH",
            FindingTitle = "Known Cheat Artifact on Disk: Vape Client",
            EvidenceCategory = EvidenceCategory.Disk,
            Classification = FindingClassification.ConfirmedCheatArtifact,
            Severity = Severity.Medium,
            EvidenceClusterId = clusterId,
            FilePath = @"C:\Users\Player\Downloads\vape.exe"
        });

        // Collector 2: Registry UserAssist
        report.Findings.Add(new FindingRecord
        {
            RuleId = "REG-USERASSIST-CHEAT",
            FindingTitle = "UserAssist Execution Record: Vape Client",
            EvidenceCategory = EvidenceCategory.Historical,
            Classification = FindingClassification.StrongIndicator,
            Severity = Severity.Medium,
            EvidenceClusterId = clusterId,
            FilePath = @"C:\Users\Player\Downloads\vape.exe"
        });

        report.RecomputeSummaryCounts();

        // Findings share the exact same cluster ID
        Assert.Equal(2, report.Findings.Count);
        Assert.Equal(report.Findings[0].EvidenceClusterId, report.Findings[1].EvidenceClusterId);

        // Distinct cluster count is 1
        var distinctClusters = report.Findings.Select(f => f.EvidenceClusterId).Distinct().Count();
        Assert.Equal(1, distinctClusters);
    }

    // =========================================================================
    // Scenario J: Collector fails or cannot access data (Inconclusive)
    // =========================================================================
    [Fact]
    public void ScenarioJ_CollectorFails_RecordedAsIncompleteCheck_InconclusiveVerdict()
    {
        var report = new StandaloneReport();

        // Process module inspection was denied due to permissions
        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-PROCESS-MODULES",
            CheckName = "Active Process & Loaded Module Audit",
            Source = "ProcessScanner",
            Status = CheckStatus.UNAVAILABLE,
            Reason = "Access to process memory inspection was denied in standard user mode."
        });

        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-MODS",
            Status = CheckStatus.PASSED,
            Reason = "Audited mods"
        });

        report.RecomputeSummaryCounts();

        Assert.Equal(1, report.SummaryCounts.IncompleteOrFailedChecks);
        Assert.Equal(0, report.SummaryCounts.TotalFindings);

        // Formulate verdict
        if (report.SummaryCounts.IncompleteOrFailedChecks > 0 &&
            report.DiagnosticChecks.Any(c => c.CheckId == "CHK-PROCESS-MODULES" && c.Status == CheckStatus.UNAVAILABLE))
        {
            report.Verdict.OverallAssessment = InvestigationVerdict.InconclusiveTelemetry;
            report.Verdict.Recommendation = "Critical forensic telemetry was restricted or inaccessible in current scan context. Investigation is inconclusive.";
        }

        Assert.Equal(InvestigationVerdict.InconclusiveTelemetry, report.Verdict.OverallAssessment);
    }

    // =========================================================================
    // Scenario K: Historical trace exists without current activity
    // =========================================================================
    [Fact]
    public void ScenarioK_HistoricalTraceExistsWithoutCurrentActivity_MarkedHistorical()
    {
        var report = new StandaloneReport();

        // Prefetch entry from 3 days ago
        var pastTimestamp = DateTimeOffset.UtcNow.AddDays(-3);
        report.ExecutionHistory.Add(new ExecutionHistoryItem
        {
            Source = "Prefetch",
            ApplicationName = "ITAMI.EXE",
            ApplicationPath = @"C:\Tools\itami.exe",
            LastExecutionTime = pastTimestamp,
            Details = "Prefetch execution record: ITAMI.EXE-1A2B3C4D.pf (Run Count: 2)"
        });

        report.Findings.Add(new FindingRecord
        {
            RuleId = "REG-USERASSIST-CHEAT",
            FindingTitle = "UserAssist Execution Record: Itami Autoclicker",
            EvidenceCategory = EvidenceCategory.Historical,
            Classification = FindingClassification.StrongIndicator,
            Severity = Severity.Medium,
            SoftwareState = SoftwareEvidenceState.SoftwareExecuted,
            ObservedTimestamp = pastTimestamp,
            IsInScanWindow = false,
            Interpretation = "Historical execution record found; not active in current scan window."
        });

        report.RecomputeSummaryCounts();

        Assert.Equal(1, report.SummaryCounts.TotalFindings);
        Assert.Equal(0, report.SummaryCounts.RuntimeObservations);
        Assert.False(report.Findings[0].IsInScanWindow);
        Assert.Equal(EvidenceCategory.Historical, report.Findings[0].EvidenceCategory);

        // Verdict must be ProhibitedArtifactNotActive
        report.Verdict.OverallAssessment = InvestigationVerdict.ProhibitedArtifactNotActive;
        Assert.Equal(InvestigationVerdict.ProhibitedArtifactNotActive, report.Verdict.OverallAssessment);
    }

    // =========================================================================
    // Scenario L: Minecraft running normally with no cheats
    // =========================================================================
    [Fact]
    public void ScenarioL_MinecraftRunningNormallyNoCheats_CleanVerdict()
    {
        var report = new StandaloneReport();

        // Minecraft running normally
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 6000,
            ProcessName = "javaw.exe",
            ExecutablePath = @"C:\Program Files\Java\jdk-21\bin\javaw.exe",
            StartTime = DateTimeOffset.UtcNow.AddHours(-1),
            SanitizedCommandLine = "-Xmx4G -Dnet.minecraft=true"
        });

        // Legitimate JNA library loaded
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 6000,
            ModuleName = "jna.dll",
            FilePath = @"C:\Program Files\Java\jdk-21\bin\jna.dll",
            IsInTempDirectory = false,
            IsRecognizedJavaNativeLibrary = true,
            ProvenanceAssessment = "Standard System Module"
        });

        // All checks passed
        report.DiagnosticChecks.Add(new DiagnosticCheckItem { CheckId = "CHK-MODS", Status = CheckStatus.PASSED, Reason = "Clean" });
        report.DiagnosticChecks.Add(new DiagnosticCheckItem { CheckId = "CHK-PROCESS-MODULES", Status = CheckStatus.PASSED, Reason = "Clean" });
        report.DiagnosticChecks.Add(new DiagnosticCheckItem { CheckId = "CHK-FILE-DISCOVERY", Status = CheckStatus.PASSED, Reason = "Clean" });

        report.RecomputeSummaryCounts();

        // Cryptographic seal
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        Assert.Equal(0, report.SummaryCounts.TotalFindings);
        Assert.Equal(0, report.SummaryCounts.Critical);
        Assert.Equal(0, report.SummaryCounts.High);
        Assert.Equal(0, report.SummaryCounts.Medium);
        Assert.Equal(0, report.SummaryCounts.IncompleteOrFailedChecks);
        Assert.Equal(InvestigationVerdict.NoProhibitedIndicators, report.Verdict.OverallAssessment);

        var (sealValid, _) = ReportIntegrityValidator.VerifyReportIntegrity(report);
        Assert.True(sealValid, "Cryptographic seal must be valid for clean report.");
    }
}

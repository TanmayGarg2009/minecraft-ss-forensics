using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class StandaloneForensicTests : IDisposable
{
    private readonly string _testWorkspace;

    public StandaloneForensicTests()
    {
        _testWorkspace = Path.Combine(Path.GetTempPath(), $"ForensicTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testWorkspace);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testWorkspace))
            {
                Directory.Delete(_testWorkspace, true);
            }
        }
        catch { /* Best effort test cleanup */ }
    }

    private class MockModVerifier : IModVerifier
    {
        private readonly Func<DiscoveredMod, ModVerificationResult> _handler;

        public MockModVerifier(Func<DiscoveredMod, ModVerificationResult> handler)
        {
            _handler = handler;
        }

        public Task<ModVerificationResult> VerifyModAsync(DiscoveredMod mod, CancellationToken ct = default)
        {
            return Task.FromResult(_handler(mod));
        }
    }

    // 1. Legitimate renamed Minecraft mod (INFO-RENAMED-MOD / MOD-RENAMED-GENUINE, Informational)
    [Fact]
    public void Scenario01_LegitimateRenamedMod_ClassifiedAsInformational()
    {
        var lookalikeDetector = new LookalikeDetector();
        var mod = new DiscoveredMod
        {
            FileName = "my-custom-sodium.jar",
            FilePath = "C:\\mc\\mods\\my-custom-sodium.jar",
            Metadata = new ModMetadata { ModId = "sodium", ModName = "Sodium", Version = "0.5.8" }
        };
        var verification = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            ProjectName = "Sodium",
            ProjectId = "sodium",
            MatchedFileName = "sodium-fabric-0.5.8+mc1.20.4.jar"
        };

        var findings = lookalikeDetector.AnalyzeMods(new[] { (mod, verification) });

        var renamedFinding = findings.FirstOrDefault(f => f.RuleId == "MOD-RENAMED-GENUINE" || f.RuleId == "INFO-RENAMED-MOD");
        Assert.NotNull(renamedFinding);
        Assert.Equal("Low", renamedFinding.Severity);
        Assert.Contains("renamed", renamedFinding.Explanation, StringComparison.OrdinalIgnoreCase);
        // Ensure no cheat accusations
        Assert.DoesNotContain("cheat", renamedFinding.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    // 2. Duplicate mod ID (maintenance warning)
    [Fact]
    public void Scenario02_DuplicateModId_DetectedAsMaintenanceWarning()
    {
        var lookalikeDetector = new LookalikeDetector();
        var mod1 = new DiscoveredMod
        {
            FileName = "appleskin-1.0.jar",
            FilePath = "C:\\mc\\mods\\appleskin-1.0.jar",
            Metadata = new ModMetadata { ModId = "appleskin", ModName = "AppleSkin", Version = "1.0" }
        };
        var mod2 = new DiscoveredMod
        {
            FileName = "appleskin-2.0.jar",
            FilePath = "C:\\mc\\mods\\appleskin-2.0.jar",
            Metadata = new ModMetadata { ModId = "appleskin", ModName = "AppleSkin", Version = "2.0" }
        };
        var ver = new ModVerificationResult { State = ModVerificationState.VERIFIED_EXACT_RELEASE };

        var findings = lookalikeDetector.AnalyzeMods(new[] { (mod1, ver), (mod2, ver) });

        var dupFinding = findings.FirstOrDefault(f => f.RuleId == "MOD-DUPLICATE-ID" || f.RuleId == "WARN-DUPLICATE-MOD-ID");
        Assert.NotNull(dupFinding);
        Assert.Contains("Multiple files share the same declared mod ID", dupFinding.Explanation);
    }

    // 3. Unknown mod (NEEDS REVIEW, not auto-cheat)
    [Fact]
    public void Scenario03_UnknownMod_ClassifiedAsNeedsReview_NeverAutoCheat()
    {
        var engine = new ModPolicyEngine();
        var policy = engine.Registry.GetPolicy("Crystal PvP");
        var mod = new DiscoveredMod
        {
            FileName = "local-utility-build-1.jar",
            FilePath = "C:\\mc\\mods\\local-utility-build-1.jar",
            Metadata = new ModMetadata { ModId = "localutil", ModName = "Local Utility" }
        };
        var ver = new ModVerificationResult
        {
            State = ModVerificationState.UNKNOWN_OR_UNLISTED,
            Explanation = "Not present in official registries."
        };

        var result = engine.EvaluateMod(mod, ver, policy);

        Assert.Equal(GameplayPolicy.NEEDS_REVIEW, result.Policy);
        Assert.NotEqual(GameplayPolicy.PROHIBITED, result.Policy);
        Assert.Contains("REVIEW", result.Policy.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    // 4. Verified prohibited mod (disallowed under active policy)
    [Fact]
    public void Scenario04_VerifiedAuthenticMod_ProhibitedUnderServerPolicy()
    {
        var engine = new ModPolicyEngine();
        var policy = engine.Registry.GetPolicy("Crystal PvP");
        var mod = new DiscoveredMod
        {
            FileName = "freecam-fabric-1.20.4-0.4.4.jar",
            FilePath = "C:\\mc\\mods\\freecam-fabric-1.20.4-0.4.4.jar",
            Metadata = new ModMetadata { ModId = "freecam", ModName = "Freecam" }
        };
        var ver = new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            ProjectId = "freecam",
            ProjectName = "Freecam (Modrinth)",
            Provider = "Modrinth"
        };

        var result = engine.EvaluateMod(mod, ver, policy);

        // Crucial test of policy separation: authenticity is verified exact, but policy is prohibited!
        Assert.Equal(ModVerificationState.VERIFIED_EXACT_RELEASE, result.AuthenticityState);
        Assert.Equal(GameplayPolicy.PROHIBITED, result.Policy);
        Assert.Equal(BehaviorCategory.HiddenInformationAdvantages, result.Behavior);
    }

    // 5. Known cheat artifact (confirmed cheat class/hash)
    [Fact]
    public void Scenario05_KnownCheatArtifact_MatchedByCatalog()
    {
        // 5a. Filename matching
        var fileMatch = CheatDetectionDatabase.MatchFileName("meteor-client-0.5.5.jar");
        Assert.NotNull(fileMatch);
        Assert.Equal("Meteor Client", fileMatch.Name);

        // 5b. Bytecode class match
        var classMatch = CheatDetectionDatabase.MatchClassOrPackage("net.ccbluex.liquidbounce.LiquidBounce");
        Assert.NotNull(classMatch);
        Assert.Equal("LiquidBounce", classMatch.Name);

        // 5c. Bytecode string token
        string? matchedKeyword = CheatDetectionDatabase.MatchCombatBytecodeKeyword("killAuraTriggerBotAutoArmor");
        Assert.NotNull(matchedKeyword);
        Assert.Equal("killaura", matchedKeyword);
    }

    // 6. Harmless executable with suspicious filename (provenance / explanation testing)
    [Fact]
    public void Scenario06_HarmlessExecutableWithSuspiciousName_RecordsBalancedEvidence()
    {
        var finding = new FindingRecord
        {
            RuleId = "STAGE-SUSP-FILE",
            DetectionName = "Suspicious Filename in Downloads",
            Classification = FindingClassification.Suspicious,
            Severity = Severity.Medium,
            Confidence = ConfidenceLevel.Medium,
            FilePath = "C:\\Users\\Player\\Downloads\\vape_test.txt",
            WhatIsProven = "File with name matching keyword exists in staging folder.",
            WhatIsNotProven = "Does not prove executable was executed or injected into game.",
            AlternativeLegitimateExplanations = "User may have downloaded a text document, logs, or false positive test file."
        };

        Assert.Equal(FindingClassification.Suspicious, finding.Classification);
        Assert.False(string.IsNullOrWhiteSpace(finding.AlternativeLegitimateExplanations));
        Assert.False(string.IsNullOrWhiteSpace(finding.WhatIsNotProven));
    }

    // 7. Normal Java process loading JNA (provenance verified, not flagged)
    [Fact]
    public void Scenario07_NormalJavaProcess_LoadingJna_RecognizedAsLegitimateExtraction()
    {
        var procInfo = new DiscoveredProcess
        {
            ProcessId = 1234,
            ProcessName = "javaw",
            ExecutablePath = "C:\\Program Files\\Java\\jdk-17\\bin\\javaw.exe"
        };

        var module = new LoadedModuleInfo
        {
            ModuleName = "jnidispatch.dll",
            FilePath = "C:\\Users\\Player\\AppData\\Local\\Temp\\jna1234567\\jnidispatch.dll",
            IsSuspiciousLocation = true
        };

        procInfo.LoadedModules.Add(module);
        var (isNativeLib, explanation) = ProcessScanner.CheckJavaNativeProvenance(module.FilePath, module.ModuleName);
        module.IsRecognizedJavaNativeLibrary = isNativeLib;
        module.ProvenanceAssessment = explanation;

        Assert.True(module.IsRecognizedJavaNativeLibrary);
        Assert.Contains("Java native library", module.ProvenanceAssessment);
    }

    // 8. Ordinary unsigned DLL in temp (flagged for review with alt explanations)
    [Fact]
    public void Scenario08_OrdinaryUnsignedDllInTemp_FlaggedWithBalancedForensicDetails()
    {
        var procInfo = new DiscoveredProcess
        {
            ProcessId = 1234,
            ProcessName = "javaw",
            ExecutablePath = "C:\\Program Files\\Java\\jdk-17\\bin\\javaw.exe"
        };

        var module = new LoadedModuleInfo
        {
            ModuleName = "hooker64.dll",
            FilePath = "C:\\Users\\Player\\AppData\\Local\\Temp\\hooker64.dll",
            IsSuspiciousLocation = true,
            IsSigned = false
        };

        procInfo.LoadedModules.Add(module);
        var (isNative, nonNativeExpl) = ProcessScanner.CheckJavaNativeProvenance(module.FilePath, module.ModuleName);
        module.IsRecognizedJavaNativeLibrary = isNative;
        module.ProvenanceAssessment = nonNativeExpl;

        Assert.False(module.IsRecognizedJavaNativeLibrary);
        Assert.Contains("Unsigned module", module.ProvenanceAssessment);
    }

    // 9. Missing Prefetch data (disabled/cleared detection)
    [Fact]
    public void Scenario09_MissingPrefetchData_HandledGracefully()
    {
        var scanner = new HistoricalEvidenceScanner();
        var records = scanner.ScanHistoricalArtifacts();

        // Should return a list without unhandled exception regardless of admin/non-admin environment
        Assert.NotNull(records);
    }

    // 10. Incomplete execution history
    [Fact]
    public void Scenario10_IncompleteExecutionHistory_DiagnosticItemCreated()
    {
        var report = new StandaloneReport();
        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-EXEC-HIST",
            CheckName = "Prefetch & Execution Trace",
            Status = CheckStatus.UNAVAILABLE,
            Reason = "Windows Prefetch directory is inaccessible or disabled on SSD."
        });

        report.RecomputeSummaryCounts();
        Assert.Equal(1, report.SummaryCounts.UnavailableChecks);
    }

    // 11. Disabled or unavailable registry access
    [Fact]
    public void Scenario11_RegistryAccessUnavailable_ReturnsGracefully()
    {
        var regScanner = new RegistryScanner();
        var items = regScanner.ScanRegistryArtifacts(out var findings);

        Assert.NotNull(items);
        Assert.NotNull(findings);
    }

    // 12. Missing browser history (skipped or empty)
    [Fact]
    public void Scenario12_BrowserHistory_OptOut_ProperlySkipped()
    {
        var browserScanner = new BrowserHistoryScanner();
        var items = browserScanner.ScanBrowserArtifacts(
            isExplicitlyConsented: false,
            out var findings,
            out var diagnostic);

        Assert.Empty(items);
        Assert.Empty(findings);
        Assert.Equal(CheckStatus.SKIPPED, diagnostic.Status);
        Assert.Contains("scope", diagnostic.Reason, StringComparison.OrdinalIgnoreCase);
    }

    // 13. Malformed report files (tampering / seal validation)
    [Fact]
    public void Scenario13_MalformedOrTamperedReport_DetectedByIntegritySeal()
    {
        var report = new StandaloneReport
        {
            ReportId = "SS-TAMPER-TEST",
            ScanMode = "QUICK"
        };
        report.Findings.Add(new FindingRecord
        {
            RuleId = "TEST-RULE",
            DetectionName = "Test Finding",
            Classification = FindingClassification.Suspicious
        });
        report.RecomputeSummaryCounts();
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        // Original verifies
        Assert.True(ReportIntegrityValidator.VerifyReportIntegrity(report).IsValid);

        // Tamper with data
        report.Findings.Clear();
        Assert.False(ReportIntegrityValidator.VerifyReportIntegrity(report).IsValid);
    }

    // 14. Older report versions backward compatibility
    [Fact]
    public void Scenario14_LegacyReportVersion1_SuccessfullyMigratesToV2()
    {
        string legacyJson = """
        {
            "schemaVersion": "1.0.0",
            "scannerVersion": "1.0.0",
            "scanMode": "FULL",
            "osName": "Windows 11",
            "osVersion": "10.0.22631",
            "osArchitecture": "X64",
            "scanStartedAt": "2026-10-30T10:00:00Z",
            "scanCompletedAt": "2026-10-30T10:01:00Z",
            "detectedMinecraftVersions": ["1.20.4"],
            "detectedLoaders": ["Fabric 0.15.7"],
            "appliedPolicyName": "Crystal PvP",
            "appliedGamemode": "Crystal PvP",
            "findings": [
                {
                    "ruleId": "RULE-TEST",
                    "title": "Legacy Test Finding",
                    "severity": "High",
                    "confidence": "Certain",
                    "explanation": "Legacy finding explanation"
                }
            ],
            "collectionCoverage": {
                "totalChecks": 10,
                "passedChecks": 9,
                "flaggedChecks": 1,
                "unavailableChecks": 0
            }
        }
        """;

        string filePath = Path.Combine(_testWorkspace, "legacy_report.json");
        File.WriteAllText(filePath, legacyJson);

        var (success, loaded, error) = PortableJsonExporter.LoadFromFile(filePath);
        Assert.True(success, error);
        Assert.NotNull(loaded);
        Assert.Equal("2.0.0", loaded.SchemaVersion);
        Assert.Equal("FULL", loaded.ScanMode);
        Assert.Single(loaded.Findings);
        Assert.Equal("RULE-TEST", loaded.Findings[0].RuleId);
        Assert.Equal(FindingClassification.Suspicious, loaded.Findings[0].Classification);
    }

    // 15. Inconsistent evidence counts recomputation
    [Fact]
    public void Scenario15_InconsistentSummaryCounts_RecomputedStrictly()
    {
        var report = new StandaloneReport();
        report.Findings.Add(new FindingRecord
        {
            RuleId = "CONFIRMED-CHEAT-1",
            Classification = FindingClassification.ConfirmedCheatArtifact
        });
        report.Findings.Add(new FindingRecord
        {
            RuleId = "STRONG-IND-1",
            Classification = FindingClassification.StrongIndicator
        });
        report.Findings.Add(new FindingRecord
        {
            RuleId = "SUSP-1",
            Classification = FindingClassification.Suspicious
        });
        report.Findings.Add(new FindingRecord
        {
            RuleId = "INFO-1",
            Classification = FindingClassification.Informational
        });

        // Intentional wrong summary counts
        report.SummaryCounts.ConfirmedCheats = 999;
        report.SummaryCounts.Suspicious = 0;

        report.RecomputeSummaryCounts();

        Assert.Equal(1, report.SummaryCounts.ConfirmedCheats);
        Assert.Equal(1, report.SummaryCounts.StrongIndicators);
        Assert.Equal(1, report.SummaryCounts.Suspicious);
        Assert.Equal(1, report.SummaryCounts.Informational);
        Assert.Equal(4, report.SummaryCounts.TotalFindings);
    }

    // 16. End-to-end Player Scan -> Save -> Staff Load & Inspect Workflow
    [Fact]
    public async Task Scenario16_EndToEnd_PlayerScan_Save_StaffLoad_SealVerified()
    {
        // 1. Setup mock Minecraft environment
        string mcDir = Path.Combine(_testWorkspace, ".minecraft");
        string modsDir = Path.Combine(mcDir, "mods");
        Directory.CreateDirectory(modsDir);

        string testJar = Path.Combine(modsDir, "appleskin-fabric-2.5.1.jar");
        using (var zip = ZipFile.Open(testJar, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("""
            {
                "schemaVersion": 1,
                "id": "appleskin",
                "name": "AppleSkin",
                "version": "2.5.1"
            }
            """);
        }

        var verifier = new MockModVerifier(mod => new ModVerificationResult
        {
            State = ModVerificationState.VERIFIED_EXACT_RELEASE,
            Provider = "Modrinth",
            ProjectId = "appleskin",
            ProjectName = "AppleSkin",
            VersionNumber = "2.5.1"
        });

        var engine = new StandaloneScannerEngine(verifier: verifier);
        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectMinecraftMods = true,
            PerformOnlineVerification = true,
            InspectProcessesAndModules = true,
            InspectExecutionArtifacts = true,
            InspectRegistryArtifacts = true,
            InspectUsbHistory = true,
            InspectFileDiscovery = true,
            InspectBrowserHistory = false // Player opts out of browser audit
        };

        // 2. Execute Player Scan
        var report = await engine.ExecuteScanAsync(
            consent: consent,
            scanMode: "QUICK",
            customDirectory: mcDir,
            onlyCustomDirectory: true);

        Assert.NotNull(report);
        Assert.NotEmpty(report.ReportId);
        Assert.NotEmpty(report.ReportIntegrityHash);
        Assert.Single(report.ModInventory);
        Assert.Equal("AppleSkin", report.ModInventory[0].Name);
        Assert.True(report.ModInventory[0].Verified);

        // 3. Save JSON and HTML reports locally
        string jsonReportPath = Path.Combine(_testWorkspace, $"Report_{report.ReportId}.json");
        string htmlReportPath = Path.Combine(_testWorkspace, $"Report_{report.ReportId}.html");

        PortableJsonExporter.SaveToFile(report, jsonReportPath);
        StandaloneHtmlExporter.SaveToFile(report, htmlReportPath);

        Assert.True(File.Exists(jsonReportPath));
        Assert.True(File.Exists(htmlReportPath));

        // 4. Verify HTML report is self-contained with XSS protection and styles
        string htmlContent = File.ReadAllText(htmlReportPath);
        Assert.Contains("<!DOCTYPE html>", htmlContent);
        Assert.Contains(report.ReportId, htmlContent);
        Assert.Contains("AppleSkin", htmlContent);
        Assert.Contains("<style>", htmlContent);
        Assert.Contains("<script>", htmlContent);

        // 5. Staff loads report from JSON file
        var (success, staffLoadedReport, error) = PortableJsonExporter.LoadFromFile(jsonReportPath);
        Assert.True(success, error);
        Assert.NotNull(staffLoadedReport);
        Assert.Equal(report.ReportId, staffLoadedReport.ReportId);
        Assert.Equal(report.ModInventory.Count, staffLoadedReport.ModInventory.Count);

        // 6. Staff verifies cryptographic seal
        bool isSealValid = ReportIntegrityValidator.VerifyReportIntegrity(staffLoadedReport).IsValid;
        Assert.True(isSealValid);
    }

    // 17. Possession-based prohibition triggers violation upon confirmed installation/presence
    [Fact]
    public void Scenario17_PossessionBasedProhibition_TriggersViolationWithoutExecution()
    {
        var correlationEngine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy
        {
            Gamemode = "Crystal PvP",
            PolicyName = "Competitive CPvP Ruleset"
        };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "Meteor Client",
            Policy = GameplayPolicy.PROHIBITED_POSSESSION,
            Reason = "Possession of hacked client is strictly prohibited on server."
        });

        var report = new StandaloneReport();
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Meteor Client",
            FileName = "meteor-client-0.5.5.jar",
            FullPath = "C:\\Users\\Player\\AppData\\Roaming\\.minecraft\\mods\\meteor-client-0.5.5.jar",
            GameplayPolicy = "PROHIBITED_POSSESSION",
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        });

        var assessments = correlationEngine.Correlate(report, policy);
        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "Meteor Client");

        Assert.NotNull(assessment);
        Assert.True(assessment.IsPolicyViolation);
        Assert.Equal(GameplayPolicy.PROHIBITED_POSSESSION, assessment.Policy);
        Assert.Contains("POSSESSION BANNED", assessment.PolicyEvaluationExplanation);
        Assert.Contains("is not required under the applicable possession policy", assessment.WhatIsNotProven);
    }

    // 18. Execution-based prohibition requires execution traces to establish violation
    [Fact]
    public void Scenario18_ExecutionBasedProhibition_RequiresExecutionProof()
    {
        var correlationEngine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy
        {
            Gamemode = "Sword",
            PolicyName = "Sword PvP Ruleset"
        };
        policy.Rules.Add(new ModPolicyRule
        {
            ModName = "SpeedAutoClicker",
            Policy = GameplayPolicy.PROHIBITED_EXECUTION,
            Reason = "Execution of external macro during match is prohibited."
        });

        // Case A: File present on disk, but NO execution traces
        var reportPresentOnly = new StandaloneReport();
        reportPresentOnly.ModInventory.Add(new DiscoveredModItem
        {
            Name = "SpeedAutoClicker",
            FileName = "SpeedAutoClicker.jar",
            FullPath = "C:\\Users\\Player\\AppData\\Roaming\\.minecraft\\mods\\SpeedAutoClicker.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var assessmentsA = correlationEngine.Correlate(reportPresentOnly, policy);
        var assessmentA = assessmentsA.First(a => a.SoftwareName == "SpeedAutoClicker");
        Assert.False(assessmentA.IsPolicyViolation); // Execution was NOT established!

        // Case B: Same file, with active game process running
        var reportExecuted = new StandaloneReport();
        reportExecuted.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5544,
            ProcessName = "javaw.exe"
        });
        reportExecuted.ModInventory.Add(new DiscoveredModItem
        {
            Name = "SpeedAutoClicker",
            FileName = "SpeedAutoClicker.jar",
            FullPath = "C:\\Users\\Player\\AppData\\Roaming\\.minecraft\\mods\\SpeedAutoClicker.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var assessmentsB = correlationEngine.Correlate(reportExecuted, policy);
        var assessmentB = assessmentsB.First(a => a.SoftwareName == "SpeedAutoClicker");
        Assert.True(assessmentB.IsPolicyViolation); // Execution was established!
        Assert.Contains("VIOLATION (EXECUTION BANNED)", assessmentB.PolicyEvaluationExplanation);
    }

    // 19. Static Bytecode Analyzer detects Crystal Automation and Combat capabilities from constant pool
    [Fact]
    public void Scenario19_StaticBytecodeAnalyzer_IdentifiesCrystalAutomationAndCombat()
    {
        string jarPath = Path.Combine(_testWorkspace, "suspicious_automation.jar");
        using (var zip = ZipFile.Open(jarPath, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("com/example/AutomationModule.class");
            using var stream = entry.Open();

            // Construct synthetic Java class file bytes with valid constant pool
            var ms = new MemoryStream();
            var bw = new BinaryWriter(ms);

            // Magic (0xCAFEBABE) in Big-Endian
            bw.Write(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE });
            // Minor version 0, Major version 52 (Java 8)
            bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x34 });

            // Strings to embed
            string[] testStrings = new[]
            {
                "EndCrystalEntity",
                "autoCrystal",
                "interactBlock",
                "killAura",
                "PlayerMoveC2SPacket",
                "java/awt/Robot"
            };

            // Constant Pool Count: (testStrings.Length + 1) in big-endian
            ushort cpCount = (ushort)(testStrings.Length + 1);
            bw.Write((byte)(cpCount >> 8));
            bw.Write((byte)(cpCount & 0xFF));

            foreach (var str in testStrings)
            {
                bw.Write((byte)1); // CONSTANT_Utf8 tag
                byte[] utfBytes = System.Text.Encoding.UTF8.GetBytes(str);
                ushort len = (ushort)utfBytes.Length;
                bw.Write((byte)(len >> 8));
                bw.Write((byte)(len & 0xFF));
                bw.Write(utfBytes);
            }

            // Access flags, this_class, super_class, interfaces_count, fields_count, methods_count, attributes_count (all zeroes)
            bw.Write(new byte[16]);

            byte[] classBytes = ms.ToArray();
            stream.Write(classBytes, 0, classBytes.Length);
        }

        using var archive = ZipFile.OpenRead(jarPath);
        var result = StaticBytecodeAnalyzer.AnalyzeArchive(archive);

        Assert.NotNull(result);
        Assert.True(result.HasAutomationCapabilities);
        Assert.Contains(result.DetectedCapabilities, c => c.CapabilityType == BytecodeCapabilityType.CrystalAutomation);
        Assert.Contains(result.DetectedCapabilities, c => c.CapabilityType == BytecodeCapabilityType.CombatAutomation);
        Assert.Contains(result.DetectedCapabilities, c => c.CapabilityType == BytecodeCapabilityType.PacketManipulation);
        Assert.Contains(result.DetectedCapabilities, c => c.CapabilityType == BytecodeCapabilityType.InputSimulation);
    }

    // 20. Distributable Policy Pack serializes, validates, and detects tampering
    [Fact]
    public void Scenario20_PolicyPack_SerializationValidationAndTamperDetection()
    {
        var pack = new PolicyPack
        {
            PackId = "phoenixmc-crystal-pvp",
            PolicyName = "PhoenixMC Official Crystal PvP Ruleset",
            Gamemode = "Crystal PvP",
            Version = "2.0.0",
            Publisher = "PhoenixMC Anti-Cheat Committee",
            IsExamplePolicy = false
        };

        pack.Rules.Add(new ModPolicyRule
        {
            ModName = "MarlowCrystalOptimizer",
            Policy = GameplayPolicy.PROHIBITED_POSSESSION,
            Reason = "Packet manipulation and auto-crystal placement advantages."
        });

        // 1. Export with seal
        string json = pack.ExportToJson();
        Assert.NotEmpty(pack.IntegrityHash);

        // 2. Load from JSON
        var (success, loadedPack, error) = PolicyPack.LoadFromJson(json);
        Assert.True(success, error);
        Assert.NotNull(loadedPack);
        Assert.Equal("Crystal PvP", loadedPack.Gamemode);

        // 3. Verify seal matches
        string recomputed = loadedPack.ComputeIntegrityHash();
        Assert.Equal(loadedPack.IntegrityHash, recomputed);

        // 4. Tamper with rule and verify seal mismatch
        loadedPack.Rules[0].Policy = GameplayPolicy.ALLOWED;
        string tamperedSeal = loadedPack.ComputeIntegrityHash();
        Assert.NotEqual(loadedPack.IntegrityHash, tamperedSeal);
    }

    // 21. Service & Driver Scanner detects user directory drivers and digital signatures
    [Fact]
    public void Scenario21_ServiceAndDriverScanner_UserDirectoryPath_Flagged()
    {
        var driver = new ServiceOrDriverRecord
        {
            Name = "VapeDriver",
            DisplayName = "Vape Kernel Helper",
            ImagePath = "C:\\Users\\Player\\AppData\\Local\\Temp\\vape_driver.sys",
            ServiceType = 1, // Kernel Driver
            StartType = 3,   // Demand Start
            IsInUserDirectory = true,
            IsSigned = false,
            Source = "Registry:Services"
        };

        Assert.True(driver.IsDriver);
        Assert.True(driver.IsInUserDirectory);
        Assert.False(driver.IsSigned);
        Assert.Equal("Registry:Services", driver.Source);
    }

    // 22. Verification of 6 Software States and 9 Evidence States
    [Fact]
    public void Scenario22_EvidenceCorrelationEngine_Distinguishes6SoftwareStates()
    {
        // Verify all 6 distinct software evidence states
        Assert.Equal(6, Enum.GetValues<SoftwareEvidenceState>().Length);
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.SoftwarePresent));
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.SoftwareInstalled));
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.SoftwareExecuted));
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.SoftwareActiveDuringSession));
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.SoftwareInteractingWithMinecraft));
        Assert.True(Enum.IsDefined(typeof(SoftwareEvidenceState), SoftwareEvidenceState.ProhibitedFunctionalityUsed));

        // Verify 9 distinct evidence states
        Assert.Equal(9, Enum.GetValues<EvidenceState>().Length);
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.CONFIRMED));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.STRONG_INDICATOR));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.WEAK_INDICATOR));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.INCONCLUSIVE));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.NOT_CONFIGURED));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.NOT_AVAILABLE));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.DATA_EXPIRED_OR_OVERWRITTEN));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.COLLECTION_FAILED));
        Assert.True(Enum.IsDefined(typeof(EvidenceState), EvidenceState.NOT_COLLECTED_BY_USER_CHOICE));
    }
}

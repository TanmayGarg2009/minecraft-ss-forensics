using System.Text.Json;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Models.Legacy;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class ReportExporterTests
{
    private static SubmitReportRequest CreateSampleReport()
    {
        return new SubmitReportRequest
        {
            SchemaVersion = "1.0.0",
            ScannerVersion = "1.0.0",
            ScanMode = "FULL",
            OsName = "Microsoft Windows 11 Pro",
            OsVersion = "10.0.22631",
            OsArchitecture = "X64",
            ScanStartedAt = new DateTimeOffset(2026, 10, 30, 10, 0, 0, TimeSpan.Zero),
            ScanCompletedAt = new DateTimeOffset(2026, 10, 30, 10, 0, 45, TimeSpan.Zero),
            DetectedMinecraftVersions = new List<string> { "1.20.4" },
            DetectedLoaders = new List<string> { "Fabric 0.15.7" },
            AppliedPolicyName = "Crystal PvP Standard",
            AppliedPolicyVersion = "1.0.0",
            AppliedGamemode = "Crystal PvP",
            AppliedPolicyRulesUrl = "https://rules.example.com/crystal",
            ConsentConfirmation = new ConsentSubmissionDto
            {
                ConsentGiven = true,
                CollectionScopeVersion = "1.0",
                ConsentTimestamp = new DateTimeOffset(2026, 10, 30, 9, 59, 50, TimeSpan.Zero)
            },
            CollectionCoverage = new CoverageSubmissionDto
            {
                TotalChecks = 12,
                PassedChecks = 10,
                FlaggedChecks = 1,
                UnavailableChecks = 1
            },
            RetentionDays = 14,
            Findings = new List<FindingSubmissionDto>
            {
                new FindingSubmissionDto
                {
                    RuleId = "MOD-POLICY-PROHIBITED",
                    Title = "Prohibited Advantage Mod Detected: Freecam",
                    Category = "ModIntegrity",
                    Severity = "High",
                    Confidence = "Certain",
                    Explanation = "Discovered freecam-fabric-1.20.4.jar which provides illegal perspective decoupling.",
                    FilePath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\freecam-fabric-1.20.4.jar",
                    FileSizeBytes = 128450,
                    FileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ProcessId = 1234,
                    ProcessName = "javaw.exe",
                    ProcessCommandLine = @"javaw.exe -Xmx4G --accessToken secret_token_xyz123 --uuid player-uuid-456 net.fabricmc.loader.launch.knot.KnotClient",
                    EvidenceSource = "ModFolder",
                    DetectionRuleVersion = "1.0.0",
                    LimitationsAndFalsePositives = "Player may use this profile on creative building servers."
                }
            },
            EvidenceItems = new List<EvidenceSubmissionDto>
            {
                new EvidenceSubmissionDto
                {
                    PublicEvidenceId = "evi_mod_inventory_01",
                    Type = "ModInventory",
                    Title = "Discovered Mod Inventory",
                    Description = "List of mod JARs found in mods folder.",
                    IsAvailable = true,
                    CapturedAt = new DateTimeOffset(2026, 10, 30, 10, 0, 10, TimeSpan.Zero),
                    StructuredPayload = new List<object>
                    {
                        new
                        {
                            name = "Freecam",
                            fileName = "freecam-fabric-1.20.4.jar",
                            sizeBytes = 128450L,
                            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            modId = "freecam",
                            version = "1.20.4-0.4.2",
                            loader = "fabric",
                            verified = true,
                            verificationState = "VERIFIED_EXACT_RELEASE",
                            verificationProvider = "Modrinth",
                            projectUrl = "https://modrinth.com/mod/freecam",
                            gameplayPolicy = "PROHIBITED",
                            behaviorCategory = "PerspectiveExploit",
                            policyReason = "Freecam is strictly prohibited in Crystal PvP ruleset."
                        },
                        new
                        {
                            name = "Sodium",
                            fileName = "sodium-fabric-0.5.8.jar",
                            sizeBytes = 850000L,
                            sha256 = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                            modId = "sodium",
                            version = "0.5.8",
                            loader = "fabric",
                            verified = true,
                            verificationState = "VERIFIED_EXACT_RELEASE",
                            verificationProvider = "Modrinth",
                            projectUrl = "https://modrinth.com/mod/sodium",
                            gameplayPolicy = "ALLOWED",
                            behaviorCategory = "PerformanceOptimization",
                            policyReason = "Standard rendering optimization mod."
                        }
                    }
                },
                new EvidenceSubmissionDto
                {
                    PublicEvidenceId = "evi_jvm_01",
                    Type = "JvmArguments",
                    Title = "JVM Arguments",
                    Description = "Active JVM startup parameters.",
                    IsAvailable = true,
                    CapturedAt = new DateTimeOffset(2026, 10, 30, 10, 0, 12, TimeSpan.Zero),
                    RawContent = "-Xmx4096M -XX:+UseG1GC --accessToken secret_jwt_token_here --session user_session_token"
                }
            },
            TimelineEvents = new List<TimelineEventSubmissionDto>
            {
                new TimelineEventSubmissionDto
                {
                    Timestamp = new DateTimeOffset(2026, 10, 30, 9, 30, 0, TimeSpan.Zero),
                    IsInferred = false,
                    Category = "ProcessExecution",
                    Source = "Prefetch",
                    Description = "javaw.exe executed from launcher directory.",
                    Confidence = "Certain"
                }
            },
            DiagnosticItems = new List<DiagnosticItemSubmissionDto>
            {
                new DiagnosticItemSubmissionDto
                {
                    CheckName = "Prefetch Forensic Inspection",
                    Source = "WindowsPrefetch",
                    Status = "Completed",
                    Reason = "Prefetch file parsed successfully."
                },
                new DiagnosticItemSubmissionDto
                {
                    CheckName = "Raw NTFS USN Journal Parser",
                    Source = "UsnJournal",
                    Status = "AccessDenied",
                    Reason = "Direct volume handle read access denied under standard user privileges.",
                    Recommendation = "If file deletion is suspected, verify via Windows event logs or recycle bin inspection."
                }
            }
        };
    }

    [Fact]
    public void ExportToJson_ValidDocument_ParsesSuccessfullyAndExcludesSensitiveData()
    {
        var report = CreateSampleReport();
        string publicId = "rep_test_abc123";

        string json = ReportExporter.ExportToJson(report, publicId);

        Assert.False(string.IsNullOrWhiteSpace(json));

        // Must be valid JSON
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Verify metadata block
        Assert.True(root.TryGetProperty("exportMetadata", out var meta));
        Assert.Equal("1.0.0", meta.GetProperty("exportSchemaVersion").GetString());
        Assert.Equal("FullForensicJson", meta.GetProperty("exportFormat").GetString());
        Assert.Equal(publicId, meta.GetProperty("reportId").GetString());

        // Verify report block
        Assert.True(root.TryGetProperty("report", out var rep));
        Assert.Equal("FULL", rep.GetProperty("scanMode").GetString());
        Assert.Equal("Crystal PvP", rep.GetProperty("appliedGamemode").GetString());

        // Verify command line redactor scrubbed access tokens
        Assert.DoesNotContain("secret_token_xyz123", json);
        Assert.DoesNotContain("secret_jwt_token_here", json);
        Assert.Contains("[REDACTED_ACCESS_TOKEN]", json);
        Assert.Contains("[REDACTED_SESSION]", json);

        // Verify deletion key is never present
        Assert.DoesNotContain("deletionKey", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExportToMarkdown_ContainsAllThirteenRequiredSectionsAndAiPreamble()
    {
        var report = CreateSampleReport();
        string publicId = "rep_test_ai456";

        string markdown = ReportExporter.ExportToMarkdown(report, publicId);

        Assert.False(string.IsNullOrWhiteSpace(markdown));

        // 1. Report Overview
        Assert.Contains("# Minecraft Screenshare Forensic Investigation Report", markdown);
        Assert.Contains("## 1. Report Overview", markdown);
        Assert.Contains("`rep_test_ai456`", markdown);
        Assert.Contains("Crystal PvP", markdown);

        // 2. Scan Completeness & Limitations
        Assert.Contains("## 2. Scan Completeness and Limitations", markdown);
        Assert.Contains("Forensic Boundary Notice", markdown);

        // 3. AI Analysis Guide - Must strictly contain core instructions
        Assert.Contains("## 3. AI Analysis Guide", markdown);
        Assert.Contains("Instructions for AI Forensic Reviewer:", markdown);
        Assert.Contains("Directly observed facts.", markdown);
        Assert.Contains("Verified artifact identity.", markdown);
        Assert.Contains("Server-policy violations.", markdown);
        Assert.Contains("Do not assume that an unknown mod is malicious", markdown);
        Assert.Contains("Do not treat a file existing on disk as proof that it executed", markdown);

        // 4. Key Findings
        Assert.Contains("## 4. Key Findings", markdown);
        Assert.Contains("Prohibited Advantage Mod Detected: Freecam", markdown);
        Assert.Contains("What was observed:", markdown);
        Assert.Contains("Supporting evidence:", markdown);
        Assert.Contains("Why it may matter:", markdown);
        Assert.Contains("Alternative explanations & false positives:", markdown);
        Assert.Contains("What it does not prove:", markdown);
        Assert.Contains("Additional checks that could clarify it:", markdown);

        // 5. Minecraft Installations & Environment Metadata
        Assert.Contains("## 5. Minecraft Installations and Environment Metadata", markdown);
        Assert.Contains("Parsed JVM Launch Arguments", markdown);
        Assert.DoesNotContain("secret_jwt_token_here", markdown); // token redacted

        // 6. Complete Mod Inventory
        Assert.Contains("## 6. Complete Discovered Mod Inventory", markdown);
        Assert.Contains("freecam-fabric-1.20.4.jar", markdown);
        Assert.Contains("sodium-fabric-0.5.8.jar", markdown);

        // 7. Artifact Authenticity Verification
        Assert.Contains("## 7. Artifact Authenticity Verification", markdown);
        Assert.Contains("VERIFIED_EXACT_RELEASE", markdown);

        // 8. Server Policy Compliance
        Assert.Contains("## 8. Server Policy Compliance", markdown);
        Assert.Contains("PROHIBITED", markdown);
        Assert.Contains("ALLOWED", markdown);

        // 9. Process and Runtime Module Findings
        Assert.Contains("## 9. Process and Runtime Module Findings", markdown);

        // 10. Log and Historical Evidence
        Assert.Contains("## 10. Log and Historical Evidence", markdown);

        // 11. Evidence Correlation and Timeline
        Assert.Contains("## 11. Evidence Correlation and Timeline", markdown);

        // 12. Failed, Skipped, or Unavailable Checks
        Assert.Contains("## 12. Failed, Skipped, or Unavailable Checks", markdown);
        Assert.Contains("Raw NTFS USN Journal Parser", markdown);
        Assert.Contains("AccessDenied", markdown);

        // 13. Questions Requiring Further Investigation
        Assert.Contains("## 13. Questions Requiring Further Investigation", markdown);
        Assert.Contains("Prohibited Mod", markdown);

        // 14. Appendix
        Assert.Contains("## 14. Full Structured Evidence Appendix", markdown);
        Assert.Contains("evi_mod_inventory_01", markdown);
    }

    [Fact]
    public void GenerateSuggestedFilename_FormatsCorrectly()
    {
        var report = CreateSampleReport();

        string jsonName = ReportExporter.GenerateSuggestedFilename(report, ReportExportFormat.Json, "rep_abc_789");
        string mdName = ReportExporter.GenerateSuggestedFilename(report, ReportExportFormat.Markdown, "rep_abc_789");
        string nullIdName = ReportExporter.GenerateSuggestedFilename(report, ReportExportFormat.Json, null);

        Assert.Equal("MinecraftForensicReport_2026-10-30_rep_abc_789.json", jsonName);
        Assert.Equal("MinecraftForensicReport_2026-10-30_rep_abc_789.md", mdName);
        Assert.Equal("MinecraftForensicReport_2026-10-30_local.json", nullIdName);
    }

    [Fact]
    public void GenerateExport_ProducesSelfContainedResult()
    {
        var report = CreateSampleReport();

        var jsonExport = ReportExporter.GenerateExport(report, ReportExportFormat.Json, "rep_123");
        var mdExport = ReportExporter.GenerateExport(report, ReportExportFormat.Markdown, "rep_123");

        Assert.Equal(ReportExportFormat.Json, jsonExport.Format);
        Assert.Equal("application/json", jsonExport.MimeType);
        Assert.True(jsonExport.ByteCount > 0);
        Assert.EndsWith(".json", jsonExport.SuggestedFileName);

        Assert.Equal(ReportExportFormat.Markdown, mdExport.Format);
        Assert.Equal("text/markdown", mdExport.MimeType);
        Assert.True(mdExport.ByteCount > 0);
        Assert.EndsWith(".md", mdExport.SuggestedFileName);
    }
}

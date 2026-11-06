using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

/// <summary>
/// Workstream H (F-019): Comprehensive Historical Compatibility & Schema Migration Test Suite.
/// Validates backward compatibility against historical v1 and v2 report fixtures, resource bounds,
/// and untrusted payload defenses.
/// </summary>
public class HistoricalCompatibilityTests
{
    [Fact]
    public void LoadFromJson_ValidV2Report_LoadsAndVerifiesIntegritySuccessfully()
    {
        var original = new StandaloneReport
        {
            ReportId = "rep_v2_canonical_test",
            ScanMode = "QUICK",
            ScanStartedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            ScanCompletedAt = DateTimeOffset.UtcNow,
            ScanDurationMs = 300000
        };

        original.Findings.Add(new FindingRecord
        {
            RuleId = "TEST-V2-RULE",
            DetectionName = "Test V2 Finding",
            Severity = Severity.Medium,
            Category = FindingCategory.CheatArtifact,
            Classification = FindingClassification.ConfirmedCheatArtifact,
            Confidence = ConfidenceLevel.Certain,
            EvidenceSource = "FileSystem"
        });

        original.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-V2-01",
            CheckName = "Test Diagnostic",
            Source = "TestScanner",
            Status = CheckStatus.PASSED,
            Reason = "Check passed normally."
        });

        string json = PortableJsonExporter.ExportToJson(original);
        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(json);

        Assert.True(success, error);
        Assert.NotNull(loaded);
        Assert.Equal("rep_v2_canonical_test", loaded.ReportId);
        Assert.Single(loaded.Findings);
        Assert.Equal("TEST-V2-RULE", loaded.Findings[0].RuleId);
        Assert.Equal(FindingClassification.ConfirmedCheatArtifact, loaded.Findings[0].Classification);
        Assert.NotEmpty(loaded.ReportIntegrityHash);
        Assert.DoesNotContain(loaded.DiagnosticChecks, c => c.CheckId == "CHK-INTEGRITY-FAILED");
    }

    [Fact]
    public void LoadFromJson_LegacyV1WrappedReport_MigratesFindingsAndGeneratesValidReport()
    {
        // Representative V1.0 wrapped export format
        string legacyV1Json = @"
        {
            ""exportMetadata"": {
                ""reportId"": ""rep_legacy_v1_wrapped_12345"",
                ""exportedAt"": ""2025-06-15T10:30:00Z"",
                ""formatVersion"": ""1.0""
            },
            ""report"": {
                ""scanMode"": ""FULL"",
                ""osName"": ""Microsoft Windows 10 Pro"",
                ""osVersion"": ""10.0.19045"",
                ""findings"": [
                    {
                        ""ruleId"": ""V1-RULE-INJECTED-DLL"",
                        ""title"": ""Injected DLL Detected"",
                        ""explanation"": ""Suspicious DLL mapped into game memory"",
                        ""severity"": ""Critical"",
                        ""filePath"": ""C:\\Temp\\cheat.dll"",
                        ""fileSha256"": ""e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""
                    },
                    {
                        ""ruleId"": ""V1-RULE-MOD-LOOKALIKE"",
                        ""title"": ""Lookalike Mod Name"",
                        ""explanation"": ""Disguised mod jar"",
                        ""severity"": ""High"",
                        ""filePath"": ""C:\\Minecraft\\mods\\optifine_fake.jar"",
                        ""fileSha256"": ""ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb""
                    }
                ]
            }
        }";

        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(legacyV1Json);

        Assert.True(success, error);
        Assert.NotNull(loaded);
        Assert.Equal("rep_legacy_v1_wrapped_12345", loaded.ReportId);
        Assert.Equal("FULL", loaded.ScanMode);
        Assert.Equal("Microsoft Windows 10 Pro", loaded.TargetSystem.OsName);
        Assert.Equal(2, loaded.Findings.Count);

        var first = loaded.Findings[0];
        Assert.Equal("V1-RULE-INJECTED-DLL", first.RuleId);
        Assert.Equal("Injected DLL Detected", first.DetectionName);
        Assert.Equal(Severity.Critical, first.Severity);
        Assert.Equal("C:\\Temp\\cheat.dll", first.FilePath);

        var second = loaded.Findings[1];
        Assert.Equal("V1-RULE-MOD-LOOKALIKE", second.RuleId);
        Assert.Equal(Severity.High, second.Severity);

        // Verification of migrated unverified trust state (FND-006 & FND-012: never auto-generate new seals for migrated reports)
        var loadResult = PortableJsonExporter.LoadFromJson(legacyV1Json);
        Assert.Equal(ReportLoadTrustState.MigratedHistoricalUnverified, loadResult.TrustState);
        Assert.Empty(loaded.ReportIntegrityHash);
        Assert.Equal(2, loaded.SummaryCounts.TotalFindings);
    }

    [Fact]
    public void LoadFromJson_LegacyV1DirectReport_MigratesFindingsAndGeneratesValidReport()
    {
        // Representative V1.0 direct submit report format
        string legacyV1DirectJson = @"
        {
            ""reportId"": ""rep_legacy_direct_998877"",
            ""scanMode"": ""QUICK"",
            ""osName"": ""Microsoft Windows 11 Home"",
            ""osVersion"": ""10.0.22631"",
            ""detectedMinecraftVersions"": [ ""1.20.4"", ""1.21.1"" ],
            ""findings"": [
                {
                    ""ruleId"": ""DIRECT-V1-AUTOCLICKER"",
                    ""title"": ""Autoclicker Prefetch Execution"",
                    ""explanation"": ""Historical execution in Prefetch"",
                    ""severity"": ""Medium"",
                    ""filePath"": ""C:\\Users\\User\\Downloads\\clicker.exe"",
                    ""fileSha256"": ""b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9""
                }
            ]
        }";

        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(legacyV1DirectJson);

        Assert.True(success, error);
        Assert.NotNull(loaded);
        Assert.Equal("rep_legacy_direct_998877", loaded.ReportId);
        Assert.Equal("QUICK", loaded.ScanMode);
        Assert.Single(loaded.Findings);
        Assert.Equal("DIRECT-V1-AUTOCLICKER", loaded.Findings[0].RuleId);
        Assert.Equal(Severity.Medium, loaded.Findings[0].Severity);
    }

    [Fact]
    public void LoadFromJson_ExceedsMaxResourceLimit_RejectsGracefully()
    {
        // Construct string exceeding MaxReportFileSizeBytes (50 MB)
        string oversized = new string('A', (int)PortableJsonExporter.MaxReportFileSizeBytes + 1024);
        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(oversized);

        Assert.False(success);
        Assert.Null(loaded);
        Assert.Contains("exceeds maximum permitted resource limit", error);
    }

    [Fact]
    public void LoadFromJson_ExceedsMaxCollectionLimit_RejectsGracefully()
    {
        var oversizedReport = new StandaloneReport
        {
            ReportId = "rep_oversized_test",
            SchemaVersion = "2.0.0"
        };

        // Add 25,001 findings to trigger limit
        for (int i = 0; i <= PortableJsonExporter.MaxCollectionItemLimit; i++)
        {
            oversizedReport.Findings.Add(new FindingRecord
            {
                RuleId = $"FLOOD-{i}",
                DetectionName = $"Flood finding {i}",
                Severity = Severity.Low
            });
        }

        string json = JsonSerializer.Serialize(oversizedReport);
        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(json);

        Assert.False(success);
        Assert.Null(loaded);
        Assert.Contains("exceeds maximum safe resource limit", error);
    }

    [Fact]
    public void LoadFromJson_TamperedIntegritySeal_FlagsCheckWithoutCrashing()
    {
        var original = new StandaloneReport
        {
            ReportId = "rep_tamper_test",
            ScanMode = "QUICK"
        };
        original.Findings.Add(new FindingRecord
        {
            RuleId = "RULE-01",
            DetectionName = "Authentic Finding",
            Severity = Severity.Medium
        });

        string json = PortableJsonExporter.ExportToJson(original);

        // Tamper with content by altering the detection name in json without recomputing seal
        string tamperedJson = json.Replace("Authentic Finding", "Tampered Finding");

        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(tamperedJson);

        Assert.True(success);
        Assert.NotNull(loaded);
        // Tampered report should have an added FLAGGED check indicating integrity failure
        Assert.Contains(loaded.DiagnosticChecks, c => c.CheckId == "CHK-INTEGRITY-FAILED" && c.Status == CheckStatus.FLAGGED);
    }

    [Fact]
    public void LoadFromJson_MalformedJson_ReturnsGracefulError()
    {
        string badJson = "{ \"reportId\": \"corrupt\", \"schemaVersion\": [unclosed";
        var (success, loaded, error) = PortableJsonExporter.LoadFromJson(badJson);

        Assert.False(success);
        Assert.Null(loaded);
        Assert.NotEmpty(error);
    }

    [Fact]
    public void LoadFromJson_EmptyOrWhitespace_ReturnsGracefulError()
    {
        var (success1, _, err1) = PortableJsonExporter.LoadFromJson("");
        Assert.False(success1);
        Assert.Contains("empty", err1);

        var (success2, _, err2) = PortableJsonExporter.LoadFromJson("   \t\r\n  ");
        Assert.False(success2);
        Assert.Contains("empty", err2);
    }
}

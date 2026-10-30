using System;
using System.Collections.Generic;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class ReportIntegrityValidatorTests
{
    private static StandaloneReport CreateRealisticSampleReport()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_test_fixture_101",
            SchemaVersion = "2.0.0",
            ScannerVersion = "2.0.0-standalone",
            ScanMode = "QUICK",
            CreatedAt = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero),
            ScanStartedAt = new DateTimeOffset(2026, 10, 30, 11, 59, 30, TimeSpan.Zero),
            ScanCompletedAt = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero)
        };

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Sodium",
            FileName = "sodium-fabric-0.5.8.jar",
            FullPath = "C:\\Users\\TestPlayer\\.minecraft\\mods\\sodium-fabric-0.5.8.jar",
            Sha256 = "6c54784a3275de18e77c8e317bb7d5d2c20fbbad9e0802c6d48dc390b3f81e3a",
            Verified = true,
            GameplayPolicy = "ALLOWED",
            FileSizeBytes = 1254300
        });

        report.Findings.Add(new FindingRecord
        {
            FindingId = "fnd_001",
            RuleId = "MOD-POLICY-ALLOWED",
            DetectionName = "Sodium Optimization Mod",
            Category = FindingCategory.ModIntegrity,
            Classification = FindingClassification.Informational,
            Severity = Severity.Informational,
            Confidence = ConfidenceLevel.Certain,
            FilePath = "C:\\Users\\TestPlayer\\.minecraft\\mods\\sodium-fabric-0.5.8.jar",
            FileSha256 = "6c54784a3275de18e77c8e317bb7d5d2c20fbbad9e0802c6d48dc390b3f81e3a",
            TechnicalExplanation = "Sodium is a standard rendering optimization mod."
        });

        report.RecomputeSummaryCounts();
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);
        return report;
    }

    [Fact]
    public void ReportIntegrity_UntamperedReport_PassesVerification()
    {
        var report = CreateRealisticSampleReport();
        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.True(result.IsValid);
        Assert.False(result.IsTampered);
        Assert.Equal(report.ReportIntegrityHash, result.ExpectedDigest);
        Assert.Contains("Cryptographic integrity verified", result.StatusMessage);
    }

    [Fact]
    public void ReportIntegrity_AlteringCheatNameInFindings_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with detection name in finding
        report.Findings[0].DetectionName = "Tampered Safe Optimization Mod";

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
        Assert.NotEqual(report.ReportIntegrityHash, result.ExpectedDigest);
        Assert.Contains("Integrity mismatch", result.StatusMessage);
    }

    [Fact]
    public void ReportIntegrity_AlteringFilePathInModInventory_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with file path
        report.ModInventory[0].FullPath = "C:\\Different\\Path\\sodium.jar";

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_AlteringFileSha256_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with hash
        report.ModInventory[0].Sha256 = "0000000000000000000000000000000000000000000000000000000000000000";

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_AlteringFindingClassification_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with classification (e.g. from Informational to ConfirmedCheatArtifact)
        report.Findings[0].Classification = FindingClassification.ConfirmedCheatArtifact;

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_AlteringTimestamp_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with creation timestamp
        report.CreatedAt = DateTimeOffset.UtcNow.AddDays(-10);

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_AlteringPolicyDecision_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper with policy evaluation
        report.PolicyEvaluation.AppliedGamemode = "Anarchy Ruleset";

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_AddingNewEvidenceItem_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper by injecting an evidence item
        report.EvidenceItems.Add(new EvidenceReferenceItem
        {
            EvidenceId = "EVD-INJECTED-99",
            Title = "Unauthorized Evidence Injected",
            Type = EvidenceType.WindowsArtifact
        });

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_RemovingFinding_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        // Tamper by removing findings
        report.Findings.Clear();

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_ReorderingFindings_FailsVerification()
    {
        var report = CreateRealisticSampleReport();
        report.Findings.Add(new FindingRecord
        {
            FindingId = "fnd_002",
            RuleId = "MOD-SECOND",
            DetectionName = "Second Mod Finding"
        });
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        // Swap the order of findings
        (report.Findings[0], report.Findings[1]) = (report.Findings[1], report.Findings[0]);

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.True(result.IsTampered);
    }

    [Fact]
    public void ReportIntegrity_EmptyOrUnsealedReport_FailsGracefully()
    {
        var report = CreateRealisticSampleReport();
        report.ReportIntegrityHash = string.Empty;

        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);

        Assert.False(result.IsValid);
        Assert.False(result.IsTampered); // Not tampered, just unsealed
        Assert.Contains("lacks an embedded SHA-256 integrity seal", result.StatusMessage);
    }
}

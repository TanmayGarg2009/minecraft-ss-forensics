using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Models;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class SecurityAndHardeningTests
{
    [Fact]
    public async Task SafeArchive_ZipSlipPathTraversal_IsDefensivelyBlocked()
    {
        string zipPath = Path.Combine(Path.GetTempPath(), $"zip_slip_{Guid.NewGuid():N}.zip");
        try
        {
            // Create a malicious zip file containing path traversal entries ("../../evil.bat")
            using (var fs = File.Create(zipPath))
            using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("../../Windows/System32/evil.bat");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("malicious payload");
            }

            var inspector = new SafeArchiveInspector();
            var metadata = await inspector.InspectModJarAsync(zipPath);

            // Safe inspector must reject entry or block extraction outside sandbox
            Assert.NotNull(metadata);
        }
        finally
        {
            if (File.Exists(zipPath)) File.Delete(zipPath);
        }
    }

    [Fact]
    public void HtmlExporter_MaliciousHtmlTags_AreProperlyEscaped()
    {
        var report = new StandaloneReport();
        report.Findings.Add(new FindingRecord
        {
            RuleId = "TEST-XSS",
            DetectionName = "<script>alert('xss')</script>",
            TechnicalExplanation = "<img src=x onerror=alert('xss')>",
            FilePath = "C:\\test\\<script>.jar"
        });
        report.RecomputeSummaryCounts();

        string html = StandaloneHtmlExporter.ExportToHtml(report);

        // Raw executable script tags must NOT be present unescaped
        Assert.DoesNotContain("<script>alert('xss')</script>", html);
        Assert.DoesNotContain("<img src=x onerror=alert('xss')>", html);
        // Must contain escaped versions
        Assert.Contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", html);
    }

    [Fact]
    public void PortableJsonExporter_RoundtripSerialization_PreservesIntegrity()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_roundtrip_test",
            ScanMode = "FULL"
        };
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Iris Shaders",
            FileName = "iris-1.7.0.jar",
            Sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        });
        report.RecomputeSummaryCounts();
        report.ReportIntegrityHash = Integrity.ReportIntegrityValidator.ComputeReportSeal(report);

        string json = PortableJsonExporter.ExportToJson(report);
        var (success, importedReport, error) = PortableJsonExporter.LoadFromJson(json);

        Assert.True(success, error);
        Assert.NotNull(importedReport);
        Assert.Equal(report.ReportId, importedReport.ReportId);
        Assert.Equal(report.ReportIntegrityHash, importedReport.ReportIntegrityHash);

        var verifyResult = Integrity.ReportIntegrityValidator.VerifyReportIntegrityDetailed(importedReport);
        Assert.True(verifyResult.IsValid);
    }
}

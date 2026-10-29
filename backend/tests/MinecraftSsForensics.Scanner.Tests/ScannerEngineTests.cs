using System.IO.Compression;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Validation;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class ScannerEngineTests
{
    private class StubModVerifier : IModVerifier
    {
        public Task<ModVerificationResult> VerifyModAsync(DiscoveredMod mod, CancellationToken ct = default)
        {
            return Task.FromResult(new ModVerificationResult
            {
                State = ModVerificationState.VERIFIED_EXACT_RELEASE,
                Provider = "Modrinth",
                ProjectId = "appleskin",
                VersionNumber = "2.5.1",
                Explanation = "Verified exact hash in mock stub.",
                MatchedFileName = mod.FileName
            });
        }
    }

    [Fact]
    public async Task ExecuteScanAsync_GeneratesReport_ThatPassesBackendSchemaValidation()
    {
        // Create temporary dummy .minecraft folder with a test mod
        string tempDir = Path.Combine(Path.GetTempPath(), $"scanner_engine_test_{Guid.NewGuid():N}");
        string modsDir = Path.Combine(tempDir, "mods");
        string logsDir = Path.Combine(tempDir, "logs");
        Directory.CreateDirectory(modsDir);
        Directory.CreateDirectory(logsDir);

        string testJar = Path.Combine(modsDir, "appleskin-fabric-mc1.20.4-2.5.1.jar");
        using (var zip = ZipFile.Open(testJar, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("fabric.mod.json");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("""
            {
                "schemaVersion": 1,
                "id": "appleskin",
                "name": "AppleSkin",
                "version": "2.5.1",
                "description": "Food HUD improvements",
                "authors": ["squeek502"]
            }
            """);
        }

        string logFile = Path.Combine(logsDir, "latest.log");
        await File.WriteAllTextAsync(logFile, "[12:00:00] [main/INFO]: Loading Minecraft 1.20.4 with Fabric Loader 0.15.7\n");

        try
        {
            var engine = new ScannerEngine(verifier: new StubModVerifier());
            var progressUpdates = new List<ScanProgressUpdate>();
            var progress = new Progress<ScanProgressUpdate>(progressUpdates.Add);

            var report = await engine.ExecuteScanAsync(
                ScanMode.Quick,
                customDirectory: tempDir,
                onlyCustomDirectory: true,
                progress: progress);

            // Verify basic report fields
            Assert.Equal("1.0.0", report.SchemaVersion);
            Assert.Equal("QUICK", report.ScanMode);
            Assert.True(report.ConsentConfirmation.ConsentGiven);
            Assert.Contains("1.20.4", report.DetectedMinecraftVersions);
            Assert.Contains(report.DetectedLoaders, l => l.Contains("Fabric"));
            Assert.NotNull(report.CollectionCoverage);
            Assert.True(report.CollectionCoverage.TotalChecks > 0);

            // Execute backend validator to guarantee 100% API schema compatibility
            var validator = new ReportSubmissionValidator();
            var validationResult = await validator.ValidateAsync(report);

            Assert.True(validationResult.IsValid, string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage)));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task ExecuteScanAsync_RespectsCancellationToken()
    {
        var engine = new ScannerEngine(verifier: new StubModVerifier());
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancel

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await engine.ExecuteScanAsync(ScanMode.Quick, ct: cts.Token);
        });
    }
}

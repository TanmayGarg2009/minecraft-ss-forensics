using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MinecraftSsForensics.Api.Data;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Models.Dtos.Presentation;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Client;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Lookalike;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class TestApiFactory : WebApplicationFactory<Program>
{
    private readonly string _dbName = "E2ETestDb_" + Guid.NewGuid().ToString("N");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ForensicsDbContext>));
            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            services.AddDbContext<ForensicsDbContext>(options =>
            {
                options.UseInMemoryDatabase(_dbName);
            });
        });
    }
}

public class ScannerEndToEndIntegrationTests : IClassFixture<TestApiFactory>, IDisposable
{
    private readonly TestApiFactory _factory;
    private readonly string _tempDir;

    public ScannerEndToEndIntegrationTests(TestApiFactory factory)
    {
        _factory = factory;
        _tempDir = Path.Combine(Path.GetTempPath(), "MC_Scanner_E2E_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, true);
            }
        }
        catch
        {
            // cleanup ignore
        }
    }

    private class MockProcessScanner : IProcessScanner
    {
        public List<DiscoveredProcess> ScanProcesses(bool inspectModules = false)
        {
            return new List<DiscoveredProcess>
            {
                new()
                {
                    ProcessId = 1234,
                    ProcessName = "javaw.exe",
                    ExecutablePath = @"C:\Program Files\Java\bin\javaw.exe",
                    RedactedCommandLine = "javaw.exe -Xmx4G -Dminecraft.launcher=prism --accessToken [REDACTED]",
                    IsGameProcess = true,
                    LoadedModules = new List<LoadedModuleInfo>
                    {
                        new()
                        {
                            ModuleName = "ntdll.dll",
                            FilePath = @"C:\Windows\System32\ntdll.dll",
                            IsSigned = true,
                            IsSuspiciousLocation = false
                        }
                    }
                }
            };
        }
    }

    private class StubModVerifier : IModVerifier
    {
        public Task<ModVerificationResult> VerifyModAsync(DiscoveredMod mod, CancellationToken ct = default)
        {
            return Task.FromResult(new ModVerificationResult
            {
                State = ModVerificationState.VERIFIED_EXACT_RELEASE,
                Provider = "Modrinth",
                ProjectName = "Sodium",
                MatchedFileName = mod.FileName,
                Explanation = "Cryptographic hash matches official Modrinth release."
            });
        }
    }

    [Fact]
    public async Task FullScannerLifecycle_ScansEnvironment_SubmitsReport_FetchesReport_AndDeletesReport()
    {
        // 1. Arrange: Create test Minecraft installation with mods and logs
        string modsDir = Path.Combine(_tempDir, "mods");
        string logsDir = Path.Combine(_tempDir, "logs");
        Directory.CreateDirectory(modsDir);
        Directory.CreateDirectory(logsDir);

        // Create a test mod JAR with valid fabric.mod.json
        string modJarPath = Path.Combine(modsDir, "sodium-fabric-0.5.8.jar");
        using (var zipStream = new FileStream(modJarPath, FileMode.Create))
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("fabric.mod.json");
            using var entryWriter = new StreamWriter(entry.Open());
            entryWriter.Write("""
            {
                "schemaVersion": 1,
                "id": "sodium",
                "version": "0.5.8",
                "name": "Sodium",
                "description": "Modern rendering engine for Minecraft."
            }
            """);
        }

        // Create a mock latest.log
        string logPath = Path.Combine(logsDir, "latest.log");
        File.WriteAllLines(logPath, new[]
        {
            "[14:00:00] [main/INFO]: Loading Minecraft 1.20.4 with Fabric Loader 0.15.7",
            "[14:00:01] [main/INFO]: Loading 1 mods: sodium 0.5.8"
        });

        // 2. Assemble scanner engine with test dependencies
        var hasher = new StreamingFileHasher();
        var archiveInspector = new SafeArchiveInspector();
        var verifier = new StubModVerifier();
        var lookalike = new LookalikeDetector();
        var procScanner = new MockProcessScanner();
        var locator = new InstallationLocator();
        var logAuditor = new LogAuditor();
        var histScanner = new HistoricalEvidenceScanner();

        var engine = new ScannerEngine(
            hasher,
            archiveInspector,
            verifier,
            lookalike,
            procScanner,
            locator,
            logAuditor,
            histScanner);

        // 3. Act - Execute Scan
        var scannedReport = await engine.ExecuteScanAsync(
            ScanMode.Quick,
            customDirectory: _tempDir,
            onlyCustomDirectory: true);

        Assert.NotNull(scannedReport);
        Assert.True(scannedReport.ConsentConfirmation.ConsentGiven);
        Assert.Equal("QUICK", scannedReport.ScanMode);
        Assert.NotEmpty(scannedReport.EvidenceItems);
        Assert.Contains(scannedReport.EvidenceItems, e => e.Type == "ModInventory");
        Assert.Contains(scannedReport.EvidenceItems, e => e.Type == "LoadedModules");

        // 4. Act - Submit Report to API via BackendApiClient
        var httpClient = _factory.CreateClient();
        var apiClient = new BackendApiClient(httpClient.BaseAddress?.ToString() ?? "http://localhost", httpClient);

        var uploadResult = await apiClient.SubmitReportAsync(scannedReport);

        // Assert submission response
        Assert.NotNull(uploadResult);
        Assert.StartsWith("mc_", uploadResult.PublicId);
        Assert.StartsWith("del_", uploadResult.DeletionKey);
        Assert.Contains($"/report/{uploadResult.PublicId}", uploadResult.ShareUrl);

        // Verify share URL construction via ReportShareUrlBuilder
        string desktopShareUrl = ReportShareUrlBuilder.BuildShareUrl("http://localhost:3000", uploadResult.PublicId, isProduction: false);
        Assert.Equal($"http://localhost:3000/report/{uploadResult.PublicId}", desktopShareUrl);
        Assert.DoesNotContain("5000", desktopShareUrl);
        Assert.DoesNotContain(uploadResult.DeletionKey, desktopShareUrl);

        // 5. Act - Retrieve Report from API via GET /api/v1/reports/{publicId}
        var getResponse = await httpClient.GetAsync($"/api/v1/reports/{uploadResult.PublicId}");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

        var reportDetail = await getResponse.Content.ReadFromJsonAsync<ReportDetailResponse>();
        Assert.NotNull(reportDetail);
        Assert.Equal(uploadResult.PublicId, reportDetail!.PublicId);
        Assert.Equal("QUICK", reportDetail.ScanMode);
        Assert.NotEmpty(reportDetail.EvidenceItems);

        // Verify mod inventory structured payload
        var modInventory = reportDetail.EvidenceItems.FirstOrDefault(e => e.Type == "ModInventory");
        Assert.NotNull(modInventory);
        Assert.NotNull(modInventory!.StructuredPayload);

        // 6. Act - Delete Report using secret deletion key via BackendApiClient
        var deleteResult = await apiClient.DeleteReportAsync(uploadResult.PublicId, uploadResult.DeletionKey);
        Assert.NotNull(deleteResult);
        Assert.True(deleteResult.Success);

        // 7. Assert - Verify subsequent GET returns 404 Not Found
        var verifyDeletedResponse = await httpClient.GetAsync($"/api/v1/reports/{uploadResult.PublicId}");
        Assert.Equal(HttpStatusCode.NotFound, verifyDeletedResponse.StatusCode);
    }
}

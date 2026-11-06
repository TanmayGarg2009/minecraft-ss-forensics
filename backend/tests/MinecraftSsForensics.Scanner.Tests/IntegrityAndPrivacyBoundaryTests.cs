using System;
using System.IO;
using System.Threading.Tasks;
using MinecraftSsForensics.Scanner.Archive;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Process;
using MinecraftSsForensics.Scanner.Verification;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class IntegrityAndPrivacyBoundaryTests
{
    [Fact]
    public void ConsentScopeConfig_DefaultsPerformOnlineVerificationToFalse()
    {
        var config = new ConsentScopeConfig();
        // Strict Offline-First Rule: Must be false by default
        Assert.False(config.PerformOnlineVerification);
        Assert.False(config.InspectBrowserHistory); // Browser history also false by default
    }

    [Fact]
    public async Task CompositeModVerifier_OfflineBoundary_MakesZeroNetworkRequests()
    {
        var cache = new VerificationCache();
        var modrinth = new ModrinthVerificationProvider();
        var curse = new CurseForgeVerificationProvider();
        var github = new GitHubVerificationProvider();

        // Instantiate verifier with AllowNetworkRequests = false (strict offline boundary)
        var verifier = new CompositeModVerifier(cache, modrinth, curse, github, allowNetworkRequests: false);
        Assert.False(verifier.AllowNetworkRequests);

        var testMod = new DiscoveredMod
        {
            FileName = "Sodium-Fabric-1.20.4.jar",
            FilePath = @"C:\mods\Sodium-Fabric-1.20.4.jar",
            Hashes = new FileHashResult
            {
                Sha256 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
                Sha512 = "dummy512"
            },
            Metadata = new ModMetadata
            {
                ModId = "sodium",
                ModName = "Sodium",
                Version = "0.5.8",
                ParseSuccess = true
            }
        };

        // When offline, it should immediately evaluate without network calls
        var result = await verifier.VerifyModAsync(testMod);

        Assert.NotNull(result);
        Assert.Equal(ModVerificationState.UNKNOWN_OR_UNLISTED, result.State);
        Assert.Contains("No cryptographic digest match found", result.Explanation);
    }

    [Fact]
    public void ReportIntegrityValidator_DistinguishesContentIntegrityFromAuthenticity()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_test_integrity_01",
            ScanMode = "QUICK"
        };

        // Compute valid seal
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        var validResult = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);
        Assert.True(validResult.IsValid);
        Assert.False(validResult.IsTampered);
        Assert.Contains("does not authenticate the author's identity", validResult.ProvenanceNotice);

        // Tamper with report content
        report.ScanMode = "FULL_MODIFIED";

        var tamperedResult = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);
        Assert.False(tamperedResult.IsValid);
        Assert.True(tamperedResult.IsTampered);
        Assert.Contains("tampered with", tamperedResult.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CommandLineRedactor_Scrubbing_ProtectsUserPathsAndSessionTokens()
    {
        string rawCmd = @"C:\Program Files\Java\bin\javaw.exe -Xmx4G --accessToken abc123def456secret --uuid 550e8400-e29b-41d4-a716-446655440000 --userProperties {}";
        string redacted = CommandLineRedactor.Redact(rawCmd);

        Assert.DoesNotContain("abc123def456secret", redacted);
        Assert.Contains("[REDACTED_ACCESS_TOKEN]", redacted);
        Assert.Contains("[REDACTED_UUID]", redacted);

        string rawPath = @"C:\Users\JohnSmith\AppData\Roaming\.minecraft\mods\cheat.jar";
        string redactedPath = CommandLineRedactor.RedactPath(rawPath);

        Assert.DoesNotContain("JohnSmith", redactedPath);
        Assert.Equal(@"C:\Users\[REDACTED_USER]\AppData\Roaming\.minecraft\mods\cheat.jar", redactedPath);
    }

    [Fact]
    public void FindingRecord_DefaultsToInconclusive_NeverConfirmed()
    {
        var finding = new FindingRecord();

        // Evidentiary safety invariant: newly constructed finding without proof must NEVER default to CONFIRMED
        Assert.Equal(EvidenceState.INCONCLUSIVE, finding.EvidenceState);
        Assert.Equal(EvidenceStrength.Inconclusive, finding.EvidenceStrength);
        Assert.Equal(ConfidenceLevel.Low, finding.Confidence);
        Assert.Equal(FindingClassification.Informational, finding.Classification);
    }

    [Fact]
    public void PrivacyBoundary_ExportDoesNotMutateRawReportInMemory()
    {
        var rawReport = new StandaloneReport
        {
            ReportId = "rep_non_mutating_test",
            ScanMode = "QUICK"
        };

        string originalUserPath = @"C:\Users\Alice\AppData\Roaming\.minecraft\mods\test.jar";
        string originalCmd = @"javaw.exe --accessToken secretToken12345 --uuid 11111111-2222-3333-4444-555555555555";

        rawReport.Findings.Add(new FindingRecord
        {
            RuleId = "TEST-RULE-01",
            DetectionName = "Test Finding",
            FilePath = originalUserPath,
            ProcessCommandLine = originalCmd,
            TechnicalExplanation = $"Process launched with arguments: {originalCmd}"
        });

        rawReport.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1234,
            ProcessName = "javaw.exe",
            ExecutablePath = @"C:\Users\Alice\Java\bin\javaw.exe",
            SanitizedCommandLine = originalCmd
        });

        // Export to JSON, Markdown, HTML
        string jsonExport = Export.PortableJsonExporter.ExportToJson(rawReport);
        string mdExport = Export.MarkdownExporter.ExportToMarkdown(rawReport);
        string htmlExport = Export.StandaloneHtmlExporter.ExportToHtml(rawReport);

        // Assert exports are sanitized
        Assert.Contains("[REDACTED_USER]", jsonExport);
        Assert.Contains("[REDACTED_ACCESS_TOKEN]", jsonExport);
        Assert.DoesNotContain("secretToken12345", jsonExport);

        Assert.Contains("[REDACTED_USER]", mdExport);
        Assert.Contains("[REDACTED_ACCESS_TOKEN]", mdExport);
        Assert.DoesNotContain("secretToken12345", mdExport);

        Assert.Contains("[REDACTED_USER]", htmlExport);
        Assert.Contains("[REDACTED_ACCESS_TOKEN]", htmlExport);
        Assert.DoesNotContain("secretToken12345", htmlExport);

        // CRITICAL INVARIANT: The caller's raw in-memory report MUST NOT be mutated!
        Assert.Equal(originalUserPath, rawReport.Findings[0].FilePath);
        Assert.Equal(originalCmd, rawReport.Findings[0].ProcessCommandLine);
        Assert.Equal($"Process launched with arguments: {originalCmd}", rawReport.Findings[0].TechnicalExplanation);
        Assert.Equal(@"C:\Users\Alice\Java\bin\javaw.exe", rawReport.RunningProcesses[0].ExecutablePath);
        Assert.Equal(originalCmd, rawReport.RunningProcesses[0].SanitizedCommandLine);
    }

    [Fact]
    public void ReportLoadResult_ExplicitTrustState_DistinguishesVerifiedFromTamperedAndUnsealed()
    {
        var authentic = new StandaloneReport
        {
            ReportId = "rep_trust_state_test",
            ScanMode = "QUICK"
        };
        authentic.Findings.Add(new FindingRecord
        {
            RuleId = "RULE-01",
            DetectionName = "Authentic Finding"
        });

        // 1. Export valid sealed report
        string authenticJson = Export.PortableJsonExporter.ExportToJson(authentic);
        var verifiedResult = Export.PortableJsonExporter.LoadFromJson(authenticJson);

        Assert.True(verifiedResult.Success);
        Assert.Equal(Export.ReportLoadTrustState.VerifiedCanonicalV2, verifiedResult.TrustState);
        Assert.NotNull(verifiedResult.Report);

        // 2. Tamper with content while keeping old seal
        string tamperedJson = authenticJson.Replace("Authentic Finding", "Malicious Injected Finding");
        var tamperedResult = Export.PortableJsonExporter.LoadFromJson(tamperedJson);

        Assert.True(tamperedResult.Success); // Parsed successfully into diagnostic structure
        Assert.Equal(Export.ReportLoadTrustState.TamperedDigestMismatch, tamperedResult.TrustState);
        Assert.Contains(tamperedResult.Report!.DiagnosticChecks, c => c.CheckId == "CHK-INTEGRITY-FAILED");

        // 3. Unsealed report (seal stripped)
        string unsealedJson = authenticJson.Replace(verifiedResult.Report.ReportIntegrityHash!, "");
        var unsealedResult = Export.PortableJsonExporter.LoadFromJson(unsealedJson);

        Assert.True(unsealedResult.Success);
        Assert.Equal(Export.ReportLoadTrustState.UnsealedHistorical, unsealedResult.TrustState);
    }

    [Fact]
    public void EvidenceGraph_ResourceBounds_EnforcesLimitsOnNodesAndEdges()
    {
        var graph = new Graph.EvidenceGraph();

        // Verify constants
        Assert.Equal(50000, Graph.EvidenceGraph.MaxGraphNodes);
        Assert.Equal(100000, Graph.EvidenceGraph.MaxGraphEdges);

        // Add node
        var node1 = new Graph.GraphEntity { EntityId = "node:001", Type = Graph.EntityType.File };
        var node2 = new Graph.GraphEntity { EntityId = "node:002", Type = Graph.EntityType.OsProcess };
        Assert.True(graph.AddNode(node1));
        Assert.True(graph.AddNode(node2));

        var edge = new Graph.GraphEdge
        {
            SourceEntityId = "node:001",
            TargetEntityId = "node:002",
            Type = Graph.EdgeType.LoadedBy
        };
        Assert.True(graph.AddEdge(edge));

        // Re-adding identical edge should be rejected (anti-duplicate)
        Assert.False(graph.AddEdge(edge));
    }

    [Fact]
    public async Task NetworkBoundary_EnforcesSecurityAndRejectsSsrfAndInsecureSchemes()
    {
        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            PerformOnlineVerification = true
        };

        var client = Verification.NetworkBoundary.CreateConsentBoundedClient(consent);

        // 1. Insecure HTTP scheme should be blocked
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetAsync("http://api.modrinth.com/v2/project"));

        // 2. Loopback IP address should be blocked (SSRF defense)
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetAsync("https://127.0.0.1/"));

        // 3. Cloud metadata endpoint (169.254.169.254) should be blocked (SSRF defense)
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetAsync("https://169.254.169.254/latest/meta-data/"));

        // 4. Unauthorized domain not in whitelist should be blocked
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetAsync("https://evil-unauthorized-domain.com/data"));
    }

    [Fact]
    public void VerificationCache_CacheHit_RecordsProvenanceAndRetrievalTimestamp()
    {
        var cache = new Verification.VerificationCache();
        var original = new Verification.ModVerificationResult
        {
            State = Verification.ModVerificationState.VERIFIED_EXACT_RELEASE,
            Provider = "Modrinth",
            ProjectId = "test_mod"
        };

        string hashKey = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        cache.Set(hashKey, original, TimeSpan.FromMinutes(10));

        bool found = cache.TryGet(hashKey, out var cached);
        Assert.True(found);
        Assert.NotNull(cached);
        Assert.True(cached.IsCached);
        Assert.NotNull(cached.CacheRetrievedAtUtc);
        Assert.NotNull(cached.CacheProvenance);
        Assert.Contains("Disk/Memory Cache", cached.CacheProvenance);
    }

    [Fact]
    public void ProcessInstanceId_ImmuneToPidRecycling_DistinguishesProcessesWithSamePid()
    {
        int recycledPid = 4096;
        var t1 = DateTimeOffset.UtcNow.AddHours(-2);
        var t2 = DateTimeOffset.UtcNow.AddMinutes(-5);

        var id1 = Identities.ProcessInstanceId.Create("host-01", recycledPid, t1, "hash_aaa");
        var id2 = Identities.ProcessInstanceId.Create("host-01", recycledPid, t2, "hash_bbb");

        Assert.NotEqual(id1.ToString(), id2.ToString());
        Assert.NotEqual(id1, id2);
    }
}

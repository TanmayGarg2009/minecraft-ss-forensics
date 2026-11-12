using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Tests;

public class PrivacyBoundaryCompletenessTests
{
    [Fact]
    public void CreateSanitizedCopy_RedactsIdentityAcrossReportAndEvidence()
    {
        var report = new StandaloneReport();
        report.TargetSystem.MachineIdentifier = "PRIVATE-HOST";
        report.TargetSystem.UserIdentifier = "PRIVATE-USER";
        report.MinecraftInstallations.Add(new MinecraftInstallationInfo { RootPath = @"C:\Users\Alice\.minecraft" });
        report.EvidenceItems.Add(new EvidenceReferenceItem
        {
            FilePath = @"C:\Users\Alice\Downloads\payload.jar",
            SourceArtifact = @"C:\Users\Alice\Downloads\payload.jar",
            Description = @"Found at C:\Users\Alice\Downloads\payload.jar",
            ProcessIdentity = @"C:\Users\Alice\javaw.exe"
        });
        report.CorrelatedAssessments.Add(new Correlation.CorrelatedSoftwareAssessment
        {
            FilePath = @"C:\Users\Alice\Downloads\payload.jar",
            StateDescription = @"Located under C:\Users\Alice\Downloads"
        });
        report.EvidenceGraph = new Graph.EvidenceGraph();
        report.EvidenceGraph.AddNode(new Graph.GraphEntity
        {
            EntityId = "proc:PRIVATE-HOST:42:1000:deadbeef",
            Type = Graph.EntityType.OsProcess,
            Properties = { ["ExecutablePath"] = @"C:\Users\Alice\javaw.exe" }
        });

        var sanitized = PrivacyBoundary.CreateSanitizedCopy(report);
        string json = System.Text.Json.JsonSerializer.Serialize(sanitized);

        Assert.DoesNotContain("PRIVATE-HOST", json);
        Assert.DoesNotContain("PRIVATE-USER", json);
        Assert.DoesNotContain("Alice", json);
        Assert.Contains("[REDACTED_USER]", json);
        Assert.Contains("[REDACTED_HOST]", json);
        Assert.Contains("payload.jar", json);
        Assert.Equal("PRIVATE-HOST", report.TargetSystem.MachineIdentifier);
        Assert.Contains("Alice", report.EvidenceItems[0].FilePath);
    }
}

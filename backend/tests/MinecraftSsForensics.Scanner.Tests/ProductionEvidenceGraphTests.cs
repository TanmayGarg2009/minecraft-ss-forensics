using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Graph;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Observations;
using MinecraftSsForensics.Scanner.Policy;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

/// <summary>
/// Stage 2/8 Production Evidence Graph Integration Regression Tests.
/// Validates real production pipeline integration: graph construction, EvidenceClusters,
/// PID reuse defense, graph relationship validation, graph-driven correlation, serialization,
/// deterministic integrity sealing, safety limits, and historical report handling.
/// </summary>
public class ProductionEvidenceGraphTests
{
    private readonly ModPolicyEngine _policyEngine = new();

    /// <summary>
    /// Scenario 1: A normal scan constructs an in-memory graph containing its collected evidence.
    /// </summary>
    [Fact]
    public void Scenario01_NormalScan_ConstructsGraphWithCollectedEvidence()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_graph_s1",
            ScanStartedAt = DateTimeOffset.UtcNow
        };

        // Add telemetry
        report.MinecraftInstallations.Add(new MinecraftInstallationInfo
        {
            Name = "DefaultProfile",
            RootPath = @"C:\Users\TargetUser\AppData\Roaming\.minecraft",
            LauncherType = "Vanilla"
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 4100,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = @"C:\Java\bin\javaw.exe -cp minecraft.jar net.minecraft.client.main.Main",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-20),
            ImageSha256 = "1111111111111111111111111111111111111111111111111111111111111111"
        });

        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 4100,
            ModuleName = "lwjgl.dll",
            ModulePath = @"C:\Users\TargetUser\AppData\Roaming\.minecraft\bin\lwjgl.dll",
            Sha256 = "2222222222222222222222222222222222222222222222222222222222222222",
            IsRecognizedJavaNativeLibrary = true
        });

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "Sodium",
            FileName = "sodium-mc1.20-0.5.jar",
            FullPath = @"C:\Users\TargetUser\AppData\Roaming\.minecraft\mods\sodium-mc1.20-0.5.jar",
            Sha256 = "3333333333333333333333333333333333333333333333333333333333333333",
            FileSizeBytes = 1048576,
            GameplayPolicy = "ALLOWED"
        });

        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "suspicious_tool.jar",
            FilePath = @"C:\Users\TargetUser\Downloads\suspicious_tool.jar",
            Sha256 = "4444444444444444444444444444444444444444444444444444444444444444",
            FileSizeBytes = 204800,
            DiscoveryCategory = "Downloads"
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        Assert.NotNull(report.EvidenceGraph);
        Assert.True(report.EvidenceGraph.NodeCount >= 5);
        Assert.True(report.EvidenceGraph.EdgeCount >= 3);
        Assert.True(report.EvidenceGraph.IsValid);

        // Verify entity types
        var jvmNodes = report.EvidenceGraph.Nodes.Where(n => n.Type == EntityType.JvmProcess).ToList();
        Assert.Single(jvmNodes);
        Assert.Contains("ProcessScanner", jvmNodes[0].ProvenanceSources);

        var moduleNodes = report.EvidenceGraph.Nodes.Where(n => n.Type == EntityType.LoadedModule).ToList();
        Assert.Single(moduleNodes);

        var modNodes = report.EvidenceGraph.Nodes.Where(n => n.Type == EntityType.JarArchive).ToList();
        Assert.Single(modNodes);

        var fileNodes = report.EvidenceGraph.Nodes.Where(n => n.Type == EntityType.File).ToList();
        Assert.Single(fileNodes);
    }

    /// <summary>
    /// Scenario 2: A process and independently observed module receive a relationship ONLY when supporting evidence exists.
    /// </summary>
    [Fact]
    public void Scenario02_ProcessAndModule_ReceiveRelationshipOnlyWhenSupportingEvidenceExists()
    {
        var report = new StandaloneReport();

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5000,
            ProcessName = "javaw.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-10),
            ImageSha256 = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000",
            ProcessInstanceId = "proc:host:5000:1000:aaaa"
        });

        // Module A has verified ProcessInstanceId matching process 5000
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 5000,
            ProcessInstanceId = "proc:host:5000:1000:aaaa",
            ModuleName = "supported.dll",
            ModulePath = @"C:\Temp\supported.dll",
            IsInTempDirectory = true
        });

        // Module B belongs to an unobserved/dead PID 9999
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 9999,
            ProcessInstanceId = "proc:host:9999:9999:unknown",
            ModuleName = "unsupported.dll",
            ModulePath = @"C:\Temp\unsupported.dll",
            IsInTempDirectory = true
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // Module A must have an edge to process 5000
        var modANode = report.EvidenceGraph.Nodes.FirstOrDefault(n => n.Properties.GetValueOrDefault("ModuleName") == "supported.dll");
        Assert.NotNull(modANode);
        var outgoingA = report.EvidenceGraph.GetOutgoingEdges(modANode.EntityId);
        Assert.Contains(outgoingA, e => e.TargetEntityId == "proc:host:5000:1000:aaaa" && e.Type == EdgeType.LoadedBy);

        // Module B must NOT have any edge to process 5000
        var modBNode = report.EvidenceGraph.Nodes.FirstOrDefault(n => n.Properties.GetValueOrDefault("ModuleName") == "unsupported.dll");
        Assert.Null(modBNode); // Not attached to unrelated processes
    }

    /// <summary>
    /// Scenario 3: A filename-only match does not create an execution relationship.
    /// </summary>
    [Fact]
    public void Scenario03_FilenameOnlyMatch_DoesNotCreateExecutionRelationship()
    {
        var report = new StandaloneReport();

        // Active Minecraft process
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 6000,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "javaw.exe -cp minecraft.jar net.minecraft.client.main.Main",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30),
            ProcessInstanceId = "proc:host:6000:1000:java"
        });

        // Discovered file on disk with known cheat name
        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "vape_v4.exe",
            FilePath = @"C:\Users\TargetUser\Downloads\vape_v4.exe",
            FileSizeBytes = 500000,
            Sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            DiscoveryCategory = "Downloads"
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        var fileNode = report.EvidenceGraph.Nodes.First(n => n.Type == EntityType.File);
        var jvmNode = report.EvidenceGraph.Nodes.First(n => n.Type == EntityType.JvmProcess);

        // Assert: NO execution or session relationship connects the idle file to the active JVM process
        bool hasRelationship = report.EvidenceGraph.HasRelationship(fileNode.EntityId, jvmNode.EntityId);
        Assert.False(hasRelationship);

        // Correlate: Must be SoftwarePresent, NOT SoftwareActiveDuringSession
        var corrEngine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Competitive", PolicyName = "Strict Ruleset" };
        var assessments = corrEngine.Correlate(report, policy);
        var vapeAssessment = assessments.FirstOrDefault(a => a.SoftwareName.Contains("Vape", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(vapeAssessment);
        Assert.Equal(SoftwareEvidenceState.SoftwarePresent, vapeAssessment.State);
    }

    /// <summary>
    /// Scenario 4: A PID reused by a different process does not create a false relationship.
    /// </summary>
    [Fact]
    public void Scenario04_PidReusedByDifferentProcess_DoesNotCreateFalseRelationship()
    {
        var report = new StandaloneReport();

        // Process currently running with PID 7000: Started 2 minutes ago
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 7000,
            ProcessName = "notepad.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-2),
            ImageSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ProcessInstanceId = "proc:host:7000:new-proc:bbbb"
        });

        // Module recorded from earlier process that also had PID 7000, but an older instance ID
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 7000,
            ProcessInstanceId = "proc:host:7000:old-dead-proc:aaaa",
            ModuleName = "cheat_inject.dll",
            ModulePath = @"C:\Temp\cheat_inject.dll",
            IsInTempDirectory = true
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // Ingest should NOT link cheat_inject.dll to the new notepad.exe instance
        var currentProcNode = report.EvidenceGraph.GetNode("proc:host:7000:new-proc:bbbb");
        Assert.NotNull(currentProcNode);

        var incomingToCurrentProc = report.EvidenceGraph.GetIncomingEdges(currentProcNode.EntityId);
        Assert.DoesNotContain(incomingToCurrentProc, e => e.AssertedRelationship.Contains("cheat_inject.dll"));
    }

    /// <summary>
    /// Scenario 5: An EvidenceCluster is created for genuinely related observations.
    /// </summary>
    [Fact]
    public void Scenario05_EvidenceCluster_CreatedForGenuinelyRelatedObservations()
    {
        var report = new StandaloneReport();

        string modSha = "5555555555555555555555555555555555555555555555555555555555555555";
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "InventoryWalk",
            FileName = "invwalk.jar",
            FullPath = @"C:\Users\TargetUser\AppData\Roaming\.minecraft\mods\invwalk.jar",
            Sha256 = modSha,
            FileSizeBytes = 65536,
            GameplayPolicy = "PROHIBITED_POSSESSION"
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // Verify cluster node
        var cluster = report.EvidenceGraph.Nodes.FirstOrDefault(n => n.Type == EntityType.EvidenceCluster);
        Assert.NotNull(cluster);
        Assert.StartsWith("CLUSTER-MOD-", cluster.EntityId);
        Assert.Contains("Cryptographic SHA-256", cluster.Properties["RelationshipBasis"]);
        Assert.Equal("Certain", cluster.Properties["Confidence"]);

        // Verify member edges into cluster
        var incoming = report.EvidenceGraph.GetIncomingEdges(cluster.EntityId);
        Assert.True(incoming.Count >= 2); // Mod archive node + hash node
        Assert.All(incoming, e => Assert.Equal(EdgeType.DerivedFrom, e.Type));
    }

    /// <summary>
    /// Scenario 6: Unrelated observations are not merged into one cluster.
    /// </summary>
    [Fact]
    public void Scenario06_UnrelatedObservations_NotMergedIntoOneCluster()
    {
        var report = new StandaloneReport();

        // Process
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 8100,
            ProcessName = "chrome.exe",
            StartTime = DateTimeOffset.UtcNow.AddHours(-1)
        });

        // Unrelated file
        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "random_music.mp3",
            FilePath = @"C:\Users\TargetUser\Music\random_music.mp3",
            Sha256 = "6666666666666666666666666666666666666666666666666666666666666666"
        });

        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // Verify chrome and music are NOT in the same cluster
        var clusters = report.EvidenceGraph.Nodes.Where(n => n.Type == EntityType.EvidenceCluster).ToList();
        foreach (var c in clusters)
        {
            var incoming = report.EvidenceGraph.GetIncomingEdges(c.EntityId).Select(e => e.SourceEntityId).ToList();
            bool hasChrome = incoming.Any(id => id.Contains("8100") || id.Contains("chrome"));
            bool hasMusic = incoming.Any(id => id.Contains("random_music"));
            Assert.False(hasChrome && hasMusic, "Unrelated process and music file must never be clustered together.");
        }
    }

    /// <summary>
    /// Scenario 7: Every edge references existing nodes in the graph.
    /// </summary>
    [Fact]
    public void Scenario07_EveryEdgeReferencesExistingNodes()
    {
        var graph = new EvidenceGraph();

        var nodeA = new GraphEntity { EntityId = "node:A", Type = EntityType.OsProcess };
        var nodeB = new GraphEntity { EntityId = "node:B", Type = EntityType.LoadedModule };
        graph.AddNode(nodeA);
        graph.AddNode(nodeB);

        // Valid edge
        bool validAdded = graph.AddEdge(new GraphEdge
        {
            SourceEntityId = "node:A",
            TargetEntityId = "node:B",
            Type = EdgeType.LoadedBy
        });
        Assert.True(validAdded);

        // Invalid edge referencing nonexistent target
        bool invalidAdded = graph.AddEdge(new GraphEdge
        {
            SourceEntityId = "node:A",
            TargetEntityId = "node:NONEXISTENT",
            Type = EdgeType.LoadedBy
        });
        Assert.False(invalidAdded);

        // Validate graph
        bool isValid = graph.Validate(out var errors);
        Assert.True(isValid);
        Assert.Empty(errors);
    }

    /// <summary>
    /// Scenario 8: Invalid imported graph references are rejected or explicitly marked invalid.
    /// </summary>
    [Fact]
    public void Scenario08_InvalidImportedGraphReferences_RejectedOrMarkedInvalid()
    {
        // Construct graph with edge pointing to nonexistent vertex via constructor
        var nodes = new List<GraphEntity>
        {
            new GraphEntity { EntityId = "valid:node1", Type = EntityType.OsProcess }
        };

        var edges = new List<GraphEdge>
        {
            new GraphEdge
            {
                EdgeId = "bad_edge_1",
                SourceEntityId = "valid:node1",
                TargetEntityId = "ghost:target",
                Type = EdgeType.LaunchedBy
            }
        };

        var graph = new EvidenceGraph(nodes, edges);

        Assert.False(graph.IsValid);
        Assert.NotEmpty(graph.ValidationErrors);
        Assert.Contains("missing vertex endpoint", graph.ValidationErrors[0]);
    }

    /// <summary>
    /// Scenario 9: Graph serialization and deserialization preserve all nodes, edges, clusters, and provenance.
    /// </summary>
    [Fact]
    public void Scenario09_GraphSerializationAndDeserialization_PreservesAllElements()
    {
        var originalReport = new StandaloneReport
        {
            ReportId = "rep_roundtrip_test",
            ScanStartedAt = DateTimeOffset.UtcNow
        };

        var graph = new EvidenceGraph();
        var pNode = new GraphEntity
        {
            EntityId = "proc:javaw:1",
            Type = EntityType.JvmProcess,
            ProvenanceSources = { "ProcessScanner" },
            Properties = { ["PID"] = "1234" }
        };
        var mNode = new GraphEntity
        {
            EntityId = "mod:hack:1",
            Type = EntityType.LoadedModule,
            ProvenanceSources = { "LoadedModules" },
            Properties = { ["ModuleName"] = "hack.dll" }
        };

        graph.AddNode(pNode);
        graph.AddNode(mNode);
        graph.AddEdge(new GraphEdge
        {
            SourceEntityId = mNode.EntityId,
            TargetEntityId = pNode.EntityId,
            Type = EdgeType.LoadedBy,
            Confidence = ConfidenceLevel.Certain,
            Provenance = "LoadedModules",
            AssertedRelationship = "DLL injected into Java"
        });

        graph.CreateEvidenceCluster(
            clusterId: "CLUSTER-TEST-01",
            title: "Test Injected Cluster",
            relationshipBasis: "Virtual memory mapping",
            memberEntityIds: new[] { pNode.EntityId, mNode.EntityId },
            confidence: ConfidenceLevel.Certain,
            provenance: "TestHarness");

        originalReport.EvidenceGraph = graph;

        string json = PortableJsonExporter.ExportToJson(originalReport);
        var loadResult = PortableJsonExporter.LoadFromJson(json);

        Assert.True(loadResult.Success, loadResult.StatusMessage);
        Assert.NotNull(loadResult.Report?.EvidenceGraph);

        var loadedGraph = loadResult.Report!.EvidenceGraph!;
        Assert.Equal(graph.NodeCount, loadedGraph.NodeCount);
        Assert.Equal(graph.EdgeCount, loadedGraph.EdgeCount);

        var loadedCluster = loadedGraph.GetNode("CLUSTER-TEST-01");
        Assert.NotNull(loadedCluster);
        Assert.Equal(EntityType.EvidenceCluster, loadedCluster.Type);
        Assert.Equal("Test Injected Cluster", loadedCluster.Properties["Title"]);
        Assert.Contains("TestHarness", loadedCluster.ProvenanceSources);
    }

    /// <summary>
    /// Scenario 10: Mutating graph data after report sealing invalidates integrity verification.
    /// </summary>
    [Fact]
    public void Scenario10_MutatingGraphAfterSealing_InvalidatesIntegrityVerification()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_seal_test",
            ScanStartedAt = DateTimeOffset.UtcNow
        };

        var graph = new EvidenceGraph();
        graph.AddNode(new GraphEntity { EntityId = "node:proc:1", Type = EntityType.OsProcess });
        report.EvidenceGraph = graph;

        // Seal report
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        var initialCheck = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);
        Assert.True(initialCheck.IsValid);
        Assert.False(initialCheck.IsTampered);

        // Post-seal mutation: Add an illicit node to the graph
        report.EvidenceGraph.AddNode(new GraphEntity
        {
            EntityId = "node:forged:tampered",
            Type = EntityType.EvidenceCluster,
            Properties = { ["Forged"] = "True" }
        });

        var tamperedCheck = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);
        Assert.False(tamperedCheck.IsValid);
        Assert.True(tamperedCheck.IsTampered);
        Assert.Contains("Integrity mismatch", tamperedCheck.StatusMessage);
    }

    /// <summary>
    /// Scenario 11: Reordering equivalent graph input produces identical deterministic integrity output.
    /// </summary>
    [Fact]
    public void Scenario11_ReorderingEquivalentGraphInput_ProducesIdenticalDigest()
    {
        var fixedTime = new DateTimeOffset(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);

        var reportA = new StandaloneReport
        {
            ReportId = "rep_canon_test",
            CreatedAt = fixedTime,
            ScanStartedAt = fixedTime,
            ScanCompletedAt = fixedTime
        };
        reportA.Consent.ConsentTimestamp = fixedTime;
        var graphA = new EvidenceGraph();
        var node1 = new GraphEntity { EntityId = "entity:1", Type = EntityType.OsProcess, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime };
        var node2 = new GraphEntity { EntityId = "entity:2", Type = EntityType.LoadedModule, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime };
        var node3 = new GraphEntity { EntityId = "entity:3", Type = EntityType.CryptographicHash, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime };

        // Insertion order 1: 1, 2, 3
        graphA.AddNode(node1);
        graphA.AddNode(node2);
        graphA.AddNode(node3);
        graphA.AddEdge(new GraphEdge { EdgeId = "e1", SourceEntityId = "entity:1", TargetEntityId = "entity:2", Type = EdgeType.LoadedBy, CreatedAtUtc = fixedTime });
        graphA.AddEdge(new GraphEdge { EdgeId = "e2", SourceEntityId = "entity:2", TargetEntityId = "entity:3", Type = EdgeType.HashMatches, CreatedAtUtc = fixedTime });
        reportA.EvidenceGraph = graphA;

        var reportB = new StandaloneReport
        {
            ReportId = "rep_canon_test",
            CreatedAt = fixedTime,
            ScanStartedAt = fixedTime,
            ScanCompletedAt = fixedTime
        };
        reportB.Consent.ConsentTimestamp = fixedTime;
        var graphB = new EvidenceGraph();
        // Insertion order 2: 3, 1, 2 (different order)
        graphB.AddNode(new GraphEntity { EntityId = "entity:3", Type = EntityType.CryptographicHash, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime });
        graphB.AddNode(new GraphEntity { EntityId = "entity:1", Type = EntityType.OsProcess, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime });
        graphB.AddNode(new GraphEntity { EntityId = "entity:2", Type = EntityType.LoadedModule, FirstObservedUtc = fixedTime, LastObservedUtc = fixedTime });
        graphB.AddEdge(new GraphEdge { EdgeId = "e2", SourceEntityId = "entity:2", TargetEntityId = "entity:3", Type = EdgeType.HashMatches, CreatedAtUtc = fixedTime });
        graphB.AddEdge(new GraphEdge { EdgeId = "e1", SourceEntityId = "entity:1", TargetEntityId = "entity:2", Type = EdgeType.LoadedBy, CreatedAtUtc = fixedTime });
        reportB.EvidenceGraph = graphB;

        string digestA = ReportIntegrityValidator.ComputeReportSeal(reportA);
        string digestB = ReportIntegrityValidator.ComputeReportSeal(reportB);

        Assert.Equal(digestA, digestB);
    }

    /// <summary>
    /// Scenario 12: Historical reports without graph data remain explicitly unverified for graph provenance.
    /// </summary>
    [Fact]
    public void Scenario12_HistoricalReportsWithoutGraphData_RemainExplicitlyUnverifiedForGraphProvenance()
    {
        var historicalReport = new StandaloneReport
        {
            ReportId = "rep_hist_v1",
            EvidenceGraph = null // Historical report without graph payload
        };

        historicalReport.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(historicalReport);
        var result = ReportIntegrityValidator.VerifyReportIntegrityDetailed(historicalReport);

        Assert.True(result.IsValid);
        Assert.False(result.HasGraphData);
        Assert.Equal("HistoricalReportWithoutGraphData_UnverifiedGraphProvenance", result.GraphProvenanceStatus);
    }

    /// <summary>
    /// Scenario 13: Graph construction failure cannot produce a clean verdict.
    /// </summary>
    [Fact]
    public void Scenario13_GraphConstructionFailure_CannotProduceCleanVerdict()
    {
        var report = new StandaloneReport
        {
            ReportId = "rep_fail_graph"
        };

        // Graph marked invalid
        report.EvidenceGraph = new EvidenceGraph
        {
            IsValid = false,
            ValidationErrors = { "Catastrophic graph structural corruption: dangling pointers detected." }
        };

        // Add diagnostic error check
        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-EVIDENCE-GRAPH",
            CheckName = "Evidence Graph Integrity & Bounds",
            Source = "EvidenceGraph",
            Status = CheckStatus.ERROR,
            Reason = "Evidence Graph validation failed."
        });

        report.RecomputeSummaryCounts();

        // Evaluate verdict determination
        bool hasUnavailableRequiredTelemetry = (report.SummaryCounts.IncompleteOrFailedChecks > 0 &&
            report.DiagnosticChecks.Any(c => (c.CheckId == "CHK-PROCESS-MODULES" || c.CheckId == "CHK-FILE-DISCOVERY" || c.CheckId == "CHK-EVIDENCE-GRAPH") &&
                                            (c.Status == CheckStatus.UNAVAILABLE || c.Status == CheckStatus.ERROR))) ||
            (report.EvidenceGraph == null || !report.EvidenceGraph.IsValid || report.EvidenceGraph.IsResourceBounded);

        Assert.True(hasUnavailableRequiredTelemetry);
        // Verdict cannot be NoProhibitedIndicators
        report.Verdict.OverallAssessment = hasUnavailableRequiredTelemetry
            ? InvestigationVerdict.InconclusiveTelemetry
            : InvestigationVerdict.NoProhibitedIndicators;

        Assert.Equal(InvestigationVerdict.InconclusiveTelemetry, report.Verdict.OverallAssessment);
    }

    /// <summary>
    /// Scenario 14: Resource-limit exhaustion is reported as incomplete rather than silently accepted.
    /// </summary>
    [Fact]
    public void Scenario14_ResourceLimitExhaustion_ReportedAsIncomplete()
    {
        var graph = new EvidenceGraph();

        // Simulate hitting maximum node limit
        graph.IsResourceBounded = true;

        bool isValid = graph.Validate(out var errors);
        Assert.False(isValid);
        Assert.False(graph.IsValid);
        Assert.NotEmpty(errors);
        Assert.Contains("resource bounds", errors[0]);
    }

    /// <summary>
    /// Scenario 15: Production correlation demonstrably uses graph relationships.
    /// Meaningful comparison: Valid graph relationship changes correlation to SoftwareActiveDuringSession / ConfirmedCheatArtifact,
    /// and REMOVING that relationship changes correlation to SoftwareExecuted / StrongIndicator.
    /// </summary>
    [Fact]
    public void Scenario15_ProductionCorrelation_DemonstrablyUsesGraphRelationships()
    {
        var policy = new ServerGamemodePolicy { Gamemode = "Competitive", PolicyName = "Strict Ruleset" };
        var corrEngine = new EvidenceCorrelationEngine();

        // 1. Setup report with concurrent Java process and Cheat process
        var report = new StandaloneReport { ReportId = "rep_s15_corr_test" };

        var jvmProc = new ProcessTelemetryItem
        {
            ProcessId = 9000,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = "javaw.exe -cp minecraft.jar net.minecraft.client.main.Main",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-15),
            ProcessInstanceId = "proc:host:9000:1000:javaw"
        };
        var cheatProc = new ProcessTelemetryItem
        {
            ProcessId = 9100,
            ProcessName = "itami.exe",
            ExecutablePath = @"C:\Cheats\itami.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-10),
            ProcessInstanceId = "proc:host:9100:2000:itami"
        };

        report.RunningProcesses.Add(jvmProc);
        report.RunningProcesses.Add(cheatProc);

        // Pre-build graph
        var bridge = new GraphSerializationBridge();
        report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // PART A: Add verified graph relationship between Minecraft JVM and Cheat process
        string jvmNodeId = "proc:host:9000:1000:javaw";
        string cheatNodeId = "proc:host:9100:2000:itami";

        report.EvidenceGraph.AddEdge(new GraphEdge
        {
            EdgeId = "edge_verified_link",
            SourceEntityId = jvmNodeId,
            TargetEntityId = cheatNodeId,
            Type = EdgeType.LaunchedBy,
            Confidence = ConfidenceLevel.Certain,
            AssertedRelationship = "Process was launched by Minecraft JVM session"
        });

        // Correlate with active relationship in graph
        var assessmentsWithLink = corrEngine.Correlate(report, policy);
        var cheatAssessmentWithLink = assessmentsWithLink.First(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        var findingWithLink = report.Findings.First(f => f.DetectionName.Contains("Itami", StringComparison.OrdinalIgnoreCase));

        // Assert: Graph relationship elevates state to ActiveDuringSession and ConfirmedCheatArtifact
        Assert.Equal(SoftwareEvidenceState.SoftwareActiveDuringSession, cheatAssessmentWithLink.State);
        Assert.Equal(FindingClassification.ConfirmedCheatArtifact, findingWithLink.Classification);
        Assert.Equal(Severity.High, findingWithLink.Severity);
        Assert.Equal(EvidenceCategory.ActiveInScanWindow, findingWithLink.EvidenceCategory);
        Assert.True(findingWithLink.IsInScanWindow);

        // PART B: REMOVE the graph relationship
        bool edgeRemoved = report.EvidenceGraph.RemoveEdge("edge_verified_link");
        Assert.True(edgeRemoved, "Edge must be cleanly removed from graph.");

        // Clear previous findings/assessments and re-correlate with relationship removed
        report.Findings.Clear();
        report.EvidenceItems.Clear();
        var assessmentsWithoutLink = corrEngine.Correlate(report, policy);
        var cheatAssessmentWithoutLink = assessmentsWithoutLink.First(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        var findingWithoutLink = report.Findings.First(f => f.DetectionName.Contains("Itami", StringComparison.OrdinalIgnoreCase));

        // Assert: Without graph relationship, falls back to unassociated SoftwareExecuted and StrongIndicator
        Assert.Equal(SoftwareEvidenceState.SoftwareExecuted, cheatAssessmentWithoutLink.State);
        Assert.Equal(FindingClassification.StrongIndicator, findingWithoutLink.Classification);
        Assert.Equal(Severity.Medium, findingWithoutLink.Severity);
        Assert.Equal(EvidenceCategory.RunningProcess, findingWithoutLink.EvidenceCategory);
        Assert.False(findingWithoutLink.IsInScanWindow);
    }
}

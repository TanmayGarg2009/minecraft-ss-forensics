using System;
using System.Collections.Generic;
using System.Linq;
using MinecraftSsForensics.Scanner.Graph;
using MinecraftSsForensics.Scanner.Identities;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Observations;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class FoundationalDataArchitectureTests
{
    // ==========================================
    // 1. Observation Model Tests
    // ==========================================

    [Fact]
    public void RawObservation_CreateFileObservation_SetsImmutablePropertiesCorrectly()
    {
        var modTime = DateTimeOffset.UtcNow.AddHours(-2);
        var obs = RawObservation.CreateFileObservation(
            collectorName: "FileDiscoveryScanner",
            filePath: @"C:\Users\Player\AppData\Roaming\.minecraft\mods\krypton-0.2.3.jar",
            sizeBytes: 81920,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            modifiedUtc: modTime,
            provenance: "DirectoryEnumeration"
        );

        Assert.NotNull(obs.ObservationId);
        Assert.Equal("FileObservation", obs.ObservationType);
        Assert.Equal("FileDiscoveryScanner", obs.SourceCollector);
        Assert.Equal("NTFS_MFT", obs.SourceIdentity);
        Assert.Equal("DirectoryEnumeration", obs.Provenance);
        Assert.Equal(CollectionStatus.Success, obs.AvailabilityState);
        Assert.Equal(modTime, obs.EventTimestampUtc);
        Assert.NotNull(obs.TargetEntityId);
        Assert.StartsWith("file:", obs.TargetEntityId);
        Assert.Equal("81920", obs.Properties["SizeBytes"]);
    }

    [Fact]
    public void RawObservation_CreateProcessObservation_GeneratesStableTargetEntityId()
    {
        var startTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        var obs = RawObservation.CreateProcessObservation(
            collectorName: "ProcessScanner",
            pid: 4321,
            processName: "javaw.exe",
            executablePath: @"C:\Program Files\Java\bin\javaw.exe",
            startTimeUtc: startTime,
            commandLine: "-Xmx4G -jar server.jar",
            imageSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );

        Assert.Equal("ProcessObservation", obs.ObservationType);
        Assert.Equal(startTime, obs.EventTimestampUtc);
        Assert.NotNull(obs.TargetEntityId);
        Assert.StartsWith("proc:", obs.TargetEntityId);
        Assert.Contains(":4321:", obs.TargetEntityId);
        Assert.Contains(startTime.UtcTicks.ToString(), obs.TargetEntityId);
    }

    [Fact]
    public void CollectionOutcome_FactoryMethods_RepresentExecutionStatesAccurately()
    {
        var success = CollectionOutcome.Succeeded("PrefetchScanner", 12, TimeSpan.FromMilliseconds(150));
        Assert.Equal(CollectionStatus.Success, success.Status);
        Assert.Equal(12, success.ItemsCollected);
        Assert.Equal(TimeSpan.FromMilliseconds(150), success.Duration);

        var partial = CollectionOutcome.PartiallySucceeded("ArchiveInspector", 5, TimeSpan.FromSeconds(2), "1 file locked");
        Assert.Equal(CollectionStatus.PartialSuccess, partial.Status);
        Assert.Equal("1 file locked", partial.Reason);

        var unavail = CollectionOutcome.SourceUnavailable("UsnJournalScanner", "Volume does not support USN");
        Assert.Equal(CollectionStatus.Unavailable, unavail.Status);

        var timeout = CollectionOutcome.TimedOut("DeepBytecodeScanner", TimeSpan.FromSeconds(10));
        Assert.Equal(CollectionStatus.Timeout, timeout.Status);
        Assert.Contains("10.0s", timeout.Reason);
    }

    // ==========================================
    // 2. Composite Entity Identity Tests
    // ==========================================

    [Fact]
    public void ProcessInstanceId_DistinguishesRecycledPIDsAcrossTime()
    {
        // PID 8080 used by Process A at T0
        var t0 = DateTimeOffset.UtcNow.AddHours(-1);
        var procA = ProcessInstanceId.Create("desktop-test", 8080, t0, "hash_aaa");

        // Windows recycles PID 8080 for Process B at T1
        var t1 = DateTimeOffset.UtcNow.AddMinutes(-5);
        var procB = ProcessInstanceId.Create("desktop-test", 8080, t1, "hash_bbb");

        Assert.NotEqual(procA, procB);
        Assert.NotEqual(procA.ToString(), procB.ToString());
        Assert.Equal(8080, procA.ProcessId);
        Assert.Equal(8080, procB.ProcessId);
        Assert.NotEqual(procA.StartTimeTicks, procB.StartTimeTicks);
    }

    [Fact]
    public void ProcessInstanceId_ParseAndToString_AreDeterministicAndInvertible()
    {
        var original = new ProcessInstanceId("node01", 1234, 638000000000000000L, "deadbeef12345678");
        string formatted = original.ToString();
        Assert.Equal("proc:node01:1234:638000000000000000:deadbeef12345678", formatted);

        var parsed = ProcessInstanceId.Parse(formatted);
        Assert.Equal(original, parsed);
        Assert.False(parsed.IsProvisional);

        bool success = ProcessInstanceId.TryParse("invalid:string", out var failed);
        Assert.False(success);
    }

    [Fact]
    public void CompositeIdentities_ModuleAndFileAndSession_FormatCorrectly()
    {
        var modId = new ModuleInstanceId("proc:local:100:63800:hash", "0x7ffa1000", 65536, "modhash");
        Assert.Equal("mod:proc:local:100:63800:hash:0x7ffa1000:65536:modhash", modId.ToString());

        var fileId = new FileInstanceId(@"C:\Games\.minecraft\mods\test.jar", 1024, "filehash");
        Assert.Equal("file:c:/games/.minecraft/mods/test.jar:1024:filehash", fileId.ToString());

        var sessionTime = DateTimeOffset.UtcNow;
        var sessionId = new MinecraftSessionId("proc:local:100:63800:hash", sessionTime);
        Assert.Equal($"session:proc:local:100:63800:hash:{sessionTime.UtcTicks}", sessionId.ToString());
    }

    // ==========================================
    // 3. Evidence Graph Tests
    // ==========================================

    [Fact]
    public void EvidenceGraph_AddNodeAndEdge_MaintainsAdjacency()
    {
        var graph = new EvidenceGraph();

        var procNode = new GraphEntity
        {
            EntityId = "proc:local:1000:100:hash",
            Type = EntityType.JvmProcess
        };

        var modNode = new GraphEntity
        {
            EntityId = "mod:proc:local:1000:100:hash:0x1000:200:modhash",
            Type = EntityType.LoadedModule
        };

        Assert.True(graph.AddNode(procNode));
        Assert.True(graph.AddNode(modNode));
        Assert.False(graph.AddNode(procNode)); // Duplicate prevented

        var edge = new GraphEdge
        {
            SourceEntityId = modNode.EntityId,
            TargetEntityId = procNode.EntityId,
            Type = EdgeType.LoadedBy,
            Confidence = ConfidenceLevel.Certain,
            AssertedRelationship = "Loaded into memory"
        };

        Assert.True(graph.AddEdge(edge));
        Assert.False(graph.AddEdge(edge)); // Duplicate edge prevented

        var outgoing = graph.GetOutgoingEdges(modNode.EntityId);
        Assert.Single(outgoing);
        Assert.Equal(procNode.EntityId, outgoing[0].TargetEntityId);

        var incoming = graph.GetIncomingEdges(procNode.EntityId);
        Assert.Single(incoming);
        Assert.Equal(modNode.EntityId, incoming[0].SourceEntityId);
    }

    [Fact]
    public void EvidenceGraph_Traverse_BoundsDepthToMaximumFourHops()
    {
        var graph = new EvidenceGraph();

        // Create chain: N0 -> N1 -> N2 -> N3 -> N4 -> N5 -> N6
        for (int i = 0; i <= 6; i++)
        {
            graph.AddNode(new GraphEntity { EntityId = $"node_{i}", Type = EntityType.RawObservation });
        }

        for (int i = 0; i < 6; i++)
        {
            graph.AddEdge(new GraphEdge
            {
                SourceEntityId = $"node_{i}",
                TargetEntityId = $"node_{i + 1}",
                Type = EdgeType.Corroborates
            });
        }

        // Default traversal has maxDepth = 4
        var traversed = graph.Traverse("node_0", maxDepth: 4);

        // From node_0: can reach node_1 (depth 1), node_2 (depth 2), node_3 (depth 3), node_4 (depth 4)
        Assert.Equal(4, traversed.Count);
        Assert.Contains(traversed, n => n.EntityId == "node_1");
        Assert.Contains(traversed, n => n.EntityId == "node_2");
        Assert.Contains(traversed, n => n.EntityId == "node_3");
        Assert.Contains(traversed, n => n.EntityId == "node_4");
        Assert.DoesNotContain(traversed, n => n.EntityId == "node_5");
        Assert.DoesNotContain(traversed, n => n.EntityId == "node_6");
    }

    [Fact]
    public void EvidenceGraph_Traverse_HandlesCyclesGracefullyWithoutInfiniteLoop()
    {
        var graph = new EvidenceGraph();

        // Create cyclic graph: A -> B -> C -> A
        graph.AddNode(new GraphEntity { EntityId = "A", Type = EntityType.RawObservation });
        graph.AddNode(new GraphEntity { EntityId = "B", Type = EntityType.RawObservation });
        graph.AddNode(new GraphEntity { EntityId = "C", Type = EntityType.RawObservation });

        graph.AddEdge(new GraphEdge { SourceEntityId = "A", TargetEntityId = "B", Type = EdgeType.Corroborates });
        graph.AddEdge(new GraphEdge { SourceEntityId = "B", TargetEntityId = "C", Type = EdgeType.Corroborates });
        graph.AddEdge(new GraphEdge { SourceEntityId = "C", TargetEntityId = "A", Type = EdgeType.Corroborates });

        var traversed = graph.Traverse("A", maxDepth: 4);

        // Visited set prevents infinite recursion; reaches B and C once
        Assert.Equal(2, traversed.Count);
        Assert.Contains(traversed, n => n.EntityId == "B");
        Assert.Contains(traversed, n => n.EntityId == "C");
    }

    // ==========================================
    // 4. Graph Serialization Bridge Tests
    // ==========================================

    [Fact]
    public void GraphSerializationBridge_BuildGraphFromObservations_CreatesNodesAndLineageEdges()
    {
        var bridge = new GraphSerializationBridge();
        var obsList = new List<IObservation>
        {
            RawObservation.CreateFileObservation("FileScanner", @"C:\mods\cheat.jar", 1024, "sha256_cheat", DateTimeOffset.UtcNow),
            RawObservation.CreateProcessObservation("ProcessScanner", 9999, "javaw.exe", @"C:\java\bin\javaw.exe", DateTimeOffset.UtcNow, "-Xmx2G", "sha256_java")
        };

        var graph = bridge.BuildGraphFromObservations(obsList);

        Assert.Equal(4, graph.NodeCount); // 2 observations + 2 target entities
        Assert.Equal(2, graph.EdgeCount); // 2 DerivedFrom lineage edges
    }

    [Fact]
    public void GraphSerializationBridge_ProjectGraphToFindings_ProducesCanonicalFindingRecords()
    {
        var bridge = new GraphSerializationBridge();
        var graph = new EvidenceGraph();

        // Create cluster node
        var cluster = new GraphEntity
        {
            EntityId = "cluster:cheataux:01",
            Type = EntityType.EvidenceCluster,
            Properties =
            {
                ["DetectionName"] = "Prohibited Fly Hack Utility",
                ["RuleId"] = "CHEAT-FLY-01",
                ["Severity"] = "High",
                ["Category"] = "CheatArtifact",
                ["FilePath"] = @"C:\mods\flyhack.jar",
                ["Explanation"] = "Corroborated by file discovery and runtime process observation."
            }
        };
        graph.AddNode(cluster);

        var obs = new GraphEntity
        {
            EntityId = "obs:101",
            Type = EntityType.RawObservation
        };
        graph.AddNode(obs);

        graph.AddEdge(new GraphEdge
        {
            SourceEntityId = obs.EntityId,
            TargetEntityId = cluster.EntityId,
            Type = EdgeType.Corroborates
        });

        var findings = bridge.ProjectGraphToFindings(graph);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("CHEAT-FLY-01", finding.RuleId);
        Assert.Equal("Prohibited Fly Hack Utility", finding.FindingTitle);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(FindingCategory.CheatArtifact, finding.Category);
        Assert.Equal("cluster:cheataux:01", finding.EvidenceClusterId);
        Assert.Contains("obs:101", finding.RelatedEvidenceIds);
    }
}

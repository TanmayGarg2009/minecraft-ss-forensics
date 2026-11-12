using System;
using System.Collections.Generic;
using System.Linq;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Observations;

namespace MinecraftSsForensics.Scanner.Graph;

/// <summary>
/// Bridge that deterministically constructs Directed Attributed Evidence Graphs from
/// observations and report telemetry, and projects graph clusters and correlated findings back
/// into canonical finding records.
/// Enforces PID reuse protection, multi-modal evidence clustering, and relationship provenance.
/// </summary>
public class GraphSerializationBridge
{
    /// <summary>
    /// Builds an in-memory Evidence Graph from a collection of raw observations and report telemetry.
    /// </summary>
    public EvidenceGraph BuildGraphFromObservations(
        IEnumerable<IObservation> observations,
        StandaloneReport? baselineReport = null)
    {
        var graph = new EvidenceGraph();

        // 1. Ingest raw observations as vertices
        foreach (var obs in observations)
        {
            var obsEntity = new GraphEntity
            {
                EntityId = $"obs:{obs.ObservationId}",
                Type = EntityType.RawObservation,
                FirstObservedUtc = obs.CollectionTimestampUtc,
                LastObservedUtc = obs.CollectionTimestampUtc,
                ProvenanceSources = { obs.SourceCollector, obs.Provenance }
            };

            foreach (var kvp in obs.Properties)
            {
                obsEntity.Properties[kvp.Key] = kvp.Value;
            }

            graph.AddNode(obsEntity);

            // If observation targets an entity, create entity node and relationship edge
            if (!string.IsNullOrEmpty(obs.TargetEntityId))
            {
                var targetType = InferEntityTypeFromId(obs.TargetEntityId);
                var targetEntity = graph.GetNode(obs.TargetEntityId) ?? new GraphEntity
                {
                    EntityId = obs.TargetEntityId,
                    Type = targetType,
                    FirstObservedUtc = obs.EventTimestampUtc ?? obs.CollectionTimestampUtc,
                    LastObservedUtc = obs.CollectionTimestampUtc,
                    ProvenanceSources = { obs.SourceCollector }
                };

                graph.AddNode(targetEntity);

                graph.AddEdge(new GraphEdge
                {
                    SourceEntityId = obsEntity.EntityId,
                    TargetEntityId = targetEntity.EntityId,
                    Type = EdgeType.DerivedFrom,
                    Confidence = ConfidenceLevel.Certain,
                    AssertedRelationship = "Observation documents properties of target entity",
                    Provenance = obs.Provenance
                });
            }
        }

        // 2. Ingest baseline report entities if supplied
        if (baselineReport != null)
        {
            IngestReportItems(graph, baselineReport);
        }

        // Validate graph integrity
        graph.Validate(out _);

        return graph;
    }

    /// <summary>
    /// Projects graph clusters and correlated findings back into standard FindingRecord instances
    /// suitable for StandaloneReport.Findings serialization.
    /// </summary>
    public List<FindingRecord> ProjectGraphToFindings(EvidenceGraph graph)
    {
        var findings = new List<FindingRecord>();

        // Find all EvidenceCluster nodes
        var clusterNodes = graph.Nodes.Where(n => n.Type == EntityType.EvidenceCluster).ToList();

        foreach (var cluster in clusterNodes)
        {
            var relatedObs = graph.GetIncomingEdges(cluster.EntityId)
                .Where(e => e.Type == EdgeType.Corroborates || e.Type == EdgeType.DerivedFrom)
                .Select(e => e.SourceEntityId)
                .Distinct()
                .ToList();

            cluster.Properties.TryGetValue("DetectionName", out var name);
            cluster.Properties.TryGetValue("RuleId", out var ruleId);
            cluster.Properties.TryGetValue("Severity", out var sevStr);
            cluster.Properties.TryGetValue("Category", out var catStr);
            cluster.Properties.TryGetValue("FilePath", out var filePath);
            cluster.Properties.TryGetValue("Explanation", out var explanation);

            var finding = new FindingRecord
            {
                RuleId = ruleId ?? "GRAPH-CORR-01",
                DetectionName = name ?? "Correlated Evidence Cluster",
                FindingTitle = name ?? "Correlated Evidence Cluster",
                EvidenceClusterId = cluster.EntityId,
                RelatedEvidenceIds = relatedObs,
                FilePath = filePath,
                TechnicalExplanation = explanation ?? "Synthesized from Evidence Graph correlation."
            };

            if (Enum.TryParse<Severity>(sevStr, true, out var sev))
            {
                finding.Severity = sev;
            }

            if (Enum.TryParse<FindingCategory>(catStr, true, out var cat))
            {
                finding.Category = cat;
            }

            findings.Add(finding);
        }

        return findings;
    }

    private void IngestReportItems(EvidenceGraph graph, StandaloneReport report)
    {
        var scanTime = report.ScanStartedAt != default ? report.ScanStartedAt : DateTimeOffset.UtcNow;
        string hostId = Environment.MachineName.ToLowerInvariant();

        // 1. Ingest Minecraft Installations
        var installNodes = new List<string>();
        foreach (var inst in report.MinecraftInstallations)
        {
            string instId = $"install:{inst.RootPath.ToLowerInvariant()}";
            installNodes.Add(instId);
            var instEntity = new GraphEntity
            {
                EntityId = instId,
                Type = EntityType.MinecraftInstallation,
                FirstObservedUtc = scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { "InstallationScanner" },
                Properties =
                {
                    ["RootPath"] = inst.RootPath,
                    ["InstallationName"] = inst.Name ?? "Default",
                    ["LauncherType"] = inst.LauncherType ?? "Vanilla"
                }
            };
            graph.AddNode(instEntity);
        }

        // 2. Ingest Running Processes with Unique Instance Identification (PID Reuse Defense)
        var procsByPid = new Dictionary<int, List<ProcessTelemetryItem>>();
        var procIdsByPid = new Dictionary<int, List<string>>();
        var procMap = new Dictionary<string, ProcessTelemetryItem>();
        var gameProcIds = new List<string>();

        foreach (var proc in report.RunningProcesses)
        {
            long startTicks = proc.StartTime?.UtcTicks ?? 0L;
            string procId = !string.IsNullOrEmpty(proc.ProcessInstanceId)
                ? proc.ProcessInstanceId
                : $"proc:{hostId}:{proc.ProcessId}:{startTicks}:{proc.ImageSha256 ?? "unknown"}";

            if (!procsByPid.TryGetValue(proc.ProcessId, out var pList))
            {
                pList = new List<ProcessTelemetryItem>();
                procsByPid[proc.ProcessId] = pList;
            }
            pList.Add(proc);

            if (!procIdsByPid.TryGetValue(proc.ProcessId, out var idList))
            {
                idList = new List<string>();
                procIdsByPid[proc.ProcessId] = idList;
            }
            idList.Add(procId);

            procMap[procId] = proc;

            bool isGameProc = MinecraftSsForensics.Scanner.Process.MinecraftProcessClassifier.IsMinecraftProcess(proc.ProcessName, proc.SanitizedCommandLine);

            if (isGameProc)
            {
                gameProcIds.Add(procId);
            }

            var procEntity = new GraphEntity
            {
                EntityId = procId,
                Type = isGameProc ? EntityType.JvmProcess : EntityType.OsProcess,
                FirstObservedUtc = proc.StartTime ?? scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { "ProcessScanner" },
                Properties =
                {
                    ["PID"] = proc.ProcessId.ToString(),
                    ["ProcessName"] = proc.ProcessName,
                    ["ProcessInstanceId"] = procId,
                    ["ImageSha256"] = proc.ImageSha256 ?? "unknown",
                    ["CommandLine"] = proc.SanitizedCommandLine ?? string.Empty,
                    ["ExecutablePath"] = proc.ExecutablePath ?? string.Empty,
                    ["StartTimeUtc"] = proc.StartTime?.ToString("o") ?? string.Empty
                }
            };
            graph.AddNode(procEntity);

            // If game process, link to active Minecraft Session
            if (isGameProc)
            {
                string sessionId = "session:active-mc-session";
                if (!graph.ContainsNode(sessionId))
                {
                    graph.AddNode(new GraphEntity
                    {
                        EntityId = sessionId,
                        Type = EntityType.MinecraftSession,
                        FirstObservedUtc = proc.StartTime ?? scanTime,
                        LastObservedUtc = scanTime,
                        ProvenanceSources = { "ProcessScanner" },
                        Properties = { ["SessionState"] = "ActiveGameSession" }
                    });
                }

                graph.AddEdge(new GraphEdge
                {
                    SourceEntityId = procId,
                    TargetEntityId = sessionId,
                    Type = EdgeType.AssociatedWith,
                    Confidence = ConfidenceLevel.Certain,
                    AssertedRelationship = "Process is the active Minecraft JVM host",
                    Provenance = "ProcessScanner"
                });
            }
        }

        // Add parentage edges with temporal & instance checks (Preventing PID reuse cycles/anachronisms)
        foreach (var proc in report.RunningProcesses)
        {
            if (proc.ParentProcessId.HasValue && procIdsByPid.TryGetValue(proc.ProcessId, out var childIds))
            {
                string childId = !string.IsNullOrEmpty(proc.ProcessInstanceId) ? proc.ProcessInstanceId : childIds[0];
                int parentPid = proc.ParentProcessId.Value;

                if (procsByPid.TryGetValue(parentPid, out var candidateParents))
                {
                    // Check if multiple candidates exist
                    if (candidateParents.Count > 1)
                    {
                        proc.AmbiguityReason = $"Ambiguous parent PID {parentPid}: multiple candidate process instances exist; cannot determine true parent.";
                        continue;
                    }

                    var parentProc = candidateParents[0];
                    string parentId = !string.IsNullOrEmpty(parentProc.ProcessInstanceId)
                        ? parentProc.ProcessInstanceId
                        : procIdsByPid[parentPid][0];

                    if (graph.ContainsNode(parentId))
                    {
                        // Check temporal inversion: parent must not start after child (anachronistic PID reuse)
                        if (parentProc.StartTime.HasValue && proc.StartTime.HasValue && parentProc.StartTime.Value > proc.StartTime.Value)
                        {
                            proc.AmbiguityReason = $"Temporal inversion detected: Parent {parentProc.ProcessName} (PID {parentProc.ProcessId}) started at {parentProc.StartTime:o} which is AFTER child {proc.ProcessName} (PID {proc.ProcessId}) started at {proc.StartTime:o}. Refusing to link unrelated process lifetimes.";
                            continue;
                        }

                        // Consistent: add edge
                        graph.AddEdge(new GraphEdge
                        {
                            SourceEntityId = parentId,
                            TargetEntityId = childId,
                            Type = EdgeType.LaunchedBy,
                            Confidence = ConfidenceLevel.Certain,
                            AssertedRelationship = $"Process {parentProc.ProcessName} (PID {parentProc.ProcessId}) launched {proc.ProcessName} (PID {proc.ProcessId})",
                            Provenance = "ProcessScanner"
                        });

                        // Create Launch Chain EvidenceCluster if parent is a launcher and child is Minecraft
                        if (gameProcIds.Contains(childId))
                        {
                            graph.CreateEvidenceCluster(
                                clusterId: $"CLUSTER-LAUNCH-{parentProc.ProcessId}-{proc.ProcessId}",
                                title: $"Process Launch Chain ({parentProc.ProcessName} -> {proc.ProcessName})",
                                relationshipBasis: "Verified Windows process parentage link to Minecraft JVM",
                                memberEntityIds: new[] { parentId, childId },
                                confidence: ConfidenceLevel.Certain,
                                provenance: "ProcessScanner");
                        }
                    }
                }
            }
        }

        // 3. Ingest Loaded Modules with PID Reuse Defense
        var modulesByProc = new Dictionary<string, List<string>>();
        foreach (var mod in report.LoadedModules)
        {
            // Resolve target process
            string? targetProcId = null;
            if (!string.IsNullOrEmpty(mod.ProcessInstanceId))
            {
                if (graph.ContainsNode(mod.ProcessInstanceId))
                {
                    targetProcId = mod.ProcessInstanceId;
                }
                else
                {
                    // PID Reuse Defense: The module specifies a process instance that is not in the graph
                    // (e.g. earlier process that exited). Do NOT attach to a new process that merely reuses the PID!
                    mod.EnumerationStatus = ModuleEnumerationStatus.AmbiguousIdentity;
                    mod.EnumerationNote = $"Target process instance '{mod.ProcessInstanceId}' does not exist in graph; refusing to bind to reused PID {mod.ProcessId}.";
                    continue;
                }
            }
            else if (procsByPid.TryGetValue(mod.ProcessId, out var candidateProcs))
            {
                if (candidateProcs.Count > 1)
                {
                    // Ambiguity defense: Multiple process instances share this PID.
                    // Do NOT arbitrarily attach module to one of them!
                    mod.EnumerationStatus = ModuleEnumerationStatus.AmbiguousIdentity;
                    mod.EnumerationNote = $"Ambiguous process association: {candidateProcs.Count} candidate process instances found for PID {mod.ProcessId} without qualifying ProcessInstanceId.";
                    continue;
                }
                else if (candidateProcs.Count == 1)
                {
                    targetProcId = !string.IsNullOrEmpty(candidateProcs[0].ProcessInstanceId)
                        ? candidateProcs[0].ProcessInstanceId
                        : procIdsByPid[mod.ProcessId][0];
                }
            }

            // PID Reuse Validation: Only attach module if target process exists in graph and matches instance
            if (targetProcId == null || !graph.ContainsNode(targetProcId))
            {
                // Unresolvable process target; do not fabricate edge to an unrelated process
                continue;
            }

            string modId = !string.IsNullOrEmpty(mod.ModuleInstanceId)
                ? mod.ModuleInstanceId
                : $"mod:{targetProcId}:{mod.BaseAddressHex ?? "0x0"}:{mod.FileSizeBytes ?? 0}:{mod.Sha256 ?? "unknown"}";

            var modEntity = new GraphEntity
            {
                EntityId = modId,
                Type = EntityType.LoadedModule,
                FirstObservedUtc = scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { "LoadedModules" },
                Properties =
                {
                    ["ModuleName"] = mod.ModuleName,
                    ["ModulePath"] = mod.ModulePath ?? string.Empty,
                    ["BaseAddressHex"] = mod.BaseAddressHex ?? "0x0",
                    ["Sha256"] = mod.Sha256 ?? "unknown",
                    ["ProcessId"] = mod.ProcessId.ToString(),
                    ["ProcessInstanceId"] = targetProcId,
                    ["IsRecognizedJavaNativeLibrary"] = mod.IsRecognizedJavaNativeLibrary.ToString(),
                    ["ProvenanceAssessment"] = mod.ProvenanceAssessment
                }
            };
            graph.AddNode(modEntity);

            // Edge: LoadedModule -> Process
            graph.AddEdge(new GraphEdge
            {
                SourceEntityId = modEntity.EntityId,
                TargetEntityId = targetProcId,
                Type = EdgeType.LoadedBy,
                Confidence = ConfidenceLevel.Certain,
                AssertedRelationship = $"Module '{mod.ModuleName}' mapped into virtual address space of PID {mod.ProcessId}",
                Provenance = "LoadedModules"
            });

            // Hash node & edge if present
            if (!string.IsNullOrEmpty(mod.Sha256) && !mod.Sha256.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            {
                string hashId = $"hash:{mod.Sha256.ToLowerInvariant()}";
                if (!graph.ContainsNode(hashId))
                {
                    graph.AddNode(new GraphEntity
                    {
                        EntityId = hashId,
                        Type = EntityType.CryptographicHash,
                        FirstObservedUtc = scanTime,
                        LastObservedUtc = scanTime,
                        ProvenanceSources = { "LoadedModules" },
                        Properties = { ["SHA256"] = mod.Sha256.ToLowerInvariant() }
                    });
                }

                graph.AddEdge(new GraphEdge
                {
                    SourceEntityId = modEntity.EntityId,
                    TargetEntityId = hashId,
                    Type = EdgeType.HashMatches,
                    Confidence = ConfidenceLevel.Certain,
                    AssertedRelationship = "Cryptographic SHA-256 match",
                    Provenance = "LoadedModules"
                });
            }

            if (!modulesByProc.TryGetValue(targetProcId, out var mList))
            {
                mList = new List<string>();
                modulesByProc[targetProcId] = mList;
            }
            mList.Add(modId);
        }

        // Create EvidenceClusters for Process + Loaded Modules
        foreach (var (procId, modIds) in modulesByProc)
        {
            var clusterMembers = new List<string> { procId };
            clusterMembers.AddRange(modIds);

            procMap.TryGetValue(procId, out var procItem);
            string procName = procItem?.ProcessName ?? "Process";

            graph.CreateEvidenceCluster(
                clusterId: $"CLUSTER-PROC-MEM-{procId}",
                title: $"Process Virtual Memory Space ({procName})",
                relationshipBasis: "Verified address space mapping of modules into process",
                memberEntityIds: clusterMembers,
                confidence: ConfidenceLevel.Certain,
                provenance: "LoadedModules");
        }

        // 4. Ingest Mod Inventory (Installed JARs) & Multi-Modal Clusters
        foreach (var mod in report.ModInventory)
        {
            string modNodeId = $"modfile:{mod.Sha256 ?? mod.FullPath.ToLowerInvariant()}";
            var modEntity = new GraphEntity
            {
                EntityId = modNodeId,
                Type = EntityType.JarArchive,
                FirstObservedUtc = scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { "ModInventoryScanner" },
                Properties =
                {
                    ["FileName"] = mod.FileName,
                    ["FullPath"] = mod.FullPath,
                    ["Sha256"] = mod.Sha256 ?? "unknown",
                    ["FileSizeBytes"] = mod.FileSizeBytes.ToString(),
                    ["ModName"] = mod.Name,
                    ["GameplayPolicy"] = mod.GameplayPolicy
                }
            };
            graph.AddNode(modEntity);

            // Hash node & edge
            if (!string.IsNullOrEmpty(mod.Sha256))
            {
                string hashId = $"hash:{mod.Sha256.ToLowerInvariant()}";
                if (!graph.ContainsNode(hashId))
                {
                    graph.AddNode(new GraphEntity
                    {
                        EntityId = hashId,
                        Type = EntityType.CryptographicHash,
                        FirstObservedUtc = scanTime,
                        LastObservedUtc = scanTime,
                        ProvenanceSources = { "ModInventoryScanner" },
                        Properties = { ["SHA256"] = mod.Sha256.ToLowerInvariant() }
                    });
                }

                graph.AddEdge(new GraphEdge
                {
                    SourceEntityId = modNodeId,
                    TargetEntityId = hashId,
                    Type = EdgeType.HashMatches,
                    Confidence = ConfidenceLevel.Certain,
                    AssertedRelationship = "Physical file cryptographic SHA-256 match",
                    Provenance = "ModInventoryScanner"
                });

                // EvidenceCluster grouping mod file and hash
                graph.CreateEvidenceCluster(
                    clusterId: $"CLUSTER-MOD-{mod.Sha256[..Math.Min(12, mod.Sha256.Length)].ToLowerInvariant()}",
                    title: $"Mod Artifact and Cryptographic Hash ({mod.FileName})",
                    relationshipBasis: "Cryptographic SHA-256 digest matching physical JAR archive on disk",
                    memberEntityIds: new[] { modNodeId, hashId },
                    confidence: ConfidenceLevel.Certain,
                    provenance: "ModInventoryScanner");
            }

            // Link to installation location
            foreach (var instId in installNodes)
            {
                var instNode = graph.GetNode(instId);
                if (instNode != null && instNode.Properties.TryGetValue("RootPath", out var rootPath) &&
                    mod.FullPath.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
                {
                    graph.AddEdge(new GraphEdge
                    {
                        SourceEntityId = modNodeId,
                        TargetEntityId = instId,
                        Type = EdgeType.LocatedIn,
                        Confidence = ConfidenceLevel.Certain,
                        AssertedRelationship = "File resides within Minecraft installation directory",
                        Provenance = "ModInventoryScanner"
                    });
                }
            }

            // Check if active game process command line explicitly references this mod
            foreach (var gProcId in gameProcIds)
            {
                var gProc = graph.GetNode(gProcId);
                if (gProc != null && gProc.Properties.TryGetValue("CommandLine", out var cmdLine) && !string.IsNullOrEmpty(cmdLine))
                {
                    if (cmdLine.Contains(mod.FileName, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(mod.FullPath) && cmdLine.Contains(mod.FullPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        graph.AddEdge(new GraphEdge
                        {
                            SourceEntityId = modNodeId,
                            TargetEntityId = gProcId,
                            Type = EdgeType.AssociatedWith,
                            Confidence = ConfidenceLevel.Medium,
                            AssertedRelationship = $"Mod JAR referenced in JVM process launch configuration / command-line arguments",
                            Limitations = "Command-line argument indicates process launch configuration; does not prove class loading into JVM memory",
                            Provenance = "ProcessScanner"
                        });
                    }
                }
            }
        }

        // 5. Ingest File Discoveries on Disk (Downloads/Desktop/Recycle Bin)
        // FORENSIC INVARIANT: Physical file presence on disk NEVER creates an execution edge without independent execution telemetry.
        foreach (var file in report.FileDiscoveries)
        {
            string fileNodeId = $"file:{file.Sha256 ?? file.FilePath.ToLowerInvariant()}";
            var fileEntity = new GraphEntity
            {
                EntityId = fileNodeId,
                Type = EntityType.File,
                FirstObservedUtc = scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { "FileDiscoveryScanner" },
                Properties =
                {
                    ["FileName"] = file.FileName,
                    ["FilePath"] = file.FilePath,
                    ["Sha256"] = file.Sha256 ?? "unknown",
                    ["FileSizeBytes"] = file.FileSizeBytes.ToString(),
                    ["DiscoveryCategory"] = file.DiscoveryCategory
                }
            };
            graph.AddNode(fileEntity);

            if (!string.IsNullOrEmpty(file.Sha256))
            {
                string hashId = $"hash:{file.Sha256.ToLowerInvariant()}";
                if (!graph.ContainsNode(hashId))
                {
                    graph.AddNode(new GraphEntity
                    {
                        EntityId = hashId,
                        Type = EntityType.CryptographicHash,
                        FirstObservedUtc = scanTime,
                        LastObservedUtc = scanTime,
                        ProvenanceSources = { "FileDiscoveryScanner" },
                        Properties = { ["SHA256"] = file.Sha256.ToLowerInvariant() }
                    });
                }

                graph.AddEdge(new GraphEdge
                {
                    SourceEntityId = fileNodeId,
                    TargetEntityId = hashId,
                    Type = EdgeType.HashMatches,
                    Confidence = ConfidenceLevel.Certain,
                    AssertedRelationship = "Physical file cryptographic SHA-256 match",
                    Provenance = "FileDiscoveryScanner"
                });
            }
        }

        // 6. Ingest Historical Execution Records
        foreach (var hist in report.ExecutionHistory)
        {
            long ticks = hist.LastExecutionTime?.UtcTicks ?? 0L;
            string histId = $"hist:{hist.Source}:{hist.ApplicationName}:{ticks}";
            var histEntity = new GraphEntity
            {
                EntityId = histId,
                Type = EntityType.HistoricalRecord,
                FirstObservedUtc = hist.LastExecutionTime ?? scanTime,
                LastObservedUtc = hist.LastExecutionTime ?? scanTime,
                ProvenanceSources = { hist.Source },
                Properties =
                {
                    ["Source"] = hist.Source,
                    ["ApplicationName"] = hist.ApplicationName,
                    ["ApplicationPath"] = hist.ApplicationPath,
                    ["ExecutionCount"] = hist.ExecutionCount?.ToString() ?? "1",
                    ["LastExecutionTimeUtc"] = hist.LastExecutionTime?.ToString("o") ?? string.Empty
                }
            };
            graph.AddNode(histEntity);

            // Connect to matching file nodes on disk if path/name matches
            foreach (var node in graph.Nodes.Where(n => n.Type == EntityType.File || n.Type == EntityType.JarArchive))
            {
                if (node.Properties.TryGetValue("FilePath", out var fp) &&
                    !string.IsNullOrEmpty(fp) &&
                    fp.Equals(hist.ApplicationPath, StringComparison.OrdinalIgnoreCase))
                {
                    graph.AddEdge(new GraphEdge
                    {
                        SourceEntityId = histId,
                        TargetEntityId = node.EntityId,
                        Type = EdgeType.HistoricallyExecuted,
                        Confidence = ConfidenceLevel.Certain,
                        AssertedRelationship = $"Historical execution record in {hist.Source} corroborates prior execution of binary",
                        Provenance = hist.Source
                    });
                }
            }
        }

        // 7. Ingest Findings and link to EvidenceClusters
        foreach (var finding in report.Findings)
        {
            string clusterId = !string.IsNullOrEmpty(finding.EvidenceClusterId)
                ? finding.EvidenceClusterId
                : $"CLUSTER-{finding.RuleId}-{finding.DetectionName.ToLowerInvariant().Replace(' ', '-')}";

            var clusterEntity = graph.GetNode(clusterId) ?? new GraphEntity
            {
                EntityId = clusterId,
                Type = EntityType.EvidenceCluster,
                FirstObservedUtc = (finding.ObservedTimestamp.HasValue && finding.ObservedTimestamp.Value != default) ? finding.ObservedTimestamp.Value : scanTime,
                LastObservedUtc = scanTime,
                ProvenanceSources = { finding.EvidenceSource },
                Properties =
                {
                    ["RuleId"] = finding.RuleId,
                    ["DetectionName"] = finding.DetectionName,
                    ["Severity"] = finding.Severity.ToString(),
                    ["Category"] = finding.Category.ToString(),
                    ["FilePath"] = finding.FilePath ?? string.Empty,
                    ["Explanation"] = finding.TechnicalExplanation
                }
            };
            graph.AddNode(clusterEntity);

            // Connect related observations
            foreach (var evId in finding.RelatedEvidenceIds)
            {
                string obsNodeId = evId.StartsWith("obs:", StringComparison.OrdinalIgnoreCase) ? evId : $"obs:{evId}";
                if (graph.ContainsNode(obsNodeId))
                {
                    graph.AddEdge(new GraphEdge
                    {
                        SourceEntityId = obsNodeId,
                        TargetEntityId = clusterEntity.EntityId,
                        Type = EdgeType.Corroborates,
                        Confidence = finding.Confidence,
                        AssertedRelationship = "Observation corroborates finding cluster",
                        Provenance = finding.EvidenceSource
                    });
                }
            }

            // Connect process if finding references TargetProcessId
            if (finding.TargetProcessId.HasValue && procIdsByPid.TryGetValue(finding.TargetProcessId.Value, out var candidateIds))
            {
                if (candidateIds.Count == 1)
                {
                    string findingProcId = candidateIds[0];
                    graph.AddEdge(new GraphEdge
                    {
                        SourceEntityId = findingProcId,
                        TargetEntityId = clusterEntity.EntityId,
                        Type = EdgeType.Corroborates,
                        Confidence = finding.Confidence,
                        AssertedRelationship = "Process entity associated with finding cluster",
                        Provenance = finding.EvidenceSource
                    });
                }
            }
        }
    }

    private static EntityType InferEntityTypeFromId(string targetEntityId)
    {
        if (targetEntityId.StartsWith("proc:", StringComparison.OrdinalIgnoreCase)) return EntityType.OsProcess;
        if (targetEntityId.StartsWith("mod:", StringComparison.OrdinalIgnoreCase)) return EntityType.LoadedModule;
        if (targetEntityId.StartsWith("modfile:", StringComparison.OrdinalIgnoreCase)) return EntityType.JarArchive;
        if (targetEntityId.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) return EntityType.File;
        if (targetEntityId.StartsWith("session:", StringComparison.OrdinalIgnoreCase)) return EntityType.MinecraftSession;
        if (targetEntityId.StartsWith("hist:", StringComparison.OrdinalIgnoreCase)) return EntityType.HistoricalRecord;
        if (targetEntityId.StartsWith("CLUSTER", StringComparison.OrdinalIgnoreCase)) return EntityType.EvidenceCluster;
        return EntityType.File;
    }
}

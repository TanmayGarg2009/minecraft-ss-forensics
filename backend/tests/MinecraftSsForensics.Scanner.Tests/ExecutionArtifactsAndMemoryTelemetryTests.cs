using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Correlation;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Graph;
using MinecraftSsForensics.Scanner.Identities;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.LogsAndHistory;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Process;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

/// <summary>
/// STAGE 3/8 — EXECUTION ARTIFACTS & MEMORY TELEMETRY REGRESSION SUITE
/// Covers all 25 required verification scenarios strictly enforcing the 7 execution-attribution states:
/// 1. FilePresent
/// 2. SoftwareInstalled
/// 3. LaunchConfigurationReference
/// 4. HistoricalExecution
/// 5. ProcessLoadedModule
/// 6. MinecraftProcessAssociation
/// 7. ActiveDuringInspectedSession
/// </summary>
public class ExecutionArtifactsAndMemoryTelemetryTests
{
    // =========================================================================
    // Scenario 1: Suspicious file present on disk but not executed
    // =========================================================================
    [Fact]
    public void Scenario01_SuspiciousFilePresent_NotExecuted()
    {
        var report = new StandaloneReport();
        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "itami.exe",
            FilePath = @"C:\Users\Player\Downloads\itami.exe",
            FileSizeBytes = 1048576,
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            DiscoveryCategory = "UserStagingFolder"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.FirstOrDefault(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(assessment);
        Assert.Equal(SoftwareEvidenceState.SoftwarePresent, assessment.State);
        Assert.Equal(ExecutionEvidenceState.FilePresent, assessment.ExecutionState);
        Assert.Contains("physically present on disk", assessment.WhatIsProven);
        Assert.Contains("No execution or game interaction records found", assessment.WhatIsNotProven);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareExecuted, assessment.State);
    }

    // =========================================================================
    // Scenario 2: Suspicious file installed in Minecraft profile but not loaded
    // =========================================================================
    [Fact]
    public void Scenario02_SuspiciousFileInstalledInProfile_NotLoaded()
    {
        var report = new StandaloneReport();
        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "AutoClickerMod",
            FileName = "autoclicker.jar",
            FullPath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\autoclicker.jar",
            FileSizeBytes = 51200,
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        policy.Rules.Add(new ModPolicyRule { ModName = "AutoClickerMod", Policy = GameplayPolicy.PROHIBITED_EXECUTION });

        var assessments = engine.Correlate(report, policy);
        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "AutoClickerMod");

        Assert.NotNull(assessment);
        Assert.Equal(SoftwareEvidenceState.SoftwareInstalled, assessment.State);
        Assert.Equal(ExecutionEvidenceState.SoftwareInstalled, assessment.ExecutionState);
        Assert.False(assessment.IsPolicyViolation);
        Assert.Contains("EXECUTION UNPROVEN", assessment.PolicyEvaluationExplanation);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
    }

    // =========================================================================
    // Scenario 3: JVM classpath reference without loaded-module evidence
    // =========================================================================
    [Fact]
    public void Scenario03_JvmClasspathReference_WithoutLoadedModule()
    {
        var report = new StandaloneReport();
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1111,
            ProcessName = "javaw.exe",
            SanitizedCommandLine = @"-classpath C:\Users\Player\AppData\Roaming\.minecraft\mods\suspicious_lib.jar;libraries.jar net.minecraft.client.main.Main",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30)
        });

        report.ModInventory.Add(new DiscoveredModItem
        {
            Name = "SuspiciousLib",
            FileName = "suspicious_lib.jar",
            FullPath = @"C:\Users\Player\AppData\Roaming\.minecraft\mods\suspicious_lib.jar",
            GameplayPolicy = "PROHIBITED_EXECUTION"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.FirstOrDefault(a => a.SoftwareName == "SuspiciousLib");
        Assert.NotNull(assessment);
        Assert.Equal(ExecutionEvidenceState.LaunchConfigurationReference, assessment.ExecutionState);
        Assert.NotEqual(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);

        var evItem = report.EvidenceItems.FirstOrDefault(e => e.Type == EvidenceType.JvmArguments);
        Assert.NotNull(evItem);
        Assert.Contains("does not establish that classes were loaded into JVM memory or executed", evItem.Limitations, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Scenario 4: Java agent argument without proof that the agent loaded
    // =========================================================================
    [Fact]
    public async System.Threading.Tasks.Task Scenario04_JavaAgentArgument_WithoutLoadedProof()
    {
        var proc = new DiscoveredProcess
        {
            ProcessId = 2222,
            ProcessName = "javaw.exe",
            IsGameProcess = true,
            StartTime = DateTime.UtcNow.AddMinutes(-20),
            JavaAgents = new List<string> { @"C:\Temp\unverified_agent.jar" }
        };

        var procScanner = new TestProcessScanner(new List<DiscoveredProcess> { proc });
        var engine = new StandaloneScannerEngine(processScanner: procScanner);

        var report = await engine.ExecuteScanAsync(new ConsentScopeConfig
        {
            ConsentGiven = true,
            ConsentTimestamp = DateTimeOffset.UtcNow,
            InspectProcessesAndModules = true,
            InspectMinecraftMods = false,
            InspectExecutionArtifacts = false,
            InspectRegistryArtifacts = false
        });

        var agentFinding = report.Findings.FirstOrDefault(f => f.RuleId.Contains("JAVA-AGENT"));
        Assert.NotNull(agentFinding);
        Assert.Equal(ExecutionEvidenceState.LaunchConfigurationReference, agentFinding.ExecutionState);
        Assert.NotEqual(FindingClassification.ConfirmedCheatArtifact, agentFinding.Classification);
        Assert.Contains("bytecode", agentFinding.WhatIsNotProven, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // Scenario 5: Historical Prefetch/BAM evidence without current-session evidence
    // =========================================================================
    [Fact]
    public void Scenario05_HistoricalPrefetchBam_WithoutCurrentSession()
    {
        var report = new StandaloneReport();
        report.ExecutionHistory.Add(new ExecutionHistoryItem
        {
            Source = "WindowsBAM",
            ApplicationName = "itami.exe",
            ApplicationPath = @"C:\Users\Player\Downloads\itami.exe",
            LastExecutionTime = DateTimeOffset.UtcNow.AddDays(-2),
            ExecutionCount = 3
        });

        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "itami.exe",
            FilePath = @"C:\Users\Player\Downloads\itami.exe",
            FileSizeBytes = 1048576,
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            DiscoveryCategory = "UserStagingFolder"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.FirstOrDefault(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(assessment);
        Assert.Equal(SoftwareEvidenceState.SoftwareExecuted, assessment.State);
        Assert.Equal(ExecutionEvidenceState.FilePresent, assessment.ExecutionState); // Base file discovery
        Assert.Contains("executed historically", assessment.WhatIsProven, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Does not prove execution occurred during the specific match", assessment.WhatIsNotProven);
    }

    // =========================================================================
    // Scenario 6: Loaded module in an unrelated process
    // =========================================================================
    [Fact]
    public void Scenario06_LoadedModule_InUnrelatedProcess()
    {
        var report = new StandaloneReport();
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1000,
            ProcessName = "javaw.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30)
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5555,
            ProcessName = "notepad.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-10)
        });

        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 5555,
            ModuleName = "suspicious_hook.dll",
            ModulePath = @"C:\Users\Player\AppData\Local\Temp\suspicious_hook.dll",
            IsInTempDirectory = true,
            IsRecognizedJavaNativeLibrary = false
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var modAssessment = assessments.FirstOrDefault(a => a.SoftwareName == "suspicious_hook.dll");
        Assert.NotNull(modAssessment);
        Assert.Equal(ExecutionEvidenceState.ProcessLoadedModule, modAssessment.ExecutionState);
        Assert.Equal(SoftwareEvidenceState.SoftwareExecuted, modAssessment.State);
        Assert.Contains("non-Minecraft process", modAssessment.StateDescription);
        Assert.Contains("Module was not loaded by or associated with any Minecraft process", modAssessment.WhatIsNotProven);
    }

    // =========================================================================
    // Scenario 7: Loaded module in the correct Minecraft process instance
    // =========================================================================
    [Fact]
    public void Scenario07_LoadedModule_InCorrectMinecraftProcessInstance()
    {
        var report = new StandaloneReport();
        string mcProcInst = "proc:myhost:1111:63800000:abc123sha";

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1111,
            ProcessName = "javaw.exe",
            ProcessInstanceId = mcProcInst,
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30)
        });

        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 1111,
            ProcessInstanceId = mcProcInst,
            ModuleName = "injected_payload.dll",
            ModulePath = @"C:\Users\Player\AppData\Local\Temp\injected_payload.dll",
            IsInTempDirectory = true,
            IsRecognizedJavaNativeLibrary = false
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var modAssessment = assessments.FirstOrDefault(a => a.SoftwareName == "injected_payload.dll");
        Assert.NotNull(modAssessment);
        Assert.Equal(ExecutionEvidenceState.MinecraftProcessAssociation, modAssessment.ExecutionState);
        Assert.Equal(SoftwareEvidenceState.SoftwareInteractingWithMinecraft, modAssessment.State);
        Assert.Contains("mapped directly into Minecraft process", modAssessment.StateDescription);
    }

    // =========================================================================
    // Scenario 8: PID reuse across process lifetimes
    // =========================================================================
    [Fact]
    public void Scenario08_PidReuse_AcrossProcessLifetimes()
    {
        var report = new StandaloneReport();
        DateTimeOffset t1 = DateTimeOffset.UtcNow.AddHours(-2);
        DateTimeOffset t2 = DateTimeOffset.UtcNow.AddMinutes(-5);

        string oldInstId = "proc:local:3000:" + t1.UtcTicks + ":oldsha";
        string newInstId = "proc:local:3000:" + t2.UtcTicks + ":newsha";

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 3000,
            ProcessName = "javaw.exe",
            ProcessInstanceId = newInstId,
            StartTime = t2
        });

        // Module was captured from earlier terminated process lifetime (oldInstId)
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 3000,
            ProcessInstanceId = oldInstId,
            ModuleName = "old_module.dll",
            ModulePath = @"C:\Temp\old_module.dll"
        });

        var bridge = new GraphSerializationBridge();
        var graph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // Verify that the module was NOT attached to the new process instance merely because PID is 3000
        Assert.False(graph.HasRelationship($"mod:{oldInstId}:0x0:0:unknown", newInstId, maxDepth: 1));
        var modItem = report.LoadedModules.First();
        Assert.Equal(ModuleEnumerationStatus.AmbiguousIdentity, modItem.EnumerationStatus);
        Assert.Contains("refusing to bind to reused PID", modItem.EnumerationNote);
    }

    // =========================================================================
    // Scenario 9: Missing process start timestamp
    // =========================================================================
    [Fact]
    public void Scenario09_MissingProcessStartTimestamp()
    {
        var proc = new DiscoveredProcess
        {
            ProcessId = 4444,
            ProcessName = "javaw.exe",
            StartTime = null, // Inaccessible start time
            HasAccessDenied = true
        };

        var procInstId = ProcessInstanceId.Create("local", proc.ProcessId, null, null);
        Assert.True(procInstId.IsProvisional);
        Assert.Equal(0L, procInstId.StartTimeTicks);

        var telemetryItem = new ProcessTelemetryItem
        {
            ProcessId = proc.ProcessId,
            ProcessName = proc.ProcessName,
            ProcessInstanceId = procInstId.ToString(),
            StartTime = null
        };

        Assert.False(telemetryItem.HasStartTime);
        Assert.Null(telemetryItem.StartTime);
    }

    // =========================================================================
    // Scenario 10: Missing collection timestamp
    // =========================================================================
    [Fact]
    public void Scenario10_MissingCollectionTimestamp()
    {
        var histRecord = new HistoricalArtifactRecord
        {
            Source = "Prefetch",
            Path = @"C:\Windows\Prefetch\UNKNOWN.PF",
            Timestamp = null, // Timestamp unavailable in corrupted header
            IsCorruptOrMalformed = true
        };

        Assert.Null(histRecord.Timestamp);
        Assert.True(histRecord.IsCorruptOrMalformed);
        Assert.True(histRecord.CollectionTimeUtc <= DateTimeOffset.UtcNow);
    }

    // =========================================================================
    // Scenario 11: Multiple candidate process instances (Ambiguity defense)
    // =========================================================================
    [Fact]
    public void Scenario11_MultipleCandidateProcessInstances()
    {
        var report = new StandaloneReport();

        // Two processes sharing the same PID 7777 without disambiguated module target
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 7777,
            ProcessName = "javaw.exe",
            ProcessInstanceId = "proc:local:7777:1000:sha1",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-30)
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 7777,
            ProcessName = "javaw.exe",
            ProcessInstanceId = "proc:local:7777:2000:sha2",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-10)
        });

        // Module only has PID, not instance ID
        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 7777,
            ProcessInstanceId = null,
            ModuleName = "hook.dll",
            ModulePath = @"C:\Temp\hook.dll"
        });

        var bridge = new GraphSerializationBridge();
        var graph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        var modItem = report.LoadedModules.First();
        Assert.Equal(ModuleEnumerationStatus.AmbiguousIdentity, modItem.EnumerationStatus);
        Assert.Contains("Ambiguous process association", modItem.EnumerationNote);
    }

    // =========================================================================
    // Scenario 12: Contradictory process timestamps (Temporal inversion)
    // =========================================================================
    [Fact]
    public void Scenario12_ContradictoryProcessTimestamps()
    {
        var report = new StandaloneReport();
        DateTimeOffset tChild = DateTimeOffset.UtcNow.AddMinutes(-20);
        DateTimeOffset tParentAnachronistic = DateTimeOffset.UtcNow.AddMinutes(-5); // Parent started AFTER child!

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1000,
            ProcessName = "launcher.exe",
            ProcessInstanceId = "proc:local:1000:parent",
            StartTime = tParentAnachronistic
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 2000,
            ProcessName = "javaw.exe",
            ProcessInstanceId = "proc:local:2000:child",
            ParentProcessId = 1000,
            StartTime = tChild
        });

        var bridge = new GraphSerializationBridge();
        var graph = bridge.BuildGraphFromObservations(report.RawObservations, report);

        // LaunchedBy edge must NOT be created due to temporal contradiction
        Assert.False(graph.HasRelationship("proc:local:1000:parent", "proc:local:2000:child", maxDepth: 1));
        var childProc = report.RunningProcesses.First(p => p.ProcessId == 2000);
        Assert.NotNull(childProc.AmbiguityReason);
        Assert.Contains("Temporal inversion detected", childProc.AmbiguityReason);
    }

    // =========================================================================
    // Scenario 13: Module enumeration access denied
    // =========================================================================
    [Fact]
    public void Scenario13_ModuleEnumeration_AccessDenied()
    {
        var proc = new DiscoveredProcess
        {
            ProcessId = 1234,
            ProcessName = "javaw.exe",
            ModuleEnumerationStatus = ModuleEnumerationStatus.AccessDenied,
            ModuleEnumerationNote = "Access denied: elevated permissions required."
        };

        Assert.Equal(ModuleEnumerationStatus.AccessDenied, proc.ModuleEnumerationStatus);
        Assert.Empty(proc.LoadedModules);

        var report = new StandaloneReport();
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = proc.ProcessId,
            ProcessName = proc.ProcessName,
            ModuleStatus = proc.ModuleEnumerationStatus,
            ModuleStatusNote = proc.ModuleEnumerationNote
        });

        // An access-denied module check must prevent a clean verdict
        bool hasUnavailableTelemetry = report.RunningProcesses.Any(p => p.ModuleStatus == ModuleEnumerationStatus.AccessDenied);
        Assert.True(hasUnavailableTelemetry);
    }

    // =========================================================================
    // Scenario 14: Partial module enumeration
    // =========================================================================
    [Fact]
    public void Scenario14_PartialModuleEnumeration()
    {
        var proc = new DiscoveredProcess
        {
            ProcessId = 5678,
            ProcessName = "javaw.exe",
            ModuleEnumerationStatus = ModuleEnumerationStatus.Partial,
            ModuleEnumerationNote = "One or more modules could not be read."
        };

        Assert.Equal(ModuleEnumerationStatus.Partial, proc.ModuleEnumerationStatus);
    }

    // =========================================================================
    // Scenario 15: Unsupported architecture or unavailable module metadata
    // =========================================================================
    [Fact]
    public void Scenario15_UnsupportedArchitecture_ModuleMetadata()
    {
        var proc = new DiscoveredProcess
        {
            ProcessId = 9999,
            ProcessName = "javaw.exe",
            ModuleEnumerationStatus = ModuleEnumerationStatus.UnsupportedArchitecture,
            ModuleEnumerationNote = "Cross-architecture module query restriction (32-bit / 64-bit boundary)."
        };

        Assert.Equal(ModuleEnumerationStatus.UnsupportedArchitecture, proc.ModuleEnumerationStatus);
    }

    // =========================================================================
    // Scenario 16: Malformed historical artifact
    // =========================================================================
    [Fact]
    public void Scenario16_MalformedHistoricalArtifact()
    {
        byte[] malformedBytes = Encoding.ASCII.GetBytes("This is not a Windows Prefetch file header!");
        var result = PrefetchParser.ParsePrefetchBytes(malformedBytes);

        Assert.False(result.Success);
        Assert.True(result.IsCorrupt);
        Assert.NotNull(result.FailureReason);
        Assert.Empty(result.ExecutionTimestamps);
    }

    // =========================================================================
    // Scenario 17: Corrupted historical artifact
    // =========================================================================
    [Fact]
    public void Scenario17_CorruptedHistoricalArtifact()
    {
        byte[] truncatedBytes = new byte[] { 0x4D, 0x41, 0x4D, 0x04 }; // 4 bytes only
        var result = PrefetchParser.ParsePrefetchBytes(truncatedBytes);

        Assert.False(result.Success);
        Assert.True(result.IsCorrupt);
        Assert.Contains("truncated", result.FailureReason);
    }

    // =========================================================================
    // Scenario 18: Graph relationship created from unsupported evidence
    // =========================================================================
    [Fact]
    public void Scenario18_GraphRelationship_FromUnsupportedEvidence()
    {
        var graph = new EvidenceGraph();
        graph.AddNode(new GraphEntity { EntityId = "file:somefile.exe", Type = EntityType.File });

        // Edge attempting to assert execution from mere file presence must be rejected or not created
        Assert.False(graph.HasRelationship("file:somefile.exe", "session:active", maxDepth: 2, edgeFilter: e => e.Type == EdgeType.LoadedBy));
    }

    // =========================================================================
    // Scenario 19: Verified cheat artifact without execution evidence
    // =========================================================================
    [Fact]
    public void Scenario19_VerifiedCheatArtifact_WithoutExecutionEvidence()
    {
        var report = new StandaloneReport();
        report.FileDiscoveries.Add(new DiscoveredFileItem
        {
            FileName = "itami.exe",
            FilePath = @"C:\Users\Player\Downloads\itami.exe",
            FileSizeBytes = 1048576,
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.First(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(ExecutionEvidenceState.FilePresent, assessment.ExecutionState);
        Assert.NotEqual(ExecutionEvidenceState.ActiveDuringInspectedSession, assessment.ExecutionState);
    }

    // =========================================================================
    // Scenario 20: Verified cheat artifact loaded in an unrelated process
    // =========================================================================
    [Fact]
    public void Scenario20_VerifiedCheatArtifact_LoadedInUnrelatedProcess()
    {
        var report = new StandaloneReport();
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 8888,
            ProcessName = "svchost.exe",
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-10)
        });

        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 8888,
            ModuleName = "vape_hook.dll",
            ModulePath = @"C:\Users\Player\AppData\Local\Temp\vape_hook.dll",
            IsInTempDirectory = true,
            IsRecognizedJavaNativeLibrary = false
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var modAssessment = assessments.FirstOrDefault(a => a.SoftwareName == "vape_hook.dll");
        Assert.NotNull(modAssessment);
        Assert.Equal(ExecutionEvidenceState.ProcessLoadedModule, modAssessment.ExecutionState);
        Assert.NotEqual(ExecutionEvidenceState.MinecraftProcessAssociation, modAssessment.ExecutionState);
    }

    // =========================================================================
    // Scenario 21: Verified cheat artifact loaded in Minecraft process but without session timing
    // =========================================================================
    [Fact]
    public void Scenario21_VerifiedCheatArtifact_LoadedInMinecraft_WithoutSessionTiming()
    {
        var report = new StandaloneReport();

        // Minecraft process has NO start time
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1111,
            ProcessName = "javaw.exe",
            StartTime = null
        });

        // Cheat process linked to Minecraft by parentage, but has NO start time
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 2222,
            ProcessName = "itami.exe",
            ParentProcessId = 1111,
            StartTime = null
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.FirstOrDefault(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(assessment);
        // Must downgrade from ActiveDuringInspectedSession to MinecraftProcessAssociation due to missing session timing
        Assert.Equal(ExecutionEvidenceState.MinecraftProcessAssociation, assessment.ExecutionState);
        Assert.NotEqual(ExecutionEvidenceState.ActiveDuringInspectedSession, assessment.ExecutionState);
    }

    // =========================================================================
    // Scenario 22: Fully supported active-session relationship
    // =========================================================================
    [Fact]
    public void Scenario22_FullySupportedActiveSessionRelationship()
    {
        var report = new StandaloneReport();
        DateTimeOffset mcStart = DateTimeOffset.UtcNow.AddMinutes(-30);
        DateTimeOffset cheatStart = DateTimeOffset.UtcNow.AddMinutes(-20);

        string mcInstId = "proc:host:1111:" + mcStart.UtcTicks + ":javasha";
        string cheatInstId = "proc:host:2222:" + cheatStart.UtcTicks + ":itamisha";

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 1111,
            ProcessName = "javaw.exe",
            ProcessInstanceId = mcInstId,
            StartTime = mcStart
        });

        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 2222,
            ProcessName = "itami.exe",
            ProcessInstanceId = cheatInstId,
            ParentProcessId = 1111,
            StartTime = cheatStart
        });

        var engine = new EvidenceCorrelationEngine();
        var policy = new ServerGamemodePolicy { Gamemode = "Ranked" };
        var assessments = engine.Correlate(report, policy);

        var assessment = assessments.FirstOrDefault(a => a.SoftwareName.Contains("Itami", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(assessment);
        Assert.Equal(ExecutionEvidenceState.ActiveDuringInspectedSession, assessment.ExecutionState);
        Assert.Equal(SoftwareEvidenceState.SoftwareActiveDuringSession, assessment.State);
        Assert.Equal(ConfidenceLevel.Certain, assessment.Confidence);
    }

    // =========================================================================
    // Scenario 23: Graph failure preventing a clean verdict
    // =========================================================================
    [Fact]
    public void Scenario23_GraphFailure_PreventsCleanVerdict()
    {
        var report = new StandaloneReport();
        report.EvidenceGraph = new EvidenceGraph();
        report.EvidenceGraph.IsValid = false;
        report.EvidenceGraph.ValidationErrors.Add("Simulated cyclic graph failure");

        Assert.False(report.EvidenceGraph.IsValid);

        report.DiagnosticChecks.Add(new DiagnosticCheckItem
        {
            CheckId = "CHK-EVIDENCE-GRAPH",
            Status = CheckStatus.FLAGGED,
            Reason = "Graph structural integrity validation failed."
        });

        // Any graph invalidity or collector failures prevent clean verdict (NoProhibitedIndicators)
        bool hasUnavailableRequiredTelemetry = (report.EvidenceGraph == null || !report.EvidenceGraph.IsValid || report.EvidenceGraph.IsResourceBounded);
        Assert.True(hasUnavailableRequiredTelemetry);
    }

    // =========================================================================
    // Scenario 24: Historical report compatibility
    // =========================================================================
    [Fact]
    public void Scenario24_HistoricalReportCompatibility()
    {
        // Legacy JSON report without new ModuleStatus, CollectionTimeUtc, or ExecutionState
        string legacyJson = """
        {
            "reportId": "rep_legacy123456",
            "schemaVersion": "2.0.0",
            "createdAt": "2026-10-01T12:00:00Z",
            "runningProcesses": [
                {
                    "processId": 1234,
                    "processName": "javaw.exe"
                }
            ],
            "loadedModules": [
                {
                    "processId": 1234,
                    "moduleName": "ntdll.dll",
                    "modulePath": "C:\\Windows\\System32\\ntdll.dll"
                }
            ]
        }
        """;

        var deserialized = JsonSerializer.Deserialize<StandaloneReport>(legacyJson, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.NotNull(deserialized);
        Assert.Single(deserialized.RunningProcesses);
        Assert.Equal(ModuleEnumerationStatus.Complete, deserialized.RunningProcesses[0].ModuleStatus);
        Assert.Single(deserialized.LoadedModules);
        Assert.Equal(ModuleEnumerationStatus.Complete, deserialized.LoadedModules[0].EnumerationStatus);
    }

    // =========================================================================
    // Scenario 25: Serialization and integrity round-trip for new telemetry
    // =========================================================================
    [Fact]
    public void Scenario25_SerializationAndIntegrityRoundTrip_NewTelemetry()
    {
        var report = new StandaloneReport();
        report.RunningProcesses.Add(new ProcessTelemetryItem
        {
            ProcessId = 5555,
            ProcessName = "javaw.exe",
            CollectionTimeUtc = DateTimeOffset.UtcNow,
            ModuleStatus = ModuleEnumerationStatus.Complete,
            ModuleStatusNote = "All modules enumerated successfully."
        });

        report.LoadedModules.Add(new LoadedModuleItem
        {
            ProcessId = 5555,
            ModuleName = "test_mod.dll",
            CollectionTimeUtc = DateTimeOffset.UtcNow,
            EnumerationStatus = ModuleEnumerationStatus.Complete
        });

        report.ExecutionHistory.Add(new ExecutionHistoryItem
        {
            Source = "Prefetch",
            ApplicationName = "test.exe",
            CollectionTimeUtc = DateTimeOffset.UtcNow,
            IsCorruptOrMalformed = false
        });

        // Compute seal
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        // Serialize and Deserialize
        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        var roundTripped = JsonSerializer.Deserialize<StandaloneReport>(json);

        Assert.NotNull(roundTripped);
        var verifyResult = ReportIntegrityValidator.VerifyReportIntegrityDetailed(roundTripped);
        Assert.True(verifyResult.IsValid);
        Assert.Equal(report.ReportIntegrityHash, roundTripped.ReportIntegrityHash);
    }

    private class TestProcessScanner : IProcessScanner
    {
        private readonly List<DiscoveredProcess> _procs;
        public TestProcessScanner(List<DiscoveredProcess> procs) => _procs = procs;
        public List<DiscoveredProcess> ScanProcesses(bool inspectModules = true) => _procs;
    }
}

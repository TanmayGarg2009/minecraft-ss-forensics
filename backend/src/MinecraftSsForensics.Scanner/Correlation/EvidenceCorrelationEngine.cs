using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;
using MinecraftSsForensics.Scanner.Graph;

namespace MinecraftSsForensics.Scanner.Correlation;

public class CorrelatedSoftwareAssessment
{
    public string SoftwareName { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public string? Sha256 { get; set; }
    public SoftwareEvidenceState State { get; set; } = SoftwareEvidenceState.SoftwarePresent;
    public ExecutionEvidenceState ExecutionState { get; set; } = ExecutionEvidenceState.FilePresent;
    public string StateDescription { get; set; } = string.Empty;
    public GameplayPolicy Policy { get; set; } = GameplayPolicy.UNKNOWN;
    public bool IsPolicyViolation { get; set; }
    public string PolicyEvaluationExplanation { get; set; } = string.Empty;
    public List<string> SupportingEvidenceIds { get; set; } = new();
    public string WhatIsProven { get; set; } = string.Empty;
    public string WhatIsNotProven { get; set; } = string.Empty;
    public string AlternativeLegitimateExplanations { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
}

/// <summary>
/// Correlates evidence across filesystem, process memory, execution history, and registry hives.
/// Strictly distinguishes the 6 evidentiary correlation states:
/// 1. Software is present (Disk)
/// 2. Software is running (RunningProcess)
/// 3. Software module loaded in virtual memory (LoadedModule)
/// 4. Direct technical interaction or injection with Minecraft (Injected)
/// 5. Active during scan window or match session (ActiveInScanWindow)
/// 6. Historical execution prior to scan window (Historical)
/// 
/// Strictly never treats a running Java process as proof that every discovered mod was loaded.
/// Never conflates presence on disk with active in-game cheating.
/// </summary>
public class EvidenceCorrelationEngine
{
    private readonly ModPolicyEngine _policyEngine;

    public EvidenceCorrelationEngine(ModPolicyEngine? policyEngine = null)
    {
        _policyEngine = policyEngine ?? new ModPolicyEngine();
    }

    /// <summary>
    /// Correlates all collected telemetry into defensible findings and evidence links.
    /// </summary>
    public List<CorrelatedSoftwareAssessment> Correlate(
        StandaloneReport report,
        ServerGamemodePolicy policy)
    {
        var assessments = new List<CorrelatedSoftwareAssessment>();

        // Ensure in-memory Evidence Graph is constructed and validated before correlation
        if (report.EvidenceGraph == null)
        {
            var bridge = new GraphSerializationBridge();
            report.EvidenceGraph = bridge.BuildGraphFromObservations(report.RawObservations, report);
        }

        // Identify active Minecraft game processes specifically
        var activeGameProcesses = report.RunningProcesses
            .Where(p => p.ProcessName.Contains("javaw", StringComparison.OrdinalIgnoreCase) ||
                        p.ProcessName.Contains("minecraft", StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(p.SanitizedCommandLine) &&
                         (p.SanitizedCommandLine.Contains("net.minecraft", StringComparison.OrdinalIgnoreCase) ||
                          p.SanitizedCommandLine.Contains("fabric", StringComparison.OrdinalIgnoreCase) ||
                          p.SanitizedCommandLine.Contains("forge", StringComparison.OrdinalIgnoreCase))))
            .ToList();

        // 1. Correlate Mod Inventory Items (Installed)
        foreach (var mod in report.ModInventory)
        {
            var assessment = new CorrelatedSoftwareAssessment
            {
                SoftwareName = mod.Name,
                FilePath = mod.FullPath,
                Sha256 = mod.Sha256,
                State = SoftwareEvidenceState.SoftwareInstalled,
                StateDescription = $"Mod archive installed in Minecraft profile mods folder: '{mod.FileName}'."
            };

            string evId = $"EVD-MOD-{Guid.NewGuid():N}"[..12];
            report.EvidenceItems.Add(new EvidenceReferenceItem
            {
                EvidenceId = evId,
                Type = EvidenceType.ModInventory,
                EvidenceCategory = "InstalledMod",
                SourceArtifact = mod.FullPath,
                FilePath = mod.FullPath,
                Sha256 = mod.Sha256,
                Title = $"Installed Mod JAR: {mod.FileName}",
                Description = $"Installed in profile directory: {mod.FullPath} ({mod.FileSizeBytes} bytes)",
                State = EvidenceState.CONFIRMED,
                Confidence = ConfidenceLevel.Certain,
                Limitations = "Presence in mods folder confirms installation, but does not prove features were toggled during match."
            });
            assessment.SupportingEvidenceIds.Add(evId);

            // Check for structural JVM command line references (FND-004)
            CommandLineReferenceInfo? bestCmdRef = null;
            foreach (var gameProc in activeGameProcesses)
            {
                var cmdInfo = InspectCommandLineForMod(gameProc.SanitizedCommandLine, mod.FileName, mod.FullPath, gameProc.ProcessId, gameProc.ProcessName);
                if (cmdInfo.HasReference)
                {
                    bestCmdRef = cmdInfo;
                    break;
                }
            }

            if (bestCmdRef != null && bestCmdRef.HasReference)
            {
                string cmdEvId = $"EVD-CMD-{Guid.NewGuid():N}"[..12];
                report.EvidenceItems.Add(new EvidenceReferenceItem
                {
                    EvidenceId = cmdEvId,
                    Type = EvidenceType.JvmArguments,
                    EvidenceCategory = "JvmCommandLineReference",
                    SourceArtifact = $"{bestCmdRef.ProcessName} (PID {bestCmdRef.ProcessId})",
                    FilePath = mod.FullPath,
                    Title = $"JVM Command-Line Reference ({bestCmdRef.ReferenceContext}): {mod.FileName}",
                    Description = $"Process {bestCmdRef.ProcessName} (PID {bestCmdRef.ProcessId}) argument in {bestCmdRef.ReferenceContext}: '{bestCmdRef.RawArgument}'.",
                    State = EvidenceState.STRONG_INDICATOR,
                    Confidence = ConfidenceLevel.Medium,
                    Limitations = "Command-line argument indicates process launch configuration. Does not establish that classes were loaded into JVM memory or executed."
                });
                assessment.SupportingEvidenceIds.Add(cmdEvId);
            }

            // Check if historically executed
            var execRecord = report.ExecutionHistory.FirstOrDefault(h =>
                (!string.IsNullOrEmpty(h.ApplicationName) && h.ApplicationName.Contains(mod.Name, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(h.ApplicationPath) && h.ApplicationPath.Contains(mod.FileName, StringComparison.OrdinalIgnoreCase)));

            // FORENSIC INVARIANT (FND-004): Command-line reference ALONE must never establish SoftwareActiveDuringSession!
            if (execRecord != null)
            {
                assessment.State = SoftwareEvidenceState.SoftwareExecuted;
                assessment.StateDescription = $"Mod or associated executable has historical execution trace in {execRecord.Source} at {execRecord.LastExecutionTime}, but was not confirmed active in current session memory.";
                assessment.WhatIsProven = "Software has historical proof of execution on this computer.";
                assessment.WhatIsNotProven = "Was not confirmed active in the active game session memory.";
            }
            else if (mod.HasConflictingSignals)
            {
                assessment.State = SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities;
                assessment.StateDescription = "Mod contains verified suspicious or automated bytecode capabilities; no execution records found.";
                assessment.WhatIsProven = "Mod binary contains automated/restricted structural capabilities.";
                assessment.WhatIsNotProven = "Execution was not detected.";
            }
            else if (bestCmdRef != null && bestCmdRef.HasReference)
            {
                assessment.State = SoftwareEvidenceState.SoftwareInstalled;
                assessment.ExecutionState = ExecutionEvidenceState.LaunchConfigurationReference;
                assessment.StateDescription = $"Mod is installed on disk; referenced on command line ({bestCmdRef.ReferenceContext}) of {bestCmdRef.ProcessName} (PID {bestCmdRef.ProcessId}), but class loading/execution in active session is not proven.";
                assessment.WhatIsProven = $"Mod archive is installed in mods directory. Referenced on command line of process {bestCmdRef.ProcessName} (PID {bestCmdRef.ProcessId}) in {bestCmdRef.ReferenceContext}: '{bestCmdRef.RawArgument}'.";
                assessment.WhatIsNotProven = "Command-line reference does not prove that JAR classes were loaded into JVM memory or executed during the game session.";
            }
            else
            {
                assessment.State = SoftwareEvidenceState.SoftwareInstalled;
                assessment.ExecutionState = ExecutionEvidenceState.SoftwareInstalled;
                assessment.StateDescription = "Mod is installed on disk; no active session loading or execution telemetry was found.";
                assessment.WhatIsProven = "File exists on disk in a Minecraft mods folder.";
                assessment.WhatIsNotProven = "No proof of execution or active in-game use.";
            }

            // Evaluate against Policy
            Enum.TryParse<GameplayPolicy>(mod.GameplayPolicy, out var parsedPolicy);
            assessment.Policy = parsedPolicy;

            if (parsedPolicy == GameplayPolicy.PROHIBITED_POSSESSION)
            {
                assessment.IsPolicyViolation = true;
                assessment.PolicyEvaluationExplanation = $"VIOLATION (POSSESSION BANNED): Server policy for {policy.Gamemode} bans possession or installation of '{mod.Name}'.";
                assessment.WhatIsProven = "Artifact is installed in the active Minecraft mods directory.";
                assessment.WhatIsNotProven = "Gameplay use is not proven, but is not required under the applicable possession policy.";
                assessment.AlternativeLegitimateExplanations = "Player may use the same installation for unmoderated singleplayer or external servers.";
            }
            else if (parsedPolicy == GameplayPolicy.PROHIBITED_EXECUTION)
            {
                bool executed = (assessment.State == SoftwareEvidenceState.SoftwareActiveDuringSession ||
                                 assessment.State == SoftwareEvidenceState.SoftwareExecuted ||
                                 assessment.State == SoftwareEvidenceState.SoftwareInteractingWithMinecraft);

                assessment.IsPolicyViolation = executed;
                assessment.PolicyEvaluationExplanation = executed
                    ? $"VIOLATION (EXECUTION BANNED): Server policy prohibits execution of '{mod.Name}', and verified loading/execution telemetry was confirmed."
                    : $"COMPLIANT (EXECUTION UNPROVEN): Server policy prohibits execution of '{mod.Name}'. Mod is installed on disk, but was NOT executed or loaded in the game session.";
                assessment.AlternativeLegitimateExplanations = "Player has the mod installed but did not load or run it during this Minecraft session.";
            }
            else if (parsedPolicy == GameplayPolicy.PROHIBITED_GAMEPLAY_USE)
            {
                assessment.IsPolicyViolation = false;
                assessment.PolicyEvaluationExplanation = $"RESTRICTED/NEEDS REVIEW: '{mod.Name}' is prohibited on active gameplay use. Installation is verified, but in-game activation requires staff session review.";
                assessment.AlternativeLegitimateExplanations = "Mod may be installed for cosmetic or non-combat purposes allowed outside competitive matches.";
            }
            else if (parsedPolicy == GameplayPolicy.ALLOWED)
            {
                assessment.IsPolicyViolation = false;
                assessment.PolicyEvaluationExplanation = $"ALLOWED: '{mod.Name}' is permitted under {policy.Gamemode} policy.";
            }
            else if (parsedPolicy == GameplayPolicy.RESTRICTED)
            {
                assessment.IsPolicyViolation = false;
                assessment.PolicyEvaluationExplanation = $"RESTRICTED: '{mod.Name}' has conditional restrictions under {policy.Gamemode} policy. Verify permitted settings.";
            }
            else
            {
                assessment.IsPolicyViolation = false;
                assessment.PolicyEvaluationExplanation = $"NEEDS REVIEW: '{mod.Name}' policy classification is {parsedPolicy}. Staff review recommended.";
            }

            assessments.Add(assessment);
        }

        // 2. Correlate File Discoveries in Downloads/Desktop/Recycle Bin (Disk only)
        foreach (var file in report.FileDiscoveries)
        {
            var cheatMatch = CheatDetectionDatabase.MatchFileName(file.FileName);
            if (cheatMatch != null)
            {
                var assessment = new CorrelatedSoftwareAssessment
                {
                    SoftwareName = cheatMatch.Name,
                    FilePath = file.FilePath,
                    Sha256 = file.Sha256,
                    State = SoftwareEvidenceState.SoftwarePresent,
                    StateDescription = $"Potential cheat artifact located on disk in user staging directory: '{file.FilePath}'.",
                    Confidence = ConfidenceLevel.Medium
                };

                string evId = $"EVD-FILE-{Guid.NewGuid():N}"[..12];
                report.EvidenceItems.Add(new EvidenceReferenceItem
                {
                    EvidenceId = evId,
                    Type = EvidenceType.FileMetadata,
                    EvidenceCategory = "StagedFile",
                    SourceArtifact = file.FilePath,
                    FilePath = file.FilePath,
                    Sha256 = file.Sha256,
                    Title = $"Staged File on Disk (Filename Match): {file.FileName}",
                    Description = $"File located at '{file.FilePath}'. Pattern match: {cheatMatch.Description}",
                    State = EvidenceState.STRONG_INDICATOR,
                    Confidence = ConfidenceLevel.Medium,
                    Limitations = "File presence on disk proves possession; does not prove installation into Minecraft or execution."
                });
                assessment.SupportingEvidenceIds.Add(evId);

                // Check historical execution records for this executable
                var execRecord = report.ExecutionHistory.FirstOrDefault(h =>
                    (!string.IsNullOrEmpty(h.ApplicationName) && h.ApplicationName.Equals(file.FileName, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrEmpty(h.ApplicationPath) && h.ApplicationPath.Equals(file.FilePath, StringComparison.OrdinalIgnoreCase)));

                if (execRecord != null)
                {
                    assessment.State = SoftwareEvidenceState.SoftwareExecuted;
                    assessment.Confidence = ConfidenceLevel.High;
                    assessment.StateDescription = $"Cheat artifact present on disk AND recorded in historical execution records ({execRecord.Source}) at {execRecord.LastExecutionTime}.";
                    assessment.WhatIsProven = $"File was executed historically on this machine ({execRecord.Source}).";
                    assessment.WhatIsNotProven = "Does not prove execution occurred during the specific match or active Minecraft session.";
                }
                else
                {
                    assessment.WhatIsProven = $"File '{file.FileName}' is physically present on disk in a user staging folder.";
                    assessment.WhatIsNotProven = "No execution or game interaction records found.";
                }

                // Check policy rule
                var policyRule = policy.Rules.FirstOrDefault(r =>
                    r.ModName.Equals(cheatMatch.Name, StringComparison.OrdinalIgnoreCase) ||
                    r.Aliases.Any(a => a.Equals(cheatMatch.Name, StringComparison.OrdinalIgnoreCase)));

                if (policyRule != null && policyRule.Policy == GameplayPolicy.PROHIBITED_POSSESSION)
                {
                    assessment.Policy = GameplayPolicy.PROHIBITED_POSSESSION;
                    assessment.IsPolicyViolation = true;
                    assessment.PolicyEvaluationExplanation = $"VIOLATION (POSSESSION PROHIBITED): Server policy for {policy.Gamemode} explicitly bans possession of '{cheatMatch.Name}'. Confirmed presence on system constitutes a violation.";
                    assessment.WhatIsProven = $"File '{file.FileName}' is physically stored on disk in staging folder.";
                    assessment.WhatIsNotProven = "Gameplay use or execution is not proven and is not required under the applicable possession policy.";
                    assessment.AlternativeLegitimateExplanations = "User downloaded file, joke file, or old artifact prior to joining server.";
                }

                string clusterId = !string.IsNullOrEmpty(file.Sha256)
                    ? $"CLUSTER-FILE-{file.Sha256[..Math.Min(12, file.Sha256.Length)].ToLowerInvariant()}"
                    : $"CLUSTER-FILE-{cheatMatch.Name.ToLowerInvariant().Replace(" ", "-")}";
                var fileFinding = report.Findings.FirstOrDefault(f => (!string.IsNullOrEmpty(f.FilePath) && f.FilePath.Equals(file.FilePath, StringComparison.OrdinalIgnoreCase)) || f.DetectionName.Contains(cheatMatch.Name, StringComparison.OrdinalIgnoreCase));
                if (fileFinding != null) { fileFinding.EvidenceClusterId = clusterId; if (execRecord != null) { fileFinding.RelatedEvidenceIds.Add("HIST:" + execRecord.Source); } }

                assessments.Add(assessment);
            }
        }

        // 3. Correlate Loaded DLL Modules (Interacting With Minecraft)
        // Forensic Correctness (F-010): Attribute to Minecraft ONLY if target PID is an active Minecraft process
        foreach (var mod in report.LoadedModules)
        {
            if (mod.IsInTempDirectory && !mod.IsRecognizedJavaNativeLibrary)
            {
                var targetGameProc = activeGameProcesses.FirstOrDefault(p => p.ProcessId == mod.ProcessId);
                bool isMinecraftProcess = false;

                // Graph-based module association reasoning (only if graph is valid)
                if (report.EvidenceGraph != null && report.EvidenceGraph.IsValid)
                {
                    var modNode = report.EvidenceGraph.Nodes.FirstOrDefault(n =>
                        n.Type == EntityType.LoadedModule &&
                        (n.EntityId.Equals(mod.ModuleInstanceId, StringComparison.OrdinalIgnoreCase) ||
                         (n.Properties.TryGetValue("ModuleName", out var mName) && mName.Equals(mod.ModuleName, StringComparison.OrdinalIgnoreCase) &&
                          n.Properties.TryGetValue("ProcessId", out var pId) && pId == mod.ProcessId.ToString())));

                    if (modNode != null)
                    {
                        var gameProcNodes = report.EvidenceGraph.Nodes
                            .Where(n => n.Type == EntityType.JvmProcess)
                            .ToList();

                        isMinecraftProcess = gameProcNodes.Any(gp =>
                            report.EvidenceGraph.HasRelationship(modNode.EntityId, gp.EntityId, maxDepth: 2,
                                edgeFilter: e => e.Type == EdgeType.LoadedBy || e.Type == EdgeType.AssociatedWith));
                    }
                }
                else
                {
                    isMinecraftProcess = targetGameProc != null;
                }

                var assessment = new CorrelatedSoftwareAssessment
                {
                    SoftwareName = mod.ModuleName,
                    FilePath = mod.FilePath,
                    State = isMinecraftProcess
                        ? SoftwareEvidenceState.SoftwareInteractingWithMinecraft
                        : SoftwareEvidenceState.SoftwareExecuted,
                    ExecutionState = isMinecraftProcess
                        ? ExecutionEvidenceState.MinecraftProcessAssociation
                        : ExecutionEvidenceState.ProcessLoadedModule,
                    StateDescription = isMinecraftProcess
                        ? $"Unrecognized DLL module '{mod.ModuleName}' is mapped directly into Minecraft process {targetGameProc!.ProcessName} (PID {mod.ProcessId}) address space from temporary directory."
                        : $"Unrecognized DLL module '{mod.ModuleName}' is mapped into non-Minecraft process (PID {mod.ProcessId}) from temporary directory; not associated with Minecraft.",
                    Confidence = isMinecraftProcess ? ConfidenceLevel.High : ConfidenceLevel.Low,
                    WhatIsProven = isMinecraftProcess
                        ? $"Module '{mod.FilePath}' was mapped into Minecraft ({targetGameProc!.ProcessName}, PID {mod.ProcessId}) virtual memory."
                        : $"Module '{mod.FilePath}' was mapped into non-Minecraft process PID {mod.ProcessId}.",
                    WhatIsNotProven = isMinecraftProcess
                        ? "Does not prove malicious intent without reverse-engineering module exports."
                        : "Module was not loaded by or associated with any Minecraft process.",
                    AlternativeLegitimateExplanations = "Third-party screen recorder, overlay, graphics utility, or audio driver hook."
                };

                string evId = $"EVD-MODINJ-{Guid.NewGuid():N}"[..12];
                report.EvidenceItems.Add(new EvidenceReferenceItem
                {
                    EvidenceId = evId,
                    Type = EvidenceType.LoadedModules,
                    EvidenceCategory = "ProcessMemoryModule",
                    SourceArtifact = mod.FilePath,
                    FilePath = mod.FilePath,
                    Title = isMinecraftProcess
                        ? $"Unrecognized DLL Mapped into {targetGameProc!.ProcessName}: {mod.ModuleName}"
                        : $"Unrecognized DLL in Non-Minecraft Process (PID {mod.ProcessId}): {mod.ModuleName}",
                    Description = $"Process PID {mod.ProcessId} loaded '{mod.FilePath}'. Provenance: {mod.ProvenanceAssessment}.",
                    State = isMinecraftProcess ? EvidenceState.STRONG_INDICATOR : EvidenceState.INCONCLUSIVE,
                    Confidence = isMinecraftProcess ? ConfidenceLevel.High : ConfidenceLevel.Low,
                    Limitations = isMinecraftProcess
                        ? "Module mapping confirms memory interaction; does not prove modification of game packets or competitive advantages."
                        : "Module is not associated with Minecraft process."
                });
                assessment.SupportingEvidenceIds.Add(evId);

                assessments.Add(assessment);
            }
        }

        // 4. Correlate Running Processes
        // Forensic Correctness (F-009): Concurrent execution is NEVER association without technical link
        foreach (var proc in report.RunningProcesses)
        {
            var cheatMatch = CheatDetectionDatabase.MatchFileName(proc.ProcessName + ".exe") ??
                             CheatDetectionDatabase.MatchFileName(proc.ProcessName);

            if (cheatMatch != null)
            {
                bool isMinecraftActive = activeGameProcesses.Count > 0;
                bool hasTechnicalLink = false;

                // Graph-based process relationship reasoning (only if graph is valid)
                if (report.EvidenceGraph != null && report.EvidenceGraph.IsValid)
                {
                    var procNode = report.EvidenceGraph.Nodes.FirstOrDefault(n =>
                        (n.Type == EntityType.OsProcess || n.Type == EntityType.JvmProcess) &&
                        (n.EntityId.Equals(proc.ProcessInstanceId, StringComparison.OrdinalIgnoreCase) ||
                         (n.Properties.TryGetValue("PID", out var pId) && pId == proc.ProcessId.ToString() &&
                          n.Properties.TryGetValue("ProcessName", out var pName) && pName.Equals(proc.ProcessName, StringComparison.OrdinalIgnoreCase))));

                    if (procNode != null)
                    {
                        var gameProcNodes = report.EvidenceGraph.Nodes
                            .Where(n => n.Type == EntityType.JvmProcess)
                            .ToList();

                        hasTechnicalLink = gameProcNodes.Any(gp =>
                            report.EvidenceGraph.HasRelationship(gp.EntityId, procNode.EntityId, maxDepth: 4,
                                edgeFilter: e => e.Type == EdgeType.LaunchedBy || e.Type == EdgeType.AssociatedWith || e.Type == EdgeType.LoadedBy));
                    }
                }
                else
                {
                    hasTechnicalLink = activeGameProcesses.Any(gp =>
                        gp.ProcessId == proc.ParentProcessId ||
                        proc.ParentProcessId == gp.ProcessId);
                }

                // Check temporal consistency with active Minecraft session
                bool hasSessionTiming = proc.StartTime.HasValue && activeGameProcesses.Any(gp => gp.StartTime.HasValue);
                bool isActiveDuringSession = hasTechnicalLink && hasSessionTiming;

                var assessment = new CorrelatedSoftwareAssessment
                {
                    SoftwareName = cheatMatch.Name,
                    FilePath = proc.ExecutablePath,
                    State = isActiveDuringSession
                        ? SoftwareEvidenceState.SoftwareActiveDuringSession
                        : (hasTechnicalLink ? SoftwareEvidenceState.SoftwareInteractingWithMinecraft : SoftwareEvidenceState.SoftwareExecuted),
                    ExecutionState = isActiveDuringSession
                        ? ExecutionEvidenceState.ActiveDuringInspectedSession
                        : (hasTechnicalLink ? ExecutionEvidenceState.MinecraftProcessAssociation : ExecutionEvidenceState.HistoricalExecution),
                    StateDescription = isActiveDuringSession
                        ? $"Cheat executable '{cheatMatch.Name}' (PID {proc.ProcessId}) has verified technical process link and chronologically verified activity during active Minecraft session."
                        : (hasTechnicalLink
                            ? $"Cheat executable '{cheatMatch.Name}' (PID {proc.ProcessId}) has verified technical process link to Minecraft, but session timing could not be verified due to missing/unavailable process start timestamp."
                            : (isMinecraftActive
                                ? $"Cheat executable '{cheatMatch.Name}' (PID {proc.ProcessId}) was executing concurrently with Minecraft, but NO technical link, injection, or handle association was established."
                                : $"Cheat executable '{cheatMatch.Name}' (PID {proc.ProcessId}) is currently executing; Minecraft is not running.")),
                    Confidence = isActiveDuringSession ? ConfidenceLevel.Certain : (hasTechnicalLink ? ConfidenceLevel.High : ConfidenceLevel.High),
                    WhatIsProven = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) is actively running on the operating system.",
                    WhatIsNotProven = isActiveDuringSession
                        ? "Does not prove individual cheat features were toggled during a specific match moment."
                        : (hasTechnicalLink
                            ? "Missing start timestamps prevent chronological proof that process was active during the inspected Minecraft session window."
                            : (isMinecraftActive
                                ? "Concurrent execution does NOT prove association with Minecraft or that it interacted with the game session (Forensic Principle: concurrent execution is never association without technical link)."
                                : "Minecraft was not running; cheat did not interact with an active Minecraft session.")),
                    AlternativeLegitimateExplanations = "Process left running from previous activity or testing outside Minecraft."
                };

                assessments.Add(assessment);

                string clusterId = !string.IsNullOrEmpty(proc.ImageSha256)
                    ? $"CLUSTER-PROC-{proc.ImageSha256[..Math.Min(12, proc.ImageSha256.Length)].ToLowerInvariant()}"
                    : (!string.IsNullOrEmpty(proc.ProcessInstanceId)
                        ? $"CLUSTER-PROC-{proc.ProcessId}"
                        : $"CLUSTER-PROC-{cheatMatch.Name.ToLowerInvariant().Replace(" ", "-")}");
                var existingFinding = report.Findings.FirstOrDefault(f => f.DetectionName.Contains(cheatMatch.Name, StringComparison.OrdinalIgnoreCase));
                if (existingFinding != null)
                {
                    existingFinding.EvidenceCategory = isActiveDuringSession ? EvidenceCategory.ActiveInScanWindow : EvidenceCategory.RunningProcess;
                    existingFinding.SoftwareState = isActiveDuringSession
                        ? SoftwareEvidenceState.SoftwareActiveDuringSession
                        : (hasTechnicalLink ? SoftwareEvidenceState.SoftwareInteractingWithMinecraft : SoftwareEvidenceState.SoftwareExecuted);
                    existingFinding.ExecutionState = isActiveDuringSession
                        ? ExecutionEvidenceState.ActiveDuringInspectedSession
                        : (hasTechnicalLink ? ExecutionEvidenceState.MinecraftProcessAssociation : ExecutionEvidenceState.HistoricalExecution);
                    existingFinding.Severity = hasTechnicalLink ? Severity.High : Severity.Medium;
                    existingFinding.IsInScanWindow = isActiveDuringSession;
                    existingFinding.TargetProcessId = proc.ProcessId;
                    existingFinding.TargetProcessName = proc.ProcessName;
                    existingFinding.EvidenceClusterId = clusterId;
                    if (!isActiveDuringSession && hasTechnicalLink)
                    {
                        existingFinding.Limitations = "Technical link confirmed, but session timing could not be chronologically established due to missing start timestamps.";
                    }
                }
                else
                {
                    report.Findings.Add(new FindingRecord
                    {
                        RuleId = "PROC-CHEAT-PROCESS-RUNNING",
                        DetectionName = $"Known Cheat Process Executing: {cheatMatch.Name}",
                        FindingTitle = $"Known Cheat Process Executing: {cheatMatch.Name}",
                        Category = FindingCategory.CheatArtifact,
                        EvidenceCategory = isActiveDuringSession ? EvidenceCategory.ActiveInScanWindow : EvidenceCategory.RunningProcess,
                        Classification = isActiveDuringSession ? FindingClassification.ConfirmedCheatArtifact : FindingClassification.StrongIndicator,
                        Severity = hasTechnicalLink ? Severity.High : Severity.Medium,
                        EvidenceStrength = isActiveDuringSession ? EvidenceStrength.Strong : EvidenceStrength.Moderate,
                        Confidence = isActiveDuringSession ? ConfidenceLevel.Certain : ConfidenceLevel.High,
                        DetectionMethod = DetectionMethod.ExactSignature,
                        EvidenceState = isActiveDuringSession ? EvidenceState.CONFIRMED : EvidenceState.STRONG_INDICATOR,
                        SoftwareState = isActiveDuringSession
                            ? SoftwareEvidenceState.SoftwareActiveDuringSession
                            : (hasTechnicalLink ? SoftwareEvidenceState.SoftwareInteractingWithMinecraft : SoftwareEvidenceState.SoftwareExecuted),
                        ExecutionState = isActiveDuringSession
                            ? ExecutionEvidenceState.ActiveDuringInspectedSession
                            : (hasTechnicalLink ? ExecutionEvidenceState.MinecraftProcessAssociation : ExecutionEvidenceState.HistoricalExecution),
                        SoftwareStateDescription = assessment.StateDescription,
                        EvidenceSource = "ProcessMonitor",
                        FilePath = proc.ExecutablePath,
                        TargetProcessId = proc.ProcessId,
                        TargetProcessName = proc.ProcessName,
                        ObservedTimestamp = proc.StartTime ?? DateTimeOffset.UtcNow,
                        IsInScanWindow = isActiveDuringSession,
                        EvidenceClusterId = clusterId,
                        Interpretation = assessment.WhatIsProven,
                        Limitations = assessment.WhatIsNotProven,
                        RecommendedReview = "Check process memory, network connections, and injected modules."
                    });
                }
            }
        }

        return assessments;
    }

    public record CommandLineReferenceInfo(
        bool HasReference,
        string ReferenceContext, // "JavaAgent", "Classpath", "SystemProperty", "ArgumentToken", "None"
        string RawArgument,
        int ProcessId,
        string ProcessName);

    private static CommandLineReferenceInfo InspectCommandLineForMod(
        string? commandLine,
        string fileName,
        string fullPath,
        int processId,
        string processName)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return new CommandLineReferenceInfo(false, "None", string.Empty, processId, processName);
        }

        var tokens = TokenizeCommandLine(commandLine);

        foreach (var token in tokens)
        {
            // 1. Check for -javaagent:
            if (token.StartsWith("-javaagent:", StringComparison.OrdinalIgnoreCase))
            {
                string agentSpec = token.Substring("-javaagent:".Length).Trim('\"');
                int eqIdx = agentSpec.IndexOf('=');
                string agentPath = eqIdx > 0 ? agentSpec.Substring(0, eqIdx) : agentSpec;

                if (agentPath.Contains(fileName, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(fullPath) && agentPath.Contains(fullPath, StringComparison.OrdinalIgnoreCase)))
                {
                    return new CommandLineReferenceInfo(true, "JavaAgent", token, processId, processName);
                }
            }

            // 2. Check for -cp, -classpath, --class-path
            if (token.StartsWith("-classpath=", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("-cp=", StringComparison.OrdinalIgnoreCase) ||
                token.StartsWith("--class-path=", StringComparison.OrdinalIgnoreCase))
            {
                int eq = token.IndexOf('=');
                string cpVal = token.Substring(eq + 1).Trim('\"');
                if (MatchesClasspathSegment(cpVal, fileName, fullPath))
                {
                    return new CommandLineReferenceInfo(true, "Classpath", token, processId, processName);
                }
            }
            else if (MatchesClasspathSegment(token, fileName, fullPath))
            {
                return new CommandLineReferenceInfo(true, "Classpath", token, processId, processName);
            }

            // 3. Check for -D<property>=<value>
            if (token.StartsWith("-D", StringComparison.OrdinalIgnoreCase))
            {
                int eq = token.IndexOf('=');
                if (eq > 0)
                {
                    string propVal = token.Substring(eq + 1).Trim('\"');
                    if (propVal.Contains(fileName, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(fullPath) && propVal.Contains(fullPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        return new CommandLineReferenceInfo(true, "SystemProperty", token, processId, processName);
                    }
                }
            }

            // 4. Any other argument token
            if (token.Contains(fileName, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(fullPath) && token.Contains(fullPath, StringComparison.OrdinalIgnoreCase)))
            {
                return new CommandLineReferenceInfo(true, "ArgumentToken", token, processId, processName);
            }
        }

        return new CommandLineReferenceInfo(false, "None", string.Empty, processId, processName);
    }

    private static bool MatchesClasspathSegment(string cpString, string fileName, string fullPath)
    {
        var segments = cpString.Split(new[] { ';', ':' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var seg in segments)
        {
            string cleanSeg = seg.Trim('\"').Trim();
            if (cleanSeg.EndsWith(fileName, StringComparison.OrdinalIgnoreCase) ||
                cleanSeg.Equals(fileName, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(fullPath) && cleanSeg.Equals(fullPath, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        return false;
    }

    private static List<string> TokenizeCommandLine(string cmdLine)
    {
        var list = new List<string>();
        bool inQuotes = false;
        var current = new StringBuilder();

        for (int i = 0; i < cmdLine.Length; i++)
        {
            char c = cmdLine[i];
            if (c == '\"')
            {
                inQuotes = !inQuotes;
                current.Append(c);
            }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0)
                {
                    list.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            list.Add(current.ToString());
        }

        return list;
    }
}

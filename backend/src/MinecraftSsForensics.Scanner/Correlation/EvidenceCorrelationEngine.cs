using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.Correlation;

public class CorrelatedSoftwareAssessment
{
    public string SoftwareName { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public string? Sha256 { get; set; }
    public SoftwareEvidenceState State { get; set; } = SoftwareEvidenceState.SoftwarePresent;
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
/// Strictly distinguishes the 8 evidentiary correlation states:
/// 1. Software is present
/// 2. Software is installed
/// 3. Software was executed
/// 4. Software was active during a Minecraft session
/// 5. Software interacted with Minecraft
/// 6. Software contains prohibited capabilities
/// 7. Prohibited functionality was used
/// 8. Applicable server policy prohibits its possession, execution, or use
/// 
/// Strictly never treats a running Java process as proof that every discovered mod was loaded.
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

            // Create structured Evidence item
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

            // Defensible verification of whether this specific mod was loaded in the active game process
            bool isLoadedInActiveSession = false;
            int activePid = 0;
            string? modDir = Path.GetDirectoryName(mod.FullPath);

            foreach (var gameProc in activeGameProcesses)
            {
                if (!string.IsNullOrEmpty(gameProc.SanitizedCommandLine))
                {
                    // Check if mod file name or path is in JVM classpath, -javaagent, or arguments
                    if (gameProc.SanitizedCommandLine.Contains(mod.FileName, StringComparison.OrdinalIgnoreCase) ||
                        gameProc.SanitizedCommandLine.Contains(mod.FullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        isLoadedInActiveSession = true;
                        activePid = gameProc.ProcessId;
                        break;
                    }

                    // Check if the running game process is running out of this mod's installation root
                    if (!string.IsNullOrEmpty(modDir) &&
                        gameProc.SanitizedCommandLine.Contains(modDir, StringComparison.OrdinalIgnoreCase))
                    {
                        isLoadedInActiveSession = true;
                        activePid = gameProc.ProcessId;
                        break;
                    }
                }
            }

            // Check if historically executed
            var execRecord = report.ExecutionHistory.FirstOrDefault(h =>
                (!string.IsNullOrEmpty(h.ApplicationName) && h.ApplicationName.Contains(mod.Name, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(h.ApplicationPath) && h.ApplicationPath.Contains(mod.FileName, StringComparison.OrdinalIgnoreCase)));

            if (isLoadedInActiveSession)
            {
                assessment.State = SoftwareEvidenceState.SoftwareActiveDuringSession;
                assessment.StateDescription = $"Mod verified loaded in active Minecraft session (PID {activePid}).";
                assessment.WhatIsProven = $"Mod was loaded into the running Minecraft game instance (PID {activePid}).";
                assessment.WhatIsNotProven = "Does not prove specific in-game cheats were actively toggled during match.";
            }
            else if (execRecord != null)
            {
                assessment.State = SoftwareEvidenceState.SoftwareExecuted;
                assessment.StateDescription = $"Mod or associated executable has historical execution trace in {execRecord.Source} at {execRecord.LastExecutionTime}, but was not loaded in active session.";
                assessment.WhatIsProven = "Software has historical proof of execution on this computer.";
                assessment.WhatIsNotProven = "Was not loaded in the active game session.";
            }
            else if (mod.HasConflictingSignals)
            {
                assessment.State = SoftwareEvidenceState.SoftwareContainsProhibitedCapabilities;
                assessment.StateDescription = $"Mod contains verified suspicious or automated bytecode capabilities; no execution records found.";
                assessment.WhatIsProven = "Mod binary contains automated/restricted structural capabilities.";
                assessment.WhatIsNotProven = "Execution was not detected.";
            }
            else
            {
                assessment.State = SoftwareEvidenceState.SoftwareInstalled;
                assessment.StateDescription = $"Mod is installed on disk; no active session loading or execution telemetry was found.";
                assessment.WhatIsProven = "File exists on disk in a Minecraft mods folder.";
                assessment.WhatIsNotProven = "No proof of execution or active in-game use.";
            }

            // Evaluate against Policy
            Enum.TryParse<GameplayPolicy>(mod.GameplayPolicy, out var parsedPolicy);
            assessment.Policy = parsedPolicy;

            if (parsedPolicy == GameplayPolicy.PROHIBITED_POSSESSION)
            {
                // Possession prohibition: possession/installation alone is a violation
                assessment.IsPolicyViolation = true;
                assessment.PolicyEvaluationExplanation = $"VIOLATION (POSSESSION BANNED): Server policy for {policy.Gamemode} bans possession or installation of '{mod.Name}'.";
                assessment.WhatIsProven = "Artifact is installed in the active Minecraft mods directory.";
                assessment.WhatIsNotProven = "Gameplay use is not proven, but is not required under the applicable possession policy.";
                assessment.AlternativeLegitimateExplanations = "Player may use the same installation for unmoderated singleplayer or external servers.";
            }
            else if (parsedPolicy == GameplayPolicy.PROHIBITED_EXECUTION)
            {
                // Execution prohibition: ONLY violates if actively executed or loaded into session
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
                assessment.IsPolicyViolation = false; // Requires packet or in-game telemetry
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

        // 2. Correlate File Discoveries in Downloads/Desktop/Recycle Bin (Present)
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
                    StateDescription = $"Cheat artifact located on disk in user staging directory: '{file.FilePath}'.",
                    Confidence = ConfidenceLevel.Certain
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
                    Title = $"Staged Cheat Artifact on Disk: {file.FileName}",
                    Description = $"File located at '{file.FilePath}'. Description: {cheatMatch.Description}",
                    State = EvidenceState.CONFIRMED,
                    Confidence = ConfidenceLevel.Certain,
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
                    assessment.StateDescription = $"Cheat artifact present on disk AND recorded in historical execution records ({execRecord.Source}) at {execRecord.LastExecutionTime}.";
                    assessment.WhatIsProven = $"File was executed historically on this machine ({execRecord.Source}).";
                    assessment.WhatIsNotProven = "Does not prove execution occurred during the specific match.";
                }
                else
                {
                    assessment.WhatIsProven = $"File '{file.FileName}' is physically present on disk.";
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
                    assessment.AlternativeLegitimateExplanations = "User downloaded file, joke file, or old artifact prior to joining server.";
                }

                assessments.Add(assessment);
            }
        }

        // 3. Correlate Loaded DLL Modules (Interacting With Minecraft)
        foreach (var mod in report.LoadedModules)
        {
            if (mod.IsInTempDirectory && !mod.IsRecognizedJavaNativeLibrary)
            {
                var assessment = new CorrelatedSoftwareAssessment
                {
                    SoftwareName = mod.ModuleName,
                    FilePath = mod.FilePath,
                    State = SoftwareEvidenceState.SoftwareInteractingWithMinecraft,
                    StateDescription = $"Unrecognized DLL module '{mod.ModuleName}' is mapped directly into javaw.exe (PID {mod.ProcessId}) process address space from temporary directory.",
                    Confidence = ConfidenceLevel.High,
                    WhatIsProven = $"Module '{mod.FilePath}' was mapped into javaw.exe memory.",
                    WhatIsNotProven = "Does not prove malicious intent without reverse-engineering module exports.",
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
                    Title = $"Unrecognized DLL Mapped into javaw.exe: {mod.ModuleName}",
                    Description = $"Process PID {mod.ProcessId} loaded '{mod.FilePath}'. Provenance: {mod.ProvenanceAssessment}.",
                    State = EvidenceState.STRONG_INDICATOR,
                    Confidence = ConfidenceLevel.High,
                    Limitations = "Module mapping confirms memory interaction; does not prove modification of game packets or competitive advantages."
                });
                assessment.SupportingEvidenceIds.Add(evId);

                assessments.Add(assessment);
            }
        }

        return assessments;
    }
}

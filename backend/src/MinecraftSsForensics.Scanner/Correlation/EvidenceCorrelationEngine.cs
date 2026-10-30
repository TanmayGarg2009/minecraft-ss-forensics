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
/// Correlates diverse evidence artifacts across filesystem, process memory, execution history,
/// and registry hives. Strictly distinguishes the 6 software states:
/// 1. Software present
/// 2. Software installed
/// 3. Software executed
/// 4. Software active during a Minecraft session
/// 5. Software interacting with Minecraft
/// 6. Prohibited functionality used
/// Never collapses these states into a generic 'cheat detected' flag.
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

        // 1. Correlate Mod Inventory Items (Installed)
        foreach (var mod in report.ModInventory)
        {
            var assessment = new CorrelatedSoftwareAssessment
            {
                SoftwareName = mod.Name,
                FilePath = mod.FullPath,
                Sha256 = mod.Sha256,
                State = SoftwareEvidenceState.SoftwareInstalled,
                StateDescription = $"Mod archive installed in active Minecraft profile mods folder: '{mod.FileName}'."
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
                Description = $"Installed in active profile directory: {mod.FullPath} ({mod.FileSizeBytes} bytes)",
                State = EvidenceState.CONFIRMED,
                Confidence = ConfidenceLevel.Certain,
                Limitations = "Presence in mods folder confirms installation, but does not prove features were toggled during match."
            });
            assessment.SupportingEvidenceIds.Add(evId);

            // Determine if active in session
            bool hasRunningGame = report.RunningProcesses.Any(p => p.ProcessName.Contains("java", StringComparison.OrdinalIgnoreCase));
            if (hasRunningGame)
            {
                assessment.State = SoftwareEvidenceState.SoftwareActiveDuringSession;
                assessment.StateDescription = $"Mod installed in active game directory while Minecraft (javaw.exe) is running.";
            }

            // Check if bytecode has automated capabilities
            if (mod.HasConflictingSignals || mod.GameplayPolicy == "PROHIBITED" || mod.GameplayPolicy.StartsWith("PROHIBITED_"))
            {
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
                    bool executed = report.ExecutionHistory.Any(h => h.ApplicationName.Contains(mod.Name, StringComparison.OrdinalIgnoreCase)) || hasRunningGame;
                    assessment.IsPolicyViolation = executed;
                    assessment.PolicyEvaluationExplanation = executed
                        ? $"VIOLATION (EXECUTION BANNED): Server policy prohibits execution of '{mod.Name}', and game session was running."
                        : $"NEEDS REVIEW: '{mod.Name}' is prohibited on execution, but active execution is unconfirmed.";
                }
                else if (parsedPolicy == GameplayPolicy.PROHIBITED_GAMEPLAY_USE)
                {
                    assessment.IsPolicyViolation = false; // Gameplay use requires corroborating packet or in-game telemetry
                    assessment.PolicyEvaluationExplanation = $"RESTRICTED/NEEDS REVIEW: '{mod.Name}' is prohibited on active gameplay use. Installation is verified, but in-game activation requires staff session review.";
                    assessment.WhatIsProven = "Mod is installed in game profile.";
                    assessment.WhatIsNotProven = "In-game activation or feature toggle during competition is not proven.";
                }
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
                    h.ApplicationName.Equals(file.FileName, StringComparison.OrdinalIgnoreCase) ||
                    h.ApplicationPath.Equals(file.FilePath, StringComparison.OrdinalIgnoreCase));

                if (execRecord != null)
                {
                    assessment.State = SoftwareEvidenceState.SoftwareExecuted;
                    assessment.StateDescription = $"Cheat artifact present on disk AND recorded in historical execution records ({execRecord.Source}) at {execRecord.LastExecutionTime}.";
                }

                // Check policy rule
                var policyRule = policy.Rules.FirstOrDefault(r =>
                    r.ModName.Equals(cheatMatch.Name, StringComparison.OrdinalIgnoreCase) ||
                    r.Aliases.Any(a => a.Equals(cheatMatch.Name, StringComparison.OrdinalIgnoreCase)));

                if (policyRule != null && policyRule.Policy == GameplayPolicy.PROHIBITED_POSSESSION)
                {
                    assessment.Policy = GameplayPolicy.PROHIBITED_POSSESSION;
                    assessment.IsPolicyViolation = true;
                    assessment.PolicyEvaluationExplanation = $"VIOLATION (POSSESSION BANNED): Server policy for {policy.Gamemode} explicitly bans possession of '{cheatMatch.Name}'. Confirmed presence on system constitutes a violation.";
                    assessment.WhatIsProven = $"File '{file.FileName}' exists on the player's system at '{file.FilePath}'.";
                    assessment.WhatIsNotProven = "Does not prove the cheat was active during the specific match being investigated.";
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

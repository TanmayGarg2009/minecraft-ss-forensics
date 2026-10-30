using System;
using System.Collections.Generic;
using System.Linq;
using MinecraftSsForensics.Scanner.Collectors;
using MinecraftSsForensics.Scanner.Correlation;

namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// Portable, self-contained standalone forensic report (Schema v2.0).
/// Strictly internal consistent with complete evidence structures.
/// </summary>
public class StandaloneReport
{
    // 1. Report metadata
    public string ReportId { get; set; } = $"rep_{Guid.NewGuid():N}"[..16];
    public string SchemaVersion { get; set; } = "2.0.0";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string ReportIntegrityHash { get; set; } = string.Empty;

    // 2. Scanner version and build
    public string ScannerVersion { get; set; } = "2.0.0-standalone";
    public string ScannerBuild { get; set; } = "Standalone-Win-x64-Release";

    // 3. Operating system information
    public TargetSystemInfo TargetSystem { get; set; } = new();

    // 4. Scan start and completion times
    public DateTimeOffset ScanStartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ScanCompletedAt { get; set; } = DateTimeOffset.UtcNow;
    public long ScanDurationMs { get; set; }
    public string ScanMode { get; set; } = "QUICK"; // QUICK or FULL

    // 5. Consent and selected audit categories
    public ConsentScopeConfig Consent { get; set; } = new();

    // 6. Minecraft installation information
    public List<MinecraftInstallationInfo> MinecraftInstallations { get; set; } = new();
    public List<string> DetectedMinecraftVersions { get; set; } = new();
    public List<string> DetectedLoaders { get; set; } = new();

    // 7. Java runtime information
    public JavaRuntimeInfo JavaRuntime { get; set; } = new();

    // 8. Complete mod inventory
    public List<DiscoveredModItem> ModInventory { get; set; } = new();

    // 9. Mod authenticity verification
    public List<ModAuthenticityItem> AuthenticityVerifications { get; set; } = new();

    // 10. Gameplay-policy evaluation
    public PolicyEvaluationSummary PolicyEvaluation { get; set; } = new();

    // 11. Known cheat artifact detections
    public List<CheatDetectionItem> CheatDetections { get; set; } = new();

    // 12. Running process information
    public List<ProcessTelemetryItem> RunningProcesses { get; set; } = new();

    // 13. Loaded module information
    public List<LoadedModuleItem> LoadedModules { get; set; } = new();

    // 14. Relevant execution history
    public List<ExecutionHistoryItem> ExecutionHistory { get; set; } = new();

    // 15. Relevant registry evidence
    public List<RegistryEvidenceItem> RegistryEvidence { get; set; } = new();

    // 16. Relevant USB evidence, if selected
    public List<UsbDeviceItem> UsbEvidence { get; set; } = new();

    // 17. Relevant browser evidence, if selected
    public List<BrowserHistoryItem> BrowserEvidence { get; set; } = new();

    // 18. File discovery metadata and hashes
    public List<DiscoveredFileItem> FileDiscoveries { get; set; } = new();

    // 18b. Services and drivers
    public List<ServiceOrDriverRecord> ServicesAndDrivers { get; set; } = new();

    // 18c. Correlated software assessments
    public List<CorrelatedSoftwareAssessment> CorrelatedAssessments { get; set; } = new();

    // 19. Detailed findings
    public List<FindingRecord> Findings { get; set; } = new();

    // 20. Evidence references & timeline
    public List<TimelineEventRecord> TimelineEvents { get; set; } = new();
    public List<EvidenceReferenceItem> EvidenceItems { get; set; } = new();

    // 21. Summary counts & confidence assessments
    public ReportSummaryCounts SummaryCounts { get; set; } = new();

    // 22-25. Collection diagnostics & technical limitations
    public List<DiagnosticCheckItem> DiagnosticChecks { get; set; } = new();
    public List<string> TechnicalLimitations { get; set; } = new();

    // 26. Final investigation summary
    public InvestigationVerdict Verdict { get; set; } = new();

    /// <summary>
    /// Recalculates and enforces mathematical internal consistency between checks, findings, and summaries.
    /// </summary>
    public void RecomputeSummaryCounts()
    {
        SummaryCounts.TotalChecks = DiagnosticChecks.Count;
        SummaryCounts.PassedChecks = DiagnosticChecks.Count(c => c.Status == CheckStatus.PASSED);
        SummaryCounts.FlaggedChecks = DiagnosticChecks.Count(c => c.Status == CheckStatus.FLAGGED);
        SummaryCounts.SkippedChecks = DiagnosticChecks.Count(c => c.Status == CheckStatus.SKIPPED);
        SummaryCounts.UnavailableChecks = DiagnosticChecks.Count(c => c.Status == CheckStatus.UNAVAILABLE);
        SummaryCounts.ErrorChecks = DiagnosticChecks.Count(c => c.Status == CheckStatus.ERROR);

        SummaryCounts.TotalFindings = Findings.Count;
        SummaryCounts.ConfirmedCheats = Findings.Count(f => f.Classification == FindingClassification.ConfirmedCheatArtifact);
        SummaryCounts.StrongIndicators = Findings.Count(f => f.Classification == FindingClassification.StrongIndicator);
        SummaryCounts.Suspicious = Findings.Count(f => f.Classification == FindingClassification.Suspicious);
        SummaryCounts.NeedsReview = Findings.Count(f => f.Classification == FindingClassification.NeedsReview);
        SummaryCounts.Informational = Findings.Count(f => f.Classification == FindingClassification.Informational);

        SummaryCounts.VerifiedMods = ModInventory.Count(m => m.Verified);
        SummaryCounts.UnverifiedMods = ModInventory.Count(m => !m.Verified);
        SummaryCounts.ProhibitedMods = ModInventory.Count(m => m.GameplayPolicy != null && m.GameplayPolicy.StartsWith("PROHIBITED", StringComparison.OrdinalIgnoreCase));
    }
}

public class TargetSystemInfo
{
    public string OsName { get; set; } = "Microsoft Windows";
    public string OsVersion { get; set; } = Environment.OSVersion.VersionString;
    public string Architecture { get; set; } = Environment.Is64BitOperatingSystem ? "X64" : "X86";
    public string MachineIdentifier { get; set; } = Environment.MachineName;
    public string UserIdentifier { get; set; } = Environment.UserName;
}

public class MinecraftInstallationInfo
{
    public string Name { get; set; } = string.Empty;
    public string RootPath { get; set; } = string.Empty;
    public bool Exists { get; set; }
    public string LauncherType { get; set; } = string.Empty;
}

public class JavaRuntimeInfo
{
    public string? JavaHome { get; set; }
    public string? JavaExecutablePath { get; set; }
    public string? JavaVendor { get; set; }
    public string? JavaVersion { get; set; }
    public string? RawJvmArguments { get; set; }
    public List<string> SanitizedJvmFlags { get; set; } = new();
}

public class DiscoveredModItem
{
    public string Name { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public string ModId { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Loader { get; set; } = string.Empty;
    public bool Verified { get; set; }
    public string VerificationState { get; set; } = "UNKNOWN";
    public string VerificationProvider { get; set; } = string.Empty;
    public string? ProjectUrl { get; set; }
    public string GameplayPolicy { get; set; } = "UNKNOWN";
    public string BehaviorCategory { get; set; } = "None";
    public string PolicyReason { get; set; } = string.Empty;
    public bool HasConflictingSignals { get; set; }
    public string? ConflictDetails { get; set; }
}

public class ModAuthenticityItem
{
    public string FileName { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
    public string? OfficialProjectUrl { get; set; }
}

public class PolicyEvaluationSummary
{
    public string AppliedGamemode { get; set; } = "Standard PvP";
    public string AppliedPolicyName { get; set; } = "Standard Ruleset";
    public string AppliedPolicyVersion { get; set; } = "2.0.0";
    public string RulesDocumentationUrl { get; set; } = string.Empty;
    public int AllowedCount { get; set; }
    public int ProhibitedCount { get; set; }
    public int RestrictedCount { get; set; }
    public int NeedsReviewCount { get; set; }
}

public class CheatDetectionItem
{
    public string CheatName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public FindingClassification Classification { get; set; }
    public string MatchDetails { get; set; } = string.Empty;
    public string MatchedSignature { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
}

public class ProcessTelemetryItem
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string? ExecutablePath { get; set; }
    public int? ParentProcessId { get; set; }
    public string? ParentProcessName { get; set; }
    public string? SanitizedCommandLine { get; set; }
    public DateTimeOffset? StartTime { get; set; }
}

public class LoadedModuleItem
{
    public int ProcessId { get; set; }
    public string ModuleName { get; set; } = string.Empty;
    public string ModulePath { get; set; } = string.Empty;
    public string FilePath { get => ModulePath; set => ModulePath = value; }
    public long? FileSizeBytes { get; set; }
    public bool IsInTempDirectory { get; set; }
    public bool IsRecognizedJavaNativeLibrary { get; set; }
    public string ProvenanceAssessment { get; set; } = "Normal System Module";
}

public class ExecutionHistoryItem
{
    public string Source { get; set; } = string.Empty; // Prefetch, BAM, PCA, PowerShell
    public string ApplicationName { get; set; } = string.Empty;
    public string ApplicationPath { get; set; } = string.Empty;
    public DateTimeOffset? LastExecutionTime { get; set; }
    public int? ExecutionCount { get; set; }
    public bool IsSuspiciousLocation { get; set; }
    public string Details { get; set; } = string.Empty;
}

public class RegistryEvidenceItem
{
    public string KeyPath { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string ValueData { get; set; } = string.Empty;
    public string Significance { get; set; } = string.Empty;
}

public class UsbDeviceItem
{
    public string DeviceName { get; set; } = string.Empty;
    public string DeviceDescription { get => DeviceName; set => DeviceName = value; }
    public string SerialNumber { get; set; } = string.Empty;
    public string HardwareId { get => SerialNumber; set => SerialNumber = value; }
    public DateTimeOffset? LastConnectedTime { get; set; }
    public DateTimeOffset? LastConnectedTimestamp { get => LastConnectedTime; set => LastConnectedTime = value; }
    public DateTimeOffset? DisconnectedTime { get; set; }
    public string MountLocation { get; set; } = string.Empty;
}

public class BrowserHistoryItem
{
    public string BrowserName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string Url { get => Domain; set => Domain = value; }
    public string MatchedCheatCategory { get; set; } = string.Empty;
    public DateTimeOffset? VisitTime { get; set; }
    public int VisitCount { get; set; }
}

public class DiscoveredFileItem
{
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset LastModified { get; set; }
    public string SuspicionReason { get; set; } = string.Empty;
    public string DiscoveryCategory { get => SuspicionReason; set => SuspicionReason = value; }
}

public class TimelineEventRecord
{
    public DateTimeOffset Timestamp { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
}

public class EvidenceReferenceItem
{
    public string EvidenceId { get; set; } = $"EVD-{Guid.NewGuid():N}"[..12];
    public EvidenceType Type { get; set; }
    public string EvidenceCategory { get; set; } = "Artifact";
    public string SourceArtifact { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTimeOffset CollectionTimestamp { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? OriginalEventTimestamp { get; set; }
    public string? FilePath { get; set; }
    public string? ProcessIdentity { get; set; }
    public string? Sha256 { get; set; }
    public string CollectionMethod { get; set; } = "Static Analysis";
    public EvidenceState State { get; set; } = EvidenceState.CONFIRMED;
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
    public string Limitations { get; set; } = string.Empty;
    public List<string> RelatedEvidenceIds { get; set; } = new();
    public bool IsAvailable { get; set; } = true;
    public string? DiagnosticMessage { get; set; }
    public DateTimeOffset CapturedAt { get => CollectionTimestamp; set => CollectionTimestamp = value; }
    public object? StructuredData { get; set; }
}

public class ReportSummaryCounts
{
    public int TotalChecks { get; set; }
    public int PassedChecks { get; set; }
    public int FlaggedChecks { get; set; }
    public int SkippedChecks { get; set; }
    public int UnavailableChecks { get; set; }
    public int ErrorChecks { get; set; }

    public int TotalFindings { get; set; }
    public int ConfirmedCheats { get; set; }
    public int StrongIndicators { get; set; }
    public int Suspicious { get; set; }
    public int NeedsReview { get; set; }
    public int Informational { get; set; }

    public int VerifiedMods { get; set; }
    public int UnverifiedMods { get; set; }
    public int ProhibitedMods { get; set; }
}

public class InvestigationVerdict
{
    public string OverallAssessment { get; set; } = "NO EVIDENCE OF CHEATING DETECTED";
    public string Recommendation { get; set; } = "No policy violations or cheat software found in active scope.";
    public List<string> KeyTakeaways { get; set; } = new();
    public List<string> UnansweredQuestions { get; set; } = new();
}

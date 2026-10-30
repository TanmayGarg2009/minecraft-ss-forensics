using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Scanner.Models.Legacy;

public enum ScanMode
{
    Quick,
    Full
}

public class SubmitReportRequest
{
    public string SchemaVersion { get; set; } = "1.0.0";
    public string ScannerVersion { get; set; } = string.Empty;
    public string ScanMode { get; set; } = "QUICK";
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsArchitecture { get; set; } = "x64";
    public DateTimeOffset? ScanStartedAt { get; set; }
    public DateTimeOffset? ScanCompletedAt { get; set; }
    public List<string> DetectedMinecraftVersions { get; set; } = new();
    public List<string> DetectedLoaders { get; set; } = new();
    public string? AppliedPolicyName { get; set; }
    public string? AppliedPolicyVersion { get; set; }
    public string? AppliedGamemode { get; set; }
    public string? AppliedPolicyRulesUrl { get; set; }
    public ConsentSubmissionDto ConsentConfirmation { get; set; } = new();
    public CoverageSubmissionDto? CollectionCoverage { get; set; }
    public int? RetentionDays { get; set; } = 7;
    public List<FindingSubmissionDto> Findings { get; set; } = new();
    public List<EvidenceSubmissionDto> EvidenceItems { get; set; } = new();
    public List<TimelineEventSubmissionDto> TimelineEvents { get; set; } = new();
    public List<DiagnosticItemSubmissionDto> DiagnosticItems { get; set; } = new();
}

public class ConsentSubmissionDto
{
    public bool ConsentGiven { get; set; }
    public string CollectionScopeVersion { get; set; } = "1.0";
    public DateTimeOffset ConsentTimestamp { get; set; } = DateTimeOffset.UtcNow;
}

public class CoverageSubmissionDto
{
    public int TotalChecks { get; set; }
    public int PassedChecks { get; set; }
    public int FlaggedChecks { get; set; }
    public int UnavailableChecks { get; set; }
}

public class FindingSubmissionDto
{
    public string RuleId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Category { get; set; } = "Other";
    public string Severity { get; set; } = "Informational";
    public string Confidence { get; set; } = "Medium";
    public string Explanation { get; set; } = string.Empty;
    public object? ObservedEvidence { get; set; }
    public string? FilePath { get; set; }
    public long? FileSizeBytes { get; set; }
    public string? FileSha256 { get; set; }
    public DateTimeOffset? FileCreatedTime { get; set; }
    public DateTimeOffset? FileModifiedTime { get; set; }
    public DateTimeOffset? FileLastAccessTime { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessCommandLine { get; set; }
    public DateTimeOffset? FirstObservedAt { get; set; }
    public DateTimeOffset? LastObservedAt { get; set; }
    public string EvidenceSource { get; set; } = "Other";
    public string DetectionRuleVersion { get; set; } = "1.0.0";
    public string LimitationsAndFalsePositives { get; set; } = string.Empty;
}

public class EvidenceSubmissionDto
{
    public string PublicEvidenceId { get; set; } = string.Empty;
    public string Type { get; set; } = "FileMetadata";
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? RawContent { get; set; }
    public object? StructuredPayload { get; set; }
    public string? Sha256Hash { get; set; }
    public bool IsAvailable { get; set; } = true;
    public string? DiagnosticMessage { get; set; }
    public DateTimeOffset? CapturedAt { get; set; }
}

public class TimelineEventSubmissionDto
{
    public DateTimeOffset Timestamp { get; set; }
    public bool IsInferred { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Confidence { get; set; } = "Medium";
    public string? CorrelationGroup { get; set; }
}

public class DiagnosticItemSubmissionDto
{
    public string CheckName { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Status { get; set; } = "Completed";
    public string Reason { get; set; } = string.Empty;
    public string? Recommendation { get; set; }
}

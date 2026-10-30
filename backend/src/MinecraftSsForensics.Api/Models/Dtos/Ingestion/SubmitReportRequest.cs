using System.ComponentModel.DataAnnotations;
using MinecraftSsForensics.Api.Models.Domain;

namespace MinecraftSsForensics.Api.Models.Dtos.Ingestion;

public class SubmitReportRequest
{
    [Required]
    [MaxLength(32)]
    public string SchemaVersion { get; set; } = "1.0.0";

    [Required]
    [MaxLength(64)]
    public string ScannerVersion { get; set; } = string.Empty;

    [Required]
    public string ScanMode { get; set; } = "QUICK"; // QUICK or FULL

    [Required]
    [MaxLength(64)]
    public string OsName { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string OsVersion { get; set; } = string.Empty;

    [MaxLength(32)]
    public string OsArchitecture { get; set; } = "x64";

    public DateTimeOffset? ScanStartedAt { get; set; }
    public DateTimeOffset? ScanCompletedAt { get; set; }

    public List<string> DetectedMinecraftVersions { get; set; } = new();
    public List<string> DetectedLoaders { get; set; } = new();

    [MaxLength(100)]
    public string? AppliedPolicyName { get; set; }

    [MaxLength(32)]
    public string? AppliedPolicyVersion { get; set; }

    [MaxLength(64)]
    public string? AppliedGamemode { get; set; }

    [MaxLength(256)]
    public string? AppliedPolicyRulesUrl { get; set; }

    [Required]
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
    [Required]
    public bool ConsentGiven { get; set; }

    [MaxLength(64)]
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
    [Required]
    [MaxLength(64)]
    public string RuleId { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    [Required]
    public string Category { get; set; } = "Other";

    [Required]
    public string Severity { get; set; } = "Informational";

    [Required]
    public string Confidence { get; set; } = "Medium";

    [Required]
    public string Explanation { get; set; } = string.Empty;

    public object? ObservedEvidence { get; set; }

    [MaxLength(1024)]
    public string? FilePath { get; set; }
    public long? FileSizeBytes { get; set; }

    [MaxLength(128)]
    public string? FileSha256 { get; set; }

    public DateTimeOffset? FileCreatedTime { get; set; }
    public DateTimeOffset? FileModifiedTime { get; set; }
    public DateTimeOffset? FileLastAccessTime { get; set; }

    public int? ProcessId { get; set; }

    [MaxLength(256)]
    public string? ProcessName { get; set; }
    public string? ProcessCommandLine { get; set; }

    public DateTimeOffset? FirstObservedAt { get; set; }
    public DateTimeOffset? LastObservedAt { get; set; }

    public string EvidenceSource { get; set; } = "Other";

    [MaxLength(32)]
    public string DetectionRuleVersion { get; set; } = "1.0.0";

    public string LimitationsAndFalsePositives { get; set; } = string.Empty;
}

public class EvidenceSubmissionDto
{
    [Required]
    [MaxLength(64)]
    public string PublicEvidenceId { get; set; } = string.Empty;

    [Required]
    public string Type { get; set; } = "FileMetadata";

    [Required]
    [MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string? RawContent { get; set; }
    public object? StructuredPayload { get; set; }

    [MaxLength(128)]
    public string? Sha256Hash { get; set; }

    public bool IsAvailable { get; set; } = true;

    [MaxLength(512)]
    public string? DiagnosticMessage { get; set; }

    public DateTimeOffset? CapturedAt { get; set; }
}

public class TimelineEventSubmissionDto
{
    public DateTimeOffset Timestamp { get; set; }
    public bool IsInferred { get; set; }

    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = string.Empty;

    [Required]
    public string Description { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Source { get; set; } = string.Empty;

    public string Confidence { get; set; } = "Medium";

    [MaxLength(100)]
    public string? CorrelationGroup { get; set; }
}

public class DiagnosticItemSubmissionDto
{
    [Required]
    [MaxLength(150)]
    public string CheckName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Source { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string Status { get; set; } = "Skipped";

    [Required]
    public string Reason { get; set; } = string.Empty;

    public string? Recommendation { get; set; }
}

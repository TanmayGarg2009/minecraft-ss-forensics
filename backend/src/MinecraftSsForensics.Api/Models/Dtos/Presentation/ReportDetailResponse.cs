namespace MinecraftSsForensics.Api.Models.Dtos.Presentation;

public class ReportDetailResponse
{
    public string PublicId { get; set; } = string.Empty;
    public string SchemaVersion { get; set; } = "1.0.0";
    public string ScannerVersion { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UploadedAt { get; set; }
    public DateTimeOffset? ScanStartedAt { get; set; }
    public DateTimeOffset? ScanCompletedAt { get; set; }
    public string ScanMode { get; set; } = "QUICK";

    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsArchitecture { get; set; } = string.Empty;

    public List<string> DetectedMinecraftVersions { get; set; } = new();
    public List<string> DetectedLoaders { get; set; } = new();

    public ConsentDetailDto Consent { get; set; } = new();
    public string ProcessingStatus { get; set; } = "Completed";
    public DateTimeOffset ExpiresAt { get; set; }

    public CoverageDetailDto Coverage { get; set; } = new();
    public Dictionary<string, int> SeveritySummary { get; set; } = new();

    public List<FindingDetailDto> Findings { get; set; } = new();
    public List<EvidenceSummaryDto> EvidenceItems { get; set; } = new();
    public List<TimelineEventDetailDto> TimelineEvents { get; set; } = new();
    public List<DiagnosticItemDetailDto> DiagnosticItems { get; set; } = new();

    public string PrivacyNotice { get; set; } = "This report is accessible via this unguessable link without authentication. Please share only with trusted server staff.";
}

public class ConsentDetailDto
{
    public bool ConsentGiven { get; set; }
    public string CollectionScopeVersion { get; set; } = "1.0";
    public DateTimeOffset ConsentTimestamp { get; set; }
}

public class CoverageDetailDto
{
    public int TotalChecks { get; set; }
    public int PassedChecks { get; set; }
    public int FlaggedChecks { get; set; }
    public int UnavailableChecks { get; set; }
}

public class FindingDetailDto
{
    public string RuleId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Confidence { get; set; } = string.Empty;
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

    public string EvidenceSource { get; set; } = string.Empty;
    public string DetectionRuleVersion { get; set; } = string.Empty;
    public string LimitationsAndFalsePositives { get; set; } = string.Empty;
}

public class EvidenceSummaryDto
{
    public string PublicEvidenceId { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? Sha256Hash { get; set; }
    public bool IsAvailable { get; set; }
    public string? DiagnosticMessage { get; set; }
    public DateTimeOffset CapturedAt { get; set; }
    public bool HasRawContent { get; set; }
    public object? StructuredPayload { get; set; }
}

public class EvidenceDetailDto : EvidenceSummaryDto
{
    public string? RawContent { get; set; }
}

public class TimelineEventDetailDto
{
    public DateTimeOffset Timestamp { get; set; }
    public bool IsInferred { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Confidence { get; set; } = string.Empty;
    public string? CorrelationGroup { get; set; }
}

public class DiagnosticItemDetailDto
{
    public string CheckName { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string? Recommendation { get; set; }
}

public class DeleteReportRequest
{
    public string DeletionKey { get; set; } = string.Empty;
}

public class DeleteReportResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

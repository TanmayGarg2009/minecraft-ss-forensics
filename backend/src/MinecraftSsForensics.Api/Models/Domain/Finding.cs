using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Api.Models.Domain;

public class Finding
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ReportId { get; set; }
    public Report Report { get; set; } = null!;

    [Required]
    [MaxLength(64)]
    public string RuleId { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    public FindingCategory Category { get; set; }
    public Severity Severity { get; set; }
    public ConfidenceLevel Confidence { get; set; }

    [Required]
    public string Explanation { get; set; } = string.Empty;

    public string ObservedEvidenceJson { get; set; } = "{}";

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

    public EvidenceSource EvidenceSource { get; set; }

    [MaxLength(32)]
    public string DetectionRuleVersion { get; set; } = "1.0.0";

    public string LimitationsAndFalsePositives { get; set; } = string.Empty;
}

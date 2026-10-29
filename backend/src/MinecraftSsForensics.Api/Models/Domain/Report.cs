using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Api.Models.Domain;

public class Report
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(64)]
    public string PublicId { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string DeletionKeyHash { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string SchemaVersion { get; set; } = "1.0.0";

    [Required]
    [MaxLength(64)]
    public string ScannerVersion { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UploadedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ScanStartedAt { get; set; }
    public DateTimeOffset? ScanCompletedAt { get; set; }

    public ScanMode ScanMode { get; set; } = ScanMode.Quick;

    [Required]
    [MaxLength(64)]
    public string OsName { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string OsVersion { get; set; } = string.Empty;

    [MaxLength(32)]
    public string OsArchitecture { get; set; } = "x64";

    public string DetectedMinecraftVersionsJson { get; set; } = "[]";
    public string DetectedLoadersJson { get; set; } = "[]";

    public bool ConsentGiven { get; set; }
    
    [MaxLength(64)]
    public string CollectionScopeVersion { get; set; } = "1.0";
    public DateTimeOffset ConsentTimestamp { get; set; } = DateTimeOffset.UtcNow;

    public ProcessingStatus ProcessingStatus { get; set; } = ProcessingStatus.Completed;
    public DateTimeOffset ExpiresAt { get; set; }

    public int TotalChecks { get; set; }
    public int PassedChecks { get; set; }
    public int FlaggedChecks { get; set; }
    public int UnavailableChecks { get; set; }

    // Navigation properties
    public List<Finding> Findings { get; set; } = new();
    public List<EvidenceItem> EvidenceItems { get; set; } = new();
    public List<TimelineEvent> TimelineEvents { get; set; } = new();
    public List<DiagnosticItem> DiagnosticItems { get; set; } = new();
}

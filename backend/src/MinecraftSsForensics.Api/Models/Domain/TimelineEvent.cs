using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Api.Models.Domain;

public class TimelineEvent
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ReportId { get; set; }
    public Report Report { get; set; } = null!;

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

    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;

    [MaxLength(100)]
    public string? CorrelationGroup { get; set; }
}

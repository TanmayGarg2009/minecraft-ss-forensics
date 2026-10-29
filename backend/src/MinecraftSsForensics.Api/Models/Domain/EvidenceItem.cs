using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Api.Models.Domain;

public class EvidenceItem
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ReportId { get; set; }
    public Report Report { get; set; } = null!;

    [Required]
    [MaxLength(64)]
    public string PublicEvidenceId { get; set; } = string.Empty;

    public EvidenceType Type { get; set; }

    [Required]
    [MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string? RawContent { get; set; }

    public string? StructuredPayloadJson { get; set; }

    [MaxLength(128)]
    public string? Sha256Hash { get; set; }

    public bool IsAvailable { get; set; } = true;

    [MaxLength(512)]
    public string? DiagnosticMessage { get; set; }

    public DateTimeOffset CapturedAt { get; set; } = DateTimeOffset.UtcNow;
}

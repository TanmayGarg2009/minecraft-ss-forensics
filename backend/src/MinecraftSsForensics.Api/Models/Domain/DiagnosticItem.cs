using System.ComponentModel.DataAnnotations;

namespace MinecraftSsForensics.Api.Models.Domain;

public class DiagnosticItem
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ReportId { get; set; }
    public Report Report { get; set; } = null!;

    [Required]
    [MaxLength(150)]
    public string CheckName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Source { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string Status { get; set; } = "Skipped"; // Skipped, AccessDenied, Unsupported, Failed, Completed

    [Required]
    public string Reason { get; set; } = string.Empty;

    public string? Recommendation { get; set; }
}

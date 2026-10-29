namespace MinecraftSsForensics.Api.Models.Dtos.Ingestion;

public class SubmitReportResponse
{
    public string PublicId { get; set; } = string.Empty;
    public string ShareUrl { get; set; } = string.Empty;
    public string DeletionKey { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public string ProcessingStatus { get; set; } = string.Empty;
    public int FindingsCount { get; set; }
    public string Message { get; set; } = string.Empty;
}

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Encapsulates the exported forensic report document, metadata, and suggested filename.
/// </summary>
public class ReportExportResult
{
    public string Content { get; set; } = string.Empty;
    public string SuggestedFileName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/json";
    public ReportExportFormat Format { get; set; } = ReportExportFormat.Json;
    public DateTimeOffset ExportedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public int ByteCount => System.Text.Encoding.UTF8.GetByteCount(Content);
}

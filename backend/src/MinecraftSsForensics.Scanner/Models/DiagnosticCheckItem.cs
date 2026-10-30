namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// Status record for an individual forensic check executed or attempted by the scanner.
/// </summary>
public class DiagnosticCheckItem
{
    public string CheckId { get; set; } = string.Empty;
    public string CheckName { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public CheckStatus Status { get; set; } = CheckStatus.PASSED;
    public string Reason { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public long DurationMs { get; set; }
}

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Supported export formats for portable offline forensic reports.
/// </summary>
public enum ReportExportFormat
{
    /// <summary>
    /// Self-contained, full structured JSON report containing all evidentiary payloads.
    /// </summary>
    Json,

    /// <summary>
    /// Human- and AI-readable Markdown report with structured sections and an AI analysis guide.
    /// </summary>
    Markdown,

    /// <summary>
    /// Self-contained interactive HTML document for offline staff triage.
    /// </summary>
    Html,

    /// <summary>
    /// RFC-4180 compliant CSV export of forensic findings for tabular spreadsheet auditing.
    /// </summary>
    Csv
}

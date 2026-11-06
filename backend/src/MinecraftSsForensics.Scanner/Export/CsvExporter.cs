using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Exports forensic findings into RFC-4180 compliant CSV format suitable for spreadsheet software
/// and tabular automated data processing pipelines.
/// </summary>
public static class CsvExporter
{
    private static readonly string[] Headers = new[]
    {
        "FindingId",
        "RuleId",
        "FindingTitle",
        "Category",
        "EvidenceCategory",
        "Classification",
        "Severity",
        "EvidenceStrength",
        "Confidence",
        "DetectionMethod",
        "SoftwareState",
        "SoftwareStateDescription",
        "EvidenceSource",
        "FilePath",
        "FileSha256",
        "FileSizeBytes",
        "ObservedTimestamp",
        "IsInScanWindow",
        "EvidenceClusterId",
        "Interpretation"
    };

    /// <summary>
    /// Exports findings of the given report as an RFC-4180 compliant CSV string.
    /// </summary>
    public static string ExportToCsv(StandaloneReport report)
    {
        report = PrivacyBoundary.CreateSanitizedCopy(report);

        var sb = new StringBuilder();

        // Write header row
        sb.AppendLine(string.Join(",", Headers));

        if (report.Findings != null)
        {
            foreach (var finding in report.Findings)
            {
                var row = new[]
                {
                    EscapeCsvField(finding.FindingId),
                    EscapeCsvField(finding.RuleId),
                    EscapeCsvField(finding.FindingTitle),
                    EscapeCsvField(finding.Category.ToString()),
                    EscapeCsvField(finding.EvidenceCategory.ToString()),
                    EscapeCsvField(finding.Classification.ToString()),
                    EscapeCsvField(finding.Severity.ToString()),
                    EscapeCsvField(finding.EvidenceStrength.ToString()),
                    EscapeCsvField(finding.Confidence.ToString()),
                    EscapeCsvField(finding.DetectionMethod.ToString()),
                    EscapeCsvField(finding.SoftwareState.ToString()),
                    EscapeCsvField(finding.SoftwareStateDescription),
                    EscapeCsvField(finding.EvidenceSource),
                    EscapeCsvField(finding.FilePath ?? string.Empty),
                    EscapeCsvField(finding.FileSha256 ?? string.Empty),
                    EscapeCsvField(finding.FileSizeBytes?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
                    EscapeCsvField(finding.ObservedTimestamp?.ToString("o", CultureInfo.InvariantCulture) ?? string.Empty),
                    EscapeCsvField(finding.IsInScanWindow ? "true" : "false"),
                    EscapeCsvField(finding.EvidenceClusterId),
                    EscapeCsvField(finding.Interpretation)
                };

                sb.AppendLine(string.Join(",", row));
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Produces a ReportExportResult packaging the CSV string.
    /// </summary>
    public static ReportExportResult Export(StandaloneReport report)
    {
        string content = ExportToCsv(report);
        return new ReportExportResult
        {
            Content = content,
            Format = ReportExportFormat.Csv,
            MimeType = "text/csv; charset=utf-8",
            SuggestedFileName = $"mc-ss-findings-{report.ReportId}.csv",
            ExportedAtUtc = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Escapes an individual field according to RFC-4180 rules.
    /// Fields containing commas, quotation marks, or line breaks are enclosed in double quotes,
    /// and any internal double quotes are escaped by doubling them ("").
    /// </summary>
    public static string EscapeCsvField(string? field)
    {
        if (string.IsNullOrEmpty(field))
        {
            return string.Empty;
        }

        bool containsSpecialChars = field.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0;
        if (containsSpecialChars)
        {
            return $"\"{field.Replace("\"", "\"\"")}\"";
        }

        return field;
    }
}

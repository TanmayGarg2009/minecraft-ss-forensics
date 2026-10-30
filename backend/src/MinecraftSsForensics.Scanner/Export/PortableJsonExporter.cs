using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Serializes and deserializes standalone forensic reports with backward-compatibility
/// for legacy schema formats and untrusted input defenses.
/// </summary>
public static class PortableJsonExporter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string ExportToJson(StandaloneReport report)
    {
        // Compute and seal integrity hash
        report.RecomputeSummaryCounts();
        report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);

        return JsonSerializer.Serialize(report, JsonOpts);
    }

    public static void SaveToFile(StandaloneReport report, string filePath)
    {
        string json = ExportToJson(report);
        File.WriteAllText(filePath, json, System.Text.Encoding.UTF8);
    }

    public static (bool Success, StandaloneReport? Report, string ErrorMessage) LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return (false, null, $"Report file not found: {filePath}");
        }

        try
        {
            string json = File.ReadAllText(filePath, System.Text.Encoding.UTF8);
            return LoadFromJson(json);
        }
        catch (Exception ex)
        {
            return (false, null, $"Error reading report file: {ex.Message}");
        }
    }

    public static (bool Success, StandaloneReport? Report, string ErrorMessage) LoadFromJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return (false, null, "Report content is empty.");
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Check if this is v2.0 StandaloneReport
            if (root.TryGetProperty("reportId", out _) && root.TryGetProperty("schemaVersion", out var sVer))
            {
                var report = JsonSerializer.Deserialize<StandaloneReport>(json, JsonOpts);
                if (report == null)
                    return (false, null, "Failed to deserialize standalone report structure.");

                report.RecomputeSummaryCounts();
                return (true, report, string.Empty);
            }

            // Backward compatibility: Support v1.0 wrapped export format ({ exportMetadata: ..., report: ... })
            if (root.TryGetProperty("report", out var v1Rep))
            {
                var report = new StandaloneReport
                {
                    SchemaVersion = "2.0.0",
                    ReportId = root.TryGetProperty("exportMetadata", out var meta) && meta.TryGetProperty("reportId", out var idProp)
                        ? idProp.GetString() ?? "rep_v1_legacy"
                        : "rep_v1_legacy",
                    ScanMode = v1Rep.TryGetProperty("scanMode", out var sm) ? sm.GetString() ?? "QUICK" : "QUICK"
                };

                if (v1Rep.TryGetProperty("osName", out var osN)) report.TargetSystem.OsName = osN.GetString() ?? "Windows";
                if (v1Rep.TryGetProperty("osVersion", out var osV)) report.TargetSystem.OsVersion = osV.GetString() ?? "";

                // Migrate findings
                if (v1Rep.TryGetProperty("findings", out var findingsArr) && findingsArr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var fEl in findingsArr.EnumerateArray())
                    {
                        var finding = new FindingRecord
                        {
                            RuleId = fEl.TryGetProperty("ruleId", out var r) ? r.GetString() ?? "" : "",
                            DetectionName = fEl.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "",
                            TechnicalExplanation = fEl.TryGetProperty("explanation", out var e) ? e.GetString() ?? "" : "",
                            FilePath = fEl.TryGetProperty("filePath", out var fp) ? fp.GetString() : null,
                            FileSha256 = fEl.TryGetProperty("fileSha256", out var sha) ? sha.GetString() : null,
                            Classification = FindingClassification.Suspicious
                        };

                        if (fEl.TryGetProperty("severity", out var sevStr))
                        {
                            Enum.TryParse<Severity>(sevStr.GetString(), true, out var sev);
                            finding.Severity = sev;
                        }

                        report.Findings.Add(finding);
                    }
                }

                report.RecomputeSummaryCounts();
                report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);
                return (true, report, "Migrated legacy v1.0 report format successfully.");
            }

            // Backward compatibility: Support direct v1.0 root payload (SubmitReportRequest)
            if (root.TryGetProperty("scanMode", out var smDirect) || root.TryGetProperty("detectedMinecraftVersions", out _))
            {
                var report = new StandaloneReport
                {
                    SchemaVersion = "2.0.0",
                    ReportId = root.TryGetProperty("reportId", out var idDirect)
                        ? idDirect.GetString() ?? "rep_v1_legacy"
                        : "rep_v1_legacy",
                    ScanMode = smDirect.ValueKind == JsonValueKind.String ? smDirect.GetString() ?? "QUICK" : "QUICK"
                };

                if (root.TryGetProperty("osName", out var osN)) report.TargetSystem.OsName = osN.GetString() ?? "Windows";
                if (root.TryGetProperty("osVersion", out var osV)) report.TargetSystem.OsVersion = osV.GetString() ?? "";

                // Migrate findings
                if (root.TryGetProperty("findings", out var findingsArr) && findingsArr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var fEl in findingsArr.EnumerateArray())
                    {
                        var finding = new FindingRecord
                        {
                            RuleId = fEl.TryGetProperty("ruleId", out var r) ? r.GetString() ?? "" : "",
                            DetectionName = fEl.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "",
                            TechnicalExplanation = fEl.TryGetProperty("explanation", out var e) ? e.GetString() ?? "" : "",
                            FilePath = fEl.TryGetProperty("filePath", out var fp) ? fp.GetString() : null,
                            FileSha256 = fEl.TryGetProperty("fileSha256", out var sha) ? sha.GetString() : null,
                            Classification = FindingClassification.Suspicious
                        };

                        if (fEl.TryGetProperty("severity", out var sevStr))
                        {
                            Enum.TryParse<Severity>(sevStr.GetString(), true, out var sev);
                            finding.Severity = sev;
                        }

                        report.Findings.Add(finding);
                    }
                }

                report.RecomputeSummaryCounts();
                report.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(report);
                return (true, report, "Migrated direct legacy v1.0 report payload successfully.");
            }

            return (false, null, "Unrecognized report format or incompatible schema version.");
        }
        catch (JsonException ex)
        {
            return (false, null, $"Malformed JSON payload: {ex.Message}");
        }
        catch (Exception ex)
        {
            return (false, null, $"Report loading failed: {ex.Message}");
        }
    }
}

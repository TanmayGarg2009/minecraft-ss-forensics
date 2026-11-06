using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Cryptographic trust classification for loaded untrusted reports.
/// Distinguishes canonical SHA-256 integrity verification from missing seals,
/// corrupted/tampered payloads, and resource boundary violations.
/// </summary>
public enum ReportLoadTrustState
{
    VerifiedCanonicalV2,
    UnsealedHistorical,
    MigratedHistoricalUnverified,
    TamperedDigestMismatch,
    ResourceLimitExceeded,
    MalformedJson,
    UnsupportedSchemaVersion
}

/// <summary>
/// Unambiguous result contract for loading untrusted report payloads.
/// </summary>
public record ReportLoadResult(
    bool Success,
    StandaloneReport? Report,
    ReportLoadTrustState TrustState,
    string StatusMessage)
{
    public string ErrorMessage => StatusMessage;

    public void Deconstruct(out bool success, out StandaloneReport? report, out string statusMessage)
    {
        success = Success;
        report = Report;
        statusMessage = StatusMessage;
    }
}

/// <summary>
/// Serializes and deserializes standalone forensic reports with backward-compatibility
/// for legacy schema formats, strict resource limits, and untrusted input defenses.
/// </summary>
public static class PortableJsonExporter
{
    public const long MaxReportFileSizeBytes = 50 * 1024 * 1024; // 50 MB
    public const int MaxJsonDepth = 32;
    public const int MaxCollectionItemLimit = 25000;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        MaxDepth = MaxJsonDepth
    };

    public static string ExportToJson(StandaloneReport report)
    {
        // 1. Create deep-cloned sanitized derivative for export (non-mutating)
        var sanitizedReport = PrivacyBoundary.CreateSanitizedCopy(report);

        // 2. Compute and seal deterministic canonical integrity digest (SHA256-CANONICAL-V2)
        sanitizedReport.RecomputeSummaryCounts();
        sanitizedReport.ReportIntegrityHash = ReportIntegrityValidator.ComputeReportSeal(sanitizedReport);

        return JsonSerializer.Serialize(sanitizedReport, JsonOpts);
    }

    public static void SaveToFile(StandaloneReport report, string filePath)
    {
        string json = ExportToJson(report);
        File.WriteAllText(filePath, json, System.Text.Encoding.UTF8);
    }

    public static ReportLoadResult LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, $"Report file not found: {filePath}");
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxReportFileSizeBytes)
            {
                return new ReportLoadResult(false, null, ReportLoadTrustState.ResourceLimitExceeded, $"Report file exceeds maximum permitted resource limit ({MaxReportFileSizeBytes / (1024 * 1024)} MB). File size: {fileInfo.Length / (1024 * 1024)} MB.");
            }

            string json = File.ReadAllText(filePath, System.Text.Encoding.UTF8);
            return LoadFromJson(json);
        }
        catch (Exception ex)
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, $"Error reading report file: {ex.Message}");
        }
    }

    public static ReportLoadResult LoadFromJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, "Report content is empty.");
        }

        if (json.Length > MaxReportFileSizeBytes)
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.ResourceLimitExceeded, $"Report payload exceeds maximum permitted resource limit ({MaxReportFileSizeBytes / (1024 * 1024)} MB).");
        }

        try
        {
            var docOpts = new JsonDocumentOptions
            {
                MaxDepth = MaxJsonDepth,
                AllowTrailingCommas = true
            };

            using var doc = JsonDocument.Parse(json, docOpts);
            var root = doc.RootElement;

            // Check if this is v2.0 StandaloneReport (supports both camelCase and PascalCase)
            bool isV2Standalone = (root.TryGetProperty("reportId", out _) || root.TryGetProperty("ReportId", out _)) &&
                                  (root.TryGetProperty("schemaVersion", out _) || root.TryGetProperty("SchemaVersion", out _));

            if (isV2Standalone)
            {
                var report = JsonSerializer.Deserialize<StandaloneReport>(json, JsonOpts);
                if (report == null)
                    return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, "Failed to deserialize standalone report structure.");

                if (report.Findings.Count > MaxCollectionItemLimit)
                {
                    return new ReportLoadResult(false, null, ReportLoadTrustState.ResourceLimitExceeded, $"Report collection size ({report.Findings.Count} findings) exceeds maximum safe resource limit ({MaxCollectionItemLimit}).");
                }

                report.RecomputeSummaryCounts();

                // Validate graph structure if graph data is present
                if (report.EvidenceGraph != null && report.EvidenceGraph.IsCaptured)
                {
                    report.EvidenceGraph.Validate(out _);
                }

                // Verify integrity seal if present
                if (!string.IsNullOrEmpty(report.ReportIntegrityHash))
                {
                    var integrity = ReportIntegrityValidator.VerifyReportIntegrityDetailed(report);
                    if (!integrity.IsValid)
                    {
                        report.DiagnosticChecks.Add(new DiagnosticCheckItem
                        {
                            CheckId = "CHK-INTEGRITY-FAILED",
                            CheckName = "Report Integrity Verification",
                            Source = "ReportIntegrityValidator",
                            Status = CheckStatus.FLAGGED,
                            Reason = integrity.StatusMessage
                        });

                        return new ReportLoadResult(true, report, ReportLoadTrustState.TamperedDigestMismatch, integrity.StatusMessage);
                    }

                    return new ReportLoadResult(true, report, ReportLoadTrustState.VerifiedCanonicalV2, "Content integrity verified by SHA-256 canonical digest.");
                }

                return new ReportLoadResult(true, report, ReportLoadTrustState.UnsealedHistorical, "Loaded report is valid but lacks cryptographic integrity seal.");
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
                report.ReportIntegrityHash = string.Empty;
                return new ReportLoadResult(true, report, ReportLoadTrustState.MigratedHistoricalUnverified, "Migrated legacy v1.0 report format; historical unsealed report remained unsealed.");
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
                report.ReportIntegrityHash = string.Empty;
                return new ReportLoadResult(true, report, ReportLoadTrustState.MigratedHistoricalUnverified, "Migrated direct legacy v1.0 report payload; historical unsealed report remained unsealed.");
            }

            return new ReportLoadResult(false, null, ReportLoadTrustState.UnsupportedSchemaVersion, "Unrecognized report format or incompatible schema version.");
        }
        catch (JsonException ex)
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, $"Malformed JSON payload: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ReportLoadResult(false, null, ReportLoadTrustState.MalformedJson, $"Report loading failed: {ex.Message}");
        }
    }
}

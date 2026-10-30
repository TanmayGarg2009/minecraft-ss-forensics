using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Integrity;

/// <summary>
/// Computes and verifies cryptographic SHA-256 integrity seals for standalone forensic reports.
/// Establishes whether a report file has been modified after generation.
/// (Notice: Cryptographic seals establish file integrity since generation, but do not prevent offline forgery if the signing key is public).
/// </summary>
public static class ReportIntegrityValidator
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Computes the SHA-256 digest of the report payload (excluding the integrity hash property itself).
    /// </summary>
    public static string ComputeReportSeal(StandaloneReport report)
    {
        string currentHash = report.ReportIntegrityHash;
        report.ReportIntegrityHash = string.Empty;

        try
        {
            // Serialize normalized representation for deterministic hashing
            string normalized = JsonSerializer.Serialize(new
            {
                report.ReportId,
                report.SchemaVersion,
                report.ScannerVersion,
                report.CreatedAt,
                report.ScanStartedAt,
                report.ScanCompletedAt,
                report.ScanMode,
                findingsCount = report.Findings.Count,
                evidenceCount = report.EvidenceItems.Count,
                modsCount = report.ModInventory.Count,
                diagnosticsCount = report.DiagnosticChecks.Count,
                report.SummaryCounts
            }, JsonOpts);

            byte[] bytes = Encoding.UTF8.GetBytes(normalized);
            byte[] hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            report.ReportIntegrityHash = currentHash;
        }
    }

    /// <summary>
    /// Validates whether a loaded report matches its embedded cryptographic integrity seal.
    /// </summary>
    public static (bool IsValid, string StatusMessage) VerifyReportIntegrity(StandaloneReport report)
    {
        if (string.IsNullOrWhiteSpace(report.ReportIntegrityHash))
        {
            return (false, "Report lacks an embedded SHA-256 cryptographic integrity seal (Unsealed or legacy format).");
        }

        string expected = ComputeReportSeal(report);
        if (string.Equals(report.ReportIntegrityHash, expected, StringComparison.OrdinalIgnoreCase))
        {
            return (true, "Cryptographic integrity verified: Report data has not been modified since initial generation.");
        }

        return (false, $"Integrity mismatch! Expected SHA-256 digest '{expected}', but report file contains '{report.ReportIntegrityHash}'. Data may have been tampered with or modified.");
    }
}

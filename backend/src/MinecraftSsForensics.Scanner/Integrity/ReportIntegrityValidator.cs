using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Integrity;

/// <summary>
/// Result of report integrity verification distinguishing content integrity from authenticity and provenance.
/// </summary>
public class ReportIntegrityResult
{
    public bool IsValid { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public string IntegrityAlgorithm { get; set; } = "SHA256-CANONICAL-V2";
    public string ExpectedDigest { get; set; } = string.Empty;
    public string EmbeddedDigest { get; set; } = string.Empty;
    public bool IsTampered => !IsValid && !string.IsNullOrEmpty(EmbeddedDigest);
    public string EvidenceIntegrityScope { get; set; } = "Full Payload: Covers all evidence collections, findings, classifications, timestamps, mods, and policy decisions.";
    public string ProvenanceNotice { get; set; } = "Cryptographic hash integrity confirms that report contents match the recorded digest. It does not authenticate the author's identity without an asymmetric digital signature.";
}

/// <summary>
/// Computes and verifies deterministic SHA-256 canonical integrity digests for standalone forensic reports.
/// Covers the complete evidence payload, preventing undetected tampering with findings, mods, or telemetry.
/// </summary>
public static class ReportIntegrityValidator
{
    public const string CurrentAlgorithm = "SHA256-CANONICAL-V2";

    private static readonly JsonSerializerOptions BaseJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    /// <summary>
    /// Computes the deterministic SHA-256 canonical digest over the entire report payload.
    /// Excludes the ReportIntegrityHash property itself.
    /// </summary>
    public static string ComputeReportSeal(StandaloneReport report)
    {
        string currentHash = report.ReportIntegrityHash;
        report.ReportIntegrityHash = string.Empty;

        try
        {
            byte[] rawJsonBytes = JsonSerializer.SerializeToUtf8Bytes(report, BaseJsonOptions);
            using var doc = JsonDocument.Parse(rawJsonBytes);

            using var ms = new MemoryStream();
            using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            }))
            {
                WriteCanonicalElement(doc.RootElement, writer, isRoot: true);
            }

            byte[] canonicalBytes = ms.ToArray();
            byte[] hash = SHA256.HashData(canonicalBytes);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            report.ReportIntegrityHash = currentHash;
        }
    }

    /// <summary>
    /// Validates whether a loaded report matches its embedded cryptographic integrity seal.
    /// Rejects altered, truncated, or tampered report files.
    /// </summary>
    public static (bool IsValid, string StatusMessage) VerifyReportIntegrity(StandaloneReport report)
    {
        var result = VerifyReportIntegrityDetailed(report);
        return (result.IsValid, result.StatusMessage);
    }

    /// <summary>
    /// Detailed verification returning complete cryptographic integrity and provenance telemetry.
    /// </summary>
    public static ReportIntegrityResult VerifyReportIntegrityDetailed(StandaloneReport report)
    {
        if (report == null)
        {
            return new ReportIntegrityResult
            {
                IsValid = false,
                StatusMessage = "Report object is null."
            };
        }

        if (string.IsNullOrWhiteSpace(report.ReportIntegrityHash))
        {
            return new ReportIntegrityResult
            {
                IsValid = false,
                StatusMessage = "Report lacks an embedded SHA-256 integrity seal (Unsealed or legacy format). Cannot guarantee data integrity."
            };
        }

        string expected = ComputeReportSeal(report);
        string embedded = report.ReportIntegrityHash.Trim().ToLowerInvariant();

        bool isValid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(embedded),
            Encoding.UTF8.GetBytes(expected)
        );

        if (isValid)
        {
            return new ReportIntegrityResult
            {
                IsValid = true,
                StatusMessage = "Cryptographic integrity verified: All evidence payloads, findings, mods, and telemetry match the recorded canonical SHA-256 digest.",
                ExpectedDigest = expected,
                EmbeddedDigest = embedded
            };
        }

        return new ReportIntegrityResult
        {
            IsValid = false,
            StatusMessage = $"Integrity mismatch! Expected canonical digest '{expected}', but report file contains '{embedded}'. Data has been modified, corrupted, or tampered with since generation.",
            ExpectedDigest = expected,
            EmbeddedDigest = embedded
        };
    }

    private static void WriteCanonicalElement(JsonElement element, Utf8JsonWriter writer, bool isRoot = false)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                // Recursively sort properties by name (Ordinal) for deterministic canonicalization
                var properties = new System.Collections.Generic.List<JsonProperty>();
                foreach (var prop in element.EnumerateObject())
                {
                    // Exclude reportIntegrityHash at root level
                    if (isRoot && string.Equals(prop.Name, "reportIntegrityHash", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    properties.Add(prop);
                }

                properties.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

                foreach (var prop in properties)
                {
                    writer.WritePropertyName(prop.Name);
                    WriteCanonicalElement(prop.Value, writer, isRoot: false);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonicalElement(item, writer, isRoot: false);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                if (element.TryGetInt64(out long l))
                {
                    writer.WriteNumberValue(l);
                }
                else if (element.TryGetDouble(out double d))
                {
                    writer.WriteNumberValue(d);
                }
                else
                {
                    writer.WriteRawValue(element.GetRawText());
                }
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
        }
    }
}

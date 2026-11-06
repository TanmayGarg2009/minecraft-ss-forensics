using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace MinecraftSsForensics.Scanner.Observations;

/// <summary>
/// Immutable, typed representation of a raw forensic observation.
/// Never mutates original evidence; derived findings maintain explicit foreign-key lineage back to ObservationId.
/// </summary>
public record RawObservation : IObservation
{
    public string ObservationId { get; init; } = Guid.NewGuid().ToString("N");
    public required string ObservationType { get; init; }
    public required string SourceCollector { get; init; }
    public DateTimeOffset CollectionTimestampUtc { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? EventTimestampUtc { get; init; }
    public required string SourceIdentity { get; init; }
    public required string Provenance { get; init; }
    public CollectionStatus AvailabilityState { get; init; } = CollectionStatus.Success;
    public string ReliabilityLimitations { get; init; } = string.Empty;
    public string? TargetEntityId { get; init; }
    public IReadOnlyDictionary<string, string> Properties { get; init; } = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());
    public object? RawPayload { get; init; }

    public static RawObservation CreateFileObservation(
        string collectorName,
        string filePath,
        long sizeBytes,
        string sha256,
        DateTimeOffset? modifiedUtc,
        string provenance = "FileSystemDiscovery")
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FilePath"] = filePath,
            ["SizeBytes"] = sizeBytes.ToString(),
            ["Sha256"] = sha256
        };

        if (modifiedUtc.HasValue)
        {
            dict["ModifiedUtc"] = modifiedUtc.Value.ToString("O");
        }

        return new RawObservation
        {
            ObservationType = "FileObservation",
            SourceCollector = collectorName,
            EventTimestampUtc = modifiedUtc,
            SourceIdentity = "NTFS_MFT",
            Provenance = provenance,
            TargetEntityId = $"file:{filePath.ToLowerInvariant()}:{sizeBytes}:{sha256.ToLowerInvariant()}",
            Properties = new ReadOnlyDictionary<string, string>(dict)
        };
    }

    public static RawObservation CreateProcessObservation(
        string collectorName,
        int pid,
        string processName,
        string executablePath,
        DateTimeOffset? startTimeUtc,
        string? commandLine,
        string? imageSha256)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["PID"] = pid.ToString(),
            ["ProcessName"] = processName,
            ["ExecutablePath"] = executablePath
        };

        if (!string.IsNullOrEmpty(commandLine))
        {
            dict["CommandLine"] = commandLine;
        }

        if (!string.IsNullOrEmpty(imageSha256))
        {
            dict["ImageSha256"] = imageSha256;
        }

        string hostId = Environment.MachineName.ToLowerInvariant();
        long startTicks = startTimeUtc?.UtcTicks ?? 0L;
        string hashPart = !string.IsNullOrEmpty(imageSha256) ? imageSha256.ToLowerInvariant() : "unknown_hash";
        string targetId = $"proc:{hostId}:{pid}:{startTicks}:{hashPart}";

        return new RawObservation
        {
            ObservationType = "ProcessObservation",
            SourceCollector = collectorName,
            EventTimestampUtc = startTimeUtc,
            SourceIdentity = "Win32_Process",
            Provenance = "ProcessScanner_Snapshot",
            TargetEntityId = targetId,
            Properties = new ReadOnlyDictionary<string, string>(dict)
        };
    }

    public static RawObservation CreateHistoricalObservation(
        string collectorName,
        string sourceArtifactType,
        string executableName,
        DateTimeOffset? eventTimeUtc,
        string provenance,
        int runCount = 1)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SourceArtifactType"] = sourceArtifactType,
            ["ExecutableName"] = executableName,
            ["RunCount"] = runCount.ToString()
        };

        if (eventTimeUtc.HasValue)
        {
            dict["EventTimestampUtc"] = eventTimeUtc.Value.ToString("O");
        }

        string timePart = eventTimeUtc.HasValue ? eventTimeUtc.Value.UtcTicks.ToString() : "unknown";
        string targetId = $"hist:{sourceArtifactType.ToLowerInvariant()}:{timePart}:{executableName.ToLowerInvariant()}";

        return new RawObservation
        {
            ObservationType = "HistoricalObservation",
            SourceCollector = collectorName,
            EventTimestampUtc = eventTimeUtc,
            SourceIdentity = sourceArtifactType,
            Provenance = provenance,
            ReliabilityLimitations = eventTimeUtc.HasValue ? string.Empty : "Original execution timestamp unavailable from forensic source.",
            TargetEntityId = targetId,
            Properties = new ReadOnlyDictionary<string, string>(dict)
        };
    }
}

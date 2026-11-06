using System;
using System.Security.Cryptography;
using System.Text;

namespace MinecraftSsForensics.Scanner.Identities;

/// <summary>
/// Stable composite identity for an operating system process instance.
/// Immune to Windows PID recycling by binding HostId, PID, Process Start Time ticks, and Executable Binary SHA-256.
/// Format: proc:{HostId}:{PID}:{StartTimeTicks}:{ImageSha256}
/// </summary>
public readonly record struct ProcessInstanceId
{
    public string HostId { get; }
    public int ProcessId { get; }
    public long StartTimeTicks { get; }
    public string ImageSha256 { get; }

    public bool IsProvisional => StartTimeTicks == 0 || string.IsNullOrEmpty(ImageSha256) || ImageSha256 == "unknown";

    public ProcessInstanceId(string hostId, int processId, long startTimeTicks, string? imageSha256)
    {
        HostId = string.IsNullOrWhiteSpace(hostId) ? "local" : hostId.Trim().ToLowerInvariant();
        ProcessId = processId;
        StartTimeTicks = startTimeTicks;
        ImageSha256 = string.IsNullOrWhiteSpace(imageSha256) ? "unknown" : imageSha256.Trim().ToLowerInvariant();
    }

    public static ProcessInstanceId Create(string hostId, int processId, DateTimeOffset? startTimeUtc, string? imageSha256)
    {
        return new ProcessInstanceId(hostId, processId, startTimeUtc?.UtcTicks ?? 0L, imageSha256);
    }

    public static ProcessInstanceId Parse(string compositeId)
    {
        if (string.IsNullOrWhiteSpace(compositeId))
            throw new ArgumentException("Composite ID cannot be null or empty", nameof(compositeId));

        var parts = compositeId.Split(':');
        if (parts.Length < 5 || parts[0] != "proc")
            throw new FormatException($"Invalid ProcessInstanceId format: '{compositeId}'. Expected 'proc:{{HostId}}:{{PID}}:{{StartTimeTicks}}:{{ImageSha256}}'");

        string hostId = parts[1];
        if (!int.TryParse(parts[2], out int pid))
            throw new FormatException($"Invalid PID in ProcessInstanceId: '{parts[2]}'");

        if (!long.TryParse(parts[3], out long ticks))
            throw new FormatException($"Invalid StartTimeTicks in ProcessInstanceId: '{parts[3]}'");

        string sha256 = parts[4];
        return new ProcessInstanceId(hostId, pid, ticks, sha256);
    }

    public static bool TryParse(string compositeId, out ProcessInstanceId result)
    {
        try
        {
            result = Parse(compositeId);
            return true;
        }
        catch
        {
            result = default;
            return false;
        }
    }

    public override string ToString() => $"proc:{HostId}:{ProcessId}:{StartTimeTicks}:{ImageSha256}";
}

/// <summary>
/// Stable composite identity for a loaded module within a target process virtual address space.
/// Format: mod:{ProcessInstanceId}:{BaseAddressHex}:{Size}:{ModuleSha256}
/// </summary>
public readonly record struct ModuleInstanceId
{
    public string ProcessInstanceId { get; }
    public string BaseAddressHex { get; }
    public long ModuleSizeBytes { get; }
    public string ModuleSha256 { get; }

    public bool IsProvisional => string.IsNullOrEmpty(ModuleSha256) || ModuleSha256 == "unknown" || BaseAddressHex == "0x0" || string.IsNullOrEmpty(ProcessInstanceId);

    public ModuleInstanceId(string processInstanceId, string baseAddressHex, long moduleSizeBytes, string? moduleSha256)
    {
        ProcessInstanceId = processInstanceId;
        BaseAddressHex = string.IsNullOrWhiteSpace(baseAddressHex) ? "0x0" : baseAddressHex.Trim().ToLowerInvariant();
        ModuleSizeBytes = moduleSizeBytes;
        ModuleSha256 = string.IsNullOrWhiteSpace(moduleSha256) ? "unknown" : moduleSha256.Trim().ToLowerInvariant();
    }

    public override string ToString() => $"mod:{ProcessInstanceId}:{BaseAddressHex}:{ModuleSizeBytes}:{ModuleSha256}";
}

/// <summary>
/// Stable composite identity for a file instance on storage.
/// Format: file:{NormalizedPath}:{SizeBytes}:{Sha256}
/// </summary>
public readonly record struct FileInstanceId
{
    public string NormalizedPath { get; }
    public long SizeBytes { get; }
    public string Sha256 { get; }

    public bool IsProvisional => string.IsNullOrEmpty(Sha256) || Sha256 == "unknown" || string.IsNullOrEmpty(NormalizedPath);

    public FileInstanceId(string path, long sizeBytes, string? sha256)
    {
        NormalizedPath = (path ?? string.Empty).Trim().Replace('\\', '/').ToLowerInvariant();
        SizeBytes = sizeBytes;
        Sha256 = string.IsNullOrWhiteSpace(sha256) ? "unknown" : sha256.Trim().ToLowerInvariant();
    }

    public override string ToString() => $"file:{NormalizedPath}:{SizeBytes}:{Sha256}";
}

/// <summary>
/// Stable composite identity for a Minecraft gameplay session.
/// Format: session:{ProcessInstanceId}:{SessionStartTimeUtcTicks}
/// </summary>
public readonly record struct MinecraftSessionId
{
    public string ProcessInstanceId { get; }
    public long SessionStartTimeTicks { get; }

    public MinecraftSessionId(string processInstanceId, DateTimeOffset sessionStartTimeUtc)
    {
        ProcessInstanceId = processInstanceId;
        SessionStartTimeTicks = sessionStartTimeUtc.UtcTicks;
    }

    public override string ToString() => $"session:{ProcessInstanceId}:{SessionStartTimeTicks}";
}

/// <summary>
/// Stable composite identity for a historical execution record.
/// Format: hist:{SourceType}:{EventTimestampTicks}:{ExecutableName}
/// </summary>
public readonly record struct HistoricalRecordId
{
    public string SourceType { get; }
    public long EventTimestampTicks { get; }
    public string ExecutableName { get; }

    public HistoricalRecordId(string sourceType, DateTimeOffset eventTimestampUtc, string executableName)
    {
        SourceType = (sourceType ?? "unknown").Trim().ToLowerInvariant();
        EventTimestampUtcTicks = eventTimestampUtc.UtcTicks;
        ExecutableName = (executableName ?? "unknown").Trim().ToLowerInvariant();
    }

    public long EventTimestampUtcTicks { get; }

    public override string ToString() => $"hist:{SourceType}:{EventTimestampUtcTicks}:{ExecutableName}";
}

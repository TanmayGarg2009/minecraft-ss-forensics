using System.Text.RegularExpressions;

namespace MinecraftSsForensics.Scanner.LogsAndHistory;

public class LogAuditResult
{
    public string? DetectedMinecraftVersion { get; set; }
    public string? DetectedLoader { get; set; }
    public List<string> LoadedModsFromLogs { get; set; } = new();
    public List<string> SuspiciousLogEntries { get; set; } = new();
    public List<string> SessionTimestamps { get; set; } = new();
    public string? LastSessionStartTime { get; set; }
    public string RawLogSummary { get; set; } = string.Empty;
}

public class LogAuditor
{
    private static readonly Regex FabricHeaderRegex = new(
        @"Loading Minecraft ([\d\.]+) with Fabric Loader ([\d\.]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ForgeHeaderRegex = new(
        @"MinecraftForge v([\d\.]+) Initialized",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex NeoForgeHeaderRegex = new(
        @"NeoForge ([\d\.]+) initialized",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex QuiltHeaderRegex = new(
        @"Loading Minecraft ([\d\.]+) with Quilt Loader ([\d\.]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ModLineRegex = new(
        @"Loading \d+ mods:\s*\n((?:\s*-\s*[^@\n]+@[^\n]+\n)+)",
        RegexOptions.Compiled);

    public async Task<LogAuditResult> AuditLogFileAsync(string logFilePath, CancellationToken ct = default)
    {
        var result = new LogAuditResult();

        if (!File.Exists(logFilePath))
        {
            return result;
        }

        try
        {
            using var stream = new FileStream(logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);

            string content = await reader.ReadToEndAsync(ct);
            result.RawLogSummary = content.Length > 2000 ? content[..2000] + "\n...[truncated]" : content;

            // 1. Detect Loader & Minecraft Version
            var fabricMatch = FabricHeaderRegex.Match(content);
            if (fabricMatch.Success)
            {
                result.DetectedMinecraftVersion = fabricMatch.Groups[1].Value;
                result.DetectedLoader = $"Fabric {fabricMatch.Groups[2].Value}";
            }

            var quiltMatch = QuiltHeaderRegex.Match(content);
            if (quiltMatch.Success)
            {
                result.DetectedMinecraftVersion = quiltMatch.Groups[1].Value;
                result.DetectedLoader = $"Quilt {quiltMatch.Groups[2].Value}";
            }

            var neoForgeMatch = NeoForgeHeaderRegex.Match(content);
            if (neoForgeMatch.Success)
            {
                result.DetectedLoader = $"NeoForge {neoForgeMatch.Groups[1].Value}";
            }

            var forgeMatch = ForgeHeaderRegex.Match(content);
            if (forgeMatch.Success)
            {
                result.DetectedLoader = $"Forge {forgeMatch.Groups[1].Value}";
            }

            // 2. Scan lines for suspicious tokens
            using var lineReader = new StringReader(content);
            string? line;
            while ((line = await lineReader.ReadLineAsync(ct)) != null)
            {
                // Check timestamps [HH:mm:ss]
                if (line.StartsWith('[') && line.Length >= 10 && line[9] == ']')
                {
                    result.SessionTimestamps.Add(line[1..9]);
                    if (string.IsNullOrEmpty(result.LastSessionStartTime))
                    {
                        result.LastSessionStartTime = line[1..9];
                    }
                }

                // Look for suspicious activity logs
                string lower = line.ToLowerInvariant();
                if (lower.Contains("premain") || lower.Contains("agent-class") ||
                    lower.Contains("injecting foreign") || lower.Contains("disabling anticheat") ||
                    lower.Contains("baritone control") || lower.Contains("k32hook") ||
                    lower.Contains("packet cancellation exception"))
                {
                    result.SuspiciousLogEntries.Add(line.Trim());
                }
            }
        }
        catch (Exception ex)
        {
            result.SuspiciousLogEntries.Add($"Log file audit encountered error: {ex.Message}");
        }

        return result;
    }
}

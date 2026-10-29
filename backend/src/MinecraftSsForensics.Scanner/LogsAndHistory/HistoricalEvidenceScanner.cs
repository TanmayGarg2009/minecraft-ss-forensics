using Microsoft.Win32;

namespace MinecraftSsForensics.Scanner.LogsAndHistory;

public class HistoricalArtifactRecord
{
    public string Source { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime? Timestamp { get; set; }
    public bool IsDeletedIndicator { get; set; }
    public bool HasAccessDenied { get; set; }
    public string? LimitationNote { get; set; }
}

public class HistoricalEvidenceScanner
{
    public List<HistoricalArtifactRecord> ScanHistoricalArtifacts()
    {
        var records = new List<HistoricalArtifactRecord>();

        // 1. Inspect Windows Temp for orphaned Minecraft JARs or cheat binaries
        string tempDir = Path.GetTempPath();
        try
        {
            if (Directory.Exists(tempDir))
            {
                var files = Directory.GetFiles(tempDir, "*.jar", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    var fi = new FileInfo(file);
                    records.Add(new HistoricalArtifactRecord
                    {
                        Source = "WindowsTemp",
                        Path = file,
                        Description = $"JAR file located in user Temp directory: {Path.GetFileName(file)} ({fi.Length} bytes)",
                        Timestamp = fi.LastWriteTimeUtc,
                        IsDeletedIndicator = false
                    });
                }
            }
        }
        catch (Exception ex)
        {
            records.Add(new HistoricalArtifactRecord
            {
                Source = "WindowsTemp",
                HasAccessDenied = true,
                LimitationNote = $"User temp directory access was restricted: {ex.Message}"
            });
        }

        // 2. Windows Prefetch Inspection (Read-Only)
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            if (Directory.Exists(prefetchDir))
            {
                // Look for javaw.exe or known cheat binary prefetch files
                var pfFiles = Directory.GetFiles(prefetchDir, "*JAVA*.pf", SearchOption.TopDirectoryOnly);
                foreach (var pf in pfFiles)
                {
                    var fi = new FileInfo(pf);
                    records.Add(new HistoricalArtifactRecord
                    {
                        Source = "Prefetch",
                        Path = pf,
                        Description = $"Windows Prefetch execution record: {Path.GetFileName(pf)}",
                        Timestamp = fi.LastWriteTimeUtc,
                        IsDeletedIndicator = false
                    });
                }
            }
            else
            {
                records.Add(new HistoricalArtifactRecord
                {
                    Source = "Prefetch",
                    HasAccessDenied = false,
                    LimitationNote = "Prefetch directory does not exist on this operating system edition or was disabled."
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            records.Add(new HistoricalArtifactRecord
            {
                Source = "Prefetch",
                HasAccessDenied = true,
                LimitationNote = "Windows Prefetch directory (C:\\Windows\\Prefetch) access was denied in standard user mode. Non-elevated scan cannot audit historical prefetch records."
            });
        }
        catch (Exception ex)
        {
            records.Add(new HistoricalArtifactRecord
            {
                Source = "Prefetch",
                HasAccessDenied = true,
                LimitationNote = $"Prefetch collection error: {ex.Message}"
            });
        }

        // 3. Background Activity Moderator (BAM) Registry Check (Read-Only)
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var bamKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");
                if (bamKey != null)
                {
                    // If accessible, check subkeys
                    var subkeys = bamKey.GetSubKeyNames();
                    records.Add(new HistoricalArtifactRecord
                    {
                        Source = "BamDam",
                        Description = $"BAM UserSettings registry root accessed successfully ({subkeys.Length} user profiles found).",
                        HasAccessDenied = false
                    });
                }
                else
                {
                    records.Add(new HistoricalArtifactRecord
                    {
                        Source = "BamDam",
                        HasAccessDenied = true,
                        LimitationNote = "BAM registry hive key returned null or is protected by Windows ACLs."
                    });
                }
            }
            catch (Exception ex)
            {
                records.Add(new HistoricalArtifactRecord
                {
                    Source = "BamDam",
                    HasAccessDenied = true,
                    LimitationNote = $"BAM registry access restricted in user mode: {ex.Message}"
                });
            }
        }

        return records;
    }
}

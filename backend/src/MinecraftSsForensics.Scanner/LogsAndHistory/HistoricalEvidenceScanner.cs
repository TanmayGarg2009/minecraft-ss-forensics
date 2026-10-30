using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Cheats;

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

        // 2. Windows Prefetch Inspection & Tampering Check
        if (OperatingSystem.IsWindows())
        {
            CheckPrefetchConfiguration(records);
            ScanPrefetchDirectory(records);
            ScanBamRegistry(records);
            ScanPowerShellHistory(records);
        }

        return records;
    }

    private void CheckPrefetchConfiguration(List<HistoricalArtifactRecord> records)
    {
        try
        {
            using var pfKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (pfKey != null)
            {
                var val = pfKey.GetValue("EnablePrefetcher");
                if (val is int intVal && intVal == 0)
                {
                    records.Add(new HistoricalArtifactRecord
                    {
                        Source = "PrefetchConfig",
                        Path = @"HKLM\...\PrefetchParameters\EnablePrefetcher",
                        Description = "Windows Prefetcher is explicitly DISABLED (EnablePrefetcher = 0). Potential anti-screenshare evasion or system optimizer tweak.",
                        IsDeletedIndicator = true
                    });
                }
            }
        }
        catch { /* Non-fatal access restriction */ }
    }

    private void ScanPrefetchDirectory(List<HistoricalArtifactRecord> records)
    {
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            if (Directory.Exists(prefetchDir))
            {
                var dirInfo = new DirectoryInfo(prefetchDir);
                var pfFiles = dirInfo.GetFiles("*.pf", SearchOption.TopDirectoryOnly);

                foreach (var pf in pfFiles)
                {
                    string nameUpper = pf.Name.ToUpperInvariant();
                    bool isJava = nameUpper.Contains("JAVA");

                    // Check if prefetch file matches any known cheat signature
                    var cheatMatch = CheatDetectionDatabase.Signatures.FirstOrDefault(s =>
                        s.KnownFileNames.Any(k => nameUpper.StartsWith(Path.GetFileNameWithoutExtension(k).ToUpperInvariant())));

                    if (isJava || cheatMatch != null)
                    {
                        records.Add(new HistoricalArtifactRecord
                        {
                            Source = "Prefetch",
                            Path = pf.FullName,
                            Description = cheatMatch != null
                                ? $"Windows Prefetch execution record matching known cheat: {cheatMatch.Name} ({pf.Name})"
                                : $"Windows Prefetch execution record: {pf.Name}",
                            Timestamp = pf.LastWriteTimeUtc,
                            IsDeletedIndicator = false
                        });
                    }
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
    }

    private void ScanBamRegistry(List<HistoricalArtifactRecord> records)
    {
        try
        {
            // Inspect BAM (Background Activity Moderator) and DAM (Desktop Activity Moderator)
            string[] moderatorKeys = { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" };

            foreach (var rootPath in moderatorKeys)
            {
                using var rootKey = Registry.LocalMachine.OpenSubKey(rootPath);
                if (rootKey == null) continue;

                foreach (string sid in rootKey.GetSubKeyNames())
                {
                    try
                    {
                        using var sidKey = rootKey.OpenSubKey(sid);
                        if (sidKey == null) continue;

                        foreach (string valName in sidKey.GetValueNames())
                        {
                            if (string.IsNullOrWhiteSpace(valName)) continue;

                            // BAM stores executable path as value name and 8-byte FILETIME as value data
                            DateTime? executionTime = null;
                            if (sidKey.GetValue(valName) is byte[] bytes && bytes.Length >= 8)
                            {
                                try
                                {
                                    long fileTime = BitConverter.ToInt64(bytes, 0);
                                    if (fileTime > 0)
                                    {
                                        executionTime = DateTime.FromFileTimeUtc(fileTime);
                                    }
                                }
                                catch { }
                            }

                            string upperName = valName.ToUpperInvariant();
                            var cheatMatch = CheatDetectionDatabase.Signatures.FirstOrDefault(s =>
                                s.KnownFileNames.Any(k => upperName.Contains(Path.GetFileNameWithoutExtension(k).ToUpperInvariant())));

                            if (cheatMatch != null || upperName.Contains("JAVA") || upperName.Contains("MINECRAFT") || upperName.Contains(@"\TEMP\"))
                            {
                                records.Add(new HistoricalArtifactRecord
                                {
                                    Source = rootPath.Contains("bam") ? "WindowsBAM" : "WindowsDAM",
                                    Path = valName,
                                    Description = cheatMatch != null
                                        ? $"BAM execution record matching known cheat '{cheatMatch.Name}': {valName}"
                                        : $"BAM execution record: {Path.GetFileName(valName)}",
                                    Timestamp = executionTime,
                                    IsDeletedIndicator = false
                                });
                            }
                        }
                    }
                    catch { /* Restricted SID subkey */ }
                }
            }
        }
        catch (Exception ex)
        {
            records.Add(new HistoricalArtifactRecord
            {
                Source = "BamDam",
                HasAccessDenied = true,
                LimitationNote = $"BAM/DAM registry access restricted in user mode: {ex.Message}"
            });
        }
    }

    private void ScanPowerShellHistory(List<HistoricalArtifactRecord> records)
    {
        try
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string psHistoryPath = Path.Combine(appData, @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

            if (File.Exists(psHistoryPath))
            {
                var lines = File.ReadAllLines(psHistoryPath);
                foreach (var line in lines.TakeLast(100))
                {
                    string lower = line.ToLowerInvariant();
                    if (lower.Contains("fsutil") || lower.Contains("deletejournal") || lower.Contains("wevtutil") || lower.Contains("vape") || lower.Contains("slinky") || lower.Contains("doomsday"))
                    {
                        records.Add(new HistoricalArtifactRecord
                        {
                            Source = "PowerShellHistory",
                            Path = psHistoryPath,
                            Description = $"PowerShell history entry: {line.Trim()}",
                            IsDeletedIndicator = lower.Contains("delete") || lower.Contains("cl")
                        });
                    }
                }
            }
        }
        catch { /* Non-fatal */ }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Cheats;

namespace MinecraftSsForensics.Scanner.LogsAndHistory;

public class HistoricalArtifactRecord
{
    public string Source { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime? Timestamp { get; set; }
    public int? RunCount { get; set; }
    public bool IsDeletedIndicator { get; set; }
    public bool HasAccessDenied { get; set; }
    public string? LimitationNote { get; set; }
}

/// <summary>
/// Historical execution artifact collector auditing Windows Prefetch (.pf with MAM decompression),
/// BAM/DAM registry execution keys with volume resolution, and PowerShell history.
/// </summary>
public class HistoricalEvidenceScanner
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    private static readonly Dictionary<string, string> DeviceToDriveMap = InitDeviceDriveMap();

    private static Dictionary<string, string> InitDeviceDriveMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows()) return map;

        try
        {
            var sb = new StringBuilder(1024);
            foreach (string drive in Environment.GetLogicalDrives())
            {
                string cleanDrive = drive.TrimEnd('\\');
                if (QueryDosDevice(cleanDrive, sb, sb.Capacity) > 0)
                {
                    string target = sb.ToString().Trim();
                    if (!string.IsNullOrEmpty(target))
                    {
                        map[target] = cleanDrive;
                    }
                }
            }
        }
        catch { /* Non-fatal */ }

        return map;
    }

    public static string ResolveDevicePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return string.Empty;
        foreach (var kvp in DeviceToDriveMap)
        {
            if (rawPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                return kvp.Value + rawPath[kvp.Key.Length..];
            }
        }
        return rawPath;
    }

    public List<HistoricalArtifactRecord> ScanHistoricalArtifacts()
    {
        var records = new List<HistoricalArtifactRecord>();

        // 1. Scan %TEMP% for JAR artifacts
        try
        {
            string tempDir = Path.GetTempPath();
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
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string prefetchDir = Path.Combine(winDir, "Prefetch");

        try
        {
            if (Directory.Exists(prefetchDir))
            {
                var dirInfo = new DirectoryInfo(prefetchDir);
                var pfFiles = dirInfo.GetFiles("*.pf", SearchOption.TopDirectoryOnly);

                foreach (var pf in pfFiles)
                {
                    string nameUpper = pf.Name.ToUpperInvariant();
                    bool isJavaOrMinecraft = nameUpper.Contains("JAVA") || nameUpper.Contains("MINECRAFT");

                    var cheatMatch = CheatDetectionDatabase.Signatures.FirstOrDefault(s =>
                        s.KnownFileNames.Any(k => nameUpper.StartsWith(Path.GetFileNameWithoutExtension(k).ToUpperInvariant())));

                    if (isJavaOrMinecraft || cheatMatch != null)
                    {
                        // Parse MAM compressed or uncompressed prefetch header
                        var parsed = PrefetchParser.ParsePrefetchFile(pf.FullName);

                        DateTime timestamp = pf.LastWriteTimeUtc;
                        if (parsed.Success && parsed.ExecutionTimestamps.Count > 0)
                        {
                            timestamp = parsed.ExecutionTimestamps[0].UtcDateTime;
                        }

                        string desc;
                        if (cheatMatch != null)
                        {
                            desc = $"Prefetch execution matching cheat '{cheatMatch.Name}' (Run Count: {parsed.RunCount}, Compression: {parsed.CompressionType})";
                        }
                        else
                        {
                            desc = $"Prefetch execution record: {pf.Name} (Run Count: {parsed.RunCount})";
                        }

                        // Inspect referenced modules for injected hooks
                        if (parsed.LoadedFilesAndModules.Count > 0)
                        {
                            var suspiciousRef = parsed.LoadedFilesAndModules.FirstOrDefault(m =>
                                m.Contains("vape", StringComparison.OrdinalIgnoreCase) ||
                                m.Contains("slinky", StringComparison.OrdinalIgnoreCase) ||
                                m.Contains("doomsday", StringComparison.OrdinalIgnoreCase));

                            if (suspiciousRef != null)
                            {
                                desc += $" • References suspicious module: {suspiciousRef}";
                            }
                        }

                        records.Add(new HistoricalArtifactRecord
                        {
                            Source = "Prefetch",
                            Path = pf.FullName,
                            Description = desc,
                            Timestamp = timestamp,
                            RunCount = parsed.Success ? parsed.RunCount : null,
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
                LimitationNote = "Windows Prefetch directory access was denied in standard user mode. Non-elevated scan cannot audit historical prefetch records."
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

                            string resolvedPath = ResolveDevicePath(valName);
                            string upperName = resolvedPath.ToUpperInvariant();

                            var cheatMatch = CheatDetectionDatabase.Signatures.FirstOrDefault(s =>
                                s.KnownFileNames.Any(k => upperName.Contains(Path.GetFileNameWithoutExtension(k).ToUpperInvariant())));

                            if (cheatMatch != null || upperName.Contains("JAVA") || upperName.Contains("MINECRAFT") || upperName.Contains(@"\TEMP\"))
                            {
                                records.Add(new HistoricalArtifactRecord
                                {
                                    Source = rootPath.Contains("bam") ? "WindowsBAM" : "WindowsDAM",
                                    Path = resolvedPath,
                                    Description = cheatMatch != null
                                        ? $"BAM execution record matching known cheat '{cheatMatch.Name}': {resolvedPath}"
                                        : $"BAM execution record: {Path.GetFileName(resolvedPath)}",
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
                using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs);
                var lines = new List<string>();
                string? l;
                while ((l = reader.ReadLine()) != null)
                {
                    lines.Add(l);
                }

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

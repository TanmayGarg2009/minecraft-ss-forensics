using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Hashing;

namespace MinecraftSsForensics.Scanner.Process;

public interface IProcessScanner
{
    List<DiscoveredProcess> ScanProcesses(bool inspectModules = true);
}

public class ProcessScanner : IProcessScanner
{
    private readonly IFileHasher _hasher;

    private static readonly HashSet<string> TargetProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "javaw", "java", "minecraftlauncher", "prismlauncher", "modrinthapp", "curseforge",
        "lunar client", "badlion client", "feather"
    };

    private static readonly Regex JnaFileNameRegex = new(
        @"^(?:jna\d+|jnidispatch|lwjgl[a-z0-9_]*|openal(?:32|64)?|glfw[0-9]*|jemalloc|tinyfd|jinput-[a-z0-9_\-]+)\.dll$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JavaAgentRegex = new(
        @"-javaagent:(?:""([^""]+)""|(\S+))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ProcessScanner(IFileHasher? hasher = null)
    {
        _hasher = hasher ?? new StreamingFileHasher();
    }

    public List<DiscoveredProcess> ScanProcesses(bool inspectModules = true)
    {
        var discovered = new List<DiscoveredProcess>();

        // Query active processes
        var processes = System.Diagnostics.Process.GetProcesses();

        foreach (var proc in processes)
        {
            try
            {
                string procName = proc.ProcessName.ToLowerInvariant();
                bool isTarget = TargetProcessNames.Contains(procName);
                var cheatSig = !isTarget ? (CheatDetectionDatabase.MatchFileName(procName + ".exe") ?? CheatDetectionDatabase.MatchFileName(procName)) : null;

                if (!isTarget && cheatSig == null)
                {
                    continue;
                }

                var item = new DiscoveredProcess
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    IsGameProcess = procName.Equals("javaw") || procName.Equals("java"),
                    IsLauncherProcess = !procName.Equals("javaw") && !procName.Equals("java") && isTarget,
                    IsCheatProcess = cheatSig != null,
                    MatchedCheatName = cheatSig?.Name
                };

                try
                {
                    item.StartTime = proc.StartTime;
                    item.ExecutablePath = proc.MainModule?.FileName;
                }
                catch (Exception ex)
                {
                    item.HasAccessDenied = true;
                    item.AccessLimitationNote = $"Process metadata restricted: {ex.Message}";
                }

                // Query command line and parent process
                var (cmdLine, parentId) = TryGetProcessDetails(proc.Id);
                item.RedactedCommandLine = cmdLine;
                item.ParentProcessId = parentId;
                if (parentId.HasValue)
                {
                    try { item.ParentProcessName = System.Diagnostics.Process.GetProcessById(parentId.Value).ProcessName; }
                    catch { /* Parent already exited */ }
                }

                // Parse Java agents if present in command line
                if (!string.IsNullOrEmpty(cmdLine))
                {
                    foreach (Match m in JavaAgentRegex.Matches(cmdLine))
                    {
                        string agentPath = !string.IsNullOrEmpty(m.Groups[1].Value) ? m.Groups[1].Value : m.Groups[2].Value;
                        if (!string.IsNullOrWhiteSpace(agentPath))
                        {
                            item.JavaAgents.Add(agentPath.Trim());
                        }
                    }
                }

                // If game process, extract java version if present
                if (item.IsGameProcess && !string.IsNullOrEmpty(item.ExecutablePath))
                {
                    item.JavaVersion = TryExtractJavaVersion(item.ExecutablePath);
                }

                // Inspect loaded modules if requested
                if (inspectModules && !item.HasAccessDenied)
                {
                    item.LoadedModules = InspectModules(proc);
                }

                discovered.Add(item);
            }
            catch
            {
                // Process terminated or inaccessible
            }
        }

        return discovered;
    }

    private List<LoadedModuleInfo> InspectModules(System.Diagnostics.Process proc)
    {
        var modules = new List<LoadedModuleInfo>();

        try
        {
            foreach (ProcessModule mod in proc.Modules)
            {
                try
                {
                    string path = mod.FileName;
                    string name = mod.ModuleName;

                    bool isSystem = path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase) ||
                                    path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase);

                    string tempPath = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);
                    bool isTemp = path.StartsWith(tempPath, StringComparison.OrdinalIgnoreCase) ||
                                  path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);

                    var modInfo = new LoadedModuleInfo
                    {
                        ModuleName = name,
                        FilePath = path,
                        IsStandardSystemModule = isSystem,
                        IsSuspiciousLocation = isTemp
                    };

                    // Check digital signature and Authenticode trust if file exists
                    if (File.Exists(path))
                    {
                        var trust = AuthenticodeTrustValidator.VerifyFileTrust(path);
                        modInfo.IsSigned = trust.IsSigned;
                        modInfo.IsTrustedSignature = trust.IsTrusted;
                        modInfo.SignerSubject = trust.SignerSubject;
                        modInfo.TrustStatusExplanation = trust.StatusExplanation;

                        try
                        {
                            var fileInfo = new FileInfo(path);
                            modInfo.FileSizeBytes = fileInfo.Length;
                        }
                        catch { /* Ignored */ }
                    }

                    // Perform strict Java native library extraction provenance check
                    if (isTemp)
                    {
                        var (isNativeLib, explanation) = CheckJavaNativeProvenance(path, name);
                        modInfo.IsRecognizedJavaNativeLibrary = isNativeLib;
                        modInfo.ProvenanceAssessment = explanation;
                    }
                    else if (isSystem)
                    {
                        modInfo.ProvenanceAssessment = "Standard Windows system library";
                    }

                    modules.Add(modInfo);
                }
                catch
                {
                    // Individual module read error
                }
            }
        }
        catch
        {
            // Module enumeration denied (32-bit to 64-bit boundary or elevation)
        }

        return modules;
    }

    /// <summary>
    /// Distinguishes legitimate Java native library extraction (JNA, LWJGL, OpenAL)
    /// from suspicious DLL injection into javaw.exe without blanket whitelisting.
    /// </summary>
    public static (bool IsLegitimateNative, string Assessment) CheckJavaNativeProvenance(string filePath, string fileName)
    {
        string cleanName = Path.GetFileName(fileName);
        bool matchesNamingPattern = JnaFileNameRegex.IsMatch(cleanName);

        if (!File.Exists(filePath))
        {
            if (matchesNamingPattern)
                return (true, $"Matches standard Java native library naming convention ({cleanName}), but file is unreadable on disk.");
            return (false, "Unsigned module mapped from temporary directory with no disk artifact.");
        }

        try
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
            string desc = versionInfo.FileDescription ?? string.Empty;
            string product = versionInfo.ProductName ?? string.Empty;
            string company = versionInfo.CompanyName ?? string.Empty;

            bool hasJnaMetadata = desc.Contains("Java(TM) Native Access", StringComparison.OrdinalIgnoreCase) ||
                                  desc.Contains("JNA", StringComparison.OrdinalIgnoreCase) ||
                                  product.Contains("JNA", StringComparison.OrdinalIgnoreCase) ||
                                  company.Contains("Timothy Wall", StringComparison.OrdinalIgnoreCase);

            bool hasLwjglMetadata = desc.Contains("LWJGL", StringComparison.OrdinalIgnoreCase) ||
                                    product.Contains("LWJGL", StringComparison.OrdinalIgnoreCase);

            bool hasOpenAlMetadata = desc.Contains("OpenAL", StringComparison.OrdinalIgnoreCase) ||
                                     product.Contains("OpenAL", StringComparison.OrdinalIgnoreCase);

            bool hasJinputMetadata = desc.Contains("JInput", StringComparison.OrdinalIgnoreCase) ||
                                     product.Contains("JInput", StringComparison.OrdinalIgnoreCase);

            if (hasJnaMetadata || hasLwjglMetadata || hasOpenAlMetadata || hasJinputMetadata)
            {
                return (true, $"Verified legitimate Java native library extraction ({product} / {desc})");
            }

            if (matchesNamingPattern)
            {
                // Has valid naming pattern but missing embedded metadata
                return (true, $"Pattern-matched Java native library ({cleanName}); standard temp-extract directory");
            }
        }
        catch
        {
            if (matchesNamingPattern)
                return (true, $"Pattern-matched Java native library ({cleanName})");
        }

        // Suspicious: unsigned DLL in temp that is NOT a known Java native library
        return (false, "Unsigned DLL executing from temporary directory without Java native library provenance (potential injection artifact)");
    }

    private static (string? CommandLine, int? ParentProcessId) TryGetProcessDetails(int processId)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}");
                using var objects = searcher.Get();

                foreach (ManagementObject obj in objects)
                {
                    string? cmd = obj["CommandLine"]?.ToString();
                    int? parentId = null;
                    if (obj["ParentProcessId"] != null && int.TryParse(obj["ParentProcessId"].ToString(), out int pid))
                    {
                        parentId = pid;
                    }

                    string? redacted = !string.IsNullOrEmpty(cmd) ? CommandLineRedactor.Redact(cmd) : null;
                    return (redacted, parentId);
                }
            }
        }
        catch
        {
            // WMI access denied or not available
        }
        return (null, null);
    }

    private static string? TryExtractJavaVersion(string javaExePath)
    {
        try
        {
            var fileVersion = FileVersionInfo.GetVersionInfo(javaExePath);
            return fileVersion.ProductVersion ?? fileVersion.FileVersion;
        }
        catch
        {
            return null;
        }
    }
}

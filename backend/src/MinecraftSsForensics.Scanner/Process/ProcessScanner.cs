using System.Diagnostics;
using System.Management;
using System.Security.Cryptography.X509Certificates;
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
                if (!TargetProcessNames.Contains(procName))
                {
                    continue;
                }

                var item = new DiscoveredProcess
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    IsGameProcess = procName.Equals("javaw") || procName.Equals("java"),
                    IsLauncherProcess = !procName.Equals("javaw") && !procName.Equals("java")
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

                // Query command line if accessible
                item.RedactedCommandLine = TryGetCommandLine(proc.Id);

                // If game process, extract java version if present in path or args
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

                    // Check digital signature if file exists
                    if (File.Exists(path))
                    {
                        try
                        {
                            var cert = X509Certificate.CreateFromSignedFile(path);
                            modInfo.IsSigned = true;
                            modInfo.SignerSubject = cert.Subject;
                        }
                        catch
                        {
                            modInfo.IsSigned = false;
                        }
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
            // Module enumeration denied (e.g. 32-bit to 64-bit boundary or permissions)
        }

        return modules;
    }

    private static string? TryGetCommandLine(int processId)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                using var objects = searcher.Get();

                foreach (ManagementObject obj in objects)
                {
                    var cmd = obj["CommandLine"]?.ToString();
                    if (!string.IsNullOrEmpty(cmd))
                    {
                        return CommandLineRedactor.Redact(cmd);
                    }
                }
            }
        }
        catch
        {
            // WMI access denied or not available
        }
        return null;
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

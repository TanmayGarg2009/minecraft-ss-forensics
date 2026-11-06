using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using MinecraftSsForensics.Scanner.Cheats;
using MinecraftSsForensics.Scanner.Hashing;
using MinecraftSsForensics.Scanner.Identities;
using MinecraftSsForensics.Scanner.Models;

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
                    CollectionTimeUtc = DateTimeOffset.UtcNow,
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
                    item.StartTime = null;
                    item.HasAccessDenied = true;
                    item.AccessLimitationNote = $"Process metadata restricted: {ex.Message}";
                }

                // Compute binary hash and composite process instance identity (immune to PID recycling)
                string? imageSha256 = null;
                if (!string.IsNullOrEmpty(item.ExecutablePath) && File.Exists(item.ExecutablePath))
                {
                    imageSha256 = TryComputeFileSha256(item.ExecutablePath);
                }
                item.ImageSha256 = imageSha256;

                string hostId = Environment.MachineName.ToLowerInvariant();
                var procInstId = ProcessInstanceId.Create(hostId, proc.Id, item.StartTime.HasValue ? new DateTimeOffset(item.StartTime.Value) : null, imageSha256);
                item.ProcessInstanceId = procInstId.ToString();

                // Query command line and parent process
                var (cmdLine, parentId) = TryGetProcessDetails(proc.Id);
                item.RedactedCommandLine = cmdLine;
                item.CurrentWorkingDirectory = TryGetProcessCurrentDirectory(proc.Id);
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
                if (inspectModules)
                {
                    if (item.HasAccessDenied)
                    {
                        item.ModuleEnumerationStatus = ModuleEnumerationStatus.AccessDenied;
                        item.ModuleEnumerationNote = "Process access restricted; module enumeration could not be attempted.";
                    }
                    else
                    {
                        item.LoadedModules = InspectModules(proc, item);
                    }
                }
                else
                {
                    item.ModuleEnumerationStatus = ModuleEnumerationStatus.NotAttempted;
                    item.ModuleEnumerationNote = "Module enumeration disabled by scan scope.";
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

    private List<LoadedModuleInfo> InspectModules(System.Diagnostics.Process proc, DiscoveredProcess item)
    {
        var modules = new List<LoadedModuleInfo>();
        string procInstanceId = item.ProcessInstanceId ?? $"proc:local:{proc.Id}:0:unknown";

        try
        {
            var procModules = proc.Modules;
            foreach (ProcessModule mod in procModules)
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

                    string? baseAddressHex = null;
                    try { baseAddressHex = "0x" + mod.BaseAddress.ToInt64().ToString("x"); } catch { }

                    var modInfo = new LoadedModuleInfo
                    {
                        ModuleName = name,
                        FilePath = path,
                        BaseAddressHex = baseAddressHex,
                        CollectionTimeUtc = DateTimeOffset.UtcNow,
                        ModuleEnumerationStatus = ModuleEnumerationStatus.Complete,
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

                        if (isTemp)
                        {
                            modInfo.Sha256 = TryComputeFileSha256(path);
                        }
                    }

                    var modInstId = new ModuleInstanceId(procInstanceId, baseAddressHex ?? "0x0", modInfo.FileSizeBytes ?? 0, modInfo.Sha256);
                    modInfo.ModuleInstanceId = modInstId.ToString();

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
                catch (Exception ex)
                {
                    // Individual module read error -> mark partial
                    item.ModuleEnumerationStatus = ModuleEnumerationStatus.Partial;
                    item.ModuleEnumerationNote = $"One or more modules could not be read: {ex.Message}";
                }
            }
        }
        catch (System.ComponentModel.Win32Exception winEx)
        {
            if (winEx.NativeErrorCode == 5) // ERROR_ACCESS_DENIED
            {
                item.ModuleEnumerationStatus = ModuleEnumerationStatus.AccessDenied;
                item.ModuleEnumerationNote = "Access denied: elevated permissions required to enumerate modules of this process.";
            }
            else if (winEx.NativeErrorCode == 299) // ERROR_PARTIAL_COPY (32-bit to 64-bit boundary)
            {
                item.ModuleEnumerationStatus = ModuleEnumerationStatus.UnsupportedArchitecture;
                item.ModuleEnumerationNote = "Cross-architecture module query restriction (32-bit / 64-bit boundary).";
            }
            else
            {
                item.ModuleEnumerationStatus = ModuleEnumerationStatus.AccessDenied;
                item.ModuleEnumerationNote = $"Win32 error {winEx.NativeErrorCode}: {winEx.Message}";
            }
        }
        catch (InvalidOperationException)
        {
            item.ModuleEnumerationStatus = ModuleEnumerationStatus.ProcessExited;
            item.ModuleEnumerationNote = "Process exited before module enumeration could complete.";
        }
        catch (Exception ex)
        {
            item.ModuleEnumerationStatus = ModuleEnumerationStatus.AccessDenied;
            item.ModuleEnumerationNote = $"Module enumeration failed: {ex.Message}";
        }

        // Isolated, safe, read-only scan for unbacked reflective PE image injection
        if (item.IsGameProcess && item.ModuleEnumerationStatus != ModuleEnumerationStatus.AccessDenied)
        {
            ScanReflectiveInjections(proc, item, modules);
        }

        return modules;
    }

    /// <summary>
    /// Distinguishes legitimate Java native library extraction (JNA, LWJGL, OpenAL)
    /// from suspicious DLL injection into javaw.exe without blanket whitelisting.
    /// Unsigned temporary DLLs exporting generic JNI entrypoints (JNI_OnLoad) without authentic
    /// publisher metadata are flagged as capability indicators, not legitimate Java native libraries.
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

            var peResult = PeExportParser.ParseExports(filePath);

            // Unsigned DLL in temp exporting JNI_OnLoad without authentic publisher metadata
            // is a known indicator of native JVM attachment/injection, NOT a legitimate library
            if (peResult.HasJniOnLoad)
            {
                return (false, "Unsigned native DLL in temporary directory exporting JNI attachment points (JNI_OnLoad) without verified publisher metadata (potential injection artifact)");
            }

            // Inspect PE Export table for recognized JNA / LWJGL export symbols combined with naming pattern
            if (peResult.HasRecognizedJavaExports && matchesNamingPattern)
            {
                return (true, $"Pattern-matched Java native library ({cleanName}) with verified PE export symbol ({peResult.MatchedJavaSymbol})");
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

    private static string? TryComputeFileSha256(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return null;
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha = System.Security.Cryptography.SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    #region Win32 PEB & Memory Structures & P/Invoke

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    /// <summary>
    /// Safely resolves the process working directory from the remote Process Environment Block (PEB).
    /// Works read-only without modifying process state or requiring intrusive hooking.
    /// </summary>
    public static string? TryGetProcessCurrentDirectory(int processId)
    {
        if (!OperatingSystem.IsWindows()) return null;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
        if (hProcess == IntPtr.Zero) return null;

        try
        {
            if (IsWow64Process(hProcess, out bool isWow64) && isWow64)
            {
                return null;
            }

            var pbi = new PROCESS_BASIC_INFORMATION();
            if (NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) != 0)
            {
                return null;
            }

            IntPtr peb = pbi.PebBaseAddress;
            if (peb == IntPtr.Zero) return null;

            byte[] ptrBuf = new byte[8];
            if (!ReadProcessMemory(hProcess, peb + 0x20, ptrBuf, 8, out _) || BitConverter.ToInt64(ptrBuf, 0) == 0)
            {
                return null;
            }

            IntPtr procParams = (IntPtr)BitConverter.ToInt64(ptrBuf, 0);

            byte[] curDirHeader = new byte[16];
            if (!ReadProcessMemory(hProcess, procParams + 0x38, curDirHeader, 16, out _))
            {
                return null;
            }

            ushort length = BitConverter.ToUInt16(curDirHeader, 0);
            long bufferAddr = BitConverter.ToInt64(curDirHeader, 8);
            if (length == 0 || length > 1024 || bufferAddr == 0)
            {
                return null;
            }

            byte[] strBytes = new byte[length];
            if (!ReadProcessMemory(hProcess, (IntPtr)bufferAddr, strBytes, length, out _))
            {
                return null;
            }

            string rawPath = Encoding.Unicode.GetString(strBytes).TrimEnd('\0', ' ', '\r', '\n');
            return !string.IsNullOrWhiteSpace(rawPath) ? rawPath : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Isolated, safe, read-only memory scan looking for unbacked executable regions containing an MZ header.
    /// Distinguishes reflective manual PE mapping from HotSpot JVM JIT code cache pages (which do not start with MZ).
    /// </summary>
    private static void ScanReflectiveInjections(System.Diagnostics.Process proc, DiscoveredProcess item, List<LoadedModuleInfo> modules)
    {
        if (!OperatingSystem.IsWindows() || !item.IsGameProcess) return;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
        if (hProcess == IntPtr.Zero) return;

        try
        {
            IntPtr currentAddr = IntPtr.Zero;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            int injectionCount = 0;

            while (VirtualQueryEx(hProcess, currentAddr, out var mbi, mbiSize) != 0 && injectionCount < 10)
            {
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
                {
                    bool isExec = (mbi.Protect == PAGE_EXECUTE_READWRITE) ||
                                  (mbi.Protect == PAGE_EXECUTE_READ) ||
                                  (mbi.Protect == PAGE_EXECUTE);

                    if (isExec && (long)mbi.RegionSize >= 4096)
                    {
                        byte[] sample = new byte[64];
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, sample, sample.Length, out var bytesRead) && (long)bytesRead >= 2)
                        {
                            if (sample[0] == 0x4D && sample[1] == 0x5A) // 'M', 'Z'
                            {
                                injectionCount++;
                                string baseAddrHex = $"0x{(ulong)mbi.BaseAddress:X}";
                                long sizeBytes = (long)mbi.RegionSize;

                                var modInfo = new LoadedModuleInfo
                                {
                                    ModuleName = $"[Manual Mapped PE: {baseAddrHex}]",
                                    FilePath = $"<VirtualMemory:{baseAddrHex}>",
                                    BaseAddressHex = baseAddrHex,
                                    FileSizeBytes = sizeBytes,
                                    CollectionTimeUtc = DateTimeOffset.UtcNow,
                                    ModuleEnumerationStatus = ModuleEnumerationStatus.Complete,
                                    IsStandardSystemModule = false,
                                    IsSuspiciousLocation = true,
                                    IsRecognizedJavaNativeLibrary = false,
                                    ProvenanceAssessment = $"Unbacked private executable memory region ({sizeBytes / 1024} KB) containing PE DOS header (MZ). Known reflective DLL injection indicator."
                                };

                                var modInstId = new ModuleInstanceId(item.ProcessInstanceId ?? $"proc:local:{proc.Id}", baseAddrHex, sizeBytes, "reflective-pe");
                                modInfo.ModuleInstanceId = modInstId.ToString();

                                modules.Add(modInfo);
                            }
                        }
                    }
                }

                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)mbi.BaseAddress) break;
                currentAddr = (IntPtr)nextAddr;
            }
        }
        catch
        {
            // Suppress non-fatal memory inspection exceptions
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    #endregion
}

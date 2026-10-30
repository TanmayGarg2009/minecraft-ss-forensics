using System;
using System.Collections.Generic;

namespace MinecraftSsForensics.Scanner.Process;

public class DiscoveredProcess
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string? ExecutablePath { get; set; }
    public int? ParentProcessId { get; set; }
    public string? ParentProcessName { get; set; }
    public DateTime? StartTime { get; set; }
    public string? RedactedCommandLine { get; set; }
    public string? JavaVersion { get; set; }
    public bool IsGameProcess { get; set; }
    public bool IsLauncherProcess { get; set; }
    public bool IsCheatProcess { get; set; }
    public string? MatchedCheatName { get; set; }
    public List<string> JavaAgents { get; set; } = new();
    public List<LoadedModuleInfo> LoadedModules { get; set; } = new();
    public bool HasAccessDenied { get; set; }
    public string? AccessLimitationNote { get; set; }
}

public class LoadedModuleInfo
{
    public string ModuleName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long? FileSizeBytes { get; set; }
    public string? Sha256 { get; set; }
    public bool IsSigned { get; set; }
    public bool IsTrustedSignature { get; set; }
    public string? SignerSubject { get; set; }
    public string? TrustStatusExplanation { get; set; }
    public bool IsStandardSystemModule { get; set; }
    public bool IsSuspiciousLocation { get; set; }

    /// <summary>
    /// Distinguishes legitimate Java native library extraction (JNA, LWJGL, OpenAL)
    /// from unauthorized process injection into javaw.exe.
    /// </summary>
    public bool IsRecognizedJavaNativeLibrary { get; set; }
    public string ProvenanceAssessment { get; set; } = "Standard system module";
}

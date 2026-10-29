namespace MinecraftSsForensics.Api.Models.Domain;

public enum ScanMode
{
    Quick,
    Full
}

public enum ProcessingStatus
{
    Completed,
    Partial,
    Failed
}

public enum FindingCategory
{
    ModIntegrity,
    ProcessInjection,
    ExecutionArtifacts,
    JvmEnvironment,
    FileDeletion,
    NetworkAnomaly,
    Other
}

public enum Severity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum ConfidenceLevel
{
    Low,
    Medium,
    High,
    Certain
}

public enum EvidenceSource
{
    ModFolder,
    Prefetch,
    UsnJournal,
    BamDam,
    JvmArgs,
    EventLogs,
    ProcessMemoryMetadata,
    ShimCache,
    Amcache,
    Other
}

public enum EvidenceType
{
    MinecraftLog,
    LauncherLog,
    ModInventory,
    JvmArguments,
    LoadedModules,
    FileMetadata,
    WindowsArtifact,
    CorrelationResult,
    DiagnosticFailure
}

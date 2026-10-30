namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// Strict classification levels for forensic findings in accordance with anti-cheat standards.
/// </summary>
public enum FindingClassification
{
    ConfirmedCheatArtifact,
    StrongIndicator,
    Suspicious,
    NeedsReview,
    Informational,
    NoEvidenceFound,
    Unavailable
}

/// <summary>
/// High-level categories of forensic evidence discovered.
/// </summary>
public enum FindingCategory
{
    CheatArtifact,
    ModIntegrity,
    PolicyViolation,
    ProcessInjection,
    ExecutionArtifacts,
    JvmEnvironment,
    FileDeletion,
    NetworkAnomaly,
    RegistryArtifact,
    UsbArtifact,
    BrowserHistory,
    Other
}

/// <summary>
/// Primary evidence categories strictly separating disk presence from runtime interaction.
/// </summary>
public enum EvidenceCategory
{
    /// <summary>
    /// File physically exists on disk (e.g. Downloads, Desktop, Temp, Mods folder).
    /// </summary>
    Disk,

    /// <summary>
    /// An executable process is currently running on the operating system.
    /// </summary>
    RunningProcess,

    /// <summary>
    /// A dynamic-link library or module is loaded into process virtual address space.
    /// </summary>
    LoadedModule,

    /// <summary>
    /// Direct injection or cross-process interaction established with Minecraft process.
    /// </summary>
    Injected,

    /// <summary>
    /// Verified active during the scan window or ongoing Minecraft game session.
    /// </summary>
    ActiveInScanWindow,

    /// <summary>
    /// Historical execution artifact (Prefetch, BAM, UserAssist) prior to scan window.
    /// </summary>
    Historical,

    /// <summary>
    /// JVM arguments, Java agents, classpath entries, or runtime environment flags.
    /// </summary>
    JvmEnvironment,

    /// <summary>
    /// Minecraft mod archive structure, metadata, or authenticity verification.
    /// </summary>
    ModIntegrity,

    /// <summary>
    /// Specific rule violation under the active server gameplay policy.
    /// </summary>
    PolicyViolation,

    /// <summary>
    /// Artifact deleted or moved to Recycle Bin.
    /// </summary>
    FileDeletion,

    /// <summary>
    /// Scanner integrity check or diagnostic telemetry limitation.
    /// </summary>
    IntegrityOrDiagnostic,

    /// <summary>
    /// Other unclassified evidence category.
    /// </summary>
    Other
}

/// <summary>
/// Detection methodology utilized to discover or verify evidence.
/// </summary>
public enum DetectionMethod
{
    ExactSignature,
    HashMatch,
    MetadataRule,
    RuntimeObservation,
    BytecodeStructure,
    HistoricalArtifact,
    Heuristic,
    ManualInspection,
    Other
}

/// <summary>
/// Evidentiary strength of an individual finding.
/// </summary>
public enum EvidenceStrength
{
    Strong,
    Moderate,
    Weak,
    Inconclusive
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

/// <summary>
/// Execution status for individual diagnostic checks.
/// </summary>
public enum CheckStatus
{
    PASSED,
    FLAGGED,
    SKIPPED,
    UNAVAILABLE,
    ERROR
}

public enum EvidenceType
{
    MinecraftLog,
    LauncherLog,
    ModInventory,
    ModPolicyAudit,
    CheatSignatureMatch,
    JvmArguments,
    LoadedModules,
    FileMetadata,
    WindowsArtifact,
    RegistryKey,
    UsbDevice,
    BrowserHistory,
    CorrelationResult,
    DiagnosticFailure
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

/// <summary>
/// Structured status of individual evidence items.
/// Missing telemetry is never automatically treated as tampering.
/// </summary>
public enum EvidenceState
{
    CONFIRMED,
    STRONG_INDICATOR,
    WEAK_INDICATOR,
    INCONCLUSIVE,
    NOT_CONFIGURED,
    NOT_AVAILABLE,
    DATA_EXPIRED_OR_OVERWRITTEN,
    COLLECTION_FAILED,
    NOT_COLLECTED_BY_USER_CHOICE
}

/// <summary>
/// The 6 distinct evidentiary correlation states of software during an investigation.
/// Must never be collapsed into a generic 'cheat detected' result.
/// </summary>
public enum SoftwareEvidenceState
{
    /// <summary>
    /// Software binary or artifact exists on the file system (e.g. in Downloads, Desktop, or $Recycle.Bin).
    /// </summary>
    SoftwarePresent,

    /// <summary>
    /// Software is installed in an active game environment (e.g. in .minecraft/mods or launcher profile).
    /// </summary>
    SoftwareInstalled,

    /// <summary>
    /// Software has historical proof of execution on the OS (e.g. Windows Prefetch, BAM, or PCA).
    /// </summary>
    SoftwareExecuted,

    /// <summary>
    /// Software execution timeline overlaps with a Minecraft game session.
    /// </summary>
    SoftwareActiveDuringSession,

    /// <summary>
    /// Software has direct technical interaction with Minecraft (e.g. memory-mapped DLL in javaw.exe, process handle, or Java Agent).
    /// </summary>
    SoftwareInteractingWithMinecraft,

    /// <summary>
    /// Software binary contains verified structural or bytecode capabilities prohibited by game policy (e.g. crystal aura, reach, packet spoofing).
    /// </summary>
    SoftwareContainsProhibitedCapabilities,

    /// <summary>
    /// Prohibited in-game capability or automation was actively used (e.g. packet sequence manipulation, crystal aura telemetry).
    /// </summary>
    ProhibitedFunctionalityUsed
}

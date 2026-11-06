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
/// Status of process module enumeration, recording elevation boundaries or technical restrictions.
/// </summary>
public enum ModuleEnumerationStatus
{
    /// <summary>
    /// All loaded modules were enumerated successfully.
    /// </summary>
    Complete = 0,

    /// <summary>
    /// Module enumeration was denied by the OS (requires elevation or target is a protected process).
    /// </summary>
    AccessDenied = 1,

    /// <summary>
    /// Module enumeration was prevented by a 32-bit / 64-bit cross-architecture boundary.
    /// </summary>
    UnsupportedArchitecture = 2,

    /// <summary>
    /// Target process terminated before module enumeration completed.
    /// </summary>
    ProcessExited = 3,

    /// <summary>
    /// Enumeration started but some module descriptors could not be read.
    /// </summary>
    Partial = 4,

    /// <summary>
    /// Module inspection was not attempted or was excluded by user consent.
    /// </summary>
    NotAttempted = 5,

    /// <summary>
    /// Target process instance is ambiguous due to PID reuse or missing metadata.
    /// </summary>
    AmbiguousIdentity = 6
}

/// <summary>
/// The 7 distinct execution-evidence attribution states strictly mandated by forensic standards:
/// 1. FilePresent (physical presence on disk)
/// 2. SoftwareInstalled (staged in game profile or mods folder)
/// 3. LaunchConfigurationReference (referenced in JVM arguments, classpath, or config)
/// 4. HistoricalExecution (recorded in Windows Prefetch, BAM, or PCA)
/// 5. ProcessLoadedModule (module mapped in a process virtual address space)
/// 6. MinecraftProcessAssociation (technical link to Minecraft JVM instance)
/// 7. ActiveDuringInspectedSession (verified loaded/active state during inspected session)
/// </summary>
public enum ExecutionEvidenceState
{
    /// <summary>
    /// A file was found at a particular location on disk.
    /// Permitted: present when inspected. Not permitted: executed, loaded, or active in Minecraft.
    /// </summary>
    FilePresent = 0,

    /// <summary>
    /// A file or package was found in an installation/profile location (e.g. .minecraft/mods).
    /// Permitted: installed or staged. Not permitted: active during inspected session.
    /// </summary>
    SoftwareInstalled = 1,

    /// <summary>
    /// A JVM argument, classpath entry, agent option, or configuration refers to a software component.
    /// Permitted: launch configuration references component. Not permitted: successfully loaded or executed.
    /// </summary>
    LaunchConfigurationReference = 2,

    /// <summary>
    /// A supported Windows artifact (Prefetch, BAM, PCA) indicates execution at a historical time.
    /// Permitted: historical execution recorded by OS. Not permitted: active during inspected session.
    /// </summary>
    HistoricalExecution = 3,

    /// <summary>
    /// A module was observed in a specific process instance through actual process/module telemetry.
    /// Permitted: mapped/loaded in that process at collection time. Not permitted: malicious behavior without verified payload.
    /// </summary>
    ProcessLoadedModule = 4,

    /// <summary>
    /// A process or module has a technically supported relationship with the identified Minecraft process.
    /// Permitted: association supported by recorded relationship. Not permitted: association alone proves cheating.
    /// </summary>
    MinecraftProcessAssociation = 5,

    /// <summary>
    /// Software is demonstrated to have been active during the inspected Minecraft session with verified artifact identity,
    /// verified process identity, valid relationship, session timing, and loaded/active telemetry.
    /// </summary>
    ActiveDuringInspectedSession = 6
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
    SoftwarePresent = 0,

    /// <summary>
    /// Software is installed in an active game environment (e.g. in .minecraft/mods or launcher profile).
    /// </summary>
    SoftwareInstalled = 1,

    /// <summary>
    /// Software has historical proof of execution on the OS (e.g. Windows Prefetch, BAM, or PCA).
    /// </summary>
    SoftwareExecuted = 2,

    /// <summary>
    /// Software execution timeline overlaps with a Minecraft game session.
    /// </summary>
    SoftwareActiveDuringSession = 3,

    /// <summary>
    /// Software has direct technical interaction with Minecraft (e.g. memory-mapped DLL in javaw.exe, process handle, or Java Agent).
    /// </summary>
    SoftwareInteractingWithMinecraft = 4,

    /// <summary>
    /// Software binary contains verified structural or bytecode capabilities prohibited by game policy (e.g. crystal aura, reach, packet spoofing).
    /// </summary>
    SoftwareContainsProhibitedCapabilities = 5,

    /// <summary>
    /// Prohibited in-game capability or automation was actively used (e.g. packet sequence manipulation, crystal aura telemetry).
    /// </summary>
    ProhibitedFunctionalityUsed = 6
}

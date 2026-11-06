namespace MinecraftSsForensics.Scanner.Graph;

/// <summary>
/// The 13 canonical vertex entity types in the Directed Attributed Evidence Graph.
/// </summary>
public enum EntityType
{
    MinecraftInstallation,
    MinecraftSession,
    JvmProcess,
    OsProcess,
    File,
    JarArchive,
    NativeLibrary,
    LoadedModule,
    CryptographicHash,
    DigitalSignature,
    HistoricalRecord,
    RawObservation,
    EvidenceCluster
}

/// <summary>
/// The 11 formal relationship edge types connecting vertices in the Evidence Graph.
/// Edges represent explicitly verified relationships, never inferred purely from shared timestamps or paths.
/// </summary>
public enum EdgeType
{
    /// <summary>
    /// OS_PROCESS was launched by LAUNCHER. PPID and start timestamps correlate.
    /// </summary>
    LaunchedBy,

    /// <summary>
    /// LOADED_MODULE is loaded in virtual address space of OS_PROCESS.
    /// </summary>
    LoadedBy,

    /// <summary>
    /// FILE resides within MINECRAFT_INSTALLATION directory tree.
    /// </summary>
    LocatedIn,

    /// <summary>
    /// FILE contents match CRYPTOGRAPHIC_HASH.
    /// </summary>
    HashMatches,

    /// <summary>
    /// FILE is signed by DIGITAL_SIGNATURE Authenticode certificate.
    /// </summary>
    SignedBy,

    /// <summary>
    /// LOADED_MODULE or Process is directly associated with JVM_PROCESS (e.g. mapped into javaw.exe).
    /// </summary>
    AssociatedWith,

    /// <summary>
    /// RAW_OBSERVATION occurred strictly within the window of MINECRAFT_SESSION.
    /// </summary>
    ObservedDuring,

    /// <summary>
    /// HISTORICAL_RECORD documents prior execution of FILE on OS.
    /// </summary>
    HistoricallyExecuted,

    /// <summary>
    /// RAW_OBSERVATION confirms complementary facts supporting another RAW_OBSERVATION.
    /// </summary>
    Corroborates,

    /// <summary>
    /// RAW_OBSERVATION presents mutually exclusive evidentiary state against another RAW_OBSERVATION.
    /// </summary>
    Contradicts,

    /// <summary>
    /// FINDING_RECORD or cluster is derived from contributing RAW_OBSERVATION.
    /// </summary>
    DerivedFrom
}

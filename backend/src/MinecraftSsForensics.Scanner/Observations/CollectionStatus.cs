namespace MinecraftSsForensics.Scanner.Observations;

/// <summary>
/// Standardized execution status for evidence collection pipelines.
/// Missing telemetry is never treated as a clean result or as automatic tampering.
/// </summary>
public enum CollectionStatus
{
    /// <summary>
    /// Collection completed fully with full source coverage.
    /// </summary>
    Success,

    /// <summary>
    /// Collection completed with partial coverage (e.g. some files unreadable or partial record window).
    /// </summary>
    PartialSuccess,

    /// <summary>
    /// The target data source does not exist or is disabled on this system (e.g. Prefetch disabled, no USN journal).
    /// </summary>
    Unavailable,

    /// <summary>
    /// Access was denied due to Windows permissions, UAC, or DACL restrictions.
    /// </summary>
    PermissionDenied,

    /// <summary>
    /// The platform or environment is not supported for this collection mechanism.
    /// </summary>
    Unsupported,

    /// <summary>
    /// The collector reached its bounded execution time limit and terminated gracefully.
    /// </summary>
    Timeout,

    /// <summary>
    /// Collection was aborted due to user cancellation or scan interruption.
    /// </summary>
    Cancelled,

    /// <summary>
    /// An unexpected exception occurred during collection.
    /// </summary>
    Error
}

using System;
using System.Collections.Generic;

namespace MinecraftSsForensics.Scanner.Observations;

/// <summary>
/// Core contract for an immutable, typed observation recorded during forensic scanning.
/// Observations represent what was physically or logically observed by a specific collector.
/// Derived conclusions, assessments, and policy verdicts remain strictly decoupled from raw observations.
/// </summary>
public interface IObservation
{
    /// <summary>
    /// Unique identifier for this observation record.
    /// </summary>
    string ObservationId { get; }

    /// <summary>
    /// Categorical type of the observation (e.g. "ProcessObservation", "FileObservation", "ModuleObservation").
    /// </summary>
    string ObservationType { get; }

    /// <summary>
    /// The specific collector component that recorded this observation.
    /// </summary>
    string SourceCollector { get; }

    /// <summary>
    /// Timestamp at which the collector made this observation (UTC).
    /// </summary>
    DateTimeOffset CollectionTimestampUtc { get; }

    /// <summary>
    /// Timestamp of the underlying system event (e.g. process start time, file modification, prefetch execution), if available (UTC).
    /// </summary>
    DateTimeOffset? EventTimestampUtc { get; }

    /// <summary>
    /// Originating system source identity (e.g. "MFT", "Win32_Process", "Prefetch", "Authenticode").
    /// </summary>
    string SourceIdentity { get; }

    /// <summary>
    /// Forensic provenance describing the collection path and method.
    /// </summary>
    string Provenance { get; }

    /// <summary>
    /// Availability/collection status under which this observation was obtained.
    /// </summary>
    CollectionStatus AvailabilityState { get; }

    /// <summary>
    /// Explicit documented limitations or caveats regarding this observation's reliability.
    /// </summary>
    string ReliabilityLimitations { get; }

    /// <summary>
    /// Target entity composite identity (e.g. ProcessInstanceId, FileInstanceId, ModuleInstanceId) if applicable.
    /// </summary>
    string? TargetEntityId { get; }

    /// <summary>
    /// Structured key-value properties describing the observed entity.
    /// </summary>
    IReadOnlyDictionary<string, string> Properties { get; }

    /// <summary>
    /// Optional underlying raw payload object for deep diagnostic forensics.
    /// </summary>
    object? RawPayload { get; }
}

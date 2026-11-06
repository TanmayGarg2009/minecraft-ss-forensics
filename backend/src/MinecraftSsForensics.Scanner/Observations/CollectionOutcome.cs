using System;
using System.Collections.Generic;

namespace MinecraftSsForensics.Scanner.Observations;

/// <summary>
/// Immutable record of a collector execution outcome, capturing timing, coverage, and diagnostic limitations.
/// </summary>
public record CollectionOutcome
{
    public required string CollectorName { get; init; }
    public required CollectionStatus Status { get; init; }
    public TimeSpan Duration { get; init; }
    public int ItemsCollected { get; init; }
    public string? Reason { get; init; }
    public IReadOnlyList<string> DiagnosticNotes { get; init; } = Array.Empty<string>();
    public DateTimeOffset CompletedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public static CollectionOutcome Succeeded(string collectorName, int count, TimeSpan duration, IEnumerable<string>? notes = null) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Success,
            ItemsCollected = count,
            Duration = duration,
            DiagnosticNotes = notes != null ? new List<string>(notes) : Array.Empty<string>()
        };

    public static CollectionOutcome PartiallySucceeded(string collectorName, int count, TimeSpan duration, string reason, IEnumerable<string>? notes = null) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.PartialSuccess,
            ItemsCollected = count,
            Duration = duration,
            Reason = reason,
            DiagnosticNotes = notes != null ? new List<string>(notes) : Array.Empty<string>()
        };

    public static CollectionOutcome SourceUnavailable(string collectorName, string reason) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Unavailable,
            ItemsCollected = 0,
            Duration = TimeSpan.Zero,
            Reason = reason
        };

    public static CollectionOutcome AccessDenied(string collectorName, string pathOrResource) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.PermissionDenied,
            ItemsCollected = 0,
            Duration = TimeSpan.Zero,
            Reason = $"Access denied to resource: {pathOrResource}"
        };

    public static CollectionOutcome TimedOut(string collectorName, TimeSpan limit) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Timeout,
            ItemsCollected = 0,
            Duration = limit,
            Reason = $"Collector exceeded bounded execution budget of {limit.TotalSeconds:F1}s"
        };

    public static CollectionOutcome UnsupportedPlatform(string collectorName, string reason) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Unsupported,
            ItemsCollected = 0,
            Duration = TimeSpan.Zero,
            Reason = reason
        };

    public static CollectionOutcome Cancelled(string collectorName, string? reason = null) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Cancelled,
            ItemsCollected = 0,
            Duration = TimeSpan.Zero,
            Reason = reason ?? "Collection cancelled by user or caller."
        };

    public static CollectionOutcome Failed(string collectorName, Exception ex) =>
        new()
        {
            CollectorName = collectorName,
            Status = CollectionStatus.Error,
            ItemsCollected = 0,
            Duration = TimeSpan.Zero,
            Reason = Process.PrivacyBoundary.RedactString(ex.Message),
            DiagnosticNotes = new[] { ex.GetType().Name, Process.PrivacyBoundary.RedactString(ex.StackTrace ?? string.Empty) }
        };
}

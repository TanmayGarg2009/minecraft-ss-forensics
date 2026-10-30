using System;

namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// A detailed forensic finding with technical explanation, alternative hypotheses, and evidence links.
/// Adheres strictly to evidentiary standards: never makes unsupported accusations.
/// </summary>
public class FindingRecord
{
    public string FindingId { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string RuleId { get; set; } = string.Empty;
    public string DetectionName { get; set; } = string.Empty;
    public FindingCategory Category { get; set; } = FindingCategory.Other;
    public FindingClassification Classification { get; set; } = FindingClassification.Informational;
    public Severity Severity { get; set; } = Severity.Informational;
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
    public EvidenceState EvidenceState { get; set; } = EvidenceState.CONFIRMED;
    public SoftwareEvidenceState SoftwareState { get; set; } = SoftwareEvidenceState.SoftwarePresent;
    public string SoftwareStateDescription { get; set; } = string.Empty;
    public string PolicyViolationScope { get; set; } = string.Empty;

    public string EvidenceSource { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public long? FileSizeBytes { get; set; }
    public string? FileSha256 { get; set; }

    public DateTimeOffset? ObservedTimestamp { get; set; }
    public string TimestampReliability { get; set; } = "High (Filesystem MFT / Event Timestamp)";

    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessCommandLine { get; set; }

    public string TechnicalExplanation { get; set; } = string.Empty;
    public string WhyItMatters { get; set; } = string.Empty;
    public string AlternativeLegitimateExplanations { get; set; } = string.Empty;
    public string WhatIsProven { get; set; } = string.Empty;
    public string WhatIsNotProven { get; set; } = string.Empty;
    public string Limitations { get; set; } = string.Empty;
    public string EvidenceStrengtheningFinding { get; set; } = string.Empty;
    public string EvidenceWeakeningFinding { get; set; } = string.Empty;
    public string SuggestedNextChecks { get; set; } = string.Empty;
    public List<string> RelatedEvidenceIds { get; set; } = new();

    public object? SupportingEvidencePayload { get; set; }
}

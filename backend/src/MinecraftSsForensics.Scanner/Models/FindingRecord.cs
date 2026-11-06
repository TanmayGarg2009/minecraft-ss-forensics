using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Models;

/// <summary>
/// A detailed forensic finding with technical explanation, alternative hypotheses, and evidence links.
/// Adheres strictly to evidentiary standards: never makes unsupported accusations.
/// </summary>
public class FindingRecord
{
    public string FindingId { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string RuleId { get; set; } = string.Empty;

    // Finding description & category
    private string _detectionName = string.Empty;
    public string DetectionName
    {
        get => _detectionName;
        set
        {
            _detectionName = value;
            if (string.IsNullOrEmpty(_findingTitle)) _findingTitle = value;
        }
    }

    private string _findingTitle = string.Empty;
    public string FindingTitle
    {
        get => !string.IsNullOrEmpty(_findingTitle) ? _findingTitle : _detectionName;
        set => _findingTitle = value;
    }

    [JsonIgnore]
    public string Finding
    {
        get => FindingTitle;
        set
        {
            if (string.IsNullOrEmpty(_findingTitle)) FindingTitle = value;
            if (string.IsNullOrEmpty(_detectionName)) DetectionName = value;
        }
    }

    public FindingCategory Category { get; set; } = FindingCategory.Other;
    public EvidenceCategory EvidenceCategory { get; set; } = EvidenceCategory.Disk;
    public FindingClassification Classification { get; set; } = FindingClassification.Informational;

    private Severity _severity = Severity.Informational;
    private bool _severityExplicitlySet = false;

    public Severity Severity
    {
        get
        {
            if (_severityExplicitlySet) return _severity;
            return Classification switch
            {
                FindingClassification.ConfirmedCheatArtifact => Severity.High,
                FindingClassification.StrongIndicator => Severity.Medium,
                FindingClassification.Suspicious => Severity.Medium,
                FindingClassification.NeedsReview => Severity.Low,
                _ => Severity.Informational
            };
        }
        set
        {
            _severity = value;
            _severityExplicitlySet = true;
        }
    }

    public EvidenceStrength EvidenceStrength { get; set; } = EvidenceStrength.Inconclusive;
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Low;
    public DetectionMethod DetectionMethod { get; set; } = DetectionMethod.Other;
    public EvidenceState EvidenceState { get; set; } = EvidenceState.INCONCLUSIVE;
    public SoftwareEvidenceState SoftwareState { get; set; } = SoftwareEvidenceState.SoftwarePresent;
    public ExecutionEvidenceState ExecutionState { get; set; } = ExecutionEvidenceState.FilePresent;
    public string SoftwareStateDescription { get; set; } = string.Empty;
    public string PolicyViolationScope { get; set; } = string.Empty;

    // Artifact and target process locations
    public string EvidenceSource { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public string? FileOrModulePath { get => FilePath; set => FilePath = value; }
    public long? FileSizeBytes { get; set; }
    public string? FileSha256 { get; set; }

    // Timestamps
    public DateTimeOffset? ObservedTimestamp { get; set; }
    public DateTimeOffset? Timestamp { get => ObservedTimestamp; set => ObservedTimestamp = value; }
    public string TimestampReliability { get; set; } = string.Empty;
    public bool IsInScanWindow { get; set; }

    // Process context
    public int? ProcessId { get; set; }
    public int? TargetProcessId { get => ProcessId; set => ProcessId = value; }
    public string? ProcessName { get; set; }
    public string? TargetProcessName { get => ProcessName; set => ProcessName = value; }
    public string? ProcessCommandLine { get; set; }

    // Forensics interpretation, limitations, and recommendations
    public string TechnicalExplanation { get; set; } = string.Empty;
    public string Interpretation { get; set; } = string.Empty;
    public string Limitations { get; set; } = string.Empty;
    public string RecommendedReview { get; set; } = string.Empty;
    public string SuggestedNextChecks { get => RecommendedReview; set => RecommendedReview = value; }
    public string WhyItMatters { get; set; } = string.Empty;
    public string AlternativeLegitimateExplanations { get; set; } = string.Empty;
    public string WhatIsProven { get; set; } = string.Empty;
    public string WhatIsNotProven { get; set; } = string.Empty;
    public string EvidenceStrengtheningFinding { get; set; } = string.Empty;
    public string EvidenceWeakeningFinding { get; set; } = string.Empty;
    public string EvidenceClusterId { get; set; } = string.Empty;
    public List<string> RelatedEvidenceIds { get; set; } = new();

    public object? SupportingEvidencePayload { get; set; }

    /// <summary>
    /// Returns the file or module path with user profile folder names redacted for privacy.
    /// </summary>
    public string GetRedactedPath()
    {
        if (string.IsNullOrEmpty(FilePath)) return string.Empty;
        return CommandLineRedactor.RedactPath(FilePath);
    }
}

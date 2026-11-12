using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Process;

/// <summary>
/// Centralized privacy and redaction boundary for the Minecraft SS Forensics platform.
/// Strictly scrubs user personal identifiers, authentication secrets, passwords, provider API keys,
/// and local user home directory paths before evidence is serialized, displayed, or exported.
/// </summary>
public static class PrivacyBoundary
{
    // 1. Session and Authentication Tokens (supporting space, '=', quotes, and URI parameters)
    private static readonly Regex AccessTokenRegex = new(
        @"(?:--accessToken[\s=]+[""']?)([^""'\s]+)(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UuidRegex = new(
        @"(?:--uuid[\s=]+[""']?)([0-9a-fA-F\-]{32,36})(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SessionRegex = new(
        @"(?:--session[\s=]+[""']?)([^""'\s]+)(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UserPropertiesRegex = new(
        @"(?:--userProperties[\s=]+[""']?)({[^}]+}|\[[^\]]+\]|[^""'\s]+)(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PasswordRegex = new(
        @"(?:--password[\s=]+[""']?)([^""'\s]+)(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // 2. JVM System Property Secrets (-Dauth...=..., -Dtoken...=...)
    private static readonly Regex JvmPropertySecretRegex = new(
        @"(-D(?:auth|token|secret|password|key)[^\s=]*[\s=]+[""']?)([^""'\s]+)(?:[""']?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // 3. API Key & Auth Headers in URLs or Configuration strings
    private static readonly Regex UrlSecretRegex = new(
        @"((?:token|key|api_key|apikey|secret|password|access_token|auth)=)([^&\s""']+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // 4. File Paths (Windows C:\Users\<name>\..., Unix /home/<name>/..., macOS /Users/<name>/...)
    // Handles normal slashes and JSON-escaped double backslashes
    private static readonly Regex WindowsUserPathRegex = new(
        @"([A-Za-z]:\\Users\\)[^\\]+(\\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex WindowsUserPathEscapedRegex = new(
        @"([A-Za-z]:\\\\Users\\\\)[^\\]+(\\\\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UnixUserPathRegex = new(
        @"(/home/)[^/]+(/)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MacUserPathRegex = new(
        @"(/Users/)[^/]+(/)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessHostIdentityRegex = new(
        @"(?<=proc:)[^:]+(?=:\d+:)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// General string sanitizer redacting credentials, tokens, and personal user paths.
    /// </summary>
    public static string RedactString(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return string.Empty;

        return RedactPath(RedactCommandLine(text));
    }

    /// <summary>
    /// Redacts all sensitive command-line parameters, tokens, credentials, and user paths from a string.
    /// </summary>
    public static string RedactCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return string.Empty;

        string redacted = commandLine;

        // Scrub session tokens with space or '='
        redacted = Regex.Replace(redacted, @"(--accessToken[\s=]+)(?:""[^""]*""|'[^']*'|\S+)", "$1[REDACTED_ACCESS_TOKEN]", RegexOptions.IgnoreCase);
        redacted = Regex.Replace(redacted, @"(--uuid[\s=]+)(?:""[^""]*""|'[^']*'|[0-9a-fA-F\-]{32,36})", "$1[REDACTED_UUID]", RegexOptions.IgnoreCase);
        redacted = Regex.Replace(redacted, @"(--session[\s=]+)(?:""[^""]*""|'[^']*'|\S+)", "$1[REDACTED_SESSION]", RegexOptions.IgnoreCase);
        redacted = Regex.Replace(redacted, @"(--userProperties[\s=]+)(?:""[^""]*""|'[^']*'|\S+)", "$1[REDACTED_USER_PROPERTIES]", RegexOptions.IgnoreCase);
        redacted = Regex.Replace(redacted, @"(--password[\s=]+)(?:""[^""]*""|'[^']*'|\S+)", "$1[REDACTED_PASSWORD]", RegexOptions.IgnoreCase);

        // Scrub JVM secrets
        redacted = JvmPropertySecretRegex.Replace(redacted, "$1[REDACTED_SECRET]");

        // Scrub URL query parameter secrets
        redacted = UrlSecretRegex.Replace(redacted, "$1[REDACTED_CREDENTIAL]");

        // Scrub user paths
        redacted = RedactPath(redacted);

        return redacted;
    }

    /// <summary>
    /// Redacts personal user profile directory names from file paths while preserving the subpath.
    /// Example: C:\Users\JohnDoe\AppData\Local\Temp\mod.jar -> C:\Users\[REDACTED_USER]\AppData\Local\Temp\mod.jar
    /// </summary>
    public static string RedactPath(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return string.Empty;

        string redacted = filePath;

        redacted = WindowsUserPathRegex.Replace(redacted, "${1}[REDACTED_USER]${2}");
        redacted = WindowsUserPathEscapedRegex.Replace(redacted, "${1}[REDACTED_USER]${2}");
        redacted = UnixUserPathRegex.Replace(redacted, "${1}[REDACTED_USER]${2}");
        redacted = MacUserPathRegex.Replace(redacted, "${1}[REDACTED_USER]${2}");
        redacted = ProcessHostIdentityRegex.Replace(redacted, "[REDACTED_HOST]");

        return redacted;
    }

    private static readonly System.Text.Json.JsonSerializerOptions CloneOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Creates a complete, non-mutating deep clone of a StandaloneReport instance.
    /// </summary>
    public static StandaloneReport CloneReport(StandaloneReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        string json = System.Text.Json.JsonSerializer.Serialize(report, CloneOptions);
        var copy = System.Text.Json.JsonSerializer.Deserialize<StandaloneReport>(json, CloneOptions);
        return copy ?? throw new InvalidOperationException("Failed to deep clone standalone report.");
    }

    /// <summary>
    /// Creates a deep-cloned, privacy-redacted copy of the standalone report for export or display,
    /// ensuring the original raw forensic report remains completely untouched and authentic in memory.
    /// </summary>
    public static StandaloneReport CreateSanitizedCopy(StandaloneReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var copy = CloneReport(report);
        SanitizeReportForExport(copy);
        return copy;
    }

    /// <summary>
    /// Applies strict privacy boundary redaction across an entire report in-place prior to export or display.
    /// </summary>
    public static void SanitizeReportForExport(StandaloneReport report)
    {
        if (report == null) return;

        // Redact direct system identity fields instead of exporting personal host/account names.
        report.TargetSystem.MachineIdentifier = "[REDACTED_HOST]";
        report.TargetSystem.UserIdentifier = "[REDACTED_USER]";

        // 1. Sanitize runtime metadata
        report.JavaRuntime.JavaExecutablePath = RedactString(report.JavaRuntime.JavaExecutablePath);
        report.JavaRuntime.RawJvmArguments = RedactCommandLine(report.JavaRuntime.RawJvmArguments);
        report.JavaRuntime.JavaHome = RedactString(report.JavaRuntime.JavaHome);

        // 1. Sanitize running processes
        foreach (var proc in report.RunningProcesses)
        {
            proc.ProcessInstanceId = RedactString(proc.ProcessInstanceId);
            proc.ParentProcessName = RedactString(proc.ParentProcessName);
            if (!string.IsNullOrEmpty(proc.SanitizedCommandLine))
            {
                proc.SanitizedCommandLine = RedactCommandLine(proc.SanitizedCommandLine);
            }
            if (!string.IsNullOrEmpty(proc.ExecutablePath))
            {
                proc.ExecutablePath = RedactPath(proc.ExecutablePath);
            }
        }

        // 2. Sanitize loaded modules
        foreach (var mod in report.LoadedModules)
        {
            mod.ProcessInstanceId = RedactString(mod.ProcessInstanceId);
            mod.ModuleInstanceId = RedactString(mod.ModuleInstanceId);
            if (!string.IsNullOrEmpty(mod.ModulePath))
            {
                mod.ModulePath = RedactPath(mod.ModulePath);
            }
        }

        // 3. Sanitize mod inventory
        foreach (var mod in report.ModInventory)
        {
            if (!string.IsNullOrEmpty(mod.FullPath))
            {
                mod.FullPath = RedactPath(mod.FullPath);
            }
        }

        // 4. Sanitize file discoveries
        foreach (var file in report.FileDiscoveries)
        {
            if (!string.IsNullOrEmpty(file.FilePath))
            {
                file.FilePath = RedactPath(file.FilePath);
            }
        }

        // 5. Sanitize findings
        foreach (var finding in report.Findings)
        {
            if (!string.IsNullOrEmpty(finding.FilePath))
            {
                finding.FilePath = RedactPath(finding.FilePath);
            }
            if (!string.IsNullOrEmpty(finding.ProcessCommandLine))
            {
                finding.ProcessCommandLine = RedactCommandLine(finding.ProcessCommandLine);
            }
            finding.ProcessName = RedactString(finding.ProcessName);
            finding.TargetProcessName = RedactString(finding.TargetProcessName);
            finding.EvidenceSource = RedactString(finding.EvidenceSource);
            finding.Interpretation = RedactString(finding.Interpretation);
            finding.WhatIsProven = RedactString(finding.WhatIsProven);
            finding.WhatIsNotProven = RedactString(finding.WhatIsNotProven);
            finding.AlternativeLegitimateExplanations = RedactString(finding.AlternativeLegitimateExplanations);
            finding.Limitations = RedactString(finding.Limitations);
            if (!string.IsNullOrEmpty(finding.TechnicalExplanation))
            {
                finding.TechnicalExplanation = RedactCommandLine(finding.TechnicalExplanation);
            }
        }

        // 6. Sanitize installations
        foreach (var inst in report.MinecraftInstallations)
        {
            if (!string.IsNullOrEmpty(inst.RootPath))
            {
                inst.RootPath = RedactPath(inst.RootPath);
            }
        }

        // 7. Sanitize execution history
        foreach (var hist in report.ExecutionHistory)
        {
            hist.Details = RedactString(hist.Details);
            hist.ParseFailureReason = RedactString(hist.ParseFailureReason);
            if (!string.IsNullOrEmpty(hist.ApplicationPath))
            {
                hist.ApplicationPath = RedactPath(hist.ApplicationPath);
            }
        }

        // 8. Sanitize evidence references, correlation explanations, and collected service paths.
        foreach (var evidence in report.EvidenceItems)
        {
            evidence.FilePath = RedactString(evidence.FilePath);
            evidence.SourceArtifact = RedactString(evidence.SourceArtifact);
            evidence.ProcessIdentity = RedactString(evidence.ProcessIdentity);
            evidence.Description = RedactString(evidence.Description);
            evidence.Title = RedactString(evidence.Title);
            evidence.Limitations = RedactString(evidence.Limitations);
        }

        foreach (var assessment in report.CorrelatedAssessments)
        {
            assessment.SoftwareName = RedactString(assessment.SoftwareName);
            assessment.FilePath = RedactString(assessment.FilePath);
            assessment.StateDescription = RedactString(assessment.StateDescription);
            assessment.PolicyEvaluationExplanation = RedactString(assessment.PolicyEvaluationExplanation);
            assessment.WhatIsProven = RedactString(assessment.WhatIsProven);
            assessment.WhatIsNotProven = RedactString(assessment.WhatIsNotProven);
        }

        foreach (var service in report.ServicesAndDrivers)
        {
            service.ImagePath = RedactString(service.ImagePath);
            service.Name = RedactString(service.Name);
            service.DisplayName = RedactString(service.DisplayName);
        }

        // 9. Rebuild graph indices after redacting entity identifiers and all path-bearing properties.
        if (report.EvidenceGraph != null)
        {
            var original = report.EvidenceGraph;
            var sanitizedGraph = new MinecraftSsForensics.Scanner.Graph.EvidenceGraph
            {
                IsCaptured = original.IsCaptured,
                IsResourceBounded = original.IsResourceBounded,
                IsValid = original.IsValid,
                ValidationErrors = new List<string>(original.ValidationErrors.Select(RedactString))
            };
            var idMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int collisionIndex = 0;

            foreach (var node in original.Nodes)
            {
                string safeId = RedactString(node.EntityId);
                if (idMap.Values.Contains(safeId, StringComparer.OrdinalIgnoreCase))
                    safeId = $"{safeId}:redacted-{++collisionIndex}";
                idMap[node.EntityId] = safeId;

                var safeNode = new MinecraftSsForensics.Scanner.Graph.GraphEntity
                {
                    EntityId = safeId,
                    Type = node.Type,
                    FirstObservedUtc = node.FirstObservedUtc,
                    LastObservedUtc = node.LastObservedUtc,
                    ProvenanceSources = node.ProvenanceSources.Select(RedactString).ToList(),
                    Properties = node.Properties.ToDictionary(
                        pair => RedactString(pair.Key),
                        pair => RedactString(pair.Value),
                        StringComparer.OrdinalIgnoreCase)
                };
                sanitizedGraph.AddNode(safeNode);
            }

            foreach (var edge in original.Edges)
            {
                if (!idMap.TryGetValue(edge.SourceEntityId, out var sourceId) ||
                    !idMap.TryGetValue(edge.TargetEntityId, out var targetId))
                    continue;

                sanitizedGraph.AddEdge(new MinecraftSsForensics.Scanner.Graph.GraphEdge
                {
                    EdgeId = RedactString(edge.EdgeId),
                    SourceEntityId = sourceId,
                    TargetEntityId = targetId,
                    Type = edge.Type,
                    Confidence = edge.Confidence,
                    Provenance = RedactString(edge.Provenance),
                    AssertedRelationship = RedactString(edge.AssertedRelationship),
                    Limitations = RedactString(edge.Limitations),
                    CreatedAtUtc = edge.CreatedAtUtc
                });
            }

            sanitizedGraph.Validate(out _);
            report.EvidenceGraph = sanitizedGraph;
        }
    }
}

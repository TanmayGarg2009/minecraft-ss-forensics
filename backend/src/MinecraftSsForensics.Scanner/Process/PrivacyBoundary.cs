using System;
using System.Collections.Generic;
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

        // 1. Sanitize running processes
        foreach (var proc in report.RunningProcesses)
        {
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
            if (!string.IsNullOrEmpty(hist.ApplicationPath))
            {
                hist.ApplicationPath = RedactPath(hist.ApplicationPath);
            }
        }

        // 8. Sanitize Evidence Graph
        if (report.EvidenceGraph != null)
        {
            foreach (var node in report.EvidenceGraph.Nodes)
            {
                var keysToUpdate = new List<string>();
                foreach (var (k, v) in node.Properties)
                {
                    if (k.Contains("Path", StringComparison.OrdinalIgnoreCase) ||
                        k.Contains("CommandLine", StringComparison.OrdinalIgnoreCase))
                    {
                        keysToUpdate.Add(k);
                    }
                }

                foreach (var k in keysToUpdate)
                {
                    node.Properties[k] = RedactString(node.Properties[k]);
                }
            }
        }
    }
}

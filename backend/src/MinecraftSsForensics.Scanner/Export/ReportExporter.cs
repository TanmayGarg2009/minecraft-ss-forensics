using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Scanner.Process;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Generates portable, offline forensic report exports in Full Forensic JSON and AI-Friendly Markdown.
/// Designed for offline second-stage AI analysis and human forensic reviews with zero backend dependence.
/// </summary>
public static class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Generates a standardized export document in the requested format.
    /// </summary>
    public static ReportExportResult GenerateExport(
        SubmitReportRequest report,
        ReportExportFormat format,
        string? publicId = null)
    {
        string filename = GenerateSuggestedFilename(report, format, publicId);

        return format switch
        {
            ReportExportFormat.Markdown => new ReportExportResult
            {
                Content = ExportToMarkdown(report, publicId),
                SuggestedFileName = filename,
                MimeType = "text/markdown",
                Format = ReportExportFormat.Markdown
            },
            _ => new ReportExportResult
            {
                Content = ExportToJson(report, publicId),
                SuggestedFileName = filename,
                MimeType = "application/json",
                Format = ReportExportFormat.Json
            }
        };
    }

    /// <summary>
    /// Generates a consistent, descriptive filename containing the scan date and report identifier.
    /// </summary>
    public static string GenerateSuggestedFilename(
        SubmitReportRequest report,
        ReportExportFormat format,
        string? publicId = null)
    {
        string dateStr = (report.ScanCompletedAt ?? report.ScanStartedAt ?? DateTimeOffset.UtcNow).ToString("yyyy-MM-dd");
        string idPart = !string.IsNullOrWhiteSpace(publicId) ? publicId.Trim() : "local";
        string ext = format == ReportExportFormat.Markdown ? "md" : "json";

        return $"MinecraftForensicReport_{dateStr}_{idPart}.{ext}";
    }

    /// <summary>
    /// Exports the full structured report as a self-contained, valid JSON document.
    /// Strictly excludes any deletion credentials and redacts sensitive session tokens.
    /// </summary>
    public static string ExportToJson(SubmitReportRequest report, string? publicId = null)
    {
        // Sanitize sensitive process command lines
        var sanitizedFindings = report.Findings.Select(f => new FindingSubmissionDto
        {
            RuleId = f.RuleId,
            Title = f.Title,
            Category = f.Category,
            Severity = f.Severity,
            Confidence = f.Confidence,
            Explanation = f.Explanation,
            ObservedEvidence = f.ObservedEvidence,
            FilePath = f.FilePath,
            FileSizeBytes = f.FileSizeBytes,
            FileSha256 = f.FileSha256,
            FileCreatedTime = f.FileCreatedTime,
            FileModifiedTime = f.FileModifiedTime,
            FileLastAccessTime = f.FileLastAccessTime,
            ProcessId = f.ProcessId,
            ProcessName = f.ProcessName,
            ProcessCommandLine = !string.IsNullOrEmpty(f.ProcessCommandLine)
                ? CommandLineRedactor.Redact(f.ProcessCommandLine)
                : null,
            FirstObservedAt = f.FirstObservedAt,
            LastObservedAt = f.LastObservedAt,
            EvidenceSource = f.EvidenceSource,
            DetectionRuleVersion = f.DetectionRuleVersion,
            LimitationsAndFalsePositives = f.LimitationsAndFalsePositives
        }).ToList();

        // Sanitize raw JVM argument content in evidence items
        var sanitizedEvidence = report.EvidenceItems.Select(e => new EvidenceSubmissionDto
        {
            PublicEvidenceId = e.PublicEvidenceId,
            Type = e.Type,
            Title = e.Title,
            Description = e.Description,
            RawContent = e.Type == "JvmArguments" && !string.IsNullOrEmpty(e.RawContent)
                ? CommandLineRedactor.Redact(e.RawContent)
                : e.RawContent,
            StructuredPayload = e.StructuredPayload,
            Sha256Hash = e.Sha256Hash,
            IsAvailable = e.IsAvailable,
            DiagnosticMessage = e.DiagnosticMessage,
            CapturedAt = e.CapturedAt
        }).ToList();

        var document = new
        {
            exportMetadata = new
            {
                exportSchemaVersion = "1.0.0",
                exportFormat = "FullForensicJson",
                exportedAtUtc = DateTimeOffset.UtcNow,
                reportId = publicId ?? "LOCAL-PRE-UPLOAD",
                isLocalExport = string.IsNullOrEmpty(publicId),
                exporter = "Minecraft SS Forensics Portable Exporter v1.0.0",
                redactionDisclosure = "Minecraft session tokens, account passwords, and player deletion credentials are strictly excluded or redacted."
            },
            report = new
            {
                report.SchemaVersion,
                report.ScannerVersion,
                report.ScanMode,
                report.OsName,
                report.OsVersion,
                report.OsArchitecture,
                report.ScanStartedAt,
                report.ScanCompletedAt,
                report.DetectedMinecraftVersions,
                report.DetectedLoaders,
                report.AppliedPolicyName,
                report.AppliedPolicyVersion,
                report.AppliedGamemode,
                report.AppliedPolicyRulesUrl,
                report.ConsentConfirmation,
                report.CollectionCoverage,
                report.RetentionDays,
                findings = sanitizedFindings,
                evidenceItems = sanitizedEvidence,
                report.TimelineEvents,
                report.DiagnosticItems
            }
        };

        return JsonSerializer.Serialize(document, JsonOptions);
    }

    /// <summary>
    /// Generates a readable, 13-section Markdown report structured for human reviews
    /// and second-stage offline AI forensic analysis.
    /// </summary>
    public static string ExportToMarkdown(SubmitReportRequest report, string? publicId = null)
    {
        var sb = new StringBuilder();
        string reportTitleId = !string.IsNullOrWhiteSpace(publicId) ? publicId : "LOCAL-PRE-UPLOAD";
        string scanDate = (report.ScanCompletedAt ?? report.ScanStartedAt ?? DateTimeOffset.UtcNow).ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

        // -------------------------------------------------------------
        // 1. Report Overview
        // -------------------------------------------------------------
        sb.AppendLine("# Minecraft Screenshare Forensic Investigation Report");
        sb.AppendLine();
        sb.AppendLine("## 1. Report Overview");
        sb.AppendLine($"- **Report ID**: `{reportTitleId}`");
        sb.AppendLine($"- **Scan Mode**: `{report.ScanMode}`");
        sb.AppendLine($"- **Scanner Version**: `{report.ScannerVersion}` (Schema: `{report.SchemaVersion}`)");
        sb.AppendLine($"- **Operating System**: `{report.OsName} {report.OsVersion} ({report.OsArchitecture})`");
        sb.AppendLine($"- **Scan Started**: `{report.ScanStartedAt:u}`");
        sb.AppendLine($"- **Scan Completed**: `{report.ScanCompletedAt:u}`");
        sb.AppendLine($"- **Export Generated**: `{DateTimeOffset.UtcNow:u}`");
        sb.AppendLine($"- **Active Server Gamemode Ruleset**: `{report.AppliedGamemode ?? "Standard PvP"}`");
        if (!string.IsNullOrEmpty(report.AppliedPolicyName))
        {
            sb.AppendLine($"- **Applied Policy Rulebook**: `{report.AppliedPolicyName}` (v`{report.AppliedPolicyVersion ?? "1.0"}`)");
        }
        if (!string.IsNullOrEmpty(report.AppliedPolicyRulesUrl))
        {
            sb.AppendLine($"- **Server Rules Documentation**: {report.AppliedPolicyRulesUrl}");
        }
        sb.AppendLine($"- **Detected Minecraft Versions**: {FormatList(report.DetectedMinecraftVersions)}");
        sb.AppendLine($"- **Detected Mod Loaders & Clients**: {FormatList(report.DetectedLoaders)}");
        sb.AppendLine($"- **Player Scope Consent Given**: `{(report.ConsentConfirmation?.ConsentGiven == true ? "YES (Explicit Consent Confirmed)" : "NO")}`");
        sb.AppendLine();

        // -------------------------------------------------------------
        // 2. Scan Completeness & Limitations
        // -------------------------------------------------------------
        sb.AppendLine("## 2. Scan Completeness and Limitations");
        if (report.CollectionCoverage != null)
        {
            sb.AppendLine($"- **Total Diagnostic Checks**: `{report.CollectionCoverage.TotalChecks}`");
            sb.AppendLine($"- **Passed Checks**: `{report.CollectionCoverage.PassedChecks}`");
            sb.AppendLine($"- **Flagged Checks**: `{report.CollectionCoverage.FlaggedChecks}`");
            sb.AppendLine($"- **Unavailable / Inaccessible Checks**: `{report.CollectionCoverage.UnavailableChecks}`");
        }
        sb.AppendLine();
        sb.AppendLine("> **Forensic Boundary Notice:** This scanner operates exclusively in standard Windows user mode without kernel drivers or elevation. Deep system artifacts (such as Prefetch or raw NTFS USN journals) may report access denial on non-admin accounts. The presence of unavailable checks represents a boundary limitation, not proof of evasion or tampering.");
        sb.AppendLine();

        // -------------------------------------------------------------
        // 3. AI Analysis Guide
        // -------------------------------------------------------------
        sb.AppendLine("## 3. AI Analysis Guide");
        sb.AppendLine();
        sb.AppendLine("> **Instructions for AI Forensic Reviewer:**");
        sb.AppendLine("> You are reviewing a Minecraft screenshare forensic report. Analyze only the evidence contained in this report unless external research is explicitly requested.");
        sb.AppendLine(">");
        sb.AppendLine("> Separate:");
        sb.AppendLine("> - Directly observed facts.");
        sb.AppendLine("> - Verified artifact identity.");
        sb.AppendLine("> - Server-policy violations.");
        sb.AppendLine("> - Correlations between independent findings.");
        sb.AppendLine("> - Inferences.");
        sb.AppendLine("> - Unknowns and unavailable evidence.");
        sb.AppendLine(">");
        sb.AppendLine("> Do not assume that an unknown mod is malicious, that a renamed mod is a cheat, or that a hash mismatch proves malicious intent.");
        sb.AppendLine(">");
        sb.AppendLine("> Do not treat a file existing on disk as proof that it executed. Distinguish historical presence, current presence, process association, module loading, and evidence of actual behavior.");
        sb.AppendLine(">");
        sb.AppendLine("> Identify findings that deserve further investigation, explain possible false positives, and suggest concrete additional checks.");
        sb.AppendLine(">");
        sb.AppendLine("> Identify contradictions and gaps in the available evidence.");
        sb.AppendLine(">");
        sb.AppendLine("> Provide a concise executive summary, a prioritized list of findings, confidence explanations, and unanswered questions.");
        sb.AppendLine(">");
        sb.AppendLine("> Do not invent evidence or claim certainty beyond what the report supports.");
        sb.AppendLine();

        // -------------------------------------------------------------
        // 4. Key Findings
        // -------------------------------------------------------------
        sb.AppendLine("## 4. Key Findings");
        sb.AppendLine();
        if (report.Findings.Count == 0)
        {
            sb.AppendLine("No suspicious indicators or policy violations were flagged within the inspected scope.");
            sb.AppendLine();
        }
        else
        {
            for (int i = 0; i < report.Findings.Count; i++)
            {
                var f = report.Findings[i];
                sb.AppendLine($"### Finding {i + 1}: [{f.Severity.ToUpperInvariant()}] {f.Title}");
                sb.AppendLine($"- **Rule ID**: `{f.RuleId}` (Version: `{f.DetectionRuleVersion}`)");
                sb.AppendLine($"- **Category**: `{f.Category}`");
                sb.AppendLine($"- **Confidence**: `{f.Confidence}`");
                sb.AppendLine($"- **Evidence Source**: `{f.EvidenceSource}`");
                sb.AppendLine();
                sb.AppendLine($"**What was observed:**");
                sb.AppendLine($"{f.Explanation}");
                sb.AppendLine();
                sb.AppendLine($"**Supporting evidence:**");
                if (!string.IsNullOrEmpty(f.FilePath)) sb.AppendLine($"- File Path: `{f.FilePath}`");
                if (!string.IsNullOrEmpty(f.FileSha256)) sb.AppendLine($"- SHA-256 Digest: `{f.FileSha256}`");
                if (f.FileSizeBytes.HasValue) sb.AppendLine($"- File Size: `{f.FileSizeBytes.Value:N0} bytes ({f.FileSizeBytes.Value / 1024.0:F1} KB)`");
                if (f.ProcessId.HasValue) sb.AppendLine($"- Process: `{f.ProcessName}` (PID: `{f.ProcessId}`)");
                if (!string.IsNullOrEmpty(f.ProcessCommandLine)) sb.AppendLine($"- Command Line: `{CommandLineRedactor.Redact(f.ProcessCommandLine)}`");
                if (f.ObservedEvidence != null)
                {
                    sb.AppendLine($"- Observed Payload: `{JsonSerializer.Serialize(f.ObservedEvidence)}`");
                }
                sb.AppendLine();
                sb.AppendLine($"**Why it may matter:**");
                sb.AppendLine(GetWhyItMatters(f));
                sb.AppendLine();
                sb.AppendLine($"**Alternative explanations & false positives:**");
                sb.AppendLine(string.IsNullOrWhiteSpace(f.LimitationsAndFalsePositives)
                    ? "- Software version differences or non-standard mod configuration."
                    : $"- {f.LimitationsAndFalsePositives}");
                sb.AppendLine();
                sb.AppendLine($"**What it does not prove:**");
                sb.AppendLine(GetWhatItDoesNotProve(f));
                sb.AppendLine();
                sb.AppendLine($"**Additional checks that could clarify it:**");
                sb.AppendLine(GetSuggestedNextChecks(f));
                sb.AppendLine();
            }
        }

        // -------------------------------------------------------------
        // 5. Minecraft Installations & Environment Metadata
        // -------------------------------------------------------------
        sb.AppendLine("## 5. Minecraft Installations and Environment Metadata");
        sb.AppendLine();
        var jvmEvidence = report.EvidenceItems.FirstOrDefault(e => e.Type == "JvmArguments");
        if (jvmEvidence != null && !string.IsNullOrEmpty(jvmEvidence.RawContent))
        {
            sb.AppendLine("### Parsed JVM Launch Arguments");
            sb.AppendLine("```");
            sb.AppendLine(CommandLineRedactor.Redact(jvmEvidence.RawContent));
            sb.AppendLine("```");
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 6. Complete Mod Inventory
        // -------------------------------------------------------------
        sb.AppendLine("## 6. Complete Discovered Mod Inventory");
        sb.AppendLine();
        var modInventory = report.EvidenceItems.FirstOrDefault(e => e.Type == "ModInventory");
        var mods = DeserializeModInventory(modInventory?.StructuredPayload);

        if (mods.Count == 0)
        {
            sb.AppendLine("No mod JAR records were found or attached to this scan mode.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Mod Name | File Name | Size (KB) | SHA-256 Digest | Mod ID | Version | Loader |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");
            foreach (var m in mods)
            {
                string name = SanitizeMd(m.Name ?? m.FileName ?? "Unknown");
                string fileName = SanitizeMd(m.FileName ?? "Unknown");
                string size = m.Size != null ? $"{m.Size / 1024.0:F1}" : "N/A";
                string sha256 = !string.IsNullOrEmpty(m.Sha256)
                    ? $"`{m.Sha256[..Math.Min(16, m.Sha256.Length)]}...`"
                    : "No Hash";
                string modId = SanitizeMd(m.ModId ?? "-");
                string ver = SanitizeMd(m.Version ?? "-");
                string loader = SanitizeMd(m.Loader ?? "-");

                sb.AppendLine($"| **{name}** | `{fileName}` | {size} | {sha256} | `{modId}` | `{ver}` | `{loader}` |");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 7. Artifact Authenticity Verification
        // -------------------------------------------------------------
        sb.AppendLine("## 7. Artifact Authenticity Verification");
        sb.AppendLine();
        sb.AppendLine("> **Definition:** Artifact authenticity confirms whether a JAR byte-for-byte matches an official release published on Modrinth, CurseForge, or GitHub. Authenticity does NOT determine whether a mod is allowed under competitive server rules.");
        sb.AppendLine();

        if (mods.Count > 0)
        {
            sb.AppendLine("| Mod | File Name | Authenticity State | Provider | Project / Reference URL | Verification Notes |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- | :--- |");
            foreach (var m in mods)
            {
                string name = SanitizeMd(m.Name ?? m.FileName ?? "Unknown");
                string fileName = SanitizeMd(m.FileName ?? "Unknown");
                string state = m.VerificationState ?? (m.Verified ? "VERIFIED_EXACT_RELEASE" : "UNKNOWN_OR_UNLISTED");
                string provider = SanitizeMd(m.VerificationProvider ?? "None");
                string url = !string.IsNullOrEmpty(m.ProjectUrl) ? $"<{m.ProjectUrl}>" : "-";
                string notes = SanitizeMd(m.VerificationExplanation ?? "-");

                sb.AppendLine($"| **{name}** | `{fileName}` | `{state}` | {provider} | {url} | {notes} |");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 8. Server Policy Compliance
        // -------------------------------------------------------------
        sb.AppendLine("## 8. Server Policy Compliance");
        sb.AppendLine();
        sb.AppendLine($"- **Applied Gamemode**: `{report.AppliedGamemode ?? "Standard PvP"}`");
        sb.AppendLine($"- **Rulebook Version**: `{report.AppliedPolicyVersion ?? "1.0.0"}`");
        sb.AppendLine();
        sb.AppendLine("> **Core Principle:** Authenticity and gameplay policy are evaluated independently. An authentic release (e.g. Freecam) may be prohibited under competitive rules. An unlisted mod is not automatically a cheat.");
        sb.AppendLine();

        if (mods.Count > 0)
        {
            sb.AppendLine("| Mod Name | Gameplay Policy | Behavioral Domain | Policy Rationale | Restrictions / Conditions |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");
            foreach (var m in mods)
            {
                string name = SanitizeMd(m.Name ?? m.FileName ?? "Unknown");
                string pol = m.GameplayPolicy ?? m.Policy ?? "UNKNOWN";
                string behavior = SanitizeMd(m.BehaviorCategory ?? "None");
                string reason = SanitizeMd(m.PolicyReason ?? "Evaluated against active rulebook.");
                string conditions = SanitizeMd(m.RestrictionConditions ?? "-");

                sb.AppendLine($"| **{name}** | `{pol}` | `{behavior}` | {reason} | {conditions} |");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 9. Process & Runtime Module Findings
        // -------------------------------------------------------------
        sb.AppendLine("## 9. Process and Runtime Module Findings");
        sb.AppendLine();
        var procEvidence = report.EvidenceItems.FirstOrDefault(e => e.Type == "LoadedModules");
        var procFindings = report.Findings.Where(f => f.Category == "ProcessInjection" || f.EvidenceSource == "ProcessMemoryMetadata").ToList();

        if (procFindings.Count == 0 && procEvidence == null)
        {
            sb.AppendLine("No unsigned temp-mapped DLL modules or unauthorized memory injections detected.");
            sb.AppendLine();
        }
        else
        {
            foreach (var pf in procFindings)
            {
                sb.AppendLine($"- **{pf.Title}** (PID: `{pf.ProcessId}`): {pf.Explanation}");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 10. Log and Historical Evidence
        // -------------------------------------------------------------
        sb.AppendLine("## 10. Log and Historical Evidence");
        sb.AppendLine();
        var histFindings = report.Findings.Where(f => f.Category == "ExecutionArtifacts" || f.Category == "FileDeletion" || f.EvidenceSource == "Prefetch" || f.EvidenceSource == "BamDam" || f.EvidenceSource == "UsnJournal").ToList();

        if (histFindings.Count == 0)
        {
            sb.AppendLine("No historical execution traces, deleted cheat artifacts, or suspicious session events found.");
            sb.AppendLine();
        }
        else
        {
            foreach (var hf in histFindings)
            {
                sb.AppendLine($"- **[{hf.Severity}] {hf.Title}**: {hf.Explanation}");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 11. Evidence Correlation and Timeline
        // -------------------------------------------------------------
        sb.AppendLine("## 11. Evidence Correlation and Timeline");
        sb.AppendLine();
        if (report.TimelineEvents.Count == 0)
        {
            sb.AppendLine("No correlated timeline events recorded.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Timestamp (UTC) | Category | Source | Event Description | Confidence |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");
            foreach (var evt in report.TimelineEvents.OrderBy(t => t.Timestamp))
            {
                string time = evt.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
                string cat = SanitizeMd(evt.Category);
                string src = SanitizeMd(evt.Source);
                string desc = SanitizeMd(evt.Description);
                string conf = evt.Confidence;

                sb.AppendLine($"| `{time}` | `{cat}` | `{src}` | {desc} | `{conf}` |");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 12. Failed, Skipped, or Unavailable Checks
        // -------------------------------------------------------------
        sb.AppendLine("## 12. Failed, Skipped, or Unavailable Checks");
        sb.AppendLine();
        if (report.DiagnosticItems.Count == 0)
        {
            sb.AppendLine("All scheduled diagnostic checks completed without errors or access restrictions.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Check Name | Source | Status | Reason / Limitation | Staff Recommendation |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");
            foreach (var diag in report.DiagnosticItems)
            {
                string name = SanitizeMd(diag.CheckName);
                string src = SanitizeMd(diag.Source);
                string status = diag.Status;
                string reason = SanitizeMd(diag.Reason);
                string rec = SanitizeMd(diag.Recommendation ?? "-");

                sb.AppendLine($"| **{name}** | `{src}` | `{status}` | {reason} | {rec} |");
            }
            sb.AppendLine();
        }

        // -------------------------------------------------------------
        // 13. Questions Requiring Further Investigation
        // -------------------------------------------------------------
        sb.AppendLine("## 13. Questions Requiring Further Investigation");
        sb.AppendLine();
        var questions = GenerateInvestigationQuestions(report, mods);
        foreach (var q in questions)
        {
            sb.AppendLine($"- {q}");
        }
        sb.AppendLine();

        // -------------------------------------------------------------
        // 14. Full Structured Evidence Appendix
        // -------------------------------------------------------------
        sb.AppendLine("## 14. Full Structured Evidence Appendix");
        sb.AppendLine();
        sb.AppendLine("| Evidence ID | Type | Title | Status | Captured (UTC) |");
        sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");
        foreach (var ev in report.EvidenceItems)
        {
            string id = ev.PublicEvidenceId;
            string type = ev.Type;
            string title = SanitizeMd(ev.Title);
            string status = ev.IsAvailable ? "Available" : "Unavailable";
            string time = ev.CapturedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-";

            sb.AppendLine($"| `{id}` | `{type}` | {title} | `{status}` | `{time}` |");
        }
        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("*End of Forensic Report. Generated by Minecraft SS Forensics Stage 2 Platform.*");

        return sb.ToString();
    }

    // -------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------

    private static string FormatList(List<string>? list)
    {
        if (list == null || list.Count == 0) return "`None Detected`";
        return string.Join(", ", list.Select(i => $"`{i}`"));
    }

    private static string SanitizeMd(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        return text.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ").Trim();
    }

    private static string GetWhyItMatters(FindingSubmissionDto f)
    {
        string ruleId = f.RuleId.ToUpperInvariant();
        if (ruleId.Contains("PROHIBITED"))
            return "This mod provides direct mechanical or perspective advantages strictly disallowed under active competition rules.";
        if (ruleId.Contains("LOOKALIKE") || ruleId.Contains("METADATA-CONFLICT"))
            return "Renaming cheat archives to mimic trusted optimization utilities (e.g. Sodium) is a common evasion technique.";
        if (ruleId.Contains("HASH-MISMATCH"))
            return "Indicates bytecode modification. Repackaging cheats within legitimate mod releases avoids casual visual detection.";
        if (ruleId.Contains("PROC") || ruleId.Contains("MODULE"))
            return "Cheat software often maps unsigned dynamic libraries into javaw.exe from temporary directories to hide disk artifacts.";
        if (ruleId.Contains("HIST") || f.EvidenceSource == "Prefetch")
            return "Proves recent execution of the executable on the operating system within the historical window.";
        return "Forensic indicator helps staff assess whether unauthorized client modifications were active during gameplay.";
    }

    private static string GetWhatItDoesNotProve(FindingSubmissionDto f)
    {
        string ruleId = f.RuleId.ToUpperInvariant();
        if (ruleId.Contains("PROHIBITED"))
            return "Does NOT prove the file is malware or a hacked client. It may be an official release that is simply disallowed in this specific gamemode.";
        if (ruleId.Contains("HIST") || f.EvidenceSource == "Prefetch")
            return "Proves the executable existed and ran on disk, but does NOT prove it was executed or injected during the specific Minecraft match.";
        if (ruleId.Contains("HASH-MISMATCH"))
            return "Does not prove malicious intent; user-modified translations, custom patches, or asset customizations also alter the hash.";
        if (ruleId.Contains("LOOKALIKE"))
            return "Does not prove cheating; a player may have renamed a harmless utility for launcher sorting.";
        return "This individual indicator alone does not establish intentional cheating during match play.";
    }

    private static string GetSuggestedNextChecks(FindingSubmissionDto f)
    {
        string ruleId = f.RuleId.ToUpperInvariant();
        if (ruleId.Contains("PROHIBITED"))
            return "1. Check in-game keybinds and configuration screen for active features.\n2. Inquire if player uses this launcher profile for other servers or building.";
        if (ruleId.Contains("LOOKALIKE") || ruleId.Contains("HASH-MISMATCH"))
            return "1. Inspect internal archive entries and .class bytecode headers.\n2. Cross-reference file creation timestamp with session match times.";
        if (ruleId.Contains("PROC"))
            return "1. Check if recording software (OBS, Medal, Nvidia overlay) was active.\n2. Audit javaw.exe thread handles and loaded DLL exports.";
        if (ruleId.Contains("HIST"))
            return "1. Check NTFS USN Journal for exact deletion timestamps.\n2. Correlate Prefetch last run timestamp with server join logs.";
        return "1. Request explanation from player.\n2. Compare file timestamp against competitive match schedule.";
    }

    private static List<string> GenerateInvestigationQuestions(SubmitReportRequest report, List<ExportedModItem> mods)
    {
        var questions = new List<string>();

        var prohibitedMods = mods.Where(m => m.GameplayPolicy == "PROHIBITED" || m.Policy == "PROHIBITED").ToList();
        if (prohibitedMods.Count > 0)
        {
            questions.Add($"**Prohibited Mod Presence:** Why is `{string.Join(", ", prohibitedMods.Select(m => m.FileName))}` present in active mods? Was it toggled or active during match play?");
        }

        var conflictingMods = mods.Where(m => m.HasConflictingSignals).ToList();
        if (conflictingMods.Count > 0)
        {
            questions.Add($"**Contradictory Identity Signals:** Mod `{conflictingMods[0].FileName}` displays metadata conflict: `{conflictingMods[0].ConflictDetails}`. What is the source and purpose of this altered archive?");
        }

        var unlistedMods = mods.Where(m => m.VerificationState == "UNKNOWN_OR_UNLISTED" && m.GameplayPolicy != "PROHIBITED").ToList();
        if (unlistedMods.Count > 0)
        {
            questions.Add($"**Unlisted Artifacts:** `{unlistedMods.Count}` unlisted mod(s) found (`{string.Join(", ", unlistedMods.Take(3).Select(m => m.FileName))}`). What are their origins and functionalities?");
        }

        var unavailableChecks = report.DiagnosticItems.Where(d => d.Status != "Completed").ToList();
        if (unavailableChecks.Count > 0)
        {
            questions.Add($"**Check Coverage Gaps:** `{unavailableChecks.Count}` diagnostic check(s) could not be completed in user mode (`{string.Join(", ", unavailableChecks.Take(2).Select(d => d.CheckName))}`). Does staff policy require an elevated scan for this player tier?");
        }

        if (questions.Count == 0)
        {
            questions.Add("No unresolved contradictions or high-priority questions identified from this scan scope.");
        }

        return questions;
    }

    private class ExportedModItem
    {
        public string? Name { get; set; }
        public string? FileName { get; set; }
        public long? Size { get; set; }
        public string? Sha256 { get; set; }
        public string? ModId { get; set; }
        public string? Version { get; set; }
        public string? Loader { get; set; }
        public bool Verified { get; set; }
        public string? VerificationState { get; set; }
        public string? VerificationProvider { get; set; }
        public string? VerificationExplanation { get; set; }
        public string? ProjectUrl { get; set; }
        public string? GameplayPolicy { get; set; }
        public string? Policy { get; set; }
        public string? BehaviorCategory { get; set; }
        public string? PolicyReason { get; set; }
        public string? RestrictionConditions { get; set; }
        public bool HasConflictingSignals { get; set; }
        public string? ConflictDetails { get; set; }
    }

    private static List<ExportedModItem> DeserializeModInventory(object? payload)
    {
        var items = new List<ExportedModItem>();
        if (payload == null) return items;

        try
        {
            string json = payload is string s ? s : JsonSerializer.Serialize(payload);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    items.Add(new ExportedModItem
                    {
                        Name = GetStringProp(el, "name") ?? GetStringProp(el, "modName") ?? GetStringProp(el, "fileName"),
                        FileName = GetStringProp(el, "fileName"),
                        Size = GetLongProp(el, "sizeBytes") ?? GetLongProp(el, "fileSizeBytes"),
                        Sha256 = GetStringProp(el, "sha256"),
                        ModId = GetStringProp(el, "modId"),
                        Version = GetStringProp(el, "version"),
                        Loader = GetStringProp(el, "loader"),
                        Verified = el.TryGetProperty("verified", out var v) && v.GetBoolean(),
                        VerificationState = GetStringProp(el, "verificationState"),
                        VerificationProvider = GetStringProp(el, "verificationProvider"),
                        VerificationExplanation = GetStringProp(el, "verificationExplanation"),
                        ProjectUrl = GetStringProp(el, "projectUrl"),
                        GameplayPolicy = GetStringProp(el, "gameplayPolicy"),
                        Policy = GetStringProp(el, "policy"),
                        BehaviorCategory = GetStringProp(el, "behaviorCategory") ?? GetStringProp(el, "policyBehavior"),
                        PolicyReason = GetStringProp(el, "policyReason"),
                        RestrictionConditions = GetStringProp(el, "restrictionConditions"),
                        HasConflictingSignals = el.TryGetProperty("hasConflictingSignals", out var cs) && cs.GetBoolean(),
                        ConflictDetails = GetStringProp(el, "conflictDetails")
                    });
                }
            }
        }
        catch
        {
            // Fallback gracefully on parsing
        }

        return items;
    }

    private static string? GetStringProp(JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String)
            return p.GetString();
        return null;
    }

    private static long? GetLongProp(JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var p) && p.TryGetInt64(out long val))
            return val;
        return null;
    }
}

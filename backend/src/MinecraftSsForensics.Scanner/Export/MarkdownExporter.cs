using System;
using System.IO;
using System.Linq;
using System.Text;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Exports a StandaloneReport into an AI-friendly, 14-section Markdown investigation dossier.
/// Contains verbatim AI Analysis Guide instructions separating facts from analytical inferences.
/// </summary>
public static class MarkdownExporter
{
    public static string ExportToMarkdown(StandaloneReport report)
    {
        report.RecomputeSummaryCounts();

        var sb = new StringBuilder();

        // 1. Report Overview
        sb.AppendLine("# Minecraft Screenshare Forensic Investigation Report");
        sb.AppendLine();
        sb.AppendLine("## 1. Report Overview");
        sb.AppendLine($"- **Report ID**: `{report.ReportId}`");
        sb.AppendLine($"- **Schema Version**: `{report.SchemaVersion}`");
        sb.AppendLine($"- **Scanner Version**: `{report.ScannerVersion}` (`{report.ScannerBuild}`)");
        sb.AppendLine($"- **Scan Mode**: `{report.ScanMode}`");
        sb.AppendLine($"- **Operating System**: `{report.TargetSystem.OsName} {report.TargetSystem.OsVersion} ({report.TargetSystem.Architecture})`");
        sb.AppendLine($"- **Scan Started**: `{report.ScanStartedAt:u}`");
        sb.AppendLine($"- **Scan Completed**: `{report.ScanCompletedAt:u}`");
        sb.AppendLine($"- **Duration**: `{report.ScanDurationMs} ms`");
        sb.AppendLine($"- **Active Gamemode Ruleset**: `{report.PolicyEvaluation.AppliedGamemode}`");
        sb.AppendLine($"- **Applied Policy Rulebook**: `{report.PolicyEvaluation.AppliedPolicyName}` (v`{report.PolicyEvaluation.AppliedPolicyVersion}`)");
        sb.AppendLine($"- **Cryptographic SHA-256 Seal**: `{report.ReportIntegrityHash}`");
        sb.AppendLine($"- **Player Consent Confirmed**: `{(report.Consent.ConsentGiven ? "YES (Explicit Consent Confirmed)" : "NO")}`");
        sb.AppendLine($"- **Browser History Audit Consented**: `{(report.Consent.InspectBrowserHistory ? "YES" : "NO (Sensitive Category Excluded)")}`");
        sb.AppendLine();

        // 2. Scan Completeness & Limitations
        sb.AppendLine("## 2. Scan Completeness and Limitations");
        sb.AppendLine($"- **Total Diagnostic Checks**: `{report.SummaryCounts.TotalChecks}`");
        sb.AppendLine($"- **Passed Checks**: `{report.SummaryCounts.PassedChecks}`");
        sb.AppendLine($"- **Flagged Checks**: `{report.SummaryCounts.FlaggedChecks}`");
        sb.AppendLine($"- **Skipped Checks**: `{report.SummaryCounts.SkippedChecks}`");
        sb.AppendLine($"- **Unavailable Checks**: `{report.SummaryCounts.UnavailableChecks}`");
        sb.AppendLine($"- **Errors**: `{report.SummaryCounts.ErrorChecks}`");
        sb.AppendLine();
        sb.AppendLine("> **Forensic Boundary Notice:** This scanner operates exclusively in standard Windows user mode without kernel drivers or elevation. Deep system artifacts (such as Prefetch or raw NTFS USN journals) may report access denial on non-admin accounts. The presence of unavailable checks represents a boundary limitation, not proof of evasion or tampering.");
        sb.AppendLine();

        // 3. AI Analysis Guide
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

        // 4. Key Findings
        sb.AppendLine("## 4. Key Findings");
        sb.AppendLine();
        if (report.Findings.Count == 0)
        {
            sb.AppendLine("No suspicious indicators or cheat artifacts were flagged within the inspected scope.");
            sb.AppendLine();
        }
        else
        {
            for (int i = 0; i < report.Findings.Count; i++)
            {
                var f = report.Findings[i];
                sb.AppendLine($"### Finding {i + 1}: [{f.Classification.ToString().ToUpperInvariant()}] {f.DetectionName}");
                sb.AppendLine($"- **Rule ID**: `{f.RuleId}`");
                sb.AppendLine($"- **Category**: `{f.Category}`");
                sb.AppendLine($"- **Classification**: `{f.Classification}`");
                sb.AppendLine($"- **Confidence**: `{f.Confidence}`");
                sb.AppendLine($"- **Evidence Source**: `{f.EvidenceSource}`");
                sb.AppendLine();
                sb.AppendLine("**What was observed:**");
                sb.AppendLine(f.TechnicalExplanation);
                sb.AppendLine();
                sb.AppendLine("**Supporting evidence:**");
                if (!string.IsNullOrEmpty(f.FilePath)) sb.AppendLine($"- File Path: `{f.FilePath}`");
                if (!string.IsNullOrEmpty(f.FileSha256)) sb.AppendLine($"- SHA-256 Digest: `{f.FileSha256}`");
                if (f.FileSizeBytes.HasValue) sb.AppendLine($"- Size: `{f.FileSizeBytes.Value / 1024.0:F1} KB`");
                if (f.ProcessId.HasValue) sb.AppendLine($"- Process: `{f.ProcessName}` (PID: `{f.ProcessId}`)");
                sb.AppendLine();
                sb.AppendLine("**Why it may matter:**");
                sb.AppendLine(f.WhyItMatters);
                sb.AppendLine();
                sb.AppendLine("**Alternative explanations & false positives:**");
                sb.AppendLine(string.IsNullOrWhiteSpace(f.AlternativeLegitimateExplanations)
                    ? "- Software version differences or non-standard mod configuration."
                    : f.AlternativeLegitimateExplanations);
                sb.AppendLine();
                sb.AppendLine("**What it does not prove:**");
                sb.AppendLine(string.IsNullOrWhiteSpace(f.WhatIsNotProven)
                    ? "- Does not prove intentional cheating during the specific competitive match."
                    : f.WhatIsNotProven);
                sb.AppendLine();
            }
        }

        // 5. Minecraft Installations & Runtime
        sb.AppendLine("## 5. Minecraft Installations and Environment Metadata");
        sb.AppendLine();
        foreach (var inst in report.MinecraftInstallations)
        {
            sb.AppendLine($"- **{inst.Name}**: `{inst.RootPath}` (Exists: `{inst.Exists}`, Launcher: `{inst.LauncherType}`)");
        }
        if (!string.IsNullOrEmpty(report.JavaRuntime.RawJvmArguments))
        {
            sb.AppendLine();
            sb.AppendLine("### Parsed JVM Launch Arguments");
            sb.AppendLine("```");
            sb.AppendLine(report.JavaRuntime.RawJvmArguments);
            sb.AppendLine("```");
        }
        sb.AppendLine();

        // 6. Complete Mod Inventory
        sb.AppendLine("## 6. Complete Discovered Mod Inventory");
        sb.AppendLine();
        if (report.ModInventory.Count == 0)
        {
            sb.AppendLine("No mod JAR records found in inspected game folders.");
        }
        else
        {
            sb.AppendLine("| Mod Name | File Name | Size (KB) | SHA-256 | Authenticity | Policy |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- | :--- |");
            foreach (var m in report.ModInventory)
            {
                string sha = !string.IsNullOrEmpty(m.Sha256) ? $"`{m.Sha256[..Math.Min(16, m.Sha256.Length)]}...`" : "-";
                sb.AppendLine($"| **{m.Name}** | `{m.FileName}` | {m.FileSizeBytes / 1024.0:F1} | {sha} | `{m.VerificationState}` | `{m.GameplayPolicy}` |");
            }
        }
        sb.AppendLine();

        // 7. Policy Compliance
        sb.AppendLine("## 7. Server Policy Compliance");
        sb.AppendLine();
        sb.AppendLine($"- Allowed: `{report.PolicyEvaluation.AllowedCount}` | Prohibited: `{report.PolicyEvaluation.ProhibitedCount}` | Restricted: `{report.PolicyEvaluation.RestrictedCount}` | Needs Review: `{report.PolicyEvaluation.NeedsReviewCount}`");
        sb.AppendLine();

        // 8. Runtime & Modules
        sb.AppendLine("## 8. Process and Runtime Module Findings");
        sb.AppendLine();
        var tempMods = report.LoadedModules.Where(m => m.IsInTempDirectory).ToList();
        if (tempMods.Count == 0)
        {
            sb.AppendLine("No dynamic libraries loaded from temporary directories.");
        }
        else
        {
            sb.AppendLine("| Module Name | Path | Provenance Assessment |");
            sb.AppendLine("| :--- | :--- | :--- |");
            foreach (var tm in tempMods)
            {
                sb.AppendLine($"| **{tm.ModuleName}** | `{tm.FilePath}` | {tm.ProvenanceAssessment} |");
            }
        }
        sb.AppendLine();

        // 9. Diagnostics
        sb.AppendLine("## 9. Failed, Skipped, or Unavailable Checks");
        sb.AppendLine();
        var nonPassed = report.DiagnosticChecks.Where(c => c.Status != CheckStatus.PASSED).ToList();
        if (nonPassed.Count == 0)
        {
            sb.AppendLine("All scheduled diagnostic checks completed without error or access restriction.");
        }
        else
        {
            sb.AppendLine("| Check Name | Source | Status | Reason / Limitation |");
            sb.AppendLine("| :--- | :--- | :--- | :--- |");
            foreach (var np in nonPassed)
            {
                sb.AppendLine($"| **{np.CheckName}** | `{np.Source}` | `{np.Status}` | {np.Reason} |");
            }
        }
        sb.AppendLine();

        sb.AppendLine("---");
        sb.AppendLine("*Generated by Minecraft SS Forensics Standalone Edition.*");

        return sb.ToString();
    }
}

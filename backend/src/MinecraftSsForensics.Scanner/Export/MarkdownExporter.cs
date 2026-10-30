using System;
using System.IO;
using System.Linq;
using System.Text;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Exports a StandaloneReport into an AI-friendly, 14-section Markdown investigation dossier.
/// Contains verbatim AI Analysis Guide instructions separating facts from analytical inferences.
/// Employs reconciled summary totals and the standardized 12-column findings structure.
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

        // 2. Reconciled Summary Totals
        sb.AppendLine("## 2. Reconciled Summary Totals");
        sb.AppendLine();
        sb.AppendLine("| Metric Category | Count | Evidentiary Basis |");
        sb.AppendLine("| :--- | :---: | :--- |");
        sb.AppendLine($"| **Total Normalized Findings** | `{report.SummaryCounts.TotalFindings}` | Reconciled count across all forensic checks |");
        sb.AppendLine($"| **Critical Severity** | `{report.SummaryCounts.Critical}` | Confirmed Minecraft-associated cheat software or injection |");
        sb.AppendLine($"| **High Severity** | `{report.SummaryCounts.High}` | Prohibited possession violations or running cheat processes |");
        sb.AppendLine($"| **Medium Severity** | `{report.SummaryCounts.Medium}` | Disk cheat files, unverified temporary modules, historical traces |");
        sb.AppendLine($"| **Low Severity** | `{report.SummaryCounts.Low}` | Policy restrictions, browser history domain matches |");
        sb.AppendLine($"| **Informational** | `{report.SummaryCounts.Informational}` | Hardware connections, diagnostic environment records |");
        sb.AppendLine($"| **Confirmed Signatures** | `{report.SummaryCounts.ConfirmedSignatures}` | Matches against verified cheat signature catalog |");
        sb.AppendLine($"| **Runtime Observations** | `{report.SummaryCounts.RuntimeObservations}` | Processes, injected modules, or active scan window telemetry |");
        sb.AppendLine($"| **Disk-Only Findings** | `{report.SummaryCounts.DiskOnlyObservations}` | Files physically present on disk without runtime connection |");
        sb.AppendLine($"| **Incomplete / Failed Checks** | `{report.SummaryCounts.IncompleteOrFailedChecks}` | Telemetry boundary limitations (Unavailable / Error) |");
        sb.AppendLine();

        // 3. Investigation Verdict
        sb.AppendLine("## 3. Investigation Verdict");
        sb.AppendLine();
        sb.AppendLine($"> ### **{report.Verdict.OverallAssessment}**");
        sb.AppendLine($"> **Recommendation:** {report.Verdict.Recommendation}");
        if (report.Verdict.KeyTakeaways.Count > 0)
        {
            sb.AppendLine(">");
            sb.AppendLine("> **Key Takeaways:**");
            foreach (var t in report.Verdict.KeyTakeaways)
                sb.AppendLine($"> - {t}");
        }
        if (report.Verdict.UnansweredQuestions.Count > 0)
        {
            sb.AppendLine(">");
            sb.AppendLine("> **Unanswered Questions:**");
            foreach (var q in report.Verdict.UnansweredQuestions)
                sb.AppendLine($"> - {q}");
        }
        sb.AppendLine();

        // 4. AI Analysis Guide
        sb.AppendLine("## 4. AI Analysis Guide");
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
        sb.AppendLine();

        // 5. Findings Table (12 Columns)
        sb.AppendLine("## 5. Structured Forensic Findings Table");
        sb.AppendLine();
        if (report.Findings.Count == 0)
        {
            sb.AppendLine("No suspicious indicators or cheat artifacts were flagged within the inspected scope.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Severity | Finding | Category | Target Process | File/Module (Redacted) | Detection Method | Strength | Confidence | Timestamp | Interpretation | Limitations | Recommended Review |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

            foreach (var f in report.Findings)
            {
                string procStr = f.TargetProcessId.HasValue ? $"PID {f.TargetProcessId} ({f.TargetProcessName})" : "None";
                string pathStr = !string.IsNullOrEmpty(f.GetRedactedPath()) ? $"`{Path.GetFileName(f.GetRedactedPath())}`" : "-";
                string timeStr = f.ObservedTimestamp.HasValue ? f.ObservedTimestamp.Value.ToString("yyyy-MM-dd HH:mm") : "-";
                if (f.IsInScanWindow) timeStr += " (Active)";

                string interp = CleanCell(!string.IsNullOrEmpty(f.Interpretation) ? f.Interpretation : f.TechnicalExplanation);
                string limits = CleanCell(!string.IsNullOrEmpty(f.Limitations) ? f.Limitations : f.WhatIsNotProven);
                string review = CleanCell(!string.IsNullOrEmpty(f.RecommendedReview) ? f.RecommendedReview : f.SuggestedNextChecks);

                sb.AppendLine($"| **{f.Severity}** | {CleanCell(f.Finding)} | {f.EvidenceCategory} | {procStr} | {pathStr} | {f.DetectionMethod} | {f.EvidenceStrength} | {f.Confidence} | {timeStr} | {interp} | {limits} | {review} |");
            }
            sb.AppendLine();

            // Detailed Findings Dossier
            sb.AppendLine("## 6. Detailed Finding Breakdown");
            sb.AppendLine();
            for (int i = 0; i < report.Findings.Count; i++)
            {
                var f = report.Findings[i];
                sb.AppendLine($"### Finding {i + 1}: [{f.Severity}] {f.Finding}");
                sb.AppendLine($"- **Rule ID**: `{f.RuleId}`");
                sb.AppendLine($"- **Category**: `{f.EvidenceCategory}`");
                sb.AppendLine($"- **Severity**: `{f.Severity}`");
                sb.AppendLine($"- **Evidence Strength**: `{f.EvidenceStrength}`");
                sb.AppendLine($"- **Confidence**: `{f.Confidence}`");
                sb.AppendLine($"- **Detection Method**: `{f.DetectionMethod}`");
                sb.AppendLine($"- **Evidence Cluster ID**: `{f.EvidenceClusterId}`");
                sb.AppendLine($"- **Target Process**: {(f.TargetProcessId.HasValue ? $"PID {f.TargetProcessId} ({f.TargetProcessName})" : "None")}");
                sb.AppendLine($"- **File Path (Redacted)**: `{f.GetRedactedPath()}`");
                if (!string.IsNullOrEmpty(f.FileSha256)) sb.AppendLine($"- **SHA-256 Digest**: `{f.FileSha256}`");
                if (f.ObservedTimestamp.HasValue) sb.AppendLine($"- **Observed Timestamp**: `{f.ObservedTimestamp.Value:u}` (In Scan Window: `{f.IsInScanWindow}`)");
                sb.AppendLine();
                sb.AppendLine("**Technical Observation:**");
                sb.AppendLine(f.TechnicalExplanation);
                sb.AppendLine();
                sb.AppendLine("**Forensic Interpretation (What is proven):**");
                sb.AppendLine(!string.IsNullOrEmpty(f.Interpretation) ? f.Interpretation : f.WhatIsProven);
                sb.AppendLine();
                sb.AppendLine("**Evidentiary Limitations (What is NOT proven):**");
                sb.AppendLine(!string.IsNullOrEmpty(f.Limitations) ? f.Limitations : f.WhatIsNotProven);
                sb.AppendLine();
                sb.AppendLine("**Recommended Staff Review:**");
                sb.AppendLine(!string.IsNullOrEmpty(f.RecommendedReview) ? f.RecommendedReview : f.SuggestedNextChecks);
                sb.AppendLine();
            }
        }

        // 7. Evidence Correlation Assessments
        sb.AppendLine("## 7. Evidence Correlation Assessments");
        sb.AppendLine();
        if (report.CorrelatedAssessments.Count == 0)
        {
            sb.AppendLine("No multi-source correlated software assessments recorded.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Software / Artifact | State | Policy | Violation? | What is Proven | Evidentiary Limitations |");
            sb.AppendLine("| :--- | :--- | :--- | :---: | :--- | :--- |");
            foreach (var a in report.CorrelatedAssessments)
            {
                sb.AppendLine($"| **{a.SoftwareName}** | `{a.State}` | `{a.Policy}` | `{(a.IsPolicyViolation ? "VIOLATION" : "COMPLIANT")}` | {CleanCell(a.WhatIsProven)} | {CleanCell(a.WhatIsNotProven)} |");
            }
            sb.AppendLine();
        }

        // 8. Mod Inventory
        sb.AppendLine("## 8. Mod Inventory");
        sb.AppendLine();
        if (report.ModInventory.Count == 0)
        {
            sb.AppendLine("No mod JAR files discovered.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine("| Mod Name | File Name | SHA-256 | Verification | Policy |");
            sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");
            foreach (var m in report.ModInventory)
            {
                string hashShort = m.Sha256.Length >= 12 ? m.Sha256[..12] : m.Sha256;
                sb.AppendLine($"| **{m.Name}** | `{m.FileName}` | `{hashShort}...` | `{m.VerificationState}` | `{m.GameplayPolicy}` |");
            }
            sb.AppendLine();
        }

        // 9. Running Processes & Modules
        sb.AppendLine("## 9. Active Processes and Runtime Modules");
        sb.AppendLine();
        foreach (var p in report.RunningProcesses)
        {
            sb.AppendLine($"- **PID {p.ProcessId}**: `{p.ProcessName}` (Path: `{p.ExecutablePath}`, Started: `{p.StartTime}`)");
        }
        sb.AppendLine();

        // 10. Execution History & Staged Files
        sb.AppendLine("## 10. Execution History and Staged Files");
        sb.AppendLine();
        foreach (var f in report.FileDiscoveries)
        {
            sb.AppendLine($"- **Staged File**: `{f.FileName}` in `{f.FilePath}` ({f.FileSizeBytes} bytes, Modified: `{f.LastModified:u}`)");
        }
        foreach (var h in report.ExecutionHistory.Take(30))
        {
            sb.AppendLine($"- **[{h.Source}]** `{h.ApplicationName}`: `{h.Details}` ({h.LastExecutionTime})");
        }
        sb.AppendLine();

        // 11. Collection Diagnostics
        sb.AppendLine("## 11. Diagnostic Checks and Technical Limitations");
        sb.AppendLine();
        sb.AppendLine("| Check Name | Source | Status | Details |");
        sb.AppendLine("| :--- | :--- | :--- | :--- |");
        foreach (var d in report.DiagnosticChecks)
        {
            sb.AppendLine($"| **{d.CheckName}** | `{d.Source}` | `{d.Status}` | {CleanCell(d.Reason)} |");
        }
        sb.AppendLine();

        return sb.ToString();
    }

    public static void SaveToFile(StandaloneReport report, string filePath)
    {
        string md = ExportToMarkdown(report);
        File.WriteAllText(filePath, md, Encoding.UTF8);
    }

    private static string CleanCell(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "-";
        return text.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ").Trim();
    }
}

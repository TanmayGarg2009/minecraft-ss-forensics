using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.Export;

/// <summary>
/// Generates a completely self-contained, interactive HTML report designed for offline staff investigation.
/// Requires ZERO external dependencies, CDNs, or server infrastructure.
/// Strictly applies HTML-entity escaping to all untrusted evidentiary inputs to prevent XSS.
/// Adheres strictly to the 12-column severity table standard and reconciled category totals.
/// </summary>
public static class StandaloneHtmlExporter
{
    public static string ExportToHtml(StandaloneReport report)
    {
        report.RecomputeSummaryCounts();

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>Minecraft SS Forensics Report - {E(report.ReportId)}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine(GetEmbeddedCss());
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Top Navigation Bar
        sb.AppendLine("  <header class=\"navbar\">");
        sb.AppendLine("    <div class=\"nav-container\">");
        sb.AppendLine("      <div class=\"brand\">");
        sb.AppendLine("        <span class=\"shield-icon\">🛡️</span>");
        sb.AppendLine("        <div>");
        sb.AppendLine("          <h1 class=\"brand-title\">Minecraft SS Forensics</h1>");
        sb.AppendLine($"          <span class=\"brand-subtitle\">Standalone Investigation Report • v{E(report.ScannerVersion)}</span>");
        sb.AppendLine("        </div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"nav-actions no-print\">");
        sb.AppendLine($"        <span class=\"badge mode-badge\">{E(report.ScanMode)} SCAN</span>");
        sb.AppendLine("        <button class=\"btn\" onclick=\"window.print()\">🖨️ Print / Save PDF</button>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </header>");

        sb.AppendLine("  <main class=\"container\">");

        // Header Metadata Card
        sb.AppendLine("    <section class=\"card meta-card\">");
        sb.AppendLine("      <div class=\"meta-grid\">");
        sb.AppendLine($"        <div class=\"meta-item\"><span class=\"meta-label\">REPORT ID</span><span class=\"meta-val font-mono\">{E(report.ReportId)}</span></div>");
        sb.AppendLine($"        <div class=\"meta-item\"><span class=\"meta-label\">SCAN DATE</span><span class=\"meta-val\">{E(report.ScanStartedAt.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</span></div>");
        sb.AppendLine($"        <div class=\"meta-item\"><span class=\"meta-label\">OS PLATFORM</span><span class=\"meta-val\">{E(report.TargetSystem.OsName)} ({E(report.TargetSystem.Architecture)})</span></div>");
        sb.AppendLine($"        <div class=\"meta-item\"><span class=\"meta-label\">ACTIVE RULESET</span><span class=\"meta-val font-bold text-sky\">{E(report.PolicyEvaluation.AppliedGamemode)}</span></div>");
        sb.AppendLine("      </div>");
        sb.AppendLine($"      <div class=\"seal-banner\">🔒 Cryptographic SHA-256 Seal: <code class=\"font-mono\">{E(report.ReportIntegrityHash)}</code></div>");
        sb.AppendLine("    </section>");

        // Verdict Banner
        string verdictClass = report.SummaryCounts.Critical > 0 || report.SummaryCounts.ConfirmedCheats > 0 ? "verdict-critical" :
                              report.SummaryCounts.High > 0 || report.SummaryCounts.StrongIndicators > 0 ? "verdict-warning" :
                              report.SummaryCounts.Medium > 0 || report.SummaryCounts.Suspicious > 0 ? "verdict-suspicious" : "verdict-clean";
        sb.AppendLine($"    <section class=\"card verdict-card {verdictClass}\">");
        sb.AppendLine("      <div class=\"verdict-header\">");
        sb.AppendLine($"        <h2 class=\"verdict-title\">{E(report.Verdict.OverallAssessment)}</h2>");
        sb.AppendLine($"        <p class=\"verdict-desc\">{E(report.Verdict.Recommendation)}</p>");
        if (report.Verdict.KeyTakeaways.Count > 0)
        {
            sb.AppendLine("        <ul class=\"verdict-takeaways mt-2\">");
            foreach (var t in report.Verdict.KeyTakeaways)
                sb.AppendLine($"          <li>• {E(t)}</li>");
            sb.AppendLine("        </ul>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </section>");

        // Reconciled Summary Totals Overview
        sb.AppendLine("    <section class=\"metrics-grid\">");
        sb.AppendLine($"      <div class=\"metric-box\"><span class=\"metric-num\">{report.SummaryCounts.TotalFindings}</span><span class=\"metric-lbl\">Total Findings</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.Critical > 0 ? "text-red" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.Critical}</span><span class=\"metric-lbl\">Critical</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.High > 0 ? "text-red" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.High}</span><span class=\"metric-lbl\">High</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.Medium > 0 ? "text-amber" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.Medium}</span><span class=\"metric-lbl\">Medium</span></div>");
        sb.AppendLine($"      <div class=\"metric-box\"><span class=\"metric-num\">{report.SummaryCounts.Low}</span><span class=\"metric-lbl\">Low</span></div>");
        sb.AppendLine($"      <div class=\"metric-box text-slate\"><span class=\"metric-num\">{report.SummaryCounts.Informational}</span><span class=\"metric-lbl\">Informational</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.RuntimeObservations > 0 ? "text-amber" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.RuntimeObservations}</span><span class=\"metric-lbl\">Runtime Obs.</span></div>");
        sb.AppendLine($"      <div class=\"metric-box\"><span class=\"metric-num\">{report.SummaryCounts.DiskOnlyObservations}</span><span class=\"metric-lbl\">Disk-Only</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.IncompleteOrFailedChecks > 0 ? "text-slate" : "text-emerald")}\"><span class=\"metric-num\">{report.SummaryCounts.IncompleteOrFailedChecks}</span><span class=\"metric-lbl\">Failed Checks</span></div>");
        sb.AppendLine("    </section>");

        // Navigation Tabs
        sb.AppendLine("    <div class=\"tabs-bar no-print\">");
        sb.AppendLine("      <button class=\"tab-btn active\" onclick=\"switchTab('tab-findings')\">Findings &amp; Evidence Table (" + report.Findings.Count + ")</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-correlation')\">Evidence Correlation (" + report.CorrelatedAssessments.Count + ")</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-mods')\">Mod Inventory (" + report.ModInventory.Count + ")</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-services')\">Services &amp; Drivers (" + report.ServicesAndDrivers.Count + ")</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-runtime')\">Runtime &amp; Modules</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-history')\">Execution &amp; Files</button>");
        sb.AppendLine("      <button class=\"tab-btn\" onclick=\"switchTab('tab-diagnostics')\">Diagnostics (" + report.DiagnosticChecks.Count + ")</button>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 1: FINDINGS ----------------
        sb.AppendLine("    <div id=\"tab-findings\" class=\"tab-content active\">");
        sb.AppendLine("      <div class=\"findings-toolbar no-print\">");
        sb.AppendLine("        <div class=\"filter-group\">");
        sb.AppendLine("          <button class=\"filter-btn active\" onclick=\"filterFindings('all')\">All</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('critical')\">Critical</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('high')\">High</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('medium')\">Medium</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('low')\">Low</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('info')\">Informational</button>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <input type=\"text\" id=\"findingSearch\" class=\"search-input\" placeholder=\"Search findings, rules, files, processes...\" oninput=\"searchFindings()\" />");
        sb.AppendLine("      </div>");

        if (report.Findings.Count == 0)
        {
            sb.AppendLine("      <div class=\"empty-box\">No suspicious indicators or cheat artifacts detected in the inspected scope.</div>");
        }
        else
        {
            // Detailed Findings Table
            sb.AppendLine("      <div class=\"card\" style=\"overflow-x: auto;\">");
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead>");
            sb.AppendLine("            <tr>");
            sb.AppendLine("              <th>Severity</th>");
            sb.AppendLine("              <th>Finding</th>");
            sb.AppendLine("              <th>Evidence Category</th>");
            sb.AppendLine("              <th>Target Process</th>");
            sb.AppendLine("              <th>File / Module Path</th>");
            sb.AppendLine("              <th>Detection Method</th>");
            sb.AppendLine("              <th>Strength</th>");
            sb.AppendLine("              <th>Confidence</th>");
            sb.AppendLine("              <th>Timestamp</th>");
            sb.AppendLine("              <th>Interpretation</th>");
            sb.AppendLine("              <th>Limitations</th>");
            sb.AppendLine("              <th>Recommended Review</th>");
            sb.AppendLine("            </tr>");
            sb.AppendLine("          </thead>");
            sb.AppendLine("          <tbody>");

            foreach (var f in report.Findings)
            {
                string sevBadge = f.Severity == Severity.Critical ? "badge-red font-bold" :
                                  f.Severity == Severity.High ? "badge-red" :
                                  f.Severity == Severity.Medium ? "badge-amber" :
                                  f.Severity == Severity.Low ? "badge-orange" : "badge-slate";

                string catBadge = f.EvidenceCategory == EvidenceCategory.Injected ? "badge-red" :
                                  f.EvidenceCategory == EvidenceCategory.ActiveInScanWindow ? "badge-orange" :
                                  f.EvidenceCategory == EvidenceCategory.RunningProcess ? "badge-amber" :
                                  f.EvidenceCategory == EvidenceCategory.LoadedModule ? "badge-amber" :
                                  f.EvidenceCategory == EvidenceCategory.Historical ? "badge-slate" : "badge-slate";

                string procStr = f.TargetProcessId.HasValue
                    ? $"PID {f.TargetProcessId} ({E(f.TargetProcessName ?? "javaw.exe")})"
                    : "None";

                string timeStr = f.ObservedTimestamp.HasValue
                    ? f.ObservedTimestamp.Value.ToString("yyyy-MM-dd HH:mm:ss")
                    : "N/A";

                if (f.IsInScanWindow) timeStr += " (Active)";

                sb.AppendLine($"            <tr class=\"finding-row finding-{f.Severity.ToString().ToLowerInvariant()}\">");
                sb.AppendLine($"              <td><span class=\"badge {sevBadge}\">{f.Severity}</span></td>");
                sb.AppendLine($"              <td><strong>{E(f.Finding)}</strong><br/><small class=\"text-slate\">Rule: {E(f.RuleId)}</small></td>");
                sb.AppendLine($"              <td><span class=\"badge {catBadge}\">{f.EvidenceCategory}</span></td>");
                sb.AppendLine($"              <td>{procStr}</td>");
                sb.AppendLine($"              <td><code class=\"font-mono\">{E(f.GetRedactedPath())}</code></td>");
                sb.AppendLine($"              <td>{f.DetectionMethod}</td>");
                sb.AppendLine($"              <td>{f.EvidenceStrength}</td>");
                sb.AppendLine($"              <td>{f.Confidence}</td>");
                sb.AppendLine($"              <td>{timeStr}</td>");
                sb.AppendLine($"              <td>{E(!string.IsNullOrEmpty(f.Interpretation) ? f.Interpretation : f.TechnicalExplanation)}</td>");
                sb.AppendLine($"              <td>{E(!string.IsNullOrEmpty(f.Limitations) ? f.Limitations : f.WhatIsNotProven)}</td>");
                sb.AppendLine($"              <td>{E(!string.IsNullOrEmpty(f.RecommendedReview) ? f.RecommendedReview : f.SuggestedNextChecks)}</td>");
                sb.AppendLine("            </tr>");
            }

            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
            sb.AppendLine("      </div>");

            // Detailed Finding Expandable Cards
            sb.AppendLine("      <h3 class=\"section-title mt-4\">Detailed Forensic Breakdown</h3>");
            foreach (var f in report.Findings)
            {
                string sevTag = f.Severity.ToString().ToLowerInvariant();
                string sevBadge = f.Severity == Severity.Critical ? "badge-red" :
                                  f.Severity == Severity.High ? "badge-red" :
                                  f.Severity == Severity.Medium ? "badge-amber" :
                                  f.Severity == Severity.Low ? "badge-orange" : "badge-slate";

                sb.AppendLine($"      <div class=\"finding-card finding-{sevTag}\">");
                sb.AppendLine("        <div class=\"finding-header\">");
                sb.AppendLine("          <div class=\"finding-title-row\">");
                sb.AppendLine($"            <span class=\"badge {sevBadge}\">{f.Severity}</span>");
                sb.AppendLine($"            <span class=\"badge badge-slate\">{f.EvidenceCategory}</span>");
                sb.AppendLine($"            <span class=\"badge badge-slate\">{f.DetectionMethod}</span>");
                sb.AppendLine($"            <h3 class=\"finding-title\">{E(f.Finding)}</h3>");
                sb.AppendLine("          </div>");
                sb.AppendLine($"          <div class=\"finding-meta\">Rule: <code>{E(f.RuleId)}</code> • Source: {E(f.EvidenceSource)} • Cluster: <code>{E(f.EvidenceClusterId)}</code></div>");
                sb.AppendLine("        </div>");

                sb.AppendLine("        <div class=\"finding-body\">");
                sb.AppendLine($"          <p class=\"finding-exp\">{E(f.TechnicalExplanation)}</p>");

                if (!string.IsNullOrEmpty(f.FilePath))
                    sb.AppendLine($"          <div class=\"finding-prop\"><span class=\"prop-k\">Path (Redacted):</span> <code class=\"prop-v\">{E(f.GetRedactedPath())}</code></div>");
                if (!string.IsNullOrEmpty(f.FileSha256))
                    sb.AppendLine($"          <div class=\"finding-prop\"><span class=\"prop-k\">SHA-256:</span> <code class=\"prop-v font-mono\">{E(f.FileSha256)}</code></div>");

                sb.AppendLine("          <div class=\"analysis-grid\">");
                sb.AppendLine("            <div class=\"analysis-box\">");
                sb.AppendLine("              <div class=\"analysis-lbl\">Why this indicator matters:</div>");
                sb.AppendLine($"              <div class=\"analysis-val\">{E(f.WhyItMatters)}</div>");
                sb.AppendLine("            </div>");
                sb.AppendLine("            <div class=\"analysis-box\">");
                sb.AppendLine("              <div class=\"analysis-lbl\">Alternative legitimate explanations:</div>");
                sb.AppendLine($"              <div class=\"analysis-val\">{E(f.AlternativeLegitimateExplanations)}</div>");
                sb.AppendLine("            </div>");
                sb.AppendLine("          </div>");

                if (!string.IsNullOrEmpty(f.Interpretation) || !string.IsNullOrEmpty(f.WhatIsProven))
                {
                    sb.AppendLine($"          <div class=\"proven-box\">✅ <strong>Interpretation / What this proves:</strong> {E(!string.IsNullOrEmpty(f.Interpretation) ? f.Interpretation : f.WhatIsProven)}</div>");
                }
                if (!string.IsNullOrEmpty(f.Limitations) || !string.IsNullOrEmpty(f.WhatIsNotProven))
                {
                    sb.AppendLine($"          <div class=\"not-proven-box\">⚠️ <strong>Limitations / What this does NOT prove:</strong> {E(!string.IsNullOrEmpty(f.Limitations) ? f.Limitations : f.WhatIsNotProven)}</div>");
                }
                if (!string.IsNullOrEmpty(f.RecommendedReview))
                {
                    sb.AppendLine($"          <div class=\"limitations-box\">🔍 <strong>Recommended Staff Review:</strong> {E(f.RecommendedReview)}</div>");
                }
                sb.AppendLine("        </div>");
                sb.AppendLine("      </div>");
            }
        }
        sb.AppendLine("    </div>");

        // ---------------- TAB 2: EVIDENCE CORRELATION ----------------
        sb.AppendLine("    <div id=\"tab-correlation\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Multi-Source Evidence Correlation &amp; Software State Assessment</h3>");
        sb.AppendLine("        <p class=\"section-desc\">Strictly distinguishes the 6 software states: Present, Installed, Executed, Active in Session, Interacting, Prohibited Functionality Used. Never conflates mere file presence with active in-game use.</p>");
        if (report.CorrelatedAssessments.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No correlated software assessments recorded.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Software / Artifact</th><th>Assessed State</th><th>Policy Scope</th><th>Policy Violation?</th><th>What is Proven</th><th>Limitations / Not Proven</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var a in report.CorrelatedAssessments)
            {
                string stateBadge = a.State == SoftwareEvidenceState.ProhibitedFunctionalityUsed ? "badge-red" :
                                    a.State == SoftwareEvidenceState.SoftwareInteractingWithMinecraft ? "badge-orange" :
                                    a.State == SoftwareEvidenceState.SoftwareActiveDuringSession ? "badge-amber" :
                                    a.State == SoftwareEvidenceState.SoftwareExecuted ? "badge-amber" :
                                    a.State == SoftwareEvidenceState.SoftwareInstalled ? "badge-slate" : "badge-slate";

                string violBadge = a.IsPolicyViolation ? "badge-red" : "badge-emerald";
                string polBadge = a.Policy == GameplayPolicy.PROHIBITED_POSSESSION ? "badge-red" :
                                  a.Policy == GameplayPolicy.PROHIBITED_EXECUTION ? "badge-amber" :
                                  a.Policy == GameplayPolicy.ALLOWED ? "badge-emerald" : "badge-slate";

                sb.AppendLine("            <tr>");
                sb.AppendLine($"              <td><strong>{E(a.SoftwareName)}</strong></td>");
                sb.AppendLine($"              <td><span class=\"badge {stateBadge}\">{a.State}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {polBadge}\">{a.Policy}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {violBadge}\">{(a.IsPolicyViolation ? "VIOLATION" : "COMPLIANT")}</span></td>");
                sb.AppendLine($"              <td>{E(a.WhatIsProven)}</td>");
                sb.AppendLine($"              <td>{E(a.WhatIsNotProven)}</td>");
                sb.AppendLine("            </tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 3: MOD INVENTORY ----------------
        sb.AppendLine("    <div id=\"tab-mods\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Discovered Mod Inventory &amp; Authenticity Verification</h3>");
        if (report.ModInventory.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No Minecraft mod JAR files discovered.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Mod Name</th><th>File Name</th><th>SHA-256</th><th>Verification</th><th>Policy Status</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var m in report.ModInventory)
            {
                string verBadge = m.Verified ? "badge-emerald" : "badge-amber";
                string polBadge = m.GameplayPolicy.StartsWith("PROHIBITED") ? "badge-red" :
                                  m.GameplayPolicy == "ALLOWED" ? "badge-emerald" : "badge-slate";
                sb.AppendLine("            <tr>");
                sb.AppendLine($"              <td><strong>{E(m.Name)}</strong></td>");
                sb.AppendLine($"              <td>{E(m.FileName)}</td>");
                sb.AppendLine($"              <td><code class=\"font-mono\">{(m.Sha256.Length >= 12 ? m.Sha256[..12] + "..." : m.Sha256)}</code></td>");
                sb.AppendLine($"              <td><span class=\"badge {verBadge}\">{E(m.VerificationState)}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {polBadge}\">{E(m.GameplayPolicy)}</span></td>");
                sb.AppendLine("            </tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 4: SERVICES & DRIVERS ----------------
        sb.AppendLine("    <div id=\"tab-services\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Registered Windows Services &amp; Kernel Drivers</h3>");
        if (report.ServicesAndDrivers.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No notable third-party services or drivers recorded.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Service Name</th><th>Display Name</th><th>Type</th><th>Image Path</th><th>Signature Status</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var s in report.ServicesAndDrivers)
            {
                string signBadge = s.IsTrustedSignature ? "badge-emerald" : "badge-amber";
                sb.AppendLine("            <tr>");
                sb.AppendLine($"              <td><strong>{E(s.Name)}</strong></td>");
                sb.AppendLine($"              <td>{E(s.DisplayName)}</td>");
                sb.AppendLine($"              <td>{(s.IsDriver ? "Kernel Driver" : "Service")}</td>");
                sb.AppendLine($"              <td><code>{E(s.ImagePath)}</code></td>");
                sb.AppendLine($"              <td><span class=\"badge {signBadge}\">{(s.IsTrustedSignature ? "Verified" : "Untrusted/Unsigned")}</span></td>");
                sb.AppendLine("            </tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 5: RUNTIME & MODULES ----------------
        sb.AppendLine("    <div id=\"tab-runtime\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Running Processes &amp; Memory-Mapped DLL Modules</h3>");
        sb.AppendLine("        <h4 class=\"mt-4\">Target Processes:</h4>");
        if (report.RunningProcesses.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No active target processes running during scan.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>PID</th><th>Process Name</th><th>Start Time</th><th>Executable Path</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var p in report.RunningProcesses)
            {
                sb.AppendLine($"            <tr><td>{p.ProcessId}</td><td><strong>{E(p.ProcessName)}</strong></td><td>{p.StartTime}</td><td><code>{E(p.ExecutablePath)}</code></td></tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }

        sb.AppendLine("        <h4 class=\"mt-4\">Loaded DLL Modules in Game Processes:</h4>");
        if (report.LoadedModules.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No loaded modules recorded.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Module Name</th><th>Path</th><th>Provenance Assessment</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var m in report.LoadedModules.Take(50))
            {
                sb.AppendLine($"            <tr><td><strong>{E(m.ModuleName)}</strong></td><td><code>{E(m.FilePath)}</code></td><td>{E(m.ProvenanceAssessment)}</td></tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 6: HISTORY & FILES ----------------
        sb.AppendLine("    <div id=\"tab-history\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Execution History &amp; Staged File Discoveries</h3>");
        if (report.ExecutionHistory.Count == 0 && report.FileDiscoveries.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No notable execution history or staged files found.</div>");
        }
        else
        {
            if (report.FileDiscoveries.Count > 0)
            {
                sb.AppendLine("        <h4 class=\"mt-4\">Files Discovered in Downloads/Desktop/Recycle Bin:</h4>");
                sb.AppendLine("        <table class=\"data-table\">");
                sb.AppendLine("          <thead><tr><th>File Name</th><th>Path</th><th>Size</th><th>Last Modified</th></tr></thead>");
                sb.AppendLine("          <tbody>");
                foreach (var f in report.FileDiscoveries)
                {
                    sb.AppendLine($"            <tr><td><strong>{E(f.FileName)}</strong></td><td><code>{E(f.FilePath)}</code></td><td>{f.FileSizeBytes} B</td><td>{f.LastModified:yyyy-MM-dd HH:mm:ss}</td></tr>");
                }
                sb.AppendLine("          </tbody>");
                sb.AppendLine("        </table>");
            }

            if (report.ExecutionHistory.Count > 0)
            {
                sb.AppendLine("        <h4 class=\"mt-4\">Execution History Records (Prefetch / BAM / UserAssist):</h4>");
                sb.AppendLine("        <table class=\"data-table\">");
                sb.AppendLine("          <thead><tr><th>Source</th><th>Application</th><th>Last Executed</th><th>Details</th></tr></thead>");
                sb.AppendLine("          <tbody>");
                foreach (var h in report.ExecutionHistory.Take(50))
                {
                    sb.AppendLine($"            <tr><td><span class=\"badge badge-slate\">{E(h.Source)}</span></td><td>{E(h.ApplicationName)}</td><td>{h.LastExecutionTime}</td><td>{E(h.Details)}</td></tr>");
                }
                sb.AppendLine("          </tbody>");
                sb.AppendLine("        </table>");
            }
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 7: DIAGNOSTICS ----------------
        sb.AppendLine("    <div id=\"tab-diagnostics\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Collection Diagnostic Checks</h3>");
        sb.AppendLine("        <table class=\"data-table\">");
        sb.AppendLine("          <thead><tr><th>Check Name</th><th>Source</th><th>Status</th><th>Reason / Details</th></tr></thead>");
        sb.AppendLine("          <tbody>");
        foreach (var diag in report.DiagnosticChecks)
        {
            string statusBadge = diag.Status == CheckStatus.PASSED ? "badge-emerald" :
                                 diag.Status == CheckStatus.FLAGGED ? "badge-red" :
                                 diag.Status == CheckStatus.SKIPPED ? "badge-slate" : "badge-amber";
            sb.AppendLine($"            <tr><td><strong>{E(diag.CheckName)}</strong></td><td>{E(diag.Source)}</td><td><span class=\"badge {statusBadge}\">{diag.Status}</span></td><td>{E(diag.Reason)}</td></tr>");
        }
        sb.AppendLine("          </tbody>");
        sb.AppendLine("        </table>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        sb.AppendLine("  </main>");

        // Inline Interactive JavaScript
        sb.AppendLine("  <script>");
        sb.AppendLine(GetEmbeddedJs());
        sb.AppendLine("  </script>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    public static void SaveToFile(StandaloneReport report, string filePath)
    {
        string html = ExportToHtml(report);
        File.WriteAllText(filePath, html, Encoding.UTF8);
    }

    private static string E(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return WebUtility.HtmlEncode(input);
    }

    private static string GetEmbeddedCss()
    {
        return @"
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; line-height: 1.5; padding-bottom: 60px; }
.navbar { background-color: #111827; border-bottom: 1px solid #1f2937; padding: 14px 24px; position: sticky; top: 0; z-index: 100; }
.nav-container { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
.brand { display: flex; align-items: center; gap: 12px; }
.shield-icon { font-size: 28px; }
.brand-title { font-size: 18px; font-weight: 700; color: #f8fafc; }
.brand-subtitle { font-size: 11px; color: #94a3b8; }
.nav-actions { display: flex; align-items: center; gap: 10px; }
.btn { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; padding: 7px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: 0.2s; }
.btn:hover { background-color: #334155; }
.container { max-width: 1200px; margin: 24px auto; padding: 0 16px; }
.card { background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 14px; }
.meta-label { font-size: 10px; font-weight: 700; color: #64748b; letter-spacing: 0.5px; display: block; margin-bottom: 4px; }
.meta-val { font-size: 13px; color: #cbd5e1; }
.seal-banner { background-color: #0f172a; border: 1px solid #1e293b; padding: 8px 12px; border-radius: 6px; font-size: 11px; color: #38bdf8; overflow-x: auto; }
.verdict-card { border-left-width: 6px; }
.verdict-clean { border-left-color: #10b981; background: linear-gradient(90deg, rgba(16,185,129,0.1) 0%, rgba(17,24,39,1) 100%); }
.verdict-warning { border-left-color: #f59e0b; background: linear-gradient(90deg, rgba(245,158,11,0.1) 0%, rgba(17,24,39,1) 100%); }
.verdict-suspicious { border-left-color: #fb923c; background: linear-gradient(90deg, rgba(251,146,60,0.15) 0%, rgba(17,24,39,1) 100%); }
.verdict-critical { border-left-color: #ef4444; background: linear-gradient(90deg, rgba(239,68,68,0.15) 0%, rgba(17,24,39,1) 100%); }
.verdict-title { font-size: 18px; font-weight: 700; color: #f8fafc; margin-bottom: 6px; }
.verdict-desc { font-size: 13px; color: #cbd5e1; }
.verdict-takeaways { font-size: 12px; color: #94a3b8; list-style: none; margin-top: 6px; }
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 24px; }
.metric-box { background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 12px; text-align: center; }
.metric-num { font-size: 20px; font-weight: 800; display: block; }
.metric-lbl { font-size: 10px; color: #94a3b8; }
.tabs-bar { display: flex; gap: 8px; margin-bottom: 18px; border-bottom: 1px solid #1f2937; padding-bottom: 10px; overflow-x: auto; }
.tab-btn { background: none; border: none; color: #94a3b8; font-size: 13px; font-weight: 600; padding: 8px 14px; cursor: pointer; border-radius: 6px; }
.tab-btn.active { background-color: #1e293b; color: #38bdf8; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.findings-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.filter-group { display: flex; gap: 6px; }
.filter-btn { background-color: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 11px; font-weight: 600; padding: 5px 10px; border-radius: 6px; cursor: pointer; }
.filter-btn.active { background-color: #38bdf8; color: #0f172a; border-color: #38bdf8; }
.search-input { background-color: #0f172a; border: 1px solid #334155; color: #e2e8f0; padding: 6px 12px; border-radius: 6px; font-size: 12px; min-width: 250px; }
.finding-card { background-color: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 18px; margin-bottom: 14px; border-left: 4px solid #38bdf8; }
.finding-critical { border-left-color: #ef4444; }
.finding-high { border-left-color: #f87171; }
.finding-medium { border-left-color: #f59e0b; }
.finding-low { border-left-color: #fb923c; }
.finding-informational { border-left-color: #64748b; }
.finding-title-row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.finding-title { font-size: 15px; font-weight: 700; color: #f1f5f9; }
.finding-meta { font-size: 11px; color: #94a3b8; margin-bottom: 12px; }
.finding-exp { font-size: 13px; color: #cbd5e1; margin-bottom: 12px; line-height: 1.6; }
.finding-prop { font-size: 12px; margin-bottom: 6px; word-break: break-all; }
.prop-k { color: #94a3b8; font-weight: 600; }
.analysis-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin: 14px 0; }
.analysis-box { background-color: #0f172a; padding: 10px 14px; border-radius: 6px; border: 1px solid #1e293b; font-size: 12px; }
.analysis-lbl { font-weight: 700; color: #94a3b8; margin-bottom: 4px; }
.analysis-val { color: #cbd5e1; }
.not-proven-box { background-color: #1e1b4b; border: 1px solid #4338ca; color: #c7d2fe; padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-top: 10px; }
.proven-box { background-color: #064e3b; border: 1px solid #059669; color: #a7f3d0; padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-top: 10px; }
.limitations-box { background-color: #1e293b; border: 1px solid #475569; color: #cbd5e1; padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-top: 10px; }
.section-desc { font-size: 13px; color: #94a3b8; margin-bottom: 16px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.badge-red { background-color: #450a0a; color: #f87171; border: 1px solid #991b1b; }
.badge-amber { background-color: #451a03; color: #fbbf24; border: 1px solid #b45309; }
.badge-orange { background-color: #431407; color: #fb923c; border: 1px solid #c2410c; }
.badge-emerald { background-color: #064e3b; color: #34d399; border: 1px solid #059669; }
.badge-slate { background-color: #1e293b; color: #94a3b8; border: 1px solid #334155; }
.mode-badge { background-color: #0369a1; color: #bae6fd; }
.data-table { width: 100%; border-collapse: collapse; font-size: 12px; text-align: left; }
.data-table th { background-color: #0f172a; padding: 10px 12px; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #1f2937; }
.data-table td { padding: 10px 12px; border-bottom: 1px solid #1e293b; color: #cbd5e1; }
.font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.text-red { color: #ef4444; }
.text-amber { color: #f59e0b; }
.text-emerald { color: #10b981; }
.text-sky { color: #38bdf8; }
.text-slate { color: #94a3b8; }
.mt-2 { margin-top: 8px; }
.mt-4 { margin-top: 16px; }
.empty-box { padding: 32px; text-align: center; color: #64748b; font-size: 13px; }
@media print { .no-print { display: none !important; } .card { border: 1px solid #ccc; break-inside: avoid; } body { background: white; color: black; } }
";
    }

    private static string GetEmbeddedJs()
    {
        return @"
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

function filterFindings(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  const cards = document.querySelectorAll('.finding-card');
  const rows = document.querySelectorAll('.finding-row');
  
  cards.forEach(c => {
    if (sev === 'all') c.style.display = 'block';
    else c.style.display = c.classList.contains('finding-' + sev) ? 'block' : 'none';
  });

  rows.forEach(r => {
    if (sev === 'all') r.style.display = '';
    else r.style.display = r.classList.contains('finding-' + sev) ? '' : 'none';
  });
}

function searchFindings() {
  const query = document.getElementById('findingSearch').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(c => {
    c.style.display = c.innerText.toLowerCase().includes(query) ? 'block' : 'none';
  });
  document.querySelectorAll('.finding-row').forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(query) ? '' : 'none';
  });
}
";
    }
}

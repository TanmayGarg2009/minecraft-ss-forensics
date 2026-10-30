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
        string verdictClass = report.SummaryCounts.ConfirmedCheats > 0 ? "verdict-critical" :
                              report.SummaryCounts.StrongIndicators > 0 ? "verdict-warning" :
                              report.SummaryCounts.Suspicious > 0 ? "verdict-suspicious" : "verdict-clean";
        sb.AppendLine($"    <section class=\"card verdict-card {verdictClass}\">");
        sb.AppendLine("      <div class=\"verdict-header\">");
        sb.AppendLine($"        <h2 class=\"verdict-title\">{E(report.Verdict.OverallAssessment)}</h2>");
        sb.AppendLine($"        <p class=\"verdict-desc\">{E(report.Verdict.Recommendation)}</p>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </section>");

        // 7-Metric Overview Cards
        sb.AppendLine("    <section class=\"metrics-grid\">");
        sb.AppendLine($"      <div class=\"metric-box\"><span class=\"metric-num\">{report.SummaryCounts.TotalChecks}</span><span class=\"metric-lbl\">Total Checks</span></div>");
        sb.AppendLine($"      <div class=\"metric-box text-emerald\"><span class=\"metric-num\">{report.SummaryCounts.PassedChecks}</span><span class=\"metric-lbl\">Passed Checks</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.ConfirmedCheats > 0 ? "text-red" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.ConfirmedCheats}</span><span class=\"metric-lbl\">Confirmed Cheats</span></div>");
        sb.AppendLine($"      <div class=\"metric-box {(report.SummaryCounts.StrongIndicators > 0 ? "text-amber" : "")}\"><span class=\"metric-num\">{report.SummaryCounts.StrongIndicators}</span><span class=\"metric-lbl\">Strong Indicators</span></div>");
        sb.AppendLine($"      <div class=\"metric-box\"><span class=\"metric-num\">{report.SummaryCounts.VerifiedMods}</span><span class=\"metric-lbl\">Verified Mods</span></div>");
        sb.AppendLine($"      <div class=\"metric-box text-amber\"><span class=\"metric-num\">{report.SummaryCounts.ProhibitedMods}</span><span class=\"metric-lbl\">Prohibited Mods</span></div>");
        sb.AppendLine($"      <div class=\"metric-box text-slate\"><span class=\"metric-num\">{report.SummaryCounts.UnavailableChecks}</span><span class=\"metric-lbl\">Unavailable</span></div>");
        sb.AppendLine("    </section>");

        // Navigation Tabs
        sb.AppendLine("    <div class=\"tabs-bar no-print\">");
        sb.AppendLine("      <button class=\"tab-btn active\" onclick=\"switchTab('tab-findings')\">Key Findings (" + report.Findings.Count + ")</button>");
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
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('confirmed')\">Confirmed Cheats</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('strong')\">Strong Indicators</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('suspicious')\">Suspicious</button>");
        sb.AppendLine("          <button class=\"filter-btn\" onclick=\"filterFindings('info')\">Informational</button>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <input type=\"text\" id=\"findingSearch\" class=\"search-input\" placeholder=\"Search findings, rules, files...\" oninput=\"searchFindings()\" />");
        sb.AppendLine("      </div>");

        if (report.Findings.Count == 0)
        {
            sb.AppendLine("      <div class=\"empty-box\">No suspicious indicators or cheat artifacts detected in the inspected scope.</div>");
        }
        else
        {
            foreach (var f in report.Findings)
            {
                string classTag = f.Classification.ToString().ToLowerInvariant();
                string badgeColor = f.Classification == FindingClassification.ConfirmedCheatArtifact ? "badge-red" :
                                   f.Classification == FindingClassification.StrongIndicator ? "badge-amber" :
                                   f.Classification == FindingClassification.Suspicious ? "badge-orange" : "badge-slate";

                sb.AppendLine($"      <div class=\"finding-card finding-{classTag}\">");
                sb.AppendLine("        <div class=\"finding-header\">");
                sb.AppendLine("          <div class=\"finding-title-row\">");
                sb.AppendLine($"            <span class=\"badge {badgeColor}\">{E(f.Classification.ToString())}</span>");
                sb.AppendLine($"            <span class=\"badge badge-slate\">{E(f.EvidenceState.ToString())}</span>");
                sb.AppendLine($"            <span class=\"badge badge-slate\">{E(f.SoftwareState.ToString())}</span>");
                if (!string.IsNullOrEmpty(f.PolicyViolationScope))
                {
                    sb.AppendLine($"            <span class=\"badge badge-amber\">{E(f.PolicyViolationScope)}</span>");
                }
                sb.AppendLine($"            <h3 class=\"finding-title\">{E(f.DetectionName)}</h3>");
                sb.AppendLine("          </div>");
                sb.AppendLine($"          <div class=\"finding-meta\">Rule: <code>{E(f.RuleId)}</code> • Source: {E(f.EvidenceSource)} • Confidence: {E(f.Confidence.ToString())}</div>");
                sb.AppendLine("        </div>");

                sb.AppendLine("        <div class=\"finding-body\">");
                sb.AppendLine($"          <p class=\"finding-exp\">{E(f.TechnicalExplanation)}</p>");

                if (!string.IsNullOrEmpty(f.FilePath))
                    sb.AppendLine($"          <div class=\"finding-prop\"><span class=\"prop-k\">Path:</span> <code class=\"prop-v\">{E(f.FilePath)}</code></div>");
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

                if (!string.IsNullOrEmpty(f.WhatIsProven))
                {
                    sb.AppendLine($"          <div class=\"proven-box\">✅ <strong>What this proves:</strong> {E(f.WhatIsProven)}</div>");
                }
                if (!string.IsNullOrEmpty(f.WhatIsNotProven))
                {
                    sb.AppendLine($"          <div class=\"not-proven-box\">⚠️ <strong>What this does NOT prove:</strong> {E(f.WhatIsNotProven)}</div>");
                }
                if (!string.IsNullOrEmpty(f.Limitations))
                {
                    sb.AppendLine($"          <div class=\"limitations-box\">ℹ️ <strong>Evidentiary Limitations:</strong> {E(f.Limitations)}</div>");
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
                sb.AppendLine($"              <td><strong>{E(a.SoftwareName)}</strong><br/><code class=\"text-slate\" style=\"font-size:10px;\">{E(a.FilePath)}</code></td>");
                sb.AppendLine($"              <td><span class=\"badge {stateBadge}\">{a.State}</span><br/><span style=\"font-size:11px;color:#94a3b8;\">{E(a.StateDescription)}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {polBadge}\">{a.Policy}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {violBadge}\">{(a.IsPolicyViolation ? "VIOLATION" : "NO VIOLATION")}</span></td>");
                sb.AppendLine($"              <td style=\"font-size:11px;\">{E(a.WhatIsProven)}</td>");
                sb.AppendLine($"              <td style=\"font-size:11px;color:#94a3b8;\">{E(a.WhatIsNotProven)}</td>");
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
        sb.AppendLine("        <h3 class=\"section-title\">Discovered Minecraft Mod Inventory &amp; Policies</h3>");
        sb.AppendLine("        <table class=\"data-table\">");
        sb.AppendLine("          <thead><tr><th>Mod Name</th><th>File Name</th><th>Size</th><th>Authenticity</th><th>Policy</th><th>SHA-256</th></tr></thead>");
        sb.AppendLine("          <tbody>");
        foreach (var m in report.ModInventory)
        {
            string authBadge = m.Verified ? "badge-emerald" : "badge-slate";
            string polBadge = m.GameplayPolicy == "ALLOWED" ? "badge-emerald" :
                              m.GameplayPolicy == "PROHIBITED" || m.GameplayPolicy.StartsWith("PROHIBITED_") ? "badge-red" : "badge-amber";
            string sizeStr = (m.FileSizeBytes / 1024.0).ToString("F1") + " KB";
            sb.AppendLine($"            <tr><td><strong>{E(m.Name)}</strong></td><td><code>{E(m.FileName)}</code></td><td>{sizeStr}</td><td><span class=\"badge {authBadge}\">{E(m.VerificationState)}</span></td><td><span class=\"badge {polBadge}\">{E(m.GameplayPolicy)}</span></td><td class=\"font-mono\">{E(m.Sha256[..Math.Min(16, m.Sha256.Length)])}...</td></tr>");
        }
        sb.AppendLine("          </tbody>");
        sb.AppendLine("        </table>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 4: SERVICES & DRIVERS ----------------
        sb.AppendLine("    <div id=\"tab-services\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Windows Services &amp; Third-Party Kernel Drivers</h3>");
        sb.AppendLine("        <div class=\"limitations-box\" style=\"margin-bottom:14px;\">⚠️ <strong>Architectural Note:</strong> This audit runs in user-mode without kernel driver hooks. While it comprehensively checks HKLM Services registry hives, Event ID 7045, and SetupAPI logs for unsigned or user-writable drivers, it cannot guarantee detection of active rootkits using direct kernel object manipulation (DKOM).</div>");
        if (report.ServicesAndDrivers.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No non-standard or third-party service/driver entries detected in inspected scope.</div>");
        }
        else
        {
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Name</th><th>Type</th><th>Image Path</th><th>User Dir?</th><th>Signature Status</th><th>Source</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var s in report.ServicesAndDrivers)
            {
                string typeBadge = s.IsDriver ? "badge-amber" : "badge-slate";
                string userBadge = s.IsInUserDirectory ? "<span class=\"badge badge-red\">USER-DIR</span>" : "<span class=\"badge badge-slate\">SYSTEM</span>";
                string sigBadge = s.IsSigned ? "<span class=\"badge badge-emerald\">SIGNED</span>" : "<span class=\"badge badge-red\">UNSIGNED</span>";
                sb.AppendLine("            <tr>");
                sb.AppendLine($"              <td><strong>{E(s.Name)}</strong><br/><span style=\"font-size:11px;color:#94a3b8;\">{E(s.DisplayName)}</span></td>");
                sb.AppendLine($"              <td><span class=\"badge {typeBadge}\">{(s.IsDriver ? "DRIVER" : "SERVICE")}</span></td>");
                sb.AppendLine($"              <td><code>{E(s.ImagePath)}</code></td>");
                sb.AppendLine($"              <td>{userBadge}</td>");
                sb.AppendLine($"              <td>{sigBadge} {(string.IsNullOrEmpty(s.SignerSubject) ? "" : $"<br/><span style=\"font-size:10px;color:#94a3b8;\">{E(s.SignerSubject)}</span>")}</td>");
                sb.AppendLine($"              <td><span class=\"badge badge-slate\">{E(s.Source)}</span></td>");
                sb.AppendLine("            </tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 3: RUNTIME & MODULES ----------------
        sb.AppendLine("    <div id=\"tab-runtime\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Running Java Processes &amp; Loaded Modules</h3>");
        if (report.RunningProcesses.Count == 0)
        {
            sb.AppendLine("        <div class=\"empty-box\">No active Minecraft javaw.exe processes were running during this scan.</div>");
        }
        else
        {
            foreach (var p in report.RunningProcesses)
            {
                sb.AppendLine($"        <div class=\"process-card\">");
                sb.AppendLine($"          <div class=\"process-header\"><strong>{E(p.ProcessName)}</strong> (PID: {p.ProcessId})</div>");
                if (!string.IsNullOrEmpty(p.SanitizedCommandLine))
                    sb.AppendLine($"          <div class=\"cmd-box\"><code>{E(p.SanitizedCommandLine)}</code></div>");
                sb.AppendLine("        </div>");
            }
        }

        sb.AppendLine("        <h4 class=\"sub-title mt-4\">Loaded Dynamic Libraries (.DLL) in javaw.exe</h4>");
        sb.AppendLine("        <table class=\"data-table\">");
        sb.AppendLine("          <thead><tr><th>Module Name</th><th>Path</th><th>Provenance Assessment</th></tr></thead>");
        sb.AppendLine("          <tbody>");
        foreach (var mod in report.LoadedModules.Take(50))
        {
            string provBadge = mod.IsRecognizedJavaNativeLibrary ? "badge-emerald" :
                               mod.IsInTempDirectory ? "badge-amber" : "badge-slate";
            sb.AppendLine($"            <tr><td><strong>{E(mod.ModuleName)}</strong></td><td><code>{E(mod.FilePath)}</code></td><td><span class=\"badge {provBadge}\">{E(mod.ProvenanceAssessment)}</span></td></tr>");
        }
        sb.AppendLine("          </tbody>");
        sb.AppendLine("        </table>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 4: EXECUTION & REGISTRY ----------------
        sb.AppendLine("    <div id=\"tab-history\" class=\"tab-content\">");
        sb.AppendLine("      <div class=\"card\">");
        sb.AppendLine("        <h3 class=\"section-title\">Windows Execution Artifacts &amp; Registry Evidence</h3>");
        sb.AppendLine("        <table class=\"data-table\">");
        sb.AppendLine("          <thead><tr><th>Source</th><th>Application / Path</th><th>Last Execution / Modified</th><th>Details</th></tr></thead>");
        sb.AppendLine("          <tbody>");
        foreach (var h in report.ExecutionHistory)
        {
            string timeStr = h.LastExecutionTime?.ToString("yyyy-MM-dd HH:mm") ?? "-";
            sb.AppendLine($"            <tr><td><span class=\"badge badge-slate\">{E(h.Source)}</span></td><td><code>{E(h.ApplicationName)}</code></td><td>{timeStr}</td><td>{E(h.Details)}</td></tr>");
        }
        foreach (var r in report.RegistryEvidence)
        {
            sb.AppendLine($"            <tr><td><span class=\"badge badge-slate\">Registry</span></td><td><code>{E(r.ValueName)}</code></td><td>-</td><td>{E(r.Significance)}</td></tr>");
        }
        sb.AppendLine("          </tbody>");
        sb.AppendLine("        </table>");

        if (report.FileDiscoveries.Count > 0)
        {
            sb.AppendLine("        <h4 class=\"sub-title mt-4\">Discovered Files in Downloads, Desktop, Temp, &amp; $Recycle.Bin</h4>");
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>File Name</th><th>Path</th><th>Size</th><th>Category</th><th>SHA-256</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var f in report.FileDiscoveries)
            {
                string sizeStr = (f.FileSizeBytes / 1024.0).ToString("F1") + " KB";
                sb.AppendLine($"            <tr><td><strong>{E(f.FileName)}</strong></td><td><code>{E(f.FilePath)}</code></td><td>{sizeStr}</td><td><span class=\"badge badge-slate\">{E(f.DiscoveryCategory)}</span></td><td class=\"font-mono\">{E(f.Sha256[..Math.Min(16, f.Sha256.Length)])}...</td></tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }

        if (report.UsbEvidence.Count > 0)
        {
            sb.AppendLine("        <h4 class=\"sub-title mt-4\">Historically Connected USB Storage Devices</h4>");
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Device / Description</th><th>Hardware ID</th><th>Last Connected</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var u in report.UsbEvidence)
            {
                sb.AppendLine($"            <tr><td><strong>{E(u.DeviceDescription)}</strong></td><td><code>{E(u.HardwareId)}</code></td><td>{u.LastConnectedTimestamp?.ToString("yyyy-MM-dd HH:mm") ?? "-"}</td></tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }

        if (report.BrowserEvidence.Count > 0)
        {
            sb.AppendLine("        <h4 class=\"sub-title mt-4\">Browser History Matches (Opted-in Cheat Domains Only)</h4>");
            sb.AppendLine("        <table class=\"data-table\">");
            sb.AppendLine("          <thead><tr><th>Browser</th><th>Matched Domain / URL</th><th>Visit Time</th></tr></thead>");
            sb.AppendLine("          <tbody>");
            foreach (var b in report.BrowserEvidence)
            {
                sb.AppendLine($"            <tr><td><span class=\"badge badge-slate\">{E(b.BrowserName)}</span></td><td><code>{E(b.Url)}</code></td><td>{b.VisitTime?.ToString("yyyy-MM-dd HH:mm") ?? "-"}</td></tr>");
            }
            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
        }

        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // ---------------- TAB 5: DIAGNOSTICS ----------------
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
.verdict-critical { border-left-color: #ef4444; background: linear-gradient(90deg, rgba(239,68,68,0.15) 0%, rgba(17,24,39,1) 100%); }
.verdict-title { font-size: 18px; font-weight: 700; color: #f8fafc; margin-bottom: 6px; }
.verdict-desc { font-size: 13px; color: #cbd5e1; }
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 24px; }
.metric-box { background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 14px; text-align: center; }
.metric-num { font-size: 22px; font-weight: 800; display: block; }
.metric-lbl { font-size: 11px; color: #94a3b8; }
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
.finding-confirmedcheatartifact { border-left-color: #ef4444; }
.finding-strongindicator { border-left-color: #f59e0b; }
.finding-suspicious { border-left-color: #fb923c; }
.finding-needsreview { border-left-color: #a855f7; }
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

function filterFindings(cat) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  const cards = document.querySelectorAll('.finding-card');
  cards.forEach(c => {
    if (cat === 'all') { c.style.display = 'block'; return; }
    if (cat === 'confirmed' && c.classList.contains('finding-confirmedcheatartifact')) c.style.display = 'block';
    else if (cat === 'strong' && c.classList.contains('finding-strongindicator')) c.style.display = 'block';
    else if (cat === 'suspicious' && c.classList.contains('finding-suspicious')) c.style.display = 'block';
    else if (cat === 'info' && c.classList.contains('finding-informational')) c.style.display = 'block';
    else c.style.display = 'none';
  });
}

function searchFindings() {
  const query = document.getElementById('findingSearch').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(c => {
    c.style.display = c.innerText.toLowerCase().includes(query) ? 'block' : 'none';
  });
}
";
    }
}

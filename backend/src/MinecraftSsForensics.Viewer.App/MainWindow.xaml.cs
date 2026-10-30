using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Viewer.App;

public partial class MainWindow : Window
{
    private StandaloneReport? _currentReport;
    private List<FindingRecord> _allFindings = new();

    public MainWindow()
    {
        InitializeComponent();
    }

    private void BtnOpenReport_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open Forensic Report File (JSON)",
            Filter = "JSON Forensic Report (*.json)|*.json|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            LoadReportFromFile(dialog.FileName);
        }
    }

    public void LoadReportFromFile(string filePath)
    {
        try
        {
            var result = PortableJsonExporter.LoadFromFile(filePath);
            if (!result.Success || result.Report == null)
            {
                MessageBox.Show($"Failed to parse report file:\n{result.ErrorMessage}", "Invalid Report", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _currentReport = result.Report;
            DisplayReport(result.Report, filePath);
            TxtStatusBar.Text = $"Loaded report from: {Path.GetFileName(filePath)}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load report file:\n{ex.Message}", "Invalid Report", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void DisplayReport(StandaloneReport report, string filePath)
    {
        report.RecomputeSummaryCounts();

        // 1. Seal Verification
        var (sealValid, sealMessage) = ReportIntegrityValidator.VerifyReportIntegrity(report);
        if (sealValid)
        {
            TxtSealStatus.Text = "✔ Cryptographic Seal Verified (Authentic & Untampered)";
            TxtSealStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99));
        }
        else
        {
            TxtSealStatus.Text = "❌ " + sealMessage;
            TxtSealStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
        }

        TxtReportId.Text = $"Report ID: {report.ReportId} ({report.ScanMode} SCAN)";
        TxtReportMeta.Text = $"Target OS: {report.TargetSystem.OsName} ({report.TargetSystem.Architecture}) | Scanned: {report.ScanStartedAt:yyyy-MM-dd HH:mm:ss} UTC | Policy: {report.PolicyEvaluation.AppliedGamemode}";

        // 2. Metrics Counters
        TxtCountChecks.Text = report.SummaryCounts.TotalChecks.ToString();
        TxtCountCheats.Text = report.SummaryCounts.ConfirmedCheats.ToString();
        TxtCountIndicators.Text = report.SummaryCounts.StrongIndicators.ToString();
        TxtCountProhibited.Text = report.SummaryCounts.ProhibitedMods.ToString();
        TxtCountMods.Text = report.SummaryCounts.VerifiedMods.ToString();

        // 3. Verdict Card
        if (report.SummaryCounts.ConfirmedCheats > 0)
        {
            BorderVerdict.Background = new SolidColorBrush(Color.FromRgb(0x7F, 0x1D, 0x1D));
            BorderVerdict.BorderBrush = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
            TxtVerdictTitle.Text = "❌ " + report.Verdict.OverallAssessment;
            TxtVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xA5, 0xA5));
            TxtVerdictDesc.Text = report.Verdict.Recommendation;
        }
        else if (report.SummaryCounts.StrongIndicators > 0)
        {
            BorderVerdict.Background = new SolidColorBrush(Color.FromRgb(0x78, 0x35, 0x0F));
            BorderVerdict.BorderBrush = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
            TxtVerdictTitle.Text = "⚠️ " + report.Verdict.OverallAssessment;
            TxtVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xD3, 0x4D));
            TxtVerdictDesc.Text = report.Verdict.Recommendation;
        }
        else if (report.SummaryCounts.ProhibitedMods > 0 || report.CorrelatedAssessments.Any(a => a.IsPolicyViolation))
        {
            BorderVerdict.Background = new SolidColorBrush(Color.FromRgb(0x78, 0x35, 0x0F));
            BorderVerdict.BorderBrush = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
            TxtVerdictTitle.Text = "⚠️ " + report.Verdict.OverallAssessment;
            TxtVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xD3, 0x4D));
            TxtVerdictDesc.Text = report.Verdict.Recommendation;
        }
        else
        {
            BorderVerdict.Background = new SolidColorBrush(Color.FromRgb(0x06, 0x4E, 0x3B));
            BorderVerdict.BorderBrush = new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81));
            TxtVerdictTitle.Text = "✔ " + report.Verdict.OverallAssessment;
            TxtVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7));
            TxtVerdictDesc.Text = report.Verdict.Recommendation;
        }

        // 4. Bind Findings
        _allFindings = report.Findings;
        ApplyFindingsFilter();

        // 5. Bind Correlation Assessments
        GridCorrelation.ItemsSource = report.CorrelatedAssessments;

        // 6. Bind Mod Inventory
        GridMods.ItemsSource = report.ModInventory;

        // 7. Bind Services & Drivers
        GridServices.ItemsSource = report.ServicesAndDrivers;

        // 8. Bind Runtime & Modules
        GridModules.ItemsSource = report.LoadedModules;

        // 9. Bind History & Files
        GridExecHistory.ItemsSource = report.ExecutionHistory;
        GridDiscoveries.ItemsSource = report.FileDiscoveries;

        // 10. Bind Diagnostics
        GridDiagnostics.ItemsSource = report.DiagnosticChecks;

        // Enable Export buttons
        BtnViewInBrowser.IsEnabled = true;
        BtnExportMd.IsEnabled = true;
    }

    private void LstFindings_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LstFindings.SelectedItem is FindingRecord f)
        {
            TxtDetailTitle.Text = f.DetectionName;
            TxtDetailMeta.Text = $"Rule ID: {f.RuleId} • Classification: {f.Classification} • Software State: {f.SoftwareState} • Scope: {f.PolicyViolationScope}";
            TxtDetailExplanation.Text = f.TechnicalExplanation;
            TxtDetailPath.Text = $"Path: {f.FilePath ?? "N/A"}";
            TxtDetailHash.Text = $"SHA-256: {f.FileSha256 ?? "N/A"}";

            TxtDetailProven.Text = string.IsNullOrWhiteSpace(f.WhatIsProven) ? "Artifact presence or behavior documented above." : f.WhatIsProven;
            TxtDetailNotProven.Text = string.IsNullOrWhiteSpace(f.WhatIsNotProven) ? "Does not prove in-game advantage without corroborating match session evidence." : f.WhatIsNotProven;
            TxtDetailWhyMatters.Text = string.IsNullOrWhiteSpace(f.WhyItMatters) ? "Forensic indicator of modified game files or prohibited software." : f.WhyItMatters;
            TxtDetailAlternative.Text = string.IsNullOrWhiteSpace(f.AlternativeLegitimateExplanations) ? "Unrelated utility, development build, or joke file." : f.AlternativeLegitimateExplanations;
            TxtDetailLimitations.Text = string.IsNullOrWhiteSpace(f.Limitations) ? "Standard user-mode inspection scope." : f.Limitations;
        }
    }

    private void TxtSearchFindings_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyFindingsFilter();
    }

    private void CmbClassificationFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyFindingsFilter();
    }

    private void ApplyFindingsFilter()
    {
        if (_allFindings == null || LstFindings == null) return;

        string query = TxtSearchFindings?.Text?.Trim().ToLowerInvariant() ?? "";
        if (query == "search findings, files, rules...") query = "";

        string selectedClass = (CmbClassificationFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All Classifications";

        var filtered = _allFindings.Where(f =>
        {
            bool matchesText = string.IsNullOrEmpty(query) ||
                               f.DetectionName.ToLowerInvariant().Contains(query) ||
                               f.RuleId.ToLowerInvariant().Contains(query) ||
                               (f.FilePath != null && f.FilePath.ToLowerInvariant().Contains(query));

            bool matchesClass = selectedClass switch
            {
                "Confirmed Cheats" => f.Classification == FindingClassification.ConfirmedCheatArtifact,
                "Strong Indicators" => f.Classification == FindingClassification.StrongIndicator,
                "Suspicious" => f.Classification == FindingClassification.Suspicious,
                "Needs Review" => f.Classification == FindingClassification.NeedsReview,
                "Informational" => f.Classification == FindingClassification.Informational,
                _ => true
            };

            return matchesText && matchesClass;
        }).ToList();

        LstFindings.ItemsSource = filtered;
        if (filtered.Count > 0)
        {
            LstFindings.SelectedIndex = 0;
        }
    }

    private void BtnViewInBrowser_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;

        try
        {
            string tempHtml = Path.Combine(Path.GetTempPath(), $"MinecraftForensics_Report_{_currentReport.ReportId}.html");
            StandaloneHtmlExporter.SaveToFile(_currentReport, tempHtml);
            Process.Start(new ProcessStartInfo
            {
                FileName = tempHtml,
                UseShellExecute = true
            });
            TxtStatusBar.Text = $"Opened interactive report in default browser: {tempHtml}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to launch report in browser:\n{ex.Message}", "Launch Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnExportMd_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;

        string defaultName = $"MinecraftForensicReport_{DateTime.UtcNow:yyyy-MM-dd}_{_currentReport.ReportId}.md";
        var dialog = new SaveFileDialog
        {
            Title = "Export Forensic Report as Markdown",
            Filter = "Markdown Report (*.md)|*.md|All Files (*.*)|*.*",
            FileName = defaultName
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                string md = MarkdownExporter.ExportToMarkdown(_currentReport);
                File.WriteAllText(dialog.FileName, md, System.Text.Encoding.UTF8);
                TxtStatusBar.Text = $"Exported Markdown report: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show($"Report exported successfully to:\n{dialog.FileName}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export Markdown:\n{ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}

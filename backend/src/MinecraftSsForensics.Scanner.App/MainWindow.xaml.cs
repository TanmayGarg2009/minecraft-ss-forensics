using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Integrity;
using MinecraftSsForensics.Scanner.Models;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.App;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _scanCts;
    private StandaloneReport? _currentReport;
    private StandaloneReport? _staffReport;
    private readonly IStandaloneScannerEngine _engine;
    private readonly ModPolicyRegistry _policyRegistry = new();

    public MainWindow()
    {
        InitializeComponent();
        _engine = new StandaloneScannerEngine();
    }

    // =========================================================
    // Workflow Mode Toggling (Player vs Staff)
    // =========================================================

    private void WorkflowMode_Changed(object sender, RoutedEventArgs e)
    {
        if (PanelPlayerConsent == null || PanelStaffViewer == null) return;

        bool isStaff = RbModeStaff.IsChecked == true;
        PanelStaffViewer.Visibility = isStaff ? Visibility.Visible : Visibility.Collapsed;

        if (isStaff)
        {
            PanelPlayerConsent.Visibility = Visibility.Collapsed;
            PanelPlayerScanning.Visibility = Visibility.Collapsed;
            PanelPlayerResults.Visibility = Visibility.Collapsed;
            LblStatus.Text = "Staff Report Viewer active. Open a report file (.json) to inspect findings.";
        }
        else
        {
            if (_currentReport != null)
                PanelPlayerResults.Visibility = Visibility.Visible;
            else
                PanelPlayerConsent.Visibility = Visibility.Visible;

            LblStatus.Text = "Player Scan Mode active. Review scope and provide explicit consent to scan.";
        }
    }

    // =========================================================
    // Player Workflow Handlers
    // =========================================================

    private void ChkConsent_Changed(object sender, RoutedEventArgs e)
    {
        BtnStartScan.IsEnabled = ChkExplicitConsent.IsChecked == true;
    }

    private void BtnBrowseDir_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Select Custom Minecraft Directory"
        };

        if (dialog.ShowDialog() == true)
        {
            TxtCustomDir.Text = dialog.FolderName;
        }
    }

    private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
    {
        if (ChkExplicitConsent.IsChecked != true) return;

        var consent = new ConsentScopeConfig
        {
            ConsentGiven = true,
            InspectMinecraftMods = ChkMods.IsChecked == true,
            InspectProcessesAndModules = ChkProcesses.IsChecked == true,
            InspectExecutionArtifacts = ChkExecution.IsChecked == true,
            InspectRegistryArtifacts = ChkRegistry.IsChecked == true,
            InspectUsbHistory = ChkUsb.IsChecked == true,
            InspectFileDiscovery = ChkDiscovery.IsChecked == true,
            InspectBrowserHistory = ChkBrowser.IsChecked == true // Explicitly optional!
        };

        string gamemode = CmbGamemode.SelectedItem is ComboBoxItem item
            ? item.Content.ToString()!.Split('(')[0].Trim()
            : "Crystal PvP";

        var policy = _policyRegistry.GetPolicy(gamemode);
        string scanMode = RbFull.IsChecked == true ? "FULL" : "QUICK";
        string? customDir = string.IsNullOrWhiteSpace(TxtCustomDir.Text) ? null : TxtCustomDir.Text.Trim();

        _scanCts = new CancellationTokenSource();

        PanelPlayerConsent.Visibility = Visibility.Collapsed;
        PanelPlayerScanning.Visibility = Visibility.Visible;
        PanelPlayerResults.Visibility = Visibility.Collapsed;

        var progress = new Progress<ScanProgressUpdate>(update =>
        {
            ProgScanBar.Value = update.PercentComplete;
            LblScanCategory.Text = update.CurrentCategory;
            LblScanAction.Text = update.CurrentAction;
            LblStatus.Text = $"[{update.PercentComplete}%] {update.CurrentCategory}: {update.CurrentAction}";
        });

        try
        {
            _currentReport = await _engine.ExecuteScanAsync(
                consent,
                scanMode,
                customDir,
                onlyCustomDirectory: false,
                progress,
                policy,
                _scanCts.Token);

            ShowPlayerResults(_currentReport);
        }
        catch (OperationCanceledException)
        {
            PanelPlayerScanning.Visibility = Visibility.Collapsed;
            PanelPlayerConsent.Visibility = Visibility.Visible;
            LblStatus.Text = "Scan was cancelled by user.";
        }
        catch (Exception ex)
        {
            PanelPlayerScanning.Visibility = Visibility.Collapsed;
            PanelPlayerConsent.Visibility = Visibility.Visible;
            LblStatus.Text = $"Scan failed: {ex.Message}";
            MessageBox.Show($"Error running forensic scan:\n{ex.Message}", "Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnCancelScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void ShowPlayerResults(StandaloneReport report)
    {
        PanelPlayerScanning.Visibility = Visibility.Collapsed;
        PanelPlayerResults.Visibility = Visibility.Visible;

        // Verdict Card Styling
        if (report.SummaryCounts.ConfirmedCheats > 0)
        {
            CardVerdict.Background = new SolidColorBrush(Color.FromRgb(0x7F, 0x1D, 0x1D));
            LblVerdictTitle.Text = "❌ CONFIRMED CHEAT ARTIFACTS DETECTED";
            LblVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xA5, 0xA5));
            LblVerdictDesc.Text = $"{report.SummaryCounts.ConfirmedCheats} cheat artifact(s) discovered on system.";
            LblVerdictDesc.Foreground = new SolidColorBrush(Color.FromRgb(0xFE, 0xE2, 0xE2));
        }
        else if (report.SummaryCounts.StrongIndicators > 0)
        {
            CardVerdict.Background = new SolidColorBrush(Color.FromRgb(0x78, 0x35, 0x0F));
            LblVerdictTitle.Text = "⚠️ STRONG SUSPICIOUS INDICATORS IDENTIFIED";
            LblVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xD3, 0x4D));
            LblVerdictDesc.Text = "Execution traces matching known cheat utilities identified.";
            LblVerdictDesc.Foreground = new SolidColorBrush(Color.FromRgb(0xFE, 0xF3, 0xC7));
        }
        else if (report.SummaryCounts.ProhibitedMods > 0)
        {
            CardVerdict.Background = new SolidColorBrush(Color.FromRgb(0x78, 0x35, 0x0F));
            LblVerdictTitle.Text = "⚠️ SERVER POLICY VIOLATIONS (PROHIBITED MODS)";
            LblVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xD3, 0x4D));
            LblVerdictDesc.Text = $"Discovered {report.SummaryCounts.ProhibitedMods} prohibited mod(s) under {report.PolicyEvaluation.AppliedGamemode} ruleset.";
            LblVerdictDesc.Foreground = new SolidColorBrush(Color.FromRgb(0xFE, 0xF3, 0xC7));
        }
        else
        {
            CardVerdict.Background = new SolidColorBrush(Color.FromRgb(0x06, 0x4E, 0x3B));
            LblVerdictTitle.Text = "✔ NO EVIDENCE OF CHEATING DETECTED";
            LblVerdictTitle.Foreground = new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7));
            LblVerdictDesc.Text = "No confirmed cheat software or prohibited mod artifacts discovered.";
            LblVerdictDesc.Foreground = new SolidColorBrush(Color.FromRgb(0xA7, 0xF3, 0xD0));
        }

        TxtResChecks.Text = report.SummaryCounts.TotalChecks.ToString();
        TxtResPassed.Text = report.SummaryCounts.PassedChecks.ToString();
        TxtResFindings.Text = report.SummaryCounts.TotalFindings.ToString();
        TxtResMods.Text = report.SummaryCounts.VerifiedMods.ToString();

        LstPlayerFindings.Items.Clear();
        if (report.Findings.Count == 0)
        {
            LstPlayerFindings.Items.Add("No suspicious findings flagged within inspected scope.");
        }
        else
        {
            foreach (var f in report.Findings)
            {
                LstPlayerFindings.Items.Add($"[{f.Classification.ToString().ToUpperInvariant()}] {f.DetectionName}");
            }
        }

        LblStatus.Text = $"Scan complete ({report.ScanDurationMs} ms). Choose format to save report.";
    }

    private void BtnSaveJson_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;

        string defaultName = $"MinecraftForensicReport_{DateTime.UtcNow:yyyy-MM-dd}_{_currentReport.ReportId}.json";
        var dialog = new SaveFileDialog
        {
            Title = "Save Full Forensic Report (JSON)",
            Filter = "JSON Forensic Report (*.json)|*.json|All Files (*.*)|*.*",
            FileName = defaultName
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                PortableJsonExporter.SaveToFile(_currentReport, dialog.FileName);
                LblStatus.Text = $"Saved JSON report: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show($"Forensic report saved to:\n{dialog.FileName}\n\nYou can send this file directly to server staff.", "Report Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save report:\n{ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void BtnSaveHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;

        string defaultName = $"MinecraftForensicReport_{DateTime.UtcNow:yyyy-MM-dd}_{_currentReport.ReportId}.html";
        var dialog = new SaveFileDialog
        {
            Title = "Save Interactive Offline Report (HTML)",
            Filter = "Interactive HTML Report (*.html)|*.html|All Files (*.*)|*.*",
            FileName = defaultName
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                StandaloneHtmlExporter.SaveToFile(_currentReport, dialog.FileName);
                LblStatus.Text = $"Saved HTML report: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show($"Interactive HTML report saved to:\n{dialog.FileName}\n\nThis file opens in any browser offline without internet or server access.", "Report Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save HTML report:\n{ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void BtnSaveMd_Click(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;

        string defaultName = $"MinecraftForensicReport_{DateTime.UtcNow:yyyy-MM-dd}_{_currentReport.ReportId}.md";
        var dialog = new SaveFileDialog
        {
            Title = "Save AI-Friendly Markdown Report (.md)",
            Filter = "Markdown Report (*.md)|*.md|All Files (*.*)|*.*",
            FileName = defaultName
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                string md = MarkdownExporter.ExportToMarkdown(_currentReport);
                File.WriteAllText(dialog.FileName, md, System.Text.Encoding.UTF8);
                LblStatus.Text = $"Saved Markdown report: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show($"Markdown report saved to:\n{dialog.FileName}\n\nThis format is optimized for second-stage AI analysis (ChatGPT / Claude / Gemini).", "Report Saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save report:\n{ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void BtnNewScan_Click(object sender, RoutedEventArgs e)
    {
        _currentReport = null;
        ChkExplicitConsent.IsChecked = false;
        BtnStartScan.IsEnabled = false;
        PanelPlayerResults.Visibility = Visibility.Collapsed;
        PanelPlayerConsent.Visibility = Visibility.Visible;
        LblStatus.Text = "Ready to start a new scan.";
    }

    // =========================================================
    // Staff Report Viewer Handlers
    // =========================================================

    private void BtnOpenReportFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open Forensic Report File for Staff Investigation",
            Filter = "JSON Forensic Report (*.json)|*.json|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            var (success, report, errMsg) = PortableJsonExporter.LoadFromFile(dialog.FileName);
            if (!success || report == null)
            {
                MessageBox.Show($"Could not open report file:\n{errMsg}", "Invalid Report", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _staffReport = report;
            LoadStaffReportIntoViewer(report, Path.GetFileName(dialog.FileName));
        }
    }

    private void LoadStaffReportIntoViewer(StandaloneReport report, string fileName)
    {
        TxtStaffReportId.Text = $"{report.ReportId} ({fileName})";

        // Verify cryptographic integrity seal
        var (isValid, sealMsg) = ReportIntegrityValidator.VerifyReportIntegrity(report);
        if (isValid)
        {
            BadgeSealStatus.Background = new SolidColorBrush(Color.FromRgb(0x06, 0x4E, 0x3B));
            TxtSealStatus.Text = "✔ Cryptographic Seal Verified";
            TxtSealStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x6E, 0xE7, 0xB7));
        }
        else
        {
            BadgeSealStatus.Background = new SolidColorBrush(Color.FromRgb(0x7F, 0x1D, 0x1D));
            TxtSealStatus.Text = "⚠️ Seal Mismatch / Modified";
            TxtSealStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xA5, 0xA5));
        }

        RefreshStaffFindingsList();
        LblStatus.Text = $"Loaded report {report.ReportId}. Total findings: {report.Findings.Count}.";
    }

    private void RefreshStaffFindingsList()
    {
        if (_staffReport == null) return;

        string search = TxtStaffSearch.Text.Trim().ToLowerInvariant();
        int filterIndex = CmbStaffFilterClass.SelectedIndex;

        var filtered = _staffReport.Findings.Where(f =>
        {
            if (filterIndex == 1 && f.Classification != FindingClassification.ConfirmedCheatArtifact) return false;
            if (filterIndex == 2 && f.Classification != FindingClassification.StrongIndicator) return false;
            if (filterIndex == 3 && f.Classification != FindingClassification.Suspicious) return false;
            if (filterIndex == 4 && f.Classification != FindingClassification.NeedsReview) return false;
            if (filterIndex == 5 && f.Classification != FindingClassification.Informational) return false;

            if (!string.IsNullOrEmpty(search))
            {
                bool matchesTitle = f.DetectionName.ToLowerInvariant().Contains(search);
                bool matchesRule = f.RuleId.ToLowerInvariant().Contains(search);
                bool matchesFile = f.FilePath != null && f.FilePath.ToLowerInvariant().Contains(search);
                if (!matchesTitle && !matchesRule && !matchesFile) return false;
            }

            return true;
        }).ToList();

        LstStaffFindings.Items.Clear();
        foreach (var f in filtered)
        {
            LstStaffFindings.Items.Add($"[{f.Classification.ToString().ToUpperInvariant()}] {f.DetectionName}");
        }

        if (LstStaffFindings.Items.Count > 0)
        {
            LstStaffFindings.SelectedIndex = 0;
        }
    }

    private void LstStaffFindings_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_staffReport == null || LstStaffFindings.SelectedIndex < 0) return;

        int idx = LstStaffFindings.SelectedIndex;
        if (idx < _staffReport.Findings.Count)
        {
            var f = _staffReport.Findings[idx];
            TxtDetailTitle.Text = f.DetectionName;
            TxtDetailMeta.Text = $"Classification: {f.Classification} • Severity: {f.Severity} • Confidence: {f.Confidence} • Source: {f.EvidenceSource}";
            TxtDetailExplanation.Text = f.TechnicalExplanation;
            TxtDetailWhy.Text = string.IsNullOrWhiteSpace(f.WhyItMatters) ? "None specified" : f.WhyItMatters;
            TxtDetailAlt.Text = string.IsNullOrWhiteSpace(f.AlternativeLegitimateExplanations) ? "None identified" : f.AlternativeLegitimateExplanations;
            TxtDetailNotProven.Text = string.IsNullOrWhiteSpace(f.WhatIsNotProven) ? "What is NOT proven: Does not prove active cheat usage." : $"What is NOT proven: {f.WhatIsNotProven}";

            var props = new Dictionary<string, object?>
            {
                ["RuleId"] = f.RuleId,
                ["FilePath"] = f.FilePath,
                ["FileSha256"] = f.FileSha256,
                ["FileSizeBytes"] = f.FileSizeBytes,
                ["ProcessId"] = f.ProcessId,
                ["ProcessName"] = f.ProcessName,
                ["ProcessCommandLine"] = f.ProcessCommandLine,
                ["TimestampReliability"] = f.TimestampReliability
            };
            TxtDetailRawProps.Text = JsonSerializer.Serialize(props, new JsonSerializerOptions { WriteIndented = true });
        }
    }

    private void TxtStaffSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshStaffFindingsList();
    }

    private void CmbStaffFilter_Changed(object sender, SelectionChangedEventArgs e)
    {
        RefreshStaffFindingsList();
    }

    private void BtnStaffExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_staffReport == null)
        {
            MessageBox.Show("Please open a forensic report (.json) first.", "No Report Loaded", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            string tempHtml = Path.Combine(Path.GetTempPath(), $"ForensicReport_{_staffReport.ReportId}.html");
            StandaloneHtmlExporter.SaveToFile(_staffReport, tempHtml);

            System.Diagnostics.Process.Start(new ProcessStartInfo
            {
                FileName = tempHtml,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not launch browser:\n{ex.Message}", "Browser Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}

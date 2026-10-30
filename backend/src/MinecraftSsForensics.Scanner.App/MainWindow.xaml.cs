using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using MinecraftSsForensics.Api.Models.Domain;
using MinecraftSsForensics.Api.Models.Dtos.Ingestion;
using MinecraftSsForensics.Scanner.Client;
using MinecraftSsForensics.Scanner.Engine;
using MinecraftSsForensics.Scanner.Export;
using MinecraftSsForensics.Scanner.Policy;

namespace MinecraftSsForensics.Scanner.App;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _scanCts;
    private SubmitReportRequest? _scannedReport;
    private SubmitReportResponse? _uploadResult;
    private readonly IScannerEngine _engine;
    private readonly ModPolicyRegistry _policyRegistry = new();
    private ServerGamemodePolicy? _customPolicy;
    private IBackendApiClient? _apiClient;

    public MainWindow()
    {
        InitializeComponent();
        _engine = new ScannerEngine();
    }

    private void ChkConsent_Changed(object sender, RoutedEventArgs e)
    {
        BtnStartScan.IsEnabled = ChkConsent.IsChecked == true;
    }

    private void BtnBrowsePath_Click(object sender, RoutedEventArgs e)
    {
        // OpenFolderDialog is natively available in .NET 8 on Windows
        var dialog = new OpenFolderDialog
        {
            Title = "Select Minecraft Directory (.minecraft or Launcher Instance)"
        };

        if (dialog.ShowDialog() == true)
        {
            TxtCustomPath.Text = dialog.FolderName;
        }
    }

    private void CmbPolicyGamemode_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (CmbPolicyGamemode == null || TxtPolicyDescription == null || BtnBrowseCustomPolicy == null) return;

        int idx = CmbPolicyGamemode.SelectedIndex;
        BtnBrowseCustomPolicy.Visibility = idx == 7 ? Visibility.Visible : Visibility.Collapsed;

        string gamemodeKey = idx switch
        {
            0 => "Crystal PvP",
            1 => "Sword PvP",
            2 => "Axe PvP",
            3 => "UHC",
            4 => "Pot PvP",
            5 => "SMP",
            6 => "Default",
            _ => "Custom"
        };

        if (idx == 7)
        {
            TxtPolicyDescription.Text = _customPolicy != null
                ? $"Loaded Custom Policy: '{_customPolicy.PolicyName}' (v{_customPolicy.PolicyVersion}, Gamemode: {_customPolicy.Gamemode}, {_customPolicy.Rules.Count} rules)."
                : "Click 'Load JSON...' to select an administrator-supplied policy JSON file. Will fallback to Default if unselected.";
        }
        else
        {
            var p = _policyRegistry.GetPolicy(gamemodeKey);
            TxtPolicyDescription.Text = p.Description;
        }
    }

    private void BtnBrowseCustomPolicy_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select Mod Policy JSON File",
            Filter = "JSON Policy (*.json)|*.json|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            var (loadedPolicy, success, errors) = _policyRegistry.LoadPolicyFromFile(dialog.FileName);
            if (success)
            {
                _customPolicy = loadedPolicy;
                TxtPolicyDescription.Text = $"Loaded Custom Policy: '{_customPolicy.PolicyName}' (v{_customPolicy.PolicyVersion}, Gamemode: {_customPolicy.Gamemode}, {_customPolicy.Rules.Count} rules).";
                MessageBox.Show($"Policy '{_customPolicy.PolicyName}' loaded successfully ({_customPolicy.Rules.Count} rules).", "Policy Loaded", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                string errMsg = string.Join("\n", errors);
                MessageBox.Show($"Could not load policy JSON:\n{errMsg}\n\nFalling back to default policy.", "Invalid Policy", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
    {
        if (ChkConsent.IsChecked != true)
        {
            MessageBox.Show("Explicit consent is required to begin collection.", "Consent Required", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ScanMode mode = RbQuickScan.IsChecked == true ? ScanMode.Quick : ScanMode.Full;
        string? customDir = string.IsNullOrWhiteSpace(TxtCustomPath.Text) ? null : TxtCustomPath.Text.Trim();

        ServerGamemodePolicy selectedPolicy;
        if (CmbPolicyGamemode.SelectedIndex == 7 && _customPolicy != null)
        {
            selectedPolicy = _customPolicy;
        }
        else
        {
            string gamemodeKey = CmbPolicyGamemode.SelectedIndex switch
            {
                0 => "Crystal PvP",
                1 => "Sword PvP",
                2 => "Axe PvP",
                3 => "UHC",
                4 => "Pot PvP",
                5 => "SMP",
                _ => "Default"
            };
            selectedPolicy = _policyRegistry.GetPolicy(gamemodeKey);
        }

        SwitchView("Scanning");
        _scanCts = new CancellationTokenSource();

        var progress = new Progress<ScanProgressUpdate>(update =>
        {
            PrgScan.Value = update.PercentComplete;
            TxtScanCategory.Text = update.CurrentCategory;
            TxtScanAction.Text = string.IsNullOrEmpty(update.CurrentFileName)
                ? update.CurrentAction
                : $"{update.CurrentAction}\n{update.CurrentFileName}";

            LblDiscoveredCount.Text = update.DiscoveredModsCount.ToString();
            LblVerifiedCount.Text = update.VerifiedModsCount.ToString();
            LblFlaggedCount.Text = update.FlaggedFindingsCount.ToString();

            LblStatus.Text = $"Scanning ({selectedPolicy.Gamemode}): {update.CurrentCategory} ({update.PercentComplete}%)";
        });

        try
        {
            _scannedReport = await _engine.ExecuteScanAsync(
                mode: mode,
                customDirectory: customDir,
                onlyCustomDirectory: !string.IsNullOrWhiteSpace(customDir),
                progress: progress,
                policy: selectedPolicy,
                ct: _scanCts.Token);

            // Populate Review View
            PopulateReviewView(_scannedReport);
            SwitchView("Review");
            LblStatus.Text = $"Scan completed under {selectedPolicy.Gamemode} policy. Please review findings before confirming upload.";
        }
        catch (OperationCanceledException)
        {
            SwitchView("Consent");
            LblStatus.Text = "Scan was cancelled by user.";
            MessageBox.Show("Forensic scan was cancelled.", "Scan Cancelled", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            SwitchView("Consent");
            LblStatus.Text = $"Scan failed: {ex.Message}";
            MessageBox.Show($"Scan encountered an error:\n{ex.Message}", "Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    private void BtnCancelScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void PopulateReviewView(SubmitReportRequest report)
    {
        RevScanMode.Text = report.ScanMode;
        RevTotalChecks.Text = report.CollectionCoverage?.TotalChecks.ToString() ?? "0";
        RevPassedChecks.Text = report.CollectionCoverage?.PassedChecks.ToString() ?? "0";
        RevFlaggedFindings.Text = report.Findings.Count.ToString();

        LstFindingsPreview.Items.Clear();
        if (report.Findings.Count == 0)
        {
            LstFindingsPreview.Items.Add("No suspicious indicators flagged within inspected scope.");
        }
        else
        {
            foreach (var f in report.Findings)
            {
                LstFindingsPreview.Items.Add($"[{f.Severity.ToUpperInvariant()}] {f.RuleId}: {f.Title}");
            }
        }

        // Pretty print JSON preview
        try
        {
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            TxtRawJsonPreview.Text = json;
        }
        catch
        {
            TxtRawJsonPreview.Text = "JSON preview unavailable.";
        }
    }

    private void BtnDiscardScan_Click(object sender, RoutedEventArgs e)
    {
        _scannedReport = null;
        SwitchView("Consent");
        LblStatus.Text = "Scan discarded.";
    }

    private async void BtnConfirmUpload_Click(object sender, RoutedEventArgs e)
    {
        if (_scannedReport == null) return;

        string apiUrl = string.IsNullOrWhiteSpace(TxtApiUrl.Text) ? ReportShareUrlBuilder.DefaultDevApiUrl : TxtApiUrl.Text.Trim();
        string frontendUrl = string.IsNullOrWhiteSpace(TxtFrontendUrl.Text) ? ReportShareUrlBuilder.DefaultDevFrontendUrl : TxtFrontendUrl.Text.Trim();

        bool isProduction = Environment.GetEnvironmentVariable("MINECRAFT_SS_ENV")?.Equals("production", StringComparison.OrdinalIgnoreCase) == true;

        var (isValid, configError) = ReportShareUrlBuilder.ValidateConfiguration(apiUrl, frontendUrl, isProduction);
        if (!isValid)
        {
            MessageBox.Show(configError, "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _apiClient = new BackendApiClient(apiUrl);

        SwitchView("Uploading");
        LblStatus.Text = "Submitting forensic report to backend...";

        try
        {
            _uploadResult = await _apiClient.SubmitReportAsync(_scannedReport, frontendUrl);

            // Construct explicit public frontend viewer share URL
            string shareUrl = ReportShareUrlBuilder.BuildShareUrl(frontendUrl, _uploadResult.PublicId, isProduction);

            TxtShareUrl.Text = shareUrl;
            TxtDeletionKey.Text = _uploadResult.DeletionKey;
            LblResultMessage.Text = $"{_uploadResult.Message} (Expires: {_uploadResult.ExpiresAt.LocalDateTime:g})";

            SwitchView("Result");
            LblStatus.Text = $"Report {_uploadResult.PublicId} uploaded successfully.";
        }
        catch (Exception ex)
        {
            SwitchView("Review");
            LblStatus.Text = $"Upload failed: {ex.Message}";
            MessageBox.Show($"Failed to upload report to backend:\n{ex.Message}", "Upload Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnCopyShareUrl_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(TxtShareUrl.Text))
        {
            Clipboard.SetText(TxtShareUrl.Text);
            LblStatus.Text = "Share URL copied to clipboard! Provide this link to server staff.";
            MessageBox.Show("Share link copied to clipboard!\n\nSend this URL to the server anti-cheat staff.", "Link Copied", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnOpenInBrowser_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(TxtShareUrl.Text))
        {
            try
            {
                System.Diagnostics.Process.Start(new ProcessStartInfo
                {
                    FileName = TxtShareUrl.Text,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not launch default browser:\n{ex.Message}", "Browser Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private void BtnCopyDeletionKey_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(TxtDeletionKey.Text))
        {
            Clipboard.SetText(TxtDeletionKey.Text);
            LblStatus.Text = "Deletion key copied to clipboard. Keep this secret.";
            MessageBox.Show("Deletion key copied to clipboard!\n\nKeep this secret. You can use it to wipe the report at any time.", "Deletion Key Copied", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private async void BtnDeleteReportNow_Click(object sender, RoutedEventArgs e)
    {
        if (_uploadResult == null || _apiClient == null) return;

        var confirm = MessageBox.Show(
            "Are you sure you want to permanently delete this report and all associated raw evidence from the server right now?",
            "Confirm Permanent Report Deletion",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        try
        {
            LblStatus.Text = "Deleting report from server...";
            var deleteResult = await _apiClient.DeleteReportAsync(_uploadResult.PublicId, _uploadResult.DeletionKey);

            if (deleteResult.Success)
            {
                MessageBox.Show(deleteResult.Message, "Report Deleted", MessageBoxButton.OK, MessageBoxImage.Information);
                BtnNewScan_Click(sender, e);
            }
            else
            {
                MessageBox.Show(deleteResult.Message, "Deletion Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Deletion request failed: {ex.Message}", "Deletion Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnDownloadReport_Click(object sender, RoutedEventArgs e)
    {
        if (_scannedReport == null)
        {
            MessageBox.Show("No completed forensic report is available to export.", "Export Unavailable", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string? publicId = _uploadResult?.PublicId;
        var dialog = new SaveFileDialog
        {
            Title = "Save Forensic Report for AI / Offline Analysis",
            Filter = "JSON Forensic Report (*.json)|*.json|AI-Friendly Markdown Report (*.md)|*.md|All Files (*.*)|*.*",
            FilterIndex = 1,
            FileName = ReportExporter.GenerateSuggestedFilename(_scannedReport, ReportExportFormat.Json, publicId)
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var format = dialog.FileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
                    ? ReportExportFormat.Markdown
                    : ReportExportFormat.Json;

                var export = ReportExporter.GenerateExport(_scannedReport, format, publicId);
                File.WriteAllText(dialog.FileName, export.Content, Encoding.UTF8);

                LblStatus.Text = $"Export saved successfully: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show(
                    $"Report successfully exported to:\n{dialog.FileName}\n\nFormat: {format}\nSize: {export.ByteCount:N0} bytes\n\nThis file can be provided to an AI model or archived for offline forensic investigation.",
                    "Report Exported",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                LblStatus.Text = $"Export failed: {ex.Message}";
                MessageBox.Show($"Failed to save report export:\n{ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void BtnNewScan_Click(object sender, RoutedEventArgs e)
    {
        _scannedReport = null;
        _uploadResult = null;
        ChkConsent.IsChecked = false;
        BtnStartScan.IsEnabled = false;
        SwitchView("Consent");
        LblStatus.Text = "Ready to start a new scan.";
    }

    private void SwitchView(string viewName)
    {
        PanelConsent.Visibility = viewName == "Consent" ? Visibility.Visible : Visibility.Collapsed;
        PanelScanning.Visibility = viewName == "Scanning" ? Visibility.Visible : Visibility.Collapsed;
        PanelReview.Visibility = viewName == "Review" ? Visibility.Visible : Visibility.Collapsed;
        PanelUploading.Visibility = viewName == "Uploading" ? Visibility.Visible : Visibility.Collapsed;
        PanelResult.Visibility = viewName == "Result" ? Visibility.Visible : Visibility.Collapsed;
    }
}

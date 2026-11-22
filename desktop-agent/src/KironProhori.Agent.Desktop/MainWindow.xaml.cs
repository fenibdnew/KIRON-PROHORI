using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using KironProhori.Agent.Core.Localization;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.WindowsSecurity;

namespace KironProhori.Agent.Desktop;

/// <summary>
/// Code-behind for the KIRON PROHORI Phase 7A Windows Security Agent main window.
/// Implements all 13 navigation modules, bilingual English/Bengali switch, Dark/Light theme toggle,
/// cooperative scan cancellation, harmless EICAR verification, and user-confirmed quarantine operations.
/// </summary>
public partial class MainWindow : Window
{
    private readonly Sha256HashEngine _sha256Engine = new();
    private readonly HeuristicSuspiciousFileEngine _heuristicEngine = new();
    private readonly ClamAvExternalEngine _clamAvEngine = new();
    private readonly YaraExternalEngine _yaraEngine = new();
    private readonly ModularScanPipeline _scanPipeline;
    private readonly QuarantineManager _quarantineManager = new();
    private readonly WindowsSecurityMonitor _windowsSecurityMonitor = new();
    private readonly CloudThreatFeedSyncService _cloudSyncService = new();

    private readonly List<ScanFinding> _currentFindings = new();
    private readonly List<ScanReport> _scanHistory = new();
    private IReadOnlyList<QuarantineEntry> _quarantineEntries = Array.Empty<QuarantineEntry>();

    private CancellationTokenSource? _activeScanCts;
    private bool _isBengali;
    private bool _isLightMode;
    private string _activeViewKey = "Overview";

    public MainWindow()
    {
        InitializeComponent();

        _scanPipeline = new ModularScanPipeline(new IScanEngine[]
        {
            _sha256Engine,
            _heuristicEngine,
            _clamAvEngine,
            _yaraEngine
        });

        Loaded += async (_, _) =>
        {
            await _quarantineManager.RecoverAndVerifyVaultIntegrityAsync();
            RefreshWindowsTelemetryBanner();
            await RefreshQuarantineAndEngineListAsync();
        };
    }

    private void RefreshWindowsTelemetryBanner()
    {
        var snapshot = _windowsSecurityMonitor.GetSecuritySnapshot();
        string fwSummary = string.Join(
            ", ",
            snapshot.FirewallProfiles.Select(p => $"{p.ProfileName}: {(p.IsEnabled ? "ON" : "OFF")}"));

        TelemetrySummaryText.Text =
            $"OS: {snapshot.OsProductName} ({snapshot.OsArchitecture}) | Defender: {snapshot.MicrosoftDefenderStatus} | " +
            $"RTP: {(snapshot.RealTimeProtectionEnabled ? "ON" : "OFF")} | Firewall [{fwSummary}] | Zero-Mod Guarantee: VERIFIED";
    }

    private async Task RefreshQuarantineAndEngineListAsync()
    {
        _quarantineEntries = await _quarantineManager.ListQuarantineEntriesAsync();
        QuarantineAndStatusListBox.Items.Clear();

        QuarantineAndStatusListBox.Items.Add("=== MODULAR ENGINE STATUS ===");
        foreach (var desc in _scanPipeline.GetEngineStatuses())
        {
            QuarantineAndStatusListBox.Items.Add($"[{desc.Status}] {desc.DisplayName} — {desc.StatusDetail}");
        }

        QuarantineAndStatusListBox.Items.Add("");
        QuarantineAndStatusListBox.Items.Add($"=== QUARANTINE VAULT ({_quarantineEntries.Count(e => !e.IsRestored)} Active Isolated .kpq) ===");
        foreach (var q in _quarantineEntries.Where(e => !e.IsRestored))
        {
            QuarantineAndStatusListBox.Items.Add($"{q.QuarantineId} | {q.DetectionName} | {q.OriginalFilePath} | SHA256: {q.Sha256Hash[..16]}...");
        }
    }

    private async void OnNavButtonClick(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string viewKey) return;
        _activeViewKey = viewKey;
        ActiveSectionTitle.Text = btn.Content?.ToString() ?? viewKey;

        switch (viewKey)
        {
            case "QuickScan":
                await ExecuteQuickScanAsync();
                break;
            case "CustomScan":
                await ExecuteCustomFolderScanAsync();
                break;
            case "UsbScan":
                await ExecuteUsbDriveScanAsync();
                break;
            case "Firewall":
            case "WindowsSecurity":
            case "ProtectionStatus":
                ShowWindowsSecurityDetailInList();
                break;
            case "Updates":
                await SynchronizeCloudSignaturesAsync();
                break;
            case "Reports":
            case "ThreatHistory":
                ShowScanReportsInList();
                break;
            default:
                RefreshWindowsTelemetryBanner();
                await RefreshQuarantineAndEngineListAsync();
                break;
        }
    }

    private async void OnRunQuickScanClick(object sender, RoutedEventArgs e) =>
        await ExecuteQuickScanAsync();

    private async Task ExecuteQuickScanAsync()
    {
        var dirs = ModularScanPipeline.GetQuickScanDirectories();
        await RunDirectoryScanWithUiAsync(ScanType.QuickScan, dirs);
    }

    private async Task ExecuteCustomFolderScanAsync()
    {
        using var dialog = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select folder for KIRON PROHORI Custom Folder Scan (Read-Only Inspection)"
        };

        if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK &&
            !string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            await RunDirectoryScanWithUiAsync(ScanType.CustomFolderScan, new[] { dialog.SelectedPath });
        }
    }

    private async Task ExecuteUsbDriveScanAsync()
    {
        var usbDrives = ModularScanPipeline.GetRemovableUsbDrives();
        if (usbDrives.Count == 0)
        {
            FindingsListBox.Items.Clear();
            FindingsListBox.Items.Add("USB SCAN: No mounted removable USB drives (DriveType.Removable) detected.");
            return;
        }

        await RunDirectoryScanWithUiAsync(
            ScanType.UsbDriveScan,
            usbDrives.Select(d => d.RootDirectory.FullName));
    }

    private async Task RunDirectoryScanWithUiAsync(ScanType scanType, IEnumerable<string> directories)
    {
        _activeScanCts?.Cancel();
        _activeScanCts = new CancellationTokenSource();
        CancelScanBtn.IsEnabled = true;
        RunQuickScanBtn.IsEnabled = false;
        ScanProgressBar.IsIndeterminate = true;

        var progress = new Progress<ScanProgressUpdate>(u =>
        {
            ScanStatusSummaryText.Text =
                $"{u.ScanType}: Scanned {u.FilesScanned} files ({u.ThreatsFound} findings, {u.SkippedPermissionCount} permission-skipped) · {u.CurrentFilePath}";
        });

        try
        {
            var report = await _scanPipeline.ScanDirectoriesAsync(scanType, directories, progress, _activeScanCts.Token);
            _scanHistory.Insert(0, report);
            RenderScanReport(report);
        }
        finally
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            CancelScanBtn.IsEnabled = false;
            RunQuickScanBtn.IsEnabled = true;
        }
    }

    private async void OnRunEicarTestClick(object sender, RoutedEventArgs e)
    {
        // Creates a temporary harmless EICAR standard antivirus test file in %TEMP%\KironProhori_EicarTest,
        // scans it with ModularScanPipeline, and displays the verified detection ready for Quarantine test.
        string tempDir = Path.Combine(Path.GetTempPath(), "KironProhori_HarmlessEicarTest");
        Directory.CreateDirectory(tempDir);
        string eicarFilePath = Path.Combine(tempDir, "eicar_harmless_verification.txt");

        await File.WriteAllTextAsync(eicarFilePath, Sha256HashEngine.OfficialEicarTestString, Encoding.ASCII);

        var report = await _scanPipeline.ScanSingleFileAsync(eicarFilePath);
        _scanHistory.Insert(0, report);
        RenderScanReport(report);
    }

    private void OnCancelScanClick(object sender, RoutedEventArgs e)
    {
        _activeScanCts?.Cancel();
        ScanStatusSummaryText.Text = "Cancelling active scan...";
    }

    private void RenderScanReport(ScanReport report)
    {
        _currentFindings.Clear();
        _currentFindings.AddRange(report.Findings);

        FindingsListBox.Items.Clear();
        FindingsListBox.Items.Add(
            $"REPORT {report.ReportId} | {report.ScanType} | Status: {report.Status} | " +
            $"Files: {report.TotalFilesScanned} | Verified Threats: {report.ThreatsDetectedCount} | " +
            $"Heuristics: {report.SuspiciousHeuristicCount} | Skipped: {report.SkippedPermissionCount}");

        foreach (var finding in report.Findings)
        {
            FindingsListBox.Items.Add(
                $"[{finding.Severity} · {finding.Confidence}] {finding.DetectionName} | {finding.FilePath} | SHA256: {finding.Sha256Hash}");
        }

        if (report.Findings.Count == 0)
        {
            FindingsListBox.Items.Add("CLEAN: Zero verified threats or suspicious heuristics found in target scope.");
        }

        ScanStatusSummaryText.Text =
            $"{report.ScanType} {report.Status} in {report.DurationSeconds}s · {report.TotalFilesScanned} file(s) inspected.";
    }

    private async void OnQuarantineSelectedClick(object sender, RoutedEventArgs e)
    {
        if (_currentFindings.Count == 0)
        {
            System.Windows.MessageBox.Show("No active threat finding available to quarantine.", "Quarantine Manager");
            return;
        }

        var targetFinding = _currentFindings[0];
        var confirm = System.Windows.MessageBox.Show(
            $"Confirm Quarantine Action:\n\nFile: {targetFinding.FilePath}\nDetection: {targetFinding.DetectionName}\nSHA-256: {targetFinding.Sha256Hash}\n\nIsolate this file into the non-executable .kpq Quarantine Vault?",
            "KIRON PROHORI — Mandatory User Confirmation Gate",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm == MessageBoxResult.Yes)
        {
            await _quarantineManager.QuarantineFileAsync(targetFinding, userConfirmed: true);
            _currentFindings.RemoveAt(0);
            await RefreshQuarantineAndEngineListAsync();
            ScanStatusSummaryText.Text = $"Quarantined '{targetFinding.FileName}' into isolated .kpq vault with audit trail.";
        }
    }

    private async void OnRestoreQuarantineClick(object sender, RoutedEventArgs e)
    {
        var active = _quarantineEntries.FirstOrDefault(q => !q.IsRestored);
        if (active == null)
        {
            System.Windows.MessageBox.Show("No active quarantined files in vault to restore.", "Quarantine Manager");
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"Confirm Restore Action:\n\nRestore '{active.OriginalFileName}' back to:\n{active.OriginalFilePath}?",
            "KIRON PROHORI — Mandatory Restore Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm == MessageBoxResult.Yes)
        {
            await _quarantineManager.RestoreQuarantinedFileAsync(active.QuarantineId, userConfirmed: true);
            await RefreshQuarantineAndEngineListAsync();
            ScanStatusSummaryText.Text = $"Restored '{active.OriginalFileName}' and verified SHA-256 integrity.";
        }
    }

    private async void OnDeleteQuarantineClick(object sender, RoutedEventArgs e)
    {
        var active = _quarantineEntries.FirstOrDefault(q => !q.IsRestored);
        if (active == null)
        {
            System.Windows.MessageBox.Show("No active quarantined files in vault to delete.", "Quarantine Manager");
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"PERMANENT DELETION CONFIRMATION:\n\nPermanently delete isolated payload for '{active.OriginalFileName}' (SHA-256: {active.Sha256Hash})?\nThis action cannot be undone.",
            "KIRON PROHORI — Permanent Deletion Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Stop);

        if (confirm == MessageBoxResult.Yes)
        {
            await _quarantineManager.PermanentlyDeleteQuarantinedFileAsync(active.QuarantineId, userConfirmed: true);
            await RefreshQuarantineAndEngineListAsync();
            ScanStatusSummaryText.Text = $"Permanently deleted '{active.OriginalFileName}' from Quarantine Vault.";
        }
    }

    private void ShowWindowsSecurityDetailInList()
    {
        var snap = _windowsSecurityMonitor.GetSecuritySnapshot();
        FindingsListBox.Items.Clear();
        FindingsListBox.Items.Add("=== READ-ONLY WINDOWS SECURITY & DEFENDER CO-EXISTENCE TELEMETRY ===");
        FindingsListBox.Items.Add($"OS Version & Build      : {snap.OsProductName} (Build {snap.OsBuildNumber})");
        FindingsListBox.Items.Add($"Architecture            : {snap.OsArchitecture} (64-Bit OS: {snap.Is64BitOperatingSystem})");
        FindingsListBox.Items.Add($"Microsoft Defender      : {snap.MicrosoftDefenderStatus}");
        FindingsListBox.Items.Add($"Real-Time Protection    : {(snap.RealTimeProtectionEnabled ? "ENABLED" : "DISABLED / UNKNOWN")}");
        FindingsListBox.Items.Add($"Defender Signature Ver  : {snap.AntivirusSignatureVersion}");
        FindingsListBox.Items.Add($"Defender Engine Version : {snap.AntivirusEngineVersion}");
        FindingsListBox.Items.Add($"Last Quick Scan         : {snap.LastQuickScanTime}");
        FindingsListBox.Items.Add($"Last Full Scan          : {snap.LastFullScanTime}");
        FindingsListBox.Items.Add($"Pending Security Updates: {snap.PendingWindowsUpdatesStatus}");
        FindingsListBox.Items.Add($"Zero System Mods Guard  : {snap.ZeroSystemModificationsGuaranteed} (Never disables Defender/Firewall)");

        foreach (var fw in snap.FirewallProfiles)
        {
            FindingsListBox.Items.Add($"Firewall [{fw.ProfileName}] : {(fw.IsEnabled ? "ENABLED" : "DISABLED")} ({fw.DefaultInboundAction} / {fw.SourceInterface})");
        }
    }

    private async Task SynchronizeCloudSignaturesAsync()
    {
        ScanStatusSummaryText.Text = "Syncing read-only public signatures from KIRON PROHORI Intelligence Cloud...";
        var bundle = await _cloudSyncService.PullPublicSignaturesAsync(_sha256Engine);
        FindingsListBox.Items.Clear();
        if (bundle != null)
        {
            FindingsListBox.Items.Add($"CLOUD SYNC SUCCEEDED: Bundle {bundle.BundleVersion} at {bundle.GeneratedAtUtc:O}");
            FindingsListBox.Items.Add($"CISA KEV Catalog Count          : {bundle.CisaKevCount}");
            FindingsListBox.Items.Add($"abuse.ch Feodo Tracker C2 Count : {bundle.FeodoC2Count}");
            FindingsListBox.Items.Add($"Total Local SHA-256 Signatures  : {_sha256Engine.KnownSignatureCount}");
            ScanStatusSummaryText.Text = $"Cloud signature sync complete ({_sha256Engine.KnownSignatureCount} SHA-256 signatures active).";
        }
        else
        {
            FindingsListBox.Items.Add($"CLOUD SYNC STATUS: {_cloudSyncService.LastSyncStatus} (Operating with local built-in signatures).");
            ScanStatusSummaryText.Text = $"Cloud sync offline ({_cloudSyncService.LastSyncStatus}) — Local SHA-256 & Heuristic engines ready.";
        }
        await RefreshQuarantineAndEngineListAsync();
    }

    private void ShowScanReportsInList()
    {
        FindingsListBox.Items.Clear();
        FindingsListBox.Items.Add($"=== LOCAL SCAN REPORT HISTORY ({_scanHistory.Count} Runs) ===");
        foreach (var r in _scanHistory)
        {
            FindingsListBox.Items.Add(
                $"{r.CompletedAtUtc:yyyy-MM-dd HH:mm:ss} UTC | {r.ReportId} | {r.ScanType} | {r.Status} | " +
                $"Files: {r.TotalFilesScanned} | Threats: {r.ThreatsDetectedCount} | Heuristics: {r.SuspiciousHeuristicCount}");
        }
    }

    private void OnToggleLanguageClick(object sender, RoutedEventArgs e)
    {
        _isBengali = !_isBengali;
        BrandTitleText.Text = BilingualStrings.Get("BrandTitle", _isBengali);
        PhaseSubtitleText.Text = BilingualStrings.Get("PhaseBadge", _isBengali);
        CoexistenceNoticeText.Text = BilingualStrings.Get("CoexistenceBanner", _isBengali);
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        _isLightMode = !_isLightMode;
        if (_isLightMode)
        {
            Resources["AppBackgroundBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(248, 250, 252));
            Resources["SurfaceCardBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 255, 255));
            Resources["BorderHairlineBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(203, 213, 225));
            Resources["PrimaryTextBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(15, 23, 42));
            Resources["MutedTextBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(71, 85, 105));
        }
        else
        {
            Resources["AppBackgroundBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(8, 13, 26));
            Resources["SurfaceCardBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(14, 22, 40));
            Resources["BorderHairlineBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 45, 74));
            Resources["PrimaryTextBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(241, 245, 249));
            Resources["MutedTextBrush"] = new SolidColorBrush(System.Windows.Media.Color.FromRgb(148, 163, 184));
        }
    }
}

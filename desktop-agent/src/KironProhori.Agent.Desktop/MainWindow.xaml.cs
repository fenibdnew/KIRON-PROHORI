using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Media;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using KironProhori.Agent.Core.BrowserProtection;
using KironProhori.Agent.Core.Diagnostics;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Localization;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Performance;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Realtime;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.Updates;
using KironProhori.Agent.Core.WindowsSecurity;

namespace KironProhori.Agent.Desktop;

public partial class MainWindow : Window
{
    private readonly ExclusionManager _exclusionManager;
    private readonly PerformanceProtectionGuard _performanceGuard;
    private readonly SmartNotificationManager _notificationManager;
    private readonly SecureUpdateManager _updateManager;
    private readonly ErrorDiagnosticsManager _diagnosticsManager;
    private readonly ModularScanPipeline _scanPipeline;
    private readonly QuarantineManager _quarantineManager;
    private readonly WindowsSecurityMonitor _windowsSecurityMonitor;
    private readonly RealTimeFileProtectionMonitor _realTimeMonitor;
    private readonly NativeMessagingDownloadGuard _browserDownloadGuard;

    private readonly List<ScanFinding> _currentFindings = new();
    private readonly List<ScanReport> _scanHistory = new();
    private List<QuarantineEntry> _currentQuarantineItems = new();
    private CancellationTokenSource? _activeScanCts;
    private string _currentLanguage = "en";
    private bool _isDarkTheme = true;

    public MainWindow()
    {
        InitializeComponent();

        var localAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KironProhori"
        );

        _exclusionManager = new ExclusionManager(Path.Combine(localAppData, "Exclusions"));
        _performanceGuard = new PerformanceProtectionGuard();
        _notificationManager = new SmartNotificationManager();
        _updateManager = new SecureUpdateManager(Path.Combine(localAppData, "Updates"));
        _diagnosticsManager = new ErrorDiagnosticsManager(localAppData);

        _scanPipeline = new ModularScanPipeline(
            engines: null,
            exclusionManager: _exclusionManager,
            performanceGuard: _performanceGuard,
            notificationManager: _notificationManager
        );

        _quarantineManager = new QuarantineManager(
            Path.Combine(localAppData, "Quarantine"),
            _exclusionManager
        );
        _windowsSecurityMonitor = new WindowsSecurityMonitor();
        _realTimeMonitor = new RealTimeFileProtectionMonitor(
            _scanPipeline,
            _exclusionManager,
            _notificationManager
        );
        _browserDownloadGuard = new NativeMessagingDownloadGuard(
            _scanPipeline,
            _exclusionManager,
            _quarantineManager,
            _notificationManager
        );

        Loaded += async (_, _) =>
        {
            await RefreshWindowsSecurityPostureAsync();
            await RefreshQuarantineVaultAsync();
        };
    }

    private void RenderFindingInList(ScanFinding finding)
    {
        FindingsListBox.Items.Insert(
            0,
            $"[{finding.Verdict}] [{finding.Severity}] {finding.DetectionName} | {finding.FilePath} | Source: {finding.DetectionSourceAttribution} | Action: {finding.RecommendedAction}"
        );
    }

    private async Task RefreshWindowsSecurityPostureAsync()
    {
        var posture = _windowsSecurityMonitor.GetSecuritySnapshot();
        DefenderStatusText.Text = posture.RealTimeProtectionEnabled
            ? $"Real-Time ON ({(posture.IsRunningAsAdministrator ? "Admin" : "Standard User")})"
            : posture.MicrosoftDefenderStatus;
        SignatureVersionText.Text = $"Signature: {posture.AntivirusSignatureVersion}";
        FirewallStatusText.Text = string.Join(
            " ",
            posture.FirewallProfiles.Select(p => $"{p.ProfileName}:{OnOff(p.IsEnabled)}")
        );
        UacStatusText.Text = $"Telemetry: OFF ({AboutBrandMetadata.PrivacyPolicyDefault})";

        var diag = await _diagnosticsManager.RunSelfDiagnosticAndRepairAsync();
        DiagnosticsHealthText.Text = $"Diagnostics: {diag.Status} ({diag.TotalLocalErrorLogs} logs)";
    }

    private static string OnOff(bool state) => state ? "ON" : "OFF";

    private async Task RefreshQuarantineVaultAsync()
    {
        RightPanelHeaderText.Text = "QUARANTINE VAULT (.KPQ ISOLATED ITEMS)";
        _currentQuarantineItems = (await _quarantineManager.ListQuarantineEntriesAsync())
            .Where(e => !e.IsRestored)
            .ToList();
        var exclusionsCount = _exclusionManager.GetExclusions().Count;
        QuarantineCountText.Text = $"{_currentQuarantineItems.Count} Quarantined · {exclusionsCount} Excluded";
        QuarantineListBox.Items.Clear();

        foreach (var item in _currentQuarantineItems)
        {
            QuarantineListBox.Items.Add(
                $"{item.QuarantineId[..8]} | {item.DetectionName} ({item.DetectionEngineId}) | Orig: {item.OriginalFilePath}"
            );
        }
    }

    private void OnNavigateOverviewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = $"{BilingualStrings.Get("nav.overview", _currentLanguage)} — Privacy-First Windows Companion";
        StatusFooterText.Text = "Overview ready. All scans and exclusions are stored locally without telemetry.";
    }

    private async void OnQuickScanClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.quick_scan", _currentLanguage);
        var quickTargets = ModularScanPipeline.GetQuickScanDirectories();
        await RunScanWorkflowAsync(ScanType.QuickScan, quickTargets.Take(1));
    }

    private async void OnFullScanClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.full_scan", _currentLanguage);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        await RunScanWorkflowAsync(ScanType.FullScan, new[] { userProfile });
    }

    private async void OnCustomScanClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.custom_scan", _currentLanguage);
        var docsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        await RunScanWorkflowAsync(ScanType.CustomFolderScan, new[] { docsPath });
    }

    private async void OnUsbScanClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.usb_scan", _currentLanguage);
        var removableDrives = ModularScanPipeline.GetRemovableUsbDrives()
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        if (removableDrives.Count == 0)
        {
            StatusFooterText.Text = "No removable USB drives currently mounted.";
            return;
        }

        await RunScanWorkflowAsync(ScanType.UsbDriveScan, removableDrives);
    }

    private void OnPauseResumeScanClick(object sender, RoutedEventArgs e)
    {
        if (_performanceGuard.IsPaused)
        {
            _scanPipeline.ResumeActiveScan();
            PauseResumeScanBtn.Content = "Pause Scan";
            ScanStateText.Text = "RUNNING (Resumed)";
            StatusFooterText.Text = "Scan resumed by user.";
        }
        else
        {
            _scanPipeline.PauseActiveScan();
            PauseResumeScanBtn.Content = "Resume Scan";
            ScanStateText.Text = "PAUSED BY USER";
            StatusFooterText.Text = "Scan paused. Click Resume Scan to continue without losing progress.";
        }
    }

    private void OnCancelScanClick(object sender, RoutedEventArgs e)
    {
        _activeScanCts?.Cancel();
        _scanPipeline.ResumeActiveScan();
        PauseResumeScanBtn.Content = "Pause Scan";
        ScanStateText.Text = "CANCELLED";
        StatusFooterText.Text = "Active scan stopped safely by user.";
    }

    private void OnWebProtectionViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = "06. Web Protection (Chrome & Microsoft Edge Manifest V3 Extension)";
        RightPanelHeaderText.Text = "DECLARATIVENETREQUEST RULES & TEMPORARY ALLOWLIST";
        QuarantineListBox.Items.Clear();
        foreach (var rule in NativeMessagingDownloadGuard.GetVerifiedWebProtectionRules())
        {
            QuarantineListBox.Items.Add(
                $"Rule #{rule.RuleId} [{rule.Category}] {rule.DomainPattern} | {rule.BlockReason}"
            );
        }
        foreach (var allow in _browserDownloadGuard.GetActiveTemporaryAllowlist())
        {
            QuarantineListBox.Items.Add(
                $"[TEMP ALLOWLIST] {allow.Domain} (expires {allow.ExpiresAtUtc:HH:mm:ss} UTC)"
            );
        }
        StatusFooterText.Text = "Manifest V3 Browser Extension active · Zero browsing-history collection · Ordinary ads not blocked.";
    }

    private void OnDownloadProtectionViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = "07. Automatic Download Protection (Native Messaging Host)";
        RightPanelHeaderText.Text = $"NATIVE MESSAGING DOWNLOAD VERDICTS ({NativeMessagingDownloadGuard.NativeHostIdentifier})";
        QuarantineListBox.Items.Clear();
        foreach (var dl in _browserDownloadGuard.GetDownloadVerdictHistory())
        {
            QuarantineListBox.Items.Add(
                $"[{dl.StatusDisplayLabel}] {dl.FileName} ({dl.WebsiteDomain}) | Threat: {dl.ThreatName} | SHA-256: {dl.Sha256Hash[..Math.Min(16, dl.Sha256Hash.Length)]}..."
            );
        }
        StatusFooterText.Text = "4-Tier Download Verdict: Clean · Suspicious · Malicious · Unknown / Not scanned (Never marks incomplete scans Clean).";
    }

    private void OnRealtimeGuardToggleClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.realtime", _currentLanguage);
        RightPanelHeaderText.Text = $"USER-MODE REAL-TIME FILE PROTECTION ({(_realTimeMonitor.IsMonitoringActive ? "ACTIVE" : "READY")})";
        QuarantineListBox.Items.Clear();
        foreach (var evt in _realTimeMonitor.GetEventHistory())
        {
            QuarantineListBox.Items.Add(
                $"{evt.ObservedAtUtc:HH:mm:ss} | [{evt.Category}] [{evt.ScanStatus}] {evt.FileName} | {evt.DetectionSummary}"
            );
        }
        StatusFooterText.Text = "User-Mode Real-Time File Protection monitors Downloads, new executables, file modifications, and Startup changes without kernel drivers.";
    }

    private void OnSecurityIntelligenceViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = "12. Security Intelligence & Multi-Engine Architecture";
        RightPanelHeaderText.Text = "LOCAL & PUBLIC THREAT INTELLIGENCE ENGINES ($0)";
        QuarantineListBox.Items.Clear();
        foreach (var eng in _scanPipeline.GetEngineDescriptors())
        {
            QuarantineListBox.Items.Add(
                $"[{eng.Status}] {eng.DisplayName} ({eng.License}) | {eng.StatusDetail}"
            );
        }
        StatusFooterText.Text = AboutBrandMetadata.NetworkPrivacyDisclosure;
    }

    private void OnThreatHistoryClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.history", _currentLanguage);
        RightPanelHeaderText.Text = $"LOCAL SCAN HISTORY ({_scanHistory.Count} SESSIONS)";
        QuarantineListBox.Items.Clear();
        foreach (var session in _scanHistory)
        {
            QuarantineListBox.Items.Add(
                $"{session.StartedAtUtc:HH:mm:ss} | {session.ScanType} | Scanned: {session.TotalFilesScanned} | Threats: {session.ThreatsDetectedCount} | Excluded: {session.SkippedExcludedCount}"
            );
        }
    }

    private async void OnRefreshQuarantineClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.quarantine", _currentLanguage);
        await RefreshQuarantineVaultAsync();
    }

    private void OnExclusionsViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.exclusions", _currentLanguage);
        RightPanelHeaderText.Text = "KIRON PROHORI EXCLUSIONS (DOES NOT MODIFY DEFENDER)";
        QuarantineListBox.Items.Clear();

        foreach (var exc in _exclusionManager.GetExclusions())
        {
            QuarantineListBox.Items.Add(
                $"[{exc.Scope}] {exc.CanonicalPath} | Reason: {exc.Reason}"
            );
        }

        StatusFooterText.Text = ExclusionManager.SecurityRiskExplanation;
    }

    private async void OnRefreshWindowsSecurityClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.defender", _currentLanguage);
        await RefreshWindowsSecurityPostureAsync();
        StatusFooterText.Text = "Refreshed Microsoft Defender Antivirus status & signature version via WMI.";
    }

    private async void OnFirewallViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.firewall", _currentLanguage);
        await RefreshWindowsSecurityPostureAsync();
        StatusFooterText.Text = "Refreshed Windows Firewall Domain, Private, and Public profile status.";
    }

    private void OnCheckUpdatesClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.updates", _currentLanguage);
        RightPanelHeaderText.Text = "SIGNED HTTPS UPDATE HISTORY & ROLLBACK";
        QuarantineListBox.Items.Clear();
        foreach (var rec in _updateManager.GetUpdateHistory())
        {
            QuarantineListBox.Items.Add(
                $"{rec.ExecutedAtUtc:yyyy-MM-dd HH:mm} | {rec.ComponentId} {rec.TargetVersion} | {rec.Status} | {rec.Notes}"
            );
        }
        StatusFooterText.Text = $"Automatic Update System enforces HTTPS + SHA-256 hash + {SecureUpdateManager.TrustedPublisherIdentity}.";
    }

    private void OnNotificationsViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.notifications", _currentLanguage);
        RightPanelHeaderText.Text = "SMART NOTIFICATIONS (ANTI-SPAM + GENTLE CHIME)";
        QuarantineListBox.Items.Clear();
        foreach (var evt in _notificationManager.GetNotificationHistory())
        {
            QuarantineListBox.Items.Add(
                $"{evt.CreatedAtUtc:HH:mm:ss} | {evt.EventHeading}: {evt.ThreatName} | Chime: {evt.SoundPlayed} | Action: {evt.RecommendedAction}"
            );
        }
        StatusFooterText.Text = $"Notification Sound: {(_notificationManager.SoundEnabled ? "ON" : "OFF")} · Volume: {_notificationManager.VolumePercent}%";
    }

    private void OnSettingsViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.settings", _currentLanguage);
        StatusFooterText.Text =
            $"Performance Profile: {_performanceGuard.CurrentProfile} · Max CPU: {_performanceGuard.MaxCpuLimitPercent}% · Skip Unchanged Clean Files: {_performanceGuard.EnableUnchangedFileCache}";
    }

    private void OnAboutViewClick(object sender, RoutedEventArgs e)
    {
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.about", _currentLanguage);
        RightPanelHeaderText.Text = $"{AboutBrandMetadata.ProductName} — {AboutBrandMetadata.Subtitle}";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add($"Product: {AboutBrandMetadata.ProductName}");
        QuarantineListBox.Items.Add($"Subtitle: {AboutBrandMetadata.Subtitle}");
        QuarantineListBox.Items.Add($"Developer: {AboutBrandMetadata.DeveloperName}");
        QuarantineListBox.Items.Add("Icon: Professional Shield Icon (No personal photograph / address / phone)");
        QuarantineListBox.Items.Add("---");
        foreach (var line in AboutBrandMetadata.OfficialAboutMessage.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            QuarantineListBox.Items.Add(line);
        }
        QuarantineListBox.Items.Add("---");
        QuarantineListBox.Items.Add(AboutBrandMetadata.NonAffiliationNotice);
        StatusFooterText.Text = $"Developer: {AboutBrandMetadata.DeveloperName} · Independent Windows Security Companion";
    }

    private async void OnRunEicarSelfTestClick(object sender, RoutedEventArgs e)
    {
        var tempTestDir = Path.Combine(Path.GetTempPath(), "KironProhori_EicarSelfTest_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempTestDir);
        var eicarFilePath = Path.Combine(tempTestDir, "eicar_harmless_test.com");

        var eicarPayload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllTextAsync(eicarFilePath, eicarPayload, Encoding.ASCII);

        await RunScanWorkflowAsync(ScanType.SingleFileScan, new[] { tempTestDir });
    }

    private void OnPlayGentleChimeClick(object sender, RoutedEventArgs e)
    {
        PlayGentleChimeIfEnabled();
        StatusFooterText.Text = $"Played original gentle 280ms dual-tone chime (Volume: {_notificationManager.VolumePercent}%).";
    }

    private void PlayGentleChimeIfEnabled()
    {
        if (!_notificationManager.SoundEnabled || _notificationManager.VolumePercent <= 0)
        {
            return;
        }

        var wavBytes = _notificationManager.SynthesizeGentleChimeWavBytes();
        if (wavBytes.Length == 0)
        {
            return;
        }

        try
        {
            using var ms = new MemoryStream(wavBytes);
            using var player = new SoundPlayer(ms);
            player.Play();
        }
        catch
        {
            // Non-blocking fallback on headless/CI audio devices
        }
    }

    private async Task RunScanWorkflowAsync(ScanType mode, IEnumerable<string> targetPaths)
    {
        _activeScanCts?.Cancel();
        _activeScanCts = new CancellationTokenSource();
        _scanPipeline.ResumeActiveScan();
        PauseResumeScanBtn.Content = "Pause Scan";

        ScanStateText.Text = $"RUNNING ({mode})";
        FindingsListBox.Items.Clear();
        _currentFindings.Clear();

        var progress = new Progress<ScanProgressUpdate>(report =>
        {
            ScanMetricsText.Text = $"{report.FilesScanned} scanned · {report.ThreatsFound} detections · {report.SkippedPermissionCount} skipped";
            StatusFooterText.Text = $"Scanning: {report.CurrentFilePath}";
        });

        try
        {
            var summary = await _scanPipeline.ScanDirectoriesAsync(
                mode,
                targetPaths,
                progress,
                _activeScanCts.Token
            );

            _scanHistory.Insert(0, summary);
            ScanStateText.Text = $"COMPLETED ({summary.Findings.Count} detections)";
            ScanMetricsText.Text =
                $"{summary.TotalFilesScanned} scanned · {summary.Findings.Count} detections · {summary.SkippedExcludedCount} excluded · {summary.SkippedUnchangedCount} cached";

            foreach (var finding in summary.Findings)
            {
                _currentFindings.Add(finding);
                RenderFindingInList(finding);
            }

            if (summary.Findings.Count > 0)
            {
                PlayGentleChimeIfEnabled();
            }

            StatusFooterText.Text =
                $"Scan finished in {summary.DurationSeconds:F2}s. Select any detection to Quarantine, Ignore Once, or Add Exclusion.";
        }
        catch (OperationCanceledException)
        {
            ScanStateText.Text = "CANCELLED";
            StatusFooterText.Text = "Scan cancelled safely by user.";
        }
        catch (Exception ex)
        {
            await _diagnosticsManager.LogLocalDiagnosticErrorAsync("MainWindow.RunScanWorkflowAsync", ex.Message);
            ScanStateText.Text = "ERROR";
            StatusFooterText.Text = $"Scan error logged to local diagnostics: {ex.Message}";
        }
    }

    private async void OnQuarantineSelectedFindingClick(object sender, RoutedEventArgs e)
    {
        var idx = FindingsListBox.SelectedIndex;
        if (idx < 0 || idx >= _currentFindings.Count)
        {
            StatusFooterText.Text = "Select a detection finding first to quarantine.";
            return;
        }

        var finding = _currentFindings[idx];
        if (!File.Exists(finding.FilePath))
        {
            StatusFooterText.Text = "File no longer exists on disk.";
            return;
        }

        var confirm = MessageBox.Show(
            $"Quarantine '{finding.DetectionName}'?\n\nLocation: {finding.FilePath}\nSource: {finding.DetectionSourceAttribution}\nSeverity: {finding.Severity}\n\nFile will be isolated in the local vault and can be restored anytime.",
            "KIRON PROHORI — Confirm Quarantine (Recommended)",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning
        );

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await _quarantineManager.QuarantineFileAsync(finding, userConfirmed: true);
        await RefreshQuarantineVaultAsync();
        StatusFooterText.Text = $"Quarantined {finding.FilePath} into local vault.";
    }

    private async void OnIgnoreSelectedFindingOnceClick(object sender, RoutedEventArgs e)
    {
        var idx = FindingsListBox.SelectedIndex;
        if (idx < 0 || idx >= _currentFindings.Count)
        {
            StatusFooterText.Text = "Select a detection finding first to ignore once.";
            return;
        }

        var finding = _currentFindings[idx];
        await _quarantineManager.IgnoreFindingOnceAsync(finding, userConfirmed: true);
        _currentFindings.RemoveAt(idx);
        FindingsListBox.Items.RemoveAt(idx);
        StatusFooterText.Text = $"Ignored '{finding.DetectionName}' for this scan session only.";
    }

    private async void OnExcludeSelectedFindingClick(object sender, RoutedEventArgs e)
    {
        var idx = FindingsListBox.SelectedIndex;
        if (idx < 0 || idx >= _currentFindings.Count)
        {
            StatusFooterText.Text = "Select a detection finding first to add to KIRON PROHORI Exclusions.";
            return;
        }

        var finding = _currentFindings[idx];
        var confirm = MessageBox.Show(
            $"{ExclusionManager.SecurityRiskExplanation}\n\nExclude path:\n{finding.FilePath}",
            "KIRON PROHORI — Confirm Exclusion",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning
        );

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await _exclusionManager.AddExclusionAsync(
            finding.FilePath,
            ExclusionScope.IndividualFile,
            "User excluded from Detection list",
            userConfirmed: true
        );

        _currentFindings.RemoveAt(idx);
        FindingsListBox.Items.RemoveAt(idx);
        QuarantineCountText.Text = $"{_currentQuarantineItems.Count} Quarantined · {_exclusionManager.GetExclusions().Count} Excluded";
        StatusFooterText.Text = $"Added '{finding.FilePath}' to KIRON PROHORI Exclusions.";
    }

    private async void OnRestoreSelectedQuarantineClick(object sender, RoutedEventArgs e)
    {
        var idx = QuarantineListBox.SelectedIndex;
        if (idx < 0 || idx >= _currentQuarantineItems.Count)
        {
            StatusFooterText.Text = "Select a quarantined item to restore.";
            return;
        }

        var item = _currentQuarantineItems[idx];
        await _quarantineManager.RestoreQuarantinedFileAsync(item.QuarantineId, userConfirmed: true);
        await RefreshQuarantineVaultAsync();
        StatusFooterText.Text = $"Restored {item.OriginalFilePath} and verified SHA-256 integrity.";
    }

    private async void OnDeleteSelectedQuarantineClick(object sender, RoutedEventArgs e)
    {
        var idx = QuarantineListBox.SelectedIndex;
        if (idx < 0 || idx >= _currentQuarantineItems.Count)
        {
            StatusFooterText.Text = "Select a quarantined item to permanently delete.";
            return;
        }

        var item = _currentQuarantineItems[idx];
        var confirm = MessageBox.Show(
            $"Permanently delete quarantined payload '{item.DetectionName}'?\n\nOriginal Path: {item.OriginalFilePath}\n\nThis action cannot be undone.",
            "KIRON PROHORI — Confirm Permanent Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning
        );

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await _quarantineManager.PermanentlyDeleteQuarantinedFileAsync(item.QuarantineId, userConfirmed: true);
        await RefreshQuarantineVaultAsync();
        StatusFooterText.Text = $"Permanently deleted quarantined payload {item.QuarantineId[..8]}.";
    }

    private void OnToggleLanguageClick(object sender, RoutedEventArgs e)
    {
        _currentLanguage = _currentLanguage == "en" ? "bn" : "en";
        AppTitleBlock.Text = BilingualStrings.Get("app.title", _currentLanguage);
        AppSubtitleBlock.Text = BilingualStrings.Get("app.subtitle", _currentLanguage);
        NavOverviewBtn.Content = "01. " + BilingualStrings.Get("nav.overview", _currentLanguage);
        NavQuickScanBtn.Content = "02. " + BilingualStrings.Get("nav.quick_scan", _currentLanguage);
        NavFullScanBtn.Content = "03. " + BilingualStrings.Get("nav.full_scan", _currentLanguage);
        NavCustomScanBtn.Content = "04. " + BilingualStrings.Get("nav.custom_scan", _currentLanguage);
        NavUsbScanBtn.Content = "05. " + BilingualStrings.Get("nav.usb_scan", _currentLanguage);
        NavRealtimeBtn.Content = "06. " + BilingualStrings.Get("nav.realtime", _currentLanguage);
        NavHistoryBtn.Content = "07. " + BilingualStrings.Get("nav.history", _currentLanguage);
        NavQuarantineBtn.Content = "08. " + BilingualStrings.Get("nav.quarantine", _currentLanguage);
        NavExclusionsBtn.Content = "09. " + BilingualStrings.Get("nav.exclusions", _currentLanguage);
        NavDefenderBtn.Content = "10. " + BilingualStrings.Get("nav.defender", _currentLanguage);
        NavFirewallBtn.Content = "11. " + BilingualStrings.Get("nav.firewall", _currentLanguage);
        NavUpdatesBtn.Content = "12. " + BilingualStrings.Get("nav.updates", _currentLanguage);
        NavNotificationsBtn.Content = "13. " + BilingualStrings.Get("nav.notifications", _currentLanguage);
        NavSettingsBtn.Content = "14. " + BilingualStrings.Get("nav.settings", _currentLanguage);
        NavAboutBtn.Content = "15. " + BilingualStrings.Get("nav.about", _currentLanguage);
        DisclosureBannerText.Text = BilingualStrings.Get("status.honest_disclosure", _currentLanguage);
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        _isDarkTheme = !_isDarkTheme;
        Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(_isDarkTheme ? "#0B0F17" : "#F8FAFC"));
        Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(_isDarkTheme ? "#F3F4F6" : "#0F172A"));
    }
}

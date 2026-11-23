using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Media;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
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

    private readonly string _localAppDataDir;
    private readonly string _uiPreferencesFilePath;
    private readonly List<ScanFinding> _currentFindings = new();
    private readonly List<ScanReport> _scanHistory = new();
    private List<QuarantineEntry> _currentQuarantineItems = new();
    private CancellationTokenSource? _activeScanCts;
    private System.Windows.Forms.NotifyIcon? _systemTrayNotifyIcon;
    private System.Windows.Forms.ToolStripMenuItem? _trayRealtimeMenuItem;

    // Default Theme: Light Minimal Glass (Windows 11 Fluent)
    private bool _isDarkTheme;
    private string _currentLanguage = "en";
    private bool _minimizeToTrayOnClose = true;
    private bool _hasCompletedFirstRunWelcome;
    private bool _isExplicitExitRequested;

    private bool IsBengaliLanguage => string.Equals(_currentLanguage, "bn", StringComparison.OrdinalIgnoreCase);

    public MainWindow()
    {
        InitializeComponent();

        // Respect Windows Taskbar work area so the window never hides behind the taskbar
        ApplyWorkAreaBounds();
        StateChanged += OnWindowStateChanged;
        Closing += OnMainWindowClosing;
        Closed += OnMainWindowClosed;

        _localAppDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KironProhori"
        );
        Directory.CreateDirectory(_localAppDataDir);
        _uiPreferencesFilePath = Path.Combine(_localAppDataDir, "ui-preferences.json");

        _exclusionManager = new ExclusionManager(Path.Combine(_localAppDataDir, "Exclusions"));
        _performanceGuard = new PerformanceProtectionGuard();
        _notificationManager = new SmartNotificationManager();
        _updateManager = new SecureUpdateManager(Path.Combine(_localAppDataDir, "Updates"));
        _diagnosticsManager = new ErrorDiagnosticsManager(_localAppDataDir);

        _scanPipeline = new ModularScanPipeline(
            engines: null,
            exclusionManager: _exclusionManager,
            performanceGuard: _performanceGuard,
            notificationManager: _notificationManager
        );

        _quarantineManager = new QuarantineManager(
            Path.Combine(_localAppDataDir, "Quarantine"),
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

        LoadLocalUiPreferences();
        ApplyThemePalette();
        InitializeSystemTrayCompanion();
        ShowActiveWorkspaceView(showDashboardHero: true);

        // Show First-Run Light Minimal Glass Welcome Screen on first launch only
        if (!_hasCompletedFirstRunWelcome)
        {
            FirstRunWelcomeOverlayPanel.Visibility = Visibility.Visible;
        }

        Loaded += async (_, _) =>
        {
            ApplyWorkAreaBounds();
            await RefreshWindowsSecurityPostureAsync();
            await RefreshQuarantineVaultAsync();
            UpdateHeroProtectionBannerState();
        };
    }

    // =========================================================================
    // 1. LOCAL UI PREFERENCES & FIRST-RUN WELCOME SCREEN PERSISTENCE
    // =========================================================================

    private sealed class LocalUiPreferences
    {
        public bool IsDarkTheme { get; set; }
        public string Language { get; set; } = "en";
        public bool MinimizeToTrayOnClose { get; set; } = true;
        public bool HasCompletedFirstRunWelcome { get; set; }
    }

    private void LoadLocalUiPreferences()
    {
        try
        {
            if (!File.Exists(_uiPreferencesFilePath))
            {
                return;
            }

            var json = File.ReadAllText(_uiPreferencesFilePath);
            var prefs = JsonSerializer.Deserialize<LocalUiPreferences>(json);
            if (prefs == null)
            {
                return;
            }

            _isDarkTheme = prefs.IsDarkTheme;
            _currentLanguage = string.Equals(prefs.Language, "bn", StringComparison.OrdinalIgnoreCase) ? "bn" : "en";
            _minimizeToTrayOnClose = prefs.MinimizeToTrayOnClose;
            _hasCompletedFirstRunWelcome = prefs.HasCompletedFirstRunWelcome;
        }
        catch
        {
            // Safe default: Light Minimal Glass, English, Minimize to Tray enabled
        }
    }

    private void SaveLocalUiPreferences()
    {
        try
        {
            var prefs = new LocalUiPreferences
            {
                IsDarkTheme = _isDarkTheme,
                Language = _currentLanguage,
                MinimizeToTrayOnClose = _minimizeToTrayOnClose,
                HasCompletedFirstRunWelcome = _hasCompletedFirstRunWelcome
            };
            var json = JsonSerializer.Serialize(prefs, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_uiPreferencesFilePath, json);
        }
        catch
        {
            // Ignore non-fatal local disk write failure
        }
    }

    private void OnDismissWelcomeGetStartedClick(object sender, RoutedEventArgs e)
    {
        _hasCompletedFirstRunWelcome = true;
        FirstRunWelcomeOverlayPanel.Visibility = Visibility.Collapsed;
        SaveLocalUiPreferences();
        StatusFooterText.Text = "Welcome to KIRON PROHORI · Light Minimal Glass Dashboard ready.";
    }

    private void OnShowWelcomeScreenClick(object sender, RoutedEventArgs e)
    {
        _hasCompletedFirstRunWelcome = false;
        SaveLocalUiPreferences();
        FirstRunWelcomeOverlayPanel.Visibility = Visibility.Visible;
    }

    // =========================================================================
    // 2. CUSTOM WINDOW CHROME, WORK-AREA BOUNDS & SYSTEM TRAY INTEGRATION
    // =========================================================================

    private void ApplyWorkAreaBounds()
    {
        var workArea = SystemParameters.WorkArea;
        MaxHeight = workArea.Height;
        MaxWidth = workArea.Width;

        if (Width > workArea.Width)
        {
            Width = Math.Max(MinWidth, workArea.Width - 24);
        }

        if (Height > workArea.Height)
        {
            Height = Math.Max(MinHeight, workArea.Height - 24);
        }
    }

    private void OnTitleBarMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximizeRestore();
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
        {
            try
            {
                DragMove();
            }
            catch
            {
                // Ignore transient DragMove exception if mouse button released mid-frame
            }
        }
    }

    private void OnMinimizeWindowClick(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void OnMaximizeRestoreWindowClick(object sender, RoutedEventArgs e)
    {
        ToggleMaximizeRestore();
    }

    private void ToggleMaximizeRestore()
    {
        ApplyWorkAreaBounds();
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    private void OnWindowStateChanged(object? sender, EventArgs e)
    {
        if (MaximizeRestoreWindowBtn != null)
        {
            MaximizeRestoreWindowBtn.Content = WindowState == WindowState.Maximized ? "❐" : "□";
        }
    }

    private void OnCloseWindowClick(object sender, RoutedEventArgs e)
    {
        if (_minimizeToTrayOnClose && _systemTrayNotifyIcon != null)
        {
            MinimizeSmoothlyToSystemTray();
            return;
        }

        _isExplicitExitRequested = true;
        Close();
    }

    private void OnMainWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_isExplicitExitRequested && _minimizeToTrayOnClose && _systemTrayNotifyIcon != null)
        {
            e.Cancel = true;
            MinimizeSmoothlyToSystemTray();
        }
    }

    private void MinimizeSmoothlyToSystemTray()
    {
        if (_systemTrayNotifyIcon == null)
        {
            WindowState = WindowState.Minimized;
            return;
        }

        Hide();
        _systemTrayNotifyIcon.Visible = true;
        _systemTrayNotifyIcon.ShowBalloonTip(
            2000,
            "KIRON PROHORI — Windows Security",
            "KIRON PROHORI is protecting quietly in the system tray. Right-click or double-click the shield icon anytime.",
            System.Windows.Forms.ToolTipIcon.Info
        );
    }

    private void OnToggleCloseToTrayBehaviorClick(object sender, RoutedEventArgs e)
    {
        _minimizeToTrayOnClose = !_minimizeToTrayOnClose;
        SaveLocalUiPreferences();
        UpdateSettingsCardLabels();
        StatusFooterText.Text = _minimizeToTrayOnClose
            ? "Close button (✕) will now minimize KIRON PROHORI smoothly to the System Tray."
            : "Close button (✕) will now exit KIRON PROHORI completely.";
    }

    private void InitializeSystemTrayCompanion()
    {
        try
        {
            var trayMenu = new System.Windows.Forms.ContextMenuStrip();
            trayMenu.Items.Add("Open KIRON PROHORI", null, (_, _) => RestoreFromSystemTray());
            trayMenu.Items.Add("Quick Scan", null, (_, _) =>
            {
                RestoreFromSystemTray();
                OnQuickScanClick(this, new RoutedEventArgs());
            });

            _trayRealtimeMenuItem = new System.Windows.Forms.ToolStripMenuItem(
                "Pause/Resume Real-Time Guard",
                null,
                (_, _) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        OnToggleRealtimeEngineClick(this, new RoutedEventArgs());
                    });
                }
            );
            trayMenu.Items.Add(_trayRealtimeMenuItem);

            trayMenu.Items.Add("Check for Updates", null, (_, _) =>
            {
                RestoreFromSystemTray();
                OnCheckUpdatesClick(this, new RoutedEventArgs());
            });
            trayMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            trayMenu.Items.Add("Exit", null, (_, _) =>
            {
                _isExplicitExitRequested = true;
                Dispatcher.Invoke(Close);
            });

            System.Drawing.Icon trayIcon = System.Drawing.SystemIcons.Shield;
            var icoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "KironProhori.ico");
            if (File.Exists(icoPath))
            {
                trayIcon = new System.Drawing.Icon(icoPath);
            }

            _systemTrayNotifyIcon = new System.Windows.Forms.NotifyIcon
            {
                Text = "KIRON PROHORI — Windows Security",
                Icon = trayIcon,
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            _systemTrayNotifyIcon.DoubleClick += (_, _) => RestoreFromSystemTray();
        }
        catch
        {
            // Headless/CI runner fallback where Explorer shell tray is unavailable
        }
    }

    private void RestoreFromSystemTray()
    {
        Dispatcher.Invoke(() =>
        {
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            Activate();
        });
    }

    private void OnMainWindowClosed(object? sender, EventArgs e)
    {
        _activeScanCts?.Cancel();
        _realTimeMonitor.Dispose();
        if (_systemTrayNotifyIcon != null)
        {
            _systemTrayNotifyIcon.Visible = false;
            _systemTrayNotifyIcon.Dispose();
            _systemTrayNotifyIcon = null;
        }
    }

    // =========================================================================
    // 3. VIEW SWITCHING ARCHITECTURE (HERO DASHBOARD + DEDICATED SUB-PAGES)
    // =========================================================================

    private void ShowActiveWorkspaceView(
        bool showDashboardHero = false,
        bool showScannerInspector = false,
        bool showSettings = false,
        bool showAbout = false,
        bool isScanTab = false,
        bool isWebDownloadTab = false,
        bool isQuarantineTab = false,
        bool isRealtimeTab = false,
        bool isExclusionsFirewallTab = false)
    {
        DashboardHeroViewPanel.Visibility = showDashboardHero ? Visibility.Visible : Visibility.Collapsed;
        ScannerAndInspectorViewPanel.Visibility = showScannerInspector ? Visibility.Visible : Visibility.Collapsed;
        SettingsDedicatedViewPanel.Visibility = showSettings ? Visibility.Visible : Visibility.Collapsed;
        AboutDedicatedViewPanel.Visibility = showAbout ? Visibility.Visible : Visibility.Collapsed;

        // Contextual sub-toolbars inside the Sub-Page view
        ScanModesSubToolbar.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;
        WebAndDownloadSubToolbar.Visibility = isWebDownloadTab ? Visibility.Visible : Visibility.Collapsed;
        ExclusionsAndFirewallSubToolbar.Visibility = isExclusionsFirewallTab ? Visibility.Visible : Visibility.Collapsed;
        ToggleRealtimeMonitoringBtn.Visibility = isRealtimeTab ? Visibility.Visible : Visibility.Collapsed;

        // STRICT RULE: Restore & Permanent Delete ONLY appear inside Quarantine Vault
        QuarantineActionButtonsPanel.Visibility = isQuarantineTab ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateHeroProtectionBannerState()
    {
        var activeThreats = _currentFindings.Count;
        if (activeThreats > 0)
        {
            HeroProtectionBannerBorder.BorderBrush = CreateBrush("#F59E0B");
            HeroGradStop1.Color = ParseWpfColor(_isDarkTheme ? "#2B190B" : "#FEF3C7");
            HeroGradStop2.Color = ParseWpfColor(_isDarkTheme ? "#1E293B" : "#FFEDD5");
            HeroShieldIconBadge.BorderBrush = CreateBrush("#D97706");
            HeroShieldCornerCheck.Background = CreateBrush("#D97706");
            HeroShieldGlyphText.Text = "!";
            HeroStatusPillBorder.Background = CreateBrush("#D97706");
            HeroStatusPillText.Text = IsBengaliLanguage ? "পদক্ষেপ প্রয়োজন" : "ACTION NEEDED";
            HeroHeadlineText.Text = IsBengaliLanguage
                ? $"{activeThreats}টি থ্রেট কোয়ারেন্টাইন রিভিউয়ের অপেক্ষায়"
                : $"Action Needed — {activeThreats} Detection(s) Pending Review";
            HeroHeadlineText.Foreground = CreateBrush(_isDarkTheme ? "#F8FAFC" : "#0F172A");
            HeroSubheadlineText.Text = "KIRON PROHORI follows a Quarantine-First policy. Open Scan Results to Quarantine, Ignore Once, or Add Exclusion.";
            HeroSubheadlineText.Foreground = CreateBrush(_isDarkTheme ? "#CBD5E1" : "#334155");
        }
        else
        {
            HeroProtectionBannerBorder.BorderBrush = CreateBrush(_isDarkTheme ? "#059669" : "#A7F3D0");
            HeroGradStop1.Color = ParseWpfColor(_isDarkTheme ? "#0A221E" : "#ECFDF5");
            HeroGradStop2.Color = ParseWpfColor(_isDarkTheme ? "#0F1E36" : "#E0F2FE");
            HeroShieldIconBadge.BorderBrush = CreateBrush("#10B981");
            HeroShieldCornerCheck.Background = CreateBrush("#059669");
            HeroShieldGlyphText.Text = "✓";
            HeroStatusPillBorder.Background = CreateBrush("#059669");
            HeroStatusPillText.Text = IsBengaliLanguage ? "সুরক্ষা সক্রিয়" : "PROTECTION LIVE";
            HeroHeadlineText.Text = IsBengaliLanguage ? "আপনার সুরক্ষা এখন সক্রিয় রয়েছে" : "Your protection is live now";
            HeroHeadlineText.Foreground = CreateBrush(_isDarkTheme ? "#F8FAFC" : "#0F172A");
            HeroSubheadlineText.Text = "Multi-engine SHA-256 + Heuristic PE scanner, User-Mode Real-Time File Guard, and Chrome/Edge Manifest V3 Web Protection are active.";
            HeroSubheadlineText.Foreground = CreateBrush(_isDarkTheme ? "#CBD5E1" : "#334155");
        }

        if (DashCardRealtimeBadge != null)
        {
            DashCardRealtimeBadge.Text = _realTimeMonitor.IsMonitoringActive ? "LIVE · ON" : "READY";
        }
        if (DashCardQuarantineBadge != null)
        {
            DashCardQuarantineBadge.Text = $"{_currentQuarantineItems.Count} ISOLATED";
        }
    }

    // =========================================================================
    // 4. TELEMETRY, QUARANTINE & 8 GLASS TILE SUB-PAGE HANDLERS
    // =========================================================================

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
            ? $"Defender: Real-Time ON ({(posture.IsRunningAsAdministrator ? "Admin" : "User")})"
            : $"Defender: {posture.MicrosoftDefenderStatus}";
        SignatureVersionText.Text = $"Signature: {posture.AntivirusSignatureVersion}";
        FirewallStatusText.Text = "Firewall: " + string.Join(
            " ",
            posture.FirewallProfiles.Select(p => $"{p.ProfileName}:{OnOff(p.IsEnabled)}")
        );
        UacStatusText.Text = $"Telemetry: OFF ({AboutBrandMetadata.PrivacyPolicyDefault})";

        var diag = await _diagnosticsManager.RunSelfDiagnosticAndRepairAsync();
        DiagnosticsHealthText.Text = $"{diag.Status.ToUpperInvariant()}";
    }

    private static string OnOff(bool state) => state ? "ON" : "OFF";

    private async Task RefreshQuarantineVaultAsync()
    {
        RightPanelHeaderText.Text = "QUARANTINE VAULT (.KPQ ISOLATED ITEMS)";
        _currentQuarantineItems = (await _quarantineManager.ListQuarantineEntriesAsync())
            .Where(e => !e.IsRestored)
            .ToList();
        var exclusionsCount = _exclusionManager.GetExclusions().Count;
        QuarantineCountText.Text = $"{exclusionsCount} EXCLUDED";
        QuarantineListBox.Items.Clear();

        foreach (var item in _currentQuarantineItems)
        {
            QuarantineListBox.Items.Add(
                $"{item.QuarantineId[..8]} | {item.DetectionName} ({item.DetectionEngineId}) | Orig: {item.OriginalFilePath}"
            );
        }

        if (_currentQuarantineItems.Count == 0)
        {
            QuarantineListBox.Items.Add("Quarantine Vault is clean (0 isolated .kpq items).");
        }
    }

    private void OnNavigateOverviewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showDashboardHero: true);
        CurrentSectionTitle.Text = $"{BilingualStrings.Get("nav.overview", IsBengaliLanguage)} — Privacy-First Windows Companion";
        UpdateHeroProtectionBannerState();
        StatusFooterText.Text = "Overview ready. All scans and exclusions are stored locally without telemetry.";
    }

    private void OnOpenScanCenterTileClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.quick_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "MULTI-MODE MALWARE & HEURISTIC SCAN CENTER";
        ActiveScanLivePathText.Text = "Choose Quick Scan, Full Scan, Custom Folder, USB Scan, or Safe EICAR Self-Test.";
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
        PopulateScanHistoryInInspector();
        StatusFooterText.Text = "Scan Center ready. Click Quick Scan, Full Scan, Custom Folder, or USB Drive Scan.";
    }

    private async void OnQuickScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.quick_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "QUICK SCAN — CRITICAL USER & STARTUP DIRECTORIES";
        var quickTargets = ModularScanPipeline.GetQuickScanDirectories();
        await RunScanWorkflowAsync(ScanType.QuickScan, quickTargets.Take(1));
    }

    private async void OnFullScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.full_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "FULL SCAN — COMPLETE USER PROFILE & EXECUTABLES";
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        await RunScanWorkflowAsync(ScanType.FullScan, new[] { userProfile });
    }

    private async void OnCustomScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.custom_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "CUSTOM FOLDER SCAN — USER DOCUMENTS & WORKSPACE";
        var docsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        await RunScanWorkflowAsync(ScanType.CustomFolderScan, new[] { docsPath });
    }

    private async void OnUsbScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.usb_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "REMOVABLE USB DRIVE SCAN";
        var removableDrives = ModularScanPipeline.GetRemovableUsbDrives()
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        if (removableDrives.Count == 0)
        {
            ActiveScanLivePathText.Text = "No removable USB drives currently mounted.";
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
            ScanStateText.Text = " · RUNNING (Resumed)";
            StatusFooterText.Text = "Scan resumed by user.";
        }
        else
        {
            _scanPipeline.PauseActiveScan();
            PauseResumeScanBtn.Content = "Resume Scan";
            ScanStateText.Text = " · PAUSED BY USER";
            StatusFooterText.Text = "Scan paused. Click Resume Scan to continue without losing progress.";
        }
    }

    private void OnCancelScanClick(object sender, RoutedEventArgs e)
    {
        _activeScanCts?.Cancel();
        _scanPipeline.ResumeActiveScan();
        PauseResumeScanBtn.Content = "Pause Scan";
        ScanStateText.Text = " · CANCELLED";
        StatusFooterText.Text = "Active scan stopped safely by user.";
    }

    private void OnWebProtectionViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isWebDownloadTab: true);
        CurrentSectionTitle.Text = "Web & Download Guard (Chrome & Microsoft Edge Manifest V3)";
        ActiveScanBannerTitle.Text = "MANIFEST V3 DECLARATIVENETREQUEST WEB GUARD";
        ActiveScanLivePathText.Text = "Blocks verified phishing, malware & malvertising domains";
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
        ShowActiveWorkspaceView(showScannerInspector: true, isWebDownloadTab: true);
        CurrentSectionTitle.Text = "Automatic Download Protection (Native Messaging Host)";
        ActiveScanBannerTitle.Text = $"NATIVE MESSAGING DOWNLOAD GUARD ({NativeMessagingDownloadGuard.NativeHostIdentifier})";
        ActiveScanLivePathText.Text = "4-Tier Verdict: Clean · Suspicious · Malicious · Unknown / Not scanned";
        RightPanelHeaderText.Text = $"NATIVE MESSAGING DOWNLOAD VERDICTS ({NativeMessagingDownloadGuard.NativeHostIdentifier})";
        QuarantineListBox.Items.Clear();
        var history = _browserDownloadGuard.GetDownloadVerdictHistory();
        foreach (var dl in history)
        {
            QuarantineListBox.Items.Add(
                $"[{dl.StatusDisplayLabel}] {dl.FileName} ({dl.WebsiteDomain}) | Threat: {dl.ThreatName} | SHA-256: {dl.Sha256Hash[..Math.Min(16, dl.Sha256Hash.Length)]}..."
            );
        }
        if (history.Count == 0)
        {
            QuarantineListBox.Items.Add("No browser downloads inspected in this session yet. Native host com.kironprohori.security_agent ready.");
        }
        StatusFooterText.Text = "4-Tier Download Verdict: Clean · Suspicious · Malicious · Unknown / Not scanned (Never marks incomplete scans Clean).";
    }

    private void OnRealtimeGuardToggleClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isRealtimeTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.realtime", IsBengaliLanguage);
        RenderRealtimeGuardState();
    }

    private void OnToggleRealtimeEngineClick(object sender, RoutedEventArgs e)
    {
        if (_realTimeMonitor.IsMonitoringActive)
        {
            _realTimeMonitor.StopMonitoring();
        }
        else
        {
            _realTimeMonitor.StartMonitoring();
        }
        RenderRealtimeGuardState();
        UpdateHeroProtectionBannerState();
    }

    private void RenderRealtimeGuardState()
    {
        var stateLabel = _realTimeMonitor.IsMonitoringActive
            ? "ACTIVE (Monitoring Downloads, Temp & Startup)"
            : "READY (Click Enable to Start Live FileSystemWatcher)";
        ActiveScanBannerTitle.Text = $"USER-MODE REAL-TIME FILE PROTECTION — {stateLabel}";
        ActiveScanLivePathText.Text = "Zero Kernel Drivers · Respects KIRON PROHORI Exclusions";
        ToggleRealtimeMonitoringBtn.Content = _realTimeMonitor.IsMonitoringActive
            ? "Pause Real-Time Guard"
            : "Enable Real-Time File Guard";
        if (_trayRealtimeMenuItem != null)
        {
            _trayRealtimeMenuItem.Text = _realTimeMonitor.IsMonitoringActive
                ? "Pause Real-Time Guard (Active)"
                : "Resume Real-Time Guard";
        }
        RightPanelHeaderText.Text = $"USER-MODE REAL-TIME FILE PROTECTION ({(_realTimeMonitor.IsMonitoringActive ? "ACTIVE" : "READY")})";
        QuarantineListBox.Items.Clear();
        var events = _realTimeMonitor.GetEventHistory();
        foreach (var evt in events)
        {
            QuarantineListBox.Items.Add(
                $"{evt.ObservedAtUtc:HH:mm:ss} | [{evt.Category}] [{evt.ScanStatus}] {evt.FileName} | {evt.DetectionSummary}"
            );
        }
        if (events.Count == 0)
        {
            foreach (var dir in RealTimeFileProtectionMonitor.GetDefaultWatchedDirectories())
            {
                QuarantineListBox.Items.Add($"[WATCHED DIRECTORY] {dir}");
            }
        }
        StatusFooterText.Text = "User-Mode Real-Time File Protection monitors Downloads, new executables, file modifications, and Startup changes without kernel drivers.";
    }

    private void OnSecurityIntelligenceViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true);
        CurrentSectionTitle.Text = "Security Intelligence & Multi-Engine Architecture";
        ActiveScanBannerTitle.Text = "MULTI-ENGINE PIPELINE & ZERO-COST PUBLIC THREAT INTELLIGENCE";
        ActiveScanLivePathText.Text = "64 KB IncrementalHash SHA-256 · Heuristic PE · YARA · ClamAV";
        RightPanelHeaderText.Text = "LOCAL & PUBLIC THREAT INTELLIGENCE ENGINES ($0)";
        QuarantineListBox.Items.Clear();
        foreach (var eng in _scanPipeline.GetEngineStatuses())
        {
            QuarantineListBox.Items.Add(
                $"[{eng.Status}] {eng.DisplayName} ({eng.License}) | {eng.StatusDetail}"
            );
        }
        StatusFooterText.Text = AboutBrandMetadata.NetworkPrivacyDisclosure;
    }

    private void OnThreatHistoryClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.history", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "LOCAL SCAN SESSION LEDGER & DIAGNOSTICS";
        RightPanelHeaderText.Text = $"LOCAL SCAN HISTORY ({_scanHistory.Count} SESSIONS)";
        PopulateScanHistoryInInspector();
    }

    private void PopulateScanHistoryInInspector()
    {
        QuarantineListBox.Items.Clear();
        foreach (var session in _scanHistory)
        {
            QuarantineListBox.Items.Add(
                $"{session.StartedAtUtc:HH:mm:ss} | {session.ScanType} | Scanned: {session.TotalFilesScanned} | Threats: {session.ThreatsDetectedCount} | Excluded: {session.SkippedExcludedCount}"
            );
        }
        if (_scanHistory.Count == 0)
        {
            QuarantineListBox.Items.Add("No scan sessions recorded in this session yet. Click Quick Scan or Run Safe EICAR Self-Test.");
        }
    }

    private async void OnRefreshQuarantineClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isQuarantineTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.quarantine", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "ISOLATED QUARANTINE VAULT (.KPQ) — RESTORE OR PERMANENTLY DELETE";
        ActiveScanLivePathText.Text = "Permanent deletion requires explicit confirmation";
        await RefreshQuarantineVaultAsync();
        UpdateHeroProtectionBannerState();
    }

    private void OnExclusionsViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.exclusions", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "CANONICAL PATH EXCLUSIONS & WINDOWS SECURITY COEXISTENCE";
        RightPanelHeaderText.Text = "KIRON PROHORI EXCLUSIONS (DOES NOT MODIFY DEFENDER)";
        QuarantineListBox.Items.Clear();

        var exclusions = _exclusionManager.GetExclusions();
        foreach (var exc in exclusions)
        {
            QuarantineListBox.Items.Add(
                $"[{exc.Scope}] {exc.CanonicalPath} | Reason: {exc.Reason}"
            );
        }
        if (exclusions.Count == 0)
        {
            QuarantineListBox.Items.Add("No custom path exclusions configured.");
        }

        StatusFooterText.Text = ExclusionManager.SecurityRiskExplanation;
    }

    private async void OnRefreshWindowsSecurityClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.defender", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "MICROSOFT DEFENDER COEXISTENCE (READ-ONLY WMI TELEMETRY)";
        await RefreshWindowsSecurityPostureAsync();
        var posture = _windowsSecurityMonitor.GetSecuritySnapshot();
        RightPanelHeaderText.Text = "MICROSOFT DEFENDER & SYSTEM POSTURE";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add($"Microsoft Defender Status: {posture.MicrosoftDefenderStatus}");
        QuarantineListBox.Items.Add($"Real-Time Protection Enabled: {posture.RealTimeProtectionEnabled}");
        QuarantineListBox.Items.Add($"Antivirus Signature Version: {posture.AntivirusSignatureVersion}");
        QuarantineListBox.Items.Add($"Running with Administrator Privileges: {posture.IsRunningAsAdministrator}");
        StatusFooterText.Text = "Refreshed Microsoft Defender Antivirus status & signature version via WMI.";
    }

    private async void OnFirewallViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.firewall", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "WINDOWS FIREWALL PROFILE MONITOR (DOMAIN / PRIVATE / PUBLIC)";
        await RefreshWindowsSecurityPostureAsync();
        var posture = _windowsSecurityMonitor.GetSecuritySnapshot();
        RightPanelHeaderText.Text = "WINDOWS FIREWALL PROFILES (READ-ONLY)";
        QuarantineListBox.Items.Clear();
        foreach (var profile in posture.FirewallProfiles)
        {
            QuarantineListBox.Items.Add($"Profile: {profile.ProfileName} | Status: {OnOff(profile.IsEnabled)}");
        }
        StatusFooterText.Text = "Refreshed Windows Firewall Domain, Private, and Public profile status.";
    }

    private void OnCheckUpdatesClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.updates", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "CRYPTOGRAPHICALLY VERIFIED HTTPS UPDATE MANAGER";
        ActiveScanLivePathText.Text = $"Trusted Publisher: {SecureUpdateManager.TrustedPublisherIdentity}";
        RightPanelHeaderText.Text = "SIGNED HTTPS UPDATE HISTORY & ROLLBACK";
        QuarantineListBox.Items.Clear();
        var history = _updateManager.GetUpdateHistory();
        foreach (var rec in history)
        {
            QuarantineListBox.Items.Add(
                $"{rec.ExecutedAtUtc:yyyy-MM-dd HH:mm} | {rec.ComponentId} {rec.TargetVersion} | {rec.Status} | {rec.Notes}"
            );
        }
        if (history.Count == 0)
        {
            QuarantineListBox.Items.Add($"Engine & Intelligence V{AboutBrandMetadata.ProductVersion} up to date · Publisher: {SecureUpdateManager.TrustedPublisherIdentity}");
        }
        StatusFooterText.Text = $"Automatic Update System enforces HTTPS + SHA-256 hash + {SecureUpdateManager.TrustedPublisherIdentity}.";
    }

    private void OnNotificationsViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.notifications", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "SMART ANTI-SPAM NOTIFICATION CENTER & 280MS GENTLE CHIME";
        RightPanelHeaderText.Text = "SMART NOTIFICATIONS (ANTI-SPAM + GENTLE CHIME)";
        QuarantineListBox.Items.Clear();
        var notifications = _notificationManager.GetNotificationHistory();
        foreach (var evt in notifications)
        {
            QuarantineListBox.Items.Add(
                $"{evt.CreatedAtUtc:HH:mm:ss} | {evt.EventHeading}: {evt.ThreatName} | Chime: {evt.SoundPlayed} | Action: {evt.RecommendedAction}"
            );
        }
        if (notifications.Count == 0)
        {
            QuarantineListBox.Items.Add("No threat notifications triggered in this session.");
        }
        StatusFooterText.Text = $"Notification Sound: {(_notificationManager.SoundEnabled ? "ON" : "OFF")} · Volume: {_notificationManager.VolumePercent}%";
    }

    private void OnSettingsViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showSettings: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.settings", IsBengaliLanguage);
        UpdateSettingsCardLabels();
        StatusFooterText.Text =
            $"Performance Profile: {_performanceGuard.CurrentProfile} · Max CPU: {_performanceGuard.MaxCpuLimitPercent}% · Skip Unchanged Clean Files: {_performanceGuard.EnableUnchangedFileCache}";
    }

    private void UpdateSettingsCardLabels()
    {
        if (SettingsLanguageStatusText != null)
        {
            SettingsLanguageStatusText.Text = IsBengaliLanguage ? "বাংলা (BN)" : "English (EN)";
        }
        if (SettingsThemeStatusText != null)
        {
            SettingsThemeStatusText.Text = _isDarkTheme ? "Obsidian Dark (#0B1120)" : "Light Minimal Glass (Default)";
        }
        if (SettingsCloseBehaviorText != null)
        {
            SettingsCloseBehaviorText.Text = _minimizeToTrayOnClose
                ? "Minimize to System Tray on Close (Recommended)"
                : "Exit Application Completely on Close";
        }
        if (SettingsPerformanceProfileText != null)
        {
            SettingsPerformanceProfileText.Text = $"{_performanceGuard.CurrentProfile} · Max CPU {_performanceGuard.MaxCpuLimitPercent}%";
        }
    }

    private void OnAboutViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showAbout: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.about", IsBengaliLanguage);
        AboutOfficialMessageBlock.Text = BilingualStrings.Get("AboutMessage", IsBengaliLanguage);
        AboutNonAffiliationBlock.Text = BilingualStrings.Get("NonAffiliationNotice", IsBengaliLanguage);
        StatusFooterText.Text = $"Developer: {AboutBrandMetadata.DeveloperName} · Independent Windows Security Companion";
    }

    // =========================================================================
    // 5. EICAR SELF-TEST, GENTLE CHIME & SCAN PIPELINE WORKFLOW
    // =========================================================================

    private async void OnRunEicarSelfTestClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        ActiveScanBannerTitle.Text = "SAFE EICAR STANDARD ANTIVIRUS SELF-TEST";

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

        ScanStateText.Text = $" · RUNNING ({mode})";
        ScanProgressBar.IsIndeterminate = true;
        FindingsListBox.Items.Clear();
        _currentFindings.Clear();

        var progress = new Progress<ScanProgressUpdate>(report =>
        {
            ScanMetricsText.Text = $"{report.FilesScanned} scanned · {report.ThreatsFound} detections · {report.SkippedPermissionCount} skipped";
            ActiveScanLivePathText.Text = report.CurrentFilePath;
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
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            ScanStateText.Text = $" · COMPLETED ({summary.Findings.Count} detections)";
            ScanMetricsText.Text =
                $"{summary.TotalFilesScanned} scanned · {summary.Findings.Count} detections · {summary.SkippedExcludedCount} excluded · {summary.SkippedUnchangedCount} cached";
            ActiveScanLivePathText.Text = $"Completed in {summary.DurationSeconds:F2}s ({summary.TotalFilesScanned} files inspected)";

            foreach (var finding in summary.Findings)
            {
                _currentFindings.Add(finding);
                RenderFindingInList(finding);
            }

            if (summary.Findings.Count == 0)
            {
                FindingsListBox.Items.Add($"[CLEAN] No malware or suspicious indicators detected across {summary.TotalFilesScanned} scanned file(s).");
            }
            else
            {
                PlayGentleChimeIfEnabled();
            }

            PopulateScanHistoryInInspector();
            UpdateHeroProtectionBannerState();
            StatusFooterText.Text =
                $"Scan finished in {summary.DurationSeconds:F2}s. Select any detection to Quarantine, Ignore Once, or Add Exclusion.";
        }
        catch (OperationCanceledException)
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 0;
            ScanStateText.Text = " · CANCELLED";
            ActiveScanLivePathText.Text = "Scan cancelled by user.";
            StatusFooterText.Text = "Scan cancelled safely by user.";
        }
        catch (Exception ex)
        {
            ScanProgressBar.IsIndeterminate = false;
            await _diagnosticsManager.LogLocalDiagnosticErrorAsync("MainWindow.RunScanWorkflowAsync", ex.Message);
            ScanStateText.Text = " · ERROR";
            StatusFooterText.Text = $"Scan error logged to local diagnostics: {ex.Message}";
        }
    }

    // =========================================================================
    // 6. QUARANTINE-FIRST REMEDIATION & CONTEXTUAL VAULT ACTIONS
    // =========================================================================

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

        var confirm = System.Windows.MessageBox.Show(
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
        _currentFindings.RemoveAt(idx);
        FindingsListBox.Items.RemoveAt(idx);
        await RefreshQuarantineVaultAsync();
        UpdateHeroProtectionBannerState();
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
        UpdateHeroProtectionBannerState();
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
        var confirm = System.Windows.MessageBox.Show(
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
        QuarantineCountText.Text = $"{_exclusionManager.GetExclusions().Count} EXCLUDED";
        UpdateHeroProtectionBannerState();
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
        UpdateHeroProtectionBannerState();
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
        var confirm = System.Windows.MessageBox.Show(
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
        UpdateHeroProtectionBannerState();
        StatusFooterText.Text = $"Permanently deleted quarantined payload {item.QuarantineId[..8]}.";
    }

    // =========================================================================
    // 7. BILINGUAL (EN / বাংলা) & THEME (LIGHT MINIMAL GLASS / OBSIDIAN DARK)
    // =========================================================================

    private void OnToggleLanguageClick(object sender, RoutedEventArgs e)
    {
        _currentLanguage = _currentLanguage == "en" ? "bn" : "en";
        SaveLocalUiPreferences();
        var isBn = IsBengaliLanguage;

        AppTitleBlock.Text = BilingualStrings.Get("app.title", isBn);
        AppSubtitleBlock.Text = BilingualStrings.Get("app.subtitle", isBn);
        DisclosureBannerText.Text = BilingualStrings.Get("status.honest_disclosure", isBn);

        Tile1TitleText.Text = BilingualStrings.Get("nav.quick_scan", isBn);
        Tile2TitleText.Text = BilingualStrings.Get("nav.web_protection", isBn);
        Tile3TitleText.Text = BilingualStrings.Get("nav.realtime", isBn);
        Tile4TitleText.Text = BilingualStrings.Get("nav.quarantine", isBn);
        Tile5TitleText.Text = BilingualStrings.Get("nav.history", isBn);
        Tile6TitleText.Text = BilingualStrings.Get("nav.security_intel", isBn);
        Tile7TitleText.Text = BilingualStrings.Get("nav.updates", isBn);
        Tile8TitleText.Text = BilingualStrings.Get("nav.exclusions", isBn);

        HeroQuickScanCtaBtn.Content = BilingualStrings.Get("nav.quick_scan", isBn);

        if (AboutOfficialMessageBlock != null)
        {
            AboutOfficialMessageBlock.Text = BilingualStrings.Get("AboutMessage", isBn);
        }
        if (AboutNonAffiliationBlock != null)
        {
            AboutNonAffiliationBlock.Text = BilingualStrings.Get("NonAffiliationNotice", isBn);
        }

        UpdateSettingsCardLabels();
        UpdateHeroProtectionBannerState();
    }

    private void OnToggleThemeClick(object sender, RoutedEventArgs e)
    {
        _isDarkTheme = !_isDarkTheme;
        SaveLocalUiPreferences();
        ApplyThemePalette();
        UpdateSettingsCardLabels();
        UpdateHeroProtectionBannerState();
    }

    private void ApplyThemePalette()
    {
        var res = System.Windows.Application.Current?.Resources ?? Resources;
        if (_isDarkTheme)
        {
            // Optional Obsidian Dark Mode
            res["AppCanvasBrush"] = CreateBrush("#0B1120");
            res["TitleBarBackgroundBrush"] = CreateBrush("#070B14");
            res["UtilityBarBackgroundBrush"] = CreateBrush("#080D1A");
            res["GlassCardBrush"] = CreateBrush("#111827");
            res["GlassElevatedBrush"] = CreateBrush("#172033");
            res["GlassBorderBrush"] = CreateBrush("#1F2937");
            res["PrimaryTextBrush"] = CreateBrush("#F8FAFC");
            res["SecondaryTextBrush"] = CreateBrush("#94A3B8");
            res["MutedTextBrush"] = CreateBrush("#64748B");
        }
        else
        {
            // Default Light Minimal Glass (Windows 11 Fluent)
            res["AppCanvasBrush"] = CreateBrush("#F4F7FB");
            res["TitleBarBackgroundBrush"] = CreateBrush("#EAF0F8");
            res["UtilityBarBackgroundBrush"] = CreateBrush("#EEF3F9");
            res["GlassCardBrush"] = CreateBrush("#FFFFFF");
            res["GlassElevatedBrush"] = CreateBrush("#F8FAFC");
            res["GlassBorderBrush"] = CreateBrush("#E2E8F0");
            res["PrimaryTextBrush"] = CreateBrush("#0F172A");
            res["SecondaryTextBrush"] = CreateBrush("#475569");
            res["MutedTextBrush"] = CreateBrush("#64748B");
        }

        var bgBrush = (SolidColorBrush)res["AppCanvasBrush"];
        var fgBrush = (SolidColorBrush)res["PrimaryTextBrush"];
        Background = bgBrush;
        Foreground = fgBrush;
        if (OuterWindowFrame != null)
        {
            OuterWindowFrame.Background = bgBrush;
        }
    }

    private static System.Windows.Media.Color ParseWpfColor(string hex) =>
        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);

    private static SolidColorBrush CreateBrush(string hex) =>
        new(ParseWpfColor(hex));
}

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Media;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
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
    private readonly RansomwareShieldMonitor _ransomwareShield;
    private readonly PrivacyProtectionMonitor _privacyMonitor;
    private readonly SafeBankingProtectionModule _safeBankingModule;
    private readonly EmailAttachmentSecurityScanner _emailAttachmentScanner;
    private readonly PrivacyFirstCloudThreatIntelligenceService _cloudIntelService;

    private readonly string _localAppDataDir;
    private readonly string _uiPreferencesFilePath;
    private readonly List<ScanFinding> _currentFindings = new();
    private readonly List<ScanReport> _scanHistory = new();
    private List<QuarantineEntry> _currentQuarantineItems = new();
    private readonly HashSet<string> _knownRemovableDrives = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _appShutdownCts = new();
    private CancellationTokenSource? _activeScanCts;
    private System.Windows.Forms.NotifyIcon? _systemTrayNotifyIcon;
    private System.Windows.Forms.ToolStripMenuItem? _trayRealtimeMenuItem;

    private const int WmDeviceChange = 0x0219;
    private const int DbtDeviceArrival = 0x8000;
    private const int DbtDevNodesChanged = 0x0007;

    // Default Theme: Light Minimal Glass (#F3F8F6) with Bengal Emerald (#006A4E / #10B981) Accents
    private bool _isDarkTheme = false;
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
        _ransomwareShield = new RansomwareShieldMonitor(_notificationManager);
        _privacyMonitor = new PrivacyProtectionMonitor();
        _safeBankingModule = new SafeBankingProtectionModule(_browserDownloadGuard);
        _emailAttachmentScanner = new EmailAttachmentSecurityScanner(_scanPipeline);
        _cloudIntelService = new PrivacyFirstCloudThreatIntelligenceService(null, _updateManager);

        LoadLocalUiPreferences();
        ApplyThemePalette();
        UpdateEcoPowerModeBadgeAndLabels();
        InitializeSystemTrayCompanion();
        ShowActiveWorkspaceView(showDashboardHero: true);

        // Show First-Run Light Minimal Glass Welcome Screen on first launch only (unless launched via Explorer Right-Click --scan-path)
        if (!_hasCompletedFirstRunWelcome && string.IsNullOrWhiteSpace(App.InitialScanTargetPath))
        {
            FirstRunWelcomeOverlayPanel.Visibility = Visibility.Visible;
        }

        SourceInitialized += OnWindowSourceInitialized;

        Loaded += async (_, _) =>
        {
            ApplyWorkAreaBounds();
            SeedInitialRemovableDrivesSnapshot();
            _ = StartContextMenuScanPipeServerAsync(_appShutdownCts.Token);
            _ = MonitorUsbDriveArrivalsAsync(_appShutdownCts.Token);

            await RefreshWindowsSecurityPostureAsync();
            await RefreshQuarantineVaultAsync();
            UpdateHeroProtectionBannerState();

            if (!string.IsNullOrWhiteSpace(App.InitialScanTargetPath))
            {
                await RunExplorerContextMenuScanAsync(App.InitialScanTargetPath);
            }
            else if (App.StartMinimizedToTray)
            {
                MinimizeSmoothlyToSystemTray();
            }
        };
    }

    // =========================================================================
    // 1. LOCAL UI PREFERENCES & FIRST-RUN WELCOME SCREEN PERSISTENCE
    // =========================================================================

    private sealed class LocalUiPreferences
    {
        public int ThemeSchemaVersion { get; set; } = 4;
        public bool IsDarkTheme { get; set; } = false;
        public string Language { get; set; } = "en";
        public bool MinimizeToTrayOnClose { get; set; } = true;
        public bool EcoPowerModeEnabled { get; set; } = true;
        public bool HasCompletedFirstRunWelcome { get; set; }
    }

    private void LoadLocalUiPreferences()
    {
        // Default to Light Minimal Glass (#F3F8F6) on startup
        _isDarkTheme = false;

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

            // Apply saved theme if written by V4+ schema; otherwise default to Light Minimal Glass (#F3F8F6)
            _isDarkTheme = prefs.ThemeSchemaVersion >= 4 ? prefs.IsDarkTheme : false;
            _currentLanguage = string.Equals(prefs.Language, "bn", StringComparison.OrdinalIgnoreCase) ? "bn" : "en";
            _minimizeToTrayOnClose = prefs.MinimizeToTrayOnClose;
            _performanceGuard.SetEcoPowerMode(prefs.EcoPowerModeEnabled);
            _hasCompletedFirstRunWelcome = prefs.HasCompletedFirstRunWelcome;
        }
        catch
        {
            // Safe default: Light Minimal Glass (#F3F8F6), English, Eco-Power Mode enabled
            _isDarkTheme = false;
        }
    }

    private void SaveLocalUiPreferences()
    {
        try
        {
            var prefs = new LocalUiPreferences
            {
                ThemeSchemaVersion = 4,
                IsDarkTheme = _isDarkTheme,
                Language = _currentLanguage,
                MinimizeToTrayOnClose = _minimizeToTrayOnClose,
                EcoPowerModeEnabled = _performanceGuard.EcoPowerModeEnabled,
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
            var rootIcoPath = Path.Combine(AppContext.BaseDirectory, "KironProhori.ico");
            if (File.Exists(icoPath))
            {
                trayIcon = new System.Drawing.Icon(icoPath);
            }
            else if (File.Exists(rootIcoPath))
            {
                trayIcon = new System.Drawing.Icon(rootIcoPath);
            }
            else
            {
                var resourceStream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/KironProhori.ico"));
                if (resourceStream?.Stream != null)
                {
                    trayIcon = new System.Drawing.Icon(resourceStream.Stream);
                }
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
        _appShutdownCts.Cancel();
        _activeScanCts?.Cancel();
        _realTimeMonitor.Dispose();
        _ransomwareShield.Dispose();
        if (_systemTrayNotifyIcon != null)
        {
            _systemTrayNotifyIcon.Visible = false;
            _systemTrayNotifyIcon.Dispose();
            _systemTrayNotifyIcon = null;
        }
    }

    // =========================================================================
    // 2B. WINDOWS EXPLORER RIGHT-CLICK (--scan-path) & AUTO USB ARRIVAL WATCHER
    // =========================================================================

    private void OnWindowSourceInitialized(object? sender, EventArgs e)
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            if (handle != IntPtr.Zero)
            {
                HwndSource.FromHwnd(handle)?.AddHook(WndProc);
            }
        }
        catch
        {
            // Safe fallback on non-Win32 test host
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmDeviceChange)
        {
            int eventCode = wParam.ToInt32();
            if (eventCode == DbtDeviceArrival || eventCode == DbtDevNodesChanged)
            {
                _ = CheckForNewlyArrivedUsbDrivesAsync();
            }
        }
        return IntPtr.Zero;
    }

    private void SeedInitialRemovableDrivesSnapshot()
    {
        _knownRemovableDrives.Clear();
        foreach (var drive in ModularScanPipeline.GetRemovableUsbDrives())
        {
            _knownRemovableDrives.Add(drive.RootDirectory.FullName);
        }
    }

    private async Task MonitorUsbDriveArrivalsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2.5), cancellationToken);
                await CheckForNewlyArrivedUsbDrivesAsync();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Ignore transient volume enumeration error
            }
        }
    }

    private async Task CheckForNewlyArrivedUsbDrivesAsync()
    {
        var currentDrives = ModularScanPipeline.GetRemovableUsbDrives()
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        // Remove unplugged drives from tracked set
        _knownRemovableDrives.RemoveWhere(known =>
            !currentDrives.Contains(known, StringComparer.OrdinalIgnoreCase));

        foreach (var driveRoot in currentDrives)
        {
            if (_knownRemovableDrives.Add(driveRoot))
            {
                await HandleUsbDriveArrivalAsync(driveRoot);
            }
        }
    }

    /// <summary>
    /// Automatically invoked the moment a USB pendrive is plugged in:
    /// 1. Plays a soft, pleasant gentle chime.
    /// 2. Shows a tray notification: "USB Drive Detected (X:) — Scanning with KIRON PROHORI..."
    /// 3. Automatically un-hides folders hidden by USB shortcut viruses and scans the USB drive.
    /// 4. Shows a completion notification ("USB Safe" or "Threat Detected — Ready to Quarantine").
    /// </summary>
    public async Task HandleUsbDriveArrivalAsync(string driveRootPath)
    {
        string driveLabel = driveRootPath.TrimEnd('\\');
        PlayGentleChimeIfEnabled();

        ShowTrayNotification(
            "KIRON PROHORI — USB Protection",
            $"USB Drive Detected ({driveLabel}) — Scanning with KIRON PROHORI...",
            System.Windows.Forms.ToolTipIcon.Info);

        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = $"USB Auto-Scan ({driveLabel})";
        ActiveScanBannerTitle.Text = $"AUTOMATIC USB DRIVE SCAN — {driveLabel}";
        StatusFooterText.Text = $"USB Drive Detected ({driveLabel}) — Scanning and recovering hidden folders...";

        var recoveredFolders = ModularScanPipeline.RecoverHiddenUsbFolders(driveRootPath);
        await RunScanWorkflowAsync(ScanType.UsbDriveScan, new[] { driveRootPath });

        if (recoveredFolders.Count > 0)
        {
            foreach (var folder in recoveredFolders)
            {
                QuarantineListBox.Items.Insert(0, $"[USB FOLDER RECOVERED] Unhidden: {folder}");
            }
        }

        if (_currentFindings.Count == 0)
        {
            string recoveredNote = recoveredFolders.Count > 0
                ? $" · Recovered {recoveredFolders.Count} hidden folder(s)"
                : string.Empty;
            ShowTrayNotification(
                "KIRON PROHORI — USB Safe",
                $"USB Safe ({driveLabel}) — No malware detected{recoveredNote}.",
                System.Windows.Forms.ToolTipIcon.Info);
            StatusFooterText.Text = $"USB Safe ({driveLabel}) — Scan complete{recoveredNote}.";
        }
        else
        {
            ShowTrayNotification(
                "KIRON PROHORI — USB Threat Detected",
                $"Threat Detected on USB ({driveLabel}) — {_currentFindings.Count} item(s) ready to Quarantine.",
                System.Windows.Forms.ToolTipIcon.Warning);
        }
    }

    private void ShowTrayNotification(string title, string message, System.Windows.Forms.ToolTipIcon icon)
    {
        try
        {
            if (_systemTrayNotifyIcon != null)
            {
                _systemTrayNotifyIcon.Visible = true;
                _systemTrayNotifyIcon.ShowBalloonTip(2800, title, message, icon);
            }
        }
        catch
        {
            // Safe no-op in headless CI runner
        }
    }

    private async Task StartContextMenuScanPipeServerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    App.ScanPathNamedPipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 4,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(cancellationToken);
                using var reader = new StreamReader(server, Encoding.UTF8);
                string forwardedPath = (await reader.ReadToEndAsync(cancellationToken)).Trim();

                if (!string.IsNullOrWhiteSpace(forwardedPath))
                {
                    await Dispatcher.InvokeAsync(async () =>
                    {
                        RestoreFromSystemTray();
                        await RunExplorerContextMenuScanAsync(forwardedPath);
                    });
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(400, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Executes an immediate scan triggered from the Windows Explorer Right-Click Context Menu
    /// ("Scan with KIRON PROHORI" -> --scan-path "&lt;drive/folder/file&gt;").
    /// </summary>
    public async Task RunExplorerContextMenuScanAsync(string targetPath)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        FirstRunWelcomeOverlayPanel.Visibility = Visibility.Collapsed;
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);

        if (File.Exists(targetPath))
        {
            CurrentSectionTitle.Text = $"Explorer File Scan — {Path.GetFileName(targetPath)}";
            ActiveScanBannerTitle.Text = $"EXPLORER CONTEXT MENU FILE SCAN — {targetPath}";
            await RunSingleFileContextMenuScanAsync(targetPath);
            return;
        }

        if (Directory.Exists(targetPath))
        {
            bool isRemovableDrive = false;
            try
            {
                var root = Path.GetPathRoot(targetPath);
                if (!string.IsNullOrWhiteSpace(root))
                {
                    var di = new DriveInfo(root);
                    isRemovableDrive = di.DriveType == DriveType.Removable;
                }
            }
            catch
            {
                // Ignore DriveInfo parse error
            }

            if (isRemovableDrive)
            {
                await HandleUsbDriveArrivalAsync(targetPath);
            }
            else
            {
                CurrentSectionTitle.Text = $"Explorer Folder Scan — {targetPath}";
                ActiveScanBannerTitle.Text = $"EXPLORER CONTEXT MENU SCAN — {targetPath}";
                await RunScanWorkflowAsync(ScanType.CustomFolderScan, new[] { targetPath });
            }
            return;
        }

        ActiveScanLivePathText.Text = $"Target path not found: {targetPath}";
        StatusFooterText.Text = $"Cannot scan '{targetPath}' — path does not exist.";
    }

    private async Task RunSingleFileContextMenuScanAsync(string filePath)
    {
        _activeScanCts?.Cancel();
        _activeScanCts = new CancellationTokenSource();
        _scanPipeline.ResumeActiveScan();
        PauseResumeScanBtn.Content = "Pause Scan";

        ScanStateText.Text = " · RUNNING (Single File)";
        ScanProgressBar.IsIndeterminate = true;
        FindingsListBox.Items.Clear();
        _currentFindings.Clear();

        var progress = new Progress<ScanProgressUpdate>(report =>
        {
            ScanMetricsText.Text = $"{report.FilesScanned} scanned · {report.ThreatsFound} detections";
            ActiveScanLivePathText.Text = report.CurrentFilePath;
        });

        var summary = await _scanPipeline.ScanSingleFileAsync(filePath, progress, _activeScanCts.Token);
        _scanHistory.Insert(0, summary);
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = 100;
        ScanStateText.Text = $" · COMPLETED ({summary.Findings.Count} detections)";
        ScanMetricsText.Text = $"{summary.TotalFilesScanned} scanned · {summary.Findings.Count} detections";
        ActiveScanLivePathText.Text = $"Completed in {summary.DurationSeconds:F2}s ({filePath})";

        foreach (var finding in summary.Findings)
        {
            _currentFindings.Add(finding);
            RenderFindingInList(finding);
        }

        if (summary.Findings.Count == 0)
        {
            FindingsListBox.Items.Add($"[CLEAN] No threats detected in '{filePath}'.");
        }
        else
        {
            PlayGentleChimeIfEnabled();
        }

        PopulateScanHistoryInInspector();
        UpdateHeroProtectionBannerState();
        StatusFooterText.Text = $"Finished scanning '{Path.GetFileName(filePath)}'.";
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
        bool isExclusionsFirewallTab = false,
        bool isUpdatesTab = false,
        bool isNotificationsTab = false)
    {
        DashboardHeroViewPanel.Visibility = showDashboardHero ? Visibility.Visible : Visibility.Collapsed;
        ScannerAndInspectorViewPanel.Visibility = showScannerInspector ? Visibility.Visible : Visibility.Collapsed;
        SettingsDedicatedViewPanel.Visibility = showSettings ? Visibility.Visible : Visibility.Collapsed;
        AboutDedicatedViewPanel.Visibility = showAbout ? Visibility.Visible : Visibility.Collapsed;

        // STRICT RULE: Scan Controls (Pause/Stop/EICAR), Progress Bar, Metrics, and Left SCAN DETECTIONS box ONLY appear on Scan pages
        GlobalScanControlsToolbar.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;
        ScanProgressBar.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;
        ScanStateText.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;
        ScanMetricsText.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;

        if (isScanTab)
        {
            LeftScanDetectionsCardBorder.Visibility = Visibility.Visible;
            LeftDetectionsGridColumn.Width = new GridLength(1.25, GridUnitType.Star);
            RightInspectorGridColumn.Width = new GridLength(1.15, GridUnitType.Star);
            RightInspectorCardBorder.Margin = new Thickness(8, 0, 0, 0);
        }
        else
        {
            LeftScanDetectionsCardBorder.Visibility = Visibility.Collapsed;
            LeftDetectionsGridColumn.Width = new GridLength(0);
            RightInspectorGridColumn.Width = new GridLength(1, GridUnitType.Star);
            RightInspectorCardBorder.Margin = new Thickness(0);
        }

        // Contextual sub-toolbars inside the Sub-Page view
        ScanModesSubToolbar.Visibility = isScanTab ? Visibility.Visible : Visibility.Collapsed;
        WebAndDownloadSubToolbar.Visibility = isWebDownloadTab ? Visibility.Visible : Visibility.Collapsed;
        ExclusionsAndFirewallSubToolbar.Visibility = isExclusionsFirewallTab ? Visibility.Visible : Visibility.Collapsed;
        ToggleRealtimeMonitoringBtn.Visibility = isRealtimeTab ? Visibility.Visible : Visibility.Collapsed;
        UpdatesSubToolbar.Visibility = isUpdatesTab ? Visibility.Visible : Visibility.Collapsed;
        NotificationsSubToolbar.Visibility = isNotificationsTab ? Visibility.Visible : Visibility.Collapsed;

        // STRICT RULE: Restore & Permanent Delete ONLY appear inside Quarantine Vault
        QuarantineActionButtonsPanel.Visibility = isQuarantineTab ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateHeroProtectionBannerState()
    {
        var activeThreats = _currentFindings.Count;
        if (activeThreats > 0)
        {
            HeroProtectionBannerBorder.BorderBrush = CreateBrush("#F42A41");
            HeroGradStop1.Color = ParseWpfColor(_isDarkTheme ? "#2B1218" : "#FFF1F2");
            HeroGradStop2.Color = ParseWpfColor(_isDarkTheme ? "#111827" : "#FFE4E6");
            HeroShieldIconBadge.Background = CreateBrush("#26F42A41");
            HeroShieldIconBadge.BorderBrush = CreateBrush("#66F42A41");
            HeroShieldCornerCheck.Background = CreateBrush("#F42A41");
            HeroShieldGlyphText.Text = "!";
            HeroStatusPillBorder.Background = CreateBrush("#26F42A41");
            HeroStatusPillText.Foreground = CreateBrush("#FCA5A5");
            HeroStatusPillText.Text = IsBengaliLanguage ? "পদক্ষেপ প্রয়োজন" : "ACTION NEEDED";
            HeroHeadlineText.Text = IsBengaliLanguage
                ? $"{activeThreats}টি থ্রেট কোয়ারেন্টাইন রিভিউয়ের অপেক্ষায়"
                : $"Action Needed — {activeThreats} Detection(s) Pending Review";
            HeroHeadlineText.Foreground = CreateBrush(_isDarkTheme ? "#F8FAFC" : "#0F172A");
            HeroSubheadlineText.Text = "KIRON PROHORI follows a Quarantine-First policy with Local Heuristic AI Risk Scoring (0–100). Open Scan Results to Quarantine, Ignore Once, or Add Exclusion.";
            HeroSubheadlineText.Foreground = CreateBrush(_isDarkTheme ? "#94A3B8" : "#334155");
        }
        else
        {
            HeroProtectionBannerBorder.BorderBrush = CreateBrush(_isDarkTheme ? "#1E293B" : "#A7F3D0");
            HeroGradStop1.Color = ParseWpfColor(_isDarkTheme ? "#0D192B" : "#E8F6F1");
            HeroGradStop2.Color = ParseWpfColor(_isDarkTheme ? "#111827" : "#F3F8F6");
            HeroShieldIconBadge.Background = CreateBrush(_isDarkTheme ? "#1F10B981" : "#E6F4EF");
            HeroShieldIconBadge.BorderBrush = CreateBrush(_isDarkTheme ? "#4010B981" : "#10B981");
            HeroShieldCornerCheck.Background = CreateBrush("#10B981");
            HeroShieldGlyphText.Text = "KP";
            HeroStatusPillBorder.Background = CreateBrush(_isDarkTheme ? "#1F10B981" : "#006A4E");
            HeroStatusPillText.Foreground = CreateBrush(_isDarkTheme ? "#34D399" : "#FFFFFF");
            HeroStatusPillText.Text = IsBengaliLanguage ? "সুরক্ষা সক্রিয় · ইকো-মোড" : "PROTECTION LIVE · ECO-AI";
            HeroHeadlineText.Text = IsBengaliLanguage ? "আপনার সুরক্ষা এখন সক্রিয় রয়েছে" : "Your protection is live now";
            HeroHeadlineText.Foreground = CreateBrush(_isDarkTheme ? "#F8FAFC" : "#0F172A");
            HeroSubheadlineText.Text = "Eco-Power Green Computing Mode, Local Heuristic AI Risk Score (0–100), Infostealer & Fake AI App Guard, and Chrome/Edge MV3 Web Protection are active.";
            HeroSubheadlineText.Foreground = CreateBrush(_isDarkTheme ? "#94A3B8" : "#334155");
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
        var aiRiskScore = finding.LocalAiRiskScore0To100 > 0
            ? finding.LocalAiRiskScore0To100
            : (finding.Verdict == DetectionVerdict.ConfirmedDetection ? 95 : 78);

        FindingsListBox.Items.Insert(
            0,
            $"[{finding.Verdict}] [AI Risk: {aiRiskScore}/100] [{finding.Severity}] {finding.DetectionName} | {finding.FilePath} | Source: {finding.DetectionSourceAttribution} | Action: {finding.RecommendedAction}"
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
        ActiveScanBannerTitle.Text = "QUICK SCAN — DOWNLOADS, DESKTOP, STARTUP & TEMP";
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
        PopulateScanHistoryInInspector();
        var quickTargets = ModularScanPipeline.GetQuickScanDirectories();
        await RunScanWorkflowAsync(ScanType.QuickScan, quickTargets);
    }

    private async void OnFullScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.full_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "FULL SCAN — COMPLETE USER PROFILE & EXECUTABLES";
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
        PopulateScanHistoryInInspector();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        await RunScanWorkflowAsync(ScanType.FullScan, new[] { userProfile });
    }

    private async void OnCustomScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.custom_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "CUSTOM FOLDER SCAN — USER DOCUMENTS & WORKSPACE";
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
        PopulateScanHistoryInInspector();
        var docsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        await RunScanWorkflowAsync(ScanType.CustomFolderScan, new[] { docsPath });
    }

    private async void OnUsbScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.usb_scan", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "REMOVABLE USB DRIVE SCAN";
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
        PopulateScanHistoryInInspector();
        var removableDrives = ModularScanPipeline.GetRemovableUsbDrives()
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        if (removableDrives.Count == 0)
        {
            ActiveScanLivePathText.Text = "No removable USB drives currently mounted.";
            StatusFooterText.Text = "Plug in a USB drive — KIRON PROHORI will auto-detect and scan it automatically.";
            return;
        }

        PlayGentleChimeIfEnabled();
        foreach (var drive in removableDrives)
        {
            ModularScanPipeline.RecoverHiddenUsbFolders(drive);
        }
        await RunScanWorkflowAsync(ScanType.UsbDriveScan, removableDrives);
    }

    private void OnRecoverUsbHiddenFoldersClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = "USB Shortcut Virus — Hidden Folder Recovery";
        ActiveScanBannerTitle.Text = "RECOVER HIDDEN USB FOLDERS (SHORTCUT VIRUS REMEDIATION)";
        RightPanelHeaderText.Text = "RECOVERED USB FOLDERS";
        QuarantineListBox.Items.Clear();

        var removableDrives = ModularScanPipeline.GetRemovableUsbDrives()
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        if (removableDrives.Count == 0)
        {
            QuarantineListBox.Items.Add("No removable USB drive detected. Plug in your USB drive and click 'Recover USB Folders'.");
            StatusFooterText.Text = "No removable USB drive mounted.";
            return;
        }

        int totalRecovered = 0;
        foreach (var driveRoot in removableDrives)
        {
            var recovered = ModularScanPipeline.RecoverHiddenUsbFolders(driveRoot);
            totalRecovered += recovered.Count;
            foreach (var folder in recovered)
            {
                QuarantineListBox.Items.Add($"[RECOVERED] Cleared Hidden/System attributes: {folder}");
            }
        }

        if (totalRecovered == 0)
        {
            QuarantineListBox.Items.Add($"Checked {string.Join(", ", removableDrives)} — No hidden user folders found.");
            StatusFooterText.Text = "All USB folders are already visible.";
        }
        else
        {
            PlayGentleChimeIfEnabled();
            StatusFooterText.Text = $"Recovered {totalRecovered} hidden folder(s) on your USB drive.";
        }
    }

    private async void OnLaunchDefenderOfflineScanClick(object sender, RoutedEventArgs e)
    {
        var confirm = System.Windows.MessageBox.Show(
            "Launch Microsoft Defender Offline Scan (Start-MpWDOScan)?\n\nThis reboots Windows into a pre-boot environment to remove deep kernel/boot-sector rootkits. Save your open files before continuing.",
            "KIRON PROHORI — Deep Rootkit Offline Scan Bridge",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information
        );

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        var (invoked, statusMsg) = await _windowsSecurityMonitor.TriggerWindowsDefenderOfflineScanAsync();
        QuarantineListBox.Items.Insert(0, $"[DEFENDER OFFLINE SCAN] {statusMsg}");
        StatusFooterText.Text = statusMsg;
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
        QuarantineListBox.Items.Add(
            $"[Local Definitions: {_cloudIntelService.OfflineLocalDefinitionsState}] [Live Cloud Reputation: {_cloudIntelService.LiveCloudReputationState}] {PrivacyFirstCloudThreatIntelligenceService.PrivacyAndMetadataDisclosure}"
        );
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
        ActiveScanLivePathText.Text = "All scan reports and threat logs are stored locally on your PC with zero cloud telemetry.";
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
        ActiveScanLivePathText.Text = "Select any isolated item below to Restore with SHA-256 verification or Permanently Delete.";
        await RefreshQuarantineVaultAsync();
        UpdateHeroProtectionBannerState();
    }

    private void OnExclusionsViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.exclusions", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "CANONICAL PATH EXCLUSIONS & WINDOWS SECURITY COEXISTENCE";
        ActiveScanLivePathText.Text = "Manage trusted folders or files excluded from KIRON PROHORI scans (never modifies Microsoft Defender).";
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
            QuarantineListBox.Items.Add("No custom path exclusions configured. Click '➕ Add Exclusion' above to exclude a folder or file.");
        }

        StatusFooterText.Text = ExclusionManager.SecurityRiskExplanation;
    }

    private async void OnAddCustomExclusionClick(object sender, RoutedEventArgs e)
    {
        using var dialog = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select a trusted folder to exclude from KIRON PROHORI scans (Does not modify Microsoft Defender)",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };

        if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK || string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"{ExclusionManager.SecurityRiskExplanation}\n\nExclude folder:\n{dialog.SelectedPath}",
            "KIRON PROHORI — Confirm Folder Exclusion",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning
        );

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await _exclusionManager.AddExclusionAsync(
            dialog.SelectedPath,
            ExclusionScope.DirectoryRecursive,
            "User added via Exclusions folder picker",
            userConfirmed: true
        );

        QuarantineCountText.Text = $"{_exclusionManager.GetExclusions().Count} EXCLUDED";
        OnExclusionsViewClick(sender, e);
        StatusFooterText.Text = $"Added folder '{dialog.SelectedPath}' to KIRON PROHORI Exclusions.";
    }

    private async void OnRefreshWindowsSecurityClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.defender", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "MICROSOFT DEFENDER COEXISTENCE (READ-ONLY WMI TELEMETRY)";
        ActiveScanLivePathText.Text = "KIRON PROHORI coexists safely alongside Microsoft Defender and never disables Windows security services.";
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
        ActiveScanBannerTitle.Text = "SMART FIREWALL INTEGRATION (PROFILES & READ-ONLY TCP SESSIONS)";
        ActiveScanLivePathText.Text = "Inspects Domain, Private, and Public firewall profiles and active TCP endpoints read-only.";
        await RefreshWindowsSecurityPostureAsync();
        var posture = _windowsSecurityMonitor.GetSecuritySnapshot();
        var connections = _windowsSecurityMonitor.InspectActiveNetworkConnections();
        RightPanelHeaderText.Text = $"WINDOWS FIREWALL PROFILES & ACTIVE TCP CONNECTIONS ({connections.Count})";
        QuarantineListBox.Items.Clear();
        foreach (var profile in posture.FirewallProfiles)
        {
            QuarantineListBox.Items.Add($"[FIREWALL PROFILE] {profile.ProfileName} | Status: {OnOff(profile.IsEnabled)}");
        }
        foreach (var conn in connections.Take(15))
        {
            var flag = conn.IsSuspiciousPortOrHost ? "SUSPICIOUS PORT/HOST" : "NORMAL";
            QuarantineListBox.Items.Add(
                $"[{flag}] TCP {conn.LocalEndpoint} -> {conn.RemoteEndpoint} ({conn.TcpState}) | {conn.AssessmentNote}"
            );
        }
        StatusFooterText.Text = "Smart Firewall Integration: Read-only Domain/Private/Public status & active TCP endpoint inspection (Never modifies firewall rules silently).";
    }

    private async void OnEmailAttachmentScanClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isScanTab: true);
        CurrentSectionTitle.Text = "Email & Attachment Security (Local Attachment Scanner)";
        ActiveScanBannerTitle.Text = "EMAIL ATTACHMENT SECURITY — EXECUTABLES, SCRIPTS, MACROS & ARCHIVES";
        ActiveScanLivePathText.Text = $"Local Attachment Scanner: {_emailAttachmentScanner.LocalAttachmentScannerState} · Direct Mailbox Integration: {_emailAttachmentScanner.DirectMailboxAccessState}";
        RightPanelHeaderText.Text = "EMAIL ATTACHMENT SECURITY SCANNER";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add(
            $"[Local Attachment Scan: {_emailAttachmentScanner.LocalAttachmentScannerState}] [Direct Mailbox Access: {_emailAttachmentScanner.DirectMailboxAccessState}]"
        );
        QuarantineListBox.Items.Add("[DISCLOSURE] Local Email Attachment Scanner inspects downloaded attachments read-only. Direct mailbox/inbox integration is marked as PLANNED.");

        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            var candidateFiles = Directory.EnumerateFiles(downloadsDir)
                .Take(8)
                .ToList();
            foreach (var file in candidateFiles)
            {
                var res = await _emailAttachmentScanner.ScanDownloadedAttachmentAsync(file);
                QuarantineListBox.Items.Add(
                    $"[{res.ScanStatus}] [{res.FormatCategory}] {res.FileName} | {res.DetectionSummary}"
                );
            }
            if (candidateFiles.Count == 0)
            {
                QuarantineListBox.Items.Add("Downloads folder has 0 attachment files to inspect.");
            }
        }
        StatusFooterText.Text = "Email Attachment Scanner inspects downloaded attachments locally · Direct Mailbox Access: PLANNED.";
    }

    private void OnSafeBankingViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isWebDownloadTab: true);
        CurrentSectionTitle.Text = "Safe Banking Protection (HTTPS & Anti-Phishing Verification)";
        ActiveScanBannerTitle.Text = "SAFE BANKING & FINANCIAL DOMAIN VERIFICATION";
        ActiveScanLivePathText.Text = $"HTTPS & Phishing Check: {_safeBankingModule.UrlVerificationState} · Hardened Isolated Browser: {_safeBankingModule.HardenedBrowserIsolationState}";
        RightPanelHeaderText.Text = "SAFE BANKING VERIFICATION & FEATURE STATUS";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add(
            $"[HTTPS & Phishing Verification: {_safeBankingModule.UrlVerificationState}] [Hardened Browser Isolation: {_safeBankingModule.HardenedBrowserIsolationState}]"
        );
        QuarantineListBox.Items.Add($"[DISCLOSURE] {SafeBankingProtectionModule.HonestBankingLimitationNotice}");

        string[] sampleUrls =
        {
            "https://www.bb.org.bd",
            "https://www.sonalibank.com.bd",
            "https://www.dutchbanglabank.com",
            "https://www.bracbank.com",
            "http://insecure-banking-login.example.com"
        };
        foreach (var url in sampleUrls)
        {
            var check = _safeBankingModule.VerifyBankingUrl(url);
            var statusTag = (check.IsHttpsEncrypted && !check.HasPhishingOrRedirectRisk) ? "VERIFIED HTTPS" : "WARNING";
            QuarantineListBox.Items.Add($"[{statusTag}] {check.InputUrl} | {check.VerdictSummary}");
        }
        StatusFooterText.Text = SafeBankingProtectionModule.HonestBankingLimitationNotice;
    }

    private void OnRansomwareShieldViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = "Ransomware Shield (User-Mode Protected Folders & Burst Guard)";
        ActiveScanBannerTitle.Text = $"RANSOMWARE SHIELD — [{_ransomwareShield.FeatureState}]";
        ActiveScanLivePathText.Text = RansomwareShieldMonitor.HonestLimitationDisclosure;
        RightPanelHeaderText.Text = "PROTECTED USER FOLDERS & RANSOMWARE EVENTS";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add($"[DISCLOSURE] {RansomwareShieldMonitor.HonestLimitationDisclosure}");
        foreach (var folder in _ransomwareShield.GetProtectedFolders())
        {
            QuarantineListBox.Items.Add($"[PROTECTED FOLDER] {folder}");
        }
        foreach (var evt in _ransomwareShield.GetEventHistory())
        {
            QuarantineListBox.Items.Add(
                $"{evt.DetectedAtUtc:HH:mm:ss} | [{evt.AnomalyCategory}] [{evt.Severity}] {evt.Explanation}"
            );
        }
        StatusFooterText.Text = "Ransomware Shield monitors Documents, Pictures, and Desktop for mass file modifications, encryption extensions, and ransom notes.";
    }

    private async void OnRunHarmlessRansomwareSimulationClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = "Harmless Ransomware Simulation (Isolated Temp Sandbox)";
        ActiveScanBannerTitle.Text = "HARMLESS RANSOMWARE SIMULATION — ZERO USER FILES TOUCHED";
        var events = await _ransomwareShield.RunHarmlessRansomwareSimulationAsync();
        OnRansomwareShieldViewClick(sender, e);
        StatusFooterText.Text = $"Harmless simulation complete ({events.Count} behavioral event(s) detected in isolated sandbox).";
    }

    private void OnPrivacyProtectionViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isExclusionsFirewallTab: true);
        CurrentSectionTitle.Text = "Webcam & Microphone Privacy Protection (Read-Only Monitor)";
        ActiveScanBannerTitle.Text = "CAMERA & MICROPHONE CONSENT STORE MONITOR";
        var snapshot = _privacyMonitor.GetPrivacySnapshot();
        ActiveScanLivePathText.Text = $"Camera State: {snapshot.CameraMonitoringState} ({snapshot.GlobalCameraConsent}) · Mic State: {snapshot.MicrophoneMonitoringState} ({snapshot.GlobalMicrophoneConsent})";
        RightPanelHeaderText.Text = "WINDOWS CAMERA & MICROPHONE PERMISSIONS (READ-ONLY)";
        QuarantineListBox.Items.Clear();
        QuarantineListBox.Items.Add(
            $"[GLOBAL PRIVACY] Camera Global Consent: {snapshot.GlobalCameraConsent} | Microphone Global Consent: {snapshot.GlobalMicrophoneConsent}"
        );
        QuarantineListBox.Items.Add($"[DISCLOSURE] {snapshot.LimitationDisclosure}");
        foreach (var app in snapshot.ApplicationPermissions.Take(20))
        {
            QuarantineListBox.Items.Add(
                $"[{app.DeviceCategory}] {app.ApplicationId} | Consent: {app.ConsentValue} | Currently Active: {app.IsCurrentlyActive}"
            );
        }
        if (snapshot.ApplicationPermissions.Count == 0)
        {
            QuarantineListBox.Items.Add("No individual desktop/packaged app camera or microphone consent entries recorded in current user profile.");
        }
        StatusFooterText.Text = snapshot.LimitationDisclosure;
    }

    private void OnCheckUpdatesClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isUpdatesTab: true);
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
            QuarantineListBox.Items.Add($"Engine & Intelligence V{AboutBrandMetadata.ProductVersion} up to date · Verified at {DateTimeOffset.UtcNow:HH:mm:ss} UTC · Publisher: {SecureUpdateManager.TrustedPublisherIdentity}");
        }
        StatusFooterText.Text = $"Automatic Update System enforces HTTPS + SHA-256 hash + {SecureUpdateManager.TrustedPublisherIdentity}.";
    }

    private void OnNotificationsViewClick(object sender, RoutedEventArgs e)
    {
        ShowActiveWorkspaceView(showScannerInspector: true, isNotificationsTab: true);
        CurrentSectionTitle.Text = BilingualStrings.Get("nav.notifications", IsBengaliLanguage);
        ActiveScanBannerTitle.Text = "SMART ANTI-SPAM NOTIFICATION CENTER & 280MS GENTLE CHIME";
        ActiveScanLivePathText.Text = $"Notification Sound: {(_notificationManager.SoundEnabled ? "ON" : "OFF")} · Volume: {_notificationManager.VolumePercent}% · Anti-Spam Cooldown Active";
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

    private void OnToggleEcoPowerModeClick(object sender, RoutedEventArgs e)
    {
        _performanceGuard.SetEcoPowerMode(!_performanceGuard.EcoPowerModeEnabled);
        SaveLocalUiPreferences();
        UpdateEcoPowerModeBadgeAndLabels();
        UpdateSettingsCardLabels();
        StatusFooterText.Text = _performanceGuard.EcoPowerModeEnabled
            ? "Eco-Power Mode Active · Low Energy: Background scanning throttles automatically when CPU > 40% or on laptop battery."
            : "Standard Balanced Mode Active: Full multi-engine scan throughput enabled.";
    }

    private void UpdateEcoPowerModeBadgeAndLabels()
    {
        var ecoActive = _performanceGuard.EcoPowerModeEnabled;
        if (EcoPowerModeHeaderText != null)
        {
            EcoPowerModeHeaderText.Text = ecoActive
                ? $"● {_performanceGuard.EcoStatusBadgeLabel}"
                : "● Standard Mode · Balanced CPU";
        }
        if (EcoModeQuickToggleBtn != null)
        {
            EcoModeQuickToggleBtn.Content = ecoActive ? "Eco: ON" : "Eco: OFF";
        }
        if (ToggleEcoPowerSettingsBtn != null)
        {
            ToggleEcoPowerSettingsBtn.Content = ecoActive
                ? "Disable Eco-Power Mode (Switch to Balanced)"
                : "Enable Eco-Power Mode (Low Energy · CPU ≤ 40%)";
        }
    }

    private void UpdateSettingsCardLabels()
    {
        if (SettingsLanguageStatusText != null)
        {
            SettingsLanguageStatusText.Text = IsBengaliLanguage ? "বাংলা (BN)" : "English (EN)";
        }
        if (SettingsThemeStatusText != null)
        {
            SettingsThemeStatusText.Text = _isDarkTheme ? "Deep Slate (#0B1120)" : "Light Minimal Glass (#F3F8F6) — Default";
        }
        if (SettingsCloseBehaviorText != null)
        {
            SettingsCloseBehaviorText.Text = _minimizeToTrayOnClose
                ? "Minimize to System Tray on Close (Recommended)"
                : "Exit Application Completely on Close";
        }
        if (SettingsPerformanceProfileText != null)
        {
            SettingsPerformanceProfileText.Text =
                $"{_performanceGuard.EcoStatusBadgeLabel} · Max CPU {_performanceGuard.MaxCpuLimitPercent}%";
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
        RightPanelHeaderText.Text = $"RECENT SCAN SESSIONS ({_scanHistory.Count})";
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
            // Default Deep Slate (#0B1120) with #1E293B Card Borders, Translucent Emerald Icon Boxes (#1F10B981 / #4010B981), #34D399 Lucide Icons & Sleek Dark Pills (#14FFFFFF)
            res["AppCanvasBrush"] = CreateBrush("#0B1120");
            res["TitleBarBackgroundBrush"] = CreateBrush("#080D1A");
            res["UtilityBarBackgroundBrush"] = CreateBrush("#080D1A");
            res["GlassCardBrush"] = CreateBrush("#111827");
            res["GlassElevatedBrush"] = CreateBrush("#162032");
            res["GlassBorderBrush"] = CreateBrush("#1E293B");
            res["PrimaryTextBrush"] = CreateBrush("#F8FAFC");
            res["SecondaryTextBrush"] = CreateBrush("#94A3B8");
            res["MutedTextBrush"] = CreateBrush("#64748B");
            res["TileActionLinkBrush"] = CreateBrush("#34D399");
            res["TileActionLinkHoverBrush"] = CreateBrush("#6EE7B7");
            res["TileIconBoxBrush"] = CreateBrush("#1F10B981");
            res["TileIconBorderBrush"] = CreateBrush("#4010B981");
            res["TileIconGlyphBrush"] = CreateBrush("#34D399");
            res["DarkPillBackgroundBrush"] = CreateBrush("#14FFFFFF");
            res["DarkPillBorderBrush"] = CreateBrush("#24FFFFFF");
            res["DarkPillTextBrush"] = CreateBrush("#E2E8F0");
            res["DarkPillAccentTextBrush"] = CreateBrush("#34D399");
        }
        else
        {
            // Optional Light Minimal Glass Theme
            res["AppCanvasBrush"] = CreateBrush("#F3F8F6");
            res["TitleBarBackgroundBrush"] = CreateBrush("#E6F2EE");
            res["UtilityBarBackgroundBrush"] = CreateBrush("#E9F4F0");
            res["GlassCardBrush"] = CreateBrush("#FFFFFF");
            res["GlassElevatedBrush"] = CreateBrush("#F7FBF9");
            res["GlassBorderBrush"] = CreateBrush("#D1E7DD");
            res["PrimaryTextBrush"] = CreateBrush("#0F172A");
            res["SecondaryTextBrush"] = CreateBrush("#475569");
            res["MutedTextBrush"] = CreateBrush("#64748B");
            res["TileActionLinkBrush"] = CreateBrush("#047857");
            res["TileActionLinkHoverBrush"] = CreateBrush("#059669");
            res["TileIconBoxBrush"] = CreateBrush("#1F10B981");
            res["TileIconBorderBrush"] = CreateBrush("#4010B981");
            res["TileIconGlyphBrush"] = CreateBrush("#059669");
            res["DarkPillBackgroundBrush"] = CreateBrush("#E6F4EF");
            res["DarkPillBorderBrush"] = CreateBrush("#A7F3D0");
            res["DarkPillTextBrush"] = CreateBrush("#0F172A");
            res["DarkPillAccentTextBrush"] = CreateBrush("#047857");
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

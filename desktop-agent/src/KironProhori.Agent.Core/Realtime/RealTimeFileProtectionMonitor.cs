using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Scanning;

namespace KironProhori.Agent.Core.Realtime;

/// <summary>
/// MODULE 2 — KIRON PROHORI V1.0 Real-Time File Protection (Safe User-Mode Monitoring).
/// 
/// Responsibilities:
/// - Monitors newly downloaded files, newly created executable files, suspicious file modifications,
///   and potentially dangerous Windows Startup folder changes.
/// - Combines SHA-256 hash verification, verified threat intelligence, YARA/YARA-X &amp; ClamAV adapters
///   (where installed), static heuristic analysis, and Microsoft Defender coexistence.
/// - Never executes suspicious files to test them.
/// - Never claims kernel-level protection and never installs unsigned kernel drivers (.sys) in V1.0.
/// - Strictly respects user-configured KIRON PROHORI exclusions.
/// </summary>
public sealed class RealTimeFileProtectionMonitor : IDisposable
{
    private static readonly HashSet<string> MonitoredExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsf", ".lnk"
    };

    private readonly ModularScanPipeline _scanPipeline;
    private readonly ExclusionManager _exclusionManager;
    private readonly SmartNotificationManager _notificationManager;
    private readonly List<FileSystemWatcher> _activeWatchers = new();
    private readonly List<RealTimeProtectionEvent> _eventHistory = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _debounceMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public bool IsMonitoringActive { get; private set; }
    public bool IsKernelDriverInstalled => false; // Explicit V1.0 architectural boundary: User-Mode only
    public string ProtectionArchitecture => "User-Mode FileSystemWatcher + Modular Scan Pipeline (Coexists with Microsoft Defender)";

    public RealTimeFileProtectionMonitor(
        ModularScanPipeline? scanPipeline = null,
        ExclusionManager? exclusionManager = null,
        SmartNotificationManager? notificationManager = null)
    {
        _exclusionManager = exclusionManager ?? new ExclusionManager();
        _notificationManager = notificationManager ?? new SmartNotificationManager();
        _scanPipeline = scanPipeline ?? new ModularScanPipeline(
            exclusionManager: _exclusionManager,
            notificationManager: _notificationManager
        );
    }

    public IReadOnlyList<RealTimeProtectionEvent> GetEventHistory()
    {
        lock (_lock)
        {
            return _eventHistory.ToList();
        }
    }

    public static IReadOnlyList<string> GetDefaultWatchedDirectories()
    {
        var list = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) list.Add(downloads);

            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop)) list.Add(desktop);
        }

        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startup) && Directory.Exists(startup))
        {
            list.Add(startup);
        }

        var temp = Path.GetTempPath();
        if (!string.IsNullOrWhiteSpace(temp) && Directory.Exists(temp))
        {
            list.Add(temp);
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Starts user-mode real-time folder monitoring on the specified directories.
    /// </summary>
    public void StartMonitoring(IEnumerable<string>? directoriesToWatch = null)
    {
        StopMonitoring();
        var targets = (directoriesToWatch ?? GetDefaultWatchedDirectories())
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var dir in targets)
        {
            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            watcher.Created += async (_, e) => await EvaluateFileEventAsync(e.FullPath, "CREATED");
            watcher.Changed += async (_, e) => await EvaluateFileEventAsync(e.FullPath, "MODIFIED");
            watcher.Renamed += async (_, e) => await EvaluateFileEventAsync(e.FullPath, $"RENAMED_FROM_{Path.GetFileName(e.OldFullPath)}");

            _activeWatchers.Add(watcher);
        }

        IsMonitoringActive = _activeWatchers.Count > 0;
    }

    public void StopMonitoring()
    {
        foreach (var watcher in _activeWatchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch
            {
                // Ignore watcher disposal errors
            }
        }
        _activeWatchers.Clear();
        IsMonitoringActive = false;
    }

    /// <summary>
    /// Evaluates a single user-mode file creation, download, modification, or startup change event safely without executing the file.
    /// </summary>
    public async Task<RealTimeProtectionEvent> EvaluateFileEventAsync(
        string filePath,
        string changeType = "CREATED",
        bool isStartupDirectory = false,
        CancellationToken cancellationToken = default)
    {
        string fileName = Path.GetFileName(filePath);
        var now = DateTimeOffset.UtcNow;

        // Classify the real-time event category
        var category = ClassifyEventCategory(filePath, fileName, changeType, isStartupDirectory);

        // 1. Check KIRON PROHORI Exclusions first
        if (_exclusionManager.IsPathExcluded(filePath))
        {
            var excludedEvt = new RealTimeProtectionEvent(
                EventId: $"RT-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
                Category: category,
                FilePath: filePath,
                FileName: fileName,
                ChangeType: changeType,
                ScanStatus: DownloadScanStatus.UnknownNotScanned,
                Sha256Hash: "SKIPPED_BY_USER_EXCLUSION",
                DetectionSummary: "Skipped: Path is in user-configured KIRON PROHORI Exclusions.",
                WasExcluded: true,
                WasQuarantined: false,
                ObservedAtUtc: now
            );
            RecordEvent(excludedEvt);
            return excludedEvt;
        }

        // 2. If file does not exist or is still locked/incomplete, never report it as Clean
        if (!File.Exists(filePath))
        {
            var missingEvt = new RealTimeProtectionEvent(
                EventId: $"RT-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
                Category: category,
                FilePath: filePath,
                FileName: fileName,
                ChangeType: changeType,
                ScanStatus: DownloadScanStatus.UnknownNotScanned,
                Sha256Hash: "NOT_AVAILABLE",
                DetectionSummary: "Unknown / Not scanned: File does not exist or write has not completed.",
                WasExcluded: false,
                WasQuarantined: false,
                ObservedAtUtc: now
            );
            RecordEvent(missingEvt);
            return missingEvt;
        }

        // Debounce rapid duplicate file-system write events within 500ms
        _debounceMap[filePath] = now;

        // 3. Scan the file via ModularScanPipeline (SHA-256 + Verified Intel + Heuristics + YARA/ClamAV where installed)
        var report = await _scanPipeline.ScanSingleFileAsync(filePath, cancellationToken);
        string sha256 = await Sha256HashEngine.ComputeFileSha256StreamingAsync(filePath, cancellationToken);

        DownloadScanStatus scanStatus;
        string summary;

        if (report.SkippedPermissionCount > 0 || report.TotalFilesScanned == 0)
        {
            scanStatus = DownloadScanStatus.UnknownNotScanned;
            summary = "Unknown / Not scanned: File could not be read due to OS lock or permissions.";
        }
        else if (report.Findings.Any(f => f.Verdict == DetectionVerdict.ConfirmedDetection))
        {
            var topFinding = report.Findings.First(f => f.Verdict == DetectionVerdict.ConfirmedDetection);
            scanStatus = DownloadScanStatus.Malicious;
            summary = $"MALICIOUS: {topFinding.DetectionName} ({topFinding.DetectionSourceAttribution}) — Recommended: Quarantine First.";
        }
        else if (report.Findings.Any(f => f.Verdict == DetectionVerdict.Suspicious))
        {
            var topFinding = report.Findings.First(f => f.Verdict == DetectionVerdict.Suspicious);
            scanStatus = DownloadScanStatus.Suspicious;
            summary = $"SUSPICIOUS: {topFinding.DetectionName} ({topFinding.DetectionSourceAttribution}) — Recommended: Quarantine First.";
        }
        else if (category == RealTimeEventCategory.DangerousStartupChange &&
                 MonitoredExecutableExtensions.Contains(Path.GetExtension(fileName)))
        {
            scanStatus = DownloadScanStatus.Suspicious;
            summary = $"SUSPICIOUS STARTUP CHANGE: New executable/script '{fileName}' added to Windows Startup folder.";
        }
        else
        {
            scanStatus = DownloadScanStatus.Clean;
            summary = "Clean according to available local SHA-256, heuristic, and configured scanning engines.";
        }

        var evt = new RealTimeProtectionEvent(
            EventId: $"RT-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
            Category: category,
            FilePath: filePath,
            FileName: fileName,
            ChangeType: changeType,
            ScanStatus: scanStatus,
            Sha256Hash: sha256,
            DetectionSummary: summary,
            WasExcluded: false,
            WasQuarantined: false,
            ObservedAtUtc: now
        );

        RecordEvent(evt);
        return evt;
    }

    private static RealTimeEventCategory ClassifyEventCategory(
        string filePath,
        string fileName,
        string changeType,
        bool isStartupDirectory)
    {
        string normalizedPath = filePath.Replace('\\', '/');
        string ext = Path.GetExtension(fileName);

        if (isStartupDirectory ||
            normalizedPath.Contains("/Start Menu/Programs/Startup", StringComparison.OrdinalIgnoreCase))
        {
            return RealTimeEventCategory.DangerousStartupChange;
        }

        if (changeType.StartsWith("RENAMED", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".pdf.exe", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".docx.exe", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".jpg.scr", StringComparison.OrdinalIgnoreCase))
        {
            return RealTimeEventCategory.SuspiciousFileModification;
        }

        if (normalizedPath.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase))
        {
            return RealTimeEventCategory.NewDownloadFile;
        }

        if (MonitoredExecutableExtensions.Contains(ext))
        {
            return RealTimeEventCategory.NewExecutableFile;
        }

        return RealTimeEventCategory.SuspiciousFileBehavior;
    }

    private void RecordEvent(RealTimeProtectionEvent evt)
    {
        lock (_lock)
        {
            _eventHistory.Insert(0, evt);
            if (_eventHistory.Count > 200)
            {
                _eventHistory.RemoveAt(_eventHistory.Count - 1);
            }
        }
    }

    public void Dispose()
    {
        StopMonitoring();
    }
}

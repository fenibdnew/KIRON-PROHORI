using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Performance;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Coordinates multi-engine local scanning (Quick Scan, Full Scan, Custom Folder Scan, Single File Scan, USB Drive Scan).
/// Features:
/// - Strict ExclusionManager enforcement (never scans KIRON-excluded files or folders).
/// - Lightweight PerformanceProtectionGuard (Pause/Resume, CPU pacing, low background priority, unchanged file cache).
/// - SmartNotificationManager integration (deduplicated threat notification + single gentle chime).
/// - Four-tier DetectionVerdict (ConfirmedDetection, Suspicious, Unknown, CleanAccordingToAvailableEngines).
/// - Cooperative cancellation via CancellationToken and permission error resilience.
/// </summary>
public sealed class ModularScanPipeline
{
    private readonly List<IScanEngine> _engines = new();
    private readonly ExclusionManager _exclusionManager;
    private readonly PerformanceProtectionGuard _performanceGuard;
    private readonly SmartNotificationManager _notificationManager;
    private readonly long _maxSingleFileBytes;

    public ModularScanPipeline(
        IEnumerable<IScanEngine>? engines = null,
        ExclusionManager? exclusionManager = null,
        PerformanceProtectionGuard? performanceGuard = null,
        SmartNotificationManager? notificationManager = null,
        long maxSingleFileBytes = 256L * 1024L * 1024L)
    {
        _maxSingleFileBytes = maxSingleFileBytes;
        _exclusionManager = exclusionManager ?? new ExclusionManager();
        _performanceGuard = performanceGuard ?? new PerformanceProtectionGuard();
        _notificationManager = notificationManager ?? new SmartNotificationManager();

        if (engines != null)
        {
            _engines.AddRange(engines);
        }
        else
        {
            _engines.Add(new Sha256HashEngine());
            _engines.Add(new HeuristicSuspiciousFileEngine());
            _engines.Add(new ClamAvExternalEngine());
            _engines.Add(new YaraExternalEngine());
        }
    }

    public IReadOnlyList<IScanEngine> Engines => _engines;
    public ExclusionManager Exclusions => _exclusionManager;
    public PerformanceProtectionGuard PerformanceGuard => _performanceGuard;
    public SmartNotificationManager NotificationManager => _notificationManager;

    public IReadOnlyList<EngineDescriptor> GetEngineStatuses() =>
        _engines.Select(e => e.GetDescriptor()).ToList();

    public void PauseActiveScan() => _performanceGuard.PauseScan();
    public void ResumeActiveScan() => _performanceGuard.ResumeScan();

    /// <summary>
    /// Resolves default high-risk user-mode target folders for a Quick Scan (Downloads, Desktop, Startup, and %TEMP%).
    /// </summary>
    public static IReadOnlyList<string> GetQuickScanDirectories()
    {
        var dirs = new List<string>();
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            string downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) dirs.Add(downloads);
        }

        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop))
        {
            dirs.Add(desktop);
        }

        string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startup) && Directory.Exists(startup))
        {
            dirs.Add(startup);
        }

        string tempPath = Path.GetTempPath();
        if (!string.IsNullOrWhiteSpace(tempPath) && Directory.Exists(tempPath))
        {
            dirs.Add(tempPath);
        }

        return dirs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Enumerates mounted removable USB drives (DriveType.Removable).
    /// </summary>
    public static IReadOnlyList<DriveInfo> GetRemovableUsbDrives()
    {
        try
        {
            return DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                .ToList();
        }
        catch
        {
            return Array.Empty<DriveInfo>();
        }
    }

    private static readonly HashSet<string> ProtectedSystemVolumeFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "System Volume Information",
        "$RECYCLE.BIN",
        "RECYCLER",
        "FOUND.000",
        "Config.Msi",
        ".Trashes",
        ".Spotlight-V100",
        ".fseventsd"
    };

    /// <summary>
    /// Safe USB Shortcut Virus Remediation: Clears Hidden and System attributes on legitimate user folders
    /// inside a USB drive or directory that were hidden by USB shortcut (.lnk / autorun.inf / .vbs) worms.
    /// Never modifies protected OS volume folders.
    /// </summary>
    public static IReadOnlyList<string> RecoverHiddenUsbFolders(string driveOrDirectoryPath)
    {
        var recoveredFolders = new List<string>();
        if (string.IsNullOrWhiteSpace(driveOrDirectoryPath) || !Directory.Exists(driveOrDirectoryPath))
        {
            return recoveredFolders;
        }

        try
        {
            foreach (string subDir in Directory.EnumerateDirectories(driveOrDirectoryPath, "*", SearchOption.TopDirectoryOnly))
            {
                string folderName = Path.GetFileName(subDir);
                if (string.IsNullOrWhiteSpace(folderName) || ProtectedSystemVolumeFolders.Contains(folderName))
                {
                    continue;
                }

                try
                {
                    var dirInfo = new DirectoryInfo(subDir);
                    var attrs = dirInfo.Attributes;
                    bool isHiddenOrSystem = (attrs & (FileAttributes.Hidden | FileAttributes.System)) != 0;
                    if (isHiddenOrSystem)
                    {
                        dirInfo.Attributes = attrs & ~(FileAttributes.Hidden | FileAttributes.System);
                        recoveredFolders.Add(subDir);
                    }
                }
                catch
                {
                    // Skip individual locked or read-only directory smoothly
                }
            }
        }
        catch
        {
            // Non-fatal if drive was unplugged mid-operation
        }

        return recoveredFolders;
    }

    /// <summary>
    /// Parses Windows Explorer Right-Click Context Menu CLI arguments (e.g., --scan-path "E:\" or --minimized-tray).
    /// </summary>
    public static (string? ScanTargetPath, bool StartMinimizedToTray) ParseCliScanPathArguments(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0)
        {
            return (null, false);
        }

        string? scanPath = null;
        bool minimized = false;

        for (int i = 0; i < args.Count; i++)
        {
            string current = args[i]?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(current))
            {
                continue;
            }

            if (current.Equals("--minimized-tray", StringComparison.OrdinalIgnoreCase))
            {
                minimized = true;
                continue;
            }

            if (current.Equals("--scan-path", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count)
            {
                string rawTarget = args[i + 1]?.Trim().Trim('"') ?? string.Empty;
                // Handle Windows Explorer trailing backslash quote escaping (e.g. "E:\"")
                if (rawTarget.Length == 2 && rawTarget[1] == ':')
                {
                    rawTarget += Path.DirectorySeparatorChar;
                }
                if (!string.IsNullOrWhiteSpace(rawTarget))
                {
                    scanPath = rawTarget;
                }
                i++;
                continue;
            }

            if (current.StartsWith("--scan-path=", StringComparison.OrdinalIgnoreCase))
            {
                string rawTarget = current["--scan-path=".Length..].Trim().Trim('"');
                if (!string.IsNullOrWhiteSpace(rawTarget))
                {
                    scanPath = rawTarget;
                }
            }
        }

        return (scanPath, minimized);
    }

    /// <summary>
    /// Scans a single file across all active engines while respecting KIRON exclusions and performance guards.
    /// </summary>
    public async Task<ScanReport> ScanSingleFileAsync(
        string filePath,
        IProgress<ScanProgressUpdate>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();
        var findings = new List<ScanFinding>();
        var warnings = new List<string>();
        int skippedPermissions = 0;
        int skippedExclusions = 0;
        int skippedUnchanged = 0;
        long bytesScanned = 0;
        int filesScanned = 0;
        string status = "COMPLETED";

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _performanceGuard.WaitForPauseAndThrottleAsync(cancellationToken).ConfigureAwait(false);

            if (_exclusionManager.IsPathExcluded(filePath))
            {
                skippedExclusions = 1;
                warnings.Add($"Skipped KIRON-excluded path: '{filePath}'");
            }
            else if (!File.Exists(filePath))
            {
                warnings.Add($"Target file does not exist or is inaccessible: '{filePath}'");
                skippedPermissions = 1;
                status = "COMPLETED_WITH_PERMISSION_WARNINGS";
            }
            else
            {
                var info = new FileInfo(filePath);
                if (_performanceGuard.CanSkipUnchangedCleanFile(info))
                {
                    skippedUnchanged = 1;
                }
                else
                {
                    bytesScanned = info.Length;
                    string sha256 = await Sha256HashEngine.ComputeFileSha256Async(
                        filePath,
                        cancellationToken,
                        progress,
                        ScanType.SingleFileScan).ConfigureAwait(false);
                    filesScanned = 1;

                    foreach (var engine in _engines)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var rawFinding = await engine.ScanFileAsync(filePath, sha256, info.Length, cancellationToken).ConfigureAwait(false);
                        if (rawFinding != null)
                        {
                            var classified = ClassifyFindingVerdict(rawFinding);
                            findings.Add(classified);
                            _notificationManager.TryNotifyDetection(classified);
                        }
                    }

                    if (findings.Count == 0)
                    {
                        _performanceGuard.RecordCleanFile(info);
                    }
                }

                progress?.Report(new ScanProgressUpdate(
                    ScanType.SingleFileScan,
                    filePath,
                    filesScanned,
                    findings.Count,
                    skippedPermissions,
                    bytesScanned,
                    sw.Elapsed.TotalSeconds,
                    _performanceGuard.IsPaused,
                    skippedUnchanged,
                    skippedExclusions));
            }
        }
        catch (OperationCanceledException)
        {
            status = "CANCELLED_BY_USER";
            warnings.Add("Scan was cancelled by user request.");
        }
        catch (UnauthorizedAccessException ex)
        {
            skippedPermissions++;
            status = "COMPLETED_WITH_PERMISSION_WARNINGS";
            warnings.Add($"Permission denied while reading '{filePath}': {ex.Message}");
        }
        catch (IOException ex)
        {
            skippedPermissions++;
            status = "COMPLETED_WITH_PERMISSION_WARNINGS";
            warnings.Add($"File locked or I/O error on '{filePath}': {ex.Message}");
        }

        sw.Stop();
        return BuildReport(
            ScanType.SingleFileScan,
            filePath,
            status,
            startedAt,
            sw.Elapsed.TotalSeconds,
            filesScanned,
            bytesScanned,
            skippedPermissions,
            skippedExclusions,
            skippedUnchanged,
            findings,
            warnings);
    }

    /// <summary>
    /// Scans one or more directories (Quick Scan, Custom Folder Scan, USB Drive Scan, or Full Scan).
    /// </summary>
    public async Task<ScanReport> ScanDirectoriesAsync(
        ScanType scanType,
        IEnumerable<string> rootDirectories,
        IProgress<ScanProgressUpdate>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();
        var findings = new List<ScanFinding>();
        var warnings = new List<string>();
        int filesScanned = 0;
        long bytesScanned = 0;
        int skippedPermissions = 0;
        int skippedExclusions = 0;
        int skippedUnchanged = 0;
        string status = "COMPLETED";

        var roots = rootDirectories.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
        string targetScope = roots.Count > 0 ? string.Join("; ", roots) : "(No directories specified)";

        PerformanceProtectionGuard.TrySetBackgroundLowPriority(true);
        try
        {
            var pendingDirs = new Stack<string>(roots);

            while (pendingDirs.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _performanceGuard.WaitForPauseAndThrottleAsync(cancellationToken).ConfigureAwait(false);

                string currentDir = pendingDirs.Pop();

                if (_exclusionManager.IsPathExcluded(currentDir))
                {
                    skippedExclusions++;
                    continue;
                }

                if (!Directory.Exists(currentDir))
                {
                    skippedPermissions++;
                    warnings.Add($"Directory not found or inaccessible: '{currentDir}'");
                    continue;
                }

                // Skip NTFS reparse points / symlink loops
                try
                {
                    var dirInfo = new DirectoryInfo(currentDir);
                    if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    skippedPermissions++;
                    continue;
                }

                // Enqueue subdirectories safely
                try
                {
                    foreach (string subDir in Directory.EnumerateDirectories(currentDir))
                    {
                        pendingDirs.Push(subDir);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    skippedPermissions++;
                }
                catch (IOException)
                {
                    skippedPermissions++;
                }

                IEnumerable<string> filesInDir;
                try
                {
                    filesInDir = Directory.EnumerateFiles(currentDir);
                }
                catch (UnauthorizedAccessException)
                {
                    skippedPermissions++;
                    continue;
                }
                catch (IOException)
                {
                    skippedPermissions++;
                    continue;
                }

                foreach (string filePath in filesInDir)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await _performanceGuard.WaitForPauseAndThrottleAsync(cancellationToken).ConfigureAwait(false);

                    if (_exclusionManager.IsPathExcluded(filePath))
                    {
                        skippedExclusions++;
                        continue;
                    }

                    try
                    {
                        var fileInfo = new FileInfo(filePath);
                        if (!fileInfo.Exists || (fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            continue;
                        }

                        if (_performanceGuard.CanSkipUnchangedCleanFile(fileInfo))
                        {
                            skippedUnchanged++;
                            continue;
                        }

                        if (fileInfo.Length > _maxSingleFileBytes)
                        {
                            warnings.Add($"Skipped oversized file (> {_maxSingleFileBytes / (1024 * 1024)} MB): '{filePath}'");
                            continue;
                        }

                        string sha256 = await Sha256HashEngine.ComputeFileSha256Async(filePath, cancellationToken).ConfigureAwait(false);
                        filesScanned++;
                        bytesScanned += fileInfo.Length;
                        int fileFindingsCount = 0;

                        foreach (var engine in _engines)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            var rawFinding = await engine.ScanFileAsync(filePath, sha256, fileInfo.Length, cancellationToken).ConfigureAwait(false);
                            if (rawFinding != null)
                            {
                                var classified = ClassifyFindingVerdict(rawFinding);
                                findings.Add(classified);
                                fileFindingsCount++;
                                _notificationManager.TryNotifyDetection(classified);
                            }
                        }

                        if (fileFindingsCount == 0)
                        {
                            _performanceGuard.RecordCleanFile(fileInfo);
                        }

                        progress?.Report(new ScanProgressUpdate(
                            scanType,
                            filePath,
                            filesScanned,
                            findings.Count,
                            skippedPermissions,
                            bytesScanned,
                            sw.Elapsed.TotalSeconds,
                            _performanceGuard.IsPaused,
                            skippedUnchanged,
                            skippedExclusions));

                        // For QuickScan, cap total files inspected across Downloads, Desktop, Startup, and %TEMP% at 250 files so it completes briskly while streaming real live progress
                        if (scanType == ScanType.QuickScan && filesScanned >= 250)
                        {
                            pendingDirs.Clear();
                            break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        skippedPermissions++;
                    }
                    catch (IOException)
                    {
                        skippedPermissions++;
                    }
                }
            }

            if (skippedPermissions > 0 && status == "COMPLETED")
            {
                status = "COMPLETED_WITH_PERMISSION_WARNINGS";
            }
        }
        catch (OperationCanceledException)
        {
            status = "CANCELLED_BY_USER";
            warnings.Add($"Scan cancelled by user after inspecting {filesScanned} file(s).");
        }
        finally
        {
            PerformanceProtectionGuard.TrySetBackgroundLowPriority(false);
        }

        sw.Stop();
        return BuildReport(
            scanType,
            targetScope,
            status,
            startedAt,
            sw.Elapsed.TotalSeconds,
            filesScanned,
            bytesScanned,
            skippedPermissions,
            skippedExclusions,
            skippedUnchanged,
            findings,
            warnings);
    }

    private static ScanFinding ClassifyFindingVerdict(ScanFinding raw)
    {
        var verdict = raw.Confidence == DetectionConfidence.VerifiedSignature
            ? DetectionVerdict.ConfirmedDetection
            : raw.Confidence == DetectionConfidence.HeuristicSuspicious
                ? DetectionVerdict.Suspicious
                : DetectionVerdict.Unknown;

        return raw with
        {
            Verdict = verdict,
            RecommendedAction = RemediationAction.Quarantine
        };
    }

    private ScanReport BuildReport(
        ScanType scanType,
        string targetScope,
        string status,
        DateTimeOffset startedAt,
        double durationSeconds,
        int filesScanned,
        long bytesScanned,
        int skippedPermissions,
        int skippedExclusions,
        int skippedUnchanged,
        IReadOnlyList<ScanFinding> findings,
        IReadOnlyList<string> warnings)
    {
        int verifiedThreats = findings.Count(f => f.Verdict == DetectionVerdict.ConfirmedDetection);
        int heuristics = findings.Count(f => f.Verdict == DetectionVerdict.Suspicious);
        var activeEngines = _engines
            .Select(e => e.GetDescriptor())
            .Where(d => d.Status == EngineStatus.Ready)
            .Select(d => d.EngineId)
            .ToList();

        return new ScanReport(
            ReportId: $"SCAN-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..24].ToUpperInvariant(),
            ScanType: scanType,
            TargetScope: targetScope,
            Status: status,
            StartedAtUtc: startedAt,
            CompletedAtUtc: DateTimeOffset.UtcNow,
            DurationSeconds: Math.Round(durationSeconds, 3),
            TotalFilesScanned: filesScanned,
            TotalBytesScanned: bytesScanned,
            ThreatsDetectedCount: verifiedThreats,
            SuspiciousHeuristicCount: heuristics,
            SkippedPermissionCount: skippedPermissions,
            Findings: findings,
            ActiveEnginesUsed: activeEngines,
            NonFatalWarnings: warnings,
            SkippedExcludedCount: skippedExclusions,
            SkippedUnchangedCount: skippedUnchanged
        );
    }
}

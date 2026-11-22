using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Coordinates multi-engine local scanning (Quick Scan, Full Scan, Custom Folder Scan, Single File Scan, USB Drive Scan).
/// Features:
/// - Cooperative cancellation via CancellationToken
/// - Real-time progress reporting via IProgress&lt;ScanProgressUpdate&gt;
/// - Reparse-point / symlink loop prevention
/// - Graceful handling of UnauthorizedAccessException and locked system files without crashing
/// </summary>
public sealed class ModularScanPipeline
{
    private readonly List<IScanEngine> _engines = new();
    private readonly long _maxSingleFileBytes;

    public ModularScanPipeline(IEnumerable<IScanEngine>? engines = null, long maxSingleFileBytes = 256L * 1024L * 1024L)
    {
        _maxSingleFileBytes = maxSingleFileBytes;
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

    public IReadOnlyList<EngineDescriptor> GetEngineStatuses() =>
        _engines.Select(e => e.GetDescriptor()).ToList();

    /// <summary>
    /// Resolves default high-risk user-mode target folders for a Quick Scan.
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

        string tempPath = Path.GetTempPath();
        if (!string.IsNullOrWhiteSpace(tempPath) && Directory.Exists(tempPath))
        {
            dirs.Add(tempPath);
        }

        string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startup) && Directory.Exists(startup))
        {
            dirs.Add(startup);
        }

        return dirs;
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

    /// <summary>
    /// Scans a single file across all active engines.
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
        long bytesScanned = 0;
        int filesScanned = 0;
        string status = "COMPLETED";

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!File.Exists(filePath))
            {
                warnings.Add($"Target file does not exist or is inaccessible: '{filePath}'");
                skippedPermissions = 1;
                status = "COMPLETED_WITH_PERMISSION_WARNINGS";
            }
            else
            {
                var info = new FileInfo(filePath);
                bytesScanned = info.Length;
                string sha256 = await Sha256HashEngine.ComputeFileSha256Async(filePath, cancellationToken).ConfigureAwait(false);
                filesScanned = 1;

                foreach (var engine in _engines)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var finding = await engine.ScanFileAsync(filePath, sha256, info.Length, cancellationToken).ConfigureAwait(false);
                    if (finding != null)
                    {
                        findings.Add(finding);
                    }
                }

                progress?.Report(new ScanProgressUpdate(
                    ScanType.SingleFileScan,
                    filePath,
                    filesScanned,
                    findings.Count,
                    skippedPermissions,
                    bytesScanned,
                    sw.Elapsed.TotalSeconds));
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
        string status = "COMPLETED";

        var roots = rootDirectories.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
        string targetScope = roots.Count > 0 ? string.Join("; ", roots) : "(No directories specified)";

        try
        {
            var pendingDirs = new Stack<string>(roots);

            while (pendingDirs.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string currentDir = pendingDirs.Pop();

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

                // Enumerate files in currentDir
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

                    try
                    {
                        var fileInfo = new FileInfo(filePath);
                        if (!fileInfo.Exists || (fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                        {
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

                        foreach (var engine in _engines)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            var finding = await engine.ScanFileAsync(filePath, sha256, fileInfo.Length, cancellationToken).ConfigureAwait(false);
                            if (finding != null)
                            {
                                findings.Add(finding);
                            }
                        }

                        progress?.Report(new ScanProgressUpdate(
                            scanType,
                            filePath,
                            filesScanned,
                            findings.Count,
                            skippedPermissions,
                            bytesScanned,
                            sw.Elapsed.TotalSeconds));
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
            findings,
            warnings);
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
        IReadOnlyList<ScanFinding> findings,
        IReadOnlyList<string> warnings)
    {
        int verifiedThreats = findings.Count(f => f.Confidence == DetectionConfidence.VerifiedSignature);
        int heuristics = findings.Count(f => f.Confidence == DetectionConfidence.HeuristicSuspicious);
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
            NonFatalWarnings: warnings
        );
    }
}

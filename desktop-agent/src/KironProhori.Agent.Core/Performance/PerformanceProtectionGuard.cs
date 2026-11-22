using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Performance;

/// <summary>
/// Lightweight Performance Protection &amp; Resource Throttle Guard.
/// Features:
/// - Low CPU priority during background scans (ProcessPriorityClass.BelowNormal).
/// - Configurable CPU usage limit &amp; adjustable scan speed (LowImpact, Balanced, HighSpeed).
/// - Unchanged clean file cache (avoids repeatedly scanning unchanged files with identical path, size, and LastWriteTimeUtc).
/// - Cooperative Pause / Resume / Stop support.
/// - Respects laptop battery / power saver states by automatically increasing inter-file pacing.
/// - Never promises zero performance impact; optimizes to avoid unnecessary disk and CPU spikes.
/// </summary>
public sealed class PerformanceProtectionGuard
{
    private readonly ConcurrentDictionary<string, (long Length, DateTime LastWriteUtc, string SignatureEpoch)> _cleanFileCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ManualResetEventSlim _pauseGate = new(initialState: true); // Set = running, Reset = paused

    public ScanThrottleProfile CurrentProfile { get; set; } = ScanThrottleProfile.BalancedDefault;
    public int MaxCpuLimitPercent { get; set; } = 35;
    public int MaxConcurrentFiles { get; set; } = 1;
    public bool RespectBatteryPower { get; set; } = true;
    public bool EnableUnchangedFileCache { get; set; } = true;
    public bool IsOnBatteryPowerSimulated { get; set; } = false;
    public bool IsSystemUnderHeavyLoadSimulated { get; set; } = false;
    public string CurrentSignatureEpoch { get; set; } = "v0.7.0-phase7a";

    public bool IsPaused => !_pauseGate.IsSet;
    public int CachedCleanFileCount => _cleanFileCache.Count;

    /// <summary>
    /// Pauses an active scan without losing progress.
    /// </summary>
    public void PauseScan() => _pauseGate.Reset();

    /// <summary>
    /// Resumes a paused scan.
    /// </summary>
    public void ResumeScan() => _pauseGate.Set();

    /// <summary>
    /// Sets current process priority to BelowNormal during background scans and restores Normal when complete.
    /// </summary>
    public static void TrySetBackgroundLowPriority(bool enableLowPriority)
    {
        try
        {
            using var currentProcess = Process.GetCurrentProcess();
            currentProcess.PriorityClass = enableLowPriority
                ? ProcessPriorityClass.BelowNormal
                : ProcessPriorityClass.Normal;
        }
        catch
        {
            // Ignore if OS restricts priority adjustment
        }
    }

    /// <summary>
    /// Waits if the scan is paused by the user, and applies adaptive CPU/battery pacing between files.
    /// </summary>
    public async Task WaitForPauseAndThrottleAsync(CancellationToken cancellationToken)
    {
        while (!_pauseGate.IsSet)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }

        int delayMs = CurrentProfile switch
        {
            ScanThrottleProfile.LowImpactBackground => 8,
            ScanThrottleProfile.BalancedDefault => 2,
            ScanThrottleProfile.HighSpeedForeground => 0,
            _ => 2
        };

        if ((RespectBatteryPower && IsOnBatteryPowerSimulated) || IsSystemUnderHeavyLoadSimulated)
        {
            delayMs = Math.Max(delayMs, 15);
        }

        if (delayMs > 0)
        {
            await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Checks whether a clean file is unchanged since the last scan under the same signature epoch.
    /// </summary>
    public bool CanSkipUnchangedCleanFile(FileInfo fileInfo)
    {
        if (!EnableUnchangedFileCache) return false;

        if (_cleanFileCache.TryGetValue(fileInfo.FullName, out var cached))
        {
            return cached.Length == fileInfo.Length &&
                   cached.LastWriteUtc == fileInfo.LastWriteTimeUtc &&
                   cached.SignatureEpoch == CurrentSignatureEpoch;
        }
        return false;
    }

    public void RecordCleanFile(FileInfo fileInfo)
    {
        if (!EnableUnchangedFileCache) return;
        _cleanFileCache[fileInfo.FullName] = (fileInfo.Length, fileInfo.LastWriteTimeUtc, CurrentSignatureEpoch);
    }

    public void InvalidateCacheForNewSignatures(string newSignatureEpoch)
    {
        CurrentSignatureEpoch = newSignatureEpoch;
        _cleanFileCache.Clear();
    }
}

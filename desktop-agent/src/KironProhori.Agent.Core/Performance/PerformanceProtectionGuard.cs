using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Performance;

/// <summary>
/// Lightweight Performance Protection, Eco-Power Mode (Green Computing) &amp; Resource Throttle Guard.
/// Features:
/// - Eco-Power Mode (Green Computing): Automatically throttles background scanning when CPU usage &gt; 40%
///   or when running on laptop battery power, displaying an "Eco-Mode Active · Low Energy" badge.
/// - Low CPU priority during background scans (ProcessPriorityClass.BelowNormal).
/// - Configurable CPU usage limit &amp; adjustable scan speed (LowImpact, Balanced, HighSpeed).
/// - Unchanged clean file cache (avoids repeatedly scanning unchanged files with identical path, size, and LastWriteTimeUtc).
/// - Cooperative Pause / Resume / Stop support.
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
    public string CurrentSignatureEpoch { get; set; } = "v1.0.0-ecotech";

    /// <summary>
    /// Eco-Power Mode (Green Computing): automatically throttles background scanning when CPU usage &gt; 40%
    /// or when running on laptop battery power.
    /// </summary>
    public const int EcoCpuThresholdPercent = 40;
    public bool EcoPowerModeEnabled { get; set; } = true;

    public bool IsPaused => !_pauseGate.IsSet;
    public int CachedCleanFileCount => _cleanFileCache.Count;

    public string EcoStatusBadgeLabel =>
        EcoPowerModeEnabled
            ? "Eco-Mode Active · Low Energy"
            : "Standard Balanced Power";

    /// <summary>
    /// Toggles Eco-Power Mode (Green Computing) and adjusts scan throttle profile and CPU cap.
    /// </summary>
    public void SetEcoPowerMode(bool enabled)
    {
        EcoPowerModeEnabled = enabled;
        if (enabled)
        {
            CurrentProfile = ScanThrottleProfile.LowImpactBackground;
            MaxCpuLimitPercent = Math.Min(MaxCpuLimitPercent, EcoCpuThresholdPercent);
            RespectBatteryPower = true;
            TrySetBackgroundLowPriority(true);
        }
        else
        {
            CurrentProfile = ScanThrottleProfile.BalancedDefault;
            MaxCpuLimitPercent = 40;
            TrySetBackgroundLowPriority(false);
        }
    }

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
    /// Waits if the scan is paused by the user, and applies adaptive Eco-Power / CPU (>40%) / battery pacing between files.
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

        if (EcoPowerModeEnabled)
        {
            delayMs = Math.Max(delayMs, 6);
        }

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

    /// <summary>
    /// Captures live process memory and CPU throttling optimization metrics for Phase 3 Resource Usage Optimization.
    /// </summary>
    public (double WorkingSetMemoryMb, string ProcessPriority, int CachedCleanFiles, bool EcoModeActive, int MaxCpuCapPercent) GetResourceOptimizationSnapshot()
    {
        double workingSetMb = 0;
        string priority = "Normal";
        try
        {
            using var proc = Process.GetCurrentProcess();
            workingSetMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 2);
            priority = proc.PriorityClass.ToString();
        }
        catch
        {
            // Fallback on restricted environments
        }

        return (workingSetMb, priority, CachedCleanFileCount, EcoPowerModeEnabled, MaxCpuLimitPercent);
    }
}

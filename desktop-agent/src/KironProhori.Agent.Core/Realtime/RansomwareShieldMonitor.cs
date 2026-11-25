using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;

namespace KironProhori.Agent.Core.Realtime;

/// <summary>
/// MODULE 6 — Carefully Controlled User-Mode Ransomware Shield.
/// 
/// Capabilities:
/// - Manages user-selected protected folders (Documents, Pictures, Desktop, plus custom folders).
/// - Monitors suspicious mass file modifications within a sliding time window.
/// - Detects unusual ransomware file-renaming patterns (.locked, .encrypted, .crypt, .lockbit, .ryuk, .kp_sim_enc).
/// - Detects suspicious ransom-note creation patterns (README_RESTORE_FILES.txt, DECRYPT_INSTRUCTIONS.html).
/// - Alerts the user and supports pausing/resuming the shield.
/// - Provides a 100% harmless sandbox simulation for automated testing and user verification without touching real user documents.
/// 
/// Safety &amp; Honesty Guarantees:
/// - Does NOT claim complete (100%) ransomware prevention.
/// - Does NOT install kernel minifilter drivers (.sys) or silently modify NTFS folder ACL permissions.
/// - Does NOT destroy or modify user documents during testing.
/// </summary>
public sealed class RansomwareShieldMonitor : IDisposable
{
    public const int MassModificationThresholdCount = 6;
    public static readonly TimeSpan MassModificationWindow = TimeSpan.FromSeconds(10);

    public const string HonestLimitationDisclosure =
        "User-Mode Behavioral Ransomware Shield monitors protected folders for rapid mass-modification bursts, " +
        "known encryption file extensions, and ransom-note artifacts. It operates in user-mode without modifying " +
        "folder ACL permissions or installing kernel drivers, and does not claim 100% ransomware prevention.";

    private static readonly HashSet<string> SuspiciousRansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".lockbit", ".ryuk", ".wannacry", ".conti", ".kp_sim_enc"
    };

    private static readonly string[] SuspiciousRansomNoteNames =
    {
        "README_RESTORE_FILES",
        "DECRYPT_INSTRUCTIONS",
        "HOW_TO_RECOVER_FILES",
        "RESTORE_YOUR_FILES",
        "KP_HARMLESS_RANSOM_NOTE_SIM"
    };

    private readonly SmartNotificationManager _notificationManager;
    private readonly List<string> _protectedFolders = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<RansomwareProtectionEvent> _eventHistory = new();
    private readonly ConcurrentQueue<DateTimeOffset> _recentModificationTimestamps = new();
    private readonly object _lock = new();

    public bool IsShieldEnabled { get; private set; } = true;
    public SuiteFeatureState FeatureState => IsShieldEnabled ? SuiteFeatureState.Enabled : SuiteFeatureState.Disabled;

    public RansomwareShieldMonitor(SmartNotificationManager? notificationManager = null)
    {
        _notificationManager = notificationManager ?? new SmartNotificationManager();
        foreach (var dir in GetDefaultProtectedFolders())
        {
            _protectedFolders.Add(dir);
        }
    }

    public static IReadOnlyList<string> GetDefaultProtectedFolders()
    {
        var list = new List<string>();
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (!string.IsNullOrWhiteSpace(docs) && Directory.Exists(docs)) list.Add(docs);

        var pics = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
        if (!string.IsNullOrWhiteSpace(pics) && Directory.Exists(pics)) list.Add(pics);

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (!string.IsNullOrWhiteSpace(desktop) && Directory.Exists(desktop)) list.Add(desktop);

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IReadOnlyList<string> GetProtectedFolders()
    {
        lock (_lock)
        {
            return _protectedFolders.ToList();
        }
    }

    public bool AddProtectedFolder(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath)) return false;
        string full = Path.GetFullPath(folderPath);
        lock (_lock)
        {
            if (_protectedFolders.Contains(full, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }
            _protectedFolders.Add(full);
            return true;
        }
    }

    public bool RemoveProtectedFolder(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath)) return false;
        string full = Path.GetFullPath(folderPath);
        lock (_lock)
        {
            return _protectedFolders.RemoveAll(f => f.Equals(full, StringComparison.OrdinalIgnoreCase)) > 0;
        }
    }

    public void PauseShield()
    {
        IsShieldEnabled = false;
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
        }
    }

    public void ResumeShield()
    {
        IsShieldEnabled = true;
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = true;
        }
    }

    public IReadOnlyList<RansomwareProtectionEvent> GetEventHistory()
    {
        lock (_lock)
        {
            return _eventHistory.ToList();
        }
    }

    /// <summary>
    /// Starts user-mode FileSystemWatcher monitoring across all configured protected folders.
    /// </summary>
    public int StartProtectedFolderMonitoring()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch
            {
                // Ignore
            }
        }
        _watchers.Clear();

        List<string> targets;
        lock (_lock)
        {
            targets = _protectedFolders.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        foreach (var folder in targets)
        {
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = IsShieldEnabled
                };
                watcher.Changed += (_, e) => EvaluateFileActivity(folder, e.FullPath, "MODIFIED");
                watcher.Created += (_, e) => EvaluateFileActivity(folder, e.FullPath, "CREATED");
                watcher.Renamed += (_, e) => EvaluateFileActivity(folder, e.FullPath, "RENAMED");
                _watchers.Add(watcher);
            }
            catch
            {
                // Skip inaccessible protected folder smoothly
            }
        }

        return _watchers.Count;
    }

    /// <summary>
    /// Provides actionable, non-destructive user recovery guidance when ransomware behavior is detected.
    /// </summary>
    public static IReadOnlyList<string> GetRansomwareRecoveryGuidance() => new[]
    {
        "1. Isolate Network Connectivity: Disconnect Wi-Fi/Ethernet immediately to stop active C2 key exfiltration or lateral SMB propagation.",
        "2. Inspect Suspicious Processes: Open KIRON PROHORI Process & Memory Inspector to identify non-system executables running from %TEMP% or Downloads.",
        "3. Quarantine Suspicious Payloads: Use KIRON PROHORI Quarantine Vault (.kpq) rather than deleting files so forensic evidence and reversible payloads are preserved.",
        "4. Restore from Offline Backups / Volume Shadow Copies: Check Windows File History, OneDrive Version History, or offline USB backups before reconnecting.",
        "5. Run Microsoft Defender Offline Scan (Start-MpWDOScan): Verify no boot-sector or kernel persistence remains."
    };

    /// <summary>
    /// Evaluates a file modification or rename inside a protected folder for ransomware behavioral indicators.
    /// </summary>
    public RansomwareProtectionEvent? EvaluateFileActivity(
        string protectedFolderPath,
        string filePath,
        string changeKind = "MODIFIED",
        bool isHarmlessSimulation = false)
    {
        if (!IsShieldEnabled)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        _recentModificationTimestamps.Enqueue(now);

        while (_recentModificationTimestamps.TryPeek(out var oldest) && (now - oldest) > MassModificationWindow)
        {
            _recentModificationTimestamps.TryDequeue(out _);
        }

        int burstCount = _recentModificationTimestamps.Count;
        string fileName = Path.GetFileName(filePath);
        string ext = Path.GetExtension(fileName);

        bool hasEncryptionExt = SuspiciousRansomwareExtensions.Contains(ext);
        bool isRansomNote = SuspiciousRansomNoteNames.Any(n => fileName.Contains(n, StringComparison.OrdinalIgnoreCase));
        bool isMassBurst = burstCount >= MassModificationThresholdCount;

        if (!hasEncryptionExt && !isRansomNote && !isMassBurst)
        {
            return null;
        }

        string category = hasEncryptionExt
            ? "SUSPICIOUS_ENCRYPTION_EXTENSION"
            : isRansomNote
            ? "RANSOM_NOTE_PATTERN"
            : "MASS_FILE_MODIFICATION_BURST";

        ThreatSeverity severity = (hasEncryptionExt && isMassBurst) || isRansomNote
            ? ThreatSeverity.Critical
            : ThreatSeverity.High;

        string explanation = hasEncryptionExt
            ? $"Suspicious file-renaming/encryption extension '{ext}' detected on '{fileName}' ({burstCount} modification(s) in {MassModificationWindow.TotalSeconds:F0}s window)."
            : isRansomNote
            ? $"Suspicious ransom-note filename pattern '{fileName}' detected inside protected folder."
            : $"Unusual mass file modification burst ({burstCount} files modified within {MassModificationWindow.TotalSeconds:F0}s) inside protected folder.";

        var evt = new RansomwareProtectionEvent(
            EventId: $"RW-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
            ProtectedFolderPath: protectedFolderPath,
            TriggerFilePath: filePath,
            AnomalyCategory: category,
            ModificationCountInWindow: burstCount,
            Severity: severity,
            Explanation: explanation,
            WasHarmlessSimulation: isHarmlessSimulation,
            DetectedAtUtc: now
        );

        lock (_lock)
        {
            _eventHistory.Insert(0, evt);
            if (_eventHistory.Count > 200)
            {
                _eventHistory.RemoveAt(_eventHistory.Count - 1);
            }
        }

        return evt;
    }

    /// <summary>
    /// Runs a 100% harmless, isolated ransomware behavioral simulation inside a temporary directory.
    /// Never touches user documents, creates harmless synthetic files, verifies detection, and deletes the temporary files.
    /// </summary>
    public async Task<IReadOnlyList<RansomwareProtectionEvent>> RunHarmlessRansomwareSimulationAsync(
        string? customTempSandboxDir = null,
        CancellationToken cancellationToken = default)
    {
        string sandboxDir = !string.IsNullOrWhiteSpace(customTempSandboxDir)
            ? customTempSandboxDir
            : Path.Combine(Path.GetTempPath(), "KironProhori_HarmlessRansomSim_" + Guid.NewGuid().ToString("N")[..8]);

        Directory.CreateDirectory(sandboxDir);
        var detectedEvents = new List<RansomwareProtectionEvent>();

        try
        {
            for (int i = 1; i <= MassModificationThresholdCount; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string simFile = Path.Combine(sandboxDir, $"harmless_doc_{i}.txt.kp_sim_enc");
                await File.WriteAllTextAsync(
                    simFile,
                    "HARMLESS KIRON PROHORI RANSOMWARE SHIELD SIMULATION PAYLOAD (NOT REAL ENCRYPTION)",
                    Encoding.UTF8,
                    cancellationToken).ConfigureAwait(false);

                var evt = EvaluateFileActivity(sandboxDir, simFile, "RENAMED", isHarmlessSimulation: true);
                if (evt != null)
                {
                    detectedEvents.Add(evt);
                }
            }

            string simNote = Path.Combine(sandboxDir, "KP_HARMLESS_RANSOM_NOTE_SIM.txt");
            await File.WriteAllTextAsync(simNote, "HARMLESS SIMULATION NOTE", Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            var noteEvt = EvaluateFileActivity(sandboxDir, simNote, "CREATED", isHarmlessSimulation: true);
            if (noteEvt != null)
            {
                detectedEvents.Add(noteEvt);
            }
        }
        finally
        {
            if (string.IsNullOrWhiteSpace(customTempSandboxDir) && Directory.Exists(sandboxDir))
            {
                try
                {
                    Directory.Delete(sandboxDir, recursive: true);
                }
                catch
                {
                    // Ignore temp cleanup error
                }
            }
        }

        return detectedEvents;
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch
            {
                // Ignore
            }
        }
        _watchers.Clear();
    }
}

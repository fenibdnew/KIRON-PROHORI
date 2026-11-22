using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Notifications;

/// <summary>
/// Smart Windows Notification &amp; Gentle Acoustic Alert System.
/// Features:
/// - Notification title is always "KIRON PROHORI".
/// - Displays Threat Name, File Location, Detection Source, and Recommended Action ("Quarantine").
/// - Synthesizes a short, original, gentle 2-note harmonic chime (A4 440Hz -> D5 587.33Hz) in a 16-bit PCM WAV buffer.
/// - Plays at most once per unique detection event (anti-spam deduplication by SHA256 + FilePath).
/// - Configurable Sound On/Off toggle and Volume (0% - 100%).
/// </summary>
public sealed class SmartNotificationManager
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _deduplicationMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SmartNotificationEvent> _history = new();
    private readonly object _lock = new();

    public bool SoundEnabled { get; set; } = true;
    public int VolumePercent { get; set; } = 65; // Default gentle volume (0..100)
    public TimeSpan DeduplicationWindow { get; set; } = TimeSpan.FromMinutes(10);

    public IReadOnlyList<SmartNotificationEvent> GetNotificationHistory()
    {
        lock (_lock)
        {
            return _history.ToList();
        }
    }

    public static readonly IReadOnlyList<string> StandardNotificationActions = new[]
    {
        "View Details",
        "Open Quarantine",
        "Restore (with warning)",
        "Report False Positive"
    };

    /// <summary>
    /// Creates a compact threat notification if not a duplicate within the cooldown window.
    /// Returns null if suppressed as a duplicate notification.
    /// </summary>
    public SmartNotificationEvent? TryNotifyDetection(ScanFinding finding)
    {
        string dedupKey = $"{finding.Sha256Hash}|{finding.FilePath}";
        var now = DateTimeOffset.UtcNow;

        if (_deduplicationMap.TryGetValue(dedupKey, out var lastNotified) &&
            (now - lastNotified) < DeduplicationWindow)
        {
            // Suppress duplicate notification spam
            return null;
        }

        _deduplicationMap[dedupKey] = now;
        int clampedVolume = Math.Clamp(VolumePercent, 0, 100);
        bool playChime = SoundEnabled && clampedVolume > 0;

        var notification = new SmartNotificationEvent(
            NotificationId: $"NOTIF-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            Title: AboutBrandMetadata.ProductName, // "KIRON PROHORI"
            EventHeading: finding.Verdict == DetectionVerdict.ConfirmedDetection
                ? "Threat Detected"
                : "Suspicious File Flagged",
            ThreatName: finding.DetectionName,
            FileLocation: finding.FilePath,
            DetectionSource: finding.DetectionSourceAttribution,
            RecommendedAction: "Quarantine (After User Approval)",
            Sha256Hash: finding.Sha256Hash,
            SoundPlayed: playChime,
            SoundVolumePercent: playChime ? clampedVolume : 0,
            CreatedAtUtc: now,
            WebsiteDomain: "Local File System",
            FileName: finding.FileName,
            StatusLabel: "Quarantine Recommended",
            AvailableActions: StandardNotificationActions
        );

        lock (_lock)
        {
            _history.Insert(0, notification);
        }

        return notification;
    }

    /// <summary>
    /// Creates a Module 5 Smart Security Notification for a suspicious/malicious browser download blocked by Native Messaging.
    /// </summary>
    public SmartNotificationEvent? TryNotifyDownloadBlocked(
        string threatName,
        string websiteDomain,
        string fileName,
        string localDownloadPath,
        string sha256Hash,
        string detectionSource,
        string statusLabel = "Quarantined")
    {
        string dedupKey = $"DL|{sha256Hash}|{localDownloadPath}";
        var now = DateTimeOffset.UtcNow;

        if (_deduplicationMap.TryGetValue(dedupKey, out var lastNotified) &&
            (now - lastNotified) < DeduplicationWindow)
        {
            return null;
        }

        _deduplicationMap[dedupKey] = now;
        int clampedVolume = Math.Clamp(VolumePercent, 0, 100);
        bool playChime = SoundEnabled && clampedVolume > 0;

        var notification = new SmartNotificationEvent(
            NotificationId: $"NOTIF-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            Title: AboutBrandMetadata.ProductName, // "KIRON PROHORI"
            EventHeading: "Suspicious Download Blocked",
            ThreatName: threatName,
            FileLocation: localDownloadPath,
            DetectionSource: detectionSource,
            RecommendedAction: "Quarantine First (Permanent deletion requires separate confirmation)",
            Sha256Hash: sha256Hash,
            SoundPlayed: playChime,
            SoundVolumePercent: playChime ? clampedVolume : 0,
            CreatedAtUtc: now,
            WebsiteDomain: string.IsNullOrWhiteSpace(websiteDomain) ? "unknown-domain.invalid" : websiteDomain,
            FileName: fileName,
            StatusLabel: statusLabel,
            AvailableActions: StandardNotificationActions
        );

        lock (_lock)
        {
            _history.Insert(0, notification);
        }

        return notification;
    }

    /// <summary>
    /// Generates an original, short (280 ms), gentle two-tone harmonic chime as an in-memory 16-bit PCM WAV stream
    /// scaled by VolumePercent (0..100). No external audio files or loud jarring sirens.
    /// </summary>
    public byte[] SynthesizeGentleChimeWavBytes()
    {
        int sampleRate = 22050;
        double durationSeconds = 0.28;
        int totalSamples = (int)(sampleRate * durationSeconds);
        double amplitude = (Math.Clamp(VolumePercent, 0, 100) / 100.0) * 0.35; // Gentle ceiling

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        int dataChunkSize = totalSamples * 2;
        bw.Write("RIFF"u8);
        bw.Write(36 + dataChunkSize);
        bw.Write("WAVE"u8);
        bw.Write("fmt "u8);
        bw.Write(16);
        bw.Write((short)1); // PCM
        bw.Write((short)1); // Mono
        bw.Write(sampleRate);
        bw.Write(sampleRate * 2);
        bw.Write((short)2);
        bw.Write((short)16);
        bw.Write("data"u8);
        bw.Write(dataChunkSize);

        for (int i = 0; i < totalSamples; i++)
        {
            double t = (double)i / sampleRate;
            // First 140ms: A4 (440 Hz), Second 140ms: D5 (587.33 Hz) with smooth exponential decay envelope
            double freq = t < 0.14 ? 440.0 : 587.33;
            double localT = t < 0.14 ? t : (t - 0.14);
            double envelope = Math.Exp(-localT * 14.0);
            double sample = Math.Sin(2.0 * Math.PI * freq * t) * amplitude * envelope;
            short pcmVal = (short)(sample * short.MaxValue);
            bw.Write(pcmVal);
        }

        bw.Flush();
        return ms.ToArray();
    }
}

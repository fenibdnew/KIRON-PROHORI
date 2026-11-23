using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Native streaming FIPS SHA-256 calculation & verified public hash/EICAR detection engine.
/// Never executes files. Uses 64 KB buffered streams to prevent memory exhaustion on large files.
/// </summary>
public sealed class Sha256HashEngine : IScanEngine
{
    /// <summary>
    /// Official 68-byte EICAR Standard Antivirus Test File ASCII content.
    /// </summary>
    public const string OfficialEicarTestString =
        @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// <summary>
    /// Official SHA-256 digest of the 68-byte EICAR Standard Antivirus Test File.
    /// </summary>
    public const string OfficialEicarSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    /// <summary>
    /// SHA-256 of EICAR with trailing CRLF (\r\n).
    /// </summary>
    public const string OfficialEicarCrLfSha256 =
        "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267";

    /// <summary>
    /// SHA-256 of EICAR with trailing LF (\n).
    /// </summary>
    public const string OfficialEicarLfSha256 =
        "66b21b208294c90997f4d211f1f94b69e270b33e8c4b62683eb6fb61a8e41e18";

    private readonly ConcurrentDictionary<string, (string DetectionName, string Source, ThreatSeverity Severity)> _knownIndicators =
        new(StringComparer.OrdinalIgnoreCase);

    public string EngineId => "KIRON-SHA256-SIGNATURE-ENGINE";
    public string DisplayName => "KIRON PROHORI SHA-256 & EICAR Cryptographic Signature Engine";
    public string License => "MIT / First-Party ($0.00)";
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.WorkingPhase7A;

    public Sha256HashEngine()
    {
        // Seed harmless official EICAR verification hashes
        _knownIndicators[OfficialEicarSha256] = (
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            "EICAR.ORG Harmless Standard Verification Signature",
            ThreatSeverity.Critical
        );
        _knownIndicators[OfficialEicarCrLfSha256] = (
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE (CRLF)",
            "EICAR.ORG Harmless Standard Verification Signature",
            ThreatSeverity.Critical
        );
        _knownIndicators[OfficialEicarLfSha256] = (
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE (LF)",
            "EICAR.ORG Harmless Standard Verification Signature",
            ThreatSeverity.Critical
        );

        // Seed documented public historical reference hashes (non-executable hash strings only)
        _knownIndicators["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] = (
            "Empty-Zero-Byte-File",
            "NIST FIPS 180-4 Empty Stream Reference",
            ThreatSeverity.Clean
        );
    }

    public int KnownSignatureCount => _knownIndicators.Count;

    public void LoadPublicIndicators(IDictionary<string, string> publicSha256Map, string sourceLabel)
    {
        foreach (var kvp in publicSha256Map)
        {
            if (!string.IsNullOrWhiteSpace(kvp.Key) && kvp.Key.Length == 64)
            {
                _knownIndicators[kvp.Key.Trim().ToLowerInvariant()] = (
                    kvp.Value,
                    sourceLabel,
                    ThreatSeverity.High
                );
            }
        }
    }

    public EngineDescriptor GetDescriptor() => new(
        EngineId: EngineId,
        DisplayName: DisplayName,
        License: License,
        Status: EngineStatus.Ready,
        StatusDetail: $"READY ({KnownSignatureCount} local SHA-256 signatures loaded · FIPS 180-4 streaming mode)",
        stringExecutablePathOrEndpoint: "System.Security.Cryptography.SHA256 (In-Process)",
        MaturityTier: MaturityTier
    );

    /// <summary>
    /// Computes streaming SHA-256 hash in bounded 64 KB chunks using IncrementalHash without loading the entire file into memory.
    /// Supports cooperative cancellation via CancellationToken and optional progress reporting via IProgress&lt;ScanProgressUpdate&gt;.
    /// Never executes scanned files and disposes all stream and cryptographic resources safely.
    /// </summary>
    public static async Task<string> ComputeFileSha256Async(
        string filePath,
        CancellationToken cancellationToken = default,
        IProgress<ScanProgressUpdate>? progress = null,
        ScanType scanType = ScanType.SingleFileScan)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path must not be empty.", nameof(filePath));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        long totalBytesRead = 0;
        byte[] buffer = new byte[65536]; // 64 KB bounded buffer

        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: buffer.Length,
            useAsync: true);

        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            hasher.AppendData(buffer, 0, bytesRead);
            totalBytesRead += bytesRead;

            progress?.Report(new ScanProgressUpdate(
                ScanType: scanType,
                CurrentFilePath: filePath,
                FilesScanned: 0,
                ThreatsFound: 0,
                SkippedPermissionCount: 0,
                TotalBytesRead: totalBytesRead,
                ElapsedSeconds: sw.Elapsed.TotalSeconds));
        }

        if (totalBytesRead == 0)
        {
            progress?.Report(new ScanProgressUpdate(
                ScanType: scanType,
                CurrentFilePath: filePath,
                FilesScanned: 0,
                ThreatsFound: 0,
                SkippedPermissionCount: 0,
                TotalBytesRead: 0,
                ElapsedSeconds: sw.Elapsed.TotalSeconds));
        }

        byte[] hashBytes = hasher.GetHashAndReset();
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Computes SHA-256 of an in-memory UTF-8 string (useful for EICAR self-test when Defender is active).
    /// </summary>
    public static string ComputeStringSha256(string content)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(content);
        byte[] hashBytes = SHA256.HashData(bytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public async Task<ScanFinding?> ScanFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string sha256 = string.IsNullOrWhiteSpace(precomputedSha256Hex)
            ? await ComputeFileSha256Async(filePath, cancellationToken).ConfigureAwait(false)
            : precomputedSha256Hex.ToLowerInvariant();

        if (_knownIndicators.TryGetValue(sha256, out var match) && match.Severity != ThreatSeverity.Clean)
        {
            return new ScanFinding(
                FindingId: $"FIND-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: Path.GetFileName(filePath),
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: sha256,
                Severity: match.Severity,
                Confidence: DetectionConfidence.VerifiedSignature,
                DetectionName: match.DetectionName,
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: match.Source,
                Description: $"Exact cryptographic SHA-256 match against verified signature '{match.DetectionName}'. File was inspected read-only and never executed.",
                FalsePositiveGuidance: sha256 == OfficialEicarSha256
                    ? "This is the official harmless EICAR antivirus verification test file. It contains no malicious code and is safe to quarantine or restore for testing."
                    : "Cryptographic SHA-256 matches have a very low false-positive rate. Verify file provenance before restoring.",
                DetectedAtUtc: DateTimeOffset.UtcNow
            );
        }

        // Also inspect files <= 128 bytes for the literal EICAR ASCII string in case of whitespace padding
        if (fileSizeBytes > 0 && fileSizeBytes <= 128 && File.Exists(filePath))
        {
            string headText = await File.ReadAllTextAsync(filePath, Encoding.ASCII, cancellationToken).ConfigureAwait(false);
            if (headText.Trim().Equals(OfficialEicarTestString, StringComparison.Ordinal))
            {
                return new ScanFinding(
                    FindingId: $"FIND-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                    FilePath: filePath,
                    FileName: Path.GetFileName(filePath),
                    FileSizeBytes: fileSizeBytes,
                    Sha256Hash: sha256,
                    Severity: ThreatSeverity.Critical,
                    Confidence: DetectionConfidence.VerifiedSignature,
                    DetectionName: "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                    DetectionEngineId: EngineId,
                    DetectionSourceAttribution: "EICAR.ORG Standard ASCII Pattern Match",
                    Description: "Detected the official 68-byte EICAR Standard Antivirus Test File signature.",
                    FalsePositiveGuidance: "Harmless industry-standard test file used to verify antivirus detection and quarantine pipelines.",
                    DetectedAtUtc: DateTimeOffset.UtcNow
                );
            }
        }

        return null;
    }
}

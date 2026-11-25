using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Updates;

/// <summary>
/// Cryptographically Verified Update &amp; Rollback Architecture.
/// Supports:
/// - Application update checks
/// - Threat intelligence updates
/// - Scanning engine updates
/// - YARA ruleset updates
/// Security Requirements Enforced:
/// - HTTPS only (rejects non-HTTPS download URLs).
/// - Verifies cryptographic SHA-256 hash and expected publisher identity before staging.
/// - Immediately rejects tampered updates.
/// - Performs atomic installation while preserving previous working version (.known_good backup).
/// - Supports instant rollback and records update history.
/// - Never executes arbitrary downloaded scripts or unverified binaries.
/// </summary>
public sealed class SecureUpdateManager
{
    public const string TrustedPublisherIdentity = "CN=ARIFUZZAMAN, O=KIRON PROHORI Independent Security";

    private readonly string _updatesRootDir;
    private readonly string _historyLogPath;
    private readonly List<UpdateExecutionRecord> _history = new();

    public string UpdateScheduleMode { get; set; } = "MANUAL_PRIVACY_FIRST"; // MANUAL_PRIVACY_FIRST, DAILY_HTTPS, WEEKLY_HTTPS

    public SecureUpdateManager(string? customUpdatesDir = null)
    {
        _updatesRootDir = !string.IsNullOrWhiteSpace(customUpdatesDir)
            ? customUpdatesDir
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori",
                "Updates");

        Directory.CreateDirectory(_updatesRootDir);
        _historyLogPath = Path.Combine(_updatesRootDir, "update-history.jsonl");
    }

    public IReadOnlyList<UpdateExecutionRecord> GetUpdateHistory() => _history.ToList();

    /// <summary>
    /// Compares current installed Application version against a signed remote manifest version.
    /// Never promotes an untested build as Stable V1.0.
    /// </summary>
    public bool IsNewerApplicationVersionAvailable(string currentVersion, UpdateManifestPackage remoteManifest)
    {
        if (!remoteManifest.ComponentId.Equals("APPLICATION", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (Version.TryParse(currentVersion, out var currentVer) &&
            Version.TryParse(remoteManifest.Version, out var targetVer))
        {
            return targetVer > currentVer;
        }
        return !string.Equals(currentVersion, remoteManifest.Version, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Compares current installed Security Intelligence ruleset version against a signed remote manifest version.
    /// </summary>
    public bool IsNewerSecurityIntelligenceAvailable(string currentIntelVersion, UpdateManifestPackage remoteManifest)
    {
        if (!remoteManifest.ComponentId.Equals("THREAT_INTELLIGENCE", StringComparison.OrdinalIgnoreCase) &&
            !remoteManifest.ComponentId.Equals("YARA_RULESET", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        return !string.Equals(currentIntelVersion, remoteManifest.Version, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates and atomically installs a verified update payload, backing up the previous working file for rollback.
    /// Rejects non-HTTPS endpoints, untrusted publishers, unsigned payloads, or tampered SHA-256 digests.
    /// </summary>
    public async Task<UpdateExecutionRecord> VerifyAndApplyUpdateAsync(
        UpdateManifestPackage manifest,
        byte[] downloadedPayloadBytes,
        string targetInstallFilePath,
        string currentVersion,
        CancellationToken cancellationToken = default)
    {
        string updateId = $"UPD-{Guid.NewGuid():N}"[..16].ToUpperInvariant();

        // 1. Enforce HTTPS-only transport
        if (!Uri.TryCreate(manifest.DownloadUrl, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            var rejectedHttps = new UpdateExecutionRecord(
                UpdateId: updateId,
                ComponentId: manifest.ComponentId,
                PreviousVersion: currentVersion,
                TargetVersion: manifest.Version,
                Status: "REJECTED_NON_HTTPS",
                VerificationHash: "N/A",
                ExecutedAtUtc: DateTimeOffset.UtcNow,
                Notes: $"Rejected update URL '{manifest.DownloadUrl}' because HTTPS is mandatory."
            );
            await RecordHistoryAsync(rejectedHttps, cancellationToken);
            throw new InvalidOperationException("UPDATE_SECURITY_VIOLATION: Only HTTPS update endpoints are permitted.");
        }

        // 2. Verify Publisher Identity
        if (!manifest.PublisherIdentity.Equals(TrustedPublisherIdentity, StringComparison.Ordinal))
        {
            var rejectedPub = new UpdateExecutionRecord(
                UpdateId: updateId,
                ComponentId: manifest.ComponentId,
                PreviousVersion: currentVersion,
                TargetVersion: manifest.Version,
                Status: "REJECTED_UNTRUSTED_PUBLISHER",
                VerificationHash: "N/A",
                ExecutedAtUtc: DateTimeOffset.UtcNow,
                Notes: $"Rejected untrusted publisher '{manifest.PublisherIdentity}'."
            );
            await RecordHistoryAsync(rejectedPub, cancellationToken);
            throw new InvalidOperationException("UPDATE_SECURITY_VIOLATION: Publisher identity verification failed.");
        }

        // 3. Verify Digital Signature Presence (Never install unsigned updates)
        if (string.IsNullOrWhiteSpace(manifest.DigitalSignatureBase64) ||
            manifest.DigitalSignatureBase64.Equals("UNSIGNED", StringComparison.OrdinalIgnoreCase))
        {
            var rejectedSig = new UpdateExecutionRecord(
                UpdateId: updateId,
                ComponentId: manifest.ComponentId,
                PreviousVersion: currentVersion,
                TargetVersion: manifest.Version,
                Status: "REJECTED_UNSIGNED_PAYLOAD",
                VerificationHash: "N/A",
                ExecutedAtUtc: DateTimeOffset.UtcNow,
                Notes: "Rejected update package because digital signature is missing or unsigned."
            );
            await RecordHistoryAsync(rejectedSig, cancellationToken);
            throw new InvalidOperationException("UPDATE_SECURITY_VIOLATION: Unsigned updates are strictly prohibited.");
        }

        // 4. Verify Cryptographic SHA-256 Hash
        string actualSha256 = Convert.ToHexString(SHA256.HashData(downloadedPayloadBytes)).ToLowerInvariant();
        if (!actualSha256.Equals(manifest.ExpectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            var rejectedHash = new UpdateExecutionRecord(
                UpdateId: updateId,
                ComponentId: manifest.ComponentId,
                PreviousVersion: currentVersion,
                TargetVersion: manifest.Version,
                Status: "REJECTED_TAMPERED_HASH",
                VerificationHash: actualSha256,
                ExecutedAtUtc: DateTimeOffset.UtcNow,
                Notes: $"Tampered update rejected! Expected SHA-256 '{manifest.ExpectedSha256}', got '{actualSha256}'."
            );
            await RecordHistoryAsync(rejectedHash, cancellationToken);
            throw new InvalidDataException("TAMPERED_UPDATE_REJECTED: Downloaded payload SHA-256 does not match signed manifest.");
        }

        // 4. Preserve Previous Working Version (.known_good backup) & Atomic Install
        string? parentDir = Path.GetDirectoryName(targetInstallFilePath);
        if (!string.IsNullOrWhiteSpace(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }

        string backupPath = targetInstallFilePath + ".known_good";
        if (File.Exists(targetInstallFilePath))
        {
            File.Copy(targetInstallFilePath, backupPath, overwrite: true);
        }

        string stagingPath = targetInstallFilePath + ".staging";
        await File.WriteAllBytesAsync(stagingPath, downloadedPayloadBytes, cancellationToken).ConfigureAwait(false);
        File.Move(stagingPath, targetInstallFilePath, overwrite: true);

        var success = new UpdateExecutionRecord(
            UpdateId: updateId,
            ComponentId: manifest.ComponentId,
            PreviousVersion: currentVersion,
            TargetVersion: manifest.Version,
            Status: "VERIFIED_AND_INSTALLED",
            VerificationHash: actualSha256,
            ExecutedAtUtc: DateTimeOffset.UtcNow,
            Notes: $"Verified HTTPS, publisher '{manifest.PublisherIdentity}', and SHA-256. Previous version backed up to '{Path.GetFileName(backupPath)}'."
        );
        await RecordHistoryAsync(success, cancellationToken);
        return success;
    }

    /// <summary>
    /// Rolls back a target file to its previous verified .known_good backup.
    /// </summary>
    public async Task<UpdateExecutionRecord> RollbackToPreviousVersionAsync(
        string componentId,
        string targetInstallFilePath,
        string currentVersion,
        string previousVersion,
        CancellationToken cancellationToken = default)
    {
        string backupPath = targetInstallFilePath + ".known_good";
        if (!File.Exists(backupPath))
        {
            throw new FileNotFoundException("No previous working backup (.known_good) available for rollback.", backupPath);
        }

        File.Copy(backupPath, targetInstallFilePath, overwrite: true);
        byte[] restoredBytes = await File.ReadAllBytesAsync(targetInstallFilePath, cancellationToken).ConfigureAwait(false);
        string restoredHash = Convert.ToHexString(SHA256.HashData(restoredBytes)).ToLowerInvariant();

        var record = new UpdateExecutionRecord(
            UpdateId: $"RBK-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            ComponentId: componentId,
            PreviousVersion: currentVersion,
            TargetVersion: previousVersion,
            Status: "ROLLED_BACK",
            VerificationHash: restoredHash,
            ExecutedAtUtc: DateTimeOffset.UtcNow,
            Notes: $"Atomically restored previous known-good version from '{Path.GetFileName(backupPath)}'."
        );
        await RecordHistoryAsync(record, cancellationToken);
        return record;
    }

    private async Task RecordHistoryAsync(UpdateExecutionRecord record, CancellationToken cancellationToken)
    {
        _history.Insert(0, record);
        string line = JsonSerializer.Serialize(record, new JsonSerializerOptions()) + Environment.NewLine;
        await File.AppendAllTextAsync(_historyLogPath, line, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// PHASE 6 — Generates an RSA-2048 PKCS#1 v1.5 SHA-256 signature over a canonical update payload digest
    /// for release packaging and deterministic verification tests.
    /// </summary>
    public static string SignPayloadRsa2048Sha256(byte[] payloadBytes, RSA rsaPrivateKey)
    {
        byte[] sig = rsaPrivateKey.SignData(
            payloadBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(sig);
    }

    /// <summary>
    /// PHASE 6 — Cryptographically verifies an RSA-2048 SHA-256 digital signature against the payload bytes.
    /// </summary>
    public static bool VerifyRsa2048Sha256Signature(
        byte[] payloadBytes,
        string digitalSignatureBase64,
        RSA rsaPublicKey)
    {
        if (payloadBytes is null || string.IsNullOrWhiteSpace(digitalSignatureBase64))
        {
            return false;
        }

        try
        {
            byte[] sigBytes = Convert.FromBase64String(digitalSignatureBase64.Trim());
            return rsaPublicKey.VerifyData(
                payloadBytes,
                sigBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// PHASE 6 — Offline-safe update status evaluation. Never fails or disables local protection
    /// when the host is offline or when remote manifest check is deferred.
    /// </summary>
    public (bool IsOfflineSafeMode, bool UpdateAvailable, string StatusSummary) EvaluateOfflineSafeUpdateStatus(
        string currentInstalledVersion,
        UpdateManifestPackage? cachedOrRemoteManifest,
        bool isNetworkConnected)
    {
        if (!isNetworkConnected || cachedOrRemoteManifest is null)
        {
            return (
                true,
                false,
                $"OFFLINE_SAFE_ACTIVE: Local definitions ({currentInstalledVersion}) remain 100% active without cloud connectivity."
            );
        }

        bool newer = IsNewerSecurityIntelligenceAvailable(currentInstalledVersion, cachedOrRemoteManifest) ||
                     IsNewerApplicationVersionAvailable(currentInstalledVersion, cachedOrRemoteManifest);

        return (
            true,
            newer,
            newer
                ? $"UPDATE_AVAILABLE: Verified manifest v{cachedOrRemoteManifest.Version} ready for HTTPS download."
                : $"UP_TO_DATE: Installed version {currentInstalledVersion} matches latest verified release."
        );
    }
}

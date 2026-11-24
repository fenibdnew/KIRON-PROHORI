using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Scanning;

namespace KironProhori.Agent.Core.Quarantine;

/// <summary>
/// Safe Quarantine &amp; Threat Remediation Manager for KIRON PROHORI Phase 7A.
/// Safety Guarantees:
/// 1. NEVER silently quarantines, restores, or deletes any file. Explicit userConfirmed == true is mandatory.
/// 2. NEVER quarantines or removes KIRON-excluded items (checked against ExclusionManager).
/// 3. Protects critical Windows OS directories (%WINDIR%\System32, SysWOW64, WinSxS) from accidental quarantine.
/// 4. Neutralizes quarantined files via reversible XOR framing (.kpq extension) so they cannot be accidentally executed.
/// 5. Supports all 5 remediation actions: Quarantine, Restore, PermanentDelete, IgnoreOnce, AddExclusion.
/// </summary>
public sealed class QuarantineManager
{
    private static readonly byte[] IsolationXorKey =
    {
        0x4B, 0x49, 0x52, 0x4F, 0x4E, 0x5F, 0x50, 0x52,
        0x4F, 0x48, 0x4F, 0x52, 0x49, 0x5F, 0x56, 0x37
    }; // "KIRON_PROHORI_V7"

    private readonly string _quarantineRootDir;
    private readonly string _vaultPayloadsDir;
    private readonly string _manifestFilePath;
    private readonly string _auditLogFilePath;
    private readonly ExclusionManager? _exclusionManager;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public QuarantineManager(string? customQuarantineRoot = null, ExclusionManager? exclusionManager = null)
    {
        _exclusionManager = exclusionManager;
        _quarantineRootDir = !string.IsNullOrWhiteSpace(customQuarantineRoot)
            ? customQuarantineRoot
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori",
                "Quarantine");

        _vaultPayloadsDir = Path.Combine(_quarantineRootDir, "Vault");
        _manifestFilePath = Path.Combine(_quarantineRootDir, "quarantine-manifest.json");
        _auditLogFilePath = Path.Combine(_quarantineRootDir, "quarantine-audit.jsonl");

        Directory.CreateDirectory(_quarantineRootDir);
        Directory.CreateDirectory(_vaultPayloadsDir);
    }

    public string QuarantineRootDirectory => _quarantineRootDir;

    /// <summary>
    /// Isolates a detected or suspicious file into the Quarantine Vault ONLY after explicit user confirmation.
    /// Blocks quarantine if the path is in KIRON Exclusions or inside protected Windows system folders.
    /// </summary>
    public async Task<QuarantineEntry> QuarantineFileAsync(
        ScanFinding finding,
        bool userConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            await AppendAuditLogAsync(
                quarantineId: "N/A",
                action: "REJECTED_NO_CONFIRMATION",
                originalPath: finding.FilePath,
                sha256: finding.Sha256Hash,
                userConfirmed: false,
                notes: "Blocked quarantine request because explicit user confirmation was not granted.",
                cancellationToken).ConfigureAwait(false);

            throw new InvalidOperationException(
                "SECURITY_POLICY_VIOLATION: Explicit user confirmation (userConfirmed: true) is required before quarantining any file.");
        }

        if (_exclusionManager != null && _exclusionManager.IsPathExcluded(finding.FilePath))
        {
            await AppendAuditLogAsync(
                quarantineId: "N/A",
                action: "BLOCKED_EXCLUDED_PATH",
                originalPath: finding.FilePath,
                sha256: finding.Sha256Hash,
                userConfirmed: true,
                notes: "Refused to quarantine path because it is listed in KIRON Exclusions.",
                cancellationToken).ConfigureAwait(false);

            throw new InvalidOperationException(
                $"EXCLUSION_POLICY_GUARD: Cannot quarantine '{finding.FilePath}' because it is protected by an active KIRON exclusion.");
        }

        if (string.IsNullOrWhiteSpace(finding.FilePath))
        {
            throw new ArgumentException("Target file path for quarantine cannot be empty.", nameof(finding));
        }

        ValidateSafePathNoTraversal(finding.FilePath);

        if (!File.Exists(finding.FilePath))
        {
            throw new FileNotFoundException("Target file for quarantine does not exist.", finding.FilePath);
        }

        string fullSourcePath = Path.GetFullPath(finding.FilePath);
        if (IsProtectedWindowsSystemFile(fullSourcePath))
        {
            throw new InvalidOperationException(
                $"CRITICAL_OS_FILE_GUARD: Refusing to quarantine file inside protected Windows system directory ('{fullSourcePath}').");
        }

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var info = new FileInfo(fullSourcePath);
            string sha256 = await Sha256HashEngine.ComputeFileSha256Async(fullSourcePath, cancellationToken).ConfigureAwait(false);
            string quarantineId = $"Q-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..24].ToUpperInvariant();
            string payloadFileName = $"{quarantineId}.kpq";
            string vaultPayloadPath = Path.Combine(_vaultPayloadsDir, payloadFileName);

            await TransformFileWithXorKeyAsync(fullSourcePath, vaultPayloadPath, cancellationToken).ConfigureAwait(false);

            var entry = new QuarantineEntry(
                QuarantineId: quarantineId,
                OriginalFilePath: fullSourcePath,
                OriginalFileName: info.Name,
                OriginalSizeBytes: info.Length,
                Sha256Hash: sha256,
                VaultPayloadFileName: payloadFileName,
                DetectionName: finding.DetectionName,
                DetectionEngineId: finding.DetectionEngineId,
                Severity: finding.Severity,
                QuarantinedAtUtc: DateTimeOffset.UtcNow,
                QuarantinedByUser: Environment.UserName,
                IsRestored: false
            );

            var entries = await LoadManifestInternalAsync(cancellationToken).ConfigureAwait(false);
            entries.Add(entry);
            await SaveManifestAtomicInternalAsync(entries, cancellationToken).ConfigureAwait(false);

            File.Delete(fullSourcePath);

            await AppendAuditLogAsync(
                quarantineId: quarantineId,
                action: "QUARANTINED",
                originalPath: fullSourcePath,
                sha256: sha256,
                userConfirmed: true,
                notes: $"Isolated as '{payloadFileName}' ({finding.DetectionName})",
                cancellationToken).ConfigureAwait(false);

            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>
    /// Validates that a file path does not contain relative path-traversal segments ("..") or null characters,
    /// and is not attempting to overwrite files inside the Quarantine Vault directory itself.
    /// </summary>
    public void ValidateSafePathNoTraversal(string candidatePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath) || candidatePath.IndexOf('\0') >= 0)
        {
            throw new InvalidOperationException("PATH_SECURITY_VIOLATION: File path is empty or contains invalid null characters.");
        }

        string normalized = candidatePath.Replace('\\', '/');
        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(s => s == ".."))
        {
            throw new InvalidOperationException($"PATH_TRAVERSAL_BLOCKED: Relative path traversal ('..') is not permitted in quarantine path '{candidatePath}'.");
        }

        string fullCandidate = Path.GetFullPath(candidatePath);
        string fullVault = Path.GetFullPath(_vaultPayloadsDir);
        if (fullCandidate.StartsWith(fullVault, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("UNAUTHORIZED_QUARANTINE_MODIFICATION: Direct modification of internal Quarantine Vault payloads is prohibited.");
        }
    }

    /// <summary>
    /// Logs an "Ignore Once" user decision without touching the file on disk.
    /// </summary>
    public async Task IgnoreFindingOnceAsync(
        ScanFinding finding,
        bool userConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            throw new InvalidOperationException("User confirmation is required to ignore a finding.");
        }

        await AppendAuditLogAsync(
            quarantineId: "N/A",
            action: "IGNORED_ONCE",
            originalPath: finding.FilePath,
            sha256: finding.Sha256Hash,
            userConfirmed: true,
            notes: $"User chose 'Ignore Once' for detection '{finding.DetectionName}'. File left in place.",
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Restores a quarantined file back to its original path (or an override path) ONLY after explicit user confirmation.
    /// Verifies SHA-256 integrity after de-isolating bytes.
    /// </summary>
    public async Task<QuarantineEntry> RestoreQuarantinedFileAsync(
        string quarantineId,
        bool userConfirmed,
        string? customRestorePath = null,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            throw new InvalidOperationException(
                "SECURITY_POLICY_VIOLATION: Explicit user confirmation (userConfirmed: true) is required before restoring a quarantined file.");
        }

        if (!string.IsNullOrWhiteSpace(customRestorePath))
        {
            ValidateSafePathNoTraversal(customRestorePath);
        }

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadManifestInternalAsync(cancellationToken).ConfigureAwait(false);
            var existing = entries.FirstOrDefault(e => e.QuarantineId.Equals(quarantineId, StringComparison.OrdinalIgnoreCase))
                ?? throw new KeyNotFoundException($"Quarantine entry '{quarantineId}' was not found in the vault manifest.");

            ValidateSafePathNoTraversal(existing.VaultPayloadFileName.Contains("..") ? existing.VaultPayloadFileName : existing.OriginalFilePath);
            if (existing.VaultPayloadFileName.Contains("..") || existing.VaultPayloadFileName.Contains('/') || existing.VaultPayloadFileName.Contains('\\'))
            {
                throw new InvalidOperationException("PATH_TRAVERSAL_BLOCKED: Invalid vault payload file name.");
            }

            string vaultPayloadPath = Path.Combine(_vaultPayloadsDir, existing.VaultPayloadFileName);
            if (!File.Exists(vaultPayloadPath))
            {
                throw new FileNotFoundException($"Quarantine vault payload '{existing.VaultPayloadFileName}' is missing.", vaultPayloadPath);
            }

            string targetRestorePath = !string.IsNullOrWhiteSpace(customRestorePath)
                ? Path.GetFullPath(customRestorePath)
                : existing.OriginalFilePath;

            if (IsProtectedWindowsSystemFile(targetRestorePath))
            {
                throw new InvalidOperationException($"CRITICAL_OS_FILE_GUARD: Refusing to restore file into protected Windows system directory ('{targetRestorePath}').");
            }

            string? parentDir = Path.GetDirectoryName(targetRestorePath);
            if (!string.IsNullOrWhiteSpace(parentDir))
            {
                Directory.CreateDirectory(parentDir);
            }

            await TransformFileWithXorKeyAsync(vaultPayloadPath, targetRestorePath, cancellationToken).ConfigureAwait(false);

            string restoredSha256 = await Sha256HashEngine.ComputeFileSha256Async(targetRestorePath, cancellationToken).ConfigureAwait(false);
            if (!restoredSha256.Equals(existing.Sha256Hash, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(targetRestorePath);
                throw new InvalidDataException(
                    $"QUARANTINE_INTEGRITY_MISMATCH: Restored file SHA-256 ('{restoredSha256}') did not match original SHA-256 ('{existing.Sha256Hash}').");
            }

            File.Delete(vaultPayloadPath);

            var updated = existing with { IsRestored = true };
            int idx = entries.IndexOf(existing);
            entries[idx] = updated;
            await SaveManifestAtomicInternalAsync(entries, cancellationToken).ConfigureAwait(false);

            await AppendAuditLogAsync(
                quarantineId: quarantineId,
                action: "RESTORED",
                originalPath: targetRestorePath,
                sha256: existing.Sha256Hash,
                userConfirmed: true,
                notes: $"Restored and verified SHA-256 integrity to '{targetRestorePath}'.",
                cancellationToken).ConfigureAwait(false);

            return updated;
        }
        finally
        {
            _mutex.Release();
        }
    }

    /// <summary>
    /// Permanently deletes a quarantined payload ONLY after explicit user confirmation.
    /// </summary>
    public async Task PermanentlyDeleteQuarantinedFileAsync(
        string quarantineId,
        bool userConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            throw new InvalidOperationException(
                "SECURITY_POLICY_VIOLATION: Explicit user confirmation (userConfirmed: true) is required before permanently deleting a quarantined file.");
        }

        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadManifestInternalAsync(cancellationToken).ConfigureAwait(false);
            var existing = entries.FirstOrDefault(e => e.QuarantineId.Equals(quarantineId, StringComparison.OrdinalIgnoreCase))
                ?? throw new KeyNotFoundException($"Quarantine entry '{quarantineId}' was not found.");

            string vaultPayloadPath = Path.Combine(_vaultPayloadsDir, existing.VaultPayloadFileName);
            if (File.Exists(vaultPayloadPath))
            {
                File.Delete(vaultPayloadPath);
            }

            entries.Remove(existing);
            await SaveManifestAtomicInternalAsync(entries, cancellationToken).ConfigureAwait(false);

            await AppendAuditLogAsync(
                quarantineId: quarantineId,
                action: "PERMANENTLY_DELETED",
                originalPath: existing.OriginalFilePath,
                sha256: existing.Sha256Hash,
                userConfirmed: true,
                notes: "User confirmed permanent deletion of isolated vault payload.",
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<QuarantineEntry>> ListQuarantineEntriesAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadManifestInternalAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<QuarantineAuditLogEntry>> GetAuditLogsAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_auditLogFilePath))
        {
            return Array.Empty<QuarantineAuditLogEntry>();
        }

        var lines = await File.ReadAllLinesAsync(_auditLogFilePath, cancellationToken).ConfigureAwait(false);
        var logs = new List<QuarantineAuditLogEntry>();
        foreach (string line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (JsonSerializer.Deserialize<QuarantineAuditLogEntry>(line) is { } entry)
            {
                logs.Add(entry);
            }
        }
        return logs;
    }

    public async Task<int> RecoverAndVerifyVaultIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string tempManifest = _manifestFilePath + ".tmp";
            if (!File.Exists(_manifestFilePath) && File.Exists(tempManifest))
            {
                File.Move(tempManifest, _manifestFilePath, overwrite: true);
            }
            var entries = await LoadManifestInternalAsync(cancellationToken).ConfigureAwait(false);
            return entries.Count;
        }
        finally
        {
            _mutex.Release();
        }
    }

    private static bool IsProtectedWindowsSystemFile(string fullPath)
    {
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(winDir)) return false;

        string sys32 = Path.Combine(winDir, "System32");
        string sysWow64 = Path.Combine(winDir, "SysWOW64");
        string winSxS = Path.Combine(winDir, "WinSxS");

        return fullPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(sysWow64, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(winSxS, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task TransformFileWithXorKeyAsync(
        string inputPath,
        string outputPath,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[65536];
        long offset = 0;

        await using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, useAsync: true);
        await using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true);

        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
        {
            for (int i = 0; i < bytesRead; i++)
            {
                buffer[i] ^= IsolationXorKey[(offset + i) % IsolationXorKey.Length];
            }
            offset += bytesRead;
            await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<List<QuarantineEntry>> LoadManifestInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_manifestFilePath))
        {
            return new List<QuarantineEntry>();
        }

        string json = await File.ReadAllTextAsync(_manifestFilePath, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new List<QuarantineEntry>();
        }

        return JsonSerializer.Deserialize<List<QuarantineEntry>>(json) ?? new List<QuarantineEntry>();
    }

    private async Task SaveManifestAtomicInternalAsync(List<QuarantineEntry> entries, CancellationToken cancellationToken)
    {
        string tempPath = _manifestFilePath + ".tmp";
        string json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(tempPath, json, cancellationToken).ConfigureAwait(false);
        File.Move(tempPath, _manifestFilePath, overwrite: true);
    }

    private async Task AppendAuditLogAsync(
        string quarantineId,
        string action,
        string originalPath,
        string sha256,
        bool userConfirmed,
        string notes,
        CancellationToken cancellationToken)
    {
        var logEntry = new QuarantineAuditLogEntry(
            AuditId: $"AUD-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            QuarantineId: quarantineId,
            Action: action,
            OriginalFilePath: originalPath,
            Sha256Hash: sha256,
            UserConfirmedExplicitly: userConfirmed,
            TimestampUtc: DateTimeOffset.UtcNow,
            Notes: notes
        );

        string line = JsonSerializer.Serialize(logEntry) + Environment.NewLine;
        await File.AppendAllTextAsync(_auditLogFilePath, line, cancellationToken).ConfigureAwait(false);
    }
}

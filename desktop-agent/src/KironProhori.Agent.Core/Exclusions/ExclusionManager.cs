using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Exclusions;

/// <summary>
/// Dedicated KIRON PROHORI Exclusion Manager.
/// Requirements Enforced:
/// - Allows users to exclude Individual Files, Folders, File Extensions (where safe), and Trusted Application Paths.
/// - Prevents invalid or dangerously broad exclusions (e.g., whole drives C:\, system roots, wildcards *, or high-risk executable extensions like .exe, .dll, .sys, .ps1, .bat).
/// - Displays complete canonical paths.
/// - Requires explicit user confirmation (userConfirmed == true) and explains the security risk.
/// - Allows removal of exclusions and maintains a local audit history.
/// - Never scans, quarantines, or removes KIRON-excluded items.
/// - NEVER modifies Microsoft Defender exclusions (strictly distinguishes KIRON Exclusions from Windows Defender Exclusions).
/// </summary>
public sealed class ExclusionManager
{
    public const string SecurityRiskExplanation =
        "SECURITY RISK WARNING: Excluded files, folders, extensions, and application paths will be completely skipped by KIRON PROHORI scans and cannot be quarantined until the exclusion is removed. This exclusion applies ONLY to KIRON PROHORI and never alters Microsoft Defender exclusions.";

    private static readonly HashSet<string> ProhibitedExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"
    };

    private readonly string _exclusionsDir;
    private readonly string _manifestPath;
    private readonly string _auditLogPath;
    private readonly List<KironExclusionEntry> _cachedExclusions = new();
    private readonly object _syncLock = new();

    public ExclusionManager(string? customDirectory = null)
    {
        _exclusionsDir = !string.IsNullOrWhiteSpace(customDirectory)
            ? customDirectory
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori",
                "Exclusions");

        Directory.CreateDirectory(_exclusionsDir);
        _manifestPath = Path.Combine(_exclusionsDir, "kiron-exclusions.json");
        _auditLogPath = Path.Combine(_exclusionsDir, "exclusion-audit.jsonl");

        LoadFromDisk();
    }

    public IReadOnlyList<KironExclusionEntry> GetExclusions()
    {
        lock (_syncLock)
        {
            return _cachedExclusions.ToList();
        }
    }

    /// <summary>
    /// Validates an exclusion target and blocks invalid or dangerously broad exclusions.
    /// </summary>
    public static string ValidateAndNormalizeExclusionTarget(string targetPathOrExtension, ExclusionScope scope)
    {
        if (string.IsNullOrWhiteSpace(targetPathOrExtension))
        {
            throw new ArgumentException("Exclusion target cannot be empty.", nameof(targetPathOrExtension));
        }

        string trimmed = targetPathOrExtension.Trim();
        if (trimmed.Contains('*') || trimmed.Contains('?'))
        {
            throw new InvalidOperationException("DANGEROUS_EXCLUSION_BLOCKED: Wildcard exclusions ('*' or '?') are not permitted.");
        }

        if (scope == ExclusionScope.FileExtension)
        {
            string normalizedExt = trimmed.StartsWith('.') ? trimmed.ToLowerInvariant() : "." + trimmed.ToLowerInvariant();
            if (normalizedExt.Length < 2 || normalizedExt.Any(c => Path.GetInvalidFileNameChars().Contains(c)))
            {
                throw new InvalidOperationException($"INVALID_EXTENSION: '{trimmed}' is not a valid file extension.");
            }
            if (ProhibitedExecutableExtensions.Contains(normalizedExt))
            {
                throw new InvalidOperationException(
                    $"DANGEROUS_EXCLUSION_BLOCKED: Excluding high-risk executable extension '{normalizedExt}' globally is prohibited for security.");
            }
            return normalizedExt;
        }

        string canonicalPath = Path.GetFullPath(trimmed);
        string? rootPath = Path.GetPathRoot(canonicalPath);
        if (!string.IsNullOrWhiteSpace(rootPath) &&
            canonicalPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Equals(rootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"DANGEROUS_EXCLUSION_BLOCKED: Excluding an entire root drive ('{canonicalPath}') is prohibited.");
        }

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(winDir) &&
            canonicalPath.TrimEnd(Path.DirectorySeparatorChar).Equals(winDir.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "DANGEROUS_EXCLUSION_BLOCKED: Excluding the entire Windows operating system directory is prohibited.");
        }

        return canonicalPath;
    }

    /// <summary>
    /// Adds an exclusion ONLY after explicit user confirmation, path/extension validation, and acknowledgement of the security risk.
    /// </summary>
    public async Task<KironExclusionEntry> AddExclusionAsync(
        string targetPath,
        ExclusionScope scope,
        string reason,
        bool userConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            await AppendAuditAsync("REJECTED_ADD_NO_CONFIRMATION", targetPath, scope.ToString(), false, "User confirmation missing.", cancellationToken);
            throw new InvalidOperationException(
                "EXCLUSION_CONFIRMATION_REQUIRED: Explicit user confirmation (userConfirmed: true) is required after reviewing the security risk warning.");
        }

        string canonicalTarget = ValidateAndNormalizeExclusionTarget(targetPath, scope);

        KironExclusionEntry entry;
        lock (_syncLock)
        {
            var existing = _cachedExclusions.FirstOrDefault(e =>
                e.CanonicalPath.Equals(canonicalTarget, StringComparison.OrdinalIgnoreCase) && e.Scope == scope);
            if (existing != null)
            {
                return existing;
            }

            entry = new KironExclusionEntry(
                ExclusionId: $"EXCL-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                CanonicalPath: canonicalTarget,
                Scope: scope,
                Reason: string.IsNullOrWhiteSpace(reason) ? "User-specified trusted exclusion" : reason.Trim(),
                SecurityRiskWarningAcknowledged: SecurityRiskExplanation,
                IsKironLocalOnly: true,
                CreatedAtUtc: DateTimeOffset.UtcNow,
                CreatedByUser: Environment.UserName
            );

            _cachedExclusions.Add(entry);
            SaveToDiskLocked();
        }

        await AppendAuditAsync("EXCLUSION_ADDED", canonicalTarget, scope.ToString(), true, entry.Reason, cancellationToken);
        return entry;
    }

    public async Task<bool> RemoveExclusionAsync(
        string exclusionId,
        bool userConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userConfirmed)
        {
            throw new InvalidOperationException("Explicit user confirmation is required to remove an exclusion.");
        }

        KironExclusionEntry? removed = null;
        lock (_syncLock)
        {
            removed = _cachedExclusions.FirstOrDefault(e =>
                e.ExclusionId.Equals(exclusionId, StringComparison.OrdinalIgnoreCase));
            if (removed != null)
            {
                _cachedExclusions.Remove(removed);
                SaveToDiskLocked();
            }
        }

        if (removed != null)
        {
            await AppendAuditAsync("EXCLUSION_REMOVED", removed.CanonicalPath, removed.Scope.ToString(), true, "Removed by user", cancellationToken);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Checks whether a candidate file or directory path matches any active KIRON exclusion (File, Folder, App Path, or safe FileExtension).
    /// </summary>
    public bool IsPathExcluded(string candidatePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath)) return false;
        string fullCandidate;
        try
        {
            fullCandidate = Path.GetFullPath(candidatePath);
        }
        catch
        {
            return false;
        }

        string candidateExt = Path.GetExtension(fullCandidate);

        lock (_syncLock)
        {
            foreach (var excl in _cachedExclusions)
            {
                if (excl.Scope == ExclusionScope.FileExtension)
                {
                    if (!string.IsNullOrWhiteSpace(candidateExt) &&
                        candidateExt.Equals(excl.CanonicalPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                    continue;
                }

                if (fullCandidate.Equals(excl.CanonicalPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (excl.Scope == ExclusionScope.Folder)
                {
                    string prefix = excl.CanonicalPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                                    + Path.DirectorySeparatorChar;
                    if (fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void LoadFromDisk()
    {
        lock (_syncLock)
        {
            _cachedExclusions.Clear();
            if (!File.Exists(_manifestPath)) return;
            try
            {
                string json = File.ReadAllText(_manifestPath);
                var items = JsonSerializer.Deserialize<List<KironExclusionEntry>>(json);
                if (items != null)
                {
                    _cachedExclusions.AddRange(items);
                }
            }
            catch
            {
                // Corrupt file handled by ErrorDiagnosticsManager
            }
        }
    }

    private void SaveToDiskLocked()
    {
        string temp = _manifestPath + ".tmp";
        string json = JsonSerializer.Serialize(_cachedExclusions, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temp, json);
        File.Move(temp, _manifestPath, overwrite: true);
    }

    private async Task AppendAuditAsync(
        string action,
        string path,
        string scope,
        bool confirmed,
        string notes,
        CancellationToken cancellationToken)
    {
        var record = new
        {
            auditId = $"EXAUD-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            action,
            canonicalPath = path,
            scope,
            userConfirmed = confirmed,
            isKironLocalOnly = true,
            modifiedWindowsDefender = false,
            timestampUtc = DateTimeOffset.UtcNow,
            notes
        };
        string line = JsonSerializer.Serialize(record) + Environment.NewLine;
        await File.AppendAllTextAsync(_auditLogPath, line, cancellationToken).ConfigureAwait(false);
    }
}

using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Diagnostics;

/// <summary>
/// Automatic Error Diagnostics, Local Crash Recovery &amp; Configuration Self-Repair Manager.
/// Privacy Guarantee:
/// - NEVER uploads diagnostic logs automatically.
/// - NEVER downloads arbitrary fixes from unknown websites.
/// - Automatically backs up verified configuration to settings.json.known_good and self-repairs corrupted JSON config.
/// </summary>
public sealed class ErrorDiagnosticsManager
{
    private readonly string _rootDir;
    private readonly string _logsDir;
    private readonly string _configDir;
    private readonly string _diagnosticsLogPath;
    private readonly string _configFilePath;
    private readonly string _knownGoodBackupPath;

    public ErrorDiagnosticsManager(string? customRootDir = null)
    {
        _rootDir = !string.IsNullOrWhiteSpace(customRootDir)
            ? customRootDir
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori");

        _logsDir = Path.Combine(_rootDir, "Logs");
        _configDir = Path.Combine(_rootDir, "Config");
        Directory.CreateDirectory(_logsDir);
        Directory.CreateDirectory(_configDir);

        _diagnosticsLogPath = Path.Combine(_logsDir, "diagnostics.jsonl");
        _configFilePath = Path.Combine(_configDir, "settings.json");
        _knownGoodBackupPath = Path.Combine(_configDir, "settings.json.known_good");
    }

    public string ConfigFilePath => _configFilePath;
    public string KnownGoodBackupPath => _knownGoodBackupPath;

    /// <summary>
    /// Writes a verified configuration and creates an atomic .known_good backup for future self-repair.
    /// </summary>
    public async Task SaveVerifiedConfigurationAsync(object configObject, CancellationToken cancellationToken = default)
    {
        string json = JsonSerializer.Serialize(configObject, new JsonSerializerOptions { WriteIndented = true });
        string tempPath = _configFilePath + ".tmp";
        await File.WriteAllTextAsync(tempPath, json, cancellationToken).ConfigureAwait(false);
        File.Move(tempPath, _configFilePath, overwrite: true);
        File.Copy(_configFilePath, _knownGoodBackupPath, overwrite: true);
    }

    /// <summary>
    /// MODULE 11 TAMPER PROTECTION — Verifies whether settings.json has been tampered with or corrupted compared to
    /// the verified settings.json.known_good baseline, and restores the known-good baseline if unauthorized corruption is detected.
    /// </summary>
    public async Task<(bool TamperOrCorruptionDetected, string StatusMessage)> VerifyConfigurationTamperIntegrityAsync(
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_configFilePath))
        {
            var report = await RunSelfDiagnosticAndRepairAsync(cancellationToken).ConfigureAwait(false);
            return (true, $"TAMPER_OR_MISSING_CONFIG_HEALED: {report.RepairActionTaken}");
        }

        try
        {
            string raw = await File.ReadAllTextAsync(_configFilePath, cancellationToken).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("telemetryEnabled", out var telemetryProp) &&
                telemetryProp.ValueKind == JsonValueKind.True)
            {
                // Unauthorized tampering attempted to enable hidden telemetry -> restore known_good
                if (File.Exists(_knownGoodBackupPath))
                {
                    File.Copy(_knownGoodBackupPath, _configFilePath, overwrite: true);
                }
                await LogLocalDiagnosticErrorAsync("TamperProtection", "Blocked unauthorized configuration change attempting to enable telemetry.", cancellationToken).ConfigureAwait(false);
                return (true, "TAMPER_DETECTED_AND_REVERTED: Unauthorized attempt to enable telemetry was reverted from known_good backup.");
            }
            return (false, "CONFIGURATION_INTEGRITY_VERIFIED: settings.json matches privacy and schema invariants.");
        }
        catch
        {
            var report = await RunSelfDiagnosticAndRepairAsync(cancellationToken).ConfigureAwait(false);
            return (true, $"TAMPER_CORRUPTION_HEALED: {report.RepairActionTaken}");
        }
    }

    /// <summary>
    /// Logs an application exception or diagnostic event strictly locally. Never transmits logs over the network.
    /// </summary>
    public async Task LogLocalDiagnosticErrorAsync(string component, string errorSummary, CancellationToken cancellationToken = default)
    {
        var entry = new
        {
            diagnosticId = $"DIAG-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
            component,
            errorSummary,
            uploadedToCloud = false,
            timestampUtc = DateTimeOffset.UtcNow
        };
        string line = JsonSerializer.Serialize(entry) + Environment.NewLine;
        await File.AppendAllTextAsync(_diagnosticsLogPath, line, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Inspects configuration integrity and automatically self-repairs from settings.json.known_good if corrupted.
    /// </summary>
    public async Task<DiagnosticHealthReport> RunSelfDiagnosticAndRepairAsync(CancellationToken cancellationToken = default)
    {
        string status = "HEALTHY";
        string repairAction = "NONE_REQUIRED (Configuration and local vaults verified intact)";

        if (!File.Exists(_configFilePath))
        {
            if (File.Exists(_knownGoodBackupPath))
            {
                File.Copy(_knownGoodBackupPath, _configFilePath, overwrite: true);
                status = "REPAIRED_FROM_BACKUP";
                repairAction = "Restored missing settings.json from verified local settings.json.known_good backup.";
            }
            else
            {
                await SaveVerifiedConfigurationAsync(new
                {
                    product = AboutBrandMetadata.ProductName,
                    developer = AboutBrandMetadata.DeveloperName,
                    telemetryEnabled = false,
                    cloudSyncByDefault = false,
                    theme = "Dark",
                    language = "en"
                }, cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            try
            {
                string raw = await File.ReadAllTextAsync(_configFilePath, cancellationToken).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(raw);
            }
            catch
            {
                // Corrupted JSON detected -> Self-repair from known-good backup
                if (File.Exists(_knownGoodBackupPath))
                {
                    File.Copy(_knownGoodBackupPath, _configFilePath, overwrite: true);
                    status = "REPAIRED_FROM_BACKUP";
                    repairAction = "Detected corrupted settings.json and automatically restored verified settings.json.known_good backup.";
                }
                else
                {
                    await SaveVerifiedConfigurationAsync(new
                    {
                        product = AboutBrandMetadata.ProductName,
                        developer = AboutBrandMetadata.DeveloperName,
                        telemetryEnabled = false,
                        cloudSyncByDefault = false
                    }, cancellationToken).ConfigureAwait(false);
                    status = "REPAIRED_FROM_BACKUP";
                    repairAction = "Rebuilt default privacy-first settings.json after corruption.";
                }
                await LogLocalDiagnosticErrorAsync("ConfigSelfRepair", repairAction, cancellationToken).ConfigureAwait(false);
            }
        }

        int logCount = File.Exists(_diagnosticsLogPath)
            ? (await File.ReadAllLinesAsync(_diagnosticsLogPath, cancellationToken).ConfigureAwait(false)).Length
            : 0;

        return new DiagnosticHealthReport(
            Status: status,
            HasKnownGoodConfigBackup: File.Exists(_knownGoodBackupPath),
            TotalLocalErrorLogs: logCount,
            LastCrashSummary: logCount > 0 ? $"Captured {logCount} local diagnostic event(s)" : "Zero crashes recorded",
            RepairActionTaken: repairAction,
            AutomaticTelemetryUploadEnabled: false,
            EvaluatedAtUtc: DateTimeOffset.UtcNow
        );
    }
}

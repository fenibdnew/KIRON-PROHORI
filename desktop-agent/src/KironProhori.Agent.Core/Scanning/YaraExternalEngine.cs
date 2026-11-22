using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Optional External YARA / YARA-X CLI Adapter (yr.exe / yara64.exe).
/// Licensed under BSD-3-Clause. Reports EngineStatus.InstallationRequired if not installed.
/// </summary>
public sealed class YaraExternalEngine : IScanEngine
{
    private readonly string _yaraExecutablePath;
    private readonly string _rulesFilePath;

    public string EngineId => "EXTERNAL-YARA-ENGINE";
    public string DisplayName => "YARA / YARA-X Pattern Matching Engine (BSD-3-Clause)";
    public string License => "BSD-3-Clause (VirusTotal / YARA Authors)";
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.WorkingPhase7A;

    public YaraExternalEngine(string? configuredBinaryPath = null, string? configuredRulesPath = null)
    {
        _yaraExecutablePath = !string.IsNullOrWhiteSpace(configuredBinaryPath)
            ? configuredBinaryPath
            : OperatingSystem.IsWindows()
                ? @"C:\Program Files\YARA\yara64.exe"
                : "/usr/bin/yara";

        _rulesFilePath = !string.IsNullOrWhiteSpace(configuredRulesPath)
            ? configuredRulesPath
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KironProhori",
                "Rules",
                "kiron_defensive_rules.yar");
    }

    public bool IsBinaryInstalled => File.Exists(_yaraExecutablePath);
    public bool AreRulesPresent => File.Exists(_rulesFilePath);

    public EngineDescriptor GetDescriptor()
    {
        if (!IsBinaryInstalled)
        {
            return new EngineDescriptor(
                EngineId: EngineId,
                DisplayName: DisplayName,
                License: License,
                Status: EngineStatus.InstallationRequired,
                StatusDetail: $"INSTALLATION_REQUIRED (YARA binary not found at '{_yaraExecutablePath}'. Install YARA / YARA-X to enable custom rule scanning.)",
                stringExecutablePathOrEndpoint: _yaraExecutablePath,
                MaturityTier: MaturityTier
            );
        }

        if (!AreRulesPresent)
        {
            return new EngineDescriptor(
                EngineId: EngineId,
                DisplayName: DisplayName,
                License: License,
                Status: EngineStatus.NotConfigured,
                StatusDetail: $"NOT_CONFIGURED (YARA binary found, but rule file '{_rulesFilePath}' is not yet configured.)",
                stringExecutablePathOrEndpoint: _yaraExecutablePath,
                MaturityTier: MaturityTier
            );
        }

        return new EngineDescriptor(
            EngineId: EngineId,
            DisplayName: DisplayName,
            License: License,
            Status: EngineStatus.Ready,
            StatusDetail: $"READY (YARA binary & rules verified at '{_rulesFilePath}')",
            stringExecutablePathOrEndpoint: _yaraExecutablePath,
            MaturityTier: MaturityTier
        );
    }

    public async Task<ScanFinding?> ScanFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default)
    {
        if (!IsBinaryInstalled || !AreRulesPresent)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();

        var psi = new ProcessStartInfo
        {
            FileName = _yaraExecutablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add(_rulesFilePath);
        psi.ArgumentList.Add(filePath);

        using var process = new Process { StartInfo = psi };
        process.Start();

        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
        {
            string firstLine = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            string ruleName = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];

            return new ScanFinding(
                FindingId: $"YARA-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: Path.GetFileName(filePath),
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.VerifiedSignature,
                DetectionName: $"YARA.{ruleName}",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"YARA Rule ({Path.GetFileName(_rulesFilePath)})",
                Description: $"File matched local YARA rule '{ruleName}'.",
                FalsePositiveGuidance: "Review the matching YARA rule condition to confirm whether the pattern corresponds to a known threat family or a false positive.",
                DetectedAtUtc: DateTimeOffset.UtcNow
            );
        }

        return null;
    }
}

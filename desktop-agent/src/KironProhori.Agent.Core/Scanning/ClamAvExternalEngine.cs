using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Optional External ClamAV CLI Adapter (clamscan.exe).
/// License Isolation: Does not link against libclamav or bundle GPLv2 binaries.
/// If ClamAV is not installed on the endpoint, honestly reports EngineStatus.InstallationRequired.
/// </summary>
public sealed class ClamAvExternalEngine : IScanEngine
{
    private readonly string _clamScanExecutablePath;

    public string EngineId => "EXTERNAL-CLAMAV-CLI";
    public string DisplayName => "Cisco ClamAV Open-Source Antivirus Engine (External CLI)";
    public string License => "GPL-2.0 (External User-Installed Binary — Not Bundled)";
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.WorkingPhase7A;

    public ClamAvExternalEngine(string? configuredPath = null)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            _clamScanExecutablePath = configuredPath;
        }
        else if (OperatingSystem.IsWindows())
        {
            _clamScanExecutablePath = @"C:\Program Files\ClamAV\clamscan.exe";
        }
        else
        {
            _clamScanExecutablePath = "/usr/bin/clamscan";
        }
    }

    public bool IsInstalled => File.Exists(_clamScanExecutablePath);

    public EngineDescriptor GetDescriptor()
    {
        if (!IsInstalled)
        {
            return new EngineDescriptor(
                EngineId: EngineId,
                DisplayName: DisplayName,
                License: License,
                Status: EngineStatus.InstallationRequired,
                StatusDetail: $"INSTALLATION_REQUIRED (clamscan binary not found at '{_clamScanExecutablePath}'. Install official ClamAV from clamav.net to enable this engine.)",
                stringExecutablePathOrEndpoint: _clamScanExecutablePath,
                MaturityTier: MaturityTier
            );
        }

        return new EngineDescriptor(
            EngineId: EngineId,
            DisplayName: DisplayName,
            License: License,
            Status: EngineStatus.Ready,
            StatusDetail: $"READY (Verified external ClamAV scanner at '{_clamScanExecutablePath}')",
            stringExecutablePathOrEndpoint: _clamScanExecutablePath,
            MaturityTier: MaturityTier
        );
    }

    public async Task<ScanFinding?> ScanFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default)
    {
        if (!IsInstalled)
        {
            // Honest no-op when ClamAV is not installed; never fabricates a ClamAV result.
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();

        // SECURITY: Use ArgumentList (never shell concatenation) to prevent command injection via filenames.
        var psi = new ProcessStartInfo
        {
            FileName = _clamScanExecutablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("--no-summary");
        psi.ArgumentList.Add("--infected");
        psi.ArgumentList.Add(filePath);

        using var process = new Process { StartInfo = psi };
        process.Start();

        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        // ClamAV exit code 1 indicates virus(es) found: "<filepath>: <SignatureName> FOUND"
        if (process.ExitCode == 1 && !string.IsNullOrWhiteSpace(stdout))
        {
            string signatureName = "ClamAV.SignatureMatch";
            int colonIdx = stdout.LastIndexOf(':');
            if (colonIdx >= 0 && colonIdx + 1 < stdout.Length)
            {
                signatureName = stdout[(colonIdx + 1)..]
                    .Replace("FOUND", "", StringComparison.OrdinalIgnoreCase)
                    .Trim();
            }

            return new ScanFinding(
                FindingId: $"CLAM-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: Path.GetFileName(filePath),
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.Critical,
                Confidence: DetectionConfidence.VerifiedSignature,
                DetectionName: signatureName,
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: "ClamAV Local Signature Database",
                Description: $"ClamAV reported an infected signature match ('{signatureName}').",
                FalsePositiveGuidance: "If you believe this ClamAV signature is a false positive, verify the file SHA-256 against CIRCL hashlookup or submit a false-positive report to ClamAV.",
                DetectedAtUtc: DateTimeOffset.UtcNow
            );
        }

        return null;
    }
}

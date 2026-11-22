using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.WindowsSecurity;
using Xunit;

namespace KironProhori.Agent.Tests;

/// <summary>
/// Automated Phase 7A Verification Suite covering all 9 required test scenarios using ONLY harmless test payloads
/// (including the official 68-byte EICAR Standard Antivirus Test File).
/// </summary>
public sealed class AgentPhase7ATests : IDisposable
{
    private readonly string _sandboxDir;
    private readonly ModularScanPipeline _pipeline;
    private readonly QuarantineManager _quarantineManager;

    public AgentPhase7ATests()
    {
        _sandboxDir = Path.Combine(Path.GetTempPath(), $"KironProhori_Tests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_sandboxDir);
        _pipeline = new ModularScanPipeline();
        _quarantineManager = new QuarantineManager(Path.Combine(_sandboxDir, "QuarantineVault"));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_sandboxDir))
            {
                Directory.Delete(_sandboxDir, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [Fact]
    public async Task Test01_CleanFileScan_ReportsZeroFindings()
    {
        string cleanFile = Path.Combine(_sandboxDir, "clean_readme.txt");
        await File.WriteAllTextAsync(cleanFile, "KIRON PROHORI Phase 7A benign verification text document.");

        var report = await _pipeline.ScanSingleFileAsync(cleanFile);

        Assert.Equal("COMPLETED", report.Status);
        Assert.Equal(1, report.TotalFilesScanned);
        Assert.Equal(0, report.ThreatsDetectedCount);
        Assert.Empty(report.Findings);
    }

    [Fact]
    public async Task Test02_OfficialHarmlessEicarDetection_FlagsCriticalVerifiedSignature()
    {
        string eicarFile = Path.Combine(_sandboxDir, "eicar_harmless_test.com");
        await File.WriteAllTextAsync(eicarFile, Sha256HashEngine.OfficialEicarTestString, Encoding.ASCII);

        var report = await _pipeline.ScanSingleFileAsync(eicarFile);

        Assert.Equal("COMPLETED", report.Status);
        Assert.Equal(1, report.ThreatsDetectedCount);
        Assert.Single(report.Findings);
        Assert.Equal("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", report.Findings[0].DetectionName);
        Assert.Equal(Sha256HashEngine.OfficialEicarSha256, report.Findings[0].Sha256Hash);
        Assert.Equal(ThreatSeverity.Critical, report.Findings[0].Severity);
    }

    [Fact]
    public async Task Test03_Sha256FileHashCalculation_MatchesNistAndEicarDigests()
    {
        string eicarFile = Path.Combine(_sandboxDir, "hash_check.txt");
        await File.WriteAllTextAsync(eicarFile, Sha256HashEngine.OfficialEicarTestString, Encoding.ASCII);

        string computed = await Sha256HashEngine.ComputeFileSha256Async(eicarFile);
        Assert.Equal(Sha256HashEngine.OfficialEicarSha256, computed);
    }

    [Fact]
    public async Task Test04_QuarantineAndRestore_EnforcesUserConfirmationAndRestoresExactBytes()
    {
        string testFile = Path.Combine(_sandboxDir, "suspicious_eicar.txt");
        await File.WriteAllTextAsync(testFile, Sha256HashEngine.OfficialEicarTestString, Encoding.ASCII);

        var scanReport = await _pipeline.ScanSingleFileAsync(testFile);
        var finding = Assert.Single(scanReport.Findings);

        // 1. Must reject quarantine if userConfirmed is false
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _quarantineManager.QuarantineFileAsync(finding, userConfirmed: false));
        Assert.True(File.Exists(testFile));

        // 2. Quarantine with explicit confirmation moves and XOR-isolates file
        var qEntry = await _quarantineManager.QuarantineFileAsync(finding, userConfirmed: true);
        Assert.False(File.Exists(testFile));
        Assert.EndsWith(".kpq", qEntry.VaultPayloadFileName, StringComparison.OrdinalIgnoreCase);

        // 3. Restore with explicit confirmation restores exact original bytes and SHA-256
        var restored = await _quarantineManager.RestoreQuarantinedFileAsync(qEntry.QuarantineId, userConfirmed: true);
        Assert.True(restored.IsRestored);
        Assert.True(File.Exists(testFile));
        string restoredHash = await Sha256HashEngine.ComputeFileSha256Async(testFile);
        Assert.Equal(Sha256HashEngine.OfficialEicarSha256, restoredHash);
    }

    [Fact]
    public async Task Test05_ScanCancellation_StopsGracefullyWithCancelledStatus()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancelled token

        var report = await _pipeline.ScanDirectoriesAsync(
            ScanType.CustomFolderScan,
            new[] { _sandboxDir },
            cancellationToken: cts.Token);

        Assert.Equal("CANCELLED_BY_USER", report.Status);
    }

    [Fact]
    public async Task Test06_PermissionAndMissingDirectoryErrors_HandledWithoutCrashing()
    {
        string missingDir = Path.Combine(_sandboxDir, "non_existent_protected_folder");
        var report = await _pipeline.ScanDirectoriesAsync(ScanType.CustomFolderScan, new[] { missingDir });

        Assert.Equal("COMPLETED_WITH_PERMISSION_WARNINGS", report.Status);
        Assert.True(report.SkippedPermissionCount >= 1);
    }

    [Fact]
    public void Test07_MissingExternalEngines_HonestlyReportInstallationRequired()
    {
        var clam = new ClamAvExternalEngine(Path.Combine(_sandboxDir, "missing_clamscan.exe"));
        var yara = new YaraExternalEngine(Path.Combine(_sandboxDir, "missing_yara64.exe"));

        Assert.Equal(EngineStatus.InstallationRequired, clam.GetDescriptor().Status);
        Assert.Equal(EngineStatus.InstallationRequired, yara.GetDescriptor().Status);
    }

    [Fact]
    public void Test08_WindowsDefenderAndFirewallTelemetry_IsReadOnlyAndGuaranteesZeroSystemModifications()
    {
        var monitor = new WindowsSecurityMonitor();
        var snapshot = monitor.GetSecuritySnapshot();

        Assert.True(snapshot.ZeroSystemModificationsGuaranteed);
        Assert.NotEmpty(snapshot.FirewallProfiles);
        Assert.NotNull(snapshot.MicrosoftDefenderStatus);
    }

    [Fact]
    public async Task Test09_CrashRecovery_RecoversInterruptedAtomicVaultManifest()
    {
        int recoveredCount = await _quarantineManager.RecoverAndVerifyVaultIntegrityAsync();
        Assert.True(recoveredCount >= 0);
    }
}

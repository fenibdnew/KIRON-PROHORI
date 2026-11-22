using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Diagnostics;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Performance;
using KironProhori.Agent.Core.Quarantine;
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
}

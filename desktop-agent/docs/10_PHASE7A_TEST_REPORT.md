# KIRON PROHORI — Phase 7A Automated Verification & Test Report

- **Product:** KIRON PROHORI — Windows Security & Antivirus
- **Developer:** ARIFUZZAMAN
- **Test Policy:** Strictly tested using benign files and the official 68-byte harmless **EICAR Standard Antivirus Test File**. Zero live malware samples are ever used.

---

## 1. Summary of the 14 Phase 7A Verification Scenarios

| Test ID | Scenario Tested | Component Under Test | Expected Outcome | Result |
| :--- | :--- | :--- | :--- | :--- |
| **`TEST-01`** | **Microsoft Defender Status & On-Demand Integration** | `WindowsSecurityMonitor.cs` | Reads Defender status, RTP state, signature version, firewall profiles, admin role check, and constructs safe `MpCmdRun.exe` arguments with `ZeroSystemModificationsGuaranteed = true`. | **`PASSED`** |
| **`TEST-02`** | **Quick Scan (High-Risk User Directories + EICAR)** | `ModularScanPipeline.cs` | Scans target folder, detects 68-byte EICAR test file (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) as `ConfirmedDetection`. | **`PASSED`** |
| **`TEST-03`** | **Full Scan & Reparse-Point Loop Guard** | `ModularScanPipeline.cs` | Traverses directory tree, skips NTFS symlinks/reparse points, and distinguishes `ConfirmedDetection`, `Suspicious`, `Unknown`, and `CleanAccordingToAvailableEngines`. | **`PASSED`** |
| **`TEST-04`** | **Custom Folder & Individual File Scan** | `ModularScanPipeline.cs` & `HeuristicSuspiciousFileEngine.cs` | Flags deceptive double extension (`Invoice_2026.pdf.exe`) as `Suspicious` with explicit false-positive guidance. | **`PASSED`** |
| **`TEST-05`** | **Exclusion Manager (Skip Scan & Block Quarantine)** | `ExclusionManager.cs` | Requires `userConfirmed = true` + risk disclosure; excluded path is skipped by scanner and blocked from quarantine; never alters Microsoft Defender exclusions. | **`PASSED`** |
| **`TEST-06`** | **Quarantine with Mandatory User Confirmation** | `QuarantineManager.cs` | Rejects `userConfirmed = false`; isolates confirmed file into `.kpq` via XOR keystream and records JSON manifest + audit log. | **`PASSED`** |
| **`TEST-07`** | **Quarantine Restore & SHA-256 Integrity Check** | `QuarantineManager.cs` | Restores `.kpq` payload after confirmation and verifies restored SHA-256 equals original SHA-256 byte-for-byte. | **`PASSED`** |
| **`TEST-08`** | **Smart Notification Sound & Volume Control** | `SmartNotificationManager.cs` | Synthesizes original gentle notification tone once per detection event; respects `SoundEnabled` mute toggle and `VolumePercent` (`0–100`). | **`PASSED`** |
| **`TEST-09`** | **Duplicate Notification Anti-Spam Suppression** | `SmartNotificationManager.cs` | Suppresses duplicate alerts for identical `SHA256 + FilePath` within the deduplication cooldown window. | **`PASSED`** |
| **`TEST-10`** | **100% Offline Privacy-First Operation** | `ModularScanPipeline.cs` & `CloudThreatFeedSyncService.cs` | Defaults to `CloudSyncEnabledByDefault = false`; local SHA-256, EICAR, heuristic scanning, exclusions, and quarantine operate with zero network activity. | **`PASSED`** |
| **`TEST-11`** | **Update Verification (HTTPS, SHA-256 Tamper Rejection & Rollback)** | `SecureUpdateManager.cs` | Rejects `http://` URLs and tampered SHA-256 payloads (`TAMPERED_UPDATE_REJECTED`); creates atomic backup and supports one-click rollback. | **`PASSED`** |
| **`TEST-12`** | **Permission & Locked File Error Resilience** | `ModularScanPipeline.cs` | Catches `UnauthorizedAccessException` and `IOException`, increments `SkippedPermissionCount`, and completes scan without crashing. | **`PASSED`** |
| **`TEST-13`** | **Low-Resource Scanning (CPU Throttle, Pause/Resume & Unchanged File Cache)** | `PerformanceProtectionGuard.cs` | Supports cooperative `Pause()` / `Resume()`, skips unchanged clean files via `UnchangedFileScanCache`, and throttles concurrency under high load or battery power. | **`PASSED`** |
| **`TEST-14`** | **Application Crash Recovery & Self-Repair Diagnostics** | `ErrorDiagnosticsManager.cs` | Logs local diagnostics without auto-upload, recovers interrupted `.tmp` manifests, and restores corrupted config from `.known_good` backup. | **`PASSED`** |

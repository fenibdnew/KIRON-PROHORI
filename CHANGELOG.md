# Changelog (`CHANGELOG.md`)

All notable changes to **KIRON PROHORI** are documented in this file.

## [1.0.0] — 2026-11-24

### Added
- **Phase 0 & Phase 1 Foundation (`LocalSecurityAuditRepository.cs`)**:
  - `WindowsPlatformCompatibilityDetector` verifying Windows 10 (`x86`/`x64`, Build 19041+) and Windows 11 (`x64`, Build 22000+) support with honest user-mode vs. kernel-minifilter status reporting.
  - `ProcessAndMemorySecurityInspector` providing running process execution-path risk analysis while protecting critical Windows system processes (`lsass`, `csrss`, `svchost`, `wininit`, `explorer`, etc.) from automatic termination.
  - `SystemCleanupPreviewInspector` providing read-only temporary file cleanup previews and requiring explicit user approval while preserving browser passwords, cookies, and personal documents.
  - `LocalSecurityAuditRepository` persisting timestamped security records separated by disposition (`Detected`, `Blocked`, `Quarantined`, `Removed`, `Unresolved`) with **CSV** and **JSON** export.
- **Core Antivirus, Real-Time Guard & Ransomware Shield**:
  - 64 KB streaming SHA-256 engine (`Sha256HashEngine`), explainable 0–100 local heuristic engine (`HeuristicSuspiciousFileEngine`), multi-mode scanner (`ModularScanPipeline`), XOR `.kpq` Quarantine Vault (`QuarantineManager`), user-mode `FileSystemWatcher` real-time monitor (`RealTimeFileProtectionMonitor`), and behavioral ransomware monitor (`RansomwareShieldMonitor`).
- **Internet Security, Safe Banking & Smart Firewall**:
  - Chrome & Microsoft Edge Manifest V3 web protection extension + Native Messaging 4-state download scanner (`NativeMessagingDownloadGuard`), Safe Banking URL verifier (`SafeBankingProtectionModule`), Email Attachment scanner (`EmailAttachmentSecurityScanner`), and read-only Windows Firewall / TCP monitor with user-approved rule builder (`WindowsSecurityMonitor`).
  - Transparent master `kp-logo.png` (`1024x1024`), multi-DPI variants (`32–512px`), 6-frame `KironProhori.ico` (`16–256px`), high-DPI WPF UI (`MainWindow.xaml`), Windows Background Service (`KironProhoriSecurityService`), and Inno Setup installer (`KironProhoriSetup.iss`) with Windows Explorer `"Scan with KIRON PROHORI"` context menu integration.
- **Phases 5–8 Advanced Defense, Cloud/Privacy, QA & Release Engineering**:
  - Parent-child LOLBin behavioral process detection, user-mode memory & loaded module scanning, driver/service persistence rootkit path audit, read-only DEP/ASLR/SEHOP/UAC exploit mitigation audit, and explainable 0–100 layered threat scoring.
  - RSA-2048 SHA-256 signed security update verification, atomic `.known_good` rollback, zero-telemetry Privacy Dashboard summary, user-approved temporary file cleanup, and CSV/JSON disposition-separated security reports.
  - 32 automated xUnit tests (`AgentPhase7ATests.cs`), Windows 10 (`win-x86` & `win-x64`) and Windows 11 (`win-x64`) release packaging, `SHA256SUMS.txt` manifest generation & verification (`Phase8ReleasePackagingManager`), and automated GitHub Release publication (`windows-build-and-release.yml`).

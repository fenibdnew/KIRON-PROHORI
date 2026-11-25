# KIRON PROHORI V1.0 — Phase 0 Project Audit & Engineering State (`PROJECT_STATE.md`)

**Product:** KIRON PROHORI V1.0  
**Category:** Windows 10 & Windows 11 Antivirus & Internet Security Suite + Threat Intelligence Web Dashboard  
**Developer & Architect:** ARIFUZZAMAN KIRON  
**License & Budget Policy:** $0 Free Forever · Zero Paid API Dependencies · Zero Telemetry by Default

---

## 1. Frameworks, Dependencies & Current Architecture

### A. Windows Desktop Application, Background Service & Core Engine (`/desktop-agent/`)
- **Solution:** `desktop-agent/KironProhori.DesktopAgent.sln` (C# 12 / .NET 8.0 LTS)
- **Projects & Frameworks:**
  1. `KironProhori.Agent.Core` (`net8.0`):
     - Dependencies: `System.Management (8.0.0)`, `System.Security.Cryptography.ProtectedData (8.0.0)`
     - Source Modules:
       - `Scanning/Sha256HashEngine.cs`: 64 KB incremental streaming SHA-256 hashing (`IncrementalHash.CreateHash(HashAlgorithmName.SHA256)`) and verified known-threat lookup (`TryLookupKnownThreat`).
       - `Scanning/HeuristicSuspiciousFileEngine.cs`: Explainable local 0–100 risk score (Shannon entropy, unsigned PE headers, double extensions, obfuscated PowerShell/WScript/cmd, browser credential infostealer patterns, fake AI app masquerade droppers, USB shortcut worms).
       - `Scanning/ModularScanPipeline.cs`: Quick Scan, Full Scan, Custom Folder Scan, Single File Scan, USB Drive Scan, CLI `--scan-path` parser, pause/resume/cancel orchestration, and non-destructive hidden USB folder recovery (`RecoverHiddenUsbFolders`).
       - `Realtime/RealTimeFileProtectionMonitor.cs`: User-mode `FileSystemWatcher` monitor (`Downloads`, `Desktop`, `Startup`, `%TEMP%`) with 400ms debounce queue.
       - `Realtime/RansomwareShieldMonitor.cs`: Behavioral mass-modification and `.locked`/`.encrypted` rapid-rename detection on protected folders + harmless isolated simulation.
       - `Quarantine/QuarantineManager.cs`: Quarantine-First isolation into XOR-encoded `.kpq` payloads with JSON metadata, SHA-256 integrity check, path-traversal guard, restore workflow, and explicit user-approved permanent deletion.
       - `Exclusions/ExclusionManager.cs`: Canonical path, extension, and hash exclusion store with self-exclusion protection.
       - `BrowserProtection/NativeMessagingDownloadGuard.cs`: Chrome/Edge Native Messaging length-prefixed JSON protocol, local phishing/malvertising URL reputation engine, and 4-state download scanner (`Clean`, `Suspicious`, `Malicious`, `UnknownNotScanned`).
       - `WindowsSecurity/WindowsSecurityMonitor.cs`: Strictly read-only Microsoft Defender WMI (`MSFT_MpComputerStatus`, `ROOT\SecurityCenter2`) and Windows Firewall registry monitor, supported `MpCmdRun.exe` on-demand scan runner, `Start-MpWDOScan` offline rootkit scan bridge, active TCP connection & C2 port inspector, and user-approved `netsh advfirewall` outbound block rule builder.
       - `WindowsSecurity/PrivacyProtectionMonitor.cs`: Read-only Windows `CapabilityAccessManager\ConsentStore` webcam and microphone access monitor.
       - `WindowsSecurity/AdvancedSuiteModules.cs`: `SafeBankingProtectionModule`, `EmailAttachmentSecurityScanner`, and `PrivacyFirstCloudThreatIntelligenceService`.
       - `Updates/SecureUpdateManager.cs`: HTTPS manifest validation, RSA-2048 SHA-256 signature verification, rollback on invalid definitions, and offline-safe operation.
       - `Performance/PerformanceProtectionGuard.cs`: Eco-Power green computing mode (`BelowNormal` thread priority, CPU > 40% and battery throttling).
       - `Notifications/SmartNotificationManager.cs`: Threat notifications with 280ms 440Hz sine-wave chime and toast cooldowns.
       - `Diagnostics/ErrorDiagnosticsManager.cs` & `Diagnostics/LocalSecurityAuditRepository.cs`: Self-healing config/quarantine store verification, Windows 10 (`x86`/`x64`) & Windows 11 (`x64`) platform compatibility detector (`WindowsPlatformCompatibilityDetector`), running process risk & critical Windows process guard (`ProcessAndMemorySecurityInspector`), user-approved temporary file cleanup preview (`SystemCleanupPreviewInspector`), and local security audit database with **CSV** and **JSON** export (`LocalSecurityAuditRepository`).
  2. `KironProhori.Agent.Desktop` (`net8.0-windows10.0.19041.0`, `UseWPF=true`, `UseWindowsForms=true`):
     - Source Files: `App.xaml`, `App.xaml.cs`, `MainWindow.xaml`, `MainWindow.xaml.cs`, `app.manifest`, and high-DPI assets (`Assets/KironProhori.ico` 16–256px, `Assets/kp-logo.png` 1024x1024, `Assets/kp-logo-32..512.png`, `Assets/kp-logo.svg`).
  3. `KironProhori.Agent.Service` (`net8.0-windows10.0.19041.0`, Worker Service):
     - Dependencies: `Microsoft.Extensions.Hosting (8.0.0)`, `Microsoft.Extensions.Hosting.WindowsServices (8.0.0)`
     - Source File: `Program.cs` (`KironProhoriSecurityService` hosting real-time user-mode monitoring and local Named Pipe IPC server `KironProhori.SecurityService.Ipc.v1`).
  4. `KironProhori.Agent.Tests` (`net8.0`, xUnit):
     - Source File: `AgentPhase7ATests.cs` (32 automated xUnit tests covering Phases 1–8, unit/integration, Windows 10/11 compatibility, performance, security review, install/uninstall, and release packaging).

### B. Existing Web Threat Intelligence Dashboard (`/src`, `/server.ts`, `/tests/run-all.ts`)
- **Framework:** React 19 + TypeScript + Vite 8 + Tailwind CSS 4 + Express 4 (`server.ts`)
- **Capabilities:**
  - Live keyless threat intelligence connectors (`/src/connectors/`): CISA Known Exploited Vulnerabilities (KEV), NIST NVD 2.0, FIRST EPSS, and abuse.ch Feodo Tracker (`$0.00` runtime cost).
  - Interactive Windows Desktop Agent Architecture & Verification Center (`/api/agent/v1/verify-suite` — 23/23 automated backend verification checks).
  - Phase 6 QA, Security & Zero-Cost Verification Suite (`/tests/run-all.ts` — 34/34 automated checks).

### C. Official GitHub Pages Website (`/docs/website/`)
- **Files:** `docs/website/index.html`, `docs/website/app.js`, `docs/website/assets/kp-logo.png` (`1024x1024` + `32..512px` variants), `docs/website/assets/favicon.ico`, `docs/website/assets/kp-logo.svg`.
- **Capabilities:** 10-section static download center querying `api.github.com/repos/fenibdnew/KIRON-PROHORI/releases/latest` dynamically and displaying honest release/checksum status.

### D. Chrome & Microsoft Edge Manifest V3 Browser Extension (`/browser-extension/`)
- **Files:** `manifest.json`, `background/service-worker.js`, `blocked/blocked.html`, `popup/popup.html`, `rules/declarative-net-request-rules.json`, `native-host/register-native-host.ps1`.

### E. Build Scripts, Installers & GitHub Actions Workflows
- **GitHub Actions Workflows (`.github/workflows/`):**
  1. `windows-build-and-release.yml`: Runs `verify-web-platform` (`ubuntu-latest`, 34/34 checks) followed by `build-windows-x64` (`windows-latest`, enforces `STABLE_V1_0` Authenticode signing gate, runs all 32 `dotnet test` xUnit tests, publishes `KironProhori.Agent.Desktop` and `KironProhori.Agent.Service` for both `win-x64` and Windows 10 `win-x86`, compiles `KIRON-PROHORI-Setup-x64.exe` via Inno Setup 6, packages `KIRON-PROHORI-Portable-win-x64.zip` and `KIRON-PROHORI-Portable-win-x86.zip`, and generates `SHA256SUMS.txt`).
  2. `deploy-github-pages.yml`: Packages and deploys `/docs/website` to GitHub Pages.
- **Installer & Release Scripts (`/desktop-agent/installer/`):**
  1. `build-windows-installer.ps1`: Local PowerShell release build, xUnit runner, optional `signtool.exe` Authenticode signer, Inno Setup compiler, and SHA-256 manifest generator.
  2. `inno-setup/KironProhoriSetup.iss`: Inno Setup 6 installer script configuring `{app}`, `KironProhoriSecurityService` (`sc.exe` delayed-auto start & crash recovery), Desktop/Start Menu shortcuts, Windows Explorer `"Scan with KIRON PROHORI"` context menu (`Drive`, `Directory`, `*`), and user-consented uninstall data preservation.
  3. `wix/Product.wxs`: WiX v4 MSI enterprise installer definition.

---

## 2. Module-by-Module Status Matrix (Modules 01–15)

| Module | Feature Scope | Current Status | Notes & Honest Boundaries |
| :--- | :--- | :--- | :--- |
| **01. Real-Time Antivirus** | User-mode `FileSystemWatcher` + 64 KB SHA-256 + heuristics | **WORKING (User-Mode)** | Kernel WDK minifilter is explicitly marked `NOT_IMPLEMENTED`. |
| **02. Scan Engine** | Quick, Full, Custom Folder, Single File, USB Scan + Pause/Resume/Cancel + `MpCmdRun.exe` | **WORKING** | Identifies engine used (`KironProhori` vs `Microsoft Defender`). |
| **03. USB Protection** | Removable drive detection, `Autorun.inf`/`.lnk` worm detection, hidden folder recovery | **WORKING** | Never formats or deletes USB user data automatically. |
| **04. Quarantine & Removal** | XOR `.kpq` vault, SHA-256 verification, restore, user-confirmed permanent delete | **WORKING** | Enforces path-traversal protection and Quarantine-First policy. |
| **05. Ransomware Protection** | Mass-modification & rapid `.locked`/`.encrypted` rename detection + harmless simulation | **WORKING (User-Mode)** | Alerts and logs behavioral anomalies without touching personal files. |
| **06. Web & Phishing Guard** | Local phishing/malvertising blocklist, IDN/redirect checks, Chrome/Edge MV3 + 4-state download scan | **WORKING** | Local privacy-first lookup; zero automatic file uploads. |
| **07. Firewall Integration** | Read-only Domain/Private/Public profile telemetry, active TCP C2 port check, user-approved `netsh` rule builder | **WORKING** | Never disables Windows Firewall or modifies rules without consent. |
| **08. Behavioral / Heuristics** | Parent-child LOLBin spawn detection (`EvaluateParentChildProcessBehavior`) + explainable 0–100 layered threat scoring (`ComputeExplainableLayeredThreatScore`) | **WORKING** | Deterministic local heuristic & behavioral engine; never falsely labeled cloud AI. |
| **09. Rootkit & Exploit Audit** | Driver/service persistence path audit (`AuditDriverAndServicePersistencePath`), DEP/ASLR/SEHOP/UAC read-only audit (`AuditExploitMitigationBaseline`), and `Start-MpWDOScan` bridge | **WORKING (User-Mode Foundation)** | Kernel-level driver rootkit removal is explicitly marked `Planned` (requires signed WDK driver). |
| **10. Memory & Process Scanner** | Loaded module & process-injection indicator scanner (`ScanProcessMemoryAndModuleIndicators`), `%TEMP%`/`Downloads` execution risk check, critical process guard | **WORKING (User-Mode)** | Hard-blocks automatic termination of critical Windows system processes. |
| **11. Tamper Protection** | Self-healing JSON store diagnostics, vault path guard, RSA-2048 update verification | **WORKING (User-Mode)** | Protects config/vault integrity without locking out Administrator. |
| **12. Automatic Cloud Updates** | HTTPS manifest check, RSA-2048 PKCS#1 SHA-256 signature verification (`VerifyRsa2048Sha256Signature`), `.known_good` atomic rollback (`RollbackToPreviousVersionAsync`) | **WORKING** | Operates 100% offline-safe (`EvaluateOfflineSafeUpdateStatus`) when disconnected. |
| **13. Privacy & System Cleanup** | Read-only webcam/mic consent dashboard (`GetPrivacyDashboardSummary`) + user-approved temp cleanup (`ExecuteUserApprovedTempCleanup`) | **WORKING** | Zero telemetry by default; never deletes personal documents, browser passwords, or cookies. |
| **14. Security Reports & History** | Local audit database with disposition breakdown (`GetDispositionSummaryBreakdown`) & disk export (`ExportReportsToDirectoryAsync`) | **WORKING** | Separates `Detected`, `Blocked`, `Quarantined`, `Removed`, and `Unresolved` in **CSV** and **JSON**. |
| **15. Security Dashboard** | High-DPI WPF desktop UI (`MainWindow.xaml`) + Web Threat Intelligence Dashboard | **WORKING** | Displays real system state and text-only About page (no founder photo). |

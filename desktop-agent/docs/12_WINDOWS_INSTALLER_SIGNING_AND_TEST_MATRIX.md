# KIRON PROHORI V1.0 — Windows Installer, Code Signing Strategy & Test Matrix

**Product**: KIRON PROHORI — Windows Security & Antivirus V1.0  
**Developer & Publisher**: ARIFUZZAMAN KIRON  
**Target Platform**: Windows 10 x64 (Build 19041+) and Windows 11 x64  
**Budget Policy**: Strict `$0` for development; transparent production code-signing strategy documented below.

---

## 1. Windows Application & Background Service Architecture

The Windows Desktop Security Suite in `/desktop-agent/` consists of four `.NET 8.0` (`win-x64`) projects in `KironProhori.DesktopAgent.sln`:

1. **`KironProhori.Agent.Core`** (`/desktop-agent/src/KironProhori.Agent.Core/`):
   - **Scan Manager** (`LocalScanCoordinator.cs`): Quick Scan, Full Scan, Custom Folder/File Scan, USB Drive Scan, SHA-256 calculation, 4-tier verdict distinction (`ConfirmedDetection`, `Suspicious`, `Unknown`, `CleanAccordingToAvailableEngines`).
   - **Real-Time Protection Engine** (`RealTimeFileProtectionMonitor.cs`): User-mode `FileSystemWatcher` guard on Downloads, Temp, and Windows Startup directories.
   - **Quarantine Manager** (`QuarantineVaultManager.cs`): Enforces `QUARANTINE FIRST` policy with XOR-obfuscated `.kpq` isolation and requires a separate user confirmation before permanent deletion.
   - **Update Manager** (`SecureUpdateManager.cs`): Enforces HTTPS-only transport, publisher identity verification, X.509/RSA signature verification, SHA-256 integrity checks, and atomic `.known_good` rollback.
   - **Notification Manager** (`SmartNotificationManager.cs`): Windows notifications with a gentle 280 ms sound, duplicate suppression, and `Suspicious Download Blocked` alerts.
   - **Browser Integration Manager** (`NativeMessagingDownloadGuard.cs`): Chrome & Edge Native Messaging stdio host (`4-byte little-endian` framing) for URL evaluation, malicious ad/redirect blocking, temporary allowlists, false-positive reporting, and 4-state download scanning (`Clean`, `Suspicious`, `Malicious`, `Unknown / Not scanned`).
   - **Settings & Exclusions Manager** (`ExclusionManager.cs`): Canonical path validation, blocks dangerous root/wildcard/`.exe` exclusions, and never modifies Microsoft Defender exclusions.
2. **`KironProhori.Agent.Desktop`** (`/desktop-agent/src/KironProhori.Agent.Desktop/`):
   - Modern dark-slate WPF desktop application (`KironProhori.Desktop.exe`) with 18 views from `Dashboard` through `About`.
3. **`KironProhori.Agent.Service`** (`/desktop-agent/src/KironProhori.Agent.Service/`):
   - Windows Background Service (`KironProhori.Service.exe`, service name `KironProhoriSecurityService`) using `Microsoft.Extensions.Hosting.WindowsServices` and a local Named Pipe IPC endpoint (`KironProhori.SecurityService.Ipc.v1`).
4. **`KironProhori.Agent.Tests`** (`/desktop-agent/tests/KironProhori.Agent.Tests/`):
   - Automated xUnit verification suite covering all engines, Native Messaging framing, update rollback, and installer safety boundaries.

---

## 2. Production Installer Architecture (`EXE` & `MSI`)

We provide two industry-standard Windows x64 installer definitions:

1. **Inno Setup 6 Wizard (`KIRON-PROHORI-Setup-x64.exe`)**:
   - Located at `/desktop-agent/installer/inno-setup/KironProhoriSetup.iss`.
   - Enforces `ArchitecturesAllowed=x64compatible`, `MinVersion=10.0.19041`, and `PrivilegesRequired=admin` (UAC elevation prompt).
   - Allows installation directory selection (defaulting to `C:\Program Files\KIRON PROHORI`).
   - Optional tasks for Desktop shortcut, Start Menu shortcut, Windows sign-in tray launch, `KironProhoriSecurityService` installation (`sc.exe create ... start= delayed-auto`), and user-consented Browser Extension setup guide.
   - **Safe Uninstall (`CurUninstallStepChanged`)**: Stops and deletes `KironProhoriSecurityService`, removes only application-owned files under `{app}`, prompts the user for explicit consent before preserving or removing `%LOCALAPPDATA%\KironProhori` (Quarantine Vault & Settings), and **never** deletes unrelated user files.
2. **WiX Toolset v4 MSI Package (`KIRON-PROHORI-Setup-x64.msi`)**:
   - Located at `/desktop-agent/installer/wix/Package.wxs`.
   - Supports Clean Installation, Major Upgrade (`MajorUpgrade`), Repair Installation, and `ServiceInstall`/`ServiceControl` lifecycle management.

---

## 3. Code Signing Strategy (Development vs. Production)

> **CRITICAL SECURITY RULE**: Never use a self-signed certificate as a production trust solution. Windows SmartScreen and Defender will flag self-signed executables distributed over the internet as untrusted, and installing a private root CA on end-user machines creates a severe security risk.

### A. Development & Local VM Testing Strategy (`$0` Budget)
- **Mode 1 (`UNSIGNED_DEV`)**: Local developer builds compiled via `dotnet publish` for testing on the developer's own Windows 10/11 machine or VM.
- **Mode 2 (`DEV_TEST_CERT`)**: Isolated Windows VM testing using a local test certificate restricted strictly to an offline test VM snapshot to test `signtool.exe` and `X509Certificate2` verification paths. Never distributed to external users.

### B. Production Global Distribution Strategy (`PROD_TRUSTED_CA`)
Before promoting any build to the **Stable V1.0** release channel for public download in Bangladesh and worldwide, binaries (`KironProhori.Desktop.exe`, `KironProhori.Service.exe`) and the installer (`KIRON-PROHORI-Setup-x64.exe` / `.msi`) must be signed using one of:
1. **Microsoft Azure Trusted Signing** or an **OV / EV Code Signing Certificate** issued by a publicly trusted Certificate Authority in the Microsoft Root Certificate Program (e.g., DigiCert, Sectigo, GlobalSign, SSL.com) stored on a FIPS 140-2 Level 2+ hardware token / cloud HSM.
2. **Timestamping**: Every signature must include an RFC-3161 SHA-256 timestamp (`/tr http://timestamp.digicert.com /td SHA256`) so signatures remain valid after certificate expiration.
3. **Microsoft Defender SmartScreen Submission**: Submit the signed `KIRON-PROHORI-Setup-x64.exe` to the Microsoft Security Intelligence Developer Portal (`https://www.microsoft.com/en-us/wdsi/filesubmission`) prior to public release to establish SmartScreen reputation.

---

## 4. Windows 10 & Windows 11 x64 Verification Test Matrix

| ID | Test Scenario | Target OS | Expected Behavior | Verification Method |
|---|---|---|---|---|
| **M-01** | Clean Installation | Win 10 / 11 x64 | Installs to `C:\Program Files\KIRON PROHORI`, registers `KironProhoriSecurityService`, creates shortcuts | Inno Setup / WiX MSI log + Service status check |
| **M-02** | Upgrade Installation | Win 10 / 11 x64 | Stops existing service, replaces binaries atomically, preserves `%LOCALAPPDATA%\KironProhori` quarantine vault | WiX `MajorUpgrade` & Inno Setup upgrade test |
| **M-03** | Repair Installation | Win 10 / 11 x64 | Restores missing/corrupted application binaries and self-heals JSON config via `DiagnosticRecoveryManager` | `msiexec /fa` + `TEST-12-SELF-HEALING-CONFIG` |
| **M-04** | Safe Uninstallation | Win 10 / 11 x64 | Stops & deletes service, removes only `{app}` binaries, prompts user before touching `%LOCALAPPDATA%\KironProhori`, never deletes unrelated files | Inno Setup `[UninstallRun]` + `[Code]` audit |
| **M-05** | UAC Permission Handling | Win 10 / 11 x64 | Installer requests `admin` elevation; Desktop UI runs standard user-mode scans without crashing on permission-denied system files | `PrivilegesRequired=admin` + `TEST-03` |
| **M-06** | Windows Defender Coexistence | Win 10 / 11 x64 | Read-only WMI queries; zero `Set-MpPreference` calls; Defender remains primary registered Windows AV | `TEST-01-DEFENDER-COEXISTENCE` |
| **M-07** | Browser Extension Installation | Chrome / Edge x64 | User-consented installation only; blocks verified malicious/phishing/ad-redirect domains via Manifest V3 | `TEST-15-BROWSER-WEB-PROTECTION` |
| **M-08** | Native Messaging IPC | Chrome / Edge x64 | 4-byte little-endian stdio framing with 1 MB payload cap between browser and local agent | `TEST-17-NATIVE-MESSAGING-FRAMING` |
| **M-09** | Download Scanning (4-State) | Win 10 / 11 x64 | Classifies completed downloads as `Clean`, `Suspicious`, `Malicious`, or `Unknown / Not scanned` (never marks incomplete scans as Clean) | `TEST-16-DOWNLOAD-PROTECTION-4STATE` |
| **M-10** | Quarantine & Restore | Win 10 / 11 x64 | Enforces `QUARANTINE FIRST`; isolates `.kpq` file; permanent delete requires separate confirmation | `TEST-06` & `TEST-07` |
| **M-11** | Update Integrity & Rollback | Win 10 / 11 x64 | Enforces HTTPS, publisher identity, digital signature, and SHA-256 hash; rolls back `.known_good` on failure | `TEST-10-SECURE-UPDATE-AND-ROLLBACK` |
| **M-12** | Offline Operation | Win 10 / 11 x64 | Local SHA-256 signature engine, heuristic scanner, quarantine vault, and browser rules work 100% offline | Offline scan & URL evaluation check |
| **M-13** | EICAR Safe Test File | Win 10 / 11 x64 | Detects standard 68-byte EICAR string (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) without real malware | `TEST-02-QUICK-SCAN-EICAR` |

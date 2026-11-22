# KIRON PROHORI (কিরণ প্রহরী) — Windows Endpoint Security Agent (Phase 7A)

- **Target OS:** Windows 10 (64-bit) & Windows 11 (64-bit)
- **Framework:** C# 12 / .NET 8.0 (`net8.0` Core Engine + `net8.0-windows10.0.19041.0` WPF Desktop UI)
- **Budget:** Strict `$0.00` (Zero paid APIs, zero paid cloud dependencies, zero mandatory subscriptions)
- **Co-Existence Guarantee:** Passive user-mode companion agent. Never disables Microsoft Defender, never disables Windows Firewall, never modifies Windows Security policies, never installs unsigned kernel drivers, and never silently deletes files.

---

## Project Structure

```text
desktop-agent/
├── KironProhori.DesktopAgent.sln
├── README.md
├── docs/
│   ├── 01_DESKTOP_ARCHITECTURE.md
│   ├── 02_DEPENDENCIES_AND_LICENSING.md
│   ├── 03_THREAT_MODEL.md
│   ├── 04_WINDOWS_COMPATIBILITY_PLAN.md
│   ├── 05_MINIFILTER_KERNEL_DRIVER_RESEARCH.md
│   └── 06_BUILD_AND_TEST_INSTRUCTIONS.md
├── src/
│   ├── KironProhori.Agent.Core/
│   │   ├── KironProhori.Agent.Core.csproj
│   │   ├── Models/ScanModels.cs
│   │   ├── Scanning/
│   │   │   ├── IScanEngine.cs
│   │   │   ├── Sha256HashEngine.cs
│   │   │   ├── HeuristicSuspiciousFileEngine.cs
│   │   │   ├── ClamAvExternalEngine.cs
│   │   │   ├── YaraExternalEngine.cs
│   │   │   ├── CloudThreatFeedSyncService.cs
│   │   │   └── ModularScanPipeline.cs
│   │   ├── Quarantine/QuarantineManager.cs
│   │   ├── WindowsSecurity/WindowsSecurityMonitor.cs
│   │   ├── Scheduling/ScheduledScanCoordinator.cs
│   │   └── Localization/BilingualStrings.cs
│   └── KironProhori.Agent.Desktop/
│       ├── KironProhori.Agent.Desktop.csproj
│       ├── app.manifest
│       ├── App.xaml
│       ├── App.xaml.cs
│       ├── MainWindow.xaml
│       └── MainWindow.xaml.cs
└── tests/
    └── KironProhori.Agent.Tests/
        ├── KironProhori.Agent.Tests.csproj
        └── AgentPhase7ATests.cs
```

---

## Honest Feature Maturity Matrix

1. **Working Features (Phase 7A User-Mode MVP):**
   - Quick Scan, Full Scan, Custom Folder Scan, Single File Scan, and USB Removable Drive Scan.
   - Native streaming FIPS SHA-256 file hash computation.
   - EICAR Standard Antivirus Test File detection (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) and local SHA-256 indicator matching.
   - Static heuristic detection for deceptive double extensions (`.pdf.exe`, `.docx.scr`), RTLO spoofing, and executable droppers in temporary folders (with explicit false-positive guidance).
   - Modular external engine adapters for **ClamAV** (`clamscan.exe`) and **YARA / YARA-X** (`yr.exe` / `yara64.exe`). Reports `INSTALLATION_REQUIRED` when not installed on the endpoint.
   - Safe Quarantine Manager with mandatory user confirmation before quarantine, restore, or permanent deletion, XOR payload isolation (`.kpq`), original metadata preservation, and append-only audit logging.
   - Read-only Windows Security Center, Microsoft Defender (`MSFT_MpComputerStatus`), and Windows Firewall profile telemetry.
   - Optional one-way read-only signature sync with KIRON PROHORI Intelligence Cloud (`/api/agent/v1/signatures`).
   - Bilingual UI (English & বাংলা) and Dual Theme (Dark Slate & Light High-Contrast).
2. **Experimental Features (Phase 7A User-Mode):**
   - User-mode `FileSystemWatcher` for the `%USERPROFILE%\Downloads` directory (post-write alert only).
   - User-mode Scheduled Scan helper & `schtasks.exe` command builder.
3. **Future Roadmap (Phase 7B / Phase 8 — Documented in `docs/05_MINIFILTER_KERNEL_DRIVER_RESEARCH.md`):**
   - Kernel-mode File System Minifilter Driver (`FltMgr.sys`, `IRP_MJ_CREATE` pre-execution blocking).
   - Extended Validation (EV) Hardware Code Signing & Microsoft WHQL Hardware Lab Kit (HLK) attestation.
   - Early Launch Anti-Malware (ELAM) & Protected Process Light (`PPL`) service hardening.

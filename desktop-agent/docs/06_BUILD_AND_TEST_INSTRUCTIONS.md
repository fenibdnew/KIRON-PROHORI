# KIRON PROHORI — Phase 7A: Build, Verification & Safe EICAR Test Instructions

- **Target Platform:** Windows 10 & Windows 11 (64-bit / `win-x64`)
- **Required Toolchain on Windows Host:** [.NET 8.0 SDK (v8.0.100 or newer)](https://dotnet.microsoft.com/download/dotnet/8.0) — Free (`$0.00`), MIT Licensed.

> **Transparency Notice:** The Google AI Studio preview server runs in a Linux container (`x86_64`). Therefore, no pre-compiled Windows `.exe` binary is fabricated in this repository. Follow the exact commands below on a Windows 10 or Windows 11 (64-bit) machine to compile, test, and run the native WPF Desktop Agent, or use the live **Phase 7A Endpoint Agent Sandbox & Verification Console** inside the web application to run all 9 test scenarios immediately.

---

## 1. Building the Solution on Windows 10 / Windows 11 (64-bit)

Open **PowerShell** or **Windows Terminal** (Standard User — Administrator elevation is **not** required) and run:

```powershell
# 1. Navigate to the desktop-agent directory
cd desktop-agent

# 2. Restore NuGet packages ($0 MIT-licensed official Microsoft & xUnit packages)
dotnet restore KironProhori.DesktopAgent.sln

# 3. Compile Core Engine, WPF Desktop Application, and xUnit Test Suite in Release mode
dotnet build KironProhori.DesktopAgent.sln -c Release

# 4. Run the 9 Automated Phase 7A Security & Safety Verification Tests
dotnet test tests/KironProhori.Agent.Tests/KironProhori.Agent.Tests.csproj -c Release --logger "console;verbosity=detailed"
```

### Publishing a Standalone Windows 64-bit Release Package (`win-x64`)
```powershell
dotnet publish src/KironProhori.Agent.Desktop/KironProhori.Agent.Desktop.csproj `
  -c Release `
  -r win-x64 `
  --self-contained false `
  -o ./publish/win-x64
```
The compiled executable will be produced at:
`desktop-agent\publish\win-x64\KironProhori.Agent.Desktop.exe`

---

## 2. Safe Testing Protocol (Harmless EICAR Standard Antivirus Test File Only)

> **CRITICAL SAFETY RULE:** **NEVER** test KIRON PROHORI using live malware samples, ransomware payloads, or trojans. Use **only** benign files and the industry-standard, completely harmless **EICAR Standard Antivirus Test File**.

### 2.1 Official EICAR Test String Specification
The official 68-byte ASCII EICAR test string is:
```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
- **Expected SHA-256 Digest:**
  `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
- **Expected Detection ID:**
  `EICAR-Test-File (Harmless Standard Verification Signature)`

### 2.2 The 9 Mandatory Phase 7A Test Scenarios

All 9 test cases are implemented in `desktop-agent/tests/KironProhori.Agent.Tests/AgentPhase7ATests.cs` and mirrored in the Web App's `/api/agent/v1/sandbox-scan` verification runner:

1. **Test 1 — Clean File Scan:**
   - Creates a temporary benign text file (`"KIRON PROHORI clean verification document"`).
   - Verifies `ModularScanPipeline` returns `0` detections, `IsClean == true`, and exact file size/SHA-256 telemetry.
2. **Test 2 — Harmless EICAR Antivirus Test File Detection:**
   - Passes the 68-byte EICAR standard test payload to `ModularScanPipeline`.
   - Verifies detection with `Severity = CRITICAL`, `DetectionName = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"`, `DetectionSource = "KIRON-SHA256-EICAR-ENGINE"`, and `IsExecutableExecuted = false`.
3. **Test 3 — Streaming SHA-256 File Hash Calculation:**
   - Verifies exact FIPS 180-4 SHA-256 hex digest generation for empty payloads, clean files, and the 68-byte EICAR string (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`).
4. **Test 4 — Quarantine & Restore with Mandatory User Confirmation Gate:**
   - Verifies that calling `QuarantineFileAsync(..., userConfirmed: false)` is **rejected** (`InvalidOperationException`) so no file is ever silently moved or deleted.
   - Verifies that calling `QuarantineFileAsync(..., userConfirmed: true)` isolates the file as `.kpq` with reversible XOR neutralization, removes it from the original path, records the JSON manifest and audit log, and `RestoreQuarantinedFileAsync(..., userConfirmed: true)` restores the exact original bytes and SHA-256 hash.
5. **Test 5 — Cooperative Scan Cancellation:**
   - Triggers a multi-file folder scan with a `CancellationTokenSource` cancelled mid-flight.
   - Verifies the pipeline halts cleanly with `Status = "CANCELLED_BY_USER"` and preserves partial scan metrics without throwing an unhandled exception.
6. **Test 6 — Permission Error & Inaccessible Path Resilience:**
   - Simulates an inaccessible/locked file path during directory enumeration.
   - Verifies the scanner increments `SkippedPermissionCount`, logs the warning, and completes the rest of the scan without crashing.
7. **Test 7 — Missing External Scanning Engine (`ClamAV` / `YARA-X`) Honest Status:**
   - Points `ClamAvExternalEngine` and `YaraExternalEngine` to a non-existent binary path.
   - Verifies both engines honestly report `EngineStatus.InstallationRequired` (`"INSTALLATION_REQUIRED"`) rather than faking a scan result.
8. **Test 8 — Read-Only Windows Defender & Firewall Status Detection:**
   - Calls `WindowsSecurityMonitor.GetSecuritySnapshot()`.
   - Verifies read-only telemetry structure (`DefenderStatus`, `RealTimeProtectionState`, `FirewallProfiles`, `OsArchitecture`, `ZeroSystemModificationsGuaranteed = true`).
9. **Test 9 — Application Crash Recovery & Atomic Manifest Persistence:**
   - Simulates an interrupted scan checkpoint and verifies `QuarantineManager.RecoverAndVerifyVaultIntegrity()` restores consistent vault state from disk without data loss.

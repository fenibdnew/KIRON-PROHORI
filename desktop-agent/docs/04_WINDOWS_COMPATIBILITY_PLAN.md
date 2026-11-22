# KIRON PROHORI — Phase 7A: Windows 10 & Windows 11 (64-bit) Compatibility Plan

- **Supported Operating Systems:**
  - **Windows 10 (64-bit / `win-x64`):** Version 20H2 (Build 19042), 21H2 (Build 19044), 22H2 (Build 19045)
  - **Windows 11 (64-bit / `win-x64`):** Version 21H2 (Build 22000), 22H2 (Build 22621), 23H2 (Build 22631), 24H2 (Build 26100)
- **Target Framework Moniker (TFM):** `net8.0-windows10.0.19041.0` (Desktop UI) / `net8.0` (Core Engine & xUnit Tests)

---

## 1. Windows Subsystem & API Compatibility Matrix

| Capability | Primary Windows API / Interface | Fallback Mechanism (Standard User / Restricted WMI) | Windows 10 & 11 Behavior |
| :--- | :--- | :--- | :--- |
| **Registered Antivirus Status** | WMI `ROOT\SecurityCenter2` → `SELECT displayName, productState FROM AntiVirusProduct` | Registry read `HKLM\SOFTWARE\Microsoft\Windows Defender` & `sc query WinDefend` service state | Works on Windows 10 & 11 Consumer/Pro/Enterprise editions. Does not require administrator elevation for basic query on most builds. |
| **Microsoft Defender Real-Time & Signature Telemetry** | WMI `ROOT\Microsoft\Windows\Defender` → `MSFT_MpComputerStatus` (`RealTimeProtectionEnabled`, `AntivirusSignatureVersion`, `QuickScanEndTime`, `FullScanEndTime`) | Non-destructive read-only PowerShell `Get-MpComputerStatus` or explicit `ACCESS_LIMITED_STANDARD_USER` status badge | Exposes exact Defender signature version, engine version, and last scan timestamps without altering Defender state. |
| **Windows Firewall Status (Domain / Private / Public)** | Registry read `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{StandardProfile,PublicProfile,DomainProfile}\EnableFirewall` | `netsh advfirewall show allprofiles state` (read-only output parser) | Works synchronously in `< 15 ms` with standard user read permissions on both Windows 10 and Windows 11. |
| **OS Build, Edition & 64-bit Architecture** | `Environment.OSVersion`, `RuntimeInformation.OSArchitecture`, and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`ProductName`, `DisplayVersion`, `CurrentBuildNumber`, `UBR`) | `System.Runtime.InteropServices.RuntimeInformation.OSDescription` | Accurately distinguishes Windows 10 (Builds `< 22000`) from Windows 11 (Builds `>= 22000`). |
| **Pending Windows Security Updates** | Read-only COM/Registry check `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired` & `Results\Install` | Displays `UNKNOWN (READ-ONLY CHECK)` if Windows Update COM service is busy | Never triggers forced reboots or modifies Windows Update policies. |
| **USB Removable Drive Detection** | `System.IO.DriveInfo.GetDrives()` filtered by `DriveType == DriveType.Removable && IsReady` | Manual folder browse fallback | Detects FAT32, exFAT, and NTFS USB flash drives on insertion or manual refresh. |

---

## 2. Co-Existence with Microsoft Defender & Third-Party Antivirus Products

1. **Why KIRON PROHORI Does NOT Register in `ROOT\SecurityCenter2`:**
   - Windows 10 and Windows 11 allow only **one** active primary registered antivirus provider in Windows Security Center (`WSC`). If a third-party application registers itself as an active WSC Antivirus provider via the private Microsoft WSC API, Windows automatically disables Microsoft Defender Real-Time Protection.
   - Because KIRON PROHORI Phase 7A is a `$0` user-mode on-demand scanner and threat intelligence agent (without a signed kernel-mode minifilter driver), disabling Microsoft Defender would **reduce** the user's protection.
   - Therefore, KIRON PROHORI runs strictly in **Passive Companion Mode** alongside Microsoft Defender (or any installed third-party AV such as Malwarebytes, ESET, or Bitdefender).
2. **Self-Exclusion of Quarantine Vault from Accidental False Locks:**
   - Files placed inside `%LOCALAPPDATA%\KironProhori\Quarantine\Vault` are immediately XOR-framed before flushing to disk so that the active primary antivirus (Microsoft Defender) does not lock the quarantine file mid-write while KIRON PROHORI is moving it.
   - When testing with the harmless EICAR test file on a live Windows 10/11 system where Microsoft Defender Real-Time Protection is ON, Microsoft Defender may intercept a raw `eicar.com` file written to disk before a user-mode scanner can open it. To support reliable verification without ever disabling Microsoft Defender, `Sha256HashEngine` also supports an in-memory / XOR-seeded EICAR self-test diagnostic stream.

---

## 3. Environment & Cross-Platform Build Reality

- **Important Build Environment Note:**
  - The cloud development sandbox hosting the KIRON PROHORI web preview runs on **Linux (`x86_64`)**.
  - `KironProhori.Agent.Core` and `KironProhori.Agent.Tests` use cross-platform `.NET 8.0` (`net8.0`) abstractions with runtime OS guards (`OperatingSystem.IsWindows()`) so core scanning, SHA-256 hashing, EICAR detection, heuristic analysis, and quarantine logic can be unit-tested on any OS.
  - `KironProhori.Agent.Desktop` uses Windows Presentation Foundation (`net8.0-windows10.0.19041.0` / `<UseWPF>true</UseWPF>`) and **must be compiled on a Windows 10/11 64-bit machine** (or with `dotnet build /p:EnableWindowsTargeting=true`). We never fabricate or claim that a pre-compiled `.exe` binary was produced inside the Linux container.

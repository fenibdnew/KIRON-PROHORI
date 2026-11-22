# KIRON PROHORI — Installation & Setup Guide (Windows 10 / Windows 11 x64)

- **Product:** KIRON PROHORI — Windows Security & Antivirus
- **Developer:** ARIFUZZAMAN
- **Supported OS:** Windows 10 (64-bit, Version 20H2 / Build 19042 or later) & Windows 11 (64-bit, 21H2–24H2)
- **License & Cost:** `$0.00` (Zero registration, zero telemetry, zero subscription)

---

## 1. System Prerequisites

1. **Operating System:** Windows 10 (64-bit) or Windows 11 (64-bit).
2. **Runtime:** [.NET 8.0 Desktop Runtime (x64)](https://dotnet.microsoft.com/download/dotnet/8.0) (or `.NET 8.0 SDK` to build from source).
3. **Optional External Open-Source Scanning Engines (Not Bundled):**
   - **ClamAV for Windows (Optional):** Download official `clamav-<version>.win.x64.msi` from [clamav.net](https://www.clamav.net/downloads) and install to `C:\Program Files\ClamAV\`. If not installed, KIRON PROHORI operates using its built-in SHA-256, Heuristic, and Microsoft Defender integration engines and displays `INSTALLATION_REQUIRED` for ClamAV.
   - **YARA / YARA-X for Windows (Optional):** Place `yara64.exe` or `yr.exe` in `C:\Program Files\YARA\`.

---

## 2. Building & Installing from Source on Windows 10 / 11 (x64)

```powershell
# 1. Clone the repository and open the desktop-agent folder
cd desktop-agent

# 2. Restore dependencies and build in Release mode
dotnet restore KironProhori.DesktopAgent.sln
dotnet build KironProhori.DesktopAgent.sln -c Release

# 3. Run the 14 automated Phase 7A verification tests (Harmless EICAR only)
dotnet test tests/KironProhori.Agent.Tests/KironProhori.Agent.Tests.csproj -c Release

# 4. Publish the Windows x64 Desktop Application
dotnet publish src/KironProhori.Agent.Desktop/KironProhori.Agent.Desktop.csproj `
  -c Release `
  -r win-x64 `
  --self-contained false `
  -o .\publish\win-x64
```

Launch the desktop application by running:
```powershell
.\publish\win-x64\KironProhori.Agent.Desktop.exe
```

---

## 3. First-Run Privacy & Co-Existence Verification

1. **No Account or Internet Required:** KIRON PROHORI starts immediately in **Offline Privacy-First Mode** (`CloudSyncEnabled = false`).
2. **Microsoft Defender Co-Existence Check:** Open **10. Windows Defender Status** in the left navigation bar to verify that Microsoft Defender and Windows Firewall remain active and unmodified.
3. **Harmless EICAR Verification:** Click **Harmless EICAR Verification** in the top toolbar to test local detection, notification chime, exclusion handling, and quarantine/restore confirmation gates safely.
4. **Uninstallation & Clean Removal:** To uninstall, delete the published `win-x64` directory and optionally remove `%LOCALAPPDATA%\KironProhori` after restoring or deleting any items in your Quarantine Vault.

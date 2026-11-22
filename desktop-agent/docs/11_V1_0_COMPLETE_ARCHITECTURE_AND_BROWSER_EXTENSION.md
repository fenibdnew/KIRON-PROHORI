# KIRON PROHORI V1.0 — Complete Three-Component Security Architecture

**Product Name:** KIRON PROHORI  
**Version:** 1.0.0  
**Developer:** ARIFUZZAMAN KIRON  
**Target Platform:** Windows 10 and Windows 11, x64 (`net8.0-windows10.0.19041.0`)  
**Browser Targets:** Google Chrome & Microsoft Edge (Manifest V3)  
**Budget Policy:** STRICT $0 (Free, open-source, and locally operating components)  
**Privacy Policy:** NO TELEMETRY BY DEFAULT · Zero Browsing-History Collection · Zero Automatic File Upload  
**Threat Removal Policy:** QUARANTINE FIRST (Permanent deletion requires a separate user confirmation)

---

## 1. Three Connected Components

1. **KIRON PROHORI Threat Intelligence Web Dashboard (`/src/`, `/server.ts`, `/firebase/`)**
   - Multi-source cyber threat intelligence platform integrating CISA KEV, NIST NVD API 2.0, FIRST EPSS, abuse.ch Feodo Tracker Botnet C2 Blocklist, CIRCL Public Hashlookup, optional abuse.ch URLhaus, and GitHub Security Advisories (GHSA).
2. **KIRON PROHORI Windows Desktop Security Agent (`/desktop-agent/`)**
   - Native C# 12 / .NET 8.0 modular scanning engine (`KironProhori.Agent.Core`) and Windows WPF Desktop UI (`KironProhori.Agent.Desktop`).
   - Includes Quick Scan, Full Scan, Custom Scan, USB Scan, Single File Scan, Folder Scan, Streaming 64 KB SHA-256 Hash Engine, Static Heuristic Engine, ClamAV & YARA External CLI Adapters, Real-Time User-Mode File Protection (`RealTimeFileProtectionMonitor`), Quarantine Vault (`.kpq`), Exclusions (`ExclusionManager`), Scheduled Scanning (`ScheduledScanCoordinator`), HTTPS Signed Updates with Rollback (`SecureUpdateManager`), Read-Only Microsoft Defender & Windows Firewall Monitoring (`WindowsSecurityMonitor`), Smart Notifications with 280 ms Gentle Chime (`SmartNotificationManager`), and Self-Repairing Error Diagnostics (`ErrorDiagnosticsManager`).
3. **KIRON PROHORI Chrome & Microsoft Edge Browser Protection Extension (`/browser-extension/`)**
   - Manifest V3 extension using browser-supported `declarativeNetRequest` static and dynamic rules (`verified_malicious_rules.json`).
   - Blocks verified malicious URLs, phishing domains, scam/malware distribution hosts, malicious ad redirects, and malicious third-party network requests without collecting browsing history or blocking legitimate websites with ordinary advertisements.
   - Provides a safe blocked-page interface (`blocked/blocked.html`) showing the exact reason for blocking, False Positive reporting, and a user-controlled 30-minute Temporary Allowlist.
   - Connects to the local Windows Desktop Agent via Chrome/Edge Native Messaging (`com.kironprohori.security_agent`) to scan browser downloads locally upon completion and distinguish:
     - `Clean`
     - `Suspicious`
     - `Malicious`
     - `Unknown / Not scanned` (Never reports a file as `Clean` if the scan did not complete).

---

## 2. Environment & Build Disclosure

- **Current AI Studio Preview Host:** Linux x86_64 container running Node.js + Express + Vite on port 3000.
- **Honest Build Disclosure:** Windows `.exe` binaries (`net8.0-windows10.0.19041.0` WPF) and Windows Registry (`HKCU:\Software\Google\Chrome\NativeMessagingHosts`) cannot be compiled into native Windows executables inside a Linux container. No fake `.exe` binary is fabricated.
- **How to Build on Windows 10/11 x64:**
  ```powershell
  cd desktop-agent
  dotnet restore KironProhori.DesktopAgent.sln
  dotnet build KironProhori.DesktopAgent.sln -c Release
  dotnet test KironProhori.DesktopAgent.sln -c Release
  ```
- **How to Load the Browser Extension in Chrome or Microsoft Edge:**
  1. Open `chrome://extensions` or `edge://extensions`.
  2. Enable **Developer mode**.
  3. Click **Load unpacked** and select the `/browser-extension` directory.
  4. On Windows 10/11, run `powershell -ExecutionPolicy Bypass -File browser-extension\native-host\register-native-host.ps1` to register the local Native Messaging host under `HKCU`.

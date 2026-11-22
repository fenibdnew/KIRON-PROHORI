# KIRON PROHORI — Phase 7A: Technical Dependency & Third-Party Licensing Audit

- **Budget Policy:** Strict `$0.00` (Zero commercial royalties, zero paid SDKs, zero paid API subscriptions)
- **Distribution Compliance:** All dependencies and external engine integrations have been audited for commercial and open-source redistribution rules prior to integration.

---

## 1. Runtime & Framework Dependencies (.NET 8.0)

| Component / Package | Version | License | Cost | Usage in KIRON PROHORI Windows Agent | Distribution Compliance Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Microsoft .NET 8.0 SDK & Desktop Runtime (`Microsoft.NET.Sdk.WindowsDesktop`)** | `8.0.x` (LTS) | **MIT License** | `$0.00` | Core C# 12 runtime, WPF UI framework, `System.IO`, `System.Security.Cryptography`, `System.Text.Json`, `System.Threading.Channels`. | Freely redistributable under Microsoft .NET Library License / MIT terms. |
| **`System.Management` (NuGet)** | `8.0.0` | **MIT License** | `$0.00` | Read-only WMI / CIM queries against `ROOT\SecurityCenter2` and `ROOT\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`). | Official Microsoft package under MIT License. |
| **`System.Security.Cryptography.ProtectedData` (NuGet)** | `8.0.0` | **MIT License** | `$0.00` | Windows Data Protection API (DPAPI) user-scoped encryption for local quarantine metadata and configuration settings. | Official Microsoft package under MIT License. |
| **`Microsoft.NET.Test.Sdk` & `xunit`** | `17.9.0` / `2.7.0` | **MIT / Apache-2.0** | `$0.00` | Automated unit and integration testing of EICAR detection, SHA-256 hashing, quarantine/restore confirmation gates, and scan cancellation. | Test-only dependency; not shipped in end-user binary. |

---

## 2. External Scanning Engines & Public Threat Intelligence Feeds

| Engine / Intelligence Source | Integration Method | License | Cost | Auth Required? | Architectural & Legal Isolation Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Built-in SHA-256 & EICAR Engine (`Sha256HashEngine`)** | Native in-process C# (`System.Security.Cryptography.SHA256`) | **First-Party (Apache-2.0 / MIT)** | `$0.00` | **No** | Uses official EICAR standard antivirus test string SHA-256 (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) and public SHA-256 indicators. |
| **2. ClamAV (`clamscan.exe` / `clamd`)** | **Optional External CLI Process Adapter** (`ClamAvExternalEngine.cs`) | **GPL-2.0** (External Binary Installed Separately by User) | `$0.00` | **No** | **CRITICAL LICENSE BOUNDARY:** KIRON PROHORI does **not** link against `libclamav.dll` or bundle GPLv2 ClamAV binaries inside the installer. The agent checks if the user has installed official ClamAV at `C:\Program Files\ClamAV\clamscan.exe`. If absent, the UI displays **`INSTALLATION_REQUIRED`**. When installed, it invokes `clamscan.exe --no-summary` as an isolated child process over standard output. |
| **3. YARA / YARA-X (`yr.exe` / `yara64.exe`)** | **Optional External CLI Process Adapter** (`YaraExternalEngine.cs`) | **BSD-3-Clause** (VirusTotal / YARA authors) | `$0.00` | **No** | Permissive 3-Clause BSD license allows both external CLI invocation and rule evaluation. If `yr.exe` or `yara64.exe` is not installed on the endpoint, the agent reports **`INSTALLATION_REQUIRED`**. |
| **4. CISA Known Exploited Vulnerabilities (KEV) Catalog** | Read-only JSON sync via KIRON PROHORI Cloud or direct CISA feed | **U.S. Government Public Domain (17 U.S.C. § 105)** | `$0.00` | **No** | Unrestricted public domain usage. Required attribution to CISA is displayed in the Updates & Reports views. |
| **5. abuse.ch Feodo Tracker Botnet C2 IP Blocklist** | Read-only JSON sync via KIRON PROHORI Cloud (`ipblocklist.json`) | **CC0 1.0 Universal (Public Domain Dedication)** | `$0.00` | **No** | Keyless public feed (`https://feodotracker.abuse.ch/downloads/ipblocklist.json`). Explicit source attribution (`abuse.ch Feodo Tracker`) included. |
| **6. CIRCL hashlookup Public API** | Optional user-triggered SHA-256 REST query (`hashlookup.circl.lu`) | **Public Open Service (CIRCL Computer Incident Response Center Luxembourg)** | `$0.00` | **No** | Queries known-good (NSRL) and known-file SHA-256 hashes without requiring an API key or uploading any file content. |
| **7. abuse.ch URLhaus / ThreatFox / MalwareBazaar** | Optional via KIRON PROHORI Cloud Proxy when `URLHAUS_AUTH_KEY` is configured | **CC0 1.0 (Community Terms Apply)** | `$0.00` | **Optional `Auth-Key`** | Strictly optional. Never blocks agent startup or local scanning. Displays `NOT CONFIGURED` if `URLHAUS_AUTH_KEY` is not configured on the Intelligence Cloud server. |

---

## 3. Prohibited Dependencies (Enforced Guardrails)

1. **No Unlicensed Commercial AV SDKs:** No proprietary OEM engines (Bitdefender SDK, Avira SAVAPI, Kaspersky SDK, VirusTotal Commercial Private API) are used or referenced.
2. **No Unsigned Kernel Drivers:** Zero `.sys` drivers are compiled or loaded.
3. **No Paid Telemetry / Crash Services:** No Sentry, Datadog, Application Insights, or paid cloud logging libraries are included. All logs remain locally on the user's machine under `%LOCALAPPDATA%\KironProhori\Logs`.

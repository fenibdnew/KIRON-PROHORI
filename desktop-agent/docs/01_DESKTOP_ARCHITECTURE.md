# KIRON PROHORI — Phase 7A: Dual-Plane System Architecture
## Independent Cyber Threat Intelligence Cloud & Windows Endpoint Security Agent

- **Project:** KIRON PROHORI (কিরণ প্রহরী)
- **Phase:** Phase 7A (Safe User-Mode MVP & Modular Scanning Engine)
- **Target OS:** Windows 10 (64-bit, Build 19042+) & Windows 11 (64-bit, 21H2–24H2)
- **Budget Constraint:** Strict `$0.00` (Zero paid APIs, zero paid cloud infrastructure, zero mandatory subscriptions, zero paid code-signing claims)

---

## 1. Executive Architectural Overview

KIRON PROHORI operates as two independent, decoupled product planes that can function standalone or synchronize over read-only HTTPS / loopback REST endpoints:

```text
+-----------------------------------------------------------------------------------+
| COMPONENT A: KIRON PROHORI INTELLIGENCE CLOUD (Web Application - Existing)        |
| React 19 + TypeScript + Express + Firebase Firestore (No-Cost Spark Tier)         |
|                                                                                   |
|  [01 Dashboard]  [02 CVE Explorer]  [03 CISA KEV]   [04 Malware Intel (Feodo/CIRCL)]|
|  [05 Scam/Phish] [06 Advisories]    [07 URL Tool]   [08 SHA-256 Hash Tool]        |
|  [09 Checklist]  [10 Report Center] [11 Watchlist]  [12 Notifications]            |
|  [13 Sources]    [14 Admin Center]  [15 Settings]   [16 Docs & Endpoint Agent Hub]|
|                                                                                   |
|  Read-Only Agent Signature & Feed Sync API:                                       |
|  GET /api/agent/v1/manifest   |   GET /api/agent/v1/signatures                    |
+-----------------------------------------+-----------------------------------------+
                                          |
                         Optional Read-Only HTTPS / Loopback Sync
                         (Zero Private File Uploads · Zero Telemetry Leakage)
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| COMPONENT B: KIRON PROHORI WINDOWS SECURITY AGENT (/desktop-agent)                |
| C# 12 + .NET 8.0 (net8.0-windows10.0.19041.0) · WPF Desktop UI + Core Engine      |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Presentation Layer (KironProhori.Agent.Desktop - WPF XAML)                  |  |
|  | - 13 Views: Security Overview, Quick Scan, Full Scan, Custom Scan, USB Scan,|  |
|  |   Protection Status, Threat History, Quarantine, Firewall Status,           |  |
|  |   Windows Security, Updates, Reports, Settings                              |  |
|  | - Bilingual (English / বাংলা) · Dual Theme (Dark Slate / Light High-Legibility)|
|  +--------------------------------------+--------------------------------------+  |
|                                         | In-Process / Named-Pipe IPC Contract    |
|  +--------------------------------------v--------------------------------------+  |
|  | Core Engine Layer (KironProhori.Agent.Core)                                 |  |
|  |                                                                             |  |
|  | 1. ModularScanPipeline                                                      |  |
|  |    ├── Sha256HashEngine (Native FIPS SHA-256 + EICAR + Local Hash DB)       |  |
|  |    ├── HeuristicSuspiciousFileEngine (Double extensions, temp droppers)     |  |
|  |    ├── ClamAvExternalEngine (Optional clamscan.exe CLI adapter)             |  |
|  |    ├── YaraExternalEngine (Optional yr.exe / yara64.exe CLI adapter)        |  |
|  |    └── CloudThreatFeedSyncService (Optional CISA KEV & Feodo C2 sync)       |  |
|  |                                                                             |  |
|  | 2. QuarantineManager (%LOCALAPPDATA%\KironProhori\Quarantine)               |  |
|  |    - Mandatory User Confirmation Gate (Quarantine / Restore / Delete)       |  |
|  |    - Non-executable .kpq payload isolation + JSON metadata manifest         |  |
|  |    - Immutable local audit trail (quarantine-audit.jsonl)                   |  |
|  |                                                                             |  |
|  | 3. WindowsSecurityMonitor (Strictly Read-Only WMI/CIM & Registry Queries)   |  |
|  |    - ROOT\SecurityCenter2 (Registered Antivirus & Firewall products)        |  |
|  |    - ROOT\Microsoft\Windows\Defender (MSFT_MpComputerStatus read-only)      |  |
|  |    - NetSecurity / Firewall Profile state (Domain, Private, Public)         |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Strict Scope & Honest Feature Maturity Classification

In compliance with KIRON PROHORI engineering rules, the Windows Security Agent never claims to provide commercial kernel-level antivirus replacement (such as Kaspersky, ESET, Norton, or Microsoft Defender replacement). Every module is badged in the UI and code with its exact maturity tier:

| Module / Capability | Phase 7A Maturity Tier | Operational Mechanism |
| :--- | :--- | :--- |
| **1. Quick Scan** | **`WORKING (PHASE 7A)`** | Enumerates high-risk user-mode directories (`%USERPROFILE%\Downloads`, `%TEMP%`, `%APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) with cancellation and progress telemetry. |
| **2. Full Scan** | **`WORKING (PHASE 7A)`** | Recursively scans fixed local volumes (`DriveType.Fixed`) while skipping NTFS reparse points/symlinks and handling `UnauthorizedAccessException` gracefully without crashing. |
| **3. Custom Folder Scan** | **`WORKING (PHASE 7A)`** | User-selected directory tree traversal with configurable depth and file-size bounds. |
| **4. Single File Scan** | **`WORKING (PHASE 7A)`** | Immediate on-demand SHA-256 hash computation, EICAR check, static heuristic check, and optional ClamAV/YARA invocation on a single file. |
| **5. USB Drive Scan** | **`WORKING (PHASE 7A)`** | Detects mounted `DriveType.Removable` volumes (`DriveInfo.GetDrives()`), checks for autorun abuse (`autorun.inf`, `.lnk` shortcut tricks), and scans all files on the removable drive. |
| **6. SHA-256 File Hash** | **`WORKING (PHASE 7A)`** | Native streaming `System.Security.Cryptography.SHA256` calculation (zero memory exhaustion on large files) + optional CIRCL hashlookup / local indicator match. |
| **7. Malware Detection (Known Indicators & EICAR)** | **`WORKING (PHASE 7A)`** | Detects official EICAR standard antivirus test file (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`), synced SHA-256 threat indicators, and delegates to ClamAV (`clamscan.exe`) when installed. If ClamAV is absent, explicitly displays `INSTALLATION_REQUIRED`. |
| **8. Suspicious File Detection** | **`WORKING (PHASE 7A)`** | Static user-mode heuristic analyzer flagging deceptive double extensions (`.pdf.exe`, `.jpg.scr`, `.docx.bat`), executable files hidden in `%TEMP%`, and unsigned script droppers, paired with clear false-positive warnings. |
| **9. Quarantine Manager** | **`WORKING (PHASE 7A)`** | Isolates confirmed files into `%LOCALAPPDATA%\KironProhori\Quarantine\Vault`, neutralizes headers via reversible XOR framing (`.kpq`), records original metadata, and enforces explicit user confirmation before quarantine, restore, or permanent deletion. |
| **10. Threat History & Audit Log** | **`WORKING (PHASE 7A)`** | Local append-only JSONL history of all detections, quarantine actions, restores, and scan runs. |
| **11. Scan Reports** | **`WORKING (PHASE 7A)`** | Exports structured JSON and CSV scan summaries with engine attribution, timestamps, duration, skipped-permission counts, and SHA-256 hashes. |
| **12. Security Status & Windows Security Integration** | **`WORKING (PHASE 7A)`** | Read-only WMI/CIM (`ROOT\SecurityCenter2`, `MSFT_MpComputerStatus`) queries for Microsoft Defender status, Real-Time Protection state, signature version, Windows Firewall profile state, and OS build architecture. |
| **13. Scheduled Scan** | **`EXPERIMENTAL (USER-MODE)`** | User-mode timer & Windows Task Scheduler XML/CLI command generator (`schtasks.exe /Create`) for daily/weekly background Quick Scans while the user session is active. |
| **14. Signature Update Status** | **`WORKING (PHASE 7A)`** | Pulls read-only signature metadata from KIRON PROHORI Intelligence Cloud (`/api/agent/v1/signatures`) and checks local Microsoft Defender `AntivirusSignatureVersion` / `freshclam` database timestamps. |
| **15. Real-Time Kernel File System Interception** | **`FUTURE ROADMAP (PHASE 7B/8)`** | Not implemented in Phase 7A. Documented in `05_MINIFILTER_KERNEL_DRIVER_RESEARCH.md` (requires EV Code Signing Certificate, Microsoft WHQL HLK attestation, and `FltMgr.sys` minifilter altitude). |

---

## 3. Local Inter-Process & Cloud Communication Security

1. **Zero Private File Upload Guarantee:**
   - The Windows Agent **never** uploads user files, documents, binaries, or file contents to theKIRON PROHORI Intelligence Cloud or any third-party service.
   - Cloud synchronization (`GET /api/agent/v1/signatures`) is strictly **one-way downward** (downloading public CISA KEV metadata, abuse.ch Feodo Tracker C2 IPs, and public malware SHA-256 hashes).
   - Optional SHA-256 reputation lookup sends **only** the 64-character hex SHA-256 digest when explicitly requested by the user.
2. **Crash Recovery & State Integrity:**
   - `App.xaml.cs` registers handlers for `DispatcherUnhandledException` and `AppDomain.CurrentDomain.UnhandledException`.
   - Active scan checkpoints and quarantine manifests are written atomically using write-temp-then-rename (`File.Move(tempPath, targetPath, overwrite: true)`) so an unexpected power loss or crash never corrupts the Quarantine Vault manifest.

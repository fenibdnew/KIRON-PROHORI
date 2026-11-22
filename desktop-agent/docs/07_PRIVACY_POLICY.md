# KIRON PROHORI — Privacy Policy (Phase 7A Windows Security Companion)

- **Product Name:** KIRON PROHORI
- **Subtitle:** Windows Security & Antivirus
- **Developer:** ARIFUZZAMAN
- **Platform:** Windows 10 / Windows 11 (64-bit / x64)
- **Default Privacy Posture:** **NO TELEMETRY BY DEFAULT · LOCAL-FIRST STORAGE**

---

## 1. Core Privacy Commitment

> *"Your privacy matters. Your security matters. Your trust matters. Built with care for a safer digital world."*

KIRON PROHORI is engineered from the ground up with a strict **Zero-Telemetry, Privacy-First Architecture**. Unlike commercial antivirus suites that continuously upload file metadata, browsing URLs, or usage telemetry to external servers, KIRON PROHORI keeps your endpoint data on your own computer.

### What KIRON PROHORI NEVER Does:
1. **No Telemetry or Analytics:** Zero background usage tracking, zero crash-report auto-uploads, and zero behavioral profiling.
2. **No Advertising or Trackers:** Zero third-party ad SDKs, tracking pixels, or monetization beacons.
3. **No Mandatory Registration:** No user account, email address, credit card, or license activation is required to use the Windows Desktop application.
4. **No Personal Data Collection:** Never collects your name, physical address, phone number, or device serial numbers.
5. **No Automatic File Uploads or Sample Submissions:** Scanned files and quarantined files **never** leave your computer.
6. **No Browser History or Password Collection:** Never hooks into web browsers, credential vaults, or clipboard managers.
7. **No Cloud Sync by Default:** Cloud threat feed synchronization is disabled by default (`CloudSyncEnabledByDefault = false`) and operates strictly on user request or opt-in schedule.

---

## 2. Local Data Storage Locations

All operational state is stored locally on your Windows drive under `%LOCALAPPDATA%\KironProhori\`:

| Data Type | Local Storage Path | Retention & User Control |
| :--- | :--- | :--- |
| **Scan History** | `%LOCALAPPDATA%\KironProhori\History\scan-history.jsonl` | Local JSONL file; user can export or clear at any time. |
| **KIRON Exclusions** | `%LOCALAPPDATA%\KironProhori\Exclusions\kiron-exclusions.json` | Local JSON manifest + `exclusion-audit.jsonl` audit trail. |
| **Quarantine Vault & Metadata** | `%LOCALAPPDATA%\KironProhori\Quarantine\quarantine-manifest.json` & `Vault\*.kpq` | Isolated local files; user controls restore or permanent deletion. |
| **Diagnostic & Recovery Logs** | `%LOCALAPPDATA%\KironProhori\Logs\diagnostics.jsonl` | Local-only diagnostic log; never transmitted over the network. |
| **Configuration & Backup** | `%LOCALAPPDATA%\KironProhori\Config\settings.json` (`settings.json.known_good`) | Local JSON configuration with automatic local rollback backup. |

---

## 3. Exhaustive Network Connection Disclosure

KIRON PROHORI makes **zero unsolicited background network connections** on startup. Internet access is permitted **ONLY** when explicitly initiated or enabled by the user for the following four purposes:

| Purpose | Destination Endpoint | Protocol | Data Transmitted | Frequency |
| :--- | :--- | :--- | :--- | :--- |
| **1. Verified Security Intelligence & Threat Feed Sync** | KIRON PROHORI Intelligence Cloud (`/api/agent/v1/signatures`), CISA KEV (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`), and abuse.ch Feodo Tracker (`https://feodotracker.abuse.ch/downloads/ipblocklist.json`) | HTTPS (`GET`) | Standard HTTP `GET` request headers only (`User-Agent: KIRON-PROHORI-Agent/0.7.0`). **Zero local file data transmitted.** | Manual user trigger or user-enabled schedule (Off by default). |
| **2. Application, Engine & YARA Ruleset Updates** | Configured HTTPS update manifest endpoint (`SecureUpdateManager.cs`) | HTTPS (`GET`) | Current version string check against signed SHA-256 manifest. | Manual user trigger or user-enabled schedule. |
| **3. User-Requested Online SHA-256 Hash Lookup** | CIRCL Public Hashlookup Service (`https://hashlookup.circl.lu/lookup/sha256/{sha256}`) | HTTPS (`GET`) | **Only** the 64-character hexadecimal SHA-256 hash string selected by the user. Never uploads the file itself. | Strictly on explicit user click ("Lookup SHA-256 Online"). |
| **4. Optional Community Feeds (When Configured)** | NIST NVD 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`) / FIRST EPSS (`https://api.first.org/data/v1/epss`) | HTTPS (`GET`) | Public CVE identifier query (e.g., `CVE-2024-xxxx`). | Strictly on explicit user query. |

---

## 4. Independence & Non-Affiliation Statement

KIRON PROHORI (developed by **ARIFUZZAMAN**) is an independent cybersecurity application. It is **not affiliated with, endorsed by, or sponsored by Microsoft Corporation, Cisco Systems (ClamAV), VirusTotal (YARA), CISA, or any commercial antivirus vendor**.

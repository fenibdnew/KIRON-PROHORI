# KIRON PROHORI — Phase 7A Security Model

- **Product:** KIRON PROHORI — Windows Security & Antivirus
- **Developer:** ARIFUZZAMAN
- **Platform:** Windows 10 & Windows 11 (x64)
- **Budget:** Strict `$0.00`

---

## 1. Security Design Principles

1. **Co-Existence & Non-Interference with Microsoft Defender:**
   - KIRON PROHORI operates as a **Privacy-First Windows Security Companion**.
   - It reads Microsoft Defender status (`MSFT_MpComputerStatus`), security intelligence version, last scan timestamps, and Windows Firewall profile states via supported Windows interfaces (`WMI/CIM`, registry read-only checks, and `MpCmdRun.exe` on-demand scan invocation).
   - It **never** registers as a replacement primary Antivirus in `ROOT\SecurityCenter2` (which would force Microsoft Defender into passive/disabled mode), **never** disables Windows Firewall, and **never** alters Windows Security policies.

2. **Four-Tier Honest Detection Verdict Classification:**
   Every inspected file is classified into one of four transparent categories—never claiming 100% malware detection:
   - **`ConfirmedDetection`**: Exact cryptographic SHA-256 signature match, official EICAR verification match, or verified ClamAV/YARA rule match.
   - **`Suspicious`**: Static heuristic anomaly (deceptive double extension like `.pdf.exe`, RTLO Unicode character `U+202E`, PE `MZ` header disguised inside a document extension, or `autorun.inf` on a USB drive). Always paired with false-positive guidance.
   - **`Unknown`**: File could not be fully evaluated (e.g., encrypted archive, locked OS handle, or external engine `INSTALLATION_REQUIRED`).
   - **`CleanAccordingToAvailableEngines`**: No threat indicators found across all currently enabled and installed scanning engines.

3. **Five-Option User-Controlled Threat Remediation:**
   - **Quarantine (Recommended Default after User Approval):** XOR-neutralizes the file into `%LOCALAPPDATA%\KironProhori\Quarantine\Vault\<id>.kpq`, preserves original metadata and SHA-256 hash, and logs the action.
   - **Restore:** De-isolates the `.kpq` payload back to disk after user confirmation and verifies that the restored file's SHA-256 matches the original SHA-256 byte-for-byte.
   - **Permanent Delete:** Permanently erases the isolated `.kpq` payload only after explicit user confirmation.
   - **Ignore Once:** Skips remediation for the current scan session while recording an audit entry.
   - **Add Exclusion:** Adds the canonical file or folder path to `ExclusionManager` after displaying a security risk warning and receiving explicit confirmation.

4. **Strict Separation of KIRON Exclusions vs. Microsoft Defender Exclusions:**
   - KIRON PROHORI maintains its own local exclusion store (`%LOCALAPPDATA%\KironProhori\Exclusions\kiron-exclusions.json`).
   - Adding or removing an exclusion in KIRON PROHORI **never** runs `Add-MpPreference -ExclusionPath` or silently weakens Microsoft Defender's exclusion list.

5. **Cryptographically Verified Update & Rollback Architecture:**
   - `SecureUpdateManager.cs` enforces HTTPS-only transport, verifies the downloaded package's SHA-256 hash against the signed update manifest before staging, rejects any mismatched or tampered file immediately, backs up the previous working configuration/rules as `.known_good`, installs atomically, and supports instant rollback.

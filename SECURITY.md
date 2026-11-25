# Security Policy & Vulnerability Reporting (`SECURITY.md`)

**Product:** KIRON PROHORI V1.0  
**Developer & Maintainer:** ARIFUZZAMAN KIRON

---

## 1. Core Security & Privacy Commitments

- **Zero Telemetry by Default:** KIRON PROHORI does not collect analytics, personal documents, browsing history, or credentials.
- **Zero Automatic File Uploads:** Suspicious or quarantined files are never automatically uploaded to external servers.
- **Coexistence First:** KIRON PROHORI never disables Microsoft Defender Antivirus, never disables Windows Firewall, and never modifies Windows Security Center registry keys.
- **Quarantine-First Policy:** Detected threats are isolated into the local `.kpq` Quarantine Vault; permanent file deletion always requires explicit user confirmation.
- **Cryptographic Update Verification:** Only RSA-2048 signed update manifests over HTTPS are accepted; unsigned or tampered packages are rejected with automatic rollback.

## 2. Supported Versions

| Version | Target Platforms | Supported |
| :--- | :--- | :--- |
| **V1.0.x** | Windows 10 (x86 / x64, Build 19041+) & Windows 11 (x64, Build 22000+) | Yes |

## 3. Reporting a Vulnerability or False Positive

1. **Private Vulnerability Disclosure:** Please report security vulnerabilities privately via the GitHub repository's **Security → Report a vulnerability** tab rather than opening a public issue with exploit details.
2. **False-Positive Reports:** If a legitimate file or domain is flagged by KIRON PROHORI heuristics, submit the **SHA-256 hash** (not the personal file itself) via GitHub Issues so the rule or signature can be audited.
3. **Checksum Verification:** Always verify downloaded installers (`KIRON-PROHORI-Setup-x64.exe`) against the official `SHA256SUMS.txt` published on GitHub Releases using:
   ```powershell
   Get-FileHash .\KIRON-PROHORI-Setup-x64.exe -Algorithm SHA256
   ```

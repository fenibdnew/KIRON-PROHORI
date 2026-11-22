# KIRON PROHORI — Phase 7A: Endpoint Security Agent Threat Model & Safety Invariants

- **Component:** KIRON PROHORI Windows Security Agent (`desktop-agent/`)
- **Security Posture:** Defensive, Co-Existent User-Mode Companion Agent
- **Core Principle:** First, Do No Harm to the Host Operating System or Existing Defenses

---

## 1. Non-Negotiable Windows Co-Existence & Safety Invariants

The KIRON PROHORI Windows Security Agent is engineered as a **cooperative, secondary user-mode security scanner and threat intelligence monitor**. It enforces six hard coded invariants:

1. **NEVER Disable or Weaken Microsoft Defender:**
   - The agent performs **read-only** queries against `ROOT\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`) and `ROOT\SecurityCenter2`.
   - It contains zero calls to `Set-MpPreference`, zero writes to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, and zero attempts to register as a primary Windows Security Center antivirus provider (which would cause Windows 10/11 to automatically snooze Microsoft Defender).
2. **NEVER Disable or Modify Windows Firewall:**
   - Firewall inspection reads profile state (`Domain`, `Private`, `Public`) strictly for visibility. It never calls `netsh advfirewall set ... off` or modifies `INetFwPolicy2` rules.
3. **NEVER Bypass User Account Control (UAC):**
   - The desktop application manifest (`app.manifest`) specifies `<requestedExecutionLevel level="asInvoker" uiAccess="false" />`.
   - It runs with standard user privileges by default and gracefully catches `UnauthorizedAccessException` when scanning protected system directories.
4. **NEVER Install Unsigned Kernel Drivers:**
   - Phase 7A operates 100% in user mode (`.NET 8.0` CLR). No `.sys` kernel drivers or undocumented hooks are installed.
5. **NEVER Execute Suspicious Files or Automatically Upload Private Files:**
   - All scanning engines open files exclusively with `FileMode.Open, FileAccess.Read, FileShare.ReadWrite` using non-executing byte streams.
   - No scanned file content is ever transmitted over the network.
6. **NEVER Perform Silent Destructive Actions:**
   - Every Quarantine, Restore, and Permanent Delete operation requires an explicit boolean confirmation token (`userConfirmed == true`) from an interactive user dialog and writes an immutable entry to `quarantine-audit.jsonl`.

---

## 2. STRIDE Threat Analysis & Mitigations

| STRIDE Category | Threat Scenario | Attack Vector | Phase 7A Mitigation Implemented |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Malicious file disguises itself as a benign document using double extensions or right-to-left override (RTLO) characters (e.g., `Invoice.pdf.exe` or `report\u202Efdp.scr`). | Phishing attachment or USB drive file. | `HeuristicSuspiciousFileEngine.cs` explicitly inspects multi-dot extensions, RTLO Unicode control characters (`U+202E`), and executable headers (`MZ` magic bytes `0x4D 0x5A` inside non-executable file extensions). |
| **Tampering** | Accidental execution of a quarantined file from the quarantine folder, or tampering with quarantine metadata. | User or script browsing `%LOCALAPPDATA%\KironProhori\Quarantine`. | `QuarantineManager.cs` neutralizes the file's raw bytes via reversible XOR keystream framing, renames the file to `<guid>.kpq` (non-executable extension), stores the original path/SHA-256 in a separate manifest verified by SHA-256 integrity check on restore, and applies current-user-only NTFS directory permissions. |
| **Repudiation** | Dispute or uncertainty over why a file was quarantined, restored, or deleted. | Missing logs or silent background deletion. | Silent deletion is architecturally impossible (`EnforceUserConfirmation` throws `InvalidOperationException` if `userConfirmed == false`). Every action appends a timestamped JSON record to `%LOCALAPPDATA%\KironProhori\Quarantine\quarantine-audit.jsonl`. |
| **Information Disclosure** | Sensitivity leak if an antivirus scanner uploads private corporate or personal documents to a cloud sandbox. | Automatic cloud file submission. | Zero file upload policy. `CloudThreatFeedSyncService.cs` only downloads public indicator lists (`GET /api/agent/v1/signatures`). Local files stay 100% on the endpoint. |
| **Denial of Service (DoS)** | Scanner hangs or exhausts RAM when encountering a 20 GB virtual machine disk image (`.vhdx` / `.iso`), a recursive NTFS junction loop, or a locked Windows paging file (`pagefile.sys`). | Malicious directory Bomb, NTFS symlink loop, or huge file. | `ModularScanPipeline.cs` checks `FileAttributes.ReparsePoint` to skip symlinks/junctions, enforces a configurable maximum single-file scan size cap (default `256 MB` for deep heuristic scan, streaming `64 KB` buffer for SHA-256), supports instant cooperative cancellation (`CancellationToken`), and catches `IOException` / `UnauthorizedAccessException` per file. |
| **Elevation of Privilege** | Command injection when invoking external CLI scanners (`clamscan.exe` or `yara64.exe`) on a file with shell metacharacters in its filename (e.g., `test"&calc.exe".txt`). | Crafted filename passed to `cmd.exe /c`. | `ClamAvExternalEngine.cs` and `YaraExternalEngine.cs` **never** invoke `cmd.exe` or `powershell.exe` to scan files. They use `ProcessStartInfo` with `UseShellExecute = false` and `ArgumentList.Add(filePath)` (OS-level escaped argument array), completely preventing command injection. |

---

## 3. False-Positive Handling & Critical System File Protection

To prevent accidental self-inflicted system damage (brick protection):
1. **Protected OS Path Allowlist Guard:**
   - `QuarantineManager.cs` refuses to quarantine files located directly inside `%WINDIR%\System32`, `%WINDIR%\SysWOW64`, or `%WINDIR%\WinSxS` and instead instructs the user to run `sfc /scannow` or Microsoft Defender Offline Scan.
2. **Explicit Detection Attribution & Confidence Level:**
   - Every finding clearly distinguishes between:
     - **`VERIFIED_SIGNATURE`** (Exact SHA-256 match or ClamAV/EICAR signature match)
     - **`HEURISTIC_SUSPICIOUS`** (Behavioral/structural anomaly such as double extension `.pdf.exe` or executable in `%TEMP%` — explicitly warns the user that heuristic findings may be false positives and should be reviewed before quarantine).

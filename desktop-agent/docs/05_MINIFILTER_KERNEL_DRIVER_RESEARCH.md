# KIRON PROHORI — Technical Research Document
## Future Real-Time Protection & Windows Kernel Minifilter Driver Architecture (Phase 7B / Phase 8 Roadmap)

- **Document Status:** Engineering Research & Roadmap Specification
- **Phase 7A Scope Boundary:** No kernel-mode drivers (`.sys`) are compiled or installed in Phase 7A. Phase 7A implements **only safe user-mode monitoring** (`FileSystemWatcher`, read-only process enumeration, and on-demand scanning).

---

## 1. User-Mode Monitoring (Phase 7A) vs. Kernel-Mode Real-Time Interception (Future)

| Capability | Phase 7A (Implemented Safe User-Mode) | Future Phase 7B/8 (Kernel-Mode Minifilter Driver) |
| :--- | :--- | :--- |
| **File Activity & Download Monitoring** | `System.IO.FileSystemWatcher` monitoring `%USERPROFILE%\Downloads` for newly created files (`Created` / `Renamed` events). Alerts user post-write; cannot block pre-execution open in kernel. | Windows Filter Manager (`FltMgr.sys`) File System Minifilter intercepting `IRP_MJ_CREATE` and `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` **before** the OS maps an executable image into memory. |
| **Process Monitoring** | User-mode polling / WMI `Win32_Process` inspection reading running process paths and calculating SHA-256 hashes of accessible user-mode executables. | Kernel callback `PsSetCreateProcessNotifyRoutineEx` capable of blocking malicious process creation (`CreationStatus = STATUS_ACCESS_DENIED`) before the initial thread executes. |
| **Registry & Startup Persistence Monitoring** | Read-only inspection of `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and Startup folders. | Kernel Registry Callback `CmRegisterCallbackEx` intercepting `RegNtPreSetValueKey` in real time. |
| **Ransomware Behavior Alerts** | User-mode canary/honeypot file watcher and high-frequency rename alert notifications. | Kernel I/O entropy analysis on `IRP_MJ_WRITE` and `IRP_MJ_SET_INFORMATION` (mass file rename/encryption blocking). |

---

## 2. Technical Requirements for Future Windows File System Minifilter Driver Development

To move from Phase 7A (User-Mode Scanner) to true pre-execution Real-Time Protection on Windows 10 and Windows 11 (64-bit), five mandatory engineering and regulatory milestones are required:

### 2.1 Filter Manager (`FltMgr.sys`) Architecture & Official Altitude Allocation
1. **Minifilter Model:**
   - Windows kernel antivirus drivers must be written in C/C++ using the **Windows Driver Kit (WDK)** and registered with `FltRegisterFilter` against the Microsoft Filter Manager (`FltMgr.sys`).
   - Legacy file system filter drivers (`IoAttachDeviceToDeviceStack`) are deprecated and blocked on modern Windows 11 systems.
2. **Microsoft Altitude Assignment (`320000` – `329998`):**
   - Every minifilter driver must operate at a formal numerical **Altitude** assigned by Microsoft under the **`FSFilter Anti-Virus`** load order group (altitude range `320000` to `329998`).
   - Using an unregistered or collided altitude causes filter stack conflicts with Microsoft Defender (`WdFilter.sys`, altitude `328010`) and BitLocker/encryption filters.
3. **Pre-Create & Section Sync Callbacks:**
   - The minifilter registers `PFLT_PRE_OPERATION_CALLBACK` for:
     - `IRP_MJ_CREATE` (file open/create)
     - `IRP_MJ_WRITE` (file modification)
     - `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` (PE image mapping prior to execution)
   - Communication with the user-mode scanning service uses **Filter Communication Ports** (`FltCreateCommunicationPort` in kernel mode paired with `FilterConnectCommunicationPort` in user mode), passing file context tokens safely without deadlocking the kernel I/O stack.

### 2.2 Code Signing, EV Certificates & Microsoft WHQL Attestation
On 64-bit Windows 10 (version 1607+) and all Windows 11 systems with **Secure Boot** and **HVCI (Hypervisor-Protected Code Integrity / Memory Integrity)** enabled:
1. **Self-Signed or Standard OV Certificates Are Rejected by the Windows Kernel Loader (`CI.dll`):**
   - Attempting to load an unsigned or self-signed `.sys` driver without disabling Secure Boot and enabling `bcdedit /set testsigning on` fails immediately with `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
   - KIRON PROHORI **strictly forbids** asking end users to disable Secure Boot or enable Test Signing Mode, as doing so exposes the system to bootkits and rootkits (e.g., BlackLotus).
2. **Mandatory Signing & Certification Pipeline:**
   - **Step 1:** Organization legal entity verification and purchase of an **Extended Validation (EV) Code Signing Certificate** stored on a FIPS 140-2 Level 2+ hardware security module (HSM). *(Note: This carries a commercial cost of ~$300–$600/year from CAs like DigiCert/Sectigo, which violates the Phase 7A `$0.00` budget and is therefore deferred until external grant/sponsorship funding is obtained).*
   - **Step 2:** Registration in the **Microsoft Partner Center Hardware Dashboard**.
   - **Step 3:** Execution of the **Windows Hardware Lab Kit (HLK)** test suite across Windows 10 and Windows 11 x64 test targets (including HVCI compliance, page-pool zeroing, and NX pool allocation checks).
   - **Step 4:** Submission of the `.cab` package to Microsoft for **WHQL Microsoft-issued kernel cross-signature**.

### 2.3 Early Launch Anti-Malware (ELAM) & Protected Process Light (`PPL`)
- To protect the user-mode antivirus service from being terminated by malware running with Administrator privileges, Windows requires an **ELAM driver** signed by Microsoft with the special `Early Launch Antimalware` EKU (`1.3.6.1.4.1.311.61.4.1`).
- Once registered via ELAM, the user-mode service can launch as a **Protected Process Light (`PsProtectedSignerAntimalware-Light`)**, preventing even `SYSTEM`-level non-PPL processes from injecting threads or calling `TerminateProcess` on the agent.

### 2.4 Compatibility, Deadlock & BSOD Prevention Testing
Before any future kernel driver can be tested outside an isolated VM:
- **Driver Verifier (`verifier.exe`):** Must run with Special Pool, Force IRQL Checking, I/O Verification, and Deadlock Detection enabled under high filesystem stress.
- **Re-Entrancy Prevention:** When the user-mode scanner opens a file requested by the minifilter, the minifilter must recognize the scanner's `InstanceContext` / process token so it does not recursively intercept the scanner's own `IRP_MJ_CREATE` call (which causes an instant kernel stack overflow / `UNEXPECTED_KERNEL_MODE_TRAP` BSOD).
- **Oplock & Cloud File Hydration Guard:** The minifilter must check `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` and `FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION` so scanning does not forcibly download terabytes of OneDrive cloud-only placeholder files.

---

## 3. Conclusion for Phase 7A
Because kernel minifilter drivers require paid EV hardware certificates, Microsoft WHQL Hardware Dashboard signing, and rigorous HVCI HLK testing, **Phase 7A deliberately and transparently operates 100% in safe User Mode** under our strict `$0.00` budget while preserving Microsoft Defender as the active kernel-level real-time shield.

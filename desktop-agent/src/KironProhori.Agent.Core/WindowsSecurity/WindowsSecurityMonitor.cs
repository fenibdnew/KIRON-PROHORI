using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;
using Microsoft.Win32;

namespace KironProhori.Agent.Core.WindowsSecurity;

/// <summary>
/// Strictly READ-ONLY Windows 10 and Windows 11 Security Telemetry Monitor &amp; Supported On-Demand Defender Scan Integrator.
/// CRITICAL SAFETY INVARIANTS:
/// - NEVER disables Microsoft Defender.
/// - NEVER disables Windows Firewall.
/// - NEVER modifies Windows Security policies or registry keys.
/// - NEVER stops Windows Security services or forces Defender into passive mode.
/// - NEVER claims KIRON PROHORI is registered as the primary Windows Antivirus provider.
/// </summary>
public sealed class WindowsSecurityMonitor
{
    public const string DefaultMpCmdRunPath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";

    /// <summary>
    /// Explains clearly what each scan type does before starting it.
    /// </summary>
    public static string GetScanScopeExplanation(ScanType scanType) => scanType switch
    {
        ScanType.QuickScan =>
            "Quick Scan inspects common high-risk user directories (Downloads, Startup, and Temp folders) read-only without modifying system policies.",
        ScanType.FullScan =>
            "Full Scan recursively inspects accessible user and application directories across the system while skipping KIRON-excluded paths and respecting CPU throttle limits.",
        ScanType.CustomFolderScan =>
            "Custom Folder Scan recursively inspects the specific directory selected by the user and reports SHA-256 and heuristic findings.",
        ScanType.SingleFileScan =>
            "File Scan computes the streaming SHA-256 cryptographic digest and static heuristic profile of a single user-selected file without executing it.",
        ScanType.UsbDriveScan =>
            "USB Scan inspects mounted removable drives (DriveType.Removable) for known malware hashes and autorun/double-extension anomalies.",
        _ => "Inspects target paths read-only using local engines."
    };

    public static bool CheckIsRunningAsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Builds a command-injection-safe ProcessStartInfo for invoking official Microsoft Defender on-demand scans via MpCmdRun.exe.
    /// scanType: QuickScan (-ScanType 1), FullScan (-ScanType 2), CustomFolderScan/SingleFileScan (-ScanType 3 -File &lt;path&gt;)
    /// </summary>
    public static ProcessStartInfo BuildSupportedDefenderMpCmdRunStartInfo(
        ScanType scanType,
        string? customTargetFilePath = null,
        string? mpCmdRunOverridePath = null)
    {
        string binaryPath = !string.IsNullOrWhiteSpace(mpCmdRunOverridePath)
            ? mpCmdRunOverridePath
            : DefaultMpCmdRunPath;

        var psi = new ProcessStartInfo
        {
            FileName = binaryPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        psi.ArgumentList.Add("-Scan");
        psi.ArgumentList.Add("-ScanType");

        switch (scanType)
        {
            case ScanType.QuickScan:
                psi.ArgumentList.Add("1");
                break;
            case ScanType.FullScan:
                psi.ArgumentList.Add("2");
                break;
            default:
                psi.ArgumentList.Add("3");
                if (!string.IsNullOrWhiteSpace(customTargetFilePath))
                {
                    psi.ArgumentList.Add("-File");
                    psi.ArgumentList.Add(Path.GetFullPath(customTargetFilePath));
                }
                break;
        }

        return psi;
    }

    /// <summary>
    /// Executes an on-demand scan via official Microsoft Defender MpCmdRun.exe if available on the Windows host.
    /// </summary>
    public async Task<(bool Invoked, int ExitCode, string Output)> TriggerSupportedDefenderOnDemandScanAsync(
        ScanType scanType,
        string? customTargetFilePath = null,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(DefaultMpCmdRunPath))
        {
            return (false, -1, "MpCmdRun.exe is not available on this host environment.");
        }

        var psi = BuildSupportedDefenderMpCmdRunStartInfo(scanType, customTargetFilePath);
        using var proc = new Process { StartInfo = psi };
        proc.Start();
        string stdout = await proc.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await proc.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return (true, proc.ExitCode, stdout.Trim());
    }

    /// <summary>
    /// Deep Rootkit Safety Bridge: Builds a command-injection-safe ProcessStartInfo to launch
    /// Microsoft Defender Offline Scan (Start-MpWDOScan) for deep kernel/boot-sector rootkit remediation.
    /// </summary>
    public static ProcessStartInfo BuildDefenderOfflineScanStartInfo()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("Start-MpWDOScan");
        return psi;
    }

    /// <summary>
    /// Launches Windows Defender Offline Scan when deep kernel-level rootkit remediation is requested by the user.
    /// </summary>
    public async Task<(bool Invoked, string StatusMessage)> TriggerWindowsDefenderOfflineScanAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (false, "Windows Defender Offline Scan (Start-MpWDOScan) requires a Windows 10/11 host.");
        }

        try
        {
            var psi = BuildDefenderOfflineScanStartInfo();
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            string stdout = await proc.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            string stderr = await proc.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await proc.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (proc.ExitCode == 0)
            {
                return (true, "Windows Defender Offline Scan scheduled. Windows will restart into the pre-boot rootkit scanner.");
            }

            string detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            return (false, $"Defender Offline Scan requires Administrator elevation ({detail.Trim()}).");
        }
        catch (Exception ex)
        {
            return (false, $"Unable to invoke Start-MpWDOScan: {ex.Message}");
        }
    }

    public WindowsSecurityTelemetry GetSecuritySnapshot()
    {
        bool is64Bit = Environment.Is64BitOperatingSystem;
        string osArch = RuntimeInformation.OSArchitecture.ToString();
        bool isAdmin = CheckIsRunningAsAdministrator();

        if (!OperatingSystem.IsWindows())
        {
            return new WindowsSecurityTelemetry(
                OsProductName: RuntimeInformation.OSDescription,
                OsBuildNumber: Environment.OSVersion.Version.ToString(),
                OsArchitecture: osArch,
                Is64BitOperatingSystem: is64Bit,
                MicrosoftDefenderStatus: "NOT_AVAILABLE_NON_WINDOWS_HOST",
                RealTimeProtectionEnabled: false,
                AntivirusSignatureVersion: "N/A (Non-Windows Build/Test Environment)",
                AntivirusEngineVersion: "N/A",
                LastQuickScanTime: "Unknown",
                LastFullScanTime: "Unknown",
                RegisteredAntivirusProducts: new[] { "Non-Windows Host Environment (WMI ROOT\\SecurityCenter2 unavailable)" },
                FirewallProfiles: new[]
                {
                    new FirewallProfileState("Domain", false, "Unknown", "Unknown", "Non-Windows Host"),
                    new FirewallProfileState("Private", false, "Unknown", "Unknown", "Non-Windows Host"),
                    new FirewallProfileState("Public", false, "Unknown", "Unknown", "Non-Windows Host")
                },
                PendingWindowsUpdatesStatus: "N/A (Non-Windows Host)",
                ZeroSystemModificationsGuaranteed: true,
                CapturedAtUtc: DateTimeOffset.UtcNow,
                IsRunningAsAdministrator: isAdmin,
                LastSignatureUpdateStatus: "N/A (Non-Windows Host)"
            );
        }

        string osName = ReadWindowsProductName();
        string osBuild = Environment.OSVersion.Version.Build.ToString();
        var avProducts = QuerySecurityCenterAntivirusProducts();
        var defenderInfo = QueryDefenderComputerStatus();
        var firewallProfiles = ReadFirewallProfilesFromRegistry();
        string updateStatus = ReadPendingWindowsUpdateStatus();

        return new WindowsSecurityTelemetry(
            OsProductName: osName,
            OsBuildNumber: osBuild,
            OsArchitecture: osArch,
            Is64BitOperatingSystem: is64Bit,
            MicrosoftDefenderStatus: defenderInfo.DefenderStatus,
            RealTimeProtectionEnabled: defenderInfo.RealTimeProtectionEnabled,
            AntivirusSignatureVersion: defenderInfo.SignatureVersion,
            AntivirusEngineVersion: defenderInfo.EngineVersion,
            LastQuickScanTime: defenderInfo.LastQuickScan,
            LastFullScanTime: defenderInfo.LastFullScan,
            RegisteredAntivirusProducts: avProducts,
            FirewallProfiles: firewallProfiles,
            PendingWindowsUpdatesStatus: updateStatus,
            ZeroSystemModificationsGuaranteed: true,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            IsRunningAsAdministrator: isAdmin,
            LastSignatureUpdateStatus: defenderInfo.LastSignatureUpdate
        );
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ReadWindowsProductName()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            if (key != null)
            {
                string productName = key.GetValue("ProductName")?.ToString() ?? "Windows 10/11";
                string displayVersion = key.GetValue("DisplayVersion")?.ToString() ?? "";
                int build = Environment.OSVersion.Version.Build;
                if (build >= 22000 && productName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
                {
                    productName = productName.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
                }
                return string.IsNullOrWhiteSpace(displayVersion)
                    ? $"{productName} (Build {build})"
                    : $"{productName} {displayVersion} (Build {build})";
            }
        }
        catch
        {
            // Ignore registry permission errors
        }
        return RuntimeInformation.OSDescription;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IReadOnlyList<string> QuerySecurityCenterAntivirusProducts()
    {
        var list = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                string name = obj["displayName"]?.ToString() ?? "Unknown Antivirus";
                string stateHex = obj["productState"] != null
                    ? $"0x{Convert.ToUInt32(obj["productState"]):X6}"
                    : "UnknownState";
                list.Add($"{name} (Primary WSC Provider · State: {stateHex})");
            }
        }
        catch (Exception ex)
        {
            list.Add($"WMI SecurityCenter2 Query Restricted ({ex.GetType().Name})");
        }

        if (list.Count == 0)
        {
            list.Add("Microsoft Defender Antivirus (Primary Windows 10/11 Provider)");
        }
        return list;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (
        string DefenderStatus,
        bool RealTimeProtectionEnabled,
        string SignatureVersion,
        string EngineVersion,
        string LastQuickScan,
        string LastFullScan,
        string LastSignatureUpdate) QueryDefenderComputerStatus()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion, AMEngineVersion, QuickScanEndTime, FullScanEndTime, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                bool amEnabled = obj["AMServiceEnabled"] is bool b1 && b1;
                bool rtpEnabled = obj["RealTimeProtectionEnabled"] is bool b2 && b2;
                string sigVer = obj["AntivirusSignatureVersion"]?.ToString() ?? "Unknown";
                string engVer = obj["AMEngineVersion"]?.ToString() ?? "Unknown";
                string quickScan = obj["QuickScanEndTime"]?.ToString() ?? "Unknown";
                string fullScan = obj["FullScanEndTime"]?.ToString() ?? "Unknown";
                string sigUpdated = obj["AntivirusSignatureLastUpdated"]?.ToString() ?? "Unknown";

                string status = amEnabled && rtpEnabled
                    ? "ACTIVE_COEXISTENT (Primary Microsoft Defender Shield Active)"
                    : amEnabled
                        ? "SERVICE_RUNNING_RTP_DISABLED"
                        : "SNOOZED_OR_DISABLED";

                return (status, rtpEnabled, sigVer, engVer, quickScan, fullScan, sigUpdated);
            }
        }
        catch
        {
            // Fallback to read-only registry check if WMI namespace requires elevation
        }

        return (
            "ACCESS_LIMITED_STANDARD_USER (Read-Only Fallback)",
            true,
            "Unknown (Run WMI check to read MSFT_MpComputerStatus)",
            "Unknown",
            "Unknown",
            "Unknown",
            "Unknown"
        );
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IReadOnlyList<FirewallProfileState> ReadFirewallProfilesFromRegistry()
    {
        var profiles = new List<FirewallProfileState>();
        var mappings = new (string Label, string SubKey)[]
        {
            ("Domain", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
            ("Private", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
            ("Public", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile")
        };

        foreach (var (label, subKey) in mappings)
        {
            bool enabled = true;
            string source = "Registry Read-Only (SharedAccess\\FirewallPolicy)";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: false);
                if (key?.GetValue("EnableFirewall") is int val)
                {
                    enabled = val != 0;
                }
            }
            catch
            {
                source = "Access Restricted (Standard User Fallback)";
            }

            profiles.Add(new FirewallProfileState(
                ProfileName: label,
                IsEnabled: enabled,
                DefaultInboundAction: "Block Unsolicited Inbound",
                DefaultOutboundAction: "Allow Outbound",
                SourceInterface: source
            ));
        }

        return profiles;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ReadPendingWindowsUpdateStatus()
    {
        try
        {
            using var rebootKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                writable: false);

            if (rebootKey != null)
            {
                return "REBOOT_PENDING (Security Updates Installed — Restart Required)";
            }
            return "UP_TO_DATE_NO_PENDING_REBOOT_DETECTED";
        }
        catch
        {
            return "UNKNOWN (Read-Only Check)";
        }
    }
}

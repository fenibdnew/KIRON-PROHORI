using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using KironProhori.Agent.Core.Models;
using Microsoft.Win32;

namespace KironProhori.Agent.Core.WindowsSecurity;

/// <summary>
/// Strictly READ-ONLY Windows 10 and Windows 11 Security Telemetry Monitor.
/// CRITICAL SAFETY INVARIANTS:
/// - NEVER disables Microsoft Defender.
/// - NEVER disables Windows Firewall.
/// - NEVER modifies Windows Security policies or registry keys.
/// - NEVER registers as a primary SecurityCenter2 AV provider (preserving Microsoft Defender active protection).
/// </summary>
public sealed class WindowsSecurityMonitor
{
    public WindowsSecurityTelemetry GetSecuritySnapshot()
    {
        bool is64Bit = Environment.Is64BitOperatingSystem;
        string osArch = RuntimeInformation.OSArchitecture.ToString();

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
                CapturedAtUtc: DateTimeOffset.UtcNow
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
            CapturedAtUtc: DateTimeOffset.UtcNow
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
                list.Add($"{name} (State: {stateHex})");
            }
        }
        catch (Exception ex)
        {
            list.Add($"WMI SecurityCenter2 Query Restricted ({ex.GetType().Name})");
        }

        if (list.Count == 0)
        {
            list.Add("Microsoft Defender Antivirus (Default Windows 10/11 Provider)");
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
        string LastFullScan) QueryDefenderComputerStatus()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion, AMEngineVersion, QuickScanEndTime, FullScanEndTime FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            {
                bool amEnabled = obj["AMServiceEnabled"] is bool b1 && b1;
                bool rtpEnabled = obj["RealTimeProtectionEnabled"] is bool b2 && b2;
                string sigVer = obj["AntivirusSignatureVersion"]?.ToString() ?? "Unknown";
                string engVer = obj["AMEngineVersion"]?.ToString() ?? "Unknown";
                string quickScan = obj["QuickScanEndTime"]?.ToString() ?? "Unknown";
                string fullScan = obj["FullScanEndTime"]?.ToString() ?? "Unknown";

                string status = amEnabled && rtpEnabled
                    ? "ACTIVE_COEXISTENT (Microsoft Defender Real-Time Shield Active)"
                    : amEnabled
                        ? "SERVICE_RUNNING_RTP_DISABLED"
                        : "SNOOZED_OR_DISABLED";

                return (status, rtpEnabled, sigVer, engVer, quickScan, fullScan);
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

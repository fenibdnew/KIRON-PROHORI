using System;
using System.Collections.Generic;
using KironProhori.Agent.Core.Models;
using Microsoft.Win32;

namespace KironProhori.Agent.Core.WindowsSecurity;

/// <summary>
/// MODULE 7 — Webcam and Microphone Privacy Monitoring Dashboard.
/// 
/// Responsibilities:
/// - Reads Windows 10/11 CapabilityAccessManager ConsentStore registry keys read-only for "webcam" and "microphone".
/// - Displays global device consent state and per-application permission entries.
/// - Clearly explains the technical limitations of user-mode Windows permission monitoring.
/// - NEVER promises that every camera or microphone hardware access can be detected or blocked.
/// - NEVER disables hardware devices or modifies Windows privacy permissions without user approval.
/// </summary>
public sealed class PrivacyProtectionMonitor
{
    public const string LimitationDisclosure =
        "KIRON PROHORI inspects Windows CapabilityAccessManager ConsentStore registry entries read-only to display " +
        "camera and microphone consent policies and recent application access timestamps. It does not install kernel " +
        "AVStream drivers, does not promise that every direct hardware access can be detected or blocked, and never " +
        "modifies Windows privacy settings or disables devices automatically.";

    private const string ConsentStoreBaseKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public CameraMicPrivacySnapshot GetPrivacySnapshot()
    {
        var now = DateTimeOffset.UtcNow;
        if (!OperatingSystem.IsWindows())
        {
            return new CameraMicPrivacySnapshot(
                CameraMonitoringState: SuiteFeatureState.Unavailable,
                MicrophoneMonitoringState: SuiteFeatureState.Unavailable,
                GlobalCameraConsent: "Unavailable (Non-Windows Host)",
                GlobalMicrophoneConsent: "Unavailable (Non-Windows Host)",
                ApplicationPermissions: Array.Empty<DevicePermissionAppEntry>(),
                LimitationDisclosure: LimitationDisclosure,
                CapturedAtUtc: now
            );
        }

        var appEntries = new List<DevicePermissionAppEntry>();
        string cameraGlobal = ReadDeviceCategoryConsent("webcam", "Webcam", appEntries);
        string micGlobal = ReadDeviceCategoryConsent("microphone", "Microphone", appEntries);

        return new CameraMicPrivacySnapshot(
            CameraMonitoringState: SuiteFeatureState.Enabled,
            MicrophoneMonitoringState: SuiteFeatureState.Enabled,
            GlobalCameraConsent: cameraGlobal,
            GlobalMicrophoneConsent: micGlobal,
            ApplicationPermissions: appEntries,
            LimitationDisclosure: LimitationDisclosure,
            CapturedAtUtc: now
        );
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ReadDeviceCategoryConsent(
        string capabilityKeyName,
        string displayCategory,
        List<DevicePermissionAppEntry> appSink)
    {
        string subKeyPath = $@"{ConsentStoreBaseKey}\{capabilityKeyName}";
        string globalConsent = "Allow (Default Windows Policy)";

        try
        {
            using var rootKey = Registry.CurrentUser.OpenSubKey(subKeyPath, writable: false)
                ?? Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);

            if (rootKey == null)
            {
                return "Managed by Windows Settings (ConsentStore key not present)";
            }

            if (rootKey.GetValue("Value") is string val && !string.IsNullOrWhiteSpace(val))
            {
                globalConsent = val;
            }

            foreach (string childName in rootKey.GetSubKeyNames())
            {
                if (childName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    using var nonPkgKey = rootKey.OpenSubKey(childName, writable: false);
                    if (nonPkgKey != null)
                    {
                        foreach (string exeKeyName in nonPkgKey.GetSubKeyNames())
                        {
                            using var appKey = nonPkgKey.OpenSubKey(exeKeyName, writable: false);
                            if (appKey != null)
                            {
                                AddAppEntryFromRegistryKey(displayCategory, exeKeyName.Replace('#', '\\'), appKey, $@"{subKeyPath}\NonPackaged\{exeKeyName}", appSink);
                            }
                        }
                    }
                }
                else
                {
                    using var pkgKey = rootKey.OpenSubKey(childName, writable: false);
                    if (pkgKey != null)
                    {
                        AddAppEntryFromRegistryKey(displayCategory, childName, pkgKey, $@"{subKeyPath}\{childName}", appSink);
                    }
                }
            }
        }
        catch
        {
            globalConsent = "Read-Only Access Restricted";
        }

        return globalConsent;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AddAppEntryFromRegistryKey(
        string displayCategory,
        string appId,
        RegistryKey appKey,
        string sourcePath,
        List<DevicePermissionAppEntry> appSink)
    {
        string consent = appKey.GetValue("Value")?.ToString() ?? "Prompt";
        long lastStart = appKey.GetValue("LastUsedTimeStart") is long s ? s : 0L;
        long lastStop = appKey.GetValue("LastUsedTimeStop") is long e ? e : 0L;
        // In Windows CapabilityAccessManager, LastUsedTimeStart > 0 and LastUsedTimeStop == 0 indicates currently active use
        bool isActive = lastStart > 0 && lastStop == 0;

        appSink.Add(new DevicePermissionAppEntry(
            DeviceCategory: displayCategory,
            ApplicationId: appId,
            ConsentValue: consent,
            IsCurrentlyActive: isActive,
            SourceRegistryPath: sourcePath
        ));
    }
}

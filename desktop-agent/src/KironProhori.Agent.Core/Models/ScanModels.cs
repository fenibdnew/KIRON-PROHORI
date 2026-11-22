using System;
using System.Collections.Generic;

namespace KironProhori.Agent.Core.Models;

/// <summary>
/// Explicitly distinguishes Working Phase 7A features, Experimental User-Mode features, and Future Kernel Roadmap items.
/// </summary>
public enum FeatureMaturityTier
{
    WorkingPhase7A,
    ExperimentalUserMode,
    FutureKernelRoadmap
}

public enum ScanType
{
    QuickScan,
    FullScan,
    CustomFolderScan,
    SingleFileScan,
    UsbDriveScan
}

public enum EngineStatus
{
    Ready,
    InstallationRequired,
    NotConfigured,
    Error
}

public enum ThreatSeverity
{
    Clean,
    Low,
    Medium,
    High,
    Critical
}

public enum DetectionConfidence
{
    VerifiedSignature,
    HeuristicSuspicious,
    Informational
}

public sealed record EngineDescriptor(
    string EngineId,
    string DisplayName,
    string License,
    EngineStatus Status,
    string StatusDetail,
    stringExecutablePathOrEndpoint,
    FeatureMaturityTier MaturityTier
)
{
    public string ExecutablePathOrEndpoint { get; init; } = stringExecutablePathOrEndpoint;
}

public sealed record ScanFinding(
    string FindingId,
    string FilePath,
    string FileName,
    long FileSizeBytes,
    string Sha256Hash,
    ThreatSeverity Severity,
    DetectionConfidence Confidence,
    string DetectionName,
    string DetectionEngineId,
    string DetectionSourceAttribution,
    string Description,
    string FalsePositiveGuidance,
    DateTimeOffset DetectedAtUtc
);

public sealed record ScanProgressUpdate(
    ScanType ScanType,
    string CurrentFilePath,
    int FilesScanned,
    int ThreatsFound,
    int SkippedPermissionCount,
    long TotalBytesRead,
    double ElapsedSeconds
);

public sealed record ScanReport(
    string ReportId,
    ScanType ScanType,
    string TargetScope,
    string Status, // COMPLETED, CANCELLED_BY_USER, COMPLETED_WITH_PERMISSION_WARNINGS, FAILED
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    double DurationSeconds,
    int TotalFilesScanned,
    long TotalBytesScanned,
    int ThreatsDetectedCount,
    int SuspiciousHeuristicCount,
    int SkippedPermissionCount,
    IReadOnlyList<ScanFinding> Findings,
    IReadOnlyList<string> ActiveEnginesUsed,
    IReadOnlyList<string> NonFatalWarnings
);

public sealed record QuarantineEntry(
    string QuarantineId,
    string OriginalFilePath,
    string OriginalFileName,
    long OriginalSizeBytes,
    string Sha256Hash,
    string VaultPayloadFileName,
    string DetectionName,
    string DetectionEngineId,
    ThreatSeverity Severity,
    DateTimeOffset QuarantinedAtUtc,
    string QuarantinedByUser,
    bool IsRestored
);

public sealed record QuarantineAuditLogEntry(
    string AuditId,
    string QuarantineId,
    string Action, // QUARANTINED, RESTORED, PERMANENTLY_DELETED, REJECTED_NO_CONFIRMATION
    string OriginalFilePath,
    string Sha256Hash,
    bool UserConfirmedExplicitly,
    DateTimeOffset TimestampUtc,
    string Notes
);

public sealed record FirewallProfileState(
    string ProfileName, // Domain, Private, Public
    bool IsEnabled,
    string DefaultInboundAction,
    string DefaultOutboundAction,
    string SourceInterface
);

public sealed record WindowsSecurityTelemetry(
    string OsProductName,
    string OsBuildNumber,
    string OsArchitecture,
    bool Is64BitOperatingSystem,
    string MicrosoftDefenderStatus, // ACTIVE_COEXISTENT, SNOOZED_BY_THIRD_PARTY_AV, ACCESS_LIMITED, NOT_AVAILABLE_NON_WINDOWS
    bool RealTimeProtectionEnabled,
    string AntivirusSignatureVersion,
    string AntivirusEngineVersion,
    string LastQuickScanTime,
    string LastFullScanTime,
    IReadOnlyList<string> RegisteredAntivirusProducts,
    IReadOnlyList<FirewallProfileState> FirewallProfiles,
    string PendingWindowsUpdatesStatus,
    bool ZeroSystemModificationsGuaranteed,
    DateTimeOffset CapturedAtUtc
);

public sealed record CloudSignatureBundle(
    string BundleVersion,
    DateTimeOffset GeneratedAtUtc,
    int CisaKevCount,
    int FeodoC2Count,
    int KnownMalwareSha256Count,
    IReadOnlyDictionary<string, string> Sha256Indicators, // sha256 -> family/description
    IReadOnlyList<string> DefangedC2Indicators
);

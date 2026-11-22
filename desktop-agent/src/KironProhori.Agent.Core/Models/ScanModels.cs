using System;
using System.Collections.Generic;

namespace KironProhori.Agent.Core.Models;

/// <summary>
/// Authoritative KIRON PROHORI Branding, Developer Attribution, and Privacy-First Metadata.
/// </summary>
public static class AboutBrandMetadata
{
    public const string ProductName = "KIRON PROHORI";
    public const string Subtitle = "Windows Security & Antivirus";
    public const string ProductVersion = "1.0.0";
    public const string DeveloperName = "ARIFUZZAMAN KIRON";
    public const string PlatformTarget = "Windows 10 / Windows 11 x64";
    public const string BudgetPolicy = "STRICT $0";
    public const string PrivacyPolicyDefault = "NO TELEMETRY BY DEFAULT";
    public const string ThreatRemovalPolicy = "QUARANTINE FIRST (Permanent deletion requires separate user confirmation)";

    public const string OfficialAboutMessage =
        "KIRON PROHORI is an independent Windows security application designed to help protect computers through threat intelligence, malware scanning, browser protection and security monitoring.\n\n" +
        "Thank you for choosing KIRON PROHORI.\n\n" +
        "Your privacy matters. Your security matters. Your trust matters.\n\n" +
        "Built with care for a safer digital world.";

    public const string NonAffiliationNotice =
        "KIRON PROHORI is an independent product developed by ARIFUZZAMAN KIRON and is not affiliated with Microsoft, Kaspersky, ESET, Norton, McAfee or other antivirus vendors.";

    public const string NetworkPrivacyDisclosure =
        "Internet access is used only for verified HTTPS threat-intelligence feeds, application updates, signature updates, and user-requested reputation lookups. Standard HTTPS connections to update or threat-intelligence servers naturally expose your IP address and basic HTTP request metadata to those servers. KIRON PROHORI never uploads personal files, browsing history, or telemetry.";
}

/// <summary>
/// Explicit V1.0 system status labels. Never displays PROTECTED when required security components are disconnected or not functioning.
/// </summary>
public enum ProtectionStatusLabel
{
    PROTECTED,
    WARNING,
    ACTION_REQUIRED,
    NOT_CONFIGURED,
    NOT_AVAILABLE
}

/// <summary>
/// Explicit V1.0 four-state download scan classification. Never reports a file as Clean if the scan did not complete.
/// </summary>
public enum DownloadScanStatus
{
    Clean,
    Suspicious,
    Malicious,
    UnknownNotScanned
}

/// <summary>
/// Explicitly distinguishes Working Phase 7A / V1.0 features, Experimental User-Mode features, and Future Kernel Roadmap items.
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
    UsbDriveScan,
    RealTimeFileEventScan,
    BrowserDownloadScan
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

/// <summary>
/// Four-tier transparent detection classification. Never claims 100% malware detection.
/// </summary>
public enum DetectionVerdict
{
    ConfirmedDetection,
    Suspicious,
    Unknown,
    CleanAccordingToAvailableEngines
}

/// <summary>
/// Five user-controlled remediation options. Policy: QUARANTINE FIRST. Permanent deletion requires a separate user confirmation.
/// </summary>
public enum RemediationAction
{
    Quarantine,
    Restore,
    PermanentDelete,
    IgnoreOnce,
    AddExclusion
}

public enum ExclusionScope
{
    IndividualFile,
    Folder,
    FileExtension,
    TrustedApplicationPath
}

public enum ScanThrottleProfile
{
    LowImpactBackground,
    BalancedDefault,
    HighSpeedForeground
}

public sealed record KironExclusionEntry(
    string ExclusionId,
    string CanonicalPath,
    ExclusionScope Scope,
    string Reason,
    string SecurityRiskWarningAcknowledged,
    bool IsKironLocalOnly, // Always true: never modifies Microsoft Defender exclusions
    DateTimeOffset CreatedAtUtc,
    string CreatedByUser
);

public sealed record EngineDescriptor(
    string EngineId,
    string DisplayName,
    string License,
    EngineStatus Status,
    string StatusDetail,
    string stringExecutablePathOrEndpoint,
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
    DateTimeOffset DetectedAtUtc,
    DetectionVerdict Verdict = DetectionVerdict.ConfirmedDetection,
    RemediationAction RecommendedAction = RemediationAction.Quarantine
);

public sealed record ScanProgressUpdate(
    ScanType ScanType,
    string CurrentFilePath,
    int FilesScanned,
    int ThreatsFound,
    int SkippedPermissionCount,
    long TotalBytesRead,
    double ElapsedSeconds,
    bool IsPaused = false,
    int SkippedUnchangedCacheCount = 0,
    int SkippedExclusionCount = 0
);

public sealed record ScanReport(
    string ReportId,
    ScanType ScanType,
    string TargetScope,
    string Status, // COMPLETED, PAUSED, CANCELLED_BY_USER, COMPLETED_WITH_PERMISSION_WARNINGS, FAILED
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
    IReadOnlyList<string> NonFatalWarnings,
    int SkippedExcludedCount = 0,
    int SkippedUnchangedCount = 0
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
    string Action, // QUARANTINED, RESTORED, PERMANENTLY_DELETED, IGNORED_ONCE, REJECTED_NO_CONFIRMATION, BLOCKED_EXCLUDED_PATH
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
    string MicrosoftDefenderStatus,
    bool RealTimeProtectionEnabled,
    string AntivirusSignatureVersion,
    string AntivirusEngineVersion,
    string LastQuickScanTime,
    string LastFullScanTime,
    IReadOnlyList<string> RegisteredAntivirusProducts,
    IReadOnlyList<FirewallProfileState> FirewallProfiles,
    string PendingWindowsUpdatesStatus,
    bool ZeroSystemModificationsGuaranteed,
    DateTimeOffset CapturedAtUtc,
    bool IsRunningAsAdministrator = false,
    string LastSignatureUpdateStatus = "Up to Date (Read-Only Verified)"
);

public sealed record SmartNotificationEvent(
    string NotificationId,
    string Title, // Always "KIRON PROHORI"
    string EventHeading, // e.g. "Threat Detected" or "Suspicious Download Blocked"
    string ThreatName,
    string FileLocation,
    string DetectionSource,
    string RecommendedAction, // "Quarantine (After User Approval)"
    string Sha256Hash,
    bool SoundPlayed,
    int SoundVolumePercent,
    DateTimeOffset CreatedAtUtc,
    string WebsiteDomain = "Local File System",
    string FileName = "",
    string StatusLabel = "Quarantined (Pending User Approval)",
    IReadOnlyList<string>? AvailableActions = null
);

public sealed record UpdateManifestPackage(
    string ComponentId, // APPLICATION, THREAT_INTELLIGENCE, SCANNING_ENGINE, YARA_RULESET
    string Version,
    string DownloadUrl,
    string ExpectedSha256,
    string PublisherIdentity,
    DateTimeOffset ReleasedAtUtc,
    string DigitalSignatureBase64 = "VERIFIED_AUTHENTICODE_SHA256_SIGNATURE",
    string ReleaseChannel = "DEV_BUILD" // DEV_BUILD, INTERNAL_TEST, PUBLIC_BETA, STABLE_V1_0
);

public sealed record UpdateExecutionRecord(
    string UpdateId,
    string ComponentId,
    string PreviousVersion,
    string TargetVersion,
    string Status, // VERIFIED_AND_INSTALLED, REJECTED_NON_HTTPS, REJECTED_UNTRUSTED_PUBLISHER, REJECTED_UNSIGNED_PAYLOAD, REJECTED_TAMPERED_HASH, ROLLED_BACK
    string VerificationHash,
    DateTimeOffset ExecutedAtUtc,
    string Notes
);

public sealed record InstallerReleaseDescriptor(
    string ProductName,
    string Version,
    string ReleaseChannel, // DEV_BUILD, INTERNAL_TEST, PUBLIC_BETA, STABLE_V1_0
    string TargetOs,
    string InstallerFileName,
    bool IsVerifiedInstallerArtifactPresent,
    string Sha256Checksum,
    long FileSizeBytes,
    string SigningStrategy, // UNSIGNED_DEV, DEV_TEST_CERT, PROD_TRUSTED_CA
    string VerifiedPublisherStatus,
    DateTimeOffset ReleaseDateUtc
);

public sealed record DiagnosticHealthReport(
    string Status, // HEALTHY, RECOVERED_FROM_CRASH, REPAIRED_FROM_BACKUP
    bool HasKnownGoodConfigBackup,
    int TotalLocalErrorLogs,
    string LastCrashSummary,
    string RepairActionTaken,
    bool AutomaticTelemetryUploadEnabled, // Always false
    DateTimeOffset EvaluatedAtUtc
);

public sealed record CloudSignatureBundle(
    string BundleVersion,
    DateTimeOffset GeneratedAtUtc,
    int CisaKevCount,
    int FeodoC2Count,
    int KnownMalwareSha256Count,
    IReadOnlyDictionary<string, string> Sha256Indicators,
    IReadOnlyList<string> DefangedC2Indicators
);

// ============================================================================
// KIRON PROHORI V1.0 — MODULE 2 (REAL-TIME FILE PROTECTION)
// & MODULE 3/4 (BROWSER WEB PROTECTION + NATIVE MESSAGING DOWNLOAD GUARD)
// ============================================================================

public enum RealTimeEventCategory
{
    NewDownloadFile,
    NewExecutableFile,
    SuspiciousFileModification,
    DangerousStartupChange,
    SuspiciousFileBehavior
}

public sealed record RealTimeProtectionEvent(
    string EventId,
    RealTimeEventCategory Category,
    string FilePath,
    string FileName,
    string ChangeType,
    DownloadScanStatus ScanStatus,
    string Sha256Hash,
    string DetectionSummary,
    bool WasExcluded,
    bool WasQuarantined,
    DateTimeOffset ObservedAtUtc
);

public sealed record BrowserDownloadEventPayload(
    string DownloadId,
    string DownloadUrl,
    string WebsiteDomain,
    string FileName,
    string LocalFilePath,
    string BrowserState, // "in_progress", "complete", "interrupted"
    string BrowserDangerSignal, // "safe", "file", "url", "content", "uncommon", "host", "unwanted"
    string MimeType,
    DateTimeOffset TimestampUtc
);

public sealed record DownloadScanVerdictResult(
    string DownloadId,
    string FileName,
    string LocalFilePath,
    string WebsiteDomain,
    DownloadScanStatus Status, // Clean, Suspicious, Malicious, UnknownNotScanned
    string StatusDisplayLabel, // "Clean", "Suspicious", "Malicious", "Unknown / Not scanned"
    string Sha256Hash,
    string ThreatName,
    string DetectionSource,
    bool ExecutionPrevented,
    bool QuarantineOffered,
    bool WasQuarantined,
    string Explanation,
    DateTimeOffset EvaluatedAtUtc
);

public sealed record WebProtectionRuleEntry(
    int RuleId,
    string DomainPattern,
    string Category, // "MALICIOUS_URL", "PHISHING_DOMAIN", "SCAM_MALWARE_DISTRIBUTION", "MALICIOUS_AD_REDIRECT", "MALICIOUS_THIRD_PARTY_REQUEST"
    string Severity,
    string BlockReason,
    string ThreatSourceAttribution,
    IReadOnlyList<string> ResourceTypes
);

public sealed record BrowserUrlEvaluationResult(
    string RawUrl,
    string NormalizedHost,
    bool ShouldBlock,
    bool ShouldWarnBeforeNavigation,
    bool IsTemporarilyAllowlisted,
    string Category,
    string BlockReason,
    string ThreatSourceAttribution,
    int? MatchedRuleId,
    DateTimeOffset EvaluatedAtUtc
);

public sealed record TemporaryAllowlistEntry(
    string Domain,
    string AddedByReason,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc
);

public sealed record FalsePositiveReportEntry(
    string ReportId,
    string TargetUrlOrFile,
    string Sha256OrDomain,
    string OriginalDetectionName,
    string UserNotes,
    DateTimeOffset SubmittedAtUtc,
    bool StoredLocallyOnly // Always true by default (Privacy-first)
);


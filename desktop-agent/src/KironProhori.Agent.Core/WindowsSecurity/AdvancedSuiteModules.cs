using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.BrowserProtection;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Scanning;
using KironProhori.Agent.Core.Updates;

namespace KironProhori.Agent.Core.WindowsSecurity;

/// <summary>
/// MODULE 8 — Future-Compatible Safe Banking Protection Module.
/// 
/// Requirements Enforced:
/// - Verifies HTTPS transport, anti-phishing indicators, IDN homograph spoofing, and suspicious redirects.
/// - Clearly identifies recognized trusted banking domains (Bangladesh &amp; international financial institutions).
/// - NEVER collects banking credentials, NEVER records keyboard input, and NEVER captures screenshots.
/// - Marks Hardened Browser Process Isolation as SuiteFeatureState.Planned (never falsely claims opening a browser window makes banking 100% secure).
/// </summary>
public sealed class SafeBankingProtectionModule
{
    public const string HonestBankingLimitationNotice =
        "Safe Banking URL Verification checks HTTPS encryption, anti-phishing rules, and suspicious redirect parameters. " +
        "Dedicated Hardened Browser Process Isolation is marked as PLANNED (not enabled in V1.0). " +
        "KIRON PROHORI never collects banking credentials, never logs keystrokes, and never captures your screen.";

    private static readonly HashSet<string> RecognizedTrustedBankingDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bb.org.bd",
        "sonalibank.com.bd",
        "dutchbanglabank.com",
        "bracbank.com",
        "thecitybank.com",
        "islami-bank.com",
        "bkash.com",
        "nagad.com.bd",
        "ebbl.com.bd",
        "primebank.com.bd"
    };

    private readonly NativeMessagingDownloadGuard _webGuard;

    public SuiteFeatureState UrlVerificationState => SuiteFeatureState.Enabled;
    public SuiteFeatureState HardenedBrowserIsolationState => SuiteFeatureState.Planned;

    public SafeBankingProtectionModule(NativeMessagingDownloadGuard? webGuard = null)
    {
        _webGuard = webGuard ?? new NativeMessagingDownloadGuard();
    }

    public static IReadOnlyCollection<string> GetRecognizedTrustedBankingDomains() => RecognizedTrustedBankingDomains;

    public SafeBankingVerificationResult VerifyBankingUrl(string rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl) || !Uri.TryCreate(rawUrl.Trim(), UriKind.Absolute, out var uri))
        {
            return new SafeBankingVerificationResult(
                InputUrl: rawUrl ?? "",
                NormalizedHost: "",
                IsHttpsEncrypted: false,
                IsRecognizedTrustedFinancialDomain: false,
                HasPhishingOrRedirectRisk: true,
                UrlVerificationState: SuiteFeatureState.Enabled,
                HardenedBrowserIsolationState: SuiteFeatureState.Planned,
                VerdictSummary: "INVALID_URL: Cannot verify banking safety for a malformed URL.",
                HonestLimitationNotice: HonestBankingLimitationNotice
            );
        }

        bool isHttps = uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        string host = uri.Host.ToLowerInvariant().TrimEnd('.');
        var webEval = _webGuard.EvaluateUrl(rawUrl);

        bool isRecognizedBank = RecognizedTrustedBankingDomains.Any(d =>
            host.Equals(d, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

        bool hasRisk = !isHttps || webEval.ShouldBlock || webEval.ShouldWarnBeforeNavigation;

        string summary;
        if (webEval.ShouldBlock)
        {
            summary = $"BLOCKED_PHISHING_OR_MALICIOUS: {webEval.BlockReason}";
        }
        else if (!isHttps)
        {
            summary = "UNSAFE_NON_HTTPS: Financial websites must use encrypted HTTPS transport.";
        }
        else if (webEval.ShouldWarnBeforeNavigation)
        {
            summary = $"SUSPICIOUS_REDIRECT_OR_LOOKALIKE: {webEval.BlockReason}";
        }
        else if (isRecognizedBank)
        {
            summary = $"VERIFIED_HTTPS_FINANCIAL_DOMAIN ({host}) · Hardened Browser Isolation: PLANNED";
        }
        else
        {
            summary = $"HTTPS_VERIFIED_UNLISTED_DOMAIN ({host}) · No phishing indicators matched · Hardened Browser Isolation: PLANNED";
        }

        return new SafeBankingVerificationResult(
            InputUrl: rawUrl,
            NormalizedHost: host,
            IsHttpsEncrypted: isHttps,
            IsRecognizedTrustedFinancialDomain: isRecognizedBank,
            HasPhishingOrRedirectRisk: hasRisk,
            UrlVerificationState: SuiteFeatureState.Enabled,
            HardenedBrowserIsolationState: SuiteFeatureState.Planned,
            VerdictSummary: summary,
            HonestLimitationNotice: HonestBankingLimitationNotice
        );
    }
}

/// <summary>
/// MODULE 9 — Future-Compatible Email and Attachment Security Scanner.
/// 
/// Requirements Enforced:
/// - Scans user-provided downloaded email attachments locally using ModularScanPipeline.
/// - Detects suspicious executable attachments, script formats (.vbs, .js, .ps1, .hta), macro-enabled documents (.docm, .xlsm),
///   and potentially dangerous archive containers (.zip, .rar, .7z, .iso, .cab).
/// - NEVER accesses private email accounts or inboxes without an explicitly configured and authorized integration (DirectMailboxAccessState = Planned).
/// - NEVER automatically deletes email messages or user files.
/// </summary>
public sealed class EmailAttachmentSecurityScanner
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".msi", ".dll", ".pif"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vbs", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat", ".cmd", ".hta", ".lnk"
    };

    private static readonly HashSet<string> MacroDocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".SLK"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".tar", ".gz"
    };

    private readonly ModularScanPipeline _scanPipeline;

    public SuiteFeatureState LocalAttachmentScannerState => SuiteFeatureState.Enabled;
    public SuiteFeatureState DirectMailboxAccessState => SuiteFeatureState.Planned;

    public EmailAttachmentSecurityScanner(ModularScanPipeline? scanPipeline = null)
    {
        _scanPipeline = scanPipeline ?? new ModularScanPipeline();
    }

    public async Task<EmailAttachmentScanResult> ScanDownloadedAttachmentAsync(
        string attachmentFilePath,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        string fileName = Path.GetFileName(attachmentFilePath);
        string formatCategory = ClassifyAttachmentFormat(fileName);

        if (string.IsNullOrWhiteSpace(attachmentFilePath) || !File.Exists(attachmentFilePath))
        {
            return new EmailAttachmentScanResult(
                AttachmentFilePath: attachmentFilePath ?? "",
                FileName: fileName ?? "",
                FormatCategory: formatCategory,
                ScanStatus: DownloadScanStatus.UnknownNotScanned,
                Sha256Hash: "NOT_SCANNED",
                DetectionSummary: "Unknown / Not scanned: Attachment file does not exist on disk.",
                DirectMailboxAccessState: SuiteFeatureState.Planned,
                ScannedAtUtc: now
            );
        }

        string sha256 = await Sha256HashEngine.ComputeFileSha256Async(
            attachmentFilePath,
            cancellationToken,
            scanType: ScanType.SingleFileScan).ConfigureAwait(false);

        var report = await _scanPipeline.ScanSingleFileAsync(
            attachmentFilePath,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        DownloadScanStatus status;
        string summary;

        if (report.Findings.Any(f => f.Verdict == DetectionVerdict.ConfirmedDetection))
        {
            var top = report.Findings.First(f => f.Verdict == DetectionVerdict.ConfirmedDetection);
            status = DownloadScanStatus.Malicious;
            summary = $"MALICIOUS ATTACHMENT: {top.DetectionName} ({formatCategory}) — Recommended: Quarantine First.";
        }
        else if (report.Findings.Any(f => f.Verdict == DetectionVerdict.Suspicious) ||
                 formatCategory is "EXECUTABLE_ATTACHMENT" or "SCRIPT_ATTACHMENT" or "MACRO_DOCUMENT")
        {
            var top = report.Findings.FirstOrDefault();
            status = DownloadScanStatus.Suspicious;
            summary = top != null
                ? $"SUSPICIOUS ATTACHMENT: {top.DetectionName} ({formatCategory}) — Recommended: Quarantine First."
                : $"HIGH-RISK ATTACHMENT FORMAT ({formatCategory}): Verify sender authenticity before opening.";
        }
        else
        {
            status = DownloadScanStatus.Clean;
            summary = $"Clean according to local SHA-256 and heuristic engines ({formatCategory}).";
        }

        return new EmailAttachmentScanResult(
            AttachmentFilePath: attachmentFilePath,
            FileName: fileName,
            FormatCategory: formatCategory,
            ScanStatus: status,
            Sha256Hash: sha256,
            DetectionSummary: summary,
            DirectMailboxAccessState: SuiteFeatureState.Planned,
            ScannedAtUtc: now
        );
    }

    public static string ClassifyAttachmentFormat(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return "UNKNOWN";
        string ext = Path.GetExtension(fileName);
        if (ExecutableExtensions.Contains(ext)) return "EXECUTABLE_ATTACHMENT";
        if (ScriptExtensions.Contains(ext)) return "SCRIPT_ATTACHMENT";
        if (MacroDocumentExtensions.Contains(ext)) return "MACRO_DOCUMENT";
        if (ArchiveExtensions.Contains(ext)) return "ARCHIVE_CONTAINER";
        return "STANDARD_DOCUMENT";
    }
}

/// <summary>
/// MODULE 10 — Privacy-Conscious Cloud Threat Intelligence Provider Interface &amp; Offline-Safe Implementation.
/// 
/// Privacy &amp; Architectural Rules:
/// - No telemetry, no analytics, no advertising, no mandatory user account.
/// - No automatic file uploads or sample submissions.
/// - Uses local SHA-256 hashes only; operates 100% offline-safe by default.
/// - Marks live cloud reputation endpoint as SuiteFeatureState.Unavailable unless a verified HTTPS endpoint is configured.
/// </summary>
public interface ICloudThreatIntelligenceProvider
{
    SuiteFeatureState LiveCloudReputationState { get; }
    SuiteFeatureState OfflineLocalDefinitionsState { get; }
    bool IsVerifiedHttpsEndpointConfigured { get; }
    CloudReputationLookupResult LookupSha256ReputationOfflineSafe(string sha256Hash);
}

public sealed class PrivacyFirstCloudThreatIntelligenceService : ICloudThreatIntelligenceProvider
{
    public const string PrivacyAndMetadataDisclosure =
        "Zero Telemetry & Zero Automatic File Uploads: KIRON PROHORI never uploads your personal documents, passwords, " +
        "or browsing history. When optional HTTPS threat-intelligence updates or hash lookups are configured and invoked, " +
        "standard HTTPS requests naturally expose your IP address and ordinary network metadata to the service provider.";

    private readonly string? _configuredHttpsEndpoint;
    private readonly SecureUpdateManager _updateManager;

    public bool IsVerifiedHttpsEndpointConfigured { get; }
    public SuiteFeatureState LiveCloudReputationState =>
        IsVerifiedHttpsEndpointConfigured ? SuiteFeatureState.Enabled : SuiteFeatureState.Unavailable;
    public SuiteFeatureState OfflineLocalDefinitionsState => SuiteFeatureState.Enabled;

    public PrivacyFirstCloudThreatIntelligenceService(
        string? configuredHttpsEndpoint = null,
        SecureUpdateManager? updateManager = null)
    {
        _updateManager = updateManager ?? new SecureUpdateManager();
        if (!string.IsNullOrWhiteSpace(configuredHttpsEndpoint) &&
            Uri.TryCreate(configuredHttpsEndpoint, UriKind.Absolute, out var uri) &&
            uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            _configuredHttpsEndpoint = configuredHttpsEndpoint;
            IsVerifiedHttpsEndpointConfigured = true;
        }
        else
        {
            _configuredHttpsEndpoint = null;
            IsVerifiedHttpsEndpointConfigured = false;
        }
    }

    public CloudReputationLookupResult LookupSha256ReputationOfflineSafe(string sha256Hash)
    {
        string normalized = (sha256Hash ?? "").Trim().ToLowerInvariant();
        bool matchedLocal = Sha256HashEngine.TryLookupKnownThreat(normalized, out string? threatName);

        return new CloudReputationLookupResult(
            Sha256Hash: normalized,
            CloudProviderState: LiveCloudReputationState,
            MatchedLocalVerifiedCorpus: matchedLocal,
            ThreatLabel: matchedLocal && !string.IsNullOrWhiteSpace(threatName)
                ? threatName
                : (IsVerifiedHttpsEndpointConfigured
                    ? "No match in local corpus (HTTPS cloud provider configured)"
                    : "No match in local corpus (Live Cloud Reputation: UNAVAILABLE — operating in Offline-Safe Local Mode)"),
            PrivacyAndNetworkDisclosure: PrivacyAndMetadataDisclosure,
            EvaluatedAtUtc: DateTimeOffset.UtcNow
        );
    }
}

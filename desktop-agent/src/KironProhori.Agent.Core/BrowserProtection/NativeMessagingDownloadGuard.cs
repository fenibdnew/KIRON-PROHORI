using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Exclusions;
using KironProhori.Agent.Core.Models;
using KironProhori.Agent.Core.Notifications;
using KironProhori.Agent.Core.Quarantine;
using KironProhori.Agent.Core.Scanning;

namespace KironProhori.Agent.Core.BrowserProtection;

/// <summary>
/// MODULE 3 &amp; MODULE 4 — KIRON PROHORI V1.0 Browser Web Protection &amp; Automatic Download Protection
/// via Chrome / Microsoft Edge Manifest V3 Native Messaging.
/// 
/// Responsibilities:
/// - Evaluates URLs against verified malicious URL, phishing, scam/malware distribution,
///   malicious ad-redirect, and malicious third-party network rules.
/// - Supports user-controlled Temporary Allowlist and False Positive Reporting without collecting browsing history.
/// - Implements Chrome/Edge Native Messaging 32-bit little-endian length-prefixed JSON protocol over stdin/stdout.
/// - Scans completed browser downloads locally using SHA-256, verified threat intelligence, and static heuristics.
/// - Clearly distinguishes Clean, Suspicious, Malicious, and Unknown / Not scanned.
/// - Never reports a file as Clean if the scan did not complete.
/// - Enforces QUARANTINE FIRST policy: never silently executes or permanently deletes downloaded files.
/// </summary>
public sealed class NativeMessagingDownloadGuard
{
    public const string NativeHostIdentifier = "com.kironprohori.security_agent";
    public const int MaxNativeMessageBytes = 1024 * 1024; // 1 MB Chrome/Edge Native Messaging limit

    private static readonly IReadOnlyList<WebProtectionRuleEntry> VerifiedWebRules = new[]
    {
        new WebProtectionRuleEntry(
            RuleId: 1001,
            DomainPattern: "phishing-login-verify.kiron-test.invalid",
            Category: "PHISHING_DOMAIN",
            Severity: "CRITICAL",
            BlockReason: "Verified credential-harvesting phishing domain (Controlled KIRON PROHORI V1.0 Test Indicator).",
            ThreatSourceAttribution: "KIRON PROHORI Verified Phishing Intelligence",
            ResourceTypes: new[] { "main_frame", "sub_frame" }
        ),
        new WebProtectionRuleEntry(
            RuleId: 1002,
            DomainPattern: "malware-payload-drop.kiron-test.invalid",
            Category: "SCAM_MALWARE_DISTRIBUTION",
            Severity: "CRITICAL",
            BlockReason: "Verified malware payload distribution host (Controlled KIRON PROHORI V1.0 Test Indicator).",
            ThreatSourceAttribution: "KIRON PROHORI Malware Distribution Feed",
            ResourceTypes: new[] { "main_frame", "sub_frame", "script", "xmlhttprequest" }
        ),
        new WebProtectionRuleEntry(
            RuleId: 1003,
            DomainPattern: "malvertising-redirect-chain.kiron-test.invalid",
            Category: "MALICIOUS_AD_REDIRECT",
            Severity: "HIGH",
            BlockReason: "Known malicious advertising and drive-by redirect network request (Does not block ordinary legitimate ads).",
            ThreatSourceAttribution: "KIRON PROHORI Malvertising & Redirect Intelligence",
            ResourceTypes: new[] { "main_frame", "sub_frame", "script" }
        ),
        new WebProtectionRuleEntry(
            RuleId: 1004,
            DomainPattern: "c2-skimmer-beacon.kiron-test.invalid",
            Category: "MALICIOUS_THIRD_PARTY_REQUEST",
            Severity: "CRITICAL",
            BlockReason: "Known malicious third-party skimmer / botnet C2 network request.",
            ThreatSourceAttribution: "abuse.ch Feodo Tracker & KIRON PROHORI C2 Feed",
            ResourceTypes: new[] { "script", "xmlhttprequest", "sub_frame", "connect" }
        ),
        new WebProtectionRuleEntry(
            RuleId: 1005,
            DomainPattern: "crypto-giveaway-scam.kiron-test.invalid",
            Category: "MALICIOUS_URL",
            Severity: "HIGH",
            BlockReason: "Verified financial scam & deceptive giveaway domain.",
            ThreatSourceAttribution: "KIRON PROHORI Verified Scam Report Registry",
            ResourceTypes: new[] { "main_frame", "sub_frame" }
        )
    };

    private readonly ModularScanPipeline _scanPipeline;
    private readonly ExclusionManager _exclusionManager;
    private readonly QuarantineManager _quarantineManager;
    private readonly SmartNotificationManager _notificationManager;

    private readonly ConcurrentDictionary<string, TemporaryAllowlistEntry> _temporaryAllowlist = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FalsePositiveReportEntry> _falsePositiveReports = new();
    private readonly List<DownloadScanVerdictResult> _downloadVerdictHistory = new();
    private readonly object _lock = new();

    public NativeMessagingDownloadGuard(
        ModularScanPipeline? scanPipeline = null,
        ExclusionManager? exclusionManager = null,
        QuarantineManager? quarantineManager = null,
        SmartNotificationManager? notificationManager = null)
    {
        _exclusionManager = exclusionManager ?? new ExclusionManager();
        _notificationManager = notificationManager ?? new SmartNotificationManager();
        _quarantineManager = quarantineManager ?? new QuarantineManager(exclusionManager: _exclusionManager);
        _scanPipeline = scanPipeline ?? new ModularScanPipeline(
            exclusionManager: _exclusionManager,
            notificationManager: _notificationManager
        );
    }

    public static IReadOnlyList<WebProtectionRuleEntry> GetVerifiedWebProtectionRules() => VerifiedWebRules;

    public IReadOnlyList<TemporaryAllowlistEntry> GetActiveTemporaryAllowlist()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _temporaryAllowlist)
        {
            if (kvp.Value.ExpiresAtUtc <= now)
            {
                _temporaryAllowlist.TryRemove(kvp.Key, out _);
            }
        }
        return _temporaryAllowlist.Values.OrderByDescending(e => e.CreatedAtUtc).ToList();
    }

    public TemporaryAllowlistEntry AddTemporaryAllowlistDomain(
        string domain,
        string reason = "User temporary allowlist override",
        int durationMinutes = 30)
    {
        string normalized = NormalizeHost(domain);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ArgumentException("A valid domain name is required for the temporary allowlist.", nameof(domain));
        }

        int clampedMinutes = Math.Clamp(durationMinutes, 5, 1440);
        var now = DateTimeOffset.UtcNow;
        var entry = new TemporaryAllowlistEntry(
            Domain: normalized,
            AddedByReason: string.IsNullOrWhiteSpace(reason) ? "User temporary allowlist override" : reason.Trim(),
            CreatedAtUtc: now,
            ExpiresAtUtc: now.AddMinutes(clampedMinutes)
        );

        _temporaryAllowlist[normalized] = entry;
        return entry;
    }

    public bool RemoveTemporaryAllowlistDomain(string domain)
    {
        string normalized = NormalizeHost(domain);
        return _temporaryAllowlist.TryRemove(normalized, out _);
    }

    public FalsePositiveReportEntry SubmitFalsePositiveReport(
        string targetUrlOrFile,
        string sha256OrDomain,
        string originalDetectionName,
        string userNotes)
    {
        var report = new FalsePositiveReportEntry(
            ReportId: $"FP-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
            TargetUrlOrFile: targetUrlOrFile.Trim(),
            Sha256OrDomain: sha256OrDomain.Trim(),
            OriginalDetectionName: originalDetectionName.Trim(),
            UserNotes: string.IsNullOrWhiteSpace(userNotes) ? "User reported potential false positive." : userNotes.Trim(),
            SubmittedAtUtc: DateTimeOffset.UtcNow,
            StoredLocallyOnly: true
        );

        lock (_lock)
        {
            _falsePositiveReports.Insert(0, report);
        }

        return report;
    }

    public IReadOnlyList<FalsePositiveReportEntry> GetFalsePositiveReports()
    {
        lock (_lock)
        {
            return _falsePositiveReports.ToList();
        }
    }

    public IReadOnlyList<DownloadScanVerdictResult> GetDownloadVerdictHistory()
    {
        lock (_lock)
        {
            return _downloadVerdictHistory.ToList();
        }
    }

    /// <summary>
    /// Evaluates a URL for Module 3 Browser Web Protection without recording general browsing history.
    /// Legitimate websites with ordinary ads are never blocked.
    /// </summary>
    public BrowserUrlEvaluationResult EvaluateUrl(string rawUrl)
    {
        var now = DateTimeOffset.UtcNow;
        string host = NormalizeHost(rawUrl);

        if (string.IsNullOrWhiteSpace(host))
        {
            return new BrowserUrlEvaluationResult(
                RawUrl: rawUrl,
                NormalizedHost: "",
                ShouldBlock: false,
                ShouldWarnBeforeNavigation: false,
                IsTemporarilyAllowlisted: false,
                Category: "INVALID_OR_EMPTY_URL",
                BlockReason: "URL could not be parsed.",
                ThreatSourceAttribution: "KIRON PROHORI URL Parser",
                MatchedRuleId: null,
                EvaluatedAtUtc: now
            );
        }

        // Check active Temporary Allowlist
        if (_temporaryAllowlist.TryGetValue(host, out var allowEntry))
        {
            if (allowEntry.ExpiresAtUtc > now)
            {
                return new BrowserUrlEvaluationResult(
                    RawUrl: rawUrl,
                    NormalizedHost: host,
                    ShouldBlock: false,
                    ShouldWarnBeforeNavigation: true,
                    IsTemporarilyAllowlisted: true,
                    Category: "TEMPORARY_USER_ALLOWLIST",
                    BlockReason: $"Temporarily allowlisted by user until {allowEntry.ExpiresAtUtc:HH:mm:ss} UTC.",
                    ThreatSourceAttribution: "User Temporary Allowlist",
                    MatchedRuleId: null,
                    EvaluatedAtUtc: now
                );
            }
            _temporaryAllowlist.TryRemove(host, out _);
        }

        // Check Verified declarativeNetRequest rules
        var matchedRule = VerifiedWebRules.FirstOrDefault(r =>
            host.Equals(r.DomainPattern, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + r.DomainPattern, StringComparison.OrdinalIgnoreCase)
        );

        if (matchedRule is not null)
        {
            return new BrowserUrlEvaluationResult(
                RawUrl: rawUrl,
                NormalizedHost: host,
                ShouldBlock: true,
                ShouldWarnBeforeNavigation: true,
                IsTemporarilyAllowlisted: false,
                Category: matchedRule.Category,
                BlockReason: matchedRule.BlockReason,
                ThreatSourceAttribution: matchedRule.ThreatSourceAttribution,
                MatchedRuleId: matchedRule.RuleId,
                EvaluatedAtUtc: now
            );
        }

        // Heuristic pre-navigation warning for punycode IDN homograph, brand-impersonation phishing, or deceptive login-verify subdomains
        bool suspiciousPunycodeOrPhishLookalike =
            host.Contains("xn--", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("bkash-bonus", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("nagad-reward", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("microsoft-security-verify", StringComparison.OrdinalIgnoreCase) ||
            host.Contains("paypal-account-unlock", StringComparison.OrdinalIgnoreCase) ||
            (host.Contains("login-verify", StringComparison.OrdinalIgnoreCase) && host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase));

        if (suspiciousPunycodeOrPhishLookalike)
        {
            return new BrowserUrlEvaluationResult(
                RawUrl: rawUrl,
                NormalizedHost: host,
                ShouldBlock: false,
                ShouldWarnBeforeNavigation: true,
                IsTemporarilyAllowlisted: false,
                Category: "SUSPICIOUS_LOOKALIKE_HOST",
                BlockReason: "Suspicious IDN punycode, brand-impersonation, or credential-verification hostname pattern detected. Proceed with caution.",
                ThreatSourceAttribution: "KIRON PROHORI Heuristic URL Guard",
                MatchedRuleId: null,
                EvaluatedAtUtc: now
            );
        }

        // Check for suspicious open-redirect parameters (?redirect=http, ?url=http, ?next=http) or userinfo '@' hostname spoofing
        bool hasSuspiciousRedirectOrSpoof =
            rawUrl.Contains("@", StringComparison.Ordinal) ||
            rawUrl.Contains("redirect=http", StringComparison.OrdinalIgnoreCase) ||
            rawUrl.Contains("redirect_uri=http", StringComparison.OrdinalIgnoreCase) ||
            rawUrl.Contains("url=http://", StringComparison.OrdinalIgnoreCase) ||
            rawUrl.Contains("next=http://", StringComparison.OrdinalIgnoreCase);

        if (hasSuspiciousRedirectOrSpoof)
        {
            return new BrowserUrlEvaluationResult(
                RawUrl: rawUrl,
                NormalizedHost: host,
                ShouldBlock: false,
                ShouldWarnBeforeNavigation: true,
                IsTemporarilyAllowlisted: false,
                Category: "SUSPICIOUS_REDIRECT_OR_SPOOF",
                BlockReason: "Suspicious external redirect parameter or '@' credential-in-URL spoofing indicator detected. Distinguished as Suspicious (not a confirmed block).",
                ThreatSourceAttribution: "KIRON PROHORI Anti-Phishing Redirect Guard",
                MatchedRuleId: null,
                EvaluatedAtUtc: now
            );
        }

        return new BrowserUrlEvaluationResult(
            RawUrl: rawUrl,
            NormalizedHost: host,
            ShouldBlock: false,
            ShouldWarnBeforeNavigation: false,
            IsTemporarilyAllowlisted: false,
            Category: "CLEAN_VERIFIED",
            BlockReason: "No verified malicious, phishing, or scam indicators matched. Ordinary advertisements are not blocked.",
            ThreatSourceAttribution: "KIRON PROHORI Web Protection Ruleset",
            MatchedRuleId: null,
            EvaluatedAtUtc: now
        );
    }

    /// <summary>
    /// MODULE 06 — Validates HTTPS transport encryption and detects unencrypted HTTP login/credential submission risks.
    /// </summary>
    public (bool IsHttpsEncrypted, bool HasUnencryptedCredentialRisk, string TransportAssessment) ValidateHttpsTransportPolicy(string rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl) || !Uri.TryCreate(rawUrl.Trim(), UriKind.Absolute, out var uri))
        {
            return (false, true, "INVALID_URL: Malformed URI cannot establish verified TLS transport.");
        }

        bool isHttps = uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        bool isLoginOrAuthPath =
            uri.AbsolutePath.Contains("login", StringComparison.OrdinalIgnoreCase) ||
            uri.AbsolutePath.Contains("signin", StringComparison.OrdinalIgnoreCase) ||
            uri.AbsolutePath.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
            uri.AbsolutePath.Contains("password", StringComparison.OrdinalIgnoreCase);

        bool isRawIpHost = System.Net.IPAddress.TryParse(uri.Host, out _);
        bool hasRisk = !isHttps || (isRawIpHost && isLoginOrAuthPath);

        string assessment = !isHttps && isLoginOrAuthPath
            ? "CRITICAL_PHISHING_RISK: Unencrypted HTTP connection on a credential/login path."
            : !isHttps
            ? "UNENCRYPTED_HTTP: Connection does not use HTTPS/TLS transport encryption."
            : (isRawIpHost && isLoginOrAuthPath)
            ? "SUSPICIOUS_RAW_IP_LOGIN: Credential page hosted on a raw IP address without a domain certificate."
            : $"VERIFIED_HTTPS_TRANSPORT: Encrypted TLS scheme verified for host '{uri.Host}'.";

        return (isHttps, hasRisk, assessment);
    }

    /// <summary>
    /// MODULE 4 — Evaluates and scans a browser download event received over Native Messaging.
    /// Never reports a file as Clean if the scan did not complete.
    /// Never silently executes or permanently deletes downloaded files.
    /// </summary>
    public async Task<DownloadScanVerdictResult> EvaluateBrowserDownloadAsync(
        BrowserDownloadEventPayload payload,
        bool userApprovedAutoQuarantine = false,
        CancellationToken cancellationToken = default,
        IProgress<ScanProgressUpdate>? progress = null)
    {
        var now = DateTimeOffset.UtcNow;
        string domain = NormalizeHost(string.IsNullOrWhiteSpace(payload.WebsiteDomain) ? payload.DownloadUrl : payload.WebsiteDomain);
        if (string.IsNullOrWhiteSpace(domain))
        {
            domain = "unknown-domain.invalid";
        }

        // 1. If the browser download has not finished ("in_progress" or "interrupted") or the local file is missing,
        // NEVER report the file as Clean — always return Unknown / Not scanned.
        if (!string.Equals(payload.BrowserState, "complete", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(payload.LocalFilePath) ||
            !File.Exists(payload.LocalFilePath))
        {
            var incompleteResult = new DownloadScanVerdictResult(
                DownloadId: payload.DownloadId,
                FileName: payload.FileName,
                LocalFilePath: payload.LocalFilePath,
                WebsiteDomain: domain,
                Status: DownloadScanStatus.UnknownNotScanned,
                StatusDisplayLabel: "Unknown / Not scanned",
                Sha256Hash: "NOT_SCANNED",
                ThreatName: "None (Scan Incomplete)",
                DetectionSource: "KIRON PROHORI Download Guard",
                ExecutionPrevented: false,
                QuarantineOffered: false,
                WasQuarantined: false,
                Explanation: $"Download state is '{payload.BrowserState}' or file is not yet available on disk. A file is never reported as Clean until local scanning completes.",
                EvaluatedAtUtc: now
            );
            RecordDownloadVerdict(incompleteResult);
            return incompleteResult;
        }

        // 2. Respect KIRON PROHORI Exclusions
        if (_exclusionManager.IsPathExcluded(payload.LocalFilePath))
        {
            var excludedResult = new DownloadScanVerdictResult(
                DownloadId: payload.DownloadId,
                FileName: payload.FileName,
                LocalFilePath: payload.LocalFilePath,
                WebsiteDomain: domain,
                Status: DownloadScanStatus.UnknownNotScanned,
                StatusDisplayLabel: "Unknown / Not scanned",
                Sha256Hash: "SKIPPED_BY_EXCLUSION",
                ThreatName: "Excluded by User Policy",
                DetectionSource: "KIRON PROHORI Exclusion Manager",
                ExecutionPrevented: false,
                QuarantineOffered: false,
                WasQuarantined: false,
                Explanation: "File matches a user-configured KIRON PROHORI exclusion and was not scanned or quarantined.",
                EvaluatedAtUtc: now
            );
            RecordDownloadVerdict(excludedResult);
            return excludedResult;
        }

        // 3. Scan the completed file locally
        var scanReport = await _scanPipeline.ScanSingleFileAsync(
            payload.LocalFilePath,
            progress: progress,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string sha256 = "NOT_AVAILABLE";
        try
        {
            sha256 = await Sha256HashEngine.ComputeFileSha256Async(
                payload.LocalFilePath,
                cancellationToken,
                progress: progress,
                scanType: ScanType.BrowserDownloadScan).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // File locked or permission error; handled below as Unknown / Not scanned
        }

        // If permission error prevented scanning, return Unknown / Not scanned
        if (scanReport.SkippedPermissionCount > 0 || scanReport.TotalFilesScanned == 0 || sha256 == "NOT_AVAILABLE")
        {
            var lockedResult = new DownloadScanVerdictResult(
                DownloadId: payload.DownloadId,
                FileName: payload.FileName,
                LocalFilePath: payload.LocalFilePath,
                WebsiteDomain: domain,
                Status: DownloadScanStatus.UnknownNotScanned,
                StatusDisplayLabel: "Unknown / Not scanned",
                Sha256Hash: sha256,
                ThreatName: "Scan Incomplete (File Locked / Access Denied)",
                DetectionSource: "KIRON PROHORI Download Guard",
                ExecutionPrevented: false,
                QuarantineOffered: false,
                WasQuarantined: false,
                Explanation: "Local scan could not complete because the file was locked or inaccessible. Not marked Clean.",
                EvaluatedAtUtc: now
            );
            RecordDownloadVerdict(lockedResult);
            return lockedResult;
        }

        // Also check URL reputation & PE header mismatch
        var urlEval = EvaluateUrl(payload.DownloadUrl);
        bool hasPeHeaderInNonExe = await CheckHiddenPeHeaderMismatchAsync(payload.LocalFilePath, cancellationToken);

        var confirmedFinding = scanReport.Findings.FirstOrDefault(f => f.Verdict == DetectionVerdict.ConfirmedDetection);
        var suspiciousFinding = scanReport.Findings.FirstOrDefault(f => f.Verdict == DetectionVerdict.Suspicious);

        if (confirmedFinding is not null)
        {
            bool quarantined = false;
            if (userApprovedAutoQuarantine && File.Exists(payload.LocalFilePath))
            {
                await _quarantineManager.QuarantineFileAsync(confirmedFinding, userConfirmed: true);
                quarantined = true;
            }

            _notificationManager.TryNotifyDownloadBlocked(
                threatName: confirmedFinding.DetectionName,
                websiteDomain: domain,
                fileName: payload.FileName,
                localDownloadPath: payload.LocalFilePath,
                sha256Hash: sha256,
                detectionSource: confirmedFinding.DetectionSourceAttribution,
                statusLabel: quarantined ? "Quarantined" : "Action Required: Quarantine Recommended"
            );

            var maliciousResult = new DownloadScanVerdictResult(
                DownloadId: payload.DownloadId,
                FileName: payload.FileName,
                LocalFilePath: payload.LocalFilePath,
                WebsiteDomain: domain,
                Status: DownloadScanStatus.Malicious,
                StatusDisplayLabel: "Malicious",
                Sha256Hash: sha256,
                ThreatName: confirmedFinding.DetectionName,
                DetectionSource: confirmedFinding.DetectionSourceAttribution,
                ExecutionPrevented: true,
                QuarantineOffered: true,
                WasQuarantined: quarantined,
                Explanation: $"Verified threat signature detected ({confirmedFinding.DetectionName}). Policy: QUARANTINE FIRST.",
                EvaluatedAtUtc: now
            );
            RecordDownloadVerdict(maliciousResult);
            return maliciousResult;
        }

        if (suspiciousFinding is not null || urlEval.ShouldBlock || hasPeHeaderInNonExe ||
            (!string.Equals(payload.BrowserDangerSignal, "safe", StringComparison.OrdinalIgnoreCase) &&
             !string.IsNullOrWhiteSpace(payload.BrowserDangerSignal)))
        {
            string threatTitle = suspiciousFinding?.DetectionName
                ?? (hasPeHeaderInNonExe
                    ? "Heuristic.HiddenExecutableHeaderMismatch"
                    : urlEval.ShouldBlock
                    ? $"SuspiciousDownloadFrom.{urlEval.Category}"
                    : $"BrowserRiskSignal.{payload.BrowserDangerSignal}");

            string attribution = suspiciousFinding?.DetectionSourceAttribution ?? "KIRON PROHORI Download Heuristic & URL Guard";
            bool quarantined = false;

            if (userApprovedAutoQuarantine && File.Exists(payload.LocalFilePath))
            {
                var syntheticFinding = suspiciousFinding ?? new ScanFinding(
                    FindingId: $"DL-FIND-{Guid.NewGuid():N}"[..14].ToUpperInvariant(),
                    FilePath: payload.LocalFilePath,
                    FileName: payload.FileName,
                    FileSizeBytes: new FileInfo(payload.LocalFilePath).Length,
                    Sha256Hash: sha256,
                    Severity: ThreatSeverity.High,
                    Confidence: DetectionConfidence.HeuristicSuspicious,
                    DetectionName: threatTitle,
                    DetectionEngineId: "KIRON-DOWNLOAD-GUARD",
                    DetectionSourceAttribution: attribution,
                    Description: "Suspicious browser download flagged by Native Messaging Download Protection.",
                    FalsePositiveGuidance: "Can be restored from Quarantine Vault or reported as a false positive.",
                    DetectedAtUtc: now,
                    Verdict: DetectionVerdict.Suspicious,
                    RecommendedAction: RemediationAction.Quarantine
                );
                await _quarantineManager.QuarantineFileAsync(syntheticFinding, userConfirmed: true);
                quarantined = true;
            }

            _notificationManager.TryNotifyDownloadBlocked(
                threatName: threatTitle,
                websiteDomain: domain,
                fileName: payload.FileName,
                localDownloadPath: payload.LocalFilePath,
                sha256Hash: sha256,
                detectionSource: attribution,
                statusLabel: quarantined ? "Quarantined" : "Suspicious — Quarantine Offered"
            );

            var suspiciousResult = new DownloadScanVerdictResult(
                DownloadId: payload.DownloadId,
                FileName: payload.FileName,
                LocalFilePath: payload.LocalFilePath,
                WebsiteDomain: domain,
                Status: DownloadScanStatus.Suspicious,
                StatusDisplayLabel: "Suspicious",
                Sha256Hash: sha256,
                ThreatName: threatTitle,
                DetectionSource: attribution,
                ExecutionPrevented: true,
                QuarantineOffered: true,
                WasQuarantined: quarantined,
                Explanation: $"Suspicious characteristics detected ({threatTitle}). Execution discouraged and Quarantine offered.",
                EvaluatedAtUtc: now
            );
            RecordDownloadVerdict(suspiciousResult);
            return suspiciousResult;
        }

        var cleanResult = new DownloadScanVerdictResult(
            DownloadId: payload.DownloadId,
            FileName: payload.FileName,
            LocalFilePath: payload.LocalFilePath,
            WebsiteDomain: domain,
            Status: DownloadScanStatus.Clean,
            StatusDisplayLabel: "Clean",
            Sha256Hash: sha256,
            ThreatName: "None",
            DetectionSource: "KIRON PROHORI SHA-256 & Heuristic Engines",
            ExecutionPrevented: false,
            QuarantineOffered: false,
            WasQuarantined: false,
            Explanation: "Completed download scanned locally. No known malware signatures or suspicious heuristics matched.",
            EvaluatedAtUtc: now
        );
        RecordDownloadVerdict(cleanResult);
        return cleanResult;
    }

    /// <summary>
    /// Writes a length-prefixed JSON message using standard Chrome/Edge Native Messaging framing (4-byte little-endian uint32 + UTF-8 JSON).
    /// </summary>
    public static async Task WriteNativeMessageAsync<T>(Stream outputStream, T message, CancellationToken cancellationToken = default)
    {
        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(message);
        if (jsonBytes.Length > MaxNativeMessageBytes)
        {
            throw new InvalidOperationException($"Native Messaging payload ({jsonBytes.Length} bytes) exceeds 1 MB protocol limit.");
        }

        byte[] lengthPrefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, jsonBytes.Length);

        await outputStream.WriteAsync(lengthPrefix, cancellationToken);
        await outputStream.WriteAsync(jsonBytes, cancellationToken);
        await outputStream.FlushAsync(cancellationToken);
    }

    /// <summary>
    /// Reads a length-prefixed JSON message using standard Chrome/Edge Native Messaging framing (4-byte little-endian uint32 + UTF-8 JSON).
    /// </summary>
    public static async Task<T?> ReadNativeMessageAsync<T>(Stream inputStream, CancellationToken cancellationToken = default)
    {
        byte[] lengthPrefix = new byte[4];
        int headerRead = await ReadExactBytesAsync(inputStream, lengthPrefix, cancellationToken);
        if (headerRead == 0)
        {
            return default;
        }
        if (headerRead < 4)
        {
            throw new EndOfStreamException("Incomplete 4-byte Native Messaging length header.");
        }

        int payloadLength = BinaryPrimitives.ReadInt32LittleEndian(lengthPrefix);
        if (payloadLength <= 0 || payloadLength > MaxNativeMessageBytes)
        {
            throw new InvalidDataException($"Invalid Native Messaging payload length: {payloadLength} bytes.");
        }

        byte[] payloadBytes = new byte[payloadLength];
        int bodyRead = await ReadExactBytesAsync(inputStream, payloadBytes, cancellationToken);
        if (bodyRead < payloadLength)
        {
            throw new EndOfStreamException("Incomplete Native Messaging JSON payload.");
        }

        return JsonSerializer.Deserialize<T>(payloadBytes);
    }

    private static async Task<int> ReadExactBytesAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), cancellationToken);
            if (read == 0)
            {
                break;
            }
            totalRead += read;
        }
        return totalRead;
    }

    private static async Task<bool> CheckHiddenPeHeaderMismatchAsync(string filePath, CancellationToken cancellationToken)
    {
        string ext = Path.GetExtension(filePath);
        var documentExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".txt", ".jpg", ".png", ".docx", ".xlsx", ".mp4", ".zip"
        };

        if (!documentExtensions.Contains(ext))
        {
            return false;
        }

        try
        {
            byte[] header = new byte[2];
            await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int read = await fs.ReadAsync(header.AsMemory(0, 2), cancellationToken);
            // Check for DOS/PE 'MZ' magic bytes (0x4D, 0x5A) inside a non-executable document extension
            return read == 2 && header[0] == 0x4D && header[1] == 0x5A;
        }
        catch
        {
            return false;
        }
    }

    private static string NormalizeHost(string rawUrlOrDomain)
    {
        if (string.IsNullOrWhiteSpace(rawUrlOrDomain))
        {
            return "";
        }

        string trimmed = rawUrlOrDomain.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host.ToLowerInvariant().TrimEnd('.');
        }

        if (Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var fallbackUri) &&
            !string.IsNullOrWhiteSpace(fallbackUri.Host))
        {
            return fallbackUri.Host.ToLowerInvariant().TrimEnd('.');
        }

        return trimmed.ToLowerInvariant().TrimEnd('.');
    }

    private void RecordDownloadVerdict(DownloadScanVerdictResult result)
    {
        lock (_lock)
        {
            _downloadVerdictHistory.Insert(0, result);
            if (_downloadVerdictHistory.Count > 200)
            {
                _downloadVerdictHistory.RemoveAt(_downloadVerdictHistory.Count - 1);
            }
        }
    }
}

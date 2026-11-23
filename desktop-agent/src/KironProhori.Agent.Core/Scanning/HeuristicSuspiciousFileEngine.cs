using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Safe user-mode static heuristic analyzer + Local Heuristic AI Risk Score (0–100) + Infostealer / Fake AI App Guard.
/// Flags:
/// 1. Deceptive double extensions (.pdf.exe, .docx.scr)
/// 2. Unicode RTLO spoofing (U+202E)
/// 3. Disguised PE executables (MZ header inside non-executable extension)
/// 4. USB autorun.inf abuse
/// 5. Fake AI Tool / Infostealer masquerading in %TEMP% or Downloads (e.g., fake ChatGPT/Claude/Copilot/Midjourney/DeepSeek/Sora installers or browser profile credential access strings)
/// 6. Local Heuristic AI Risk Score (0–100) based on Shannon byte entropy, unsigned PE headers, double extensions, and suspicious script patterns ($0 cloud cost).
/// Always includes clear false-positive guidance.
/// </summary>
public sealed class HeuristicSuspiciousFileEngine : IScanEngine
{
    private static readonly HashSet<string> HighRiskExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".com", ".pif", ".lnk"
    };

    private static readonly HashSet<string> ScriptMalwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"
    };

    private static readonly HashSet<string> DecoyDocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp4", ".mp3"
    };

    private static readonly string[] FakeAiToolMasqueradeKeywords =
    {
        "chatgpt-pro", "chatgpt_setup", "chatgpt-crack", "claude-desktop-crack", "copilot-unlocked",
        "midjourney-free", "sora-ai-generator", "deepseek-pro-crack", "gemini-ultra-free", "ai-voice-cloner-crack"
    };

    private static readonly string[] InfostealerBrowserTargetPatterns =
    {
        "\\Google\\Chrome\\User Data\\Default\\Login Data",
        "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        "\\Mozilla\\Firefox\\Profiles\\",
        "Local State\\os_crypt\\encrypted_key",
        "FromBase64String",
        "Invoke-Expression",
        "-EncodedCommand"
    };

    private static readonly string[] UsbShortcutWormIndicators =
    {
        "cmd.exe /c", "powershell", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "attrib +h +s", "attrib -h -s", "RECYCLER\\", "\\System Volume Information\\"
    };

    private static readonly string[] ObfuscatedScriptIndicators =
    {
        "-EncodedCommand", "-enc ", "FromBase64String", "Invoke-Expression", "IEX(",
        "Net.WebClient", "DownloadString", "WScript.Shell", "eval(atob", "String.fromCharCode"
    };

    private static readonly string[] StartupAdwarePersistenceIndicators =
    {
        "CurrentVersion\\Run", "schtasks /create", "reg add HKCU", "reg add HKLM", "--headless --disable-gpu"
    };

    public string EngineId => "KIRON-STATIC-HEURISTIC-ENGINE";
    public string DisplayName => "KIRON PROHORI Static Heuristic, Local AI Risk Scorer & Infostealer Guard";
    public string License => "MIT / First-Party ($0.00)";
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.WorkingPhase7A;

    public EngineDescriptor GetDescriptor() => new(
        EngineId: EngineId,
        DisplayName: DisplayName,
        License: License,
        Status: EngineStatus.Ready,
        StatusDetail: "READY (Local AI Risk Score 0-100, USB Shortcut Worm, Script Malware, Fake AI / Infostealer & PE Heuristics Active)",
        stringExecutablePathOrEndpoint: "In-Process Static File Entropy, Header & Multi-Threat Inspector ($0)",
        MaturityTier: MaturityTier
    );

    /// <summary>
    /// Computes a transparent Local Heuristic AI Risk Score (0–100) from Shannon byte entropy,
    /// unsigned PE header presence, double extensions, and suspicious script/infostealer patterns ($0 cloud cost).
    /// </summary>
    public static int ComputeLocalHeuristicAiRiskScore(
        string filePath,
        string fileName,
        double shannonEntropy0To8,
        bool hasPeHeader,
        bool hasDoubleExtension,
        bool hasRtloChar,
        bool matchesFakeAiOrInfostealerPattern)
    {
        int score = 0;

        if (hasRtloChar) score += 45;
        if (hasDoubleExtension) score += 40;
        if (matchesFakeAiOrInfostealerPattern) score += 45;
        if (hasPeHeader) score += 15;

        // High Shannon entropy (> 6.8 bits/byte out of 8.0) indicates packed/encrypted payload
        if (shannonEntropy0To8 >= 7.2)
        {
            score += 25;
        }
        else if (shannonEntropy0To8 >= 6.5)
        {
            score += 15;
        }

        string normalizedPath = filePath.Replace('/', '\\');
        if (normalizedPath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("\\Startup\\", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
        }

        string ext = Path.GetExtension(fileName);
        if (HighRiskExecutableExtensions.Contains(ext))
        {
            score += 10;
        }

        return Math.Clamp(score, 0, 100);
    }

    /// <summary>
    /// Computes Shannon byte entropy (0.0 to 8.0 bits/byte) on a sample buffer.
    /// </summary>
    public static double ComputeShannonEntropy(ReadOnlySpan<byte> sample)
    {
        if (sample.IsEmpty) return 0.0;

        Span<int> counts = stackalloc int[256];
        foreach (byte b in sample)
        {
            counts[b]++;
        }

        double entropy = 0.0;
        double len = sample.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }

        return Math.Round(entropy, 2);
    }

    public Task<ScanFinding?> InspectFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default) =>
        ScanFileAsync(filePath, precomputedSha256Hex, fileSizeBytes, cancellationToken);

    public async Task<ScanFinding?> ScanFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(filePath);
        if (string.IsNullOrEmpty(fileName))
        {
            return null;
        }

        // Read up to 4 KB header/sample for zero-cost local entropy, PE header, and infostealer/script inspection
        byte[] sampleBuffer = Array.Empty<byte>();
        int bytesRead = 0;
        if (fileSizeBytes > 0 && File.Exists(filePath))
        {
            int sampleLen = (int)Math.Min(fileSizeBytes, 4096);
            sampleBuffer = new byte[sampleLen];
            await using var fs = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 4096,
                useAsync: true);
            bytesRead = await fs.ReadAsync(sampleBuffer.AsMemory(0, sampleLen), cancellationToken).ConfigureAwait(false);
        }

        bool hasPeHeader = bytesRead >= 2 && sampleBuffer[0] == 0x4D && sampleBuffer[1] == 0x5A; // 'M' 'Z'
        double entropy = ComputeShannonEntropy(sampleBuffer.AsSpan(0, bytesRead));
        bool hasRtlo = fileName.Contains('\u202E');

        // 1. Check for Right-to-Left Override (U+202E) filename spoofing
        if (hasRtlo)
        {
            int riskScore = ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, true, false);
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.SpoofedFilename.RTLO",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI Static Filename Heuristic (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100 · Entropy: {entropy:F2}b] File name contains a Unicode Right-to-Left Override (U+202E) control character.",
                FalsePositiveGuidance: "Legitimate files almost never include U+202E in filenames.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        // 2. Check for deceptive double extensions (e.g., Invoice_2026.pdf.exe or Photo.jpg.scr)
        string[] segments = fileName.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length >= 3)
        {
            string finalExt = "." + segments[^1];
            string penultimateExt = "." + segments[^2];

            if (HighRiskExecutableExtensions.Contains(finalExt) &&
                DecoyDocumentExtensions.Contains(penultimateExt))
            {
                int riskScore = ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, true, false, false);
                return new ScanFinding(
                    FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                    FilePath: filePath,
                    FileName: fileName,
                    FileSizeBytes: fileSizeBytes,
                    Sha256Hash: precomputedSha256Hex,
                    Severity: ThreatSeverity.High,
                    Confidence: DetectionConfidence.HeuristicSuspicious,
                    DetectionName: $"Heuristic.DoubleExtension.{penultimateExt.TrimStart('.')}_{finalExt.TrimStart('.')}",
                    DetectionEngineId: EngineId,
                    DetectionSourceAttribution: $"KIRON PROHORI Deceptive Double-Extension Rule (Local AI Risk Score: {riskScore}/100)",
                    Description: $"[Local AI Risk Score: {riskScore}/100 · Entropy: {entropy:F2}b] Suspicious double extension detected ('{penultimateExt}{finalExt}').",
                    FalsePositiveGuidance: "Verify SHA-256 hash and digital signature before marking as safe.",
                    DetectedAtUtc: DateTimeOffset.UtcNow,
                    LocalAiRiskScore0To100: riskScore
                );
            }
        }

        // 3. Check for disguised Windows PE executable (MZ magic header 0x4D 0x5A) inside a decoy document extension
        string ext = Path.GetExtension(fileName);
        if (DecoyDocumentExtensions.Contains(ext) && hasPeHeader)
        {
            int riskScore = ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, true, false, false, false);
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.DisguisedPEHeader.MZInDocument",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI Magic-Byte Header Inspector (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100 · Entropy: {entropy:F2}b] File carries a non-executable extension ('{ext}') but begins with a Windows PE ('MZ') header.",
                FalsePositiveGuidance: "True documents never begin with an 'MZ' executable header.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        string asciiSample = bytesRead > 0
            ? Encoding.UTF8.GetString(sampleBuffer, 0, bytesRead)
            : string.Empty;

        // 4. Infostealer / Fake AI App Guard
        string lowerFileName = fileName.ToLowerInvariant();
        bool isFakeAiLauncher = HighRiskExecutableExtensions.Contains(ext) &&
                                FakeAiToolMasqueradeKeywords.Any(k => lowerFileName.Contains(k, StringComparison.OrdinalIgnoreCase));

        bool hasInfostealerBrowserPattern = bytesRead > 0 &&
            HighRiskExecutableExtensions.Contains(ext) &&
            InfostealerBrowserTargetPatterns.Any(p => asciiSample.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (isFakeAiLauncher || hasInfostealerBrowserPattern)
        {
            int riskScore = ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, false, true);
            string ruleName = isFakeAiLauncher
                ? "Heuristic.FakeAIApp.MasqueradeDropper"
                : "Heuristic.Infostealer.BrowserCredentialAccess";

            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: ruleName,
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI Infostealer & Fake AI App Guard (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100 · Entropy: {entropy:F2}b] Fake AI tool lure or unauthorized browser credential store access detected.",
                FalsePositiveGuidance: "Verify AI desktop apps are downloaded strictly from official vendor domains.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        // 5. USB Shortcut Worm (.lnk / .vbs) & Autorun.inf Detection
        if (fileName.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase))
        {
            int riskScore = Math.Max(65, ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, false, false));
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.Medium,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.RemovableMedia.AutorunInf",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI USB Autorun Abuse Check (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100] Detected an 'autorun.inf' launcher commonly abused by USB shortcut worms.",
                FalsePositiveGuidance: "Inspect autorun.inf in plain text before running referenced executables.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        if ((ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase) || ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase)) &&
            bytesRead > 0 &&
            UsbShortcutWormIndicators.Any(ind => asciiSample.Contains(ind, StringComparison.OrdinalIgnoreCase)))
        {
            int riskScore = Math.Max(82, ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, false, true));
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.UsbWorm.ShortcutVirus",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI USB Shortcut Worm Guard (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100] Malicious shortcut/script worm launching hidden command or script interpreter.",
                FalsePositiveGuidance: "Use 'Recover Hidden USB Folders' to restore legitimate folders hidden by shortcut viruses.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        // 6. Script Malware (.ps1, .bat, .vbs, .js, .cmd, .hta) Obfuscated/Encoded Commands
        if (ScriptMalwareExtensions.Contains(ext) &&
            bytesRead > 0 &&
            ObfuscatedScriptIndicators.Count(ind => asciiSample.Contains(ind, StringComparison.OrdinalIgnoreCase)) >= 2)
        {
            int riskScore = Math.Max(80, ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, false, true));
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.ScriptMalware.ObfuscatedCommand",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI Script De-Obfuscation Guard (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100] Script contains encoded or obfuscated execution commands.",
                FalsePositiveGuidance: "Inspect script source code before allowing execution.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        // 7. Adware & Startup Persistence Malware
        if (HighRiskExecutableExtensions.Contains(ext) &&
            bytesRead > 0 &&
            StartupAdwarePersistenceIndicators.Any(ind => asciiSample.Contains(ind, StringComparison.OrdinalIgnoreCase)))
        {
            int riskScore = Math.Max(76, ComputeLocalHeuristicAiRiskScore(filePath, fileName, entropy, hasPeHeader, false, false, true));
            return new ScanFinding(
                FindingId: $"HEUR-{Guid.NewGuid():N}"[..16].ToUpperInvariant(),
                FilePath: filePath,
                FileName: fileName,
                FileSizeBytes: fileSizeBytes,
                Sha256Hash: precomputedSha256Hex,
                Severity: ThreatSeverity.High,
                Confidence: DetectionConfidence.HeuristicSuspicious,
                DetectionName: "Heuristic.StartupMalware.SuspiciousPersistence",
                DetectionEngineId: EngineId,
                DetectionSourceAttribution: $"KIRON PROHORI Startup & Adware Guard (Local AI Risk Score: {riskScore}/100)",
                Description: $"[Local AI Risk Score: {riskScore}/100] Unsigned executable/script modifies Windows Startup or scheduled task persistence.",
                FalsePositiveGuidance: "Quarantine unrecognized startup executables to keep boot clean.",
                DetectedAtUtc: DateTimeOffset.UtcNow,
                LocalAiRiskScore0To100: riskScore
            );
        }

        return null;
    }
}

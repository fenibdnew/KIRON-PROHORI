using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Safe user-mode static heuristic analyzer.
/// Flags deceptive double extensions (.pdf.exe, .docx.scr), Unicode RTLO spoofing,
/// and disguised PE executables (MZ header inside non-executable extension).
/// Always includes clear false-positive guidance.
/// </summary>
public sealed class HeuristicSuspiciousFileEngine : IScanEngine
{
    private static readonly HashSet<string> HighRiskExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".com", ".pif"
    };

    private static readonly HashSet<string> DecoyDocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp4", ".mp3"
    };

    public string EngineId => "KIRON-STATIC-HEURISTIC-ENGINE";
    public string DisplayName => "KIRON PROHORI Static Heuristic & Extension Spoofing Analyzer";
    public string License => "MIT / First-Party ($0.00)";
    public FeatureMaturityTier MaturityTier => FeatureMaturityTier.WorkingPhase7A;

    public EngineDescriptor GetDescriptor() => new(
        EngineId: EngineId,
        DisplayName: DisplayName,
        License: License,
        Status: EngineStatus.Ready,
        StatusDetail: "READY (Deceptive double-extension, RTLO spoofing, and PE-header disguise heuristics active)",
        stringExecutablePathOrEndpoint: "In-Process Static File Header & Filename Inspector",
        MaturityTier: MaturityTier
    );

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

        // 1. Check for Right-to-Left Override (U+202E) filename spoofing
        if (fileName.Contains('\u202E'))
        {
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
                DetectionSourceAttribution: "KIRON PROHORI Static Filename Heuristic",
                Description: "File name contains a Unicode Right-to-Left Override (U+202E) control character commonly used to disguise executable extensions as benign documents.",
                FalsePositiveGuidance: "Legitimate files almost never include U+202E in filenames. Inspect the raw extension carefully before opening.",
                DetectedAtUtc: DateTimeOffset.UtcNow
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
                    DetectionSourceAttribution: "KIRON PROHORI Deceptive Double-Extension Rule",
                    Description: $"Suspicious double extension detected ('{penultimateExt}{finalExt}'). Attackers frequently hide Windows executables behind document or image extensions when Windows 'Hide extensions for known file types' is enabled.",
                    FalsePositiveGuidance: "Heuristic detection: If you intentionally named an installer or script with multiple dots, verify its SHA-256 hash and digital signature before marking as safe.",
                    DetectedAtUtc: DateTimeOffset.UtcNow
                );
            }
        }

        // 3. Check for disguised Windows PE executable (MZ magic header 0x4D 0x5A) inside a decoy document extension (.pdf, .jpg, .png, .txt)
        string ext = Path.GetExtension(fileName);
        if (DecoyDocumentExtensions.Contains(ext) && fileSizeBytes >= 64 && File.Exists(filePath))
        {
            byte[] header = new byte[2];
            await using var fs = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 64,
                useAsync: true);
            int read = await fs.ReadAsync(header.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
            if (read == 2 && header[0] == 0x4D && header[1] == 0x5A) // 'M' 'Z' DOS/PE Header
            {
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
                    DetectionSourceAttribution: "KIRON PROHORI Magic-Byte Header Inspector",
                    Description: $"File carries a non-executable extension ('{ext}') but begins with a Windows Portable Executable ('MZ' / 0x4D5A) binary header.",
                    FalsePositiveGuidance: "Heuristic detection: True PDF, image, or text files never begin with an 'MZ' executable header. Do not rename or execute this file.",
                    DetectedAtUtc: DateTimeOffset.UtcNow
                );
            }
        }

        // 4. Check for autorun.inf on removable drives
        if (fileName.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase))
        {
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
                DetectionSourceAttribution: "KIRON PROHORI USB Autorun Abuse Check",
                Description: "Detected an 'autorun.inf' configuration file. While occasionally used by legacy legitimate media, USB-borne worms frequently abuse autorun.inf to launch hidden payloads.",
                FalsePositiveGuidance: "Inspect the text contents of autorun.inf in a plain text viewer before opening any executables referenced by 'open=' or 'shellexecute='.",
                DetectedAtUtc: DateTimeOffset.UtcNow
            );
        }

        return null;
    }
}

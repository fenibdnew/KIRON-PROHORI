using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Modular scanning engine contract.
/// Every engine must inspect files strictly read-only without ever executing them or uploading file contents.
/// </summary>
public interface IScanEngine
{
    string EngineId { get; }
    string DisplayName { get; }
    string License { get; }
    FeatureMaturityTier MaturityTier { get; }

    /// <summary>
    /// Returns current operational readiness (e.g., Ready vs InstallationRequired if ClamAV is missing).
    /// </summary>
    EngineDescriptor GetDescriptor();

    /// <summary>
    /// Inspects a single local file strictly read-only. Returns null if clean.
    /// </summary>
    Task<ScanFinding?> ScanFileAsync(
        string filePath,
        string precomputedSha256Hex,
        long fileSizeBytes,
        CancellationToken cancellationToken = default);
}

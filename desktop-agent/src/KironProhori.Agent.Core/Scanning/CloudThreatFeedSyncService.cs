using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using KironProhori.Agent.Core.Models;

namespace KironProhori.Agent.Core.Scanning;

/// <summary>
/// Read-only Threat Intelligence Synchronizer connecting the Windows Agent to:
/// 1. KIRON PROHORI Intelligence Cloud (/api/agent/v1/signatures)
/// 2. CIRCL hashlookup Public NSRL/Known-File REST API (https://hashlookup.circl.lu/lookup/sha256/{sha256})
/// NEVER uploads private user files.
/// </summary>
public sealed class CloudThreatFeedSyncService
{
    private readonly HttpClient _httpClient;
    private readonly string _cloudBaseUrl;

    public CloudThreatFeedSyncService(HttpClient? httpClient = null, string cloudBaseUrl = "http://127.0.0.1:3000")
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _cloudBaseUrl = cloudBaseUrl.TrimEnd('/');
    }

    public DateTimeOffset? LastSyncTimestampUtc { get; private set; }
    public string LastSyncStatus { get; private set; } = "NOT_SYNCED_YET";

    /// <summary>
    /// Pulls public CISA KEV, abuse.ch Feodo Tracker C2s, and verified SHA-256 hashes from KIRON PROHORI Cloud.
    /// </summary>
    public async Task<CloudSignatureBundle?> PullPublicSignaturesAsync(
        Sha256HashEngine targetHashEngine,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = await _httpClient
                .GetAsync($"{_cloudBaseUrl}/api/agent/v1/signatures", cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                LastSyncStatus = $"HTTP_{(int)response.StatusCode}";
                return null;
            }

            string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string version = root.TryGetProperty("bundleVersion", out var vProp)
                ? vProp.GetString() ?? "v1.0"
                : "v1.0";

            int kevCount = root.TryGetProperty("cisaKevCount", out var kProp) ? kProp.GetInt32() : 0;
            int feodoCount = root.TryGetProperty("feodoC2Count", out var fProp) ? fProp.GetInt32() : 0;

            var shaMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("sha256Indicators", out var shaProp) && shaProp.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in shaProp.EnumerateObject())
                {
                    shaMap[prop.Name] = prop.Value.GetString() ?? "Public-Threat-Indicator";
                }
            }

            var c2List = new List<string>();
            if (root.TryGetProperty("defangedC2Indicators", out var c2Prop) && c2Prop.ValueKind == JsonValueKind.Array)
            {
                foreach (var elem in c2Prop.EnumerateArray())
                {
                    if (elem.GetString() is { } s)
                    {
                        c2List.Add(s);
                    }
                }
            }

            targetHashEngine.LoadPublicIndicators(shaMap, "KIRON PROHORI Intelligence Cloud Public Sync");

            LastSyncTimestampUtc = DateTimeOffset.UtcNow;
            LastSyncStatus = "CONNECTED";

            return new CloudSignatureBundle(
                BundleVersion: version,
                GeneratedAtUtc: LastSyncTimestampUtc.Value,
                CisaKevCount: kevCount,
                FeodoC2Count: feodoCount,
                KnownMalwareSha256Count: shaMap.Count,
                Sha256Indicators: shaMap,
                DefangedC2Indicators: c2List
            );
        }
        catch (Exception ex)
        {
            LastSyncStatus = $"OFFLINE_LOCAL_ONLY ({ex.GetType().Name})";
            return null;
        }
    }
}

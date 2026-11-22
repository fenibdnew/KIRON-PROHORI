/**
 * KIRON PROHORI V1.0 — Chrome & Microsoft Edge Manifest V3 Service Worker
 * Developer: ARIFUZZAMAN KIRON
 * Privacy Policy: NO TELEMETRY BY DEFAULT · Zero Browsing-History Collection · Zero Arbitrary Script Injection
 */

const NATIVE_HOST_NAME = 'com.kironprohori.security_agent';
const ALLOWLIST_RULE_BASE_ID = 50000;
const ALLOWLIST_CLEANUP_ALARM = 'kiron_prohori_allowlist_cleanup';

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({
    kironProduct: 'KIRON PROHORI V1.0',
    kironDeveloper: 'ARIFUZZAMAN KIRON',
    telemetryEnabled: false,
    browsingHistoryCollected: false,
    nativeAgentStatus: 'CHECKING',
    recentDownloadVerdicts: [],
    temporaryAllowlist: [],
    falsePositiveReports: [],
  });
  chrome.alarms.create(ALLOWLIST_CLEANUP_ALARM, { periodInMinutes: 5 });
  await checkNativeAgentHeartbeat();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALLOWLIST_CLEANUP_ALARM) {
    await pruneExpiredAllowlistRules();
  }
});

/**
 * Checks whether the local KIRON PROHORI Windows Desktop Agent Native Messaging host is reachable.
 * Never fabricates a CONNECTED status if the native host is unavailable.
 */
async function checkNativeAgentHeartbeat() {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(
        NATIVE_HOST_NAME,
        { type: 'PING_STATUS', timestampUtc: new Date().toISOString() },
        async (response) => {
          if (chrome.runtime.lastError || !response || !response.ok) {
            const errMsg = chrome.runtime.lastError
              ? chrome.runtime.lastError.message
              : 'Windows Desktop Agent Native Messaging host not reachable.';
            await chrome.storage.local.set({
              nativeAgentStatus: 'NOT AVAILABLE',
              nativeAgentError: errMsg,
            });
            resolve({ ok: false, status: 'NOT AVAILABLE', error: errMsg });
            return;
          }
          await chrome.storage.local.set({
            nativeAgentStatus: 'PROTECTED',
            nativeAgentError: null,
            nativeAgentVersion: response.version || '1.0.0',
          });
          resolve({ ok: true, status: 'PROTECTED', response });
        }
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      chrome.storage.local.set({
        nativeAgentStatus: 'NOT AVAILABLE',
        nativeAgentError: msg,
      });
      resolve({ ok: false, status: 'NOT AVAILABLE', error: msg });
    }
  });
}

/**
 * MODULE 4 — Automatic Download Protection via Native Messaging
 * 1. Detect browser download event.
 * 2. Collect minimum necessary metadata (download URL, filename, local path, browser danger signal).
 * 3. Never mark an incomplete or unscanned download as Clean.
 */
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const initialRecord = {
    downloadId: String(downloadItem.id),
    fileName: downloadItem.filename || 'pending-download',
    websiteDomain: extractDomain(downloadItem.finalUrl || downloadItem.url || ''),
    status: 'Unknown / Not scanned',
    sha256: 'PENDING_COMPLETION',
    threatName: 'None (Download In Progress)',
    explanation: 'Download is still in progress. Never reported as Clean until local SHA-256 and heuristic scan completes.',
    evaluatedAtUtc: new Date().toISOString(),
  };
  await prependDownloadVerdict(initialRecord);
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== 'complete') {
    if (delta.state && delta.state.current === 'interrupted') {
      await prependDownloadVerdict({
        downloadId: String(delta.id),
        fileName: 'interrupted-download',
        websiteDomain: 'unknown',
        status: 'Unknown / Not scanned',
        sha256: 'NOT_SCANNED',
        threatName: 'Download Interrupted',
        explanation: 'Download did not complete; local file was not scanned and is not marked Clean.',
        evaluatedAtUtc: new Date().toISOString(),
      });
    }
    return;
  }

  const items = await chrome.downloads.search({ id: delta.id });
  const item = items && items[0];
  if (!item) return;

  const payload = {
    type: 'SCAN_COMPLETED_DOWNLOAD',
    DownloadId: String(item.id),
    DownloadUrl: item.finalUrl || item.url || '',
    WebsiteDomain: extractDomain(item.finalUrl || item.url || ''),
    FileName: extractFileName(item.filename || ''),
    LocalFilePath: item.filename || '',
    BrowserState: item.state || 'complete',
    BrowserDangerSignal: item.danger || 'safe',
    MimeType: item.mime || 'application/octet-stream',
    TimestampUtc: new Date().toISOString(),
  };

  chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, payload, async (response) => {
    if (chrome.runtime.lastError || !response) {
      const errText = chrome.runtime.lastError
        ? chrome.runtime.lastError.message
        : 'Local Windows Agent Native Messaging host did not respond.';
      await prependDownloadVerdict({
        downloadId: String(item.id),
        fileName: payload.FileName,
        localFilePath: payload.LocalFilePath,
        websiteDomain: payload.WebsiteDomain,
        status: 'Unknown / Not scanned',
        sha256: 'NOT_SCANNED',
        threatName: 'Local Agent Unavailable',
        explanation: `Unknown / Not scanned: ${errText}. File is never reported as Clean when the local scan could not complete.`,
        evaluatedAtUtc: new Date().toISOString(),
      });
      return;
    }

    const verdictRecord = {
      downloadId: String(item.id),
      fileName: response.FileName || payload.FileName,
      localFilePath: response.LocalFilePath || payload.LocalFilePath,
      websiteDomain: response.WebsiteDomain || payload.WebsiteDomain,
      status: response.StatusDisplayLabel || 'Unknown / Not scanned',
      sha256: response.Sha256Hash || 'UNKNOWN',
      threatName: response.ThreatName || 'None',
      detectionSource: response.DetectionSource || 'KIRON PROHORI Windows Agent',
      quarantineOffered: Boolean(response.QuarantineOffered),
      wasQuarantined: Boolean(response.WasQuarantined),
      explanation: response.Explanation || '',
      evaluatedAtUtc: response.EvaluatedAtUtc || new Date().toISOString(),
    };

    await prependDownloadVerdict(verdictRecord);

    if (verdictRecord.status === 'Malicious' || verdictRecord.status === 'Suspicious') {
      chrome.notifications.create(`kiron_dl_${item.id}`, {
        type: 'basic',
        iconUrl: '/blocked/shield-icon.png',
        title: 'KIRON PROHORI — Suspicious Download Blocked',
        message: `Threat: ${verdictRecord.threatName} | Website: ${verdictRecord.websiteDomain} | File: ${verdictRecord.fileName} | Policy: Quarantine First`,
        priority: 2,
      });
    }
  });
});

/**
 * Handles messages from the Blocked Page UI and Extension Popup:
 * - ADD_TEMPORARY_ALLOWLIST (30-minute user-controlled declarativeNetRequest allow rule)
 * - REMOVE_TEMPORARY_ALLOWLIST
 * - REPORT_FALSE_POSITIVE (stored locally without telemetry upload)
 * - CHECK_NATIVE_AGENT
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (!message || typeof message.action !== 'string') {
      sendResponse({ ok: false, error: 'Invalid message action.' });
      return;
    }

    if (message.action === 'CHECK_NATIVE_AGENT') {
      const res = await checkNativeAgentHeartbeat();
      sendResponse(res);
      return;
    }

    if (message.action === 'ADD_TEMPORARY_ALLOWLIST') {
      const domain = normalizeDomain(message.domain || '');
      if (!domain) {
        sendResponse({ ok: false, error: 'Valid domain required.' });
        return;
      }

      const durationMinutes = Math.min(120, Math.max(5, Number(message.durationMinutes) || 30));
      const now = Date.now();
      const expiresAtMs = now + durationMinutes * 60 * 1000;
      const ruleId = ALLOWLIST_RULE_BASE_ID + Math.floor(Math.random() * 9000);

      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [
          {
            id: ruleId,
            priority: 100, // Overrides priority 10 static block rule during user allowlist window
            action: { type: 'allow' },
            condition: {
              urlFilter: `||${domain}^`,
              resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest'],
            },
          },
        ],
      });

      const store = await chrome.storage.local.get(['temporaryAllowlist']);
      const list = Array.isArray(store.temporaryAllowlist) ? store.temporaryAllowlist : [];
      const filtered = list.filter((e) => e.domain !== domain);
      const entry = {
        ruleId,
        domain,
        reason: message.reason || 'User temporary allowlist override (30m)',
        createdAtUtc: new Date(now).toISOString(),
        expiresAtUtc: new Date(expiresAtMs).toISOString(),
        expiresAtMs,
      };
      filtered.unshift(entry);
      await chrome.storage.local.set({ temporaryAllowlist: filtered });
      sendResponse({ ok: true, entry });
      return;
    }

    if (message.action === 'REMOVE_TEMPORARY_ALLOWLIST') {
      const domain = normalizeDomain(message.domain || '');
      const store = await chrome.storage.local.get(['temporaryAllowlist']);
      const list = Array.isArray(store.temporaryAllowlist) ? store.temporaryAllowlist : [];
      const toRemove = list.filter((e) => e.domain === domain);
      const remaining = list.filter((e) => e.domain !== domain);

      if (toRemove.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: toRemove.map((e) => e.ruleId),
        });
      }
      await chrome.storage.local.set({ temporaryAllowlist: remaining });
      sendResponse({ ok: true, removedCount: toRemove.length });
      return;
    }

    if (message.action === 'REPORT_FALSE_POSITIVE') {
      const store = await chrome.storage.local.get(['falsePositiveReports']);
      const reports = Array.isArray(store.falsePositiveReports) ? store.falsePositiveReports : [];
      const reportEntry = {
        reportId: `FP-${Date.now()}`,
        domainOrFile: String(message.domainOrFile || '').trim(),
        ruleIdOrHash: String(message.ruleIdOrHash || '').trim(),
        notes: String(message.notes || 'User reported false positive from blocked page').trim(),
        submittedAtUtc: new Date().toISOString(),
        storedLocallyOnly: true,
      };
      reports.unshift(reportEntry);
      await chrome.storage.local.set({ falsePositiveReports: reports.slice(0, 100) });
      sendResponse({ ok: true, report: reportEntry });
      return;
    }

    sendResponse({ ok: false, error: 'Unsupported message action.' });
  })();
  return true;
});

async function pruneExpiredAllowlistRules() {
  const now = Date.now();
  const store = await chrome.storage.local.get(['temporaryAllowlist']);
  const list = Array.isArray(store.temporaryAllowlist) ? store.temporaryAllowlist : [];
  const expired = list.filter((e) => e.expiresAtMs <= now);
  const active = list.filter((e) => e.expiresAtMs > now);

  if (expired.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: expired.map((e) => e.ruleId),
    });
    await chrome.storage.local.set({ temporaryAllowlist: active });
  }
}

async function prependDownloadVerdict(record) {
  const store = await chrome.storage.local.get(['recentDownloadVerdicts']);
  const list = Array.isArray(store.recentDownloadVerdicts) ? store.recentDownloadVerdicts : [];
  const withoutDuplicateId = list.filter((r) => r.downloadId !== record.downloadId);
  withoutDuplicateId.unshift(record);
  await chrome.storage.local.set({
    recentDownloadVerdicts: withoutDuplicateId.slice(0, 50),
  });
}

function extractDomain(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return 'unknown-domain.invalid';
  }
}

function normalizeDomain(raw) {
  const trimmed = String(raw || '').trim().toLowerCase();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return trimmed;
  }
}

function extractFileName(fullPath) {
  if (!fullPath) return 'download.bin';
  const parts = String(fullPath).split(/[\\/]/);
  return parts[parts.length - 1] || fullPath;
}

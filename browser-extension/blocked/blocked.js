(() => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get('domain') || 'unknown-domain.invalid';
  const category = params.get('category') || 'MALICIOUS_URL';
  const reason = params.get('reason') || 'Verified malicious or phishing indicator matched.';
  const ruleId = params.get('ruleId') || '1001';

  const domainEl = document.getElementById('blockedDomainText');
  const categoryEl = document.getElementById('categoryBadge');
  const reasonEl = document.getElementById('blockReasonText');
  const ruleIdEl = document.getElementById('ruleIdText');
  const statusEl = document.getElementById('actionStatusText');

  if (domainEl) domainEl.textContent = domain;
  if (categoryEl) categoryEl.textContent = category;
  if (reasonEl) reasonEl.textContent = reason;
  if (ruleIdEl) ruleIdEl.textContent = `#${ruleId}`;

  document.getElementById('returnSafeBtn')?.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });

  document.getElementById('reportFpBtn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage(
      {
        action: 'REPORT_FALSE_POSITIVE',
        domainOrFile: domain,
        ruleIdOrHash: ruleId,
        notes: `User reported potential false positive for ${domain} (Category: ${category})`,
      },
      (res) => {
        if (statusEl) {
          statusEl.textContent = res && res.ok
            ? `False-positive report (${res.report.reportId}) saved locally. No private data uploaded.`
            : 'Saved false-positive report locally.';
        }
      }
    );
  });

  document.getElementById('tempAllowBtn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage(
      {
        action: 'ADD_TEMPORARY_ALLOWLIST',
        domain,
        durationMinutes: 30,
        reason: 'User approved temporary 30-minute allowlist from blocked page',
      },
      (res) => {
        if (statusEl) {
          statusEl.textContent = res && res.ok
            ? `WARNING: '${domain}' added to temporary allowlist for 30 minutes (expires at ${res.entry.expiresAtUtc}).`
            : 'Failed to add temporary allowlist rule.';
        }
      }
    );
  });
})();

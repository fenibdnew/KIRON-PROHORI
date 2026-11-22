(() => {
  const nativeEl = document.getElementById('nativeAgentLinkStatus');
  const dlContainer = document.getElementById('downloadVerdictsContainer');
  const allowContainer = document.getElementById('allowlistContainer');

  chrome.runtime.sendMessage({ action: 'CHECK_NATIVE_AGENT' }, (res) => {
    if (nativeEl) {
      if (res && res.ok) {
        nativeEl.textContent = 'CONNECTED (Native Messaging)';
        nativeEl.style.color = '#6ee7b7';
      } else {
        nativeEl.textContent = 'NOT AVAILABLE (Agent Not Connected)';
        nativeEl.style.color = '#fcd34d';
      }
    }
  });

  chrome.storage.local.get(
    ['recentDownloadVerdicts', 'temporaryAllowlist'],
    (store) => {
      const verdicts = Array.isArray(store.recentDownloadVerdicts)
        ? store.recentDownloadVerdicts
        : [];
      if (dlContainer && verdicts.length > 0) {
        dlContainer.innerHTML = '';
        for (const v of verdicts.slice(0, 5)) {
          const div = document.createElement('div');
          div.className = 'list-item';
          div.textContent = `[${v.status}] ${v.fileName} (${v.websiteDomain}) · ${v.threatName}`;
          dlContainer.appendChild(div);
        }
      }

      const allowlist = Array.isArray(store.temporaryAllowlist)
        ? store.temporaryAllowlist
        : [];
      if (allowContainer && allowlist.length > 0) {
        allowContainer.innerHTML = '';
        for (const item of allowlist) {
          const div = document.createElement('div');
          div.className = 'list-item';
          div.textContent = `${item.domain} (expires ${item.expiresAtUtc.slice(11, 19)} UTC)`;
          allowContainer.appendChild(div);
        }
      }
    }
  );
})();

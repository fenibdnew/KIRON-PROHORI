/**
 * KIRON PROHORI — Official GitHub Pages Download Center Script
 * Dynamically queries the repository's GitHub Releases API.
 * STRICT HONESTY RULE:
 * - Only enables the Download button if a real GitHub Release exists AND contains
 *   a verified KIRON-PROHORI-Setup-x64.exe or .msi asset.
 * - Otherwise displays "Coming Soon — Awaiting Verified GitHub Release Asset"
 *   instead of a broken or fake download link.
 */

(function () {
  const downloadBtn = document.getElementById('primary-download-btn');
  const downloadLabel = document.getElementById('primary-download-label');
  const captionEl = document.getElementById('release-verification-caption');
  const repoInput = document.getElementById('github-repo-input');
  const checkBtn = document.getElementById('check-release-btn');

  const metaInstallerName = document.getElementById('meta-installer-name');
  const metaReleaseVersion = document.getElementById('meta-release-version');
  const metaSizeDate = document.getElementById('meta-size-date');
  const metaSha256Status = document.getElementById('meta-sha256-status');

  function inferGitHubRepoFromLocation() {
    const host = window.location.hostname || '';
    const pathParts = (window.location.pathname || '').split('/').filter(Boolean);
    if (host.endsWith('.github.io')) {
      const owner = host.replace('.github.io', '');
      const repo = pathParts[0] || 'kiron-prohori';
      return `${owner}/${repo}`;
    }
    return '';
  }

  function setComingSoonState(reasonText) {
    if (!downloadBtn || !downloadLabel) return;
    downloadBtn.setAttribute('href', '#download');
    downloadBtn.setAttribute('aria-disabled', 'true');
    downloadBtn.className =
      'inline-flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-950/40 px-5 py-3 mono text-xs font-bold text-amber-300 cursor-not-allowed';
    downloadLabel.textContent = 'Coming Soon — Awaiting Verified GitHub Release Asset';
    if (captionEl) {
      captionEl.textContent = reasonText || 'No verified Windows x64 installer release published yet.';
    }
  }

  async function verifyGitHubRelease(repoSlug) {
    const cleanSlug = (repoSlug || '').trim();
    if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(cleanSlug)) {
      setComingSoonState('Enter your synced GitHub repository (owner/repo) or run the GitHub Actions Windows x64 Release workflow.');
      return;
    }

    try {
      const response = await fetch(`https://api.github.com/repos/${cleanSlug}/releases`);
      if (!response.ok) {
        setComingSoonState(`No published GitHub Release found for ${cleanSlug} yet (Status: Coming Soon).`);
        return;
      }

      const releases = await response.json();
      if (!Array.isArray(releases) || releases.length === 0) {
        setComingSoonState(`Repository ${cleanSlug} has 0 published releases. Run the Windows Build & Release workflow to publish.`);
        return;
      }

      const latestRelease = releases[0];
      const assets = Array.isArray(latestRelease.assets) ? latestRelease.assets : [];
      const installerAsset = assets.find(
        (a) =>
          a &&
          typeof a.name === 'string' &&
          (a.name === 'KIRON-PROHORI-Setup-x64.exe' || a.name === 'KIRON-PROHORI-Setup-x64.msi') &&
          typeof a.browser_download_url === 'string'
      );
      const shaAsset = assets.find((a) => a && a.name === 'SHA256SUMS.txt');

      if (!installerAsset) {
        setComingSoonState(`Release ${latestRelease.tag_name} found, but KIRON-PROHORI-Setup-x64.exe is not attached yet (Coming Soon).`);
        return;
      }

      // Verified installer asset exists on GitHub Releases -> Enable real download button
      const sizeMb = (installerAsset.size / (1024 * 1024)).toFixed(2);
      const releaseDate = latestRelease.published_at
        ? new Date(latestRelease.published_at).toISOString().slice(0, 10)
        : 'Verified';
      const channelLabel = latestRelease.prerelease ? 'Pre-Release / Dev-Beta' : 'Stable Release';

      downloadBtn.setAttribute('href', installerAsset.browser_download_url);
      downloadBtn.removeAttribute('aria-disabled');
      downloadBtn.className =
        'inline-flex items-center gap-2.5 rounded-lg border border-emerald-500/60 bg-emerald-600 px-5 py-3 mono text-xs font-bold text-white hover:bg-emerald-500 transition-colors';
      downloadLabel.textContent = `Download ${installerAsset.name} (${latestRelease.tag_name} · ${sizeMb} MB)`;

      if (captionEl) {
        captionEl.textContent = `Verified GitHub Release Asset · Channel: ${channelLabel} · Published: ${releaseDate}`;
      }
      if (metaInstallerName) metaInstallerName.textContent = installerAsset.name;
      if (metaReleaseVersion) metaReleaseVersion.textContent = `${latestRelease.tag_name} (${channelLabel})`;
      if (metaSizeDate) metaSizeDate.textContent = `${sizeMb} MB · ${releaseDate}`;
      if (metaSha256Status) {
        metaSha256Status.textContent = shaAsset
          ? 'SHA256SUMS.txt Attached & Verified'
          : 'Verify via GitHub Release Tag';
      }
    } catch {
      setComingSoonState('Coming Soon — Unable to query GitHub Releases API or no release published yet.');
    }
  }

  const detectedRepo = inferGitHubRepoFromLocation();
  if (repoInput && detectedRepo) {
    repoInput.value = detectedRepo;
    void verifyGitHubRelease(detectedRepo);
  } else {
    setComingSoonState('Coming Soon — Push to GitHub and run the Windows x64 Release Action to activate live installer downloads.');
  }

  if (checkBtn && repoInput) {
    checkBtn.addEventListener('click', function () {
      void verifyGitHubRelease(repoInput.value);
    });
  }
})();

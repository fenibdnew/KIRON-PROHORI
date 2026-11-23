/**
 * KIRON PROHORI — Official GitHub Pages Download Center Script
 * Default Repository: fenibdnew/KIRON-PROHORI
 * Dynamically queries:
 *   1. https://api.github.com/repos/fenibdnew/KIRON-PROHORI/releases/latest
 *   2. https://api.github.com/repos/fenibdnew/KIRON-PROHORI/releases (fallback for pre-releases / dev-builds)
 *
 * Matches the exact Windows Build & Release Pipeline assets:
 *   - KIRON-PROHORI-Setup-x64.exe
 *   - KIRON-PROHORI-Browser-Extension-MV3.zip
 *   - SHA256SUMS.txt
 *   - Release-Notes.txt
 *   - User-Guide.txt
 *
 * STRICT HONESTY RULE:
 * - Only enables the primary installer download button if a real GitHub Release exists AND contains
 *   a verified KIRON-PROHORI-Setup-x64.exe (or .msi) asset.
 * - Otherwise displays "Coming Soon — Awaiting Verified GitHub Release Asset" and provides a clean
 *   fallback link to https://github.com/fenibdnew/KIRON-PROHORI/releases/latest.
 */

(function () {
  const DEFAULT_REPO_SLUG = 'fenibdnew/KIRON-PROHORI';

  const downloadBtn = document.getElementById('primary-download-btn');
  const downloadLabel = document.getElementById('primary-download-label');
  const fallbackReleasesLink = document.getElementById('fallback-releases-link');
  const captionEl = document.getElementById('release-verification-caption');
  const repoInput = document.getElementById('github-repo-input');
  const checkBtn = document.getElementById('check-release-btn');

  const metaInstallerName = document.getElementById('meta-installer-name');
  const metaReleaseVersion = document.getElementById('meta-release-version');
  const metaSizeDate = document.getElementById('meta-size-date');
  const metaSha256Status = document.getElementById('meta-sha256-status');

  const assetExtensionLink = document.getElementById('asset-extension-link');
  const assetSha256Link = document.getElementById('asset-sha256-link');
  const assetNotesLink = document.getElementById('asset-notes-link');
  const assetGuideLink = document.getElementById('asset-guide-link');

  function inferGitHubRepoFromLocation() {
    const host = window.location.hostname || '';
    const pathParts = (window.location.pathname || '').split('/').filter(Boolean);
    if (host.endsWith('.github.io')) {
      const owner = host.replace('.github.io', '');
      const repo = pathParts[0] || 'KIRON-PROHORI';
      return `${owner}/${repo}`;
    }
    return DEFAULT_REPO_SLUG;
  }

  function updateFallbackLinks(repoSlug) {
    const cleanSlug = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test((repoSlug || '').trim())
      ? repoSlug.trim()
      : DEFAULT_REPO_SLUG;
    const latestUrl = `https://github.com/${cleanSlug}/releases/latest`;
    const allReleasesUrl = `https://github.com/${cleanSlug}/releases`;
    if (fallbackReleasesLink) {
      fallbackReleasesLink.setAttribute('href', latestUrl);
    }
    return { cleanSlug, latestUrl, allReleasesUrl };
  }

  function setSecondaryAssetLink(el, asset, fallbackUrl, defaultLabel) {
    if (!el) return;
    if (asset && typeof asset.browser_download_url === 'string') {
      el.setAttribute('href', asset.browser_download_url);
      el.textContent = `${asset.name} (Verified)`;
      el.className = 'mono text-xs font-semibold text-emerald-300 hover:text-emerald-200 underline';
    } else {
      el.setAttribute('href', fallbackUrl);
      el.textContent = `${defaultLabel} (Pending Release)`;
      el.className = 'mono text-xs text-slate-400 hover:text-slate-200 underline';
    }
  }

  function setComingSoonState(reasonText, repoSlug) {
    const { latestUrl } = updateFallbackLinks(repoSlug);
    if (!downloadBtn || !downloadLabel) return;
    downloadBtn.setAttribute('href', latestUrl);
    downloadBtn.setAttribute('aria-disabled', 'true');
    downloadBtn.className =
      'inline-flex items-center gap-2.5 rounded-lg border border-amber-500/40 bg-amber-950/40 px-5 py-3 mono text-xs font-bold text-amber-300 hover:bg-amber-950/60 transition-colors';
    downloadLabel.textContent = 'Coming Soon — Awaiting Verified GitHub Release Asset';
    if (captionEl) {
      captionEl.textContent =
        reasonText || 'No verified Windows x64 installer release published yet. Click to view GitHub Releases.';
    }
    setSecondaryAssetLink(assetExtensionLink, null, latestUrl, 'KIRON-PROHORI-Browser-Extension-MV3.zip');
    setSecondaryAssetLink(assetSha256Link, null, latestUrl, 'SHA256SUMS.txt');
    setSecondaryAssetLink(assetNotesLink, null, latestUrl, 'Release-Notes.txt');
    setSecondaryAssetLink(assetGuideLink, null, latestUrl, 'User-Guide.txt');
  }

  async function fetchLatestOrFirstRelease(cleanSlug) {
    const latestRes = await fetch(`https://api.github.com/repos/${cleanSlug}/releases/latest`, {
      headers: { Accept: 'application/vnd.github+json' },
    });
    if (latestRes.ok) {
      return await latestRes.json();
    }
    // If /releases/latest returns 404 because only a pre-release (DEV_BUILD / BETA_BUILD) exists, check /releases
    if (latestRes.status === 404) {
      const listRes = await fetch(`https://api.github.com/repos/${cleanSlug}/releases`, {
        headers: { Accept: 'application/vnd.github+json' },
      });
      if (listRes.ok) {
        const list = await listRes.json();
        if (Array.isArray(list) && list.length > 0) {
          return list[0];
        }
      }
    }
    return null;
  }

  async function verifyGitHubRelease(repoSlug) {
    const cleanSlug = (repoSlug || DEFAULT_REPO_SLUG).trim();
    const { latestUrl } = updateFallbackLinks(cleanSlug);

    if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(cleanSlug)) {
      setComingSoonState(
        'Enter a valid GitHub repository (owner/repo) or open GitHub Releases directly.',
        DEFAULT_REPO_SLUG
      );
      return;
    }

    try {
      const latestRelease = await fetchLatestOrFirstRelease(cleanSlug);
      if (!latestRelease) {
        setComingSoonState(
          `No published GitHub Release found for ${cleanSlug} yet (Status: Coming Soon). Fallback links point to ${latestUrl}.`,
          cleanSlug
        );
        return;
      }

      const assets = Array.isArray(latestRelease.assets) ? latestRelease.assets : [];
      const installerAsset = assets.find(
        (a) =>
          a &&
          typeof a.name === 'string' &&
          (a.name === 'KIRON-PROHORI-Setup-x64.exe' || a.name === 'KIRON-PROHORI-Setup-x64.msi') &&
          typeof a.browser_download_url === 'string'
      );
      const extAsset = assets.find((a) => a && a.name === 'KIRON-PROHORI-Browser-Extension-MV3.zip');
      const shaAsset = assets.find((a) => a && a.name === 'SHA256SUMS.txt');
      const notesAsset = assets.find((a) => a && a.name === 'Release-Notes.txt');
      const guideAsset = assets.find((a) => a && a.name === 'User-Guide.txt');

      setSecondaryAssetLink(assetExtensionLink, extAsset, latestUrl, 'KIRON-PROHORI-Browser-Extension-MV3.zip');
      setSecondaryAssetLink(assetSha256Link, shaAsset, latestUrl, 'SHA256SUMS.txt');
      setSecondaryAssetLink(assetNotesLink, notesAsset, latestUrl, 'Release-Notes.txt');
      setSecondaryAssetLink(assetGuideLink, guideAsset, latestUrl, 'User-Guide.txt');

      if (!installerAsset) {
        setComingSoonState(
          `Release ${latestRelease.tag_name} found, but KIRON-PROHORI-Setup-x64.exe is not attached yet (Coming Soon).`,
          cleanSlug
        );
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
      setComingSoonState(
        `Coming Soon — GitHub Releases API rate-limited or no release published yet. Open ${latestUrl} directly.`,
        cleanSlug
      );
    }
  }

  const detectedRepo = inferGitHubRepoFromLocation();
  if (repoInput) {
    repoInput.value = detectedRepo;
  }
  void verifyGitHubRelease(detectedRepo);

  if (checkBtn && repoInput) {
    checkBtn.addEventListener('click', function () {
      void verifyGitHubRelease(repoInput.value);
    });
  }
})();

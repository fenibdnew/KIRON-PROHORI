# KIRON PROHORI V1.0 — GitHub-First Distribution & Google Drive Manual Backup Procedure

**Product**: KIRON PROHORI — Windows Security & Antivirus V1.0  
**Developer**: ARIFUZZAMAN KIRON  
**Primary Distribution Platform**: GitHub Actions + GitHub Releases + GitHub Pages (`$0` Budget)  
**Secondary Archival Mirror**: Google Drive (Manual Backup Only — Never a Required Application Dependency)

---

## 1. GitHub-First Release Workflow (Developer Build, Beta Build, Stable V1.0)

1. **Automated Windows x64 Build (`/.github/workflows/windows-build-and-release.yml`)**:
   - Triggered automatically on `main` pushes, `v*` version tags, or manual `workflow_dispatch` in your connected GitHub repository.
   - Runs on `ubuntu-latest` (verifying all `34/34` Web Threat Intelligence & zero-cost checks) and `windows-latest` (restoring `.NET 8.0`, running all `20/20` xUnit tests, publishing `KironProhori.Desktop.exe` and `KironProhori.Service.exe`, and compiling `KIRON-PROHORI-Setup-x64.exe` via Inno Setup 6).
2. **Generated Release Assets**:
   - `KIRON-PROHORI-Setup-x64.exe` (Compiled Windows 10/11 x64 installer)
   - `KIRON-PROHORI-Browser-Extension-MV3.zip` (Chrome & Microsoft Edge Manifest V3 extension package)
   - `SHA256SUMS.txt` (Computed directly from the actual generated files via `Get-FileHash -Algorithm SHA256`)
   - `Release-Notes.txt`
   - `User-Guide.txt`
3. **GitHub Pages Download Website (`/.github/workflows/deploy-github-pages.yml` & `/docs/website/`)**:
   - In your GitHub Repository, navigate to **Settings &rarr; Pages &rarr; Build and deployment &rarr; Source** and select **GitHub Actions**.
   - The workflow publishes `/docs/website/index.html` and `/docs/website/app.js` containing all 10 required sections (`Home`, `Download`, `Features`, `Installation Guide`, `System Requirements`, `Release Notes`, `Privacy Policy`, `License`, `About`, `Contact and Security Reporting`).
   - The Download button dynamically queries the GitHub Releases API and displays **"Coming Soon — Awaiting Verified GitHub Release Asset"** until a real verified `KIRON-PROHORI-Setup-x64.exe` release asset exists.

---

## 2. Phase 5 — Safe Google Drive Manual Backup Procedure

> **CRITICAL ARCHITECTURAL RULE**: Google Drive is used strictly as an offline/secondary manual backup and mirror for the developer (`ARIFUZZAMAN KIRON`). The KIRON PROHORI application, updater, and browser extension **never** depend on Google Drive APIs or require a Google account.

### Step-by-Step Manual Archival Procedure

1. **Download Official Artifacts from GitHub Releases**:
   - After the `windows-build-and-release.yml` GitHub Action succeeds and publishes a release tag (e.g., `v1.0.0-DEV_BUILD` or `v1.0.0-BETA_BUILD`), download all five release files to a clean local folder:
     - `KIRON-PROHORI-Setup-x64.exe`
     - `KIRON-PROHORI-Browser-Extension-MV3.zip`
     - `SHA256SUMS.txt`
     - `Release-Notes.txt`
     - `User-Guide.txt`
2. **Verify Local SHA-256 Checksums Before Uploading to Google Drive**:
   - Open PowerShell in the download directory and run:
     ```powershell
     Get-Content .\SHA256SUMS.txt
     Get-FileHash .\KIRON-PROHORI-Setup-x64.exe -Algorithm SHA256
     Get-FileHash .\KIRON-PROHORI-Browser-Extension-MV3.zip -Algorithm SHA256
     ```
   - Confirm that the local SHA-256 hashes match `SHA256SUMS.txt` byte-for-byte.
3. **Create a Versioned Folder in Google Drive**:
   - Create a structured folder hierarchy in your Google Drive:
     ```text
     KIRON-PROHORI-Backups/
     └── v1.0.0-DEV_BUILD_2026-11-22/
         ├── KIRON-PROHORI-Setup-x64.exe
         ├── KIRON-PROHORI-Browser-Extension-MV3.zip
         ├── SHA256SUMS.txt
         ├── Release-Notes.txt
         └── User-Guide.txt
     ```
4. **Access Control & Sharing Hygiene**:
   - Keep **Editor** permissions restricted strictly to your own Google account (`ARIFUZZAMAN KIRON` with 2-Step Verification enabled).
   - If sharing a read-only backup folder link with beta testers, always instruct users to verify the downloaded installer against the official `SHA256SUMS.txt` hosted on GitHub Releases before running `KIRON-PROHORI-Setup-x64.exe`.
   - Never store private code-signing keys (`.pfx` / `.p12`), passwords, or GitHub Personal Access Tokens in Google Drive or inside the GitHub repository.

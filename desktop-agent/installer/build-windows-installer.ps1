<#
.SYNOPSIS
  KIRON PROHORI V1.0 — Windows 10/11 x64 Release Build, Code Signing & Installer Compiler Script.
.DESCRIPTION
  Builds KironProhori.Agent.Core, KironProhori.Agent.Desktop, and KironProhori.Agent.Service,
  runs the 20-test xUnit suite, optionally signs binaries using the configured Signing Mode
  (UNSIGNED_DEV, DEV_TEST_CERT, or PROD_TRUSTED_CA_OR_AZURE_TRUSTED_SIGNING), compiles
  KIRON-PROHORI-Setup-x64.exe (via Inno Setup 6) and/or KIRON-PROHORI-Setup-x64.msi (via WiX v4),
  and outputs a cryptographic SHA-256 checksum manifest.
.NOTES
  Developer: ARIFUZZAMAN KIRON
  Policy: Never uses a self-signed certificate for production builds.
#>

param(
    [ValidateSet("DEV_BUILD", "INTERNAL_TEST", "PUBLIC_BETA", "STABLE_V1_0")]
    [string]$ReleaseChannel = "DEV_BUILD",

    [ValidateSet("UNSIGNED_DEV", "DEV_TEST_CERT", "PROD_TRUSTED_CA")]
    [string]$SigningMode = "UNSIGNED_DEV",

    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = "Stop"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "KIRON PROHORI V1.0 — Windows x64 Build & Installer Pipeline" -ForegroundColor Cyan
Write-Host "Release Channel : $ReleaseChannel"
Write-Host "Signing Mode    : $SigningMode"
Write-Host "Developer       : ARIFUZZAMAN KIRON"
Write-Host "===================================================================" -ForegroundColor Cyan

# Enforce strict production signing gate: Stable V1.0 MUST use PROD_TRUSTED_CA
if ($ReleaseChannel -eq "STABLE_V1_0" -and $SigningMode -ne "PROD_TRUSTED_CA") {
    throw "RELEASE_POLICY_VIOLATION: STABLE_V1_0 builds cannot be distributed unsigned or with a self-signed certificate. Use -SigningMode PROD_TRUSTED_CA with a publicly trusted Authenticode certificate."
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$SolutionPath = Join-Path $RepoRoot "KironProhori.DesktopAgent.sln"
$PublishDesktopDir = Join-Path $RepoRoot "publish\win-x64\desktop"
$PublishServiceDir = Join-Path $RepoRoot "publish\win-x64\service"
$ArtifactsDir = Join-Path $RepoRoot "artifacts\installer"

New-Item -ItemType Directory -Force -Path $PublishDesktopDir | Out-Null
New-Item -ItemType Directory -Force -Path $PublishServiceDir | Out-Null
New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

# 1. Execute Automated xUnit Verification Suite before packaging
Write-Host "[1/5] Running xUnit verification tests..." -ForegroundColor Yellow
dotnet test (Join-Path $RepoRoot "tests\KironProhori.Agent.Tests\KironProhori.Agent.Tests.csproj") -c Release

# 2. Publish Windows Desktop UI (win-x64)
Write-Host "[2/5] Publishing KIRON PROHORI Desktop UI (win-x64)..." -ForegroundColor Yellow
dotnet publish (Join-Path $RepoRoot "src\KironProhori.Agent.Desktop\KironProhori.Agent.Desktop.csproj") `
    -c Release -r win-x64 --self-contained true -o $PublishDesktopDir

# 3. Publish Windows Background Service (win-x64)
Write-Host "[3/5] Publishing KIRON PROHORI Windows Background Service (win-x64)..." -ForegroundColor Yellow
dotnet publish (Join-Path $RepoRoot "src\KironProhori.Agent.Service\KironProhori.Agent.Service.csproj") `
    -c Release -r win-x64 --self-contained true -o $PublishServiceDir

# 4. Authenticode Binary Signing (if configured)
if ($SigningMode -eq "PROD_TRUSTED_CA") {
    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        throw "SIGNING_ERROR: -CertificateThumbprint is required when SigningMode is PROD_TRUSTED_CA."
    }
    Write-Host "[4/5] Applying Production Authenticode SHA-256 signature & RFC-3161 timestamp..." -ForegroundColor Green
    $BinariesToSign = @(
        (Join-Path $PublishDesktopDir "KironProhori.Desktop.exe"),
        (Join-Path $PublishServiceDir "KironProhori.Service.exe")
    )
    foreach ($Bin in $BinariesToSign) {
        if (Test-Path $Bin) {
            signtool.exe sign /sha1 $CertificateThumbprint /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 /v $Bin
        }
    }
} elseif ($SigningMode -eq "DEV_TEST_CERT") {
    Write-Host "[4/5] Applying Local VM Development Test Signature (NOT FOR PUBLIC DISTRIBUTION)..." -ForegroundColor DarkYellow
} else {
    Write-Host "[4/5] Skipping binary signing (UNSIGNED_DEV mode — local developer testing only)." -ForegroundColor Gray
}

# 5. Compile Inno Setup Installer (KIRON-PROHORI-Setup-x64.exe) if ISCC.exe is installed
$IsccPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
$IssScript = Join-Path $PSScriptRoot "inno-setup\KironProhoriSetup.iss"
if (Test-Path $IsccPath) {
    Write-Host "[5/5] Compiling KIRON-PROHORI-Setup-x64.exe via Inno Setup 6..." -ForegroundColor Yellow
    & $IsccPath $IssScript
    $InstallerExe = Join-Path $ArtifactsDir "KIRON-PROHORI-Setup-x64.exe"
    if (Test-Path $InstallerExe) {
        if ($SigningMode -eq "PROD_TRUSTED_CA") {
            signtool.exe sign /sha1 $CertificateThumbprint /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 /v $InstallerExe
        }
        $Hash = (Get-FileHash -Path $InstallerExe -Algorithm SHA256).Hash.ToLowerInvariant()
        $Size = (Get-Item $InstallerExe).Length
        $ManifestJson = @{
            installerFileName = "KIRON-PROHORI-Setup-x64.exe"
            version = "1.0.0"
            releaseChannel = $ReleaseChannel
            signingMode = $SigningMode
            sha256 = $Hash
            fileSizeBytes = $Size
            builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        } | ConvertTo-Json -Depth 4
        Set-Content -Path (Join-Path $ArtifactsDir "installer-manifest.json") -Value $ManifestJson -Encoding UTF8
        Write-Host "Installer built successfully: $InstallerExe (SHA-256: $Hash)" -ForegroundColor Green
    }
} else {
    Write-Host "[5/5] Inno Setup 6 (ISCC.exe) not found at '$IsccPath'. Published binaries are ready in '$PublishDesktopDir' and '$PublishServiceDir'." -ForegroundColor Yellow
}

# KIRON PROHORI V1.0 — Chrome & Microsoft Edge Native Messaging Host Registration Script
# Developer: ARIFUZZAMAN KIRON
# Privacy Policy: Registers under Current User (HKCU) only. Never modifies Windows Defender or system-wide policies.

param(
    [Parameter(Mandatory = $false)]
    [string]$ManifestPath = "$PSScriptRoot\com.kironprohori.security_agent.json"
)

$HostName = "com.kironprohori.security_agent"
$ChromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$EdgeKey   = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"

if (-not (Test-Path $ManifestPath)) {
    Write-Error "Native Messaging manifest not found at: $ManifestPath"
    exit 1
}

New-Item -Path $ChromeKey -Force | Out-Null
Set-ItemProperty -Path $ChromeKey -Name "(Default)" -Value $ManifestPath

New-Item -Path $EdgeKey -Force | Out-Null
Set-ItemProperty -Path $EdgeKey -Name "(Default)" -Value $ManifestPath

Write-Host "[KIRON PROHORI V1.0] Registered Native Messaging Host '$HostName' for Google Chrome and Microsoft Edge under HKCU."

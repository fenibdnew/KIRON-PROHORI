; =============================================================================
; KIRON PROHORI V1.0 — Inno Setup Production Windows x64 Installer Script
; Output Binary: KIRON-PROHORI-Setup-x64.exe
; Developer & Publisher: ARIFUZZAMAN KIRON
; Target OS: Windows 10 x64 (Build 19041+) / Windows 11 x64
; =============================================================================
; Security & Coexistence Guarantees:
; 1. Enforces 64-bit Windows 10/11 architecture and Administrator UAC elevation.
; 2. Installs KIRON PROHORI Desktop UI, Background Service (KironProhoriSecurityService),
;    and Chrome/Edge Manifest V3 Browser Protection Extension assets.
; 3. Never silently modifies browser settings — launches user-consented extension
;    setup instructions after installation if opted in.
; 4. Safe Uninstall: stops and removes KironProhoriSecurityService, deletes only
;    application-owned binaries under {app}, asks explicit user consent before
;    removing or preserving %LOCALAPPDATA%\KironProhori quarantine/settings data,
;    and NEVER deletes unrelated user files.
; =============================================================================

#define MyAppName "KIRON PROHORI"
#define MyAppSubtitle "Windows Security & Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ARIFUZZAMAN KIRON"
#define MyAppURL "https://kironprohori.security"
#define MyAppExeName "KironProhori.Desktop.exe"
#define MyServiceExeName "KironProhori.Service.exe"
#define MyServiceName "KironProhoriSecurityService"

[Setup]
AppId={{2944D822-43DC-46F2-875E-2B24F2FFA62E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppSubtitle} V{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/downloads
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir=..\..\artifacts\installer
OutputBaseFilename=KIRON-PROHORI-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\KironProhori.ico
UninstallDisplayName={#MyAppName} {#MyAppSubtitle} V{#MyAppVersion}
UninstallDisplayIcon={app}\KironProhori.ico
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Windows Security & Antivirus Setup (x64)
VersionInfoCopyright=Copyright (C) 2026 {#MyAppPublisher}. All rights reserved.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startupagent"; Description: "Launch KIRON PROHORI Security Tray Companion at Windows sign-in (Recommended)"; GroupDescription: "Real-Time Protection & Startup:"
Name: "installservice"; Description: "Install and start KIRON PROHORI Windows Background Service (User-Mode File & Schedule Guard)"; GroupDescription: "Real-Time Protection & Startup:"
Name: "browserguide"; Description: "Stage Chrome & Microsoft Edge Browser Protection Extension and open user-consented setup guide"; GroupDescription: "Browser Web & Download Protection:"

[Files]
; Core Desktop Application & Background Service Binaries (Published from dotnet publish -c Release -r win-x64)
Source: "..\..\publish\win-x64\desktop\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\assets\KironProhori.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\publish\win-x64\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
; Browser Extension Manifest V3 Package & Native Messaging Host Template
Source: "..\..\..\browser-extension\*"; DestDir: "{app}\browser-extension"; Flags: ignoreversion recursesubdirs createallsubdirs
; Documentation, Privacy Policy & License
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\KironProhori.ico"; Comment: "KIRON PROHORI Windows Security & Antivirus"
Name: "{group}\Browser Protection Setup Guide"; Filename: "{app}\docs\11_V1_0_COMPLETE_ARCHITECTURE_AND_BROWSER_EXTENSION.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; IconFilename: "{app}\KironProhori.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\KironProhori.ico"; Tasks: desktopicon

[Registry]
; Optional Startup Launch (Only when user selects 'startupagent' task)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "KironProhoriSecurityTray"; ValueData: """{app}\{#MyAppExeName}"" --minimized-tray"; Flags: uninsdeletevalue; Tasks: startupagent

; Application Installation Metadata Registry Key (Application-owned only)
Root: HKLM; Subkey: "Software\KironProhori\SecurityAgent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\KironProhori\SecurityAgent"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\KironProhori\SecurityAgent"; ValueType: string; ValueName: "Developer"; ValueData: "{#MyAppPublisher}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\KironProhori\SecurityAgent"; ValueType: string; ValueName: "TelemetryDefault"; ValueData: "DISABLED"; Flags: uninsdeletekey

; Windows Explorer Right-Click Context Menu ("Scan with KIRON PROHORI") — Drives (This PC), Folders, and Files (HKCR + HKCU fallback, auto-removed on uninstall)
Root: HKCR; Subkey: "Drive\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Drive\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "Drive\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "Directory\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "*\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

Root: HKCU; Subkey: "Software\Classes\Drive\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Drive\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Drive\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

Root: HKCU; Subkey: "Software\Classes\Directory\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

Root: HKCU; Subkey: "Software\Classes\*\shell\KironProhoriScan"; ValueType: string; ValueName: ""; ValueData: "Scan with KIRON PROHORI"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\KironProhoriScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\KironProhori.ico"""; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\KironProhoriScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-path ""%1"""; Flags: uninsdeletekey

[Run]
; Install and configure Windows Background Service with delayed-auto start and crash recovery
Filename: "sc.exe"; Parameters: "create {#MyServiceName} binPath= ""\""{app}\service\{#MyServiceExeName}\"""" start= delayed-auto DisplayName= ""KIRON PROHORI Windows Security Service"""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "description {#MyServiceName} ""KIRON PROHORI user-mode real-time file monitoring, scheduled scanning, and cryptographic update verification service. Coexists safely with Microsoft Defender."""; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000"; Flags: runhidden waituntilterminated; Tasks: installservice
Filename: "sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden waituntilterminated; Tasks: installservice

; Launch KIRON PROHORI Desktop UI after installation
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Safely stop and delete Windows Background Service before removing application binaries
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopKironService"
Filename: "sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteKironService"

[Code]
// Explicit User-Consented Data Preservation / Removal Prompt During Uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  UserDataDir: String;
  RemoveUserDataChoice: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    UserDataDir := ExpandConstant('{localappdata}\KironProhori');
    if DirExists(UserDataDir) then
    begin
      RemoveUserDataChoice := MsgBox(
        'Do you want to preserve your KIRON PROHORI Quarantine Vault, Exclusions, and local Security Settings located in:' + #13#10 +
        UserDataDir + '?' + #13#10 + #13#10 +
        'Click YES to KEEP your quarantine vault and settings (Recommended for upgrades/reinstalls).' + #13#10 +
        'Click NO to permanently delete KIRON PROHORI local application data.',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON1);

      if RemoveUserDataChoice = IDNO then
      begin
        DelTree(UserDataDir, True, True, True);
      end;
    end;
  end;
end;

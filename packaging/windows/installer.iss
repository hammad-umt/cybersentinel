; Inno Setup — Flutter + engine + Npcap (silent). Requires Administrator.

#define MyAppName "CyberSentinel"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CyberSentinel"
#define MyAppExeName "cybersentinel.exe"

#ifndef FLUTTER_BUILD
  #define FLUTTER_BUILD "C:\Users\hamma\OneDrive\Desktop\New folder\build\windows\x64\runner\Release"
#endif

#ifndef ENGINE_BUILD
  #define ENGINE_BUILD "dist\CyberSentinelEngine"
#endif

#ifndef NPCAP_INSTALLER
  #define NPCAP_INSTALLER "deps\npcap-installer.exe"
#endif

#ifndef APP_ICON
  #define APP_ICON "C:\Users\hamma\OneDrive\Desktop\New folder\windows\runner\resources\app_icon.ico"
#endif

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=CyberSentinel-Setup
SetupIconFile={#APP_ICON}
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#FLUTTER_BUILD}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ENGINE_BUILD}\*"; DestDir: "{app}\engine"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#NPCAP_INSTALLER}"; DestDir: "{app}\deps"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#FLUTTER_BUILD}\deps\npcap-installer.exe"; DestDir: "{app}\deps"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Open cybersentinel://reset-password?token=... from email in the desktop app
Root: HKCR; Subkey: "cybersentinel"; ValueType: string; ValueName: ""; ValueData: "URL:CyberSentinel"; Flags: uninsdeletekey
Root: HKCR; Subkey: "cybersentinel"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletekey
Root: HKCR; Subkey: "cybersentinel\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"
Root: HKCR; Subkey: "cybersentinel\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{app}\deps\npcap-installer.exe"; Parameters: "/S /loopback_support=yes /admin_only=yes /winpcap_mode=no"; StatusMsg: "Installing Npcap packet capture driver..."; Flags: runhidden waituntilterminated; Check: ShouldInstallNpcap
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
function IsNpcapInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\wpcap.dll')) or
            RegKeyExists(HKLM, 'SOFTWARE\Npcap');
end;

function NpcapInstallerPresent(): Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\deps\npcap-installer.exe'));
end;

function ShouldInstallNpcap(): Boolean;
begin
  Result := (not IsNpcapInstalled()) and NpcapInstallerPresent();
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not FileExists(ExpandConstant('{#FLUTTER_BUILD}\{#MyAppExeName}')) then
  begin
    MsgBox('Flutter build not found. Run: flutter build windows --release', mbError, MB_OK);
    Result := False;
  end;
  if not FileExists(ExpandConstant('{#ENGINE_BUILD}\cybersentinel_engine.exe')) then
  begin
    MsgBox('Engine not found. Run: packaging\windows\build_engine.ps1', mbError, MB_OK);
    Result := False;
  end;
  if not FileExists(ExpandConstant('{#NPCAP_INSTALLER}')) and
     not FileExists(ExpandConstant('{#FLUTTER_BUILD}\deps\npcap-installer.exe')) then
  begin
    MsgBox('Npcap installer missing. Run: packaging\windows\download_npcap.ps1', mbError, MB_OK);
    Result := False;
  end;
end;

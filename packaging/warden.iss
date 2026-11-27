; Inno Setup recipe for WardenSetup.exe.  Build with:  packaging\build.ps1
;
; - Installs for the current Windows user only (no admin rights needed) into
;   %LOCALAPPDATA%\Programs\Warden.
; - Settings, log and private files live in %LOCALAPPDATA%\Warden (created by Warden itself).
; - Uninstalling first gives every AI app its tools back (Unprotect), so removing Warden
;   never leaves an app pointing at a program that is gone.

#define AppVersion "0.8.0"

[Setup]
; Never change AppId: Windows uses it to recognise updates of the same program.
AppId={{F9D1E35F-2A59-47F2-B53A-6C83E30A060F}
AppName=Warden
AppVersion={#AppVersion}
AppVerName=Warden {#AppVersion}
AppPublisher=kagefire67
AppPublisherURL=https://github.com/kagefire67/warden
AppSupportURL=https://github.com/kagefire67/warden/issues
AppComments=Security guard for AI agents
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\Warden
DisableProgramGroupPage=yes
DisableDirPage=yes
OutputDir=..\build\installer
OutputBaseFilename=WardenSetup-{#AppVersion}
SetupIconFile=warden.ico
UninstallDisplayIcon={app}\Warden.exe
UninstallDisplayName=Warden
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Close Warden (and gateways started by AI apps) before updating or removing its files.
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\build\dist\Warden\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\Warden"; Filename: "{app}\Warden.exe"; Comment: "Security guard for AI agents"
Name: "{userdesktop}\Warden"; Filename: "{app}\Warden.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Warden.exe"; Description: "Open Warden now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Give every AI app protected by THIS copy its tools back before the files are removed.
Filename: "{app}\warden-gateway.exe"; Parameters: "unprotect-all"; Flags: runhidden waituntilterminated; RunOnceId: "UnprotectAll"

[Code]
// After uninstalling, ask whether to also delete Warden's settings, history and backups.
// Default: keep them (the backups can restore an AI app's original config).
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\Warden');
    if DirExists(DataDir) and (not UninstallSilent) then
      if MsgBox('Also delete Warden''s settings, history and config backups?' + #13#10 + #13#10 +
                'Your AI apps already have their tools back. Choose No to keep the backups.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;

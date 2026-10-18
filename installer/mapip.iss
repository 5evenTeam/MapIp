#define AppName "MapIp"
#define AppVersion "0.5.0"
#define AppPublisher "5evenTeam"
#define AppId "{{3E7B41C9-5A2D-4F18-9B6E-7C4D21A85F30}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/5evenTeam/MapIp
AppSupportURL=https://github.com/5evenTeam/MapIp
AppUpdatesURL=https://github.com/5evenTeam/MapIp
DefaultDirName={autopf}\MapIp
DefaultGroupName=MapIp
DisableProgramGroupPage=yes
DisableDirPage=auto
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=MapIp-Setup-0.5.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\mapip.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "path"; Description: "Add MapIp to the system PATH so ""mapip"" works in any terminal"; GroupDescription: "Integration:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce

[Files]
Source: "..\dist\mapip.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: ..\LICENSE; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\MapIp\MapIp"; Filename: "{app}\mapip.exe"; WorkingDir: "{%USERPROFILE}"; Comment: "MapIp network host mapper (terminal UI)"
Name: "{autodesktop}\MapIp"; Filename: "{app}\mapip.exe"; WorkingDir: "{%USERPROFILE}"; Comment: "MapIp terminal UI"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}')) and WizardIsTaskSelected('path'); Flags: preservestringtype

[Run]
Filename: "{app}\mapip.exe"; Description: "Launch MapIp"; Flags: postinstall nowait skipifsilent

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function TrimTrailingSlash(Value: string): string;
begin
  Result := Value;
  while (Length(Result) > 0) and (Result[Length(Result)] = '\') do
    Delete(Result, Length(Result), 1);
end;

function PathContains(const Paths: string; const Directory: string): Boolean;
var
  Rest, Entry: string;
  Cut: Integer;
begin
  Result := False;
  Rest := Paths;
  while Rest <> '' do
  begin
    Cut := Pos(';', Rest);
    if Cut = 0 then
    begin
      Entry := Rest;
      Rest := '';
    end
    else
    begin
      Entry := Copy(Rest, 1, Cut - 1);
      Delete(Rest, 1, Cut);
    end;
    if (Entry <> '') and (CompareText(TrimTrailingSlash(Entry), TrimTrailingSlash(Directory)) = 0) then
    begin
      Result := True;
      exit;
    end;
  end;
end;

function NeedsAddPath(const Directory: string): Boolean;
var
  Current: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := not PathContains(Current, Directory);
end;

function RemoveFromPath(const Directory: string): Boolean;
var
  Current, Rest, Entry, Kept: string;
  Cut: Integer;
begin
  Result := False;
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Current) then
    exit;
  Rest := Current;
  Kept := '';
  while Rest <> '' do
  begin
    Cut := Pos(';', Rest);
    if Cut = 0 then
    begin
      Entry := Rest;
      Rest := '';
    end
    else
    begin
      Entry := Copy(Rest, 1, Cut - 1);
      Delete(Rest, 1, Cut);
    end;
    if Entry = '' then
      continue;
    if CompareText(TrimTrailingSlash(Entry), TrimTrailingSlash(Directory)) = 0 then
    begin
      Result := True;
      continue;
    end;
    if Kept <> '' then
      Kept := Kept + ';';
    Kept := Kept + Entry;
  end;
  if Result then
    RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', Kept);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;

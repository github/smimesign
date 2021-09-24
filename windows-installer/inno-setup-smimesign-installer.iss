#define MyAppName "smimesign"

#define MyGitVersion GetEnv("GIT_VERSION")
#define MyBareGitVersion GetEnv("BARE_GIT_VERSION")

#define PathToX86Binary "../build/386/smimesign.exe"
#ifnexist PathToX86Binary
  #pragma error PathToX86Binary + " does not exist, please build it first."
#endif

#define PathToX64Binary "../build/amd64/smimesign.exe"
#ifnexist PathToX64Binary
  #pragma error PathToX64Binary + " does not exist, please build it first."
#endif

#define MyAppPublisher "GitHub, Inc."
#define MyAppURL "https://github.com/github/smimesign"
#define MyAppFilePrefix "smimesign-windows"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppCopyright=GitHub, Inc.
AppId={{4F942266-232E-4F47-8D44-A6BEE366A2A0}
AppName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppVerName={#MyBareGitVersion}
ArchitecturesInstallIn64BitMode=x64
ChangesEnvironment=yes
Compression=lzma
DefaultDirName={code:GetDefaultDirName}
DirExistsWarning=no
DisableReadyPage=True
LicenseFile=..\LICENSE.md
OutputBaseFilename={#MyAppFilePrefix}-{#MyGitVersion}
OutputDir=..\build\installer\
PrivilegesRequired=none
SolidCompression=yes
UsePreviousAppDir=no
VersionInfoVersion={#MyBareGitVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: {#PathToX86Binary}; DestDir: "{app}"; Flags: ignoreversion; DestName: "smimesign.exe"; Check: not Is64BitInstallMode
Source: {#PathToX64Binary}; DestDir: "{app}"; Flags: ignoreversion; DestName: "smimesign.exe"; Check: Is64BitInstallMode

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: IsAdminLoggedOn and NeedsAddPath('{app}')
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: (not IsAdminLoggedOn) and NeedsAddPath('{app}')

[Code]
function GetDefaultDirName(Dummy: string): string;
begin
  if IsAdminInstallMode then begin
    Result:=ExpandConstant('{pf}\{#MyAppName}');
  end else begin
    Result:=ExpandConstant('{userpf}\{#MyAppName}');
  end;
end;

// Checks to see if we need to add the dir to the env PATH variable.
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  ParamExpanded: string;
begin
  //expand the setup constants like {app} from Param
  ParamExpanded := ExpandConstant(Param);
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // look for the path with leading and trailing semicolon and with or without \ ending
  // Pos() returns 0 if not found
  Result := Pos(';' + UpperCase(ParamExpanded) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
  if Result = True then
    Result := Pos(';' + UpperCase(ParamExpanded) + '\;', ';' + UpperCase(OrigPath) + ';') = 0;
end;

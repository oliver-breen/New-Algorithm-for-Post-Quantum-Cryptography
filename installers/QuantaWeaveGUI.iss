#define MyAppName "QuantaWeave GUI"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Oliver Breen"
#define MyAppExeName "QuantaWeaveGUI.exe"
#define MyAppExeSource "dist\\QuantaWeaveGUI.exe"

[Setup]
AppId={{E1F80836-3B7D-414A-AB7B-9F4F7EA989E1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=QuantaWeaveGUI-Setup

OutputDir=..\dist

Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\quantaweave.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: {#MyAppExeSource}; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

; ============================================================================
;  polyshield.iss - PolyShield setup program
; ============================================================================
;
;   build.bat -Target installer        (compiles this with ISCC.exe)
;
;  TRACKED ON PURPOSE, for the same reason build.ps1 is: a release artifact
;  that cannot be reproduced from the repository is not reproducible.
;
;  Expects a completed dist\ -- build with:
;      build.bat -BuildRuntime -Onefile -Target all
;
;  What this installs, and what it deliberately does not:
;
;    Program files    {autopf}\PolyShield  (PolyShield.exe, runtime\, service\)
;    Shared data      %ProgramData%\PolyShield, created with explicit per-subtree
;                     ACLs BEFORE the app first runs -- see setup_data_root.ps1
;    Service          PolyShieldService, from the staged runtime
;    Explorer verb    written by the app itself, per-user in HKCU
;
;    NOT System32     no pywin32_postinstall; the staged runtime carries its own
;                     pywin32_system32\ (build.ps1 asserts this), so uninstall
;                     never has to reason about a shared system DLL
;
;  The service is a REQUIRED component, not an option: intelligence updates and
;  the ignore list are service-owned in a distribution, so a service-less
;  install would have no way to update its threat data.
; ============================================================================

#define AppName        "PolyShield"
#define AppVersion     "1.16.0"
#define AppPublisher   "Alexander L Corthell"
#define AppExeName     "PolyShield.exe"
#define DistDir        "..\dist"
#define ServiceName    "PolyShieldService"

[Setup]
AppId={{7C5F1E2A-9B3D-4A6E-B1C8-2F4D6A8E0B31}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\dist
OutputBaseFilename=PolyShield-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Registering a service and writing under %ProgramData% both need it, and the
; ACLs are the whole point of installing rather than unzipping.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
LicenseFile=..\LICENSE
; The app must not be running while its files are replaced -- but Restart
; Manager is NOT how we achieve that, and turning it on cost two verification
; runs. It applies to uninstall as well as install, and a /VERYSILENT uninstall
; sat idle at 0% CPU indefinitely waiting on it, producing no report at all.
;
; [UninstallRun] already stops and removes the service before any file is
; touched (ui/core/integration.py), which is the specific thing RM would have
; been asked to discover.
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "contextmenu"; Description: "Add ""Scan with PolyShield"" to the Explorer right-click menu"; GroupDescription: "Integration:"

[Files]
Source: "{#DistDir}\{#AppExeName}";  DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\runtime\*";      DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#DistDir}\service\*";      DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
; Named explicitly as well as by the wildcard above. Without this marker the
; service resolves its data root to its own install directory while the GUI
; resolves %ProgramData%\PolyShield -- and a service writing detections where
; the UI never looks is indistinguishable from one that found nothing.
Source: "{#DistDir}\service\.polyshield-distribution"; DestDir: "{app}\service"; Flags: ignoreversion
Source: "setup_data_root.ps1";       DestDir: "{app}\installer"; Flags: ignoreversion
Source: "register_service.ps1";      DestDir: "{app}\installer"; Flags: ignoreversion
Source: "seed_k2_rules.ps1";        DestDir: "{app}\installer"; Flags: ignoreversion
Source: "..\LICENSE";                DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICES.md";             DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";           Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";     Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Order matters. The data root is created FIRST, with its ACLs, because a
; directory the app creates for itself inherits the root ACL and the privilege
; boundary would then exist only in the documentation.
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\installer\setup_data_root.ps1"""; \
  StatusMsg: "Creating the shared data directory..."; \
  Flags: runhidden waituntilterminated

Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\installer\register_service.ps1"" -InstallDir ""{app}"""; \
  StatusMsg: "Registering the PolyShield service..."; \
  Flags: runhidden waituntilterminated

; k2 carries only 23 of its 1263 signatures in its plugin modules; the rest
; arrive in rule archives it downloads. A fresh install has an empty rules
; directory, so without this the primary signature engine ships at under 2% of
; the detection it has in a checkout. Non-fatal: no network at install time is
; ordinary, and the Update Center can run it later.
Filename: "powershell.exe";   Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\installer\seed_k2_rules.ps1"" -InstallDir ""{app}""";   StatusMsg: "Downloading K2 signature archives...";   Flags: runhidden waituntilterminated

; The Explorer verb is per-user (HKCU) and the app writes it itself, so it is
; registered by running the app rather than by writing keys from here -- one
; implementation of the command string, in paths.app_launch_argv().
; NOT skipifsilent. That flag means "skip during a silent install", and a
; /VERYSILENT deployment is exactly the case where nobody is watching to
; notice the menu never appeared. Measured: the sandbox installs silently
; and the verb was absent every time.
Filename: "{app}\{#AppExeName}"; Parameters: "--register-context-menu"; \
  StatusMsg: "Adding the Explorer menu entry..."; \
  Flags: runhidden waituntilterminated; Tasks: contextmenu

Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; \
  Flags: postinstall nowait skipifsilent

[UninstallRun]
; One call. integration.unregister_all() removes the service, the Explorer verb
; and the scheduled task, and treats "it was not there" as success -- because an
; uninstall may follow a partial or failed install. See ui/core/integration.py.
Filename: "{app}\{#AppExeName}"; Parameters: "--unregister"; \
  RunOnceId: "PolyShieldUnregister"; Flags: runhidden waituntilterminated

[Code]
var
  RemoveDataCheckBox: TNewCheckBox;
  InstallCompleted: Boolean;

// ---------------------------------------------------------------------------
// Rollback. A failed install must not leave a registered service and a
// half-written install directory behind: docs/ARCHITECTURE.md records that
// repeated attempts otherwise accumulate dirty service and context-menu state,
// and that the retry path is where this belongs.
// ---------------------------------------------------------------------------
procedure RollBackIntegrations;
var
  ResultCode: Integer;
  Exe: String;
begin
  Exe := ExpandConstant('{app}\{#AppExeName}');
  if FileExists(Exe) then
    Exec(Exe, '--unregister', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    // Stop the service BEFORE any file is replaced. With CloseApplications off
    // (see [Setup]) nothing else will, and a running service holds
    // the staged runtime open -- an upgrade over an existing install
    // then fails with exit 5 while the files it could not write look fine.
    // Measured: a reinstall failed exactly that way once RM was disabled.
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(3000);
  end;
  if CurStep = ssDone then
    InstallCompleted := True;
end;

procedure DeinitializeSetup;
begin
  // Runs on every exit -- success, cancellation, or failure. Inno rolls back
  // the files it copied; the service registration and the Explorer verb are
  // ours to undo, and they are what a retry would otherwise inherit.
  //
  // unregister_all() treats absent as success, so this is safe to run after a
  // failure at any point, including before anything was registered.
  if not InstallCompleted then
    RollBackIntegrations;
end;

// ---------------------------------------------------------------------------
// Uninstall: program state always, user data only on request.
//
// The threat database, quarantine, logs and settings live under
// %ProgramData%\PolyShield and are KEPT by default. Quarantine in particular
// may hold the only copy of a file somebody wants back, and an uninstaller
// that deletes it silently is one nobody can undo.
// ---------------------------------------------------------------------------
procedure InitializeUninstallProgressForm;
begin
  RemoveDataCheckBox := TNewCheckBox.Create(UninstallProgressForm);
  RemoveDataCheckBox.Parent := UninstallProgressForm.InnerPage;
  RemoveDataCheckBox.Left := ScaleX(0);
  RemoveDataCheckBox.Top := UninstallProgressForm.StatusLabel.Top + ScaleY(40);
  RemoveDataCheckBox.Width := UninstallProgressForm.InnerPage.ClientWidth;
  RemoveDataCheckBox.Height := ScaleY(34);
  RemoveDataCheckBox.Caption :=
    'Also remove my quarantine, logs, threat database and settings' + #13#10 +
    '(leave this unticked to keep them for a reinstall)';
  RemoveDataCheckBox.Checked := False;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if (RemoveDataCheckBox <> nil) and RemoveDataCheckBox.Checked then
    begin
      DataDir := ExpandConstant('{commonappdata}\PolyShield');
      if DirExists(DataDir) then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;

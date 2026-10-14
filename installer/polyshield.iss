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
; Overridable (ISCC /DDistDir=...) so CI can build a deliberately broken payload
; and prove that Setup refuses it; see tools/ci/refusal_test.ps1.
#ifndef DistDir
#define DistDir        "..\dist"
#endif
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
#ifdef SignInstaller
; Only when build.ps1 passes /DSignInstaller together with /Spolyshield=<cmd>.
; Declaring SignTool without the matching /S is a compile error, so an unsigned
; build must not mention it at all. SignedUninstaller signs the uninstall.exe
; Inno writes at install time -- the file Windows runs elevated from
; Settings > Apps, and the one an unsigned build would leave behind.
SignTool=polyshield
SignedUninstaller=yes
#endif
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
; UNCHECKED, and it has to stay that way. PolyShield's rule is that the login
; entry is written only when somebody asked for it, and the Settings toggle
; being off by default is not enough on its own -- the installer is the one
; place where a checked-by-default box would put a Run value into the registry
; of every person who clicked Next. A silent install selects no tasks at all,
; so /VERYSILENT registers nothing here either.
; tests/test_integration_edges.py reads this line.
Name: "startupicon"; Description: "Start PolyShield when I sign in (minimised to the notification area)"; GroupDescription: "Integration:"; Flags: unchecked

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
; The two steps that MUST succeed are not [Run] lines. Creating the data root with
; its ACLs (setup_data_root.ps1) and registering the service (register_service.ps1)
; are run by RunRequiredSteps in [Code], which is attached to the FIRST entry
; below as its BeforeInstall -- i.e. after the files are copied and before every
; other entry here, in that order: the data root first, because a directory the app
; creates for itself inherits the root ACL and the boundary would otherwise exist
; only in the documentation.
;
; Why not as plain [Run] lines, and why not from CurStepChanged(ssPostInstall)?
; Inno ignores a [Run] entry's exit code, so a failure would still exit 0 with no
; service (measured in CI). And ssPostInstall fires AFTER every [Run] entry, so
; the required steps would run last (measured: ssInstall > [Run] entries >
; ssPostInstall > ssDone). Raising an exception from any of these places does NOT
; stop a silent Setup either: it is reported and ignored, exit 0 (measured, for
; RaiseException and Abort, from ssPostInstall and from BeforeInstall).
;
; This entry must stay unconditional (no Tasks/Check) and first, or the required
; steps would be skipped or reordered; tests/test_service_startup.py pins that.
Filename: "{sys}\cmd.exe"; Parameters: "/c exit 0"; \
  StatusMsg: "Setting up PolyShield..."; \
  Flags: runhidden waituntilterminated; BeforeInstall: RunRequiredSteps

; Everything below is deliberately best-effort.

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

; Same reasoning as the line above: one implementation of the command string,
; in paths.app_launch_argv(). This one runs only when the user ticked the task,
; which is what keeps "off by default" true for the packaged build as well as
; for the Settings switch.
Filename: "{app}\{#AppExeName}"; Parameters: "--register-autostart"; \
  StatusMsg: "Adding the startup entry..."; \
  Flags: runhidden waituntilterminated; Tasks: startupicon

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

// Used by FailSetup, and only there. See the note above RunRequiredSteps.
procedure ExitProcess(uExitCode: Cardinal); external 'ExitProcess@kernel32.dll stdcall';

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

// ---------------------------------------------------------------------------
// Steps that must succeed, or Setup refuses.
//
// An antivirus that is half installed is worse than one that is not installed:
// it looks protected and is not. Creating the data root with its ACLs and
// registering the service are what make the product work AND what make its
// privilege boundary real, so a failure of either fails the whole install.
//
// Inno gives a silent Setup NO supported way to stop after the files are in.
// Measured on a throwaway installer, for each of these: exit code 0, the files
// and uninstaller still on disk, later [Run] entries still executed --
//   RaiseException / Abort from CurStepChanged(ssPostInstall)
//   RaiseException / Abort from a [Run] entry's BeforeInstall
//   a [Run] entry whose program cannot be launched
// so none of them is used. What does work, and what FailSetup therefore does:
//   1. Undo the install with Inno's OWN uninstaller. It runs [UninstallRun]
//      (PolyShield.exe --unregister: service, verb, task), removes the files and
//      the uninstall registration, and keeps user data (silent default).
//   2. ExitProcess(4), Inno's "fatal error during the actual installation
//      process" exit code, so a deployment tool sees the failure.
//
// A failed UPGRADE therefore leaves nothing installed, not a mixture of old and
// new files: the uninstaller removes the product that was there, and Inno's
// transactional rollback is not reachable from here. That is deliberate. For a
// security product, "not installed, and said so" beats "partly updated".
//
// ExitProcess skips DeinitializeSetup, which is why the rollback is done here
// explicitly rather than left to RollBackIntegrations.
// ---------------------------------------------------------------------------
procedure FailSetup(const Msg: String);
var
  ResultCode, Waited: Integer;
  Uninstaller: String;
begin
  Log('SETUP REFUSED: ' + Msg + ' PolyShield was not installed.');
  SuppressibleMsgBox(Msg + #13#10#13#10 + 'PolyShield was not installed.',
                     mbCriticalError, MB_OK, IDOK);

  Uninstaller := ExpandConstant('{uninstallexe}');
  if FileExists(Uninstaller) then
  begin
    if Exec(Uninstaller, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE,
            ewWaitUntilTerminated, ResultCode) then
      Log('Rollback: uninstaller exited ' + IntToStr(ResultCode))
    else
      Log('Rollback: the uninstaller could not be started');
    // The uninstaller hands off to a temporary copy of itself and returns; the
    // real work finishes when it deletes itself, so wait for that, bounded.
    Waited := 0;
    while FileExists(Uninstaller) and (Waited < 180000) do
    begin
      Sleep(250);
      Waited := Waited + 250;
    end;
    Log('Rollback: uninstaller gone=' + IntToStr(Ord(not FileExists(Uninstaller))) +
        ' after ' + IntToStr(Waited) + ' ms');
  end
  else
    Log('Rollback: no uninstaller at ' + Uninstaller);

  ExitProcess(4);
end;

procedure RunRequiredStep(const What, ScriptName, ScriptArgs, Detail: String);
var
  ResultCode: Integer;
  Params: String;
begin
  Params := '-ExecutionPolicy Bypass -NoProfile -File "' +
            ExpandConstant('{app}\installer\') + ScriptName + '" ' + ScriptArgs;
  Log('Required step: ' + What + ' -> powershell.exe ' + Params);
  if not WizardSilent then
    WizardForm.StatusLabel.Caption := What + '...';

  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    FailSetup(What + ' failed: PowerShell could not be started (' +
              SysErrorMessage(ResultCode) + ').');

  Log('Required step exit code: ' + IntToStr(ResultCode));
  if ResultCode <> 0 then
    FailSetup(What + ' failed (exit code ' + IntToStr(ResultCode) + '). ' + Detail);
end;

// Attached to the first [Run] entry as BeforeInstall: runs after the files are
// copied and before every other entry, in this order (the data root first).
procedure RunRequiredSteps;
begin
  RunRequiredStep('Creating the shared data directory', 'setup_data_root.ps1', '',
                  'The data directory and its permissions could not be set up.');
  RunRequiredStep('Registering the PolyShield service', 'register_service.ps1',
                  '-InstallDir "' + ExpandConstant('{app}') + '"',
                  'Details: %ProgramData%\PolyShield\logs\install_register_service.log');
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

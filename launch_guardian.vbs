Dim base
base = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))

Dim pythonw : pythonw = base & "guardian_env\Scripts\pythonw.exe"
Dim script  : script  = base & "guardianai\guardian.py"

If Not CreateObject("Scripting.FileSystemObject").FileExists(pythonw) Then
    MsgBox "guardian_env not found." & vbCrLf & _
           "Please run setup_guardian.bat first.", vbCritical, "GuardianAI"
    WScript.Quit
End If

CreateObject("WScript.Shell").Run """" & pythonw & """ """ & script & """", 0, False

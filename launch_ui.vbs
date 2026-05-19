Dim base
base = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))

Dim pythonw : pythonw = base & "kicomav_env\Scripts\pythonw.exe"
Dim script  : script  = base & "src\ui\app.py"

CreateObject("WScript.Shell").Run """" & pythonw & """ """ & script & """", 0, False

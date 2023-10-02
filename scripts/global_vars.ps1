# START - GLOBAL VARIABLES - START
$global:CURRENT_VERSION = "v0.2.7-beta"
$global:scriptName = $MyInvocation.MyCommand.Name

# START - RESTART AND RESUME VARIABLES - START
$global:scriptFullPath = $myInvocation.MyCommand.Definition
$global:RegRunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:restartKey = "Restart-And-Resume"
$global:powershell = '"C:\Program Files\PowerShell\7\pwsh.exe"'
# END - RESTART AND RESUME VARIABLES - END
# END - GLOBAL VARIABLES - END
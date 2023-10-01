# START FEATURE - AUTO UPDATE - START FEATURE
function Get-ScriptUpdate {
    <#
	.SYNOPSIS
	Checks if there is any new update for the script and downloads it if user wants

	.EXAMPLE
	Get-ScriptUpdate
	#>
    $url = "https://raw.githubusercontent.com/Kiu1812/SystemTweaker/main/LATEST"
	
    $response = Invoke-RestMethod -Uri $url
    $LATEST_VERSION = $response.Split()[0]
	
    if ($LATEST_VERSION -ne $global:CURRENT_VERSION) {
        if (Confirm-Dialog "New version available ($LATEST_VERSION), will download it now. Current version: ($global:CURRENT_VERSION)" -NoExit) {
            $outputPath = "tmp_$global:scriptName"
            if (Test-Path $outputPath) {
                Remove-Item $outputPath
            }
            $URL = "https://github.com/Kiu1812/SystemTweaker/releases/download/$LATEST_VERSION/system_tweaker.ps1"
            Invoke-WebRequest -Uri $URL -OutFile $outputPath
            Start-Process -FilePath "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "$outputPath", "-Update $global:scriptName" -Verb RunAs
            exit
        }
    }
    else {
        Write-Host "No updates available"
    }
}
# END FEATURE - AUTO UPDATE - END FEATURE
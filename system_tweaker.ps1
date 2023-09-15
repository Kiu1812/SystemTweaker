param(
	# [Switch]$Restarted # HIDED PARAMETER
	[String]$NewComputerName
)

# START - DEFAULT VARIABLES - START

$global:CURRENT_VERSION = "v0.1.1-beta"
$global:scriptName = $MyInvocation.MyCommand.Name

# START - RESTART AND RESUME VARIABLES - START
$global:scriptFullPath = $myInvocation.MyCommand.Definition
$global:RegRunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:restartKey = "Restart-And-Resume"
$global:powershell = '"C:\Program Files\PowerShell\7\pwsh.exe"'
# END - RESTART AND RESUME VARIABLES - END

# END - DEFAULT VARIABLES - END

# START - RESTART AND RESUME SCRIPT FUNCTIONS - START
function Test-Key([string] $path, [string] $key) {
	return ((Test-Path $path) -and ($null -ne (Get-Key $path $key)))   
}
function Remove-Key([string] $path, [string] $key) {
	Remove-ItemProperty -path $path -name $key
}
function Set-Key([string] $path, [string] $key, [string] $value) {
	Set-ItemProperty -path $path -name $key -value $value
}
function Get-Key([string] $path, [string] $key) {
	return (Get-ItemProperty $path).$key
}
function Restart-And-Run([string] $key, [string] $run) {
	Set-Key $global:RegRunKey $key $run
	Restart-Computer
	exit
}
function Clear-Any-Restart([string] $key = $global:restartKey) {
	if (Test-Key $global:RegRunKey $key) {
		Remove-Key $global:RegRunKey $key
	}
}
function Restart-And-Resume([string] $parameters) {
	Restart-And-Run $global:restartKey "$global:powershell $global:scriptFullPath `"-Restarted $parameters`""
}
# END - RESTART AND RESUME SCRIPT FUNCTIONS - END



# START - UTIL FUNCTIONS - START
function Exit-PressKey {
	<#
	.SYNOPSIS
	Exits program when pressing "Enter" key
	
	.EXAMPLE
	Exit-PressKey
	#>
	
	Write-Host "Press `"Enter`" to exit..."
	Read-Host
	exit
}

function Wait-PressKey {
	<#
	.SYNOPSIS
	Stops program until pressing "Enter" key
	
	.EXAMPLE
	Wait-PressKey
	#>
	
	Write-Host "Press `"Enter`" to continue..."
	Read-Host
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); # PRESS ANY KEY TO CONTINUE
}

function Confirm-Dialog ([String]$Text, [Switch]$Warning, [Switch]$NoExit) {
	<#
	.SYNOPSIS
	Confirm dialog with custom message, defaults to abort
	
	.PARAMETER Text
	Message to display
	
	.PARAMETER Warning
	Display as a warning, changes the color and adds "Warning" at the beggining
	
	.EXAMPLE
	Confirm-Dialog "This action will restart the machine"
	Confirm-Dialog "This action will restart the machine" -Warning
	#>
	
	Write-Host ""
	if ($Warning) {
		Write-Host "Warning: $Text" -ForegroundColor Yellow
	}
	else {
		Write-Host $Text
	}
	
	$selection = Read-Host -Prompt "Continue (Y/N) [N]"
	Write-Host ""
	
	if ($selection.ToUpper() -eq "Y") {
		if ($NoExit) {
			return $true
		}
		return
	}
	elseif (-not($NoExit)) {
		exit
	}
}

function Test-Administrator {
	<#
	.SYNOPSIS
	Checks if script is running as an Administrator
	
	.EXAMPLE
	Test-Administrator
	#>
	$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object System.Security.Principal.WindowsPrincipal($user)
	$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Open-As-Admin {
	param (
		[String]$Arguments
	)
	
	if ($Arguments) {
		
		Start-Process -FilePath "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "$global:scriptFullPath", $Arguments -Verb RunAs
	}
	else {
		Start-Process -FilePath "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "$global:scriptFullPath" -Verb RunAs
	}
}

function Select-From-Options {
	<#
	.SYNOPSIS
	Shows a menu with all the options of the Parameter "Options"
	
	.PARAMETER Title
	Title to display before the options
	
	.PARAMETER Comments
	Additional comments to display between "Title" and "Options"
	
	.PARAMETER Options
	Options to display
	
	.EXAMPLE
	Select-From-Options -Options @("Option 1","Option 2")
	Select-From-Options -Title "User Menu" -Options @("Option 1","Option 2")
	Select-From-Options -Title "User Menu" -Comments "Additional Comments" -Options @("Option 1","Option 2")
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[String]$Title,
		
		[Parameter(Mandatory = $false)]
		[String[]]$Comments,
		
		[Parameter(Mandatory)]
		[String[]]$Options
	)
	
	Write-Host ""
	if ($Title) {
		Write-Host "[$Title]"
	}

	if ($Comments) {
		Write-Host ""
		foreach ($idx in 0..($Comments.Length - 1)) {
			$comment = $Comments[$idx]
			
			Write-Host "$comment"
		}
	}

	Write-Host ""
	foreach ($idx in 0..($Options.Length - 1)) {
		$option = $Options[$idx]
		
		Write-Host "($idx) $option"
	}
	Write-Host ""
	
	$selection = Read-Host -Prompt ":"
	
	if (-not [int]::TryParse($selection, [ref]$selection)) {
		Throw "Not a number"
	}
	if ($selection -lt 0 -or $selection -gt $Options.Length - 1) {
		Throw "Number not in range"
	}
	return $selection
}

function Test-Server {
	# Obtener información del sistema operativo
	$osInfo = Get-CimInstance -Class Win32_OperatingSystem

	# Verificar la edición del sistema operativo
	if ($osInfo.Caption -match "Windows Server") {
		return $true
		
	}
 else {
		
		return $false
	}
}
# END - UTIL FUNCTIONS - END



# START FEATURE FUNCTIONS

# START FEATURE - AUTO UPDATE - START FEATUR
function Get-ScriptUpdate {
	$url = "https://raw.githubusercontent.com/Kiu1812/SystemTweaker/main/LATEST"
	
	$response = Invoke-RestMethod -Uri $url
	$LATEST_VERSION = $response.Split()[0]
	#$URL = $response.Split()[1]
	
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
		Write-Host "Script is in latest version"
	}
}
# END FEATURE - AUTO UPDATE - END FEATURE

# START FEATURE - SET HOSTNAME - FEATURE START
function Set-Hostname ([String]$NewName) {
	<#
	.SYNOPSIS
	Set a new hostname or show the current hostname
	
	.PARAMETER NewName
	The new name to apply
	
	.EXAMPLE
	Set-Hostname "WIN-SERVER"
	#>
	
	Rename-Computer -NewName $NewName -Force -Passthru | Out-Null
	
	if ($?) {
		Write-Host "The computer will reboot with the new hostname $NewName"
		Wait-PressKey
		Restart-And-Resume "-NewComputerName $NewName"
	}
	else {
		Throw "Some error has occurred. Please try again"
	}
}
# END FEATURE - SET HOSTNAME - FEATURE END

# END FEATURE FUNCTIONS



function Open-UserMenu {
	<#
	.SYNOPSIS
	Shows the user menu with all its options
	
	.EXAMPLE
	Open-UserMenu
	#>
	

	$Options = @("Exit", "Set Hostname", "WIP Set IP", "WIP Create domain", "WIP Join domain", "WIP Create Users")
	$selection = Select-From-Options -Title "System Tweaker" -Options $Options
	switch ($selection) {
		0 {
			Exit-PressKey
		}
		1 {
			# Set Hostname
			Confirm-Dialog "This function will require a system restart" -Warning
			
			$current_hostname = hostname
			$selection = Select-From-Options -Title "Set Hostname" -Comments "Current hostname: $current_hostname" -Options @("Manually", "Random")
			switch ($selection) {
				0 {
					# Manually
					$NewComputerName = Read-Host -Prompt "Specify the new name"
					Set-Hostname $NewComputerName
				}
				1 {
					# Random
					if (Test-Server) {
						# Default
						$prefix = "WIN-SERVER"
					}
					else {
						$prefix = "WIN-DESKTOP"
					}
					$selection = Select-From-Options -Title "Set Random Hostname" -Options @("Default prefix [$prefix]", "Add custom prefix [`"-`" is added automatically]")
					if ($selection -eq 1) {
						# Custom
						$prefix = Read-Host "Custom prefix"
					}
					
					$randomHex = -join (Get-Random -InputObject (0x0..0xF) -Count 4 | ForEach-Object { '{0:X}' -f $_ })
					$NewComputerName = "$prefix-$randomHex"
					Confirm-Dialog "The hostname generated is $NewComputerName"
					Set-Hostname $NewComputerName
				}
			}
		}
	}
}


# START - MAIN - START
function Main {
	[CmdletBinding()]
	param( 
		[String[]]$ScriptArgs
	)
	clear

	if (($ScriptArgs -contains '-Update') -and (Test-Administrator)) {
		#Write-Host "El parámetro -Update se ha especificado."
		
		if ($global:scriptName.StartsWith("tmp_")) {
			#Start-Sleep -Seconds 1
			$original_name = $ScriptArgs[$ScriptArgs.IndexOf("-Update") + 1]
			$scriptBlock = {
				param($originalName, $scriptName)
				#Start-Sleep -Seconds 2
				Remove-Item -Path $originalName -Force
				Rename-Item -Path $scriptName -NewName $originalName -Force
				Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $originalName
			}
			Start-Process "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& { $scriptBlock }", "-originalName", $original_name, "-scriptName", $scriptName

			exit
		}
		Exit-PressKey
	}
	
	if (($ScriptArgs -contains '-Restarted') -and (Test-Administrator)) {
		#Write-Host "El parámetro -Restarted se ha especificado."
		$global:Restarted = $true
		Clear-Any-Restart
	}
	
	# START - CHECK ADMIN PERMISSIONS - START
	if (-not(Test-Administrator)) {
		if ($global:Restarted) {
			$Arguments = $ScriptArgs -join " "
			Open-As-Admin $Arguments
		}
		else {
			Write-Host "This script needs Administrator privileges"
			
			Confirm-Dialog -Text "Executing script as admin" -Warning
			$Arguments = $ScriptArgs -join " "
			Open-As-Admin $Arguments
		}
		exit
	}
	# END - CHECK ADMIN PERMISSIONS - END
	
	Get-ScriptUpdate
	
	# START FEATURE - SET HOSTNAME - FEATURE START
	if ($NewComputerName) {
		if ($global:Restarted) {
			Write-Host "The new computer name is" (hostname)
		}
		else {
			Set-Hostname $NewComputerName
		}
		Exit-PressKey
	}
	# END FEATURE - SET HOSTNAME - FEATURE END
	
	# START FEATURE - SET IP - FEATURE START
	
	# END FEATURE - SET IP - FEATURE END
	
	if (-not($global:Restarted)) {
		Open-UserMenu
	}
	

}
# END - MAIN - END

Main -ScriptArgs $args




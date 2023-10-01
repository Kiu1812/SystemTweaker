# START FEATURE - SET HOSTNAME - FEATURE START
function Set-Hostname-Dialog {
    <#
	.SYNOPSIS
	Show all the options to set a new hostname
	
	.EXAMPLE
	Set-Hostname-Dialog
	#>
    Confirm-Dialog "This function will require a system restart" -Warning
	
    $current_hostname = hostname
    $selection = Select-From-Options -Title "Set Hostname" -Comments "Current hostname: $current_hostname" -Options @("Manually", "Random")
    switch ($selection) {
        0 {
            # Manually
            $NewComputerName = Read-Host -Prompt "Specify the new name"
        }
        1 {
            # Random
            if (Test-ServerEdition) {
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
        }
    }

    Set-Hostname $NewComputerName
}
function Set-Hostname () {
    <#
	.SYNOPSIS
	Set a new hostname or show the current hostname
	
	.PARAMETER NewName
	The new name to apply
	
	.EXAMPLE
	Set-Hostname "WIN-SERVER"
	#>
    param (
        [Parameter(Mandatory)]
        [String]$NewName
    )

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

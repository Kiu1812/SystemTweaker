# START - MAIN - START
function Open-UserMenu {
    <#
	.SYNOPSIS
	Shows the user menu with all its options
	
	.EXAMPLE
	Open-UserMenu
	#>
	

    $Options = @("Exit", "Set Hostname", "Set IP")
    $selection = Select-From-Options -Title "System Tweaker" -Options $Options
    switch ($selection) {
        0 {
            Exit-PressKey
        }
        1 {
            Set-Hostname-Dialog
        }
        2 {
            Set-IP-Dialog
        }
    }
}

function Main {
    [CmdletBinding()]
    param( 
        [String]$ScriptArgs
    )
    #clear
    ParseArguments -ScriptArgs $ScriptArgs
    Get-ScriptUpdate

    if (-not($Restarted)) {    
        Open-UserMenu
    }
}
# END - MAIN - END

$arguments = @()
foreach ($key in $MyInvocation.BoundParameters.Keys) {
    $value = $MyInvocation.BoundParameters[$key]
    
    if ($value -eq $True) {
        # ONLY ADD VALUE IF IS NOT A SWITCH PARAMETER
        $arguments += "-$key"    
    }
    else {
        $arguments += "-$key $($MyInvocation.BoundParameters[$key])"
    }
}
$arguments = $arguments -join " "
Main -ScriptArgs $arguments
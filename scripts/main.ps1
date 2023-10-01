# START - MAIN - START
function Open-UserMenu {
    <#
	.SYNOPSIS
	Shows the user menu with all its options
	
	.EXAMPLE
	Open-UserMenu
	#>
	

    $Options = @("Exit", "Set Hostname", "Set IP", "WIP Create domain", "WIP Join domain", "WIP Create Users")
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
        [String[]]$ScriptArgs
    )
    clear
    ParseArguments -ScriptArgs $ScriptArgs
    Get-ScriptUpdate

    if (-not($global:Restarted)) {
        Open-UserMenu
    }
}
# END - MAIN - END

Main -ScriptArgs $args

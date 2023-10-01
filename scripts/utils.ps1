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
	Confirm dialog with custom message, defaults to abort and exit the script
	
	.PARAMETER Text
	Message to display
	
	.PARAMETER Warning
	Display as a warning, changes the color and adds "Warning" at the beggining
	
	.PARAMETER NoExit
	Continues without exiting the script

	.EXAMPLE
	Confirm-Dialog "This action will restart the machine"
	Confirm-Dialog "This action will restart the machine" -Warning
	Confirm-Dialog "Update needed" -Warning -NoExit
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
    <#
	.SYNOPSIS
	Opens script as admin passing console parameters to new launch
	
	.PARAMETER Arguments
	The parameters that the script recieved

	.EXAMPLE
	Open-As-Admin
	Open-As-Admin $ScriptArgs
	#>
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

	.PARAMETER CustomObject
	Enable this if "Options" parameter is a PSCustomObject. The PSCustomObject will need to have the Index itself
	
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
        $Options,

        [Switch]$CustomObject
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

    if (-not($CustomObject)) {
        Write-Host ""
        foreach ($idx in 0..($Options.Length - 1)) {
            $option = $Options[$idx]
			
            Write-Host "($idx) $option"
        }
        Write-Host ""
    }
    else {
        $Options | Format-Table -AutoSize | Out-Host
    }
	
    $selection = Read-Host -Prompt ":"
	
    if (-not [int]::TryParse($selection, [ref]$selection)) {
        Throw "Not a number"
    }
    if ($selection -lt 0 -or $selection -gt $Options.Length - 1) {
        Throw "Number not in range"
    }
    return $selection
}

function Test-ServerEdition {
    <#
	.SYNOPSIS
   	Checks if the current operating system edition is a Windows Server edition. Returns $true if its a Windows Server
   	
	.EXAMPLE
	Test-ServerEdition
	#>
    $osInfo = Get-CimInstance -Class Win32_OperatingSystem
    return ($osInfo.Caption -match "Windows Server")
}

function Test-ValidIP {
    <#
	.SYNOPSIS
	Checks if provided IP is valid

	.PARAMETER IP
	Specify the IP to check

	.EXAMPLE
	Test-ValidIP -IP "192.168.5.2"
	#>

    param (
        [String]$IP
    )

    try {
        [ipaddress] $IP | Out-Null
    }
    catch [System.InvalidCastException] {
        throw "Not a valid IP"
    }
}

function Test-ValidCIDR {
    <#
	.SYNOPSIS
	Checks if provided CIDR is valid

	.PARAMETER CIDR
	Specify the CIDR to check

	.EXAMPLE
	Test-ValidCIDR -CIDR "24"
	#>
    param (
        [String]$CIDR
    )

    if (-not($CIDR -ge 1 -and $CIDR -le 32)) {
        Throw "Not valid CIDR"
    }
}

function Test-ValidSubnetMask {
    <#
	.SYNOPSIS
	Checks if provided mask is valid

	.PARAMETER SubnetMask
	Specify the mask to check

	.EXAMPLE
	Test-ValidSubnetMask -SubnetMask "255.255.255.0"
	#>
    param (
        [String]$SubnetMask
    )

    $octets = $SubnetMask -split '\.'

    if ($octets.Length -ne 4) {
        Throw "Not a valid subnet mask"
    }

    $binaryMask = $octets | ForEach-Object {
        [Convert]::ToString([int]$_, 2).PadLeft(8, '0')
    }

    $binaryMask = [String]::Join('', $binaryMask)

    $onesCount = $binaryMask.IndexOf('0')
    
    if (-not($onesCount -ne -1 -and $binaryMask.Substring($onesCount) -notmatch '1')) {
        Throw "Not a valid subnet mask"
    }
}

function Test-ValidIPAddressWithCIDR {
    <#
	.SYNOPSIS
	Checks if provided IP is not a NetworkAddress or a BroadcastAddress with the CIDR specified

	.PARAMETER IP
	Specify the IP to check

	.PARAMETER CIDR
	Specify the CIDR to use

	.EXAMPLE
	Test-ValidIPAddressWithCIDR -IP "192.168.5.2" -CIDR "24"
	#>
    param (
        [String]$IP,
        [String]$CIDR
    )

    $IPAddressParts = $IP -split '\.'
    $IPAddressInt = 0

    for ($i = 0; $i -lt 4; $i++) {
        $IPAddressInt = $IPAddressInt * 256 + [int]$IPAddressParts[$i]
    }

    $CIDRPrefix = [int]$CIDR
    $NetworkAddressInt = $IPAddressInt -band ((-bnot 0) -shl (32 - $CIDRPrefix))
    $BroadcastAddressInt = $NetworkAddressInt -bor (-bnot ((-bnot 0) -shl (32 - $CIDRPrefix)))

    if ($IPAddressInt -eq $NetworkAddressInt -or $IPAddressInt -eq $BroadcastAddressInt) {
        Throw "Not a valid combination of IP and CIDR"
    }

    if (-not($IPAddressInt -ge $NetworkAddressInt -and $IPAddressInt -le $BroadcastAddressInt)) {
        Throw "Not a valid combination of IP and CIDR"
    }
}

function Get-Gateway {
    <#
	.SYNOPSIS
	Obtains the Gateway IP based on starting IP and CIDR

	.PARAMETER IP
	Specify the IP to use

	.PARAMETER CIDR
	Specify the CIDR to use

	.EXAMPLE
	Get-Gateway -IP "192.168.5.2" -CIDR "24"
	#>
    param (
        [String]$IP,
        [String]$CIDR
    )

	
    $IPAddressParts = $IP -split '\.'
    $IPAddressInt = 0

    for ($i = 0; $i -lt 4; $i++) {
        $IPAddressInt = $IPAddressInt * 256 + [int]$IPAddressParts[$i]
    }

    $CIDRPrefix = [int]$CIDR
    $NetworkAddressInt = $IPAddressInt -band ((-bnot 0) -shl (32 - $CIDRPrefix))
    $GatewayAddressInt = $NetworkAddressInt + 1

    $GatewayAddress = [String]::Join('.', [Math]::Truncate($GatewayAddressInt / 0x1000000), [Math]::Truncate($GatewayAddressInt / 0x10000 % 256), [Math]::Truncate($GatewayAddressInt / 0x100 % 256), [Math]::Truncate($GatewayAddressInt % 256))
    return $GatewayAddress
}
# END - UTIL FUNCTIONS - END

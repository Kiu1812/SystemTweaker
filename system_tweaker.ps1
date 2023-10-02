# START_FILE - parameters.ps1 - START_FILE

<#
.SYNOPSIS
Script with System utilities for Windows machines designed to enhance system configuration and management.

.DESCRIPTION
"SystemTweaker" is a script that provides various system utilities to streamline and optimize Windows machine settings. From self-updating capabilities to hostname customization, it aims to simplify common administrative tasks.

.NOTES
File Name : system_tweaker.ps1
Author : Kiu1812
Version : v0.2.5-beta
IMPORTANT: Some parameters are for internal use only and should not be used directly by users.

.PARAMETER Restarted
[INTERNAL PARAMETER] - This parameter is for internal use only and should not be used directly.

.PARAMETER Update
[INTERNAL PARAMETER] - This parameter is for internal use only and should not be used directly.


.PARAMETER SetHostname
    Specifies whether the script should set a new hostname for the computer.
    When enabled, the script will rename the computer using the value provided with the "Hostname" parameter.

    Type: Switch (Boolean)
    Default Value: False

.PARAMETER Hostname
    Specifies the new hostname for the computer. This parameter is only used if "SetHostname" is set to True.

    Type: String
    Default Value: (empty)

.PARAMETER SetIP
    Specifies whether the script should set an IP Address for the computer.
    When enabled, the script will set the new IP using the values provided with the "IP", "CIDR", etc... parameters.

    Type: Switch (Boolean)
    Default Value: False

.PARAMETER IP
    Specifies the new IP.
    Has to be a valid IP.
    This parameter is only used if "SetIP" is set to True.

    Type: String
    Default Value: (empty)

.PARAMETER CIDR
    Specifies the new Subnet Mask in CIDR format.
    This parameter is only used if "SetIP" is set to True.

    Type: [int]
    Default Value: (empty)

.PARAMETER Gateway
    Specifies the new Gateway.
    Can be a valid IP to set certain Gateway or any non valid IP value to set empty
    This parameter is only used if "SetIP" is set to True.
    
    Type: String
    Default Value: (empty)

.PARAMETER InterfaceIndex
    Specifies the Network Adapter to modify.
    The number has to be the field "InterfaceIndex" from the "Win32_NetworkAdapter" CIM Instance.
    Only need to set one of "InterfaceIndex" or "InterfaceName" parameters
    This parameter is only used if "SetIP" is set to True.

    Type: [int]
    Default Value: (empty)

.PARAMETER InterfaceName
    Specifies the Network Adapter to modify.
    The name has to be the field "Name" from the "Win32_NetworkAdapter" CIM Instance.
    Only need to set one of "InterfaceIndex" or "InterfaceName" parameters
    This parameter is only used if "SetIP" is set to True.

    Type: String
    Default Value: (empty)

.PARAMETER MainDNS
    Specifies the Main DNS Server.
    Has to be a valid IP.
    Only need to set one combination of ("MainDNS" and "SecondaryDNS") or "DNSServers".
    This parameter is only used if "SetIP" is set to True.

    Type: String
    Default Value: (empty)

.PARAMETER SecondaryDNS
    Specifies the Secondary DNS Server.
    Has to be a valid IP.
    Only need to set one combination of ("MainDNS" and "SecondaryDNS") or "DNSServers".
    This parameter is only used if "SetIP" is set to True.

    Type: String
    Default Value: (empty)

.PARAMETER DNSServers
    Specifies one or both DNS Servers.
    Has to contain valid(s) IP(s).
    Only need to set one combination of ("MainDNS" and "SecondaryDNS") or "DNSServers".
    This parameter is only used if "SetIP" is set to True.

    Type: String[]
    Default Value: (empty)

.EXAMPLE
.\system_tweaker.ps1
# INTERACTIVE MODE

.EXAMPLE
.\system_tweaker.ps1 -SetHostname -Hostname "DESKTOP-0DA3"
# SET NEW HOSTNAME

.EXAMPLE
.\system_tweaker.ps1 -SetIP -IP 192.168.56.4 -CIDR 24 -Gateway 192.168.56.1 -InterfaceIndex 16 -DNSServers 8.8.8.8,8.8.4.4
# SET NEW IP BY INTERFACE INDEX

.EXAMPLE
.\system_tweaker.ps1 -SetIP -IP 192.168.56.4 -CIDR 24 -Gateway 192.168.56.1 -InterfaceName "Intel(R) PRO/1000 MT Desktop Adapter #2" -DNSServers 8.8.8.8,8.8.4.4    
# SET NEW IP BY INTERFACE NAME

.LINK
GitHub Repository: https://github.com/Kiu1812/SystemTweaker
#>
[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    

    [Parameter(ParameterSetName = "Set-Hostname")]
    [Switch]$SetHostname,
    [Parameter(ParameterSetName = "Set-Hostname")]
    [String]$Hostname,
    

    [Parameter(ParameterSetName = "Set-IP")]
    [Switch]$SetIP,
    [Parameter(ParameterSetName = "Set-IP")]
    [String]$IP,
    [Parameter(ParameterSetName = "Set-IP")]
    [Int32]$CIDR,
    [Parameter(ParameterSetName = "Set-IP")]
    [String]$Gateway,
    [Parameter(ParameterSetName = "Set-IP")]
    [Int32]$InterfaceIndex,
    [Parameter(ParameterSetName = "Set-IP")]
    [String]$InterfaceName,
    [Parameter(ParameterSetName = "Set-IP")]
    [String]$MainDNS,
    [Parameter(ParameterSetName = "Set-IP")]
    [String]$SecondaryDNS,
    [Parameter(ParameterSetName = "Set-IP")]
    [String[]]$DNSServers,

    [Parameter(ParameterSetName = "__AllParameterSets")]
    [Switch]$Restarted,
    
    [Parameter(ParameterSetName = "__AllParameterSets")]
    [String]$Update
)


function ParseArguments {
    <#
	.SYNOPSIS
	Parses all the script arguments to execute the functions
	
	.PARAMETER ScriptArgs
    Array with the arguments provided to the script, only used so that I can check the "-Restarted" parameter

	.EXAMPLE
	ParseArguments -ScriptArgs "-Restarted","-NewComputerName","WIN-DESKTOP-34DE"
    #>
    param(
        [String]$ScriptArgs
    )

    if ($Update -and (Test-Administrator)) {
        if ($global:scriptName.StartsWith("tmp_")) {
            $original_name = $Update
            $scriptBlock = {
                param($originalName, $scriptName)
                Remove-Item -Path $originalName -Force
                Rename-Item -Path $scriptName -NewName $originalName -Force
                Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $originalName
            }
            Start-Process "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& { $scriptBlock }", "-originalName", $original_name, "-scriptName", $scriptName
            exit
        }
        Exit-PressKey
    }
	
    if ($Restarted -and (Test-Administrator)) {
        Clear-Any-Restart
    }
	
    # START - CHECK ADMIN PERMISSIONS - START
    if (-not(Test-Administrator)) {
        
        if ($Restarted) {
            Open-As-Admin $ScriptArgs

        }
        else {
            Write-Host "This script needs Administrator privileges"
            Confirm-Dialog -Text "Executing script as admin" -Warning
            Open-As-Admin $ScriptArgs
        }
        
        exit
    }
    # END - CHECK ADMIN PERMISSIONS - END

    # START FEATURE - SET HOSTNAME - FEATURE START
    if ($SetHostname) {
        if ($Hostname) {
            if ($Restarted) {
                Write-Host "The new computer name is" (hostname)
            }
            else {
                Set-Hostname $Hostname
            }
            Exit-PressKey
        }
    }
    # END FEATURE - SET HOSTNAME - FEATURE END
    
    # START FEATURE - SET IP - FEATURE START
    if ($SetIP) {
        if ($IP -and $CIDR -and $Gateway -and ($InterfaceIndex -or $InterfaceName)) {
            if ($DNSServers -and ($MainDNS -or $SecondaryDNS)) {
                throw "Too many DNS specified"
            }
            if ($MainDNS -or $SecondaryDNS) {
                $DNSServers = @($MainDNS, $SecondaryDNS)
            }

            if ($CIDR.Length -ge 3) {
                $CIDR = (($CIDR -split '\.' | ForEach-Object { [convert]::ToString([convert]::ToByte($_, 10), 2) }) -join '' -replace '0', '' | Measure-Object -Character).Characters
            }

            if ($InterfaceIndex) {
                if ($DNSServers) {
                    Set-IP -IP $IP -CIDR $CIDR -Gateway $Gateway -InterfaceIndex $InterfaceIndex -DNSServers $DNSServers
                }
                else {
                    Set-IP -IP $IP -CIDR $CIDR -Gateway $Gateway -InterfaceIndex $InterfaceIndex
                }
            }
            else {
                if ($DNSServers) {
                    Set-IP -IP $IP -CIDR $CIDR -Gateway $Gateway -InterfaceName $InterfaceName -DNSServers $DNSServers
                }
                else {
                    Set-IP -IP $IP -CIDR $CIDR -Gateway $Gateway -InterfaceName $InterfaceName
                }
            }
            Exit-PressKey
        }
        elseif ($IP -or $CIDR -or $Gateway -or $InterfaceIndex -or $InterfaceName -or $MainDNS -or $SecondaryDNS -or $DNSServers) {
            throw "Not enough parameters to set a new IP"
            Exit-PressKey
        }
    }
    # END FEATURE - SET IP - FEATURE END
}


# END_FILE - parameters.ps1 - END_FILE

# START_FILE - global_vars.ps1 - START_FILE

# START - GLOBAL VARIABLES - START
$global:CURRENT_VERSION = "v0.2.5-beta"
$global:scriptName = $MyInvocation.MyCommand.Name

# START - RESTART AND RESUME VARIABLES - START
$global:scriptFullPath = $myInvocation.MyCommand.Definition
$global:RegRunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$global:restartKey = "Restart-And-Resume"
$global:powershell = '"C:\Program Files\PowerShell\7\pwsh.exe"'
# END - RESTART AND RESUME VARIABLES - END
# END - GLOBAL VARIABLES - END

# END_FILE - global_vars.ps1 - END_FILE

# START_FILE - restart_and_resume.ps1 - START_FILE

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
    Restart-And-Run $global:restartKey "$global:powershell -Command `"$global:scriptFullPath -Restarted $parameters`""
}
# END - RESTART AND RESUME SCRIPT FUNCTIONS - END

# END_FILE - restart_and_resume.ps1 - END_FILE

# START_FILE - utils.ps1 - START_FILE

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
        $Arguments = $Arguments.Split(" ")
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
    
    .PARAMETER NoExit
	Return values or throw error

	.EXAMPLE
	Test-ValidIP -IP "192.168.5.2"
	#>

    param (
        [String]$IP,
        [Switch]$NoExit
    )

    try {
        [ipaddress] $IP | Out-Null
        if ($NoExit) {
            return 1
        }
    }
    catch [System.InvalidCastException] {
        if ($NoExit) {
            return 0
        }
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

# END_FILE - utils.ps1 - END_FILE

# START_FILE - auto_update.ps1 - START_FILE

# START FEATURE - AUTO UPDATE - START FEATURE
function Get-ScriptUpdate {
    <#
	.SYNOPSIS
	Checks if there is any new update for the script and downloads it if user wants

	.EXAMPLE
	Get-ScriptUpdate
	#>
    return
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

# END_FILE - auto_update.ps1 - END_FILE

# START_FILE - set_hostname.ps1 - START_FILE

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
        Restart-And-Resume "-SetHostname -Hostname $NewName"
    }
    else {
        Throw "Some error has occurred. Please try again"
    }
}
# END FEATURE - SET HOSTNAME - FEATURE END

# END_FILE - set_hostname.ps1 - END_FILE

# START_FILE - set_ip.ps1 - START_FILE

# START FEATURE - SET IP - FEATURE START
function Set-IP-Dialog {
    <#
	.SYNOPSIS
	Show all the options to set a new IP

	.EXAMPLE
	Set-IP-Dialog
	#>
    $NetworkAdapters = (Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -ge 0 -and $_.NetConnectionStatus -le 3 } | Select-Object netconnectionid, InterfaceIndex, netconnectionstatus) | ForEach-Object { $ip = (Get-NetIPAddress -AddressFamily "IPv4" -InterfaceAlias $_.netconnectionid) ; [PSCustomObject]@{netconnectionid = $_.netconnectionid; name = $_.name; netconnectionstatus = $_.netconnectionstatus; ip = $ip } }
    $NetworkAdaptersObjects = @()
    foreach ($Adapter in $NetworkAdapters) {
        $Position = "(" + $NetworkAdapters.IndexOf($Adapter) + ")"
        $Connection_ID = $Adapter.netconnectionid
        $Name = $Adapter.name
        $IP = $Adapter.ip
		
        switch ($Adapter.NetConnectionStatus) {
            0 {
                $Status = "Disconnected"
            }
            1 {
                $Status = "Connecting"
            }
            2 {
                $Status = "Connected"
            }
            3 {
                $Status = "Disconnecting"
            }
        }

        $NetworkAdaptersObjects += [PSCustomObject]@{
            "   "         = $Position
            Connection_ID = $Connection_ID
            Name          = $Name
            Status        = $Status
            IP            = $IP
        }
    }

    $selection = Select-From-Options -Title "Network Adapters" -Options $NetworkAdaptersObjects -CustomObject
	
    $NetworkAdapter = $NetworkAdaptersObjects[$selection]
    if ($NetworkAdapter.Status -eq "Disconnected") {
        Confirm-Dialog -Text "This interface is disconnected, script will try to enable it." -Warning
        Enable-NetAdapter -Name $NetworkAdapter.Connection_ID
        Start-Sleep -Seconds 2
        $NewStatus = (Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionId -eq $NetworkAdapter.Connection_ID } | Select-Object netconnectionstatus).NetConnectionStatus
        if ($NewStatus -lt 1 -or $NewStatus -gt 2) {
            Throw "Couldn't enable adapter, try to enable it manually and try again"
        }
    }

    Write-Host ""
    $NewIP = Read-Host -Prompt "New IP (Decimal or CIDR)"
    if ($NewIP.Contains("/")) {
        $NewIPParts = $NewIP -split "/"

        $NewIP = $NewIPParts[0]
        Test-ValidIP -IP $NewIP

        $NewCIDR = $NewIPParts[1]
        Test-ValidCIDR -CIDR $NewCIDR
    }
    else {
        Test-ValidIP -IP $NewIP

        $NewCIDR = Read-Host -Prompt "New Mask (Decimal or CIDR)"
        if ($NewCIDR.Length -ge 3) {
            Test-ValidSubnetMask -SubnetMask $NewCIDR
            $NewCIDR = (($NewCIDR -split '\.' | ForEach-Object { [convert]::ToString([convert]::ToByte($_, 10), 2) }) -join '' -replace '0', '' | Measure-Object -Character).Characters
        }
        else {
            Test-ValidCIDR -CIDR $NewCIDR
        }
    }

    Test-ValidIPAddressWithCIDR -IP $NewIP -CIDR $NewCIDR
    $NewGateway = Get-Gateway -IP $NewIP -CIDR $NewCIDR
    $NewGatewayPrompt = Read-Host -Prompt "New Gateway {any non IP value to set (empty)} [$NewGateway]"
    if (-not([string]::IsNullOrEmpty($NewGatewayPrompt))) {
        if ((Test-ValidIP -IP $NewGatewayPrompt -NoExit) -eq 0) {
            $NewGateway = "(empty)"
            Write-Host "Using (empty) Gateway"
        }
        else {
            $NewGateway = $NewGatewayPrompt
        }
    }
    $InterfaceIndex = (Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionId -eq $NetworkAdapter.Connection_ID } | Select-Object InterfaceIndex).InterfaceIndex
    

    # DNS OPTIONS
    $NewDNSServerAddresses = @("", "")
    $selection = Read-host -Prompt "Want to set DNS (Y/N) [N]"
    if ($selection.ToUpper() -eq "Y") {
        $NewMainDNS = "8.8.8.8"
        $NewSecondaryDNS = "8.8.4.4"

        $NewMainDNSPrompt = Read-Host -Prompt "Main DNS [8.8.8.8]`t"
        if (-not([string]::IsNullOrEmpty($NewMainDNSPrompt))) {
            Test-ValidIP -IP $NewMainDNSPrompt
            $NewMainDNS = $NewMainDNSPrompt
        }
        $NewSecondaryDNSPrompt = Read-Host -Prompt "Secondary DNS [8.8.4.4]`t"
        if (-not([string]::IsNullOrEmpty($NewSecondaryDNSPrompt))) {
            Test-ValidIP -IP $NewSecondaryDNSPrompt
            $NewSecondaryDNS = $NewSecondaryDNSPrompt
        }

        $NewDNSServerAddresses = @($NewMainDNS, $NewSecondaryDNS)
        Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceIndex $InterfaceIndex -DNSServers $NewDNSServerAddresses
    }
    else {
        Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceIndex $InterfaceIndex
    }

    <#
    Write-Host ""
    Write-Host "The new configuration is:"
    [PSCustomObject]@{
        ADAPTER       = $NetworkAdapter.Connection_ID
        IP            = $NewIP
        MASK          = $NewCIDR
        GATEWAY       = $NewGateway
        MAIN_DNS      = $NewDNSServerAddresses[0]
        SECONDARY_DNS = $NewDNSServerAddresses[1]
    } | Format-Table -AutoSize
    #>
}

function Set-IP () {
    <#
	.SYNOPSIS
	Sets a new IP from the parameters
	
	.PARAMETER IP
	New IP

    .PARAMETER CIDR
	New network mask, has to be in CIDR format

    .PARAMETER Gateway
	New Gateway

    .PARAMETER InterfaceIndex
	Index of interface where the IP will be set, has to be the "InterfaceIndex" from the "Win32_NetworkAdapter" CIM Instance

    .PARAMETER InterfaceName
	Name of interface where the IP will be set, has to be the "Name" from the "Win32_NetworkAdapter" CIM Instance

    .PARAMETER DNSServers
	Array with the two DNS servers to set

	.EXAMPLE
	Set-IP -IP "192.168.56.150" -CIDR 24 -Gateway "192.168.56.1" -InterfaceIndex 16 -DNSServers "8.8.8.8","8.8.4.4"
    Set-IP -IP "192.168.56.150" -CIDR 24 -Gateway "192.168.56.1" -InterfaceName  "Intel(R) PRO/1000 MT Desktop Adapter #2"
	#>
    param (
        [Parameter(Mandatory)]
        [String]$IP,

        [Parameter(Mandatory)]
        [Int32]$CIDR,

        [Parameter(Mandatory)]
        [String]$Gateway,

        [Parameter()]
        [String]$InterfaceIndex,

        [Parameter()]
        [String]$InterfaceName,

        [Parameter()]
        [String[]]$DNSServers
    ) 

    if (-not ($InterfaceIndex -or $InterfaceName)) {
        throw "No interface specified"
    }
    
    if ($InterfaceName) {
        $InterfaceIndex = (Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.name -eq $InterfaceName } | Select-Object InterfaceIndex).InterfaceIndex
        if (-not($InterfaceIndex)) {
            throw "Interface not found"
        }
    }

    $InterfaceIndex = (Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex } | Select-Object InterfaceIndex).InterfaceIndex
    if (-not($InterfaceIndex)) {
        throw "Interface not found"
    }

    Test-ValidIP -IP $IP
    Test-ValidCIDR -CIDR $CIDR
    Test-ValidIPAddressWithCIDR -IP $IP -CIDR $CIDR


    # Remove Old IP and Gateway before setting the new
    Remove-NetIPAddress -InterfaceIndex $InterfaceIndex -Confirm:$false
    Remove-NetRoute -InterfaceIndex $InterfaceIndex -Confirm:$false 2>$null
    
    Start-Sleep -Seconds 1
    if ($Gateway -ne "(empty)") {
        Test-ValidIP -IP $Gateway
        New-NetIPAddress -IPAddress $IP -PrefixLength $CIDR -DefaultGateway $Gateway -InterfaceIndex $InterfaceIndex | Out-Null
    }
    else {
        New-NetIPAddress -IPAddress $IP -PrefixLength $CIDR -InterfaceIndex $InterfaceIndex | Out-Null
    }
    
    if ($DNSServers -and ($DNSServers.Length -le 2)) {
        foreach ($DNSIP in $DNSServers) {
            Test-ValidIP -IP $DNSIP
        }
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DNSServers
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses
        $DNSServers = @("(empty)", "(empty)")
    }

    Write-Host ""
    Write-Host "The new configuration is:"
    [PSCustomObject]@{
        IP            = $IP
        MASK          = $CIDR
        GATEWAY       = $Gateway
        MAIN_DNS      = $DNSServers[0]
        SECONDARY_DNS = $DNSServers[1]
    } | Format-Table -AutoSize

    Exit-PressKey
}
# END FEATURE - SET IP - FEATURE END

# END_FILE - set_ip.ps1 - END_FILE

# START_FILE - main.ps1 - START_FILE

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

# END_FILE - main.ps1 - END_FILE


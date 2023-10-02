<#
.SYNOPSIS
Script with System utilities for Windows machines designed to enhance system configuration and management.

.DESCRIPTION
"SystemTweaker" is a script that provides various system utilities to streamline and optimize Windows machine settings. From self-updating capabilities to hostname customization, it aims to simplify common administrative tasks.

.NOTES
File Name : system_tweaker.ps1
Author : Kiu1812
Version : v0.2.7-beta
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


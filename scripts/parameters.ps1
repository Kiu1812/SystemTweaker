param(
    # [Switch]$Restarted # HIDED PARAMETER
    
    [String]$NewComputerName,
    
    # NEW IP PARAMETERS
    [String]$NewIP,
    [String]$NewCIDR,
    [String]$NewGateway,
    [String]$InterfaceIndex,
    [String]$InterfaceName,
    [String]$MainDNS,
    [String]$SecondaryDNS,
    [String[]]$DNSServers
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
        [String[]]$ScriptArgs
    )

    if (($ScriptArgs -contains '-Update') -and (Test-Administrator)) {
        if ($global:scriptName.StartsWith("tmp_")) {
            $original_name = $ScriptArgs[$ScriptArgs.IndexOf("-Update") + 1]
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
	
    if (($ScriptArgs -contains '-Restarted') -and (Test-Administrator)) {
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
    if ($NewIP -and $NewCIDR -and $NewGateway -and ($InterfaceIndex -or $InterfaceName)) {
        if ($DNSServers -and ($MainDNS -or $SecondaryDNS)) {
            throw "Too many DNS specified"
        }
        if ($MainDNS -or $SecondaryDNS) {
            if ($MainDNS) {
                Test-ValidIP -IP $MainDNS
            }
            if ($SecondaryDNS) {
                Test-ValidIP -IP $SecondaryDNS
            }
            $DNSServers = @($MainDNS, $SecondaryDNS)
        }

        Test-ValidIP -IP $NewIP

        if ($NewCIDR.Length -ge 3) {
            Test-ValidSubnetMask -SubnetMask $NewCIDR
            $NewCIDR = (($NewCIDR -split '\.' | ForEach-Object { [convert]::ToString([convert]::ToByte($_, 10), 2) }) -join '' -replace '0', '' | Measure-Object -Character).Characters
        }
        else {
            Test-ValidCIDR -CIDR $NewCIDR
        }
        
        Test-ValidIPAddressWithCIDR -IP $NewIP -CIDR $NewCIDR

        Test-ValidIP -IP $NewGateway

        if ($InterfaceIndex) {
            if ($DNSServers) {
                Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceIndex $InterfaceIndex -DNSServers $DNSServers
            }
            else {
                Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceIndex $InterfaceIndex
            }
        }
        else {
            if ($DNSServers) {
                Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceName $InterfaceName -DNSServers $DNSServers
            }
            else {
                Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceName $InterfaceName
            }
        }
        Exit-PressKey
    }
    elseif ($NewIP -or $NewCIDR -or $NewGateway -or $InterfaceIndex -or $InterfaceName -or $MainDNS -or $SecondaryDNS -or $DNSServers) {
        throw "Not enough parameters to set a new IP"
        Exit-PressKey
    }
    # END FEATURE - SET IP - FEATURE END
}
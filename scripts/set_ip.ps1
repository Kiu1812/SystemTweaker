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
    $NewGatewayPrompt = Read-Host -Prompt "New Gateway [$NewGateway]"
    if (-not([string]::IsNullOrEmpty($NewGatewayPrompt))) {
        Test-ValidIP -IP $NewGatewayPrompt
        $NewGateway = $NewGatewayPrompt
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
        Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceName $InterfaceIndex -DNSServers $NewDNSServerAddresses
    }
    else {
        Set-IP -IP $NewIP -CIDR $NewCIDR -Gateway $NewGateway -InterfaceName $InterfaceIndex
    }


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

    # Remove Old IP and Gateway before setting the new
    Remove-NetIPAddress -InterfaceIndex $InterfaceIndex -Confirm:$false
    Remove-NetRoute -InterfaceIndex $InterfaceIndex -Confirm:$false
    
    Start-Sleep -Seconds 1
    New-NetIPAddress -IPAddress $NewIP -PrefixLength $NewCIDR -DefaultGateway $NewGateway -InterfaceIndex $InterfaceIndex | Out-Null
    
    if ($DNSServers -and ($DNSServers.Length -le 2)) {
        foreach ($DNSIP in $DNSServers) {
            Test-ValidIP -IP $DNSIP
        }
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DNSServers
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ResetServerAddresses
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
}
# END FEATURE - SET IP - FEATURE END

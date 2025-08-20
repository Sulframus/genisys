function IndividualCheck(){
    param(
        [Parameter(Mandatory=$false)][String]$expected,
        [Parameter(Mandatory)][ScriptBlock]$actual
    )

    $Session:QCProgress = @{Step = "Checking $check..."; Percent = $($Session:QCProgress.Percent + $step)}
    Sync-UDElement -ID "QCProgress"
    [String]$actualResult = & $actual
    $result += [PSCustomObject]@{
        Value = $check
        Expected = $expected
        Actual = $actualResult
    }

    return $result
}

function QCServer(){
    param(
        [Parameter(Mandatory)][String]$serverName,
        [Parameter(Mandatory)][String]$timeZone,
        [Parameter(Mandatory)][String]$serverType,
        [Parameter(Mandatory)][PSCredential]$cred
    )

    $Session:QCProgress = @{Step = "Starting checks..."; Percent = 0}
    Sync-UDElement -ID "QCProgress"
    $CimSession = New-CimSession -ComputerName $serverName -Credential $cred -ErrorAction Stop
    $PSSession = New-PSSession -ComputerName $serverName -Credential $cred -ErrorAction Stop
    $Session:QCProgress = @{Step = "Getting VM details..."; Percent = 0}
    Sync-UDElement -ID "QCProgress"

    $VM = Get-VM -Name $serverName
    $VMView = $VM | Get-View
    $VMNIC = Get-NetworkAdapter -VM $VM

    [Array]$checks = @("Time Zone","RDP","Pagefile Location","Pagefile Management","C Drive Label","VM Memory Hot Add","VM Memory Shares","VM CPU Hot Add","VM CPU Shares","VM Adapter Direct Path","VM Encryption","DNS Settings","IPv4 Manual","IPv4 IP","IPv6 Disabled")
    [Array]$result = @()

    if(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}){
        $checks += "D Drive Label"
    }
    switch($serverType){
        "Generic"{
            # Nothing extra
        }
        "Domain Controller"{
            # Domain controller roles
            $checks += @(
                "AD-Domain-Services",
                "DNS",
                "FileAndStorage-Services",
                "File-Services",
                "FS-FileServer",
                "Storage-Services",
                "GPMC"
            )
        }
        "Office Print Server" {
            # Print role, permissions for admin groups, spooler service
            $checks += @(
                "Spooler",
                "Print-Services",
                "Print-Server",
                "Print Server Permissions"
            )
        }
        "Production Print Server" {
            # Print role, permissions for admin groups, spooler service
            $checks += @(
                "Spooler",
                "Print-Services",
                "Print-Server",
                "Print Server Permissions"
            )
        }
        "Web Server" {

        }
        "Tanium Provisioning Server" {
            # Tanium PXe service setup
        }
        "Office Terminal Server" {
            # Terminal role, remote user group
        }
        "Production Terminal Server" {
            # Terminal role, remote user group
        }
        "Crystal Reports Server" {
            # Application installed?
        }
        "SQL Server" {
            # Application installed?
        }
        "Application Server" {

        }
        "AOS File Server" {
            # Grab from AOS setup
        }
        "Commvault Proxy Server" {
            # Commvault installed?
        }
        "Network Policy Server" {
            # NPS role installed
        }
        "DHCP Server" {
            # DHCP role installed, specific location of DHCP database
        }
        default{
            $result += [PSCustomObject]@{
                Value = "MISSING SWITCH CASE"
                Expected = $serverType
                Actual = 'FROM $serverTypes ARRAY'
            }
        }
    }

    [Float]$step = 100 / $checks.Count
    [Object[]]$serverFeatures = Invoke-Command -Session $PSSession -ScriptBlock {Get-WindowsFeature}

    foreach($check in $checks){
        switch($check){
            "Time Zone"{
                IndividualCheck -Expected $timeZone -Actual {Invoke-Command -Session $PSSession -ScriptBlock {[TimeZoneInfo]::Local.DisplayName}}
            }
            "RDP"{
                IndividualCheck -Expected "1" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_TerminalServiceSetting -Namespace "root\cimv2\terminalservices").AllowTsConnections}
            }
            "Pagefile Location"{
                IndividualCheck -Expected "C:\pagefile.sys" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_PageFileUsage).Name}
            }
            "Pagefile Management"{
                IndividualCheck -Expected "False" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem).AutomaticManagedPagefile}
            }
            "C Drive Label"{
                IndividualCheck -Expected "OS" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "C:"}).Label}
            }
            "D Drive Label"{
                IndividualCheck -Expected "Data" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}).Label}
            }
            "AD-Domain-Services"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "DNS"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "FileAndStorage-Services"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "File-Services"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "FS-FileServer"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Storage-Services"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "GPMC"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Spooler"{
                IndividualCheck -Expected "Automatic" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-Service -Name "Spooler").StartType}}
            }
            "Print-Services"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Print-Server"{
                IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Print Server Permissions"{
                # TODO
            }
            "VM Memory Shares"{
                IndividualCheck -Expected "Normal" -Actual {$VM.VMResourceConfiguration.MemSharesLevel}
            }
            "VM Memory Hot Add"{
                IndividualCheck -Expected "True" -Actual {$VMView.Config.MemoryHotAddEnabled}
            }
            "VM CPU Shares"{
                IndividualCheck -Expected "Normal" -Actual {$VM.VMResourceConfiguration.CPUSharesLevel}
            }
            "VM CPU Hot Add"{
                IndividualCheck -Expected "True" -Actual {$VMView.Config.CPUHotAddEnabled}
            }
            "VM Adapter Direct Path"{
                IndividualCheck -Expected $null -Actual {$VMNIC.Device.UptCompatibilityEnabled}
            }
            "VM Encryption"{

            }
            "DNS Settings"{
                IndividualCheck -Expected $null -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-DNSClientServerAddress | Where-Object {$null -ne $_.ServerAddresses -AND $_.AddressFamily -eq "2"}).ServerAddresses}}
            }
            "IPv4 Manual"{
                IndividualCheck -Expected "Manual" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"}).PrefixOrigin}}
            }
            "IPv4 IP"{

            }
            "IPv6 Disabled"{
                IndividualCheck -Expected "False" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"} | ForEach-Object {Get-NetAdapterBinding -Name $_.InterfaceAlias -ComponentID ms_tcpip6}).Enabled}}
            }
            default{
                $result += [PSCustomObject]@{
                    Value = "MISSING SWITCH CASE"
                    Expected = $check
                    Actual = 'FROM $checks ARRAY'
                }
            }
        }
    }

    $Session:QCProgress = @{Step = "Checks for $userServerName are completed"; Percent = 100}
    Sync-UDElement -ID "QCProgress"

    return $result
}

function LoginToVCenter(){
    param(
        [Parameter(Mandatory=$false)][PSCredential]$cred
    )
    foreach($vCenterServer in $vCenterServers){
        if($cred){
            try{
                if($DefaultVIServers.Name -notcontains $vCenterServer){
                    Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -InvalidCertificateAction Ignore -ProxyPolicy NoProxy -DefaultVIServerMode Multiple -Confirm:$false -Credential $cred | Out-Null
                    Connect-VIServer -Server $vCenterServer -Force -WarningAction SilentlyContinue | Out-Null
                }
            }
            catch{
                Write-Error "Unable to login to $vCenterServer"
                Disconnect-VIServer -Server * -Confirm:$false
            }
        }
        else{
            try{
                if($DefaultVIServers.Name -notcontains $vCenterServer){
                    Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -InvalidCertificateAction Ignore -ProxyPolicy NoProxy -DefaultVIServerMode Multiple -Confirm:$false | Out-Null
                    Connect-VIServer -Server $vCenterServer -Force -WarningAction SilentlyContinue | Out-Null
                }
            }
            catch{
                Write-Error "Unable to login to $vCenterServer"
                Disconnect-VIServer -Server * -Confirm:$false
            }
        }
    }
}

$timeZones = @(
    "(UTC+00:00) Dublin, Edinburgh, Lisbon, London",
    "(UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague",
    "(UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb",
    "(UTC+01:00) Brussels, Copenhagen, Madrid, Paris",
    "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna",
    "(UTC+01:00) West Central Africa",
    "(UTC+02:00) Bucharest",
    "(UTC+02:00) Cairo",
    "(UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius",
    "(UTC+02:00) Athens, Istanbul, Minsk",
    "(UTC+02:00) Jerusalem",
    "(UTC+02:00) Harare, Pretoria"
)

$serverTypes = @(
    "Generic",
    "Domain Controller",
    "Office Print Server",
    "Production Print Server",
    "Web Server",
    "Tanium Provisioning Server",
    "Office Terminal Server",
    "Production Terminal Server",
    "Crystal Reports Server",
    "SQL Server",
    "Application Server",
    "AOS File Server",
    "Commvault Proxy Server",
    "Network Policy Server",
    "DHCP Server"
)

$vCenterServers = @(
    "IEDUB1VCA201.dpweur.ad.dpworld.com",
    "IEDUB2VCA201.dpweur.ad.dpworld.com",
    "DEAVCA201.dpweur.ad.dpworld.com"
)

New-UDDashboard -Title "Genisys" -Pages @(
    New-UDPage -Name "Home" -Content {
        New-UDButton -Text "QC Server" -OnClick {Invoke-UDRedirect "/qc-server"}
        New-UDButton -Text "Server Build" -OnClick {Invoke-UDRedirect "/server-build"}
    }

    New-UDPage -Name "QC Server" -Content {
        New-UDCard -Title "QC Server" -Content {
            New-UDTextbox -ID "serverName" -Label "Server Name"
            New-UDSelect -ID "serverType" -Label "Server Type" -DefaultValue $serverTypes[0] -Option {
                foreach($serverType in $serverTypes){
                    New-UDSelectOption -Name $serverType -Value $serverType
                }
            }

            New-UDSelect -ID "timeZone" -Label "Server Timezone" -DefaultValue $timeZones[0] -Option {
                foreach($timeZone in $timeZones){
                    New-UDSelectOption -Name $timeZone -Value $timeZone
                }
            }

            New-UDUpload -Text "Import File" -OnUpload {
                $Session:Import = Import-CSV $Body.FileName -Delimiter ";"
                if($Session:Import){
                    Show-UDToast -Message "Import successful"
                }
                else{
                    Show-UDToast -Message "Import failed"
                }
            }

            New-UDButton -Text "Submit" -OnClick {
                if($Session:Import){
                    $userCred = Get-Credential

                    $Session:QCProgress = @{Step = "Connecting to vCenters..."; Percent = 0}
                    Sync-UDElement -ID "QCProgress"
                    # Load only the important parts to speed up the process
                    Import-Module VMware.VimAutomation.Core
                    LoginToVCenter

                    foreach($line in $Session:Import){
                        $userServerName = $line.serverName
                        $userServerType = $line.serverType
                        $userTimeZone = $line.timeZone

                        $QCServerResult = QCServer -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred

                        # Insert the table dynamically
                        Set-UDElement -ID "QCServerResultTable" -Content {
                            New-UDTable -Data $QCServerResult -Columns @(
                                New-UDTableColumn -Property Value -Title "Value"
                                New-UDTableColumn -Property Expected -Title "Expected"
                                New-UDTableColumn -Property Actual -Title "Actual"
                            ) -OnRowStyle {
                                if($EventData.Expected -eq $EventData.Actual){@{backgroundColor = $null}}
                                elseif($null -eq $EventData.Expected){@{backgroundColor = "Yellow"}}
                                elseif($EventData.Expected -ne $EventData.Actual){@{backgroundColor = "Red"}}
                            }
                        }
                    }
                }
                else{
                    $userServerName = (Get-UDElement -ID "serverName").Value
                    $userServerType = (Get-UDElement -ID "serverType").Value
                    $userTimeZone = (Get-UDElement -ID "timeZone").Value
                    $userCred = Get-Credential

                    $Session:QCProgress = @{Step = "Connecting to vCenters..."; Percent = 0}
                    Sync-UDElement -ID "QCProgress"
                    # Load only the important parts to speed up the process
                    Import-Module VMware.VimAutomation.Core
                    LoginToVCenter

                    $QCServerResult = QCServer -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred

                    # Insert the table dynamically
                    Set-UDElement -ID "QCServerResultTable" -Content {
                        New-UDTable -Data $QCServerResult -Columns @(
                            New-UDTableColumn -Property Value -Title "Value"
                            New-UDTableColumn -Property Expected -Title "Expected"
                            New-UDTableColumn -Property Actual -Title "Actual"
                        ) -OnRowStyle {
                            if($EventData.Expected -eq $EventData.Actual){@{backgroundColor = $null}}
                            elseif($null -eq $EventData.Expected){@{backgroundColor = "Yellow"}}
                            elseif($EventData.Expected -ne $EventData.Actual){@{backgroundColor = "Red"}}
                        }
                    }
                }
            }

            New-UDDynamic -ID "QCProgress" -Content {
                New-UDTypography -Text $Session:QCProgress.Step
                New-UDProgress -PercentComplete $Session:QCProgress.Percent
            }

            New-UDElement -ID "QCServerResultTable" -Tag "div"
        }
    }

    New-UDPage -Name "Server Build" -Content {}
)

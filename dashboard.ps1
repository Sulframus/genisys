function IndividualCheck(){
    param(
        [Parameter(Mandatory=$false)][String]$expected,
        [Parameter(Mandatory)][ScriptBlock]$actual
    )

    $Session:QCProgress = @{Step = "Checking $check..."; Percent = $($Session:QCProgress.Percent + $step)}; Sync-UDElement -ID "QCProgress"
    [String]$actualResult = & $actual
    $individualCheckResult = [PSCustomObject]@{
        $check = @{
            expected = $expected
            actual = $actualResult
        }
    }

    return $individualCheckResult
}

function QCServer(){
    param(
        [Parameter(Mandatory)][String]$serverName,
        [Parameter(Mandatory)][String]$timeZone,
        [Parameter(Mandatory)][String]$serverType,
        [Parameter(Mandatory)][PSCredential]$cred
    )

    $Session:QCProgress = @{Step = "Creating sessions..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    $CimSession = New-CimSession -ComputerName $serverName -Credential $cred -ErrorAction Stop
    $PSSession = New-PSSession -ComputerName $serverName -Credential $cred -ErrorAction Stop

    $Session:QCProgress = @{Step = "Connecting to database..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER

    $Session:QCProgress = @{Step = "Getting VM details..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    $VM = Get-VM -Name $serverName
    $VMView = $VM | Get-View
    $VMNIC = Get-NetworkAdapter -VM $VM

    [Double]$id = (Get-MdbcData)._id ? ((Get-MdbcData)._id | Measure-Object -Maximum).Maximum + 1 : 1

    # Structure used in the database
    $dataStructure = @{
        _id = $id
        server_name = $serverName
        report_date = (Get-Date)
        setting = @()
    }

    [Array]$checks = @("Time Zone","RDP","Pagefile Location","Pagefile Management","C Drive Label","VM Memory Hot Add","VM Memory Shares","VM CPU Hot Add","VM CPU Shares","VM Adapter Direct Path","VM Encryption","DNS Settings","IPv4 Manual","IPv4 IP","IPv6 Disabled","SCOM Registries","SCOM Agent")

    if(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}){
        $checks += "D Drive Label"
    }

    # Additional checks based on the server type
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
                "Print-Server"
                #"Print Server Permissions"
            )
        }
        "Production Print Server" {
            # Print role, permissions for admin groups, spooler service
            $checks += @(
                "Spooler",
                "Print-Services",
                "Print-Server"
                #"Print Server Permissions"
            )
        }
        "Web Server" {

        }
        "Tanium Provisioning Server" {
            # Tanium PXe service setup
            $checks += @(
                "TaniumPXE"
            )
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
            $dataStructure.setting += [PSCustomObject]@{
                "MISSING SWITCH CASE" = @{
                    expected = $serverType
                    actual = 'FROM $serverTypes ARRAY'
                }
            }
        }
    }

    [Float]$step = 100 / $checks.Count # Used for calculating progress bar
    [Object[]]$serverFeatures = Invoke-Command -Session $PSSession -ScriptBlock {Get-WindowsFeature} # Pre-load all server features for checks

    # Run through each assigned check
    foreach($check in $checks){
        switch($check){
            "Time Zone"{
                $dataStructure.setting += IndividualCheck -Expected $timeZone -Actual {Invoke-Command -Session $PSSession -ScriptBlock {[TimeZoneInfo]::Local.DisplayName}}
            }
            "RDP"{
                $dataStructure.setting += IndividualCheck -Expected "1" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_TerminalServiceSetting -Namespace "root\cimv2\terminalservices").AllowTsConnections}
            }
            "Pagefile Location"{
                $dataStructure.setting += IndividualCheck -Expected "C:\pagefile.sys" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_PageFileUsage).Name}
            }
            "Pagefile Management"{
                $dataStructure.setting += IndividualCheck -Expected "False" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem).AutomaticManagedPagefile}
            }
            "C Drive Label"{
                $dataStructure.setting += IndividualCheck -Expected "OS" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "C:"}).Label}
            }
            "D Drive Label"{
                $dataStructure.setting += IndividualCheck -Expected "Data" -Actual {(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}).Label}
            }
            "AD-Domain-Services"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "DNS"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "FileAndStorage-Services"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "File-Services"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "FS-FileServer"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Storage-Services"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "GPMC"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Spooler"{
                $dataStructure.setting += IndividualCheck -Expected "Automatic" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-Service -Name "Spooler").StartType}}
            }
            "Print-Services"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            "Print-Server"{
                $dataStructure.setting += IndividualCheck -Expected "Installed" -Actual {$($serverFeatures | Where-Object {$_.Name -eq $check}).InstallState}
            }
            <#"Print Server Permissions"{
                $dataStructure.setting += IndividualCheck -Expected "SG_DPWEUR_LP_APP_AD-AllPrintServers.Operators" -Actual {
                    $SID = Invoke-Command -Session $PSSession -ScriptBlock {
                        param($cred)
                        New-PSDrive -Name AZ -PSProvider FileSystem -Root "\\DEWCPS201.dpweur.ad.dpworld.com\Share" -Credential $cred | Out-Null
                        $security = AZ:\setprinter.exe -Show \\$env:COMPUTERNAME\ 3
                        Remove-PSDrive -Name AZ | Out-Null
                        ([Regex]::matches($security,"S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}-\d{1,10}") | Sort-Object -Unique).Value
                    } -ArgumentList $cred
                    (Get-ADGroup -Filter {SID -eq $SID}).Name
                }
            }#>
            "VM Memory Shares"{
                $dataStructure.setting += IndividualCheck -Expected "Normal" -Actual {$VM.VMResourceConfiguration.MemSharesLevel}
            }
            "VM Memory Hot Add"{
                $dataStructure.setting += IndividualCheck -Expected "True" -Actual {$VMView.Config.MemoryHotAddEnabled}
            }
            "VM CPU Shares"{
                $dataStructure.setting += IndividualCheck -Expected "Normal" -Actual {$VM.VMResourceConfiguration.CPUSharesLevel}
            }
            "VM CPU Hot Add"{
                $dataStructure.setting += IndividualCheck -Expected "True" -Actual {$VMView.Config.CPUHotAddEnabled}
            }
            "VM Adapter Direct Path"{
                $dataStructure.setting += IndividualCheck -Expected "False" -Actual {$VMNIC.ExtensionData.UptCompatibilityEnabled}
            }
            "VM Encryption"{
                $dataStructure.setting += IndividualCheck -Expected "Disabled" -Actual {$VMView.Config.MigrateEncryption}
            }
            "DNS Settings"{
                $dataStructure.setting += IndividualCheck -Expected $null -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-DNSClientServerAddress | Where-Object {$_.ServerAddresses -ne $null -AND $_.AddressFamily -eq "2"}).ServerAddresses}}
            }
            "IPv4 Manual"{
                $dataStructure.setting += IndividualCheck -Expected "Manual" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"}).PrefixOrigin}}
            }
            "IPv4 IP"{
                $dataStructure.setting += IndividualCHeck -Expected $null -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"}).IPAddress}}
            }
            "IPv6 Disabled"{
                $dataStructure.setting += IndividualCheck -Expected "False" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"} | ForEach-Object {Get-NetAdapterBinding -Name $_.InterfaceAlias -ComponentID ms_tcpip6}).Enabled}}
            }
            "SCOM Registries"{
                $dataStructure.setting += IndividualCheck -Expected $null -Actual {Invoke-Command -Session $PSSession -ScriptBlock {Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Syncreon" -Name "MainGroup"; Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Syncreon" -Name "SiteCode"}}
            }
            "SCOM Agent"{
                $dataStructure.setting += IndividualCheck -Expected "Running" -Actual {Invoke-Command -Session $PSSession -ScriptBlock {(Get-Service -Name "HealthService").Status}}
            }
            "TaniumPXE"{

            }
            default{
                $dataStructure.setting += [PSCustomObject]@{
                    "MISSING SWITCH CASE" = @{
                        expected = $check
                        actual = 'FROM $checks ARRAY'
                    }
                }
            }
        }
    }

    $Session:QCProgress = @{Step = "Saving to database..."; Percent = 100}; Sync-UDElement -ID "QCProgress"
    $dataStructure | Add-MdbcData

    $Session:QCProgress = @{Step = "Checks for $serverName are completed"; Percent = 100}; Sync-UDElement -ID "QCProgress"

    Remove-PSSession -Session $PSSession
    Remove-CimSession -CimSession $CimSession
}

function LoginToVCenter(){
    param(
        [Parameter(Mandatory=$false)][PSCredential]$cred
    )
    foreach($vCenterServer in $global:VCENTER_SERVERS){
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

New-UDDashboard -Title "Genisys" -Pages @(
    # Home page used for navigating to different apps
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

            New-UDButton -Text "Start server check" -OnClick {
                # Load only the important parts to speed up the process
                [PSCredential]$userCred = Get-Credential
                Import-Module VMware.VimAutomation.Core
                $Session:QCProgress = @{Step = "Connecting to vCenters..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
                LoginToVCenter

                if($Session:Import){
                    foreach($importedLine in $Session:Import){
                        $userServerName = $importedLine.serverName
                        $userServerType = $importedLine.serverType
                        $userTimeZone = $importedLine.timeZone

                        QCServer -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred
                    }
                }
                else{
                    $userServerName = (Get-UDElement -ID "serverName").Value
                    $userServerType = (Get-UDElement -ID "serverType").Value
                    $userTimeZone = (Get-UDElement -ID "timeZone").Value

                    QCServer -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred
                }
                Sync-UDElement -ID "QCSelectRegion"
            }

            New-UDDynamic -ID "QCProgress" -Content {
                New-UDTypography -Text $Session:QCProgress.Step
                New-UDProgress -PercentComplete $Session:QCProgress.Percent
            }

            New-UDDynamic -ID "QCSelectRegion" -Content {
                Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER
                # Get data from newest to oldest
                $QCServerResultSelect = Get-MdbcData | Sort-Object -Descending | ForEach-Object {
                    [PSCustomObject]@{
                        qc_server_result_select__id = $_._id
                        qc_server_result_select_server_name = $_.server_name
                        qc_server_result_select_report_date = $_.report_date
                    }
                }
                New-UDTable -Data $QCServerResultSelect -Columns @(
                    New-UDTableColumn -Property "qc_server_result_select__id" -Title "ID" -Render {
                        New-UDButton -Text $EventData.qc_server_result_select__id -OnClick {
                            Show-UDToast -Message "Loading report ID: $($EventData.qc_server_result_select__id)"
                            $Session:qc_server_result_select__id = $EventData.qc_server_result_select__id
                            Sync-UDElement -ID "QCServerResultTable"
                        } -Variant "text"
                    }
                    New-UDTableColumn -Property "qc_server_result_select_server_name" -Title "Server Name"
                    New-UDTableColumn -Property "qc_server_result_select_report_date" -Title "Report Date"
                )
            }
            Sync-UDElement -ID "QCSelectRegion"

            New-UDDynamic -ID "QCServerResultTable" -Content {
                Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER
                $QCServerResultData = Get-MdbcData | Where-Object {$_._id -eq $Session:qc_server_result_select__id} | ForEach-Object {
                    foreach ($setting in $_.setting) {
                        [PSCustomObject]@{
                            Setting = $setting.keys
                            Expected = $setting.values.expected
                            Actual = $setting.values.actual
                        }
                    }
                }

                New-UDTable -Data $QCServerResultData -Columns @(
                    New-UDTableColumn -Property "Setting" -Title "Setting" -Render {$EventData.Setting -join ","}
                    New-UDTableColumn -Property "Expected" -Title "Expected" -Render {$EventData.Expected -join ","}
                    New-UDTableColumn -Property "Actual" -Title "Actual" -Render {$EventData.Actual -join ","}
                ) -OnRowStyle {
                    if($EventData.Expected -eq ""){@{backgroundColor = "Yellow"}}
                    elseif($EventData.Expected -ne $EventData.Actual){@{backgroundColor = "Red"}}
                }
            }
        }
    }

    New-UDPage -Name "Server Build" -Content {}
)

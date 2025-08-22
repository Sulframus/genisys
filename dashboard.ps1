try{
    $checkDefaults = Get-Content -Raw -Path $CHECK_DEFAULTS_FILEPATH | ConvertFrom-Json
}
catch{
    Write-Error "Unable to load config file: $($_.Exception.Message)"
    throw
}

function Get-CheckType {
    param([string]$serverType)

    $defaultChecks = @("Time Zone","RDP","Pagefile Location","Pagefile Management","C Drive Label","VM Memory Hot Add","VM Memory Shares","VM CPU Hot Add","VM CPU Shares","VM Adapter Direct Path","VM Encryption","DNS Settings","IPv4 Manual","IPv4 IP","IPv6 Enabled","SCOM Registries","SCOM Agent")

    if(Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}){
        $checks.Add("D Drive Label")
    }

    $serverTypeMap = @{
        "Generic" = @()
        "Domain Controller" = @("AD-Domain-Services","DNS","FileAndStorage-Services","File-Services","FS-FileServer","Storage-Services","GPMC")
        "Office Print Server" = @("Spooler", "Print-Services", "Print-Server")
        "Production Print Server" = @("Spooler", "Print-Services", "Print-Server")
        "Web Server" = @()
        "Tanium Provisioning Server" = @("TaniumPXE")
        "Office Terminal Server" = @("RDP Licensing")
        "Production Terminal Server" = @("RDP Licensing")
        "Crystal Reports Server" = @()
        "SQL Server" = @()
        "Application Server" = @()
        "AOS File Server" = @()
        "Commvault Proxy Server" = @()
        "Network Policy Server" = @()
        "DHCP Server" = @() # DHCP role installed, specific location of DHCP database
    }

    return $defaultChecks + ($serverTypeMap[$serverType] | Where-Object {$_})
}

function Get-QualityCheckResult {
    param(
        [Parameter(Mandatory)][String]$check,
        [Parameter(Mandatory=$false)][Float]$step,
        [Parameter(Mandatory=$false)][String]$expected,
        [Parameter(Mandatory)][ScriptBlock]$actual
    )

    $Session:QCProgress = @{Step = "Checking $check..."; Percent = $($Session:QCProgress.Percent + $step)}; Sync-UDElement -ID "QCProgress"
    [String]$actualResult = ($actual).Invoke()
    $individualCheckResult = [PSCustomObject]@{
        $check = @{
            expected = $expected
            actual = $actualResult
        }
    }

    return $individualCheckResult
}

function Submit-ServerQualityCheck {
    # Load only the important parts to speed up the process
    [PSCredential]$userCred = Get-Credential
    $Session:QCProgress = @{Step = "Connecting to vCenters..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    Import-Module VMware.VimAutomation.Core
    Connect-VCenterServer

    if($Session:Import){
        foreach($importedLine in $Session:Import){
            $userServerName = $importedLine.serverName
            $userServerType = $importedLine.serverType
            $userTimeZone = $importedLine.timeZone

            Invoke-ServerQualityCheck -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred
        }
    }
    else{
        $userServerName = (Get-UDElement -ID "serverName").Value
        $userServerType = (Get-UDElement -ID "serverType").Value
        $userTimeZone = (Get-UDElement -ID "timeZone").Value

        Invoke-ServerQualityCheck -serverName $userServerName -timeZone $userTimeZone -serverType $userServerType -cred $userCred
    }
    Sync-UDElement -ID "QCServerSelectTable"
}

function Invoke-ServerQualityCheck {
    param(
        [Parameter(Mandatory)][String]$serverName,
        #[Parameter(Mandatory)][String]$timeZone,
        [Parameter(Mandatory)][String]$serverType,
        [Parameter(Mandatory)][PSCredential]$cred
    )

    $Session:QCProgress = @{Step = "Creating sessions..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    $CimSession = New-CimSession -ComputerName $serverName -Credential $cred -ErrorAction Stop
    $PSSession = New-PSSession -ComputerName $serverName -Credential $cred -ErrorAction Stop

    $Session:QCProgress = @{Step = "Connecting to database..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    try{
        Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER
    }
    catch{
        Show-UDToast -Message "Unable to connect to collection $DATABASE_COLLECTION_QC_SERVER in database $DATABASE_NAME : $($_.Exception.Message)" -Duration $WARNING_TOAST_DURATION
    }

    $Session:QCProgress = @{Step = "Getting VM details..."; Percent = 0}; Sync-UDElement -ID "QCProgress"
    try{
        $VM = Get-VM -Name $serverName
        $VMView = $VM | Get-View
        $VMNIC = Get-NetworkAdapter -VM $VM
    }
    catch{
        Show-UDToast -Message "Unable to get VM details: $($_.Exception.Message)" -Duration $WARNING_TOAST_DURATION
    }

    $checks = Get-CheckType -serverType $serverType

    # Structure used in the database
    $dataStructure = @{
        _id = (New-Guid)
        caller = $user
        server_name = $serverName
        server_type = $serverType
        report_date = (Get-Date)
        setting = @()
    }

    [Float]$step = 100 / $checks.Count # Used for calculating progress bar
    $serverFeaturesMap = @{}
    Invoke-Command -Session $PSSession -ScriptBlock {Get-WindowsFeature} | ForEach-Object {$serverFeaturesMap[$_.Name] = $_.InstallState}  # Pre-load all server features for checks

    $checkActions = @{
        "Time Zone" = {Get-QualityCheckResult -check $check -step $step -Expected $timeZone -Actual {[String](Invoke-Command -Session $PSSession -ScriptBlock {[TimeZoneInfo]::Local.DisplayName})}}
        "RDP" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[UInt32](Get-CimInstance -CimSession $CimSession -ClassName Win32_TerminalServiceSetting -Namespace "root\cimv2\terminalservices").AllowTsConnections}}
        "Pagefile Location" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Get-CimInstance -CimSession $CimSession -ClassName Win32_PageFileUsage).Name}}
        "Pagefile Management" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[Boolean](Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem).AutomaticManagedPagefile}}
        "C Drive Label" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "C:"}).Label}}
        "D Drive Label" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Get-CimInstance -CimSession $CimSession -ClassName Win32_Volume | Where-Object {$_.DriveLetter -eq "D:"}).Label}}
        "AD-Domain-Services" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "DNS" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "FileAndStorage-Services" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "File-Services" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "FS-FileServer" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "Storage-Services" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "GPMC" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "Spooler" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Invoke-Command -Session $PSSession -ScriptBlock {(Get-Service -Name "Spooler").StartType})}}
        "Print-Services" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        "Print-Server" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String]$serverFeaturesMap[$check]}}
        <#"Print Server Permissions" = {
            Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {
                $SID = Invoke-Command -Session $PSSession -ScriptBlock {
                    param($cred)
                    New-PSDrive -Name AZ -PSProvider FileSystem -Root "$FILE_SHARE\setprinter.exe" -Credential $cred | Out-Null
                    $security = AZ:\setprinter.exe -Show \\$env:COMPUTERNAME\ 3
                    Remove-PSDrive -Name AZ | Out-Null
                    ([Regex]::matches($security,"S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}-\d{1,10}") | Sort-Object -Unique).Value
                } -ArgumentList $cred
                (Get-ADGroup -Filter {SID -eq $SID}).Name
            }
        }#>
        "VM Memory Shares" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VM.VMResourceConfiguration.MemSharesLevel}}
        "VM Memory Hot Add" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VMView.Config.MemoryHotAddEnabled}}
        "VM CPU Shares" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VM.VMResourceConfiguration.CPUSharesLevel}}
        "VM CPU Hot Add" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VMView.Config.CPUHotAddEnabled}}
        "VM Adapter Direct Path" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VMNIC.ExtensionData.UptCompatibilityEnabled}}
        "VM Encryption" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {$VMView.Config.MigrateEncryption}}
        "DNS Settings" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String[]](Invoke-Command -Session $PSSession -ScriptBlock {(Get-DNSClientServerAddress | Where-Object {$_.ServerAddresses -ne $null -AND $_.AddressFamily -eq "2"}).ServerAddresses})}}
        "IPv4 Manual" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"}).PrefixOrigin})}}
        "IPv4 IP" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String[]](Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"}).IPAddress})}}
        "IPv6 Enabled" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[Boolean](Invoke-Command -Session $PSSession -ScriptBlock {(Get-NetIPAddress | Where-Object {$_.IPAddress -ne "127.0.0.1" -AND $_.AddressFamily -eq "2"} | ForEach-Object {Get-NetAdapterBinding -Name $_.InterfaceAlias -ComponentID ms_tcpip6}).Enabled})}}
        "SCOM Registries" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String[]](Invoke-Command -Session $PSSession -ScriptBlock {(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Syncreon" -Name "MainGroup"); (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Syncreon" -Name "SiteCode")})}}
        "SCOM Agent" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {[String](Invoke-Command -Session $PSSession -ScriptBlock {(Get-Service -Name "HealthService").Status})}}
        "TaniumPXE" = {}
        "RDP Licensing" = {Get-QualityCheckResult -check $check -step $step -Expected $checkDefaults.$check -Actual {Invoke-Command -Session $PSSession -ScriptBlock {[Int](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core").LicensingMode}}}
    }

    # Run through each assigned check
    foreach($check in $checks){($checkActions.ContainsKey($check)) ? ($dataStructure.setting += $checkActions[$check].Invoke()) : ($dataStructure.setting += [PSCustomObject]@{
                "MISSING SWITCH CASE" = @{
                    expected = $check
                    actual = 'FROM $checks ARRAY'
                }
            }
        )
    }

    $Session:QCProgress = @{Step = "Saving to database..."; Percent = 100}; Sync-UDElement -ID "QCProgress"
    try{
        $dataStructure | Add-MdbcData
    }
    catch{
        Show-UDToast -Message "Unable to write data to collection $DATABASE_COLLECTION_QC_SERVER in database $DATABASE_NAME : $($_.Exception.Message)" -Duration $ERROR_TOAST_DURATION
        throw
    }

    $Session:QCProgress = @{Step = "Checks for $serverName are completed"; Percent = 100}; Sync-UDElement -ID "QCProgress"

    Remove-PSSession -Session $PSSession
    Remove-CimSession -CimSession $CimSession
}

function Connect-VCenterServer {
    param(
        [Parameter(Mandatory=$false)][PSCredential]$cred
    )
    foreach($vCenterServer in $VCENTER_SERVERS){
        if($cred){
            try{
                if($DefaultVIServers.Name -notcontains $vCenterServer){
                    Set-PowerCLIConfiguration -Scope User -ParticipateInCeip $false -InvalidCertificateAction Ignore -ProxyPolicy NoProxy -DefaultVIServerMode Multiple -Confirm:$false -Credential $cred | Out-Null
                    Connect-VIServer -Server $vCenterServer -Force -WarningAction SilentlyContinue | Out-Null
                }
            }
            catch{
                Show-UDToast -Message "Unable to login to $vCenterServer : $($_.Exception.Message)" -Duration $WARNING_TOAST_DURATION
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
                Show-UDToast -Message "Unable to login to $vCenterServer : $($_.Exception.Message)" -Duration $WARNING_TOAST_DURATION
                Disconnect-VIServer -Server * -Confirm:$false
            }
        }
    }
}

function Get-QualityCheckServerTable {
    param(
        [Parameter(Mandatory)][String]$ID
    )
    switch($ID){
        "QCServerSelectTable"{
            try{
                Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER
                # Get data from newest to oldest
                $QCServerResultSelect = Get-MdbcData -Sort @{report_date = -1} | ForEach-Object {
                    [PSCustomObject]@{
                        qc_server_result_select__id = $_._id
                        qc_server_result_select_server_name = $_.server_name
                        qc_server_result_select_report_date = $_.report_date
                        qc_server_result_select_server_type = $_.server_type
                        qc_server_result_select_caller = $_.caller
                    }
                }
            }
            catch{
                Show-UDToast -Message "Unable to load data for $ID : $($_.Exception.Message)" -Duration $ERROR_TOAST_DURATION
                throw
            }

            New-UDTable -Data $QCServerResultSelect -Title "Reports from database" -ShowSearch -Paging -PageSize 10 -Columns @(
                New-UDTableColumn -Property "qc_server_result_select__id" -Title "ID" -Render {
                    New-UDButton -Text $EventData.qc_server_result_select__id -OnClick {
                        Show-UDToast -Message "Loading report ID: $($EventData.qc_server_result_select__id)" -Duration $INFORMATION_TOAST_DURATION
                        $Session:qc_server_result_select__id = $EventData.qc_server_result_select__id
                        $Session:qc_server_result_select_server_name = $EventData.qc_server_result_select_server_name
                        Sync-UDElement -ID "QCServerResultTable"
                    } -Variant "text"
                }
                New-UDTableColumn -Property "qc_server_result_select_server_name" -Title "Server Name" -IncludeInSearch
                New-UDTableColumn -Property "qc_server_result_select_report_date" -Title "Report Date (UTC+00:00)"
                New-UDTableCOlumn -Property "qc_server_result_select_server_type" -Title "Server Type"
                New-UDTableColumn -Property "qc_server_result_select_caller" -Title "Caller" -IncludeInSearch
            )
        }
        "QCServerResultTable"{
            try{
                Connect-Mdbc -ConnectionString $Secret:MONGO_DB -DatabaseName $DATABASE_NAME -CollectionName $DATABASE_COLLECTION_QC_SERVER
                # Flatten the rows
                $QCServerResultData = Get-MdbcData | Where-Object {$_._id -eq $Session:qc_server_result_select__id} | ForEach-Object {
                    foreach($setting in $_.setting){
                        $key = $setting.Keys | Select-Object -First 1
                        $val = $setting[$key]
                        [PSCustomObject]@{
                            Setting = $key
                            Expected = $val.expected
                            Actual = $val.actual
                        }
                    }
                }
            }
            catch{
                Show-UDToast -Message "Unable to load data for $ID : $($_.Exception.Message)" -Duration $ERROR_TOAST_DURATION
                throw
            }

            New-UDTable -Data $QCServerResultData -Title $Session:qc_server_result_select_server_name -Columns @(
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

$page = New-UDPage -Name "QC Server" -Url "/" -Content {
    New-UDCard -Title "QC Server" -Content {
        New-UDDynamic -ID "QCProgress" -Content {
            New-UDTypography -Text $Session:QCProgress.Step
            New-UDProgress -PercentComplete $Session:QCProgress.Percent
        }

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

        New-UDGrid -Container -Spacing 3 -Content {
            New-UDGrid -Item -Content {
                New-UDUpload -Text "Import File" -OnUpload {
                    $Session:Import = Import-CSV $Body.FileName -Delimiter ";"
                    ($Session:Import) ? (Show-UDToast -Message "Import successful" -Duration $INFORMATION_TOAST_DURATION) : (Show-UDToast -Message "Import failed" -Duration $WARNING_TOAST_DURATION)
                }
            }
            New-UDGrid -Item -Content {
                New-UDButton -Text "Start server check" -OnClick {
                    Submit-ServerQualityCheck
                }
            }
        }

        New-UDDynamic -ID "QCServerSelectTable" -Content {
            Get-QualityCheckServerTable -ID "QCServerSelectTable"
        }

        New-UDDynamic -ID "QCServerResultTable" -Content {
            (-NOT([String]::IsNullOrEmpty($Session:qc_server_result_select__id))) ? (Get-QualityCheckServerTable -ID "QCServerResultTable") : (New-UDTypography -Text "Select a report to view results")
        }
    }
}

New-UDApp -Title "QC Server" -Pages $page

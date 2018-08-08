<# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

#region Functions

    function WriteInfo($message){
        Write-Host $message
    }

    function WriteInfoHighlighted($message){
        Write-Host $message -ForegroundColor Cyan
    }

    function WriteSuccess($message){
        Write-Host $message -ForegroundColor Green
    }

    function WriteError($message){
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        Stop-Transcript
        $exit=Read-Host
        Exit
    }
#>
Import-Module "$PSScriptRoot\Functions\WSLabFunctions.psd1" -Force

$IsAdmin = Test-Administrator

If (!($IsAdmin))
{
     Set-Administrator $PSCommandPath (Get-Location).Path
     Exit
}


#region Initializtion
    Function CreateUnattendFileBlob{
        #Create Unattend (parameter is Blob)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Blob,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous
        )

        if ( Test-Path "Unattend.xml" ) {
        Remove-Item .\Unattend.xml
        }
        $unattendFile = New-Item "Unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>
           <Provisioning>
             <AccountData>$Blob</AccountData>
           </Provisioning>
         </OfflineIdentification>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
       <HideEULAPage>true</HideEULAPage>
       <SkipMachineOOBE>true</SkipMachineOOBE> 
       <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>PFE</RegisteredOwner>
      <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>   
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function CreateUnattendFileNoDjoin{
        #Create Unattend(without domain join)    
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$false)]
            [string]
            $AdditionalAccount
        )

            if ( Test-Path "Unattend.xml" ) {
            Remove-Item .\Unattend.xml
            }
            $unattendFile = New-Item "Unattend.xml" -type File
            $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
          <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        $AdditionalAccount
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function CreateUnattendFileWin2012{
        #Create Unattend(traditional Djoin with username/pass)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$true)]
            [string]
            $DomainName
        )
        if ( Test-Path "Unattend.xml" ) {
            Remove-Item .\Unattend.xml
        }
        $unattendFile = New-Item "Unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Identification>
                <Credentials>
                    <Domain>$DomainName</Domain>
                    <Password>$AdminPassword</Password>
                    <Username>Administrator</Username>
                </Credentials>
                <JoinDomain>$DomainName</JoinDomain>
        </Identification>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile 
    }

    Function AdditionalLocalAccountXML{
        #Creates Additional local account unattend piece
        param (
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $AdditionalAdminName
        )
@"
<LocalAccounts>
    <LocalAccount wcm:action="add">
        <Password>
            <Value>$AdminPassword</Value>
            <PlainText>true</PlainText>
        </Password>
        <Description>$AdditionalAdminName admin account</Description>
        <DisplayName>$AdditionalAdminName</DisplayName>
        <Group>Administrators</Group>
        <Name>$AdditionalAdminName</Name>
    </LocalAccount>
</LocalAccounts>
"@
    }

    function  Get-WindowsBuildNumber { 
        $os = Get-WmiObject -Class Win32_OperatingSystem 
        return [int]($os.BuildNumber) 
    } 

    Function Set-VMNetworkConfiguration {
        #source:http://www.ravichaganti.com/blog/?p=2766 with some changes
        #example use: Get-VMNetworkAdapter -VMName Demo-VM-1 -Name iSCSINet | Set-VMNetworkConfiguration -IPAddress 192.168.100.1 00 -Subnet 255.255.0.0 -DNSServer 192.168.100.101 -DefaultGateway 192.168.100.1
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='DHCP',
                    ValueFromPipeline=$true)]
            [Parameter(Mandatory=$true,
                    Position=0,
                    ParameterSetName='Static',
                    ValueFromPipeline=$true)]
            [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,

            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='Static')]
            [String[]]$IPAddress=@(),

            [Parameter(Mandatory=$false,
                    Position=2,
                    ParameterSetName='Static')]
            [String[]]$Subnet=@(),

            [Parameter(Mandatory=$false,
                    Position=3,
                    ParameterSetName='Static')]
            [String[]]$DefaultGateway = @(),

            [Parameter(Mandatory=$false,
                    Position=4,
                    ParameterSetName='Static')]
            [String[]]$DNSServer = @(),

            [Parameter(Mandatory=$false,
                    Position=0,
                    ParameterSetName='DHCP')]
            [Switch]$Dhcp
        )

        $VM = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $NetworkAdapter.VMName } 
        $VMSettings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }    
        $VMNetAdapters = $VMSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData') 

        $NetworkSettings = @()
        foreach ($NetAdapter in $VMNetAdapters) {
            if ($NetAdapter.elementname -eq $NetworkAdapter.name) {
                $NetworkSettings = $NetworkSettings + $NetAdapter.GetRelated("Msvm_GuestNetworkAdapterConfiguration")
            }
        }

        $NetworkSettings[0].IPAddresses = $IPAddress
        $NetworkSettings[0].Subnets = $Subnet
        $NetworkSettings[0].DefaultGateways = $DefaultGateway
        $NetworkSettings[0].DNSServers = $DNSServer
        $NetworkSettings[0].ProtocolIFType = 4096

        if ($dhcp) {
            $NetworkSettings[0].DHCPEnabled = $true
        } else {
            $NetworkSettings[0].DHCPEnabled = $false
        }

        $Service = Get-WmiObject -Class "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
        $setIP = $Service.SetGuestNetworkAdapterConfiguration($VM, $NetworkSettings[0].GetText(1))

        if ($setip.ReturnValue -eq 4096) {
            $job=[WMI]$setip.job 
            while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
                start-sleep 1
                $job=[WMI]$setip.job
            }
            if ($job.JobState -eq 7) {
                Write-InfoHighlightedMessage "`t Success"
            }else {
            $job.GetError()
            }
        }elseif($setip.ReturnValue -eq 0) {
            Write-InfoHighlightedMessage "`t Success"
        }
    }

    function WrapProcess{
        #Using this function you can run legacy program and search in output string 
        #Example: WrapProcess -filename fltmc.exe -arguments "attach svhdxflt e:" -outputstring "Success"
        [CmdletBinding()]
        [Alias()]
        [OutputType([bool])]
        Param (
            # process name. For example fltmc.exe
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
            $filename,

            # arguments. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $arguments,

            # string to search. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $outputstring
        )
        Process {
            $procinfo = New-Object System.Diagnostics.ProcessStartInfo
            $procinfo.FileName = $filename
            $procinfo.Arguments = $arguments
            $procinfo.UseShellExecute = $false
            $procinfo.CreateNoWindow = $true
            $procinfo.RedirectStandardOutput = $true
            $procinfo.RedirectStandardError = $true


            # Create a process object using the startup info
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $procinfo
            # Start the process
            $process.Start() | Out-Null

            # test if process is still running
            if(!$process.HasExited){
                do{
                   Start-Sleep 1 
                }until ($process.HasExited -eq $true)
            }

            # get output 
            $out = $process.StandardOutput.ReadToEnd()

            if ($out.Contains($outputstring)) {
                $output=$true
            } else {
                $output=$false
            }
            return, $output
        }
    }

    Function BuildVM {
        [cmdletbinding()]
        param(
            [PSObject]$VMConfig,
            [PSObject]$LabConfig,
            [string]$LabFolder
        )
        Write-InfoHighlightedMessage "Creating VM $($VMConfig.VMName)"
        Write-InfoMessage "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $VMConfig.ParentVHD
            
        if ($serverparent -eq $null){
            Write-ErrorMessageAndExit "Server parent disk $($VMConfig.ParentVHD) not found"
        }else{
            Write-InfoMessage "`t`t Server parent disk $($serverparent.Name) found"
        }
                    
        $VMname=$Labconfig.Prefix+$VMConfig.VMName
        if ($serverparent.Extension -eq ".vhdx"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhdx"
        }elseif($serverparent.Extension -eq ".vhd"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhd"
        }
        Write-InfoMessage "`t Creating OS VHD"
        New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
        Write-InfoMessage "`t Creating VM"
        if ($VMConfig.Generation -eq 1){
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 1
        }else{
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 2    
        }
        $VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
        $VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
        if ($VMTemp.AutomaticCheckpointsEnabled -eq $True){
            $VMTemp | Set-VM -AutomaticCheckpointsEnabled $False
        }

        $MGMTNICs=$VMConfig.MGMTNICs
        If($MGMTNICs -eq $null){
            $MGMTNICs = 2
        }

        If($MGMTNICs -gt 8){
            $MGMTNICs=8
        }

        If($MGMTNICs -ge 2){
            2..$MGMTNICs | ForEach-Object {
                Write-InfoMessage "`t Adding Network Adapter Management$_"
                $VMTemp | Add-VMNetworkAdapter -Name "Management$_"
            }
        }
        Write-InfoMessage "`t Connecting vNIC to $switchname"
        $VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        if ($LabConfig.Secureboot -eq $False) {
            Write-InfoMessage "`t Disabling Secureboot"
            $VMTemp | Set-VMFirmware -EnableSecureBoot Off
        }

        if ($VMConfig.AdditionalNetworks -eq $True){
            Write-InfoHighlightedMessage "`t Configuring Additional networks"
            foreach ($AdditionalNetworkConfig in $Labconfig.AdditionalNetworksConfig){
                Write-InfoMessage "`t Adding Adapter $($AdditionalNetworkConfig.NetName) with IP $($AdditionalNetworkConfig.NetAddress)$global:IP"
                $VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $AdditionalNetworkConfig.NetName
                $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName  | Set-VMNetworkConfiguration -IPAddress "$($AdditionalNetworkConfig.NetAddress)$global:IP" -Subnet $AdditionalNetworkConfig.Subnet
                if($AdditionalNetworkConfig.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName | Set-VMNetworkAdapterVlan -VlanId $AdditionalNetworkConfig.NetVLAN -Access }
            }
            $global:IP++
        }

        #Generate DSC Config
        if ($VMConfig.DSCMode -eq 'Pull'){
            Write-InfoMessage "`t Setting DSC Mode to Pull"
            PullClientConfig -ComputerName $VMConfig.VMName -DSCConfig $VMConfig.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
        }

        #configure nested virt
        if ($VMConfig.NestedVirt -eq $True){
            Write-InfoMessage "`t Enabling NestedVirt"
            $VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $False
        }

        #configure vTPM
        if ($VMConfig.vTPM -eq $True){
            if ($VMConfig.Generation -eq 1){
                WriteError "`t vTPM requested. But vTPM is not compatible with Generation 1"
            }else{
                Write-InfoMessage "`t Enabling vTPM"
                $keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
                Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
                Enable-VMTPM -VM $VMTemp
            }
        }

        #set MemoryMinimumBytes
        if ($VMConfig.MemoryMinimumBytes -ne $null){
            Write-InfoMessage "`t Configuring MemoryMinimumBytes to $($VMConfig.MemoryMinimumBytes/1MB)MB"
            if ($VMConfig.NestedVirt){
                "`t `t Skipping! NestedVirt configured"
            }else{
                Set-VM -VM $VMTemp -MemoryMinimumBytes $VMConfig.MemoryMinimumBytes
            }
        }

        #Set static Memory
        if ($VMConfig.StaticMemory -eq $true){
            Write-InfoMessage "`t Configuring StaticMemory"
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
        }

        #configure number of processors
        if ($VMConfig.VMProcessorCount){
            Write-InfoMessage "`t Configuring VM Processor Count to $($VMConfig.VMProcessorCount)"
            if ($VMConfig.VMProcessorCount -le $NumberOfLogicalProcessors){
                $VMTemp | Set-VMProcessor -Count $VMConfig.VMProcessorCount
            }else{
                WriteError "`t `t Number of processors specified in VMProcessorCount is greater than Logical Processors available in Host!"
                Write-InfoMessage  "`t `t Number of logical Processors in Host $NumberOfLogicalProcessors"
                Write-InfoMessage  "`t `t Number of Processors provided in labconfig $($VMConfig.VMProcessorCount)"
                Write-InfoMessage  "`t `t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                $VMTemp | Set-VMProcessor -Count $NumberOfLogicalProcessors
            }
        }else{
            $VMTemp | Set-VMProcessor -Count 2
        }

        $Name=$VMConfig.VMName
        #add run synchronous commands
        Write-InfoHighlightedMessage "`t Adding Sync Commands"
        $RunSynchronous=""
        if ($VMConfig.EnableWinRM){
            $RunSynchronous+=@'
            <RunSynchronousCommand wcm:action="add">
                <Path>cmd.exe /c winrm quickconfig -q -force</Path>
                <Description>enable winrm</Description>
                <Order>1</Order>
            </RunSynchronousCommand>

'@
            Write-InfoMessage "`t `t WinRM will be enabled"
        }

        if ($VMConfig.DisableWCF){
            $RunSynchronous+=@'
            <RunSynchronousCommand wcm:action="add">
                <Path>reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f</Path>
                <Description>disable consumer features</Description>
                <Order>2</Order>
            </RunSynchronousCommand>

'@
            Write-InfoMessage "`t `t WCF will be disabled"
        }
        if ($VMConfig.CustomPowerShellCommands){
            $Order=3
            foreach ($CustomPowerShellCommand in $VMConfig.CustomPowerShellCommands){
                $RunSynchronous+=@"
                <RunSynchronousCommand wcm:action="add">
                    <Path>powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "$CustomPowerShellCommand"</Path>
                    <Description>run custom powershell</Description>
                    <Order>$Order</Order>
                </RunSynchronousCommand>

"@
                $Order++
            }
            Write-InfoMessage "`t `t Custom PowerShell command will be added"
        }

        if (-not $RunSynchronous){
            Write-InfoMessage "`t `t No sync commands requested"
        }

        #Create Unattend file
        if ($VMConfig.Unattend -eq "NoDjoin" -or $VMConfig.SkipDjoin){
            Write-InfoMessage "`t Skipping Djoin"
            if ($VMConfig.AdditionalLocalAdmin){
                Write-InfoMessage "`t Additional Local Admin $($VMConfig.AdditionalLocalAdmin) will added"
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -AdditionalAccount $AdditionalLocalAccountXML -TimeZone $TimeZone
            }else{
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
            }
        }elseif($VMConfig.Win2012Djoin -or $VMConfig.Unattend -eq "DjoinCred"){
            Write-InfoMessage "`t Creating Unattend with win2012-ish domain join"
            $unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName -RunSynchronous $RunSynchronous -TimeZone $TimeZone

        }elseif($VMConfig.Unattend -eq "DjoinBlob" -or -not ($VMConfig.Unattend)){
            Write-InfoMessage "`t Creating Unattend with djoin blob"
            $path="c:\$vmname.txt"
            Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
            $blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
            $unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
        }elseif($VMConfig.Unattend -eq "None"){
            $unattendFile=$Null
        }

        #adding unattend to VHD
        if ($unattendFile){
            Write-InfoMessage "`t Adding unattend to VHD"
            Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
            Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
            #&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\Mountdir
            #&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\Mountdir /Apply-Unattend:$unattendfile
            New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
            Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
        }

        if ($VMConfig.DSCMode -eq 'Pull'){
            Write-InfoMessage "`t Adding metaconfig.mof to VHD"
            Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$PSScriptRoot\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
        }

        if ($unattendFile){
            Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
            #&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\Mountdir /Commit
        }

        #add toolsdisk
        if ($VMConfig.AddToolsVHD -eq $True){
            $VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\tools.vhdx"
            Write-InfoHighlightedMessage "`t Adding Virtual Hard Disk $($VHD.Path)"
            $VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
        }
    }
#endregion

#region Initialization

    Start-Transcript -Path "$PSScriptRoot\Deploy.log"

    $StartDateTime = get-date
    Write-InfoHighlightedMessage "Script started at $StartDateTime"


    ##Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

#endregion

#region Set variables

    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

    If (!$LabConfig.DefaultOUName){
        $LabConfig.DefaultOUName="Workshop"
    }

    $DN=$null
    $LabConfig.DomainName.Split(".") | ForEach-Object {
        $DN+="DC=$_,"
    }
    $LabConfig.DN=$DN.TrimEnd(",")

    $global:IP=1

    Write-InfoHighlightedMessage "List of variables used"
    Write-InfoMessage "`t Prefix used in lab is $($labconfig.prefix)"

    $SwitchName=($labconfig.prefix+$LabConfig.SwitchName)
    Write-InfoMessage "`t Switchname is $SwitchName" 

    Write-InfoMessage "`t Workdir is $PSScriptRoot"

    $LABfolder="$PSScriptRoot\LAB"
    Write-InfoMessage "`t LabFolder is $LabFolder"

    $LABfolderDrivePath=$LABfolder.Substring(0,3)

    $ExternalSwitchName="$($Labconfig.Prefix)$($LabConfig.Switchname)-External"

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab number of processors
    (get-wmiobject win32_processor).NumberOfLogicalProcessors  | ForEach-Object { $global:NumberOfLogicalProcessors += $_}

#endregion

#region Some Additional checks and prereqs configuration

    #checking if Prefix is not empty
        if (!$LabConfig.Prefix){
            Write-ErrorMessageAndExit "`t Prefix is empty. Exiting"
        }

    # Checking for Compatible OS
        Write-InfoHighlightedMessage "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"
        $BuildNumber=Get-WindowsBuildNumber
        if ($BuildNumber -ge 10586){
            Write-SuccessMessage "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
        }else{
            Write-ErrorMessageAndExit "`t Windows 10/ Server 2016 not detected. Exiting"
        }

    # Checking for NestedVirt
        if ($LABConfig.VMs.NestedVirt -contains $True){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                Write-SuccessMessage "`t Windows is build greater than 14393. NestedVirt will work"
            }else{
                Write-ErrorMessageAndExit "`t Windows build older than 14393 detected. NestedVirt will not work. Exiting"
            }
        }

    # Checking for vTPM support
        if ($LABConfig.VMs.vTPM -contains $true){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                Write-SuccessMessage "`t Windows is build greater than 14393. vTPM will work"
            }else{
                Write-ErrorMessageAndExit "`t Windows build older than 14393 detected. vTPM will not work Exiting"
            }
            <# Not needed anymore as VBS is automatically enabled since 14393 when vTPM is used
            if (((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus -ne 0) -and ((Get-Process "secure system") -ne $null )){
                Write-SuccessMessage "`t Virtualization Based Security is running. vTPM can be enabled"
            }else{
                Write-ErrorMessageAndExit "`t Virtualization based security is not running. Enable VBS, or remove vTPM from configuration"
            }
            #>
            #load Guardian
            $guardian=Get-HgsGuardian | Select-Object -first 1
            if($guardian -eq $null){
                $guardian=New-HgsGuardian -Name LabGuardian -GenerateCertificates
                Write-InfoMessage "`t HGS with name LabGuardian created"
            }
        }

    #Check support for shared disks + enable if possible
        if ($LABConfig.VMs.Configuration -contains "Shared" -or $LABConfig.VMs.Configuration -contains "Replica"){
            Write-InfoHighlightedMessage "Configuration contains Shared or Replica scenario"

            Write-InfoMessage "Checking support for shared disks"
            $OS=Get-WmiObject win32_operatingsystem
            if (($OS.caption -like "*Server*") -and $OS.version -gt 10){
                Write-InfoMessage "`t Installing Failover Clustering Feature"
                $FC=Install-WindowsFeature Failover-Clustering
                If ($FC.Success -eq $True){
                    Write-SuccessMessage "`t`t Failover Clustering Feature installed with exit code: $($FC.ExitCode)" 
                }else{
                    WriteError "`t`t Failover Clustering Feature was not installed with exit code: $($FC.ExitCode)"
                }
            }

            Write-InfoHighlightedMessage "`t Attaching svhdxflt filter driver to drive $LABfolderDrivePath"
            if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "successful"){
                Write-SuccessMessage "`t Svhdx filter driver was successfully attached"
            }else{
                if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "0x801f0012"){
                    Write-SuccessMessage "`t Svhdx filter driver was already attached"
                }else{
                    Write-ErrorMessageAndExit "`t unable to load svhdx filter driver. Exiting Please use Server SKU or figure out how to install svhdx into the client SKU"
                }
            }

            Write-InfoHighlightedMessage "Adding svhdxflt to registry for autostart"    
            if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters)){
                New-Item HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters
            }   
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters -Name AutoAttachOnNonCSVVolumes -PropertyType DWORD -Value 1 -force
        }

    #Check if Hyper-V is installed
        Write-InfoHighlightedMessage "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            Write-SuccessMessage "`t Hyper-V is Installed"
        }else{
            Write-ErrorMessageAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        Write-InfoHighlightedMessage "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            Write-SuccessMessage "`t Hyper-V is Installed"
        }else{
            Write-ErrorMessageAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #enable EnableEnhancedSessionMode if not enabled
    if (-not (Get-VMHost).EnableEnhancedSessionMode){
        Write-InfoHighlightedMessage "Enhanced session mode was disabled. Enabling."
        Set-VMHost -EnableEnhancedSessionMode $true
    }

    #Create Switches

        Write-InfoHighlightedMessage "Creating Switch"
        Write-InfoMessage "`t Checking if $SwitchName already exists..."

        if ((Get-VMSwitch -Name $SwitchName -ErrorAction Ignore) -eq $Null){ 
            Write-InfoMessage "`t Creating $SwitchName..."
            New-VMSwitch -SwitchType Private -Name $SwitchName
        }else{
            $SwitchNameExists=$True
            Write-InfoHighlightedMessage "`t $SwitchName exists. Looks like lab with same prefix exists. "
        }

    #connect lab to internet if specified in labconfig
        if ($Labconfig.Internet){
            Write-InfoHighlightedMessage "Internet connectivity requested"

            if (!$LabConfig.CustomDnsForwarders){
                $LabConfig.CustomDnsForwarders=@("8.8.8.8","1.1.1.1") # Google DNS, Cloudfare
            }

            Write-InfoMessage "`t Detecting default vSwitch"
            $DefaultSwitch=Get-VMSwitch -Name "Default Switch" -ErrorAction Ignore
            if (-not $DefaultSwitch){
                Write-InfoMessage "`t Default switch not present, detecting external vSwitch $ExternalSwitchName"
                $ExternalSwitch=Get-VMSwitch -SwitchType External -Name $ExternalSwitchName -ErrorAction Ignore
                if ($ExternalSwitch){
                    Write-SuccessMessage "`t External vSwitch  $ExternalSwitchName detected"
                }else{
                    Write-InfoMessage "`t Detecting external VMSwitch"
                    $ExtSwitch=Get-VMSwitch -SwitchType External
                    if (!$ExtSwitch){
                        Write-InfoHighlightedMessage "`t No External Switch detected. Will create one "
                        $TempNetAdapters=get-netadapter | Where-Object Name -NotLike vEthernet* | Where-Object status -eq up
                        if (!$TempNetAdapters){
                            Write-ErrorMessageAndExit "No Adapters with Status -eq UP detected. Exiting"
                        }
                        if ($TempNetAdapters.name.count -eq 1){
                            Write-InfoMessage "`t Just one connected NIC detected ($($TempNetAdapters.name)). Will create vSwitch connected to it"
                            $ExternalSwitch=New-VMSwitch -NetAdapterName $TempNetAdapters.name -Name $ExternalSwitchName -AllowManagementOS $true
                        }
                        if ($TempNetAdapters.name.count -gt 1){
                            Write-InfoMessage "`t More than 1 NIC detected"
                            Write-InfoHighlightedMessage "`t Please select NetAdapter you want to use for vSwitch"
                            $tempNetAdapter=get-netadapter | Where-Object Name -NotLike vEthernet* | Where-Object status -eq up | Out-GridView -OutputMode Single -Title "Please select adapter you want to use for External vSwitch" 
                            if (!$tempNetAdapter){
                                Write-ErrorMessageAndExit "You did not select any net adapter. Exiting."
                            }
                            $ExternalSwitch=New-VMSwitch -NetAdapterName $tempNetAdapter.name -Name $ExternalSwitchName -AllowManagementOS $true
                        }
                    }
                    if ($ExtSwitch.count -eq 1){
                        Write-SuccessMessage "`t External vswitch $($ExtSwitch.name) found. Will be used for connecting lab to internet"
                        $ExternalSwitch=$ExtSwitch
                    }
                    if ($ExtSwitch.count -gt 1){
                        Write-InfoHighlightedMessage "`t More than 1 External Switch found. Please chose what switch you want to use for internet connectivity"
                        $ExternalSwitch=Get-VMSwitch -SwitchType External | Out-GridView -OutputMode Single -Title 'Please Select External Switch you want to use for Internet Connectivity'
                    }
                }
            }
        }

    #Testing if lab already exists.
        Write-InfoMessage "Testing if lab already exists."
        if ($SwitchNameExists){
            if ((Get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue) -ne $null){
                $LABExists=$True
                Write-InfoHighlightedMessage "`t Lab already exists. If labconfig contains additional VMs, they will be added."
            }
        }

    #If lab exists, correct starting IP will be calculated
        if (($LABExists) -and ($labconfig.AdditionalNetworksInDC)) {
            $global:IP++
        }

        $Labconfig.VMs | ForEach-Object {
            if (((Get-VM -Name ($labconfig.prefix+$_.vmname) -ErrorAction SilentlyContinue) -ne $null) -and ($_.AdditionalNetworks -eq $True)){
                $global:IP++
            }
        }

        Write-InfoMessage "Starting IP for AdditionalNetworks is $global:IP"

    #Create Mount nd VMs directories
        Write-InfoHighlightedMessage "Creating Mountdir"
        New-Item "$PSScriptRoot\Temp\MountDir" -ItemType Directory -Force

        Write-InfoHighlightedMessage "Creating VMs dir"
        New-Item "$PSScriptRoot\LAB\VMs" -ItemType Directory -Force

    #get path for Tools disk
        Write-InfoHighlightedMessage "Looking for Tools Parent Disks"
        $toolsparent=Get-ChildItem "$PSScriptRoot\ParentDisks" -Recurse | Where-Object name -eq tools.vhdx
        if ($toolsparent -eq $null){
            Write-ErrorMessageAndExit "`t Tools parent disk not found"
        }else{
            Write-InfoMessage "`t Tools parent disk $($toolsparent.fullname) found"
        }

#endregion

#region Import DC (if not already present) or just grab it and start

    if (!(get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue)){
        #import DC
            Write-InfoHighlightedMessage "Looking for DC to be imported"
            get-childitem $LABFolder -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
                $DC=Import-VM -Path $_.FullName
                if ($DC -eq $null){
                    Write-ErrorMessageAndExit "DC was not imported successfully Press any key to continue ..."
                }
            }
            Write-InfoMessage "`t Virtual Machine $($DC.name) located in folder $($DC.Path) imported"

        #create checkpoint to be able to return to consistent state when cleaned with cleanup.ps1
            $DC | Checkpoint-VM -SnapshotName Initial
            Write-InfoMessage "`t Virtual Machine $($DC.name) checkpoint created"
            Start-Sleep -Seconds 5

        #rename network adapters and add another
            Write-InfoMessage "`t Configuring Network"

            $DC | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
            If($labconfig.MGMTNICsInDC -gt 8){
                $labconfig.MGMTNICsInDC=8
            }

            If($labconfig.MGMTNICsInDC -ge 2){
                2..$labconfig.MGMTNICsInDC | ForEach-Object {
                    Write-InfoMessage "`t Adding Network Adapter Management$_"
                    $DC | Add-VMNetworkAdapter -Name Management$_
                }
            }

            $DC | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        #add aditional networks
            if ($labconfig.AdditionalNetworksInDC -eq $True){
                Write-InfoHighlightedMessage "`t Configuring Additional networks"
                foreach ($AdditionalNetworkConfig in $Labconfig.AdditionalNetworksConfig){
                    $DC | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $AdditionalNetworkConfig.NetName
                    Write-InfoMessage "`t Adding Adapter $($AdditionalNetworkConfig.NetName) with IP $($AdditionalNetworkConfig.NetAddress)$global:IP"
                    $DC | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName | Set-VMNetworkConfiguration -IPAddress "$($AdditionalNetworkConfig.NetAddress)$global:IP" -Subnet $AdditionalNetworkConfig.Subnet
                    if($AdditionalNetworkConfig.NetVLAN -ne 0){ 
                        $DC | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName  | Set-VMNetworkAdapterVlan -VlanId $AdditionalNetworkConfig.NetVLAN -Access
                    }
                }
                $global:IP++
            }

        #Enable VMNics device naming
            Write-InfoMessage "`t Enabling DC VMNics device naming"
            $DC | Set-VMNetworkAdapter -DeviceNaming On

        #add tools disk
            Write-InfoMessage "`t Adding Tools disk to DC machine"
            $VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LABFolder\VMs\ToolsDiskDC.vhdx"
            Write-InfoMessage "`t `t Adding Virtual Hard Disk $($VHD.Path)"
            $DC | Add-VMHardDiskDrive -Path $vhd.Path

        #modify number of CPUs
            if ($Labconfig.DCVMProcessorCount){
                Write-InfoMessage "`t Configuring VM Processor Count for DC VM to $($labconfig.DCVMProcessorCount)"
                If ($labconfig.DCVMProcessorCount -le $NumberOfLogicalProcessors){
                    $DC | Set-VMProcessor -Count $Labconfig.DCVMProcessorCount
                }else{
                    WriteError "`t `t Number of processors specified in DCVMProcessorCount is greater than Logical Processors available in Host!"
                    Write-InfoMessage "`t `t Number of logical Processors in Host $NumberOfLogicalProcessors"
                    Write-InfoMessage "`t `t Number of Processors provided in labconfig $($labconfig.DCVMProcessorCount)"
                    Write-InfoMessage "`t `t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                    $DC | Set-VMProcessor -Count $NumberOfLogicalProcessors
                }
            }

        #start DC
            Write-InfoMessage  "`t Starting Virtual Machine $($DC.name)"
            $DC | Start-VM

        #rename DC VM
            Write-InfoMessage "`t Renaming $($DC.name) to $($labconfig.Prefix+$DC.name)"
            $DC | Rename-VM -NewName ($labconfig.Prefix+$DC.name)
    }else{
        #if DC was present, just grab it
            $DC=get-vm -Name ($labconfig.prefix+"DC")
    }

    #Start DC if it is not running
    if ($DC.State -ne "Running"){
        Write-InfoMessage "DC was not started. Starting now..."
        $DC | Start-VM
    }

    #connect to internet
    if ($labconfig.internet){
        if (-not ($DC | Get-VMNetworkAdapter -Name Internet -ErrorAction SilentlyContinue)){
            Write-InfoMessage "`t `t Adding Network Adapter Internet"
            $DC | Add-VMNetworkAdapter -Name Internet -DeviceNaming On

            if ($DefaultSwitch){
                $internetSwitch = $DefaultSwitch
            }else{
                $internetSwitch = $ExternalSwitch
            }
            Write-InfoMessage "`t`t Connecting Network Adapter Internet to $($internetSwitch.Name)"
            $DC | Get-VMNetworkAdapter -Name Internet | Connect-VMNetworkAdapter -VMSwitch $internetSwitch
        }
    }

#endregion

#region Test DC to come up

    #Credentials for Session
        $username = "$($Labconfig.DomainNetbiosName)\Administrator"
        $password = $LabConfig.AdminPassword
        $secstr = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

    #wait for DC to start
        Write-InfoHighlightedMessage "Waiting for Active Directory on $($DC.name) to be Started."
        do{
            $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
                param($labconfig);
                Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue
            }
            Start-Sleep 5
        }until ($test -ne $Null)
        Write-SuccessMessage "Active Directory on $($DC.name) is up."

    #if DC was just created, configure additional settings with PowerShell direct
        if (!$LABExists){
            Write-InfoHighlightedMessage "Performing some actions against DC with powershell Direct"
            #make tools disk online
                Write-InfoMessage "`t Making tools disk online"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsReadOnly $false}
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsOffline $false}

            #authorize DHCP (if more networks added, then re-authorization is needed. Also if you add multiple networks once, it messes somehow even with parent VM for DC)
                Write-InfoMessage "`t Authorizing DHCP"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ScriptBlock {
                    param($labconfig);
                    Get-DhcpServerInDC | Remove-DHCPServerInDC
                    Add-DhcpServerInDC -DnsName "DC.$($Labconfig.DomainName)" -IPAddress 10.0.0.1
                }
        }

    #configure NAT on DC
        If ($labconfig.internet){
            $cmd=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {Get-WindowsFeature -Name Routing}
            if ($cmd.installed -eq $False){
                Write-InfoHighlightedMessage "`t Configuring NAT"
                Write-InfoMessage "`t `t Installing Routing and RSAT-RemoteAccess features"
                $cmd=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Install-WindowsFeature -Name Routing,RSAT-RemoteAccess -IncludeAllSubFeature -WarningAction Ignore
                }
                if ($cmd.restartneeded -eq "Yes"){
                    Write-InfoMessage "`t `t Restart of DC is requested"
                    Write-InfoMessage "`t `t Restarting DC"
                    $DC | Restart-VM -Force
                    Start-Sleep 10
                    Write-InfoHighlightedMessage "`t `t Waiting for Active Directory on $($DC.name) to be Started."
                    do{
                        $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
                            param($labconfig);
                            Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue
                        }
                        Start-Sleep 5
                    }until ($test -ne $Null)
                    Write-SuccessMessage "`t `t Active Directory on $($DC.name) is up."
                }

                $DNSServers=@()

                if(!$LabConfig.SkipHostDnsAsForwarder){
                    Write-InfoHighlightedMessage "`t Requesting DNS settings from Host"
                    if($internetSwitch.Name -eq "Default Switch"){
                        # Host's IP of Default Switch acts also as DNS resolver
                        $DNSServers+=(Get-HnsNetwork | Where-Object { $_.Name -eq "Default Switch" }).Subnets[0].GatewayAddress
                    }
                    else{
                        $vNICName=(Get-VMNetworkAdapter -ManagementOS -SwitchName $internetSwitch.Name).Name | Select-Object -First 1 #in case multiple adapters are in managementos
                        $DNSServers+=(Get-NetIPConfiguration -InterfaceAlias "vEthernet ($vNICName)").DNSServer.ServerAddresses #grab DNS IP from vNIC
                    }
                }

                $DNSServers+=$LabConfig.CustomDnsForwarders

                Write-InfoHighlightedMessage "`t Configuring NAT with netSH and starting services"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-Service -Name RemoteAccess -StartupType Automatic
                    Start-Service -Name RemoteAccess
                    netsh.exe routing ip nat install
                    netsh.exe routing ip nat add interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name
                    netsh.exe routing ip nat set interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name mode=full
                    netsh.exe ras set conf confstate = enabled
                    netsh.exe routing ip dnsproxy install
                    Write-Host "Restarting service RemoteAccess..."
                    Restart-Service -Name RemoteAccess -WarningAction SilentlyContinue
                    Add-DnsServerForwarder $Using:DNSServers
                }
            }
        }

#endregion

#region Provision VMs
    #DSC config for LCM (in case Pull configuration is specified)
        Write-InfoHighlightedMessage "Creating DSC config to configure DC as pull server"

        [DSCLocalConfigurationManager()]
        Configuration PullClientConfig 
        {
            param
                (
                    [Parameter(Mandatory=$true)]
                    [string[]]$ComputerName,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DSCConfig,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DomainName
                )
            Node $ComputerName {
                Settings{

                    AllowModuleOverwrite = $True
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Pull'
                    RebootNodeIfNeeded = $True
                    ActionAfterReboot = 'ContinueConfiguration'
                    }

                    ConfigurationRepositoryWeb PullServerWeb { 
                    ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
                    AllowUnsecureConnection = $true
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    ConfigurationNames = $DSCConfig
                    }

                    ReportServerWeb PullServerReports {
                    ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    }

                    $DSCConfig | ForEach-Object {
                        PartialConfiguration $_
                        {
                        RefreshMode = 'Pull'
                        ConfigurationSource = '[ConfigurationRepositoryWeb]PullServerWeb'
                        }
                    }
            }
        }

    #process $labconfig.VMs and create VMs (skip if machine already exists)
        Write-InfoHighlightedMessage 'Processing $LabConfig.VMs, creating VMs'
        foreach ($VMConfig in $LABConfig.VMs.GetEnumerator()){
            if (!(Get-VM -Name "$($labconfig.prefix)$($VMConfig.vmname)" -ErrorAction SilentlyContinue)){
                #create VM with Shared configuration
                    if ($VMConfig.configuration -eq 'Shared'){
                        #create disks (if not already created)
                            $VMSet=$VMConfig.VMSet
                            if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
                                $SharedSSDs=$null
                                $SharedHDDs=$null
                                If (($VMConfig.SSDNumber -ge 1) -and ($VMConfig.SSDNumber -ne $null)){  
                                    $SharedSSDs= 1..$VMConfig.ssdnumber | ForEach-Object {New-vhd -Path "$LABfolder\VMs\SharedSSD-$VMSet-$_.VHDS" -Dynamic -Size $VMConfig.SSDSize}
                                    $SharedSSDs | ForEach-Object {Write-InfoMessage "`t Disk SSD $($_.path) size $($_.size /1GB)GB created"}
                                }
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)){  
                                    $SharedHDDs= 1..$VMConfig.hddnumber | ForEach-Object {New-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-$_.VHDS" -Dynamic -Size $VMConfig.HDDSize}
                                    $SharedHDDs | ForEach-Object {Write-InfoMessage "`t Disk HDD $($_.path) size $($_.size /1GB)GB created"}
                                }
                            }else{
                                $SharedSSDs=Get-VHD -Path "$LABfolder\VMs\SharedSSD-$VMSet-*.VHDS" -ErrorAction SilentlyContinue
                                $SharedHDDs=Get-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-*.VHDS" -ErrorAction SilentlyContinue
                            }
                        #Build VM
                            BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder
                        #Compose VMName
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName
                        #Add disks
                            Write-InfoHighlightedMessage "`t Attaching Shared Disks to $VMname"
                            $SharedSSDs | ForEach-Object {
                                $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
                                Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                            }
                            $SharedHDDs | ForEach-Object {
                                $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
                                Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                            }
                    }

                #create VM with Simple configuration
                    if ($VMConfig.configuration -eq 'Simple'){
                        BuildVM -VMConfig $($VMConfig) -LabConfig $labconfig -LabFolder $LABfolder
                    }

                #create VM with S2D configuration 
                    if ($VMConfig.configuration -eq 'S2D'){
                        #build VM
                            BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder
                        #compose VM name
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName

                        #Add disks
                            #add "SSDs"
                                If (($VMConfig.SSDNumber -ge 1) -and ($VMConfig.SSDNumber -ne $null)){         
                                    $SSDs= 1..$VMConfig.SSDNumber | ForEach-Object { New-vhd -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\SSD-$_.VHDX" -Dynamic -Size $VMConfig.SSDSize}
                                    Write-InfoHighlightedMessage "`t Adding Virtual SSD Disks"
                                    $SSDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                            #add "HDDs"
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)) {
                                    $HDDs= 1..$VMConfig.HDDNumber | ForEach-Object { New-VHD -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\HDD-$_.VHDX" -Dynamic -Size $VMConfig.HDDSize}
                                    Write-InfoHighlightedMessage "`t Adding Virtual HDD Disks"
                                    $HDDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                    }

                #create VM with Replica configuration    
                    if ($VMConfig.configuration -eq 'Replica'){
                        #create shared drives if not already created
                            $VMSet=$VMConfig.VMSet
                            if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
                                $ReplicaHDD= New-vhd -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS" -Dynamic -Size $VMConfig.ReplicaHDDSize
                                $ReplicaHDD | ForEach-Object {Write-InfoMessage "`t`t ReplicaHDD $($_.path) size $($_.size /1GB)GB created"}
                                $ReplicaLog= New-vhd -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS" -Dynamic -Size $VMConfig.ReplicaLogSize
                                $ReplicaLog | ForEach-Object {Write-InfoMessage "`t`t ReplicaLog $($_.path) size $($_.size /1GB)GB created"}
                            }else{
                                $ReplicaHDD=Get-VHD -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS"
                                $ReplicaLog=Get-VHD -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS"
                            }
                        #build VM
                            BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder

                        #Add disks
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName                
                            Write-InfoHighlightedMessage "`t Attaching Shared Disks..."
                            #Add HDD
                                $ReplicaHdd | ForEach-Object {
                                    $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                    Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
                                    Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                }
                            #add Log Disk
                                $ReplicaLog | ForEach-Object {
                                    $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                    Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
                                    Write-InfoMessage "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                }
                    }
            }
        }

#endregion

#region Finishing
    Write-InfoHighlightedMessage "Finishing..." 

    #a bit cleanup
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
        if (Test-Path "$PSScriptRoot\unattend.xml") {
            remove-item "$PSScriptRoot\unattend.xml"
        }

    #set MacSpoofing and AllowTeaming (for SET switch in VMs to work properly with vNICs)
        Write-InfoMessage "`t Setting MacSpoofing On and AllowTeaming On"
        Set-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -MacAddressSpoofing On -AllowTeaming On

    #list VMs 
        Get-VM | Where-Object name -like "$($labconfig.Prefix)*"  | ForEach-Object { Write-SuccessMessage "Machine $($_.VMName) provisioned" }

    #configure allowed VLANs (to create nested vNICs with VLANs)
        if ($labconfig.AllowedVLans){
            Write-InfoMessage "`t Configuring AllowedVlanIdList for Management NICs to $($LabConfig.AllowedVlans)"
            Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList $LabConfig.AllowedVlans
        }else{
            Write-InfoMessage "`t Configuring AllowedVlanIdList for Management NICs to 1-10"
            Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList "1-10"
        }

    #configure HostResourceProtection on all VM CPUs
        Write-InfoMessage "`t Configuring EnableHostResourceProtection on all VM processors"
        Set-VMProcessor -EnableHostResourceProtection $true -VMName "$($labconfig.Prefix)*" -ErrorAction SilentlyContinue

    #Enable Guest services on all VMs if integration component if configured
    if ($labconfig.EnableGuestServiceInterface){
        Write-InfoMessage "`t Enabling Guest Service Interface"
        Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -eq "Running" -or $_.state -eq "Off"} | Enable-VMIntegrationService -Name "Guest Service Interface"
        $TempVMs=Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -ne "Running" -and $_.state -ne "Off"}
        if ($TempVMs){
            Write-InfoHighlightedMessage "`t `t Following VMs cannot be configured, as the state is not running or off"
            $TempVMs.Name
        }
    }

    #Enable VMNics device naming
        Write-InfoMessage "`t Enabling VMNics device naming"
        Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object Generation -eq 2 | Set-VMNetworkAdapter -DeviceNaming On

    #write how much it took to deploy
        Write-InfoMessage "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    Stop-Transcript

    Write-SuccessMessage "Press enter to continue ..."
    $exit=Read-Host
#endregion
<#
.SYNOPSIS
  SYSAUDIT - System Audit Tool
.DESCRIPTION
  Queries local system for inventory and configuration information. Outputs to HTML file + other formats in an OUTPUT directory.
  Tested on Windows 10
.NOTES
  Version:        0.1
  Author:         Chris R Petrie (https://github.com/chrisrpetrie)
  Creation Date:  2 Feb 2022
  Purpose/Change: Initial build
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#CSS
$header = @"
<style>

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 14px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 11px;

    }

    h3 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 10px;

    }

    p {

        font-family: Arial, Helvetica, sans-serif;
        color: #000000;
        font-size: 8px;

    }    
    
   table {
		font-size: 9px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 2px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: #49708f;
        color: #fff;
        font-size: 9px;
        padding: 5px 5px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    


    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 9px;

    }

</style>
"@
    Write-Host "[i] Running System Audit Tool ..`n"
    Write-Host "[i] This may take a few minutes ..`n" 

    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if(!$isAdmin){
            
            Write-Warning  "[i] Some of the operations need administrative privileges.`n"
            
            Write-Warning  "[!] Please run using administrative rights (Run as Administrator).`n"
                        
            pause
            exit
    }

#Display Computer Hostname
$ComputerName = "<h1>Computer name: $env:computername</h1>"

#Display general computer information
$ComputerSystem = Get-CimInstance -Class Win32_ComputerSystem | ConvertTo-Html -As List -Property * -Fragment -PreContent "<h2>Computer Information</h2>"

#Display OS Info
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -As List -Property Version,Caption,BuildNumber,Manufacturer,OSArchitecture,OSLanguage -Fragment -PreContent "<h2>Operating System Information</h2>"

#Display Processesor Info
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -As List -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer -Fragment -PreContent "<h2>Processor Information</h2>"

#Display BIOS Info
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -As List -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2>BIOS Information</h2>"

#Display Disk Info
$DiscInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ConvertTo-Html -As List -Property DeviceID,DriveType,ProviderName,VolumeName,Size,FreeSpace -Fragment -PreContent "<h2>Disk Information</h2>"

#Display Network Adapters
$Network = Get-NetAdapter | ConvertTo-Html -Property MacAddress , Status , LinkSpeed, PhysicalMediaType, AdminStatus, ifAlias -Fragment -PreContent "<h2>Network Adapters</h2>"

#Display IP Addressing
$IpAddress = Get-NetIPAddress | ConvertTo-Html -Property INTERFACEALIAS, INTERFACEINDEX, IPADDRESS, PREFIXLENGTH -Fragment -PreContent "<h2>IP Addresses</h2>"

#Display IP Configuration
$IPConfiguration = Get-NetIPConfiguration -Detailed | ConvertTo-Html -Fragment -PreContent "<h2>IP Configuration</h2>"

#Display Software Inventory 
$Software = Get-CimInstance -Class Win32_Product | Sort-Object -Property Name | ConvertTo-Html -Property Name , Vendor , Version , Caption, InstallDate, InstallLocation -Fragment -PreContent "<h2>Installed Software</h2>"

#Display Optional Features
$optionalfeatures = Get-WindowsOptionalFeature -Online | Where {$_.state -eq 'Enabled'} | sort-object FeatureName | ConvertTo-Html -property FeatureName -Fragment -PreContent "<h2>Optional Features</h2>"

#Display Services
$ServicesInfo = Get-CimInstance -ClassName Win32_Service  | Sort-Object -Property DisplayName | ConvertTo-Html -Property DisplayName,Name,State,StartMode,ProcessID,StartName,PathName,Description -Fragment -PreContent "<h2>Services Information</h2>"

#Display Running Processes
$RunningProcesses = Get-Process | ConvertTo-Html -Property name, ID, path -Fragment -PreContent "<h2>Running Processes</h2>"

#Display Remote Desktop settings
$RDP = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" | select PSPath,fdenytsconnections | ConvertTo-Html -Fragment -PreContent "<h3>Remote Desktop</h3><p>Enabled = 0<br>Disabled = 1</p>"
$RDPNLA = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "SecurityLayer" | select PSPath,SecurityLayer | ConvertTo-Html -Fragment -PreContent "<h3>Remote Desktop with NLA</h3><p>0 = Specifies that the Microsoft Remote Desktop Protocol (RDP) is used by the server and the client for authentication before a remote desktop connection is established.<br>1 = Specifies that the server and the client negotiate the method for authentication before a remote desktop connection is established. (Default)<br>2 = Specifies that the Transport Layer Security (TLS) protocol is used by the server and the client for authentication before a remote desktop connection is established.</p>"

#Display AntiVirus Products
$AntiVirus = get-ciminstance -namespace root/securitycenter2 -classname antivirusproduct | ConvertTo-Html -Fragment -PreContent "<h2>AntiVirus</h2>"

#Display Users
$Users = Get-LocalUser | ConvertTo-Html -property Name, Enabled, Description, PasswordExpires, PasswordRequired, PasswordLastSet, LastLogon -Fragment -PreContent "<h2>Local Users</h2>"

#Display Groups
$Groups = Get-LocalGroup  -ErrorAction SilentlyContinue | ConvertTo-Html -property Name, Description -Fragment -PreContent "<h2>Local Groups</h2>"

#Display Administrator Group members
$GroupAdmin = Get-LocalGroupMember -group "Administrators" -ErrorAction SilentlyContinue | ConvertTo-Html -property Name, Description -Fragment -PreContent "<h2>Group Members - Administrators</h2>"

#Display User Group members
$GroupUsers = Get-LocalGroupMember -group "Users" -ErrorAction SilentlyContinue | ConvertTo-Html -property Name, Description -Fragment -PreContent "<h2>Group Members - Users</h2>"

#Display RDP Group members
$GroupRDP = Get-LocalGroupMember -group "Remote Desktop Users" -ErrorAction SilentlyContinue | ConvertTo-Html -property Name, Description -Fragment -PreContent "<h2>Group Members - Remote Desktop</h2>"

#Display UAC Status
$UAC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | ConvertTo-Html -Property EnableLUA -Fragment -PreContent "<h2>UAC Status</h2><p>0 = Windows does not notify the user when programs try to install software or make changes to the computer.<br>1 = Windows notifies the user when programs try to make changes to the computer.</p>"

#Display Startup Programs
$Startup = Get-CimInstance Win32_StartupCommand | ConvertTo-Html -Property Name, Command, Location, User -Fragment -PreContent "<h2>Startup Programs</h2>"

#Turn off Autoplay
$AutoplayNoDriveTypeAutoRun = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue | select pspath,NoDriveTypeAutoRun | ConvertTo-Html -Fragment -PreContent "<h2>AutoPlay - Turn off AutoPlay</h2>"

#Prevent AutoPlay from remembering user choices
$AutoplayDontSetAutoplayCheckbox = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name "DontSetAutoplayCheckbox" -ErrorAction SilentlyContinue | select pspath,DontSetAutoplayCheckbox | ConvertTo-Html -Fragment -PreContent "<h2>AutoPlay - Prevent AutoPlay from remembering user choices</h2>"

#Disallow Autoplay for non-volume devices
$AutoplayNoAutoplayfornonVolume = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name "NoAutoplayfornonVolume" -ErrorAction SilentlyContinue | select pspath,NoAutoplayfornonVolume | ConvertTo-Html -Fragment -PreContent "<h2>AutoPlay - Disallow AutoPlay for non-volume devices</h2>"

#Set the default behavior for AutoRun
$AutoplayNoAutorun = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name "NoAutorun" -ErrorAction SilentlyContinue | select pspath,NoAutorun | ConvertTo-Html -Fragment -PreContent "<h2>AutoPlay - Set the default behavior for AutoRun</h2>"

#Display Screensaver Security Settings
$ssa = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue | select PSPath,ScreenSaveActive
$ScreenSaverActive = $ssa | ConvertTo-Html -Fragment -PreContent "<h2>Screen Saver Active</h2>"
$ScreenSaverIsSecure = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue | select PSPath,ScreenSaverIsSecure | ConvertTo-Html -Fragment -PreContent "<h2>Screensaver Password Protection</h2>"
$ScreenSaveTimeOut = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue | select PSPath,ScreenSaveTimeOut | ConvertTo-Html -Fragment -PreContent "<h2>Screensaver Timeout</h2>"
$ScreenSaver = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue | select PSPath,SCRNSAVE.EXE | ConvertTo-Html -Fragment -PreContent "<h2>Screensaver Executable</h2>"

#Display Logon Banner
$legalnoticecaption = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\\System\" -Name "legalnoticecaption" -ErrorAction SilentlyContinue | select pspath,legalnoticecaption | ConvertTo-Html -Fragment -PreContent "<h2>Logon Banner Title</h2>"
$legalnoticetext = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\\System\" -Name "legalnoticetext" -ErrorAction SilentlyContinue | select pspath,legalnoticetext | ConvertTo-Html -Fragment -PreContent "<h2>Logon Banner Text</h2>"

#Display Autologon Settings
$AUTOLOGON = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" | select PSPath,AutoAdminLogon,DefaultUserName,DefaultPassword | ConvertTo-Html -Fragment -PreContent "<h2>AutoLogon Settings</h2>"

#NTP
$NTP = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" | select type, ntpserver, servicemain | ConvertTo-Html -Fragment -PreContent "<h2>NTP Servers</h2>"

#Displays Network Connections
$NETSTAT = Get-NetTCPConnection | select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | ConvertTo-Html -Fragment -PreContent "<h2>TCP Connections</h2>"

#Firewall status
$Firewall = Get-NetFirewallProfile | ConvertTo-Html -Property Name, Enabled -Fragment -PreContent "<h2>Firewall Status</h2>"

#Installed Updates
$WindowsPatches = Get-HotFix | sort-object hotfixid | ConvertTo-Html -Property HotFixID, InstalledOn, Description, Caption, InstalledBy -Fragment -PreContent "<h2>Installed Updates</h2>"

#Display Event Logs and Max Size
$EventLogs = Get-EventLog -list | ConvertTo-Html -Fragment -PreContent "<h2>Event Logs</h2>"

#Display Scheduled Tasks
$ScheduledTasks =  Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ConvertTo-Html -Property TaskPath, TaskName, State, URI, Description, Author -Fragment -PreContent "<h2>Scheduled Tasks</h2><p>Displays non-Microsoft tasks</p>"

#The command below will combine all the information gathered into a single HTML report
$InventoryReport = ConvertTo-HTML -Body "
$ComputerName
$ComputerSystem
$OSinfo 
$ProcessInfo 
$BiosInfo 
$DiscInfo 
$Network
$IpAddress
$IPConfiguration
$Software
$optionalfeatures
$ServicesInfo
$RunningProcesses
$RDP
$RDPNLA
$UAC
$AntiVirus
$Users
$Groups
$GroupAdmin
$GroupUsers
$GroupRDP
$Startup
$AutoplayNoDriveTypeAutoRun
$AutoplayDontSetAutoplayCheckbox
$AutoplayNoAutoplayfornonVolume
$AutoplayNoAutorun
$ScreenSaverActive
$ScreenSaverIsSecure
$ScreenSaveTimeOut
$Screensaver
$legalnoticecaption 
$legalnoticetext
$AUTOLOGON
$NTP
$NETSTAT
$Firewall
$WindowsPatches
$EventLogs
$ScheduledTasks

" -Head $header -Title "Computer Information Report" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#Check if directories exist and create if missing
$path1 = "OUTPUT"
If(!(test-path $path1))
{
      New-Item -ItemType Directory -Force -Path $path1 | Out-Null
}
$path2 = $env:computername
If(!(test-path $path1\$path2))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2 | Out-Null
}

#The command below will generate the report to an HTML file
Write-Host "[i] Exporting HTML Audit Report ..`n" 
$FileTimeStamp = get-date -format yyyyMMddhhmmss
$InventoryReport | Out-File $path1\$path2\$env:computername-$FileTimeStamp-Inventory.html

#Export Local Group Policy
Write-Host "[i] Exporting Local Group Policy ..`n"
If(!(test-path $path1\$path2\GroupPolicy))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2\GroupPolicy | Out-Null
}
Invoke-Expression -ErrorAction SilentlyContinue "./exe/lgpo.exe /q /parse /m C:\Windows\System32\GroupPolicy\Machine\Registry.pol > $path1\$path2\GroupPolicy\Machine.txt"
Invoke-Expression -ErrorAction SilentlyContinue "./exe/lgpo.exe /q /parse /u C:\Windows\System32\GroupPolicy\User\Registry.pol > $path1\$path2\GroupPolicy\User.txt"

#Export Security Policy
Write-Host "[i] Exporting Security Policy ..`n" 
SecEdit.exe /export /cfg $path1\$path2\$env:computername-$FileTimeStamp-SecPol.cfg /quiet 

#Export Scheduled Tasks
Write-Host "[i] Exporting Scheduled Tasks ..`n"
schtasks.exe /query /FO CSV /V > $path1\$path2\$env:computername-$FileTimeStamp-ScheduledTasks.csv

#Export Windows Event Logs
Write-Host "[i] Exporting Event Logs ..`n"
If(!(test-path $path1\$path2\EventLogs))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2\EventLogs | Out-Null
}
wevtutil epl Application $path1\$path2\EventLogs\Application.evtx /ow
wevtutil epl Security $path1\$path2\EventLogs\Security.evtx /ow
wevtutil epl System $path1\$path2\EventLogs\System.evtx /ow

    Write-Host "[i] Complete - Exiting ..`n" 

    Start-Sleep -Seconds 3
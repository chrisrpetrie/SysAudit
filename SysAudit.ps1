﻿<#
.SYNOPSIS
  SYSAUDIT - System Audit Tool
.DESCRIPTION
  Queries local system for inventory and configuration information. Outputs to HTML file + other formats in an OUTPUT directory.
  Tested on Windows 10
.AUTHOR
  Chris R Petrie (https://github.com/chrisrpetrie)
.REVISION HISTORY
  Version:        0.7
    Date:  07 Oct 2024
    Purpose/Change: Formatting changes. Added Logo.
  Version:        0.6
    Date:  08 Mar 2023
    Purpose/Change: Now exports gpresult, LGPO backups, and arp -a output.
  Version:        0.5
    Date:  23 Feb 2023
    Purpose/Change: Added PolicyAnalyzer and GPO2PolicyRules functionality
  Version:        0.4
    Date:  02 Dec 2022
    Purpose/Change: Now Exports Windows Defender Logs
  Version:        0.3
    Date:  28 Nov 2022
    Purpose/Change: Added extra UAC checks
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#CSS
$header = @"
<style>

    h0 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000000;
        font-size: 24px;

    }
    

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000000;
        font-size: 14px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000000;
        font-size: 11px;

    }

    h3 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000000;
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
        color: #000000;
        font-size: 9px;

    }

</style>
"@
    Write-Host "  _________               _____            .___.__  __   "
    Write-Host " /   _____/__.__. ______ /  _  \  __ __  __| _/|__|/  |_ "
    Write-Host " \_____  <   |  |/  ___//  /_\  \|  |  \/ __ | |  \   __\"
    Write-Host " /        \___  |\___ \/    |    \  |  / /_/ | |  ||  |  "
    Write-Host "/_______  / ____/____  >____|__  /____/\____ | |__||__|  "
    Write-Host "        \/\/         \/        \/           \/           "
    Write-Host ""
    Write-Host "[i] Running System Audit Tool ..`n"
    Write-Host "[i] This may take a few minutes ..`n" 

    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if(!$isAdmin){
            
            Write-Warning  "[i] Some of the operations need administrative privileges.`n"
            
            Write-Warning  "[!] Please run using administrative rights (Run as Administrator). Exiting... `n"

            Start-Sleep -Seconds 5
                        
            exit
    }

Write-Host "[i] Gathering System Information ..`n" 

$Logo = "<img src='../../exe/Logo.png'><p><p>"

$SystemAuditInventoryReport = "<h0>System Audit Inventory Report</h0>"

#Display Computer Hostname
$ComputerName = "<h1>Hostname: $env:computername</h1><p>"

#Display general computer information
$ComputerSystem = Get-CimInstance -Class Win32_ComputerSystem | ConvertTo-Html -As List -Property * -Fragment -PreContent "<h2>Computer Information</h2>"

#Display OS Info
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -Property Version,Caption,BuildNumber,Manufacturer,OSArchitecture,OSLanguage -Fragment -PreContent "<h2>Operating System Information</h2>"

#Display Processesor Info
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer -Fragment -PreContent "<h2>Processor Information</h2>"

#Display BIOS Info
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2>BIOS Information</h2>"

#Display Disk Info
$DiscInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ConvertTo-Html -Property DeviceID,DriveType,ProviderName,VolumeName,Size,FreeSpace -Fragment -PreContent "<h2>Disk Information</h2>"

#Display Network Adapters
$Network = Get-NetAdapter | ConvertTo-Html -Property MacAddress , Status , LinkSpeed, PhysicalMediaType, AdminStatus, ifAlias -Fragment -PreContent "<h2>Network Adapters</h2>"

#Display IP Addressing
$IpAddress = Get-NetIPAddress | ConvertTo-Html -Property INTERFACEALIAS, INTERFACEINDEX, IPADDRESS, PREFIXLENGTH -Fragment -PreContent "<h2>IP Addresses</h2>"

#Display Software Inventory 
$Software = Get-CimInstance -Class Win32_Product | Sort-Object -Property Name | ConvertTo-Html -Property Name , Vendor , Version , Caption, InstallDate, InstallLocation -Fragment -PreContent "<h2>Installed Software</h2>"

#Display Optional Features
$optionalfeatures = Get-WindowsOptionalFeature -Online | Where {$_.state -eq 'Enabled'} | sort-object FeatureName | ConvertTo-Html -property FeatureName -Fragment -PreContent "<h2>Optional Features</h2>"

#Display Services
$ServicesInfo = Get-CimInstance -ClassName Win32_Service  | Sort-Object -Property DisplayName | ConvertTo-Html -Property DisplayName,Name,State,StartMode,ProcessID,StartName,PathName,Description -Fragment -PreContent "<h2>Services Information</h2>"

#Display Running Processes
$RunningProcesses = Get-Process -ErrorAction SilentlyContinue | ConvertTo-Html -Property name, ID, path -Fragment -PreContent "<h2>Running Processes</h2>"

#Display Remote Desktop settings
$RDP = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" | select PSPath,fdenytsconnections | ConvertTo-Html -Fragment -PreContent "<h2>Remote Desktop</h2><p>Enabled = 0<br>Disabled = 1</p>"
$RDPNLA = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "SecurityLayer" | select PSPath,SecurityLayer | ConvertTo-Html -Fragment -PreContent "<h2>Remote Desktop with NLA</h2><p>0 = Specifies that the Microsoft Remote Desktop Protocol (RDP) is used by the server and the client for authentication before a remote desktop connection is established.<br>1 = Specifies that the server and the client negotiate the method for authentication before a remote desktop connection is established. (Default)<br>2 = Specifies that the Transport Layer Security (TLS) protocol is used by the server and the client for authentication before a remote desktop connection is established.</p>"

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

#Display UAC settings
$UAC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | ConvertTo-Html -Property FilterAdministratorToken,ConsentPromptBehaviorAdmin,ConsentPromptBehaviorUser,EnableInstallerDetection,EnableSecureUIAPaths,EnableLUA,PromptOnSecureDesktop,EnableVirtualization -Fragment -PreContent "<h2>UAC Status</h2>"

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
$Firewall = Get-NetFirewallProfile | ConvertTo-Html -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, AllowUserApps, AllowUserPorts, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, LogIgnored -Fragment -PreContent "<h2>Firewall Status</h2>"

#Installed Updates
$WindowsPatches = Get-HotFix | sort-object hotfixid | ConvertTo-Html -Property HotFixID, InstalledOn, Description, Caption, InstalledBy -Fragment -PreContent "<h2>Installed Updates</h2>"

#Display Event Logs and Max Size
$EventLogs = Get-EventLog -list | ConvertTo-Html -Fragment -PreContent "<h2>Event Logs</h2>"

#Display Scheduled Tasks
$ScheduledTasks =  Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ConvertTo-Html -Property TaskPath, TaskName, State, URI, Description, Author -Fragment -PreContent "<h2>Scheduled Tasks</h2><p>Displays non-Microsoft tasks</p>"

#Display Removable Storage status
$RemovableStorageDenied = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue | select pspath,Deny_All | ConvertTo-Html -Fragment -PreContent "<h2>Removable Storage status</h2>"

#The command below will combine all the information gathered into a single HTML report
$InventoryReport = ConvertTo-HTML -Body "
$Logo
$SystemAuditInventoryReport
$ComputerName
$ComputerSystem
$OSinfo 
$ProcessInfo 
$BiosInfo 
$DiscInfo 
$Network
$IpAddress
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
$RemovableStorageDenied

" -Head $header -Title "Computer Information Report" -PostContent "<p id='CreationDate'>Scan time: $(Get-Date)</p>"

#Set current director as variable
$currentdir = Get-Location

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

#Export Local Group Policy (policyrules)
Write-Host "[i] Exporting Local Group Policy (policyrules) ..`n"
If(!(test-path $path1\$path2\Policies))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2\Policies | Out-Null
}
Start-Process -filepath "exe/GPO2PolicyRules.exe" -ArgumentList "C:\Windows\System32\GroupPolicy $path1\$path2\Policies\$env:computername-$FileTimeStamp-GroupPolicy.PolicyRules"

#Export Local Group Policy Backup
Write-Host "[i] Exporting Local Group Policy Backup ..`n"
If(!(test-path $path1\$path2\Policies))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2\Policies | Out-Null
}
Invoke-Expression -ErrorAction SilentlyContinue "exe/LGPO.exe /b '$currentdir\$path1\$path2\Policies'" 2> $null

#Export Resultant Set of Policy (RSoP) information
Write-Host "[i] Resultant Set of Policy (RSoP) information ..`n"
If(!(test-path $path1\$path2\Policies))
{
      New-Item -ItemType Directory -Force -Path $path1\$path2\Policies | Out-Null
}
Invoke-Expression -ErrorAction SilentlyContinue "gpresult.exe /H '$currentdir\$path1\$path2\Policies\$env:computername-$FileTimeStamp-GPResult.html'"

#Export Security Policy
Write-Host "[i] Exporting Security Policy ..`n" 
Invoke-Expression -ErrorAction SilentlyContinue "SecEdit.exe /export /cfg $path1\$path2\Policies\$env:computername-$FileTimeStamp-SecurityPolicy.inf /quiet"

#Export ARP information
Write-Host "[i] Exporting ARP information ..`n" 
Invoke-Expression -ErrorAction SilentlyContinue "arp -a > $path1\$path2\$env:computername-$FileTimeStamp-arp.txt"

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
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" $path1\$path2\EventLogs\WindowsDefender.evtx /ow

    Write-Host "[i] Complete - Exiting ..`n" 

    Start-Sleep -Seconds 3
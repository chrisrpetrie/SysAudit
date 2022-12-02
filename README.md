# SysAudit
A tool written in PowerShell for auditing Windows configurations and security settings.  
Main purpose is for local computer audits where there is little or no network connectivity. 
The tool will output a wealth of information that can be later analyzed.
The tool can be run from a USB stick or alternatively from a network share.  
The resulting output will be stored in the OUTPUT directory.  
Read more here https://chrisrpetrie.medium.com/sysaudit-windows-security-audit-tool-3b30b20e512e

## Usage
1. Clone https://github.com/chrisrpetrie/SysAudit.git (Ensure you have the exe\LGPO.exe for the local policy export)
2. On the computer to be audited, run the SysAudit.exe file. (Requires Administrator rights to run.)

### Results
The results will be available at the locations below:

- OUTPUT\
  - HOSTNAME\
    - HOSTNAME-DATETIME-Inventory.html <- Main audit report
    - HOSTNAME-DATETIME-SecPol.cfg <- Export of Local Security Policy
    - HOSTNAME-DATETIME-ScheduledTasks.csv <- Export of Scheduled Tasks configuration  
    - EVENTLOGS\
      - Application.evtx  
      - Security.evtx  
      - System.evtx  
      - WindowsDefender.evtx  
    - GROUPPOLICY\
      - Machine.txt <- Parsed local group policy files  
      - User.txt <- Parsed local group policy files  
  
### To compile the EXE use the PS2EXE module in Powershell:
1. Install-Module -Name ps2exe 
2. Invoke-PS2EXE .\SysAudit.ps1 .\SysAudit.exe -version 0.3 -title "System Audit Tool" -requireAdmin

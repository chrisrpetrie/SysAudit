# SysAudit
A tool written in PowerShell for auditing Windows configurations and security settings.  
Main purpose is for local computer audits where there is little or no network connectivity.  
The tool can be run from a USB stick or alternatively from a network share.  
The resulting output will be stored in the OUTPUT directory.  

## Usage
1. Clone https://github.com/chrisrpetrie/SysAudit.git
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
    - GROUPPOLICY\
      - Machine.txt <- Parsed local group policy files  
      - User.txt <- Parsed local group policy files  
  

# SysAudit
A tool written in PowerShell for auditing Windows configurations and security settings.  
Its main purpose is for local computer security audits on standalone or air gapped systems. 
The tool will output information that can be later analyzed.
The tool can be run from a USB stick or from a network share.  
The resulting output will be stored in the OUTPUT directory.  

## Usage
1. Place the SysAudit directory and all subfolders, files on a USB stick or a network share.
	Note that you may need to go to the exe properties and select "Unblock" if you get a Smartscreen warning.
2. On the computer to be audited, run the SysAudit.exe file. (Requires Administrator rights to run.)
	Note: Defender or Smartscreen warning may appear, or require a scan, accept those to continue - the script is non malicious using Microsoft utilities and PowerShell cmdlets.
3. The results will be available in the OUTPUT folder.

### Results
The results will be available at the locations below:

- OUTPUT\
  - HOSTNAME\
    - HOSTNAME-DATETIME-Inventory.html <- Main audit report
    - HOSTNAME-DATETIME-ScheduledTasks.csv <- Export of Scheduled Tasks configuration  
    - EVENTLOGS\
      - Application.evtx  
      - Security.evtx  
      - System.evtx  
      - WindowsDefender.evtx  
    - POLICIES\ 
      - {GUID} <- Local GPO Backup
      - HOSTNAME-DATETIME-GroupPolicy.PolicyRules <- Export of Local Group Policy Configuration for use with Policy Analyzer
      - HOSTNAME-DATETIME-SecurityPolicy.inf <- Export of Local Security Policy for use with Policy Analyzer
      - HOSTNAME-DATETIME-GPResult.html <- Local GPO Policy report
  
### To compile the EXE use the PS2EXE module in Powershell:
1. Install-Module -Name ps2exe 
2. Invoke-PS2EXE .\SysAudit.ps1 .\SysAudit.exe -version 0.6 -title "System Audit Tool" -requireAdmin
